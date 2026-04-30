"""
Cybersecurity Nexus - FastAPI server
====================================
Endpoints:
  GET  /                         -> serve the Nexus UI (single-page)
  GET  /api/health
  GET  /api/cve/{id}             -> CVE detail + CWE + OSI + PoCs + packages
  GET  /api/cwe/{id}             -> CWE detail + child/parent + linked CVEs
  GET  /api/package/{eco}/{name} -> package detail + affecting CVEs
  GET  /api/search?q=            -> universal full-text search
  GET  /api/osi/{layer}          -> CVE/CWE/AIThreat list for a layer
  GET  /api/ai-vulns             -> AI threat catalog
  GET  /api/poc/{cve}            -> PoCs for a CVE
  GET  /api/risk/{cve}           -> Combined Nexus risk score
  GET  /api/graph/{cve}          -> Subgraph (nodes/edges) for visualization
  GET  /api/stats                -> Top-level counts for the home dashboard
"""
from __future__ import annotations
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from config import settings
from engine.graph import run_read, get_driver, close_driver
from engine.risk_scoring import score_dict
from engine.osi_classifier import classify, LAYER_NAMES
from engine.attack_chain import build_chain, chains_for_packages
from engine import llm, dna, patch_twin, defense, posture
from engine import healthcare, hipaa, sra_report, clinical_runner, model_card
from ingest.sbom import scan as sbom_scan
from ingest.telemetry import ingest_kev, kev_summary
from ingest.policies import parse_any as parse_policy
from ingest.policies.upsert import upsert_policies

UI_DIR = Path(__file__).resolve().parent.parent / "ui"

app = FastAPI(title="Cybersecurity Nexus", version="1.0.0",
              description="Graph-powered CVE/CWE/Package/AI-Threat nexus across all 7 OSI layers")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


@app.on_event("shutdown")
def _shutdown() -> None:
    close_driver()


# --------------------------- Static UI -------------------------------------
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(UI_DIR / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    # 1x1 transparent SVG so the browser stops 404-ing
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="80" font-size="80">\xe2\xac\xa2</text></svg>'
    from fastapi.responses import Response
    return Response(content=svg, media_type="image/svg+xml")


app.mount("/ui", StaticFiles(directory=UI_DIR), name="ui")


# --------------------------- Global error handler --------------------------
from fastapi.requests import Request
from fastapi.exceptions import RequestValidationError


@app.exception_handler(Exception)
async def _generic_exc_handler(request: Request, exc: Exception):
    import traceback as _tb
    body = {
        "error": type(exc).__name__,
        "message": str(exc),
        "path": str(request.url.path),
    }
    # Print full trace to the server console for debugging
    _tb.print_exc()
    return JSONResponse(status_code=500, content=body)


# --------------------------- Health & stats --------------------------------
@app.get("/api/health")
def health() -> dict:
    try:
        get_driver().verify_connectivity()
        return {"status": "ok", "neo4j": "connected"}
    except Exception as e:
        raise HTTPException(503, f"Neo4j unavailable: {e}")


@app.get("/api/stats")
def stats() -> dict:
    # Neo4j 5+ uses COUNT { ... } subqueries instead of size([(n) | n])
    counts = {"cves": 0, "cwes": 0, "packages": 0, "pocs": 0, "ai_threats": 0}
    queries = {
        "cves":       "MATCH (c:CVE)      RETURN count(c) AS n",
        "cwes":       "MATCH (c:CWE)      RETURN count(c) AS n",
        "packages":   "MATCH (p:Package)  RETURN count(p) AS n",
        "pocs":       "MATCH (p:PoC)      RETURN count(p) AS n",
        "ai_threats": "MATCH (a:AIThreat) RETURN count(a) AS n",
    }
    for key, q in queries.items():
        try:
            rows = run_read(q)
            counts[key] = rows[0]["n"] if rows else 0
        except Exception:
            counts[key] = 0

    try:
        layer_rows = run_read("""
            MATCH (l:OSILayer)
            OPTIONAL MATCH (l)<-[:MAPS_TO]-(c:CVE)
            RETURN l.number AS layer, l.name AS name, count(DISTINCT c) AS cves
            ORDER BY l.number
        """)
    except Exception:
        layer_rows = []
    return {"counts": counts, "layers": layer_rows}


# --------------------------- CVE -------------------------------------------
@app.get("/api/cve/{cve_id}")
def get_cve(cve_id: str) -> dict:
    cve_id = cve_id.upper()
    rows = run_read("""
        MATCH (c:CVE {id: $id})
        OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
        OPTIONAL MATCH (c)-[:HAS_POC]->(p:PoC)
        OPTIONAL MATCH (c)-[r:AFFECTS]->(pk:Package)
        OPTIONAL MATCH (a:AIThreat)-[:RELATED_TO]->(c)
        RETURN c{.*} AS cve,
               collect(DISTINCT w{.id, .name}) AS cwes,
               collect(DISTINCT l{.number, .name}) AS layers,
               collect(DISTINCT p{.url, .source, .language, .snippet}) AS pocs,
               collect(DISTINCT {ecosystem: pk.ecosystem, name: pk.name,
                                 affected: r.affected_versions, fixed: r.fixed_versions}) AS packages,
               collect(DISTINCT a{.id, .name, .framework}) AS ai_threats
    """, id=cve_id)
    if not rows or not rows[0]["cve"]:
        raise HTTPException(404, f"{cve_id} not found")
    data = rows[0]
    # Filter empty package rows
    data["packages"] = [p for p in data["packages"] if p.get("name")]
    data["pocs"] = [p for p in data["pocs"] if p.get("url")]
    data["cwes"] = [c for c in data["cwes"] if c.get("id")]
    data["layers"] = [l for l in data["layers"] if l.get("number")]
    data["ai_threats"] = [a for a in data["ai_threats"] if a.get("id")]
    # Compute risk
    data["risk"] = score_dict({
        "cvss_score": data["cve"].get("cvss_score"),
        "cwe_ids": [c["id"] for c in data["cwes"]],
        "osi_layers": [l["number"] for l in data["layers"]],
        "poc_count": len(data["pocs"]),
        "package_count": len(data["packages"]),
        "published": data["cve"].get("published"),
    })
    return data


# --------------------------- CWE -------------------------------------------
@app.get("/api/cwe/{cwe_id}")
def get_cwe(cwe_id: str) -> dict:
    cwe_id = cwe_id.upper()
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"

    base = run_read("MATCH (w:CWE {id: $id}) RETURN w{.*} AS cwe", id=cwe_id)
    if not base or not base[0].get("cwe"):
        raise HTTPException(404, f"{cwe_id} not found")

    parents = run_read("""
        MATCH (w:CWE {id: $id})-[:CHILD_OF]->(p:CWE)
        RETURN p.id AS id, p.name AS name LIMIT 25
    """, id=cwe_id)
    children = run_read("""
        MATCH (c:CWE)-[:CHILD_OF]->(w:CWE {id: $id})
        RETURN c.id AS id, c.name AS name LIMIT 25
    """, id=cwe_id)
    layers = run_read("""
        MATCH (w:CWE {id: $id})-[:MAPS_TO]->(l:OSILayer)
        RETURN l.number AS number, l.name AS name ORDER BY l.number
    """, id=cwe_id)
    cves = run_read("""
        MATCH (c:CVE)-[:CLASSIFIED_AS]->(w:CWE {id: $id})
        RETURN c.id AS id, c.cvss_score AS cvss_score, c.severity AS severity
        ORDER BY coalesce(c.cvss_score, 0) DESC, c.id DESC
        LIMIT 50
    """, id=cwe_id)
    counts = run_read("""
        MATCH (w:CWE {id: $id})
        RETURN COUNT { (:CVE)-[:CLASSIFIED_AS]->(w) } AS cve_count
    """, id=cwe_id)
    return {
        "cwe": base[0]["cwe"],
        "parents": parents,
        "children": children,
        "layers": layers,
        "cves": cves,
        "cve_count": counts[0]["cve_count"] if counts else 0,
    }


# --------------------------- Package ---------------------------------------
@app.get("/api/package/{ecosystem}/{name:path}")
def get_package(ecosystem: str, name: str) -> dict:
    purl = f"pkg:{ecosystem.lower()}/{name}"
    rows = run_read("""
        MATCH (p:Package {purl: $purl})
        OPTIONAL MATCH (c:CVE)-[r:AFFECTS]->(p)
        RETURN p{.*} AS pkg,
               collect(DISTINCT c{.id, .cvss_score, .severity, .description,
                                 affected: r.affected_versions, fixed: r.fixed_versions}) AS cves
    """, purl=purl)
    if not rows or not rows[0]["pkg"]:
        raise HTTPException(404, f"package {ecosystem}:{name} not found")
    rows[0]["cves"] = [c for c in rows[0]["cves"] if c.get("id")]
    return rows[0]


# --------------------------- Search ----------------------------------------
@app.get("/api/search")
def search(q: str, limit: int = 25) -> dict:
    q = q.strip()
    if not q:
        return {"cves": [], "cwes": [], "packages": [], "ai_threats": []}
    # Use full-text indexes; fall back to CONTAINS if FTS misses.
    cves = run_read("""
        CALL db.index.fulltext.queryNodes('cve_search', $q + '*')
        YIELD node, score
        RETURN node.id AS id, node.severity AS severity,
               node.cvss_score AS cvss, node.description AS description, score
        ORDER BY score DESC LIMIT $limit
    """, q=q, limit=limit) or []
    cwes = run_read("""
        CALL db.index.fulltext.queryNodes('cwe_search', $q + '*')
        YIELD node, score
        RETURN node.id AS id, node.name AS name, score
        ORDER BY score DESC LIMIT $limit
    """, q=q, limit=limit) or []
    pkgs = run_read("""
        CALL db.index.fulltext.queryNodes('package_search', $q + '*')
        YIELD node, score
        RETURN node.ecosystem AS ecosystem, node.name AS name, node.purl AS purl, score
        ORDER BY score DESC LIMIT $limit
    """, q=q, limit=limit) or []
    ai = run_read("""
        CALL db.index.fulltext.queryNodes('ai_threat_search', $q + '*')
        YIELD node, score
        RETURN node.id AS id, node.name AS name, node.framework AS framework, score
        ORDER BY score DESC LIMIT $limit
    """, q=q, limit=limit) or []
    return {"cves": cves, "cwes": cwes, "packages": pkgs, "ai_threats": ai}


# --------------------------- OSI -------------------------------------------
@app.get("/api/osi/{layer}")
def by_layer(layer: int, limit: int = 100) -> dict:
    if layer not in LAYER_NAMES:
        raise HTTPException(400, "OSI layer must be 1-7")

    # Three small focused queries beat one big multi-OPTIONAL MATCH that
    # Cartesian-explodes for popular layers (L7 has tens of thousands of CVEs).
    layer_rows = run_read(
        "MATCH (l:OSILayer {number: $layer}) RETURN l{.*} AS layer",
        layer=layer,
    )
    if not layer_rows:
        raise HTTPException(404, "layer not found")

    cves = run_read("""
        MATCH (l:OSILayer {number: $layer})<-[:MAPS_TO]-(c:CVE)
        RETURN c.id AS id, c.cvss_score AS cvss_score, c.severity AS severity
        ORDER BY coalesce(c.cvss_score, 0) DESC, c.id DESC
        LIMIT $limit
    """, layer=layer, limit=limit)

    cwes = run_read("""
        MATCH (l:OSILayer {number: $layer})<-[:MAPS_TO]-(w:CWE)
        RETURN w.id AS id, w.name AS name
        ORDER BY w.id
        LIMIT $limit
    """, layer=layer, limit=limit)

    ai_threats = run_read("""
        MATCH (l:OSILayer {number: $layer})<-[:MAPS_TO]-(a:AIThreat)
        RETURN a.id AS id, a.name AS name, a.framework AS framework
        ORDER BY a.framework, a.id
        LIMIT $limit
    """, layer=layer, limit=limit)

    # Total counts (cheap with the CVE→OSI index)
    counts = run_read("""
        MATCH (l:OSILayer {number: $layer})
        RETURN
          COUNT { (l)<-[:MAPS_TO]-(:CVE) }      AS cve_total,
          COUNT { (l)<-[:MAPS_TO]-(:CWE) }      AS cwe_total,
          COUNT { (l)<-[:MAPS_TO]-(:AIThreat) } AS ai_total
    """, layer=layer)
    totals = counts[0] if counts else {"cve_total": 0, "cwe_total": 0, "ai_total": 0}

    return {
        "layer": layer_rows[0]["layer"],
        "cves": cves,
        "cwes": cwes,
        "ai_threats": ai_threats,
        "totals": totals,
    }


# --------------------------- AI threats ------------------------------------
@app.get("/api/ai-vulns")
def ai_vulns() -> list[dict]:
    # Order via the projected alias - in Cypher, after RETURN with aggregation
    # the source variable `a` is no longer accessible to ORDER BY.
    return run_read("""
        MATCH (a:AIThreat)
        OPTIONAL MATCH (a)-[:MAPS_TO]->(l:OSILayer)
        OPTIONAL MATCH (a)-[:RELATED_TO]->(c:CVE)
        RETURN a{.*} AS threat,
               collect(DISTINCT l.number) AS layers,
               collect(DISTINCT c.id)[0..10] AS cves
        ORDER BY threat.framework, threat.id
    """)


# --------------------------- PoC -------------------------------------------
@app.get("/api/poc/{cve_id}")
def get_poc(cve_id: str) -> list[dict]:
    return run_read("""
        MATCH (c:CVE {id: $id})-[:HAS_POC]->(p:PoC)
        RETURN p{.*} AS poc
        ORDER BY p.fetched DESC
    """, id=cve_id.upper()) or []


# --------------------------- Risk ------------------------------------------
@app.get("/api/risk/{cve_id}")
def get_risk(cve_id: str) -> dict:
    rows = run_read("""
        MATCH (c:CVE {id: $id})
        OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
        OPTIONAL MATCH (c)-[:HAS_POC]->(p:PoC)
        OPTIONAL MATCH (c)-[:AFFECTS]->(pk:Package)
        RETURN c.cvss_score AS cvss, c.published AS pub,
               collect(DISTINCT w.id) AS cwes,
               collect(DISTINCT l.number) AS layers,
               count(DISTINCT p) AS poc,
               count(DISTINCT pk) AS pkgs
    """, id=cve_id.upper())
    if not rows:
        raise HTTPException(404, f"{cve_id} not found")
    r = rows[0]
    return score_dict({
        "cvss_score": r["cvss"], "cwe_ids": r["cwes"], "osi_layers": r["layers"],
        "poc_count": r["poc"], "package_count": r["pkgs"], "published": r["pub"],
    })


# --------------------------- Graph subgraph --------------------------------
@app.get("/api/graph/{cve_id}")
def graph_for(cve_id: str) -> dict:
    """Return a Cytoscape-friendly node/edge list for the CVE neighborhood."""
    rows = run_read("""
        MATCH (c:CVE {id: $id})
        OPTIONAL MATCH (c)-[r1:CLASSIFIED_AS]->(w:CWE)
        OPTIONAL MATCH (c)-[r2:MAPS_TO]->(l:OSILayer)
        OPTIONAL MATCH (c)-[r3:HAS_POC]->(p:PoC)
        OPTIONAL MATCH (c)-[r4:AFFECTS]->(pk:Package)
        OPTIONAL MATCH (a:AIThreat)-[r5:RELATED_TO]->(c)
        OPTIONAL MATCH (w)-[r6:MAPS_TO]->(l2:OSILayer)
        RETURN c, w, l, p, pk, a, l2
    """, id=cve_id.upper())
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add(node, label):
        if node is None: return None
        if not isinstance(node, dict): return None
        # Pick the best identifying field per node type
        ident = (node.get("id") or node.get("purl") or node.get("url")
                 or (str(node["number"]) if node.get("number") is not None else None))
        if not ident:
            return None
        key = f"{label}:{ident}"
        if key not in nodes:
            # IMPORTANT: spread first, THEN overwrite id/label so the original
            # node.id (e.g. "CVE-2021-44228") doesn't collide with our composite
            # cytoscape key (e.g. "CVE:CVE-2021-44228"). Without this, edges
            # reference a node id that doesn't exist and the graph stays empty.
            nodes[key] = {"data": {**node, "id": key, "label": label}}
        return key

    def edge(src, tgt, kind):
        if src and tgt and src != tgt:
            eid = f"{src}->{tgt}:{kind}"
            edges.append({"data": {"id": eid, "source": src, "target": tgt, "label": kind}})

    for r in rows:
        cve_k = add(r["c"], "CVE")
        if r["w"]:  edge(cve_k, add(r["w"], "CWE"), "CLASSIFIED_AS")
        if r["l"]:  edge(cve_k, add(r["l"], "OSILayer"), "MAPS_TO")
        if r["p"]:  edge(cve_k, add(r["p"], "PoC"), "HAS_POC")
        if r["pk"]: edge(cve_k, add(r["pk"], "Package"), "AFFECTS")
        if r["a"]:  edge(add(r["a"], "AIThreat"), cve_k, "RELATED_TO")
        if r["w"] and r["l2"]: edge(add(r["w"], "CWE"), add(r["l2"], "OSILayer"), "MAPS_TO")
    return {"nodes": list(nodes.values()), "edges": edges}


# --------------------------- Classify a free-form description --------------
@app.get("/api/classify")
def classify_text(text: str, cwe: str | None = None) -> dict:
    cwes = [c.strip() for c in (cwe or "").split(",") if c.strip()]
    return {"layers": classify(text, cwes), "input": text, "cwes": cwes}


# =====================================================================
# Phase B endpoints: attack chains, SBOM, LLM, DNA, twins, defense, telemetry
# =====================================================================

# --------------------------- Attack chains ---------------------------------
@app.get("/api/attack-chain/{cve_id}")
def attack_chain(cve_id: str, entry: str = "internet", depth: int = 4, branch: int = 5) -> dict:
    chains = build_chain(cve_id, entry=entry, max_depth=depth, branch=branch)
    if not chains:
        raise HTTPException(404, f"No chains found for {cve_id} (CVE may be missing or isolated)")
    return {"seed": cve_id.upper(), "entry": entry, "chains": chains}


# --------------------------- SBOM scan -------------------------------------
@app.post("/api/sbom")
async def sbom(file: UploadFile = File(...)) -> dict:
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "SBOM file too large (5 MB limit)")
    return sbom_scan(content, file.filename or "")


# --------------------------- LLM storyteller -------------------------------
@app.get("/api/llm/health")
def llm_health() -> dict:
    return {"available": llm.is_available(), "url": llm.OLLAMA_URL,
            "default_model": llm.DEFAULT_MODEL, "embed_model": llm.EMBED_MODEL}


@app.get("/api/story/{cve_id}")
def story(cve_id: str) -> dict:
    """Generate the full narrative (non-streamed). Use /story/stream for live."""
    cve = _cve_for_llm(cve_id)
    if not cve:
        raise HTTPException(404, f"{cve_id} not found")
    try:
        text = llm.generate_story(cve, packages=cve.get("packages") or [])
    except llm.LLMUnavailable as e:
        raise HTTPException(503, str(e))
    return {"cve": cve_id.upper(), "narrative": text}


@app.get("/api/story/stream/{cve_id}")
def story_stream(cve_id: str):
    cve = _cve_for_llm(cve_id)
    if not cve:
        raise HTTPException(404, f"{cve_id} not found")

    def gen():
        try:
            for chunk in llm.stream_story(cve, packages=cve.get("packages") or []):
                yield chunk
        except llm.LLMUnavailable as e:
            yield f"\n\n[LLM unavailable: {e}]"
    return StreamingResponse(gen(), media_type="text/plain")


def _cve_for_llm(cve_id: str) -> dict | None:
    rows = run_read("""
        MATCH (c:CVE {id: $id})
        OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
        OPTIONAL MATCH (c)-[:HAS_POC]->(p:PoC)
        OPTIONAL MATCH (c)-[:AFFECTS]->(pk:Package)
        RETURN c.id AS id, c.description AS description,
               c.cvss_score AS cvss_score, c.severity AS severity,
               collect(DISTINCT w.id) AS cwes,
               collect(DISTINCT l.number) AS layers,
               count(DISTINCT p) AS poc_count,
               collect(DISTINCT pk.purl)[0..6] AS packages
    """, id=cve_id.upper())
    return rows[0] if rows and rows[0].get("id") else None


# --------------------------- AI Red-Team Mode ------------------------------
class RedTeamRequest(BaseModel):
    stack_summary: str
    purls: list[str] | None = None
    entry: str = "internet"


@app.post("/api/red-team")
def red_team(req: RedTeamRequest) -> dict:
    chains = chains_for_packages(req.purls or [], entry=req.entry, per_seed=1) if req.purls else []
    aggregate = max((c["score"] for c in chains), default=0.0)
    band = "CRITICAL" if aggregate >= 80 else "HIGH" if aggregate >= 60 else "MEDIUM" if aggregate >= 40 else "LOW"
    try:
        plan = llm.red_team_plan(req.stack_summary, chains, aggregate=aggregate, band=band)
    except llm.LLMUnavailable as e:
        # Fall back to a structured (non-LLM) plan
        plan = _fallback_red_team(req.stack_summary, chains, aggregate, band, str(e))
    return {"stack_summary": req.stack_summary, "chains": chains,
            "aggregate_score": aggregate, "band": band, "plan": plan}


def _fallback_red_team(summary: str, chains: list[dict], agg: float, band: str, err: str) -> str:
    out = [f"# Red-Team Brief (LLM offline: {err})\n"]
    out.append(f"**Stack:** {summary[:500]}\n")
    out.append(f"**Aggregate Nexus Score:** {agg:.1f} / 100  ({band})\n")
    if not chains:
        out.append("\n_No attack chains were derivable from the provided packages._")
        return "\n".join(out)
    out.append("\n## Realistic Attack Path\n")
    for c in chains[:2]:
        out.append(f"\n### Chain (score {c['score']}, layers {c['layers_traversed']})")
        for s in c["steps"]:
            arrow = f"L{s['layer_from']}→L{s['layer_to']}" if s.get("layer_from") else f"L{s['layer_to']}"
            out.append(f"  - {arrow}  **{s['cve']}** ({s.get('severity','?')}) — {s.get('transition')}")
    return "\n".join(out)


# --------------------------- Vulnerability DNA -----------------------------
@app.get("/api/similar/{cve_id}")
def similar(cve_id: str, k: int = 10) -> dict:
    return {"cve": cve_id.upper(), "neighbors": dna.similar(cve_id, k=k)}


@app.post("/api/dna/embed")
def dna_embed(limit: int = 1000, refresh: bool = False) -> dict:
    n = dna.embed_corpus(limit=limit, refresh=refresh)
    return {"embedded": n}


# --------------------------- Patch Twins -----------------------------------
@app.get("/api/patch-twins/{cve_id}")
def patch_twins(cve_id: str, k: int = 10) -> dict:
    return {"cve": cve_id.upper(), "twins": patch_twin.find_twins(cve_id, k=k)}


# --------------------------- Defense Recipes -------------------------------
@app.get("/api/defense/{cve_id}")
def defense_for_cve(cve_id: str) -> dict:
    return defense.for_cve(cve_id)


@app.get("/api/defense/cwe/{cwe_id}")
def defense_for_cwe(cwe_id: str) -> dict:
    return defense.for_cwe(cwe_id)


# --------------------------- Telemetry -------------------------------------
@app.post("/api/telemetry/refresh")
def telemetry_refresh() -> dict:
    n = ingest_kev()
    return {"kev_count": n}


@app.get("/api/telemetry/kev")
def telemetry_kev() -> dict:
    return kev_summary()


# =====================================================================
# Posture / Policy Validation endpoints
# =====================================================================

class PolicyPasteRequest(BaseModel):
    content: str
    hint: str | None = None


@app.post("/api/policies/upload")
async def policies_upload(files: list[UploadFile] = File(...)) -> dict:
    """Drag-drop multi-file upload. Auto-detects format per file."""
    total = 0
    parsed_per_file: list[dict] = []
    for f in files:
        try:
            content = await f.read()
            policies = parse_policy(content, hint=f.filename or "")
            n = upsert_policies(policies)
            total += n
            parsed_per_file.append({
                "filename": f.filename, "policies": n,
                "controls": sum(len(p.controls) for p in policies),
                "platforms": sorted({p.source for p in policies}),
            })
        except Exception as e:
            parsed_per_file.append({"filename": f.filename, "error": str(e)})
    return {"imported": total, "files": parsed_per_file}


@app.post("/api/policies/paste")
def policies_paste(req: PolicyPasteRequest) -> dict:
    """Paste-in JSON from the UI."""
    policies = parse_policy(req.content, hint=req.hint)
    n = upsert_policies(policies)
    return {"imported": n,
            "platforms": sorted({p.source for p in policies}),
            "controls": sum(len(p.controls) for p in policies)}


@app.delete("/api/policies/clear")
def policies_clear() -> dict:
    """Wipe all uploaded policies (kept simple - no auth here, local use only)."""
    rows = run_read("MATCH (p:Policy) DETACH DELETE p RETURN count(p) AS n")
    rows2 = run_read("MATCH (c:Control) WHERE NOT (c)<-[:CONTAINS]-() DETACH DELETE c RETURN count(c) AS n")
    return {"deleted_policies": rows[0]["n"] if rows else 0,
            "deleted_orphan_controls": rows2[0]["n"] if rows2 else 0}


@app.get("/api/policies")
def policies_list() -> dict:
    rows = run_read("""
        MATCH (p:Policy)
        OPTIONAL MATCH (p)-[:CONTAINS]->(c:Control)
        RETURN p.id AS id, p.source AS source, p.type AS type, p.name AS name,
               count(c) AS controls
        ORDER BY p.source, p.name LIMIT 500
    """)
    return {"count": len(rows), "policies": rows}


@app.get("/api/posture/coverage")
def posture_coverage() -> dict:
    return posture.coverage()


@app.get("/api/posture/gaps/{cve_id}")
def posture_gaps(cve_id: str) -> dict:
    return posture.gaps_for_cve(cve_id)


@app.get("/api/posture/replay/{cve_id}")
def posture_replay(cve_id: str) -> dict:
    return posture.replay_for_cve(cve_id)


class StackPostureRequest(BaseModel):
    purls: list[str]


@app.post("/api/posture/stack")
def posture_stack(req: StackPostureRequest) -> dict:
    return posture.coverage_for_stack(req.purls)


# =====================================================================
# Healthcare / HIPAA endpoints
# =====================================================================
@app.post("/api/hipaa/tag-phi")
def hipaa_tag_phi() -> dict:
    """Quick re-tag of healthcare packages already in the graph.
    Use /api/hipaa/seed-phi to also pull them from OSV."""
    n = healthcare.tag_phi_packages()
    return {"tagged": n}


@app.post("/api/hipaa/seed-phi")
def hipaa_seed_phi(via_osv: bool = True, limit: int | None = None) -> dict:
    """Pull healthcare packages from OSV.dev (creating Package nodes + linking
    any CVEs that affect them), then tag them with :HandlesPHI. ~1-2 min."""
    return healthcare.seed_phi_packages(via_osv=via_osv, limit=limit)


@app.get("/api/hipaa/coverage")
def hipaa_coverage_endpoint() -> dict:
    return hipaa.hipaa_coverage()


@app.get("/api/hipaa/gaps/{cve_id}")
def hipaa_gaps_endpoint(cve_id: str) -> dict:
    return hipaa.hipaa_gaps_for_cve(cve_id)


class SRARequest(BaseModel):
    organization: str | None = "Your Organization"
    scope: str | None = "Production environment"
    stack_summary: str | None = ""
    format: str | None = "markdown"   # "markdown" | "docx"


@app.post("/api/hipaa/sra")
def hipaa_sra_endpoint(req: SRARequest):
    if req.format == "docx":
        data = sra_report.generate_docx(
            stack_summary=req.stack_summary or "", scope=req.scope or "",
            organization=req.organization or "")
        from fastapi.responses import Response
        return Response(content=data,
                        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": "attachment; filename=HIPAA_SRA.docx"})
    md = sra_report.generate_markdown(stack_summary=req.stack_summary or "",
                                       scope=req.scope or "",
                                       organization=req.organization or "")
    return {"format": "markdown", "report": md}


# =====================================================================
# Clinical-AI test runner endpoints
# =====================================================================
class ClinicalRunRequest(BaseModel):
    model: str = "llama3.1:8b"
    categories: list[str] | None = None
    api_base: str | None = None
    api_key: str | None = None
    limit: int | None = None


@app.post("/api/clinical-ai/run")
def clinical_run(req: ClinicalRunRequest) -> dict:
    findings = clinical_runner.run_tests(
        model=req.model, categories=req.categories,
        api_base=req.api_base, api_key=req.api_key, limit=req.limit)
    s = clinical_runner.summary(req.model)
    return {"model": req.model, "findings": findings, "summary": s}


@app.get("/api/clinical-ai/findings")
def clinical_findings(model: str | None = None, limit: int = 200) -> dict:
    return {"findings": clinical_runner.list_findings(model, limit),
            "summary": clinical_runner.summary(model)}


@app.get("/api/clinical-ai/categories")
def clinical_categories() -> dict:
    from engine.clinical_ai_corpus import GENERATORS, build_corpus
    out = []
    for cat in GENERATORS:
        cases = GENERATORS[cat]()
        out.append({"category": cat, "case_count": len(cases),
                    "example_id": cases[0].id if cases else "—"})
    return {"categories": out, "total_cases": sum(c["case_count"] for c in out)}


class ModelCardRequest(BaseModel):
    model_name: str = "(unspecified)"
    intended_use: str = ""
    training_data: str = ""
    evaluation_data: str = ""
    limitations: str = ""
    monitoring_plan: str = ""
    deployment_context: str = ""
    organization: str = "Your Organization"
    format: str = "markdown"   # "markdown" | "docx"


@app.post("/api/clinical-ai/model-card")
def clinical_model_card(req: ModelCardRequest):
    if req.format == "docx":
        data = model_card.generate_docx(**req.dict(exclude={"format"}))
        from fastapi.responses import Response
        return Response(content=data,
                        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": "attachment; filename=model_card.docx"})
    md = model_card.generate_markdown(**req.dict(exclude={"format"}))
    return {"format": "markdown", "report": md}


def main() -> None:
    import uvicorn
    uvicorn.run("api.server:app", host=settings.api_host, port=settings.api_port, reload=False)


if __name__ == "__main__":
    main()
