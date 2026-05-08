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
import json
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
from engine import trust_scoring, supply_chain, threat_feeds, phi_lineage
from engine import ai_vendor_config as _vendor_audit
from engine import mcp_gate
from engine import model_gate as _model_gate
from engine import model_corpus as _model_corpus
from engine import zero_day_defense as _zdd
from engine import siem_generator as _siem
from engine import personalized_risk as _prisk
from engine import data_freshness as _freshness
from engine import model_gate_petri as _petri
from engine import petri_scenarios as _petri_scenarios
from engine import predictive as _predictive
from engine import external_finding_prioritizer as _ext_prio
from ingest.sbom import scan as sbom_scan
from ingest.telemetry import ingest_kev, kev_summary
from ingest.policies import parse_any as parse_policy
from ingest.policies.upsert import upsert_policies
from ingest import inventory as _inventory
from ingest.inventory import enrichment as _enrichment

UI_DIR = Path(__file__).resolve().parent.parent / "ui"

from contextlib import asynccontextmanager
import threading


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # ---- startup ----
    # Kick off threat-feed background refresher in a daemon thread so the
    # API isn't blocked. First refresh starts immediately; then every 6h.
    stop_event = threading.Event()
    feed_thread = threading.Thread(
        target=threat_feeds.background_loop,
        kwargs={"stop_event": stop_event, "interval_seconds": 6 * 3600},
        daemon=True, name="nikruvx-threat-feeds",
    )
    feed_thread.start()
    try:
        yield
    finally:
        # ---- shutdown ----
        stop_event.set()
        close_driver()


app = FastAPI(title="Cybersecurity Nexus", version="1.0.0",
              description="Graph-powered CVE/CWE/Package/AI-Threat nexus across all 7 OSI layers",
              lifespan=_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


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
            ORDER BY layer
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
        ORDER BY source, name LIMIT 500
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


# =====================================================================
# Asset Inventory (third-party application surface)
# =====================================================================
@app.post("/api/inventory/scan")
def inventory_scan() -> dict:
    """Walk the host: desktop binaries + browser ext + IDE ext + MCP servers."""
    summary = _inventory.scan_all()
    return summary


@app.post("/api/inventory/enrich")
def inventory_enrich() -> dict:
    """Run OpenSSF Scorecard + GHSA cross-reference + trust score recompute."""
    return _enrichment.enrich_all()


@app.get("/api/inventory")
def inventory_list(
    provenance: str | None = None,
    category: str | None = None,
    min_score: float = 0.0,
    max_score: float = 100.0,
    limit: int = 200,
) -> dict:
    where = ["a.trust_score >= $min", "a.trust_score <= $max"]
    if provenance: where.append("a.provenance = $prov")
    if category:   where.append("a.category = $cat")
    where_clause = "WHERE " + " AND ".join(where)
    # ORDER BY uses the projected map alias `app.<prop>` -- after `count()`
    # aggregation the source variable `a` is no longer in scope.
    rows = run_read(f"""
        MATCH (a:Application)
        {where_clause}
        OPTIONAL MATCH (cve:CVE)-[:AFFECTS]->(a)
        RETURN a{{.id, .name, .version, .publisher, .category,
                  .provenance, .trust_score, .trust_band,
                  .source_url, .permissions}} AS app,
               count(DISTINCT cve) AS cve_count
        ORDER BY app.trust_score ASC, cve_count DESC
        LIMIT $limit
    """, prov=provenance, cat=category,
        min=min_score, max=max_score, limit=limit)
    return {"applications": rows, "count": len(rows)}


@app.get("/api/inventory/{app_id}")
def inventory_get(app_id: str) -> dict:
    rows = run_read("""
        MATCH (a:Application {id: $id})
        OPTIONAL MATCH (cve:CVE)-[:AFFECTS]->(a)
        OPTIONAL MATCH (a)-[:USES_DEPENDENCY]->(p:Package)
        RETURN a{.*} AS app,
               collect(DISTINCT cve{.id, .severity, .cvss_score})[0..50] AS cves,
               collect(DISTINCT p{.purl, .ecosystem, .name})[0..50] AS deps
    """, id=app_id)
    if not rows or not rows[0].get("app"):
        raise HTTPException(404, f"application {app_id} not found")
    return rows[0]


@app.get("/api/inventory/stats/provenance")
def inventory_stats_provenance() -> dict:
    """Hero-stat split: first_party vs third_party CVE exposure."""
    rows = run_read("""
        MATCH (a:Application)
        OPTIONAL MATCH (cve:CVE)-[:AFFECTS]->(a)
        WITH a.provenance AS prov, count(DISTINCT a) AS apps,
             count(DISTINCT cve) AS cves
        RETURN prov, apps, cves
    """)
    out = {"first_party": {"apps": 0, "cves": 0},
           "third_party": {"apps": 0, "cves": 0},
           "unknown": {"apps": 0, "cves": 0}}
    for r in rows:
        key = r.get("prov") or "unknown"
        if key in out:
            out[key]["apps"] = r["apps"]
            out[key]["cves"] = r["cves"]
    # ORDER BY must reference the alias, not the source variable, after aggregation.
    # `coalesce` keeps avg() sane when no Application nodes exist yet.
    by_cat = run_read("""
        MATCH (a:Application)
        RETURN a.category AS category, a.provenance AS provenance,
               count(a) AS n,
               avg(coalesce(a.trust_score, 0.0)) AS avg_trust
        ORDER BY category
    """)
    return {"by_provenance": out, "by_category": by_cat}


# =====================================================================
# Threat-feed orchestration (auto-fetched in the background)
# =====================================================================
@app.get("/api/threat-feeds/status")
def tf_status() -> dict:
    """Last fetched times + entry counts per source."""
    return threat_feeds.status()


@app.post("/api/threat-feeds/refresh")
def tf_refresh() -> dict:
    """Manual re-pull of every feed. Normally not needed - the background
    thread refreshes every 6 hours automatically."""
    return threat_feeds.refresh_all()


# =====================================================================
# Supply-Chain Risk Scanner
# =====================================================================
@app.get("/api/supply-chain/scan-package")
def sc_scan_package(eco: str, name: str, version: str | None = None) -> dict:
    """Risk report for a package by ecosystem + name."""
    return supply_chain.analyze_package(eco, name, version)


@app.get("/api/supply-chain/scan-github")
def sc_scan_github(url: str) -> dict:
    """Risk report for a GitHub URL."""
    return supply_chain.analyze_github_url(url)


@app.post("/api/supply-chain/scan-inventory")
def sc_scan_inventory() -> dict:
    """Cross-reference current inventory against the malicious-package feed."""
    return supply_chain.scan_inventory_against_malicious()


# --------------------------- PHI Lineage -----------------------------------
class _LineageEvent(BaseModel):
    prompt_text: str = ""
    response_text: str = ""
    actor_id: str = "unknown"
    application_name: str = "unknown-app"
    model_name: str = ""
    vendor_id: str = ""
    vendor_name: str = ""
    region_code: str = ""
    source_name: str = "unknown-source"
    sinks: list[dict[str, Any]] = []
    evidence_grade: str = "OBSERVED"
    evidence_ref: str = ""


class _BAARequest(BaseModel):
    baa_id: str
    counterparty_vendor_id: str
    effective: str
    expires: str
    doc_hash: str = ""
    term_ids: list[str] = []


class _VendorRequest(BaseModel):
    vendor_id: str
    name: str
    region_code: str | None = None
    operates_in_regions: list[str] = []
    subprocessors: list[str] = []


@app.post("/api/lineage/event")
def lineage_event(ev: _LineageEvent) -> dict:
    """Record one PHI-lineage event (prompt -> model -> vendor -> sinks)."""
    return phi_lineage.record_call(phi_lineage.CallEvent(**ev.model_dump()))


@app.get("/api/lineage/broken-baa")
def lineage_broken_baa(window_hours: int = 24, limit: int = 200) -> dict:
    """PHI flows in the last N hours whose terminal vendor is missing or
    has missing required BAA terms."""
    rows = phi_lineage.find_broken_baa_chains(window_hours=window_hours, limit=limit)
    return {"window_hours": window_hours, "count": len(rows), "rows": rows}


@app.get("/api/lineage/replay/{prompt_id}")
def lineage_replay(prompt_id: str) -> dict:
    """Full hop list for a single prompt id, with BAA status per AIVendor."""
    return phi_lineage.replay_incident(prompt_id)


@app.get("/api/lineage/coverage")
def lineage_coverage() -> dict:
    """Per-AIVendor PHI-call counts + BAA status + missing terms."""
    rows = phi_lineage.vendor_coverage_report()
    return {"count": len(rows), "rows": rows}


@app.get("/api/lineage/stats")
def lineage_stats() -> dict:
    return phi_lineage.stats()


@app.post("/api/lineage/seed-terms")
def lineage_seed_terms() -> dict:
    n = phi_lineage.seed_baa_terms()
    return {"seeded_terms": n}


@app.post("/api/lineage/baa")
def lineage_register_baa(req: _BAARequest) -> dict:
    phi_lineage.register_baa(**req.model_dump())
    return {"status": "ok", "baa_id": req.baa_id}


@app.post("/api/lineage/vendor")
def lineage_register_vendor(req: _VendorRequest) -> dict:
    phi_lineage.register_vendor(**req.model_dump())
    return {"status": "ok", "vendor_id": req.vendor_id}


@app.post("/api/lineage/inspect-mcp")
def lineage_inspect_mcp(emit_call_events: bool = False) -> dict:
    """Run the MCP-server PHI inspector against installed servers."""
    from ingest.lineage.mcp_inspector import inspect
    return inspect(emit_call_events=emit_call_events)


# --------------------------- Vendor Config Auditor -------------------------
class _VendorAuditRequest(BaseModel):
    vendor_id: str
    config: dict[str, Any] = {}


@app.post("/api/lineage/audit-vendor")
def lineage_audit_vendor(req: _VendorAuditRequest) -> dict:
    """Audit one AI-vendor config dict against the canonical rule catalog."""
    return _vendor_audit.audit(req.vendor_id, req.config)


# --------------------------- MCP Gate --------------------------------------
class _McpReviewRequest(BaseModel):
    config: dict[str, Any]
    persist: bool = False


class _McpShadowRequest(BaseModel):
    approved: list[str] = []


@app.post("/api/mcp-gate/review")
def mcp_gate_review(req: _McpReviewRequest) -> dict:
    """Run the static review against one MCP config dict (or full
    claude_desktop_config.json with `mcpServers`)."""
    review = (mcp_gate.review_dict_from_json(json.dumps(req.config))
              if "mcpServers" in req.config
              else mcp_gate.review_config(req.config))
    if req.persist:
        mcp_gate.persist(review)
    from dataclasses import asdict
    return {
        "verdict": review.verdict,
        "target_name": review.target_name,
        "auth_method": review.auth_method,
        "transport": review.transport,
        "inferred_permissions": review.inferred_permissions,
        "declared_tools": review.declared_tools,
        "findings": [asdict(f) for f in review.findings],
        "worst_severity": review.worst_severity(),
    }


@app.post("/api/mcp-gate/review-installed")
def mcp_gate_review_installed(persist: bool = False) -> dict:
    reviews = mcp_gate.review_inventory()
    if persist:
        for r in reviews:
            mcp_gate.persist(r)
    from dataclasses import asdict
    return {
        "count": len(reviews),
        "reviews": [{
            "target_name": r.target_name,
            "verdict": r.verdict,
            "auth_method": r.auth_method,
            "transport": r.transport,
            "worst_severity": r.worst_severity(),
            "findings_count": len(r.findings),
            "findings": [asdict(f) for f in r.findings],
        } for r in reviews],
    }


@app.get("/api/mcp-gate/approvals")
def mcp_gate_approvals(status: str | None = None) -> dict:
    rows = mcp_gate.list_approvals(status=status)
    return {"count": len(rows), "rows": rows}


@app.get("/api/mcp-gate/approval/{target_name}")
def mcp_gate_approval(target_name: str) -> dict:
    out = mcp_gate.get_approval(target_name)
    if not out:
        raise HTTPException(status_code=404, detail="No approval found")
    return out


@app.post("/api/mcp-gate/shadow-check")
def mcp_gate_shadow(req: _McpShadowRequest) -> dict:
    return mcp_gate.shadow_check(req.approved)


# --------------------------- Model Gate ------------------------------------
class _ModelEvalRequest(BaseModel):
    model_spec: str
    categories: list[str] | None = None
    severities: list[str] | None = None
    probe_ids: list[str] | None = None
    parallel: int = 4
    persist: bool = False


class _ModelDiffRequest(BaseModel):
    candidate_spec: str
    baseline_spec: str
    categories: list[str] | None = None
    parallel: int = 4
    persist: bool = False


@app.post("/api/model-gate/evaluate")
def model_gate_evaluate(req: _ModelEvalRequest) -> dict:
    """Run the regression suite (or filtered subset) against one model spec."""
    from dataclasses import asdict
    res = _model_gate.evaluate(
        req.model_spec,
        categories=req.categories,
        severities=req.severities,
        probe_ids=req.probe_ids,
        parallel=req.parallel,
        persist_result=req.persist,
    )
    return asdict(res)


@app.post("/api/model-gate/diff")
def model_gate_diff(req: _ModelDiffRequest) -> dict:
    """Run the suite against a candidate and a baseline; return only the
    deltas (new failures + fixed)."""
    cand = _model_gate.evaluate(req.candidate_spec, categories=req.categories,
                                 parallel=req.parallel,
                                 persist_result=req.persist)
    base = _model_gate.evaluate(req.baseline_spec, categories=req.categories,
                                 parallel=req.parallel,
                                 persist_result=req.persist)
    return _model_gate.regression_diff(cand, base)


@app.get("/api/model-gate/evals")
def model_gate_evals(limit: int = 50) -> dict:
    rows = _model_gate.list_evals(limit=limit)
    return {"count": len(rows), "rows": rows}


@app.get("/api/model-gate/eval/{eval_id}")
def model_gate_eval(eval_id: str) -> dict:
    out = _model_gate.get_eval(eval_id)
    if not out:
        raise HTTPException(status_code=404, detail="No such eval")
    return out


@app.get("/api/model-gate/corpus")
def model_gate_corpus() -> dict:
    """Return the probe catalog so the UI can render category filters."""
    return {
        "total": len(_model_corpus.CORPUS),
        "categories": _model_corpus.categories_in_corpus(),
        "probes": [{
            "id": p.id, "category": p.category, "severity": p.severity,
            "title": p.title, "grader": p.grader, "ref": p.ref,
        } for p in _model_corpus.CORPUS],
    }


# --------------------------- Zero-Day Defense ------------------------------
@app.post("/api/zero-day/seed")
def zdd_seed() -> dict:
    """Seed all three catalogs (techniques, defenses, patterns) into the graph."""
    return _zdd.seed_all()


@app.get("/api/zero-day/stats")
def zdd_stats() -> dict:
    return _zdd.stats()


@app.get("/api/zero-day/coverage")
def zdd_coverage() -> dict:
    return _zdd.coverage_matrix()


@app.get("/api/zero-day/coverage/gaps")
def zdd_coverage_gaps() -> dict:
    rows = _zdd.coverage_gaps()
    return {"count": len(rows), "rows": rows}


@app.get("/api/zero-day/coverage/installed")
def zdd_installed_coverage() -> dict:
    return _zdd.installed_coverage()


@app.get("/api/zero-day/patterns")
def zdd_patterns(layer: int | None = None,
                 ai_only: bool = False,
                 severity: str | None = None,
                 predicted_only: bool = False,
                 historical_only: bool = False,
                 mitigation_window: str | None = None) -> dict:
    rows = _zdd.list_patterns(
        layer=layer, ai_only=ai_only, severity=severity,
        predicted_only=predicted_only, historical_only=historical_only,
        mitigation_window=mitigation_window,
    )
    return {"count": len(rows), "rows": rows}


@app.get("/api/zero-day/ai-landscape")
def zdd_ai_landscape() -> dict:
    """Anticipatory-defense view: AI-discovered + AI-anticipated forecast."""
    return _zdd.ai_threat_landscape()


# --- v2: SIEM rule generator ---
class _SiemFromIndicator(BaseModel):
    indicator: str
    technique_id: str
    severity: str = "medium"
    title: str | None = None


@app.post("/api/zero-day/siem/from-indicator")
def zdd_siem_from_indicator(req: _SiemFromIndicator) -> dict:
    return _siem.to_dict(_siem.generate_for_indicator(
        req.indicator, req.technique_id, req.severity, req.title))


@app.get("/api/zero-day/siem/from-pattern/{pattern_id}")
def zdd_siem_from_pattern(pattern_id: str) -> dict:
    rules = [_siem.to_dict(d) for d in _siem.generate_for_pattern(pattern_id)]
    if not rules:
        raise HTTPException(status_code=404, detail="No pattern or no indicators")
    return {"count": len(rules), "rules": rules,
            "formats": _siem.available_formats()}


# --- v2: Personalized risk ---
@app.get("/api/zero-day/personalized-risk")
def zdd_personalized_risk(top_n: int = 50) -> dict:
    return {"items": _prisk.compute_exposure(top_n=top_n)}


@app.get("/api/zero-day/personalized-risk/summary")
def zdd_personalized_risk_summary() -> dict:
    return _prisk.summary()


# --- v2: RSS threat-intel + Model Gate cross-reference ---
@app.post("/api/zero-day/rss/sweep")
def zdd_rss_sweep(auto_file: bool = True,
                  use_llm: bool = False,
                  llm_timeout: float = 15.0) -> dict:
    """Default = fast regex extraction. Pass use_llm=true to enable Ollama
    extraction (requires Ollama running; per-entry timeout protects against
    hangs)."""
    from ingest.threat_intel_rss import ingest_all
    return ingest_all(auto_file=auto_file, use_llm=use_llm,
                      llm_timeout=llm_timeout)


@app.post("/api/zero-day/rss/feed/{feed_id}")
def zdd_rss_feed(feed_id: str, auto_file: bool = True,
                 use_llm: bool = False,
                 llm_timeout: float = 15.0) -> dict:
    from ingest.threat_intel_rss import DEFAULT_FEEDS, import_feed
    feed = next((f for f in DEFAULT_FEEDS if f["id"] == feed_id), None)
    if not feed:
        raise HTTPException(status_code=404, detail=f"Unknown feed id: {feed_id}")
    return import_feed(feed, auto_file=auto_file,
                       use_llm=use_llm, llm_timeout=llm_timeout)


@app.get("/api/zero-day/rss/recent")
def zdd_rss_recent(limit: int = 50) -> dict:
    from ingest.threat_intel_rss import list_recent_advisories
    rows = list_recent_advisories(limit=limit)
    return {"count": len(rows), "rows": rows}


@app.post("/api/zero-day/import-from-model-gate")
def zdd_import_model_gate(min_severity: str = "high",
                          max_age_days: int = 30) -> dict:
    return _zdd.import_from_model_gate(
        min_severity=min_severity, max_age_days=max_age_days)


# --------------------------- Data Sources Freshness ------------------------
@app.get("/api/data-sources")
def data_sources_status() -> dict:
    """Per-source dashboard: count, last refresh, in-flight job state."""
    rows = _freshness.status_all()
    return {"count": len(rows), "rows": rows}


@app.get("/api/data-sources/{source_id}")
def data_source_one(source_id: str) -> dict:
    out = _freshness.status_one(source_id)
    if not out:
        raise HTTPException(status_code=404, detail=f"Unknown source: {source_id}")
    return out


@app.post("/api/data-sources/{source_id}/refresh")
def data_source_refresh(source_id: str) -> dict:
    """Trigger refresh; long-running tasks run in a background thread.
    Returns immediately with a job id."""
    return _freshness.refresh(source_id)


@app.post("/api/data-sources/refresh-all")
def data_sources_refresh_all() -> dict:
    """Kick off refresh for every source that supports it."""
    return _freshness.refresh_all()


# --------------------------- Petri Multi-turn Audits -----------------------
class _PetriRunRequest(BaseModel):
    target_spec: str
    auditor_spec: str
    scenario_id: str
    judge_spec: str | None = None
    persist: bool = False
    bridge_to_zero_day: bool = False


@app.get("/api/petri/scenarios")
def petri_scenarios_list() -> dict:
    """Return the curated Petri scenario catalog."""
    return {
        "count": len(_petri_scenarios.PETRI_SCENARIOS),
        "categories": _petri_scenarios.CATEGORIES,
        "scenarios": [{
            "id": s.id, "title": s.title, "category": s.category,
            "severity": s.severity, "hypothesis": s.hypothesis,
            "max_turns": s.max_turns,
        } for s in _petri_scenarios.PETRI_SCENARIOS],
    }


@app.get("/api/petri/scenario/{scenario_id}")
def petri_scenario(scenario_id: str) -> dict:
    s = _petri_scenarios.by_id(scenario_id)
    if not s:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    from dataclasses import asdict
    return asdict(s)


@app.post("/api/petri/run")
def petri_run(req: _PetriRunRequest) -> dict:
    """Run a single multi-turn audit. May take 30-90 seconds with real
    models — consider running off the API thread in production."""
    from dataclasses import asdict
    result = _petri.run_audit(
        target_spec=req.target_spec,
        auditor_spec=req.auditor_spec,
        scenario_id=req.scenario_id,
        judge_spec=req.judge_spec,
        persist_result=req.persist,
    )
    bridged = None
    if req.bridge_to_zero_day and not result.passed and req.persist:
        bridged = _petri.bridge_to_zero_day(result.audit_id)
    out = asdict(result)
    out["bridged_zero_day_pattern"] = bridged
    return out


@app.get("/api/petri/audits")
def petri_audits(target_spec: str | None = None, limit: int = 50) -> dict:
    rows = _petri.list_audits(target_spec=target_spec, limit=limit)
    return {"count": len(rows), "rows": rows}


@app.get("/api/petri/audit/{audit_id}")
def petri_audit_one(audit_id: str) -> dict:
    out = _petri.get_audit(audit_id)
    if not out:
        raise HTTPException(status_code=404, detail="Unknown audit")
    return out


@app.get("/api/petri/stats")
def petri_stats() -> dict:
    return _petri.stats()


# --------------------------- Predictive Exposure Window --------------------
@app.get("/api/predictive/summary")
def predictive_summary() -> dict:
    """Top-level predictive forecast — techniques landing in 30/90 days,
    techniques with no installed coverage, top-5 by risk."""
    return _predictive.summary()


@app.get("/api/predictive/forecasts")
def predictive_forecasts() -> dict:
    """Full per-technique forecast list, sorted by risk_index."""
    rows = _predictive.forecast_all()
    return {"count": len(rows), "rows": rows}


@app.get("/api/predictive/technique/{technique_id}")
def predictive_technique(technique_id: str) -> dict:
    out = _predictive.forecast_for_technique(technique_id)
    if not out:
        raise HTTPException(status_code=404, detail="Unknown technique")
    return out


@app.get("/api/predictive/velocity")
def predictive_velocity() -> dict:
    return _predictive.velocity_per_technique()


# --------------------------- External Findings (Wiz/Snyk/etc) --------------
@app.post("/api/findings/upload")
async def findings_upload(
    file: UploadFile = File(...),
    source: str = Form(""),       # blank = auto-detect
    label: str = Form(""),
    persist: bool = Form(True),
) -> dict:
    """Upload a CSV from Wiz / Snyk / Tenable / Qualys / generic.
    Auto-detects format; pass `source` to override. Re-scores against
    your environment and persists as :ExternalFinding nodes."""
    from ingest.external_findings import parse_csv
    raw = await file.read()
    detected, findings = parse_csv(raw, source=source or None)
    scored = _ext_prio.re_score_batch(findings)
    bid = None
    if persist:
        bid = _ext_prio.persist_batch(scored, source=detected,
                                       batch_label=label or file.filename or "")
    bands: dict[str, int] = {}
    for s in scored:
        bands[s.priority_band] = bands.get(s.priority_band, 0) + 1
    from dataclasses import asdict
    return {
        "detected_source": detected,
        "imported": len(findings),
        "scored": len(scored),
        "batch_id": bid,
        "bands": bands,
        "top_10": [asdict(s) for s in
                    sorted(scored, key=lambda x: -x.nikruvx_score)[:10]],
    }


@app.get("/api/findings/batches")
def findings_batches(limit: int = 50) -> dict:
    rows = _ext_prio.list_batches(limit=limit)
    return {"count": len(rows), "rows": rows}


@app.get("/api/findings")
def findings_list(batch_id: str | None = None,
                  priority_band: str | None = None,
                  limit: int = 200) -> dict:
    rows = _ext_prio.list_findings(batch_id=batch_id,
                                    priority_band=priority_band, limit=limit)
    return {"count": len(rows), "rows": rows}


@app.get("/api/findings/export.csv")
def findings_export_csv(batch_id: str | None = None) -> "StreamingResponse":
    """Re-export the prioritized list as CSV (for feeding back into Wiz/Snyk
    or your ticketing system)."""
    rows = _ext_prio.list_findings(batch_id=batch_id, limit=10000)
    # Synthesize ScoredFinding-shaped objects for the existing exporter

    class _S:  # noqa: N801
        def __init__(self, r: dict):
            import json as _json
            self.finding = {
                "cve_id": r.get("cve_id"), "package": r.get("package"),
                "version": r.get("version"),
                "original_severity": r.get("original_severity"),
                "original_cvss": r.get("original_cvss"),
                "title": r.get("title"), "source": r.get("source"),
            }
            self.nikruvx_score = r.get("nikruvx_score", 0)
            self.priority_band = r.get("priority_band", "")
            self.in_kev = r.get("in_kev", False)
            self.has_poc = r.get("has_poc", False)
            self.coverage_ratio = r.get("coverage_ratio", 0.0)
            self.recommended_action = r.get("recommended_action", "")
            self.matched_techniques: list[str] = []
            try:
                self.adjustments = _json.loads(r.get("adjustments_json") or "[]")
            except Exception:
                self.adjustments = []
    csv_text = _ext_prio.to_export_csv([_S(r) for r in rows])
    return StreamingResponse(
        iter([csv_text]),
        media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="nikruvx-findings-{batch_id or "all"}.csv"'},
    )


@app.get("/api/zero-day/pattern/{pattern_id}")
def zdd_pattern(pattern_id: str) -> dict:
    out = _zdd.recommend_for_pattern(pattern_id)
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    return out


@app.get("/api/zero-day/techniques")
def zdd_techniques(layer: int | None = None,
                   tactic: str | None = None) -> dict:
    rows = _zdd.list_techniques(layer=layer, tactic=tactic)
    return {"count": len(rows), "rows": rows}


@app.get("/api/zero-day/recommend")
def zdd_recommend(technique: str) -> dict:
    out = _zdd.recommend_defenses(technique)
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    return out


@app.get("/api/zero-day/defenses")
def zdd_defenses(tactic: str | None = None) -> dict:
    rows = _zdd.list_defenses(tactic=tactic)
    return {"count": len(rows), "rows": rows}


@app.get("/api/lineage/vendor-rules")
def lineage_vendor_rules(vendor_id: str | None = None) -> dict:
    """List the rules in the catalog (filtered by vendor_id if given)."""
    rules = (_vendor_audit.applicable_rules(vendor_id)
             if vendor_id else _vendor_audit.VENDOR_RULES)
    return {
        "count": len(rules),
        "known_vendor_ids": sorted(_vendor_audit.all_known_vendor_ids()),
        "rules": [
            {"rule_id": r.rule_id,
             "vendor_ids": sorted(r.vendor_ids),
             "baa_term": r.baa_term,
             "title": r.title,
             "citation": r.citation,
             "remediation": r.remediation,
             "severity": r.severity}
            for r in rules
        ],
    }


def main() -> None:
    import uvicorn
    uvicorn.run("api.server:app", host=settings.api_host, port=settings.api_port, reload=False)


if __name__ == "__main__":
    main()
