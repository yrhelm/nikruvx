"""
Patch Twin Finder
=================
Find sibling CVEs that almost certainly share a root cause with the given CVE.
Patches commonly fix the named variant but miss its cousins (Log4Shell -> 5
follow-ups, Spring4Shell -> many).

Heuristic (combined score):
   0.55 * embedding cosine similarity (if available)
 + 0.25 * shared CWE overlap
 + 0.10 * shared OSI layer overlap
 + 0.10 * shared affected package overlap
"""
from __future__ import annotations
from .graph import run_read
from . import dna


def _row_for(cve_id: str) -> dict | None:
    rows = run_read("""
        MATCH (c:CVE {id: $id})
        OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
        OPTIONAL MATCH (c)-[:AFFECTS]->(p:Package)
        RETURN c.id AS id,
               collect(DISTINCT w.id) AS cwes,
               collect(DISTINCT l.number) AS layers,
               collect(DISTINCT p.purl) AS purls
    """, id=cve_id.upper())
    return rows[0] if rows else None


def find_twins(cve_id: str, k: int = 10) -> list[dict]:
    cve_id = cve_id.upper()
    src = _row_for(cve_id)
    if not src:
        return []
    src_cwes = set(src["cwes"])
    src_layers = set(src["layers"])
    src_pkgs = set(src["purls"])

    # 1) Pull semantic neighbors (or lexical fallback)
    sims = {s["id"]: s.get("score", 0.0) for s in dna.similar(cve_id, k=40)}

    # 2) Score combined
    cands = run_read("""
        MATCH (c:CVE)
        WHERE c.id <> $id AND c.id IN $ids
        OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
        OPTIONAL MATCH (c)-[:AFFECTS]->(p:Package)
        RETURN c.id AS id, c.severity AS severity, c.cvss_score AS cvss,
               c.description AS description,
               collect(DISTINCT w.id) AS cwes,
               collect(DISTINCT l.number) AS layers,
               collect(DISTINCT p.purl) AS purls
    """, id=cve_id, ids=list(sims.keys()))

    scored: list[dict] = []
    for r in cands:
        emb = sims.get(r["id"], 0.0)
        cwe_o = _jacc(set(r["cwes"]), src_cwes)
        layer_o = _jacc(set(r["layers"]), src_layers)
        pkg_o = _jacc(set(r["purls"]), src_pkgs)
        combined = 0.55 * emb + 0.25 * cwe_o + 0.10 * layer_o + 0.10 * pkg_o
        scored.append({
            "id": r["id"],
            "severity": r["severity"],
            "cvss": r["cvss"],
            "description": (r["description"] or "")[:200],
            "shared_cwes": sorted(set(r["cwes"]) & src_cwes),
            "shared_layers": sorted(set(r["layers"]) & src_layers),
            "shared_packages": sorted(set(r["purls"]) & src_pkgs),
            "twin_score": round(combined, 3),
            "components": {
                "semantic": round(emb, 3),
                "cwe_overlap": round(cwe_o, 3),
                "layer_overlap": round(layer_o, 3),
                "package_overlap": round(pkg_o, 3),
            },
        })

    # Strong candidates only
    scored = [s for s in scored if s["twin_score"] >= 0.20]
    scored.sort(key=lambda x: x["twin_score"], reverse=True)
    return scored[:k]


def _jacc(a: set, b: set) -> float:
    if not a and not b: return 0.0
    return len(a & b) / max(1, len(a | b))
