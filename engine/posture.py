"""
Posture / Gap Analyzer
======================
Core engine for the policy validation feature. Takes any CVE attack chain (or
a stack's worth of chains) and asks the graph: "for each capability the
attacker would gain at each step, is there a Control node tagged with a
mitigation for that capability?"

Outputs three views the UI consumes:

    1. coverage()           - capability x OSI matrix of YES / NO / PARTIAL
    2. gaps_for_cve(id)     - prioritized gaps for a specific CVE chain
    3. replay_for_cve(id)   - per-step trace ("step 3 grants RCE → blocked by
                              control X" or "no control found - GAP")
    4. coverage_for_stack() - aggregate over an SBOM upload
"""

from __future__ import annotations

from collections import defaultdict

from .attack_chain import build_chain
from .graph import run_read
from .policy_capabilities import (
    ALL_CAPS,
    for_capability,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _existing_classes() -> set[str]:
    """Distinct capability_classes currently present in the graph."""
    rows = run_read("""
        MATCH (c:Control)
        WHERE c.capability_classes IS NOT NULL
        UNWIND c.capability_classes AS cls
        RETURN DISTINCT cls AS cls
    """)
    return {r["cls"] for r in rows if r.get("cls")}


def _controls_for_capability(cap: str) -> list[dict]:
    """Return all Control nodes in the graph that mitigate a capability."""
    return run_read(
        """
        MATCH (c:Control)
        WHERE $cap IN coalesce(c.capabilities_mitigated, [])
        OPTIONAL MATCH (p:Policy)-[:CONTAINS]->(c)
        RETURN c.id AS id, c.title AS title, c.effect AS effect,
               c.layer AS layer, c.capability_classes AS classes,
               p.id AS policy_id, p.source AS source, p.name AS policy_name
        ORDER BY p.source, c.layer
        LIMIT 50
    """,
        cap=cap,
    )


# ---------------------------------------------------------------------------
# 1. Capability x OSI coverage matrix
# ---------------------------------------------------------------------------
def coverage() -> dict:
    """For each (capability, layer) pair, count Controls present."""
    present = _existing_classes()
    classes_per_cap = {cap: [c.name for c in for_capability(cap)] for cap in ALL_CAPS}
    rows = run_read("""
        MATCH (c:Control)
        UNWIND coalesce(c.capabilities_mitigated, []) AS cap
        RETURN cap AS cap, c.layer AS layer, count(DISTINCT c) AS n
    """)
    matrix: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        matrix[r["cap"]][r["layer"]] += r["n"]
    out_caps = []
    for cap in sorted(ALL_CAPS):
        recommended_classes = classes_per_cap[cap]
        present_classes = [c for c in recommended_classes if c in present]
        coverage_pct = (
            (len(present_classes) / len(recommended_classes) * 100) if recommended_classes else 0.0
        )
        layer_counts = {f"L{l}": matrix[cap].get(l, 0) for l in range(1, 8)}
        out_caps.append(
            {
                "capability": cap,
                "controls_total": sum(layer_counts.values()),
                "by_layer": layer_counts,
                "coverage_pct": round(coverage_pct, 1),
                "recommended_classes": recommended_classes,
                "present_classes": present_classes,
                "missing_classes": [c for c in recommended_classes if c not in present],
            }
        )
    # Per-layer totals (handy for the UI)
    by_layer = {f"L{l}": sum(matrix[c].get(l, 0) for c in ALL_CAPS) for l in range(1, 8)}
    return {"matrix": out_caps, "by_layer": by_layer, "policies_loaded": _policy_summary()}


def _policy_summary() -> dict:
    rows = run_read("""
        MATCH (p:Policy)
        RETURN p.source AS source, count(p) AS n
    """)
    return {r["source"]: r["n"] for r in rows}


# ---------------------------------------------------------------------------
# 2. Gaps for a specific CVE
# ---------------------------------------------------------------------------
def gaps_for_cve(cve_id: str) -> dict:
    """Return per-step gap analysis for the top attack chain seeded at this CVE."""
    chains = build_chain(cve_id, max_depth=4, branch=4)
    if not chains:
        return {"cve": cve_id, "chains": [], "gaps": [], "blocks": []}
    chain = chains[0]
    gaps: list[dict] = []
    blocks: list[dict] = []

    for step in chain["steps"]:
        # Capabilities the attacker GAINS at this step
        for cap in step.get("gain", []):
            controls = _controls_for_capability(cap)
            if controls:
                blocks.append(
                    {
                        "cve": step["cve"],
                        "step_layer": step["layer_to"],
                        "capability": cap,
                        "controls": controls[:3],
                        "summary": f"{cap} blocked by {len(controls)} control(s) "
                        f"({', '.join(c.get('source', '?') for c in controls[:3])})",
                    }
                )
            else:
                # Is there even a recommended control class for this capability?
                rec = for_capability(cap)
                gaps.append(
                    {
                        "cve": step["cve"],
                        "step_layer": step["layer_to"],
                        "capability": cap,
                        "severity": _gap_severity(cap, step),
                        "recommended_classes": [c.name for c in rec],
                        "remediations": [
                            {
                                "title": c.title,
                                "platforms": sorted(c.platforms),
                                "snippet": c.remediation,
                            }
                            for c in rec[:3]
                        ],
                    }
                )

    gaps.sort(key=lambda g: -_severity_rank(g["severity"]))
    return {
        "cve": cve_id.upper(),
        "chain": chain,
        "gaps": gaps,
        "blocks": blocks,
        "gap_count": len(gaps),
        "block_count": len(blocks),
    }


def _gap_severity(cap: str, step: dict) -> str:
    high_caps = {"RCE", "AUTH_BYPASS", "INTERNAL_HTTP", "DATA_EXFIL", "PRIV_ESC"}
    med_caps = {"MITM_NET", "DECRYPT_TLS", "READ_FS", "WRITE_FS", "LATERAL_LAN"}
    if cap in high_caps:
        return "HIGH"
    if cap in med_caps:
        return "MEDIUM"
    return "LOW"


def _severity_rank(s: str) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0)


# ---------------------------------------------------------------------------
# 3. Per-step replay (timeline view)
# ---------------------------------------------------------------------------
def replay_for_cve(cve_id: str) -> dict:
    """Step-by-step trace through the chain showing which steps your policies block."""
    chains = build_chain(cve_id, max_depth=4, branch=4)
    if not chains:
        return {"cve": cve_id, "steps": []}
    chain = chains[0]
    timeline: list[dict] = []
    for i, step in enumerate(chain["steps"], 1):
        step_blocks = []
        step_gaps = []
        for cap in step.get("gain", []):
            cs = _controls_for_capability(cap)
            if cs:
                step_blocks.append({"capability": cap, "control": cs[0], "extra": len(cs) - 1})
            else:
                step_gaps.append(
                    {"capability": cap, "recommended": [c.name for c in for_capability(cap)][:3]}
                )
        verdict = (
            "BLOCKED"
            if step_blocks and not step_gaps
            else "PARTIAL"
            if step_blocks and step_gaps
            else "EXPLOITABLE"
            if step_gaps
            else "INFO"
        )
        timeline.append(
            {
                "n": i,
                "cve": step["cve"],
                "layer_from": step.get("layer_from"),
                "layer_to": step["layer_to"],
                "transition": step.get("transition"),
                "verdict": verdict,
                "blocks": step_blocks,
                "gaps": step_gaps,
            }
        )
    return {
        "cve": cve_id.upper(),
        "chain_score": chain["score"],
        "layers": chain["layers_traversed"],
        "steps": timeline,
        "summary": _verdict_summary(timeline),
    }


def _verdict_summary(timeline: list[dict]) -> dict:
    counts = {"BLOCKED": 0, "PARTIAL": 0, "EXPLOITABLE": 0, "INFO": 0}
    for s in timeline:
        counts[s["verdict"]] = counts.get(s["verdict"], 0) + 1
    counts["overall"] = (
        "BLOCKED"
        if counts["EXPLOITABLE"] == 0 and counts["BLOCKED"] > 0
        else "PARTIAL"
        if counts["BLOCKED"] > 0
        else "EXPLOITABLE"
    )
    return counts


# ---------------------------------------------------------------------------
# 4. Stack coverage (uses SBOM scan output)
# ---------------------------------------------------------------------------
def coverage_for_stack(purls: list[str]) -> dict:
    """Aggregate posture across every CVE affecting the given packages."""
    rows = run_read(
        """
        MATCH (p:Package)<-[:AFFECTS]-(c:CVE)
        WHERE p.purl IN $purls
        RETURN c.id AS id, c.cvss_score AS cvss
        ORDER BY coalesce(c.cvss_score,0) DESC LIMIT 30
    """,
        purls=purls,
    )
    seeds = [r["id"] for r in rows]
    aggregate_gaps: dict[str, dict] = {}
    aggregate_blocks: dict[str, dict] = {}
    for cid in seeds:
        g = gaps_for_cve(cid)
        for gap in g["gaps"]:
            key = (gap["capability"], gap["step_layer"])
            existing = aggregate_gaps.setdefault(str(key), {**gap, "count": 0, "cves": []})
            existing["count"] += 1
            existing["cves"].append(gap["cve"])
        for blk in g["blocks"]:
            key = (blk["capability"], blk["step_layer"])
            existing = aggregate_blocks.setdefault(str(key), {**blk, "count": 0})
            existing["count"] += 1
    gaps_sorted = sorted(
        aggregate_gaps.values(), key=lambda x: (-_severity_rank(x.get("severity", "")), -x["count"])
    )
    return {
        "cve_seeds": seeds,
        "gaps": gaps_sorted[:25],
        "blocks": list(aggregate_blocks.values())[:25],
        "summary": {
            "seeds": len(seeds),
            "distinct_gap_keys": len(aggregate_gaps),
            "distinct_block_keys": len(aggregate_blocks),
        },
    }
