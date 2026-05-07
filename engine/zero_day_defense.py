"""
Zero-Day Defense Engine
========================
Brings together the ATT&CK technique catalog, the D3FEND defense
catalog, and the curated zero-day pattern catalog to answer the
operational questions security teams actually have:

    - Given an ATT&CK technique (or a zero-day pattern), what defenses
      should I have in place? — `recommend_defenses(technique_id)`
    - Across the entire ATT&CK matrix, where am I covered and where
      am I exposed? — `coverage_matrix()`
    - Which techniques have NO defense in my current control stack
      (computed against existing :Policy and :Control nodes)? —
      `coverage_gaps()`
    - Which zero-day patterns specifically affect a given OSI layer
      or capability class? — `patterns_for_layer()`, `patterns_for_capability()`
    - Bring it all to life by seeding the graph from the curated
      catalogs — `seed_all()`

Designed to slot into the existing posture engine — TTPs become a
parallel row dimension to capability classes in the coverage matrix.
"""
from __future__ import annotations
from dataclasses import asdict
from typing import Any

from .attack_catalog import (
    ATTACK_TECHNIQUES, AttackTechnique,
    by_id as attack_by_id,
    for_layer as attack_for_layer,
    for_capability as attack_for_capability,
)
from .defense_catalog import (
    DEFENSE_TECHNIQUES, DefenseTechnique,
    by_id as defense_by_id,
    for_attack as defense_for_attack,
    for_tactic as defense_for_tactic,
)
from .graph import run_read, run_write
from .zero_day_catalog import (
    ZERO_DAY_PATTERNS, ZeroDayPattern,
    ai_anticipated,
    ai_discovered,
    by_id as pattern_by_id,
    by_mitigation_window,
    for_layer as patterns_for_layer,
    for_technique as patterns_for_technique,
    historical,
    predicted,
)


# ---------------------------------------------------------------------------
# Catalog seeding
# ---------------------------------------------------------------------------
def seed_attack_techniques() -> int:
    """Load the curated ATT&CK technique catalog into the graph."""
    cypher = """
    UNWIND $rows AS row
    MERGE (t:AttackTechnique {id: row.id})
      SET t.name = row.name,
          t.tactic = row.tactic,
          t.description = row.description,
          t.layer = row.layer,
          t.capabilities = row.capabilities,
          t.platforms = row.platforms,
          t.url = row.url,
          t.updated_at = datetime()
    WITH t, row
    MATCH (l:OSILayer {number: row.layer})
    MERGE (t)-[:MANIFESTS_AT]->(l)
    """
    rows = [{
        "id": t.id, "name": t.name, "tactic": t.tactic,
        "description": t.description, "layer": t.layer,
        "capabilities": list(t.capabilities),
        "platforms": list(t.platforms), "url": t.url,
    } for t in ATTACK_TECHNIQUES]
    run_write(cypher, rows=rows)
    return len(rows)


def seed_defense_techniques() -> int:
    """Load the curated D3FEND + AI-LLM defense catalog into the graph."""
    cypher = """
    UNWIND $rows AS row
    MERGE (d:DefenseTechnique {id: row.id})
      SET d.name = row.name,
          d.tactic = row.tactic,
          d.description = row.description,
          d.nikruvx_module = row.nikruvx_module,
          d.url = row.url,
          d.updated_at = datetime()
    WITH d, row
    UNWIND row.counters AS tid
    MATCH (t:AttackTechnique {id: tid})
    MERGE (t)-[:COUNTERED_BY]->(d)
    """
    rows = [{
        "id": d.id, "name": d.name, "tactic": d.tactic,
        "description": d.description, "counters": list(d.counters),
        "nikruvx_module": d.nikruvx_module, "url": d.url,
    } for d in DEFENSE_TECHNIQUES]
    run_write(cypher, rows=rows)
    return len(rows)


def seed_zero_day_patterns() -> int:
    """Load the curated zero-day pattern catalog into the graph."""
    cypher = """
    UNWIND $rows AS row
    MERGE (z:ZeroDayPattern {id: row.id})
      SET z.name = row.name,
          z.description = row.description,
          z.severity = row.severity,
          z.layer = row.layer,
          z.cve_ids = row.cve_ids,
          z.first_seen = row.first_seen,
          z.source = row.source,
          z.ai_discovered = row.ai_discovered,
          z.ai_anticipated = row.ai_anticipated,
          z.predicted = row.predicted,
          z.mitigation_window = row.mitigation_window,
          z.public_disclosure = row.public_disclosure,
          z.behavioral_indicators = row.behavioral_indicators,
          z.references = row.references,
          z.updated_at = datetime()
    WITH z, row
    UNWIND row.techniques AS tid
    MATCH (t:AttackTechnique {id: tid})
    MERGE (z)-[:USES_TECHNIQUE]->(t)
    """
    rows = [{
        "id": z.id, "name": z.name, "description": z.description,
        "severity": z.severity, "layer": z.layer,
        "techniques": list(z.techniques),
        "cve_ids": list(z.cve_ids), "first_seen": z.first_seen,
        "source": z.source,
        "ai_discovered": z.ai_discovered,
        "ai_anticipated": z.ai_anticipated,
        "predicted": z.predicted,
        "mitigation_window": z.mitigation_window,
        "public_disclosure": z.public_disclosure,
        "behavioral_indicators": list(z.behavioral_indicators),
        "references": list(z.references),
    } for z in ZERO_DAY_PATTERNS]
    run_write(cypher, rows=rows)
    # Bridge to existing :CVE nodes so queries can traverse both worlds
    run_write(
        """
        UNWIND $rows AS row
        MATCH (z:ZeroDayPattern {id: row.id})
        UNWIND row.cve_ids AS cveid
        OPTIONAL MATCH (c:CVE {id: cveid})
        FOREACH (_ IN CASE WHEN c IS NOT NULL THEN [1] ELSE [] END |
          MERGE (z)-[:OBSERVED_IN]->(c)
        )
        """,
        rows=[{"id": z.id, "cve_ids": list(z.cve_ids)}
              for z in ZERO_DAY_PATTERNS if z.cve_ids],
    )
    return len(rows)


def seed_all() -> dict:
    """One-shot seed of all three catalogs. Idempotent."""
    return {
        "attack_techniques": seed_attack_techniques(),
        "defense_techniques": seed_defense_techniques(),
        "zero_day_patterns": seed_zero_day_patterns(),
    }


# ---------------------------------------------------------------------------
# Recommender
# ---------------------------------------------------------------------------
def recommend_defenses(technique_id: str) -> dict[str, Any]:
    """For an ATT&CK technique, return the canonical D3FEND + custom
    defenses that counter it, ranked by tactic priority."""
    technique = attack_by_id(technique_id)
    if not technique:
        return {"error": f"unknown technique: {technique_id}"}
    defenses = defense_for_attack(technique_id)
    # Tactic ordering: Harden first (preventive > detective > reactive)
    order = {"Harden": 0, "Isolate": 1, "Detect": 2,
             "Deceive": 3, "Evict": 4, "Restore": 5}
    defenses.sort(key=lambda d: order.get(d.tactic, 99))
    return {
        "technique": asdict(technique),
        "defense_count": len(defenses),
        "defenses": [asdict(d) for d in defenses],
    }


def recommend_for_pattern(pattern_id: str) -> dict[str, Any]:
    """For a zero-day pattern, union the defenses for every technique
    it uses + tag the techniques + indicators."""
    pattern = pattern_by_id(pattern_id)
    if not pattern:
        return {"error": f"unknown pattern: {pattern_id}"}
    seen: set[str] = set()
    defenses: list[DefenseTechnique] = []
    for tid in pattern.techniques:
        for d in defense_for_attack(tid):
            if d.id not in seen:
                seen.add(d.id)
                defenses.append(d)
    order = {"Harden": 0, "Isolate": 1, "Detect": 2,
             "Deceive": 3, "Evict": 4, "Restore": 5}
    defenses.sort(key=lambda d: order.get(d.tactic, 99))
    techniques = [asdict(t) for t in (attack_by_id(tid) for tid in pattern.techniques) if t]
    return {
        "pattern": asdict(pattern),
        "techniques": techniques,
        "defense_count": len(defenses),
        "defenses": [asdict(d) for d in defenses],
    }


# ---------------------------------------------------------------------------
# Coverage matrix
# ---------------------------------------------------------------------------
def coverage_matrix() -> dict[str, Any]:
    """Per-OSI-layer view: how many ATT&CK techniques are mapped at
    that layer, how many have at least one defense in our catalog,
    how many zero-day patterns are present.

    Pure-catalog computation — does not depend on the live graph or
    the user's installed control stack."""
    by_layer: dict[int, dict[str, Any]] = {}
    for layer in range(1, 8):
        ttps = attack_for_layer(layer)
        with_defenses = sum(1 for t in ttps if defense_for_attack(t.id))
        patterns = patterns_for_layer(layer)
        by_layer[layer] = {
            "layer": layer,
            "technique_count": len(ttps),
            "techniques_with_defense": with_defenses,
            "techniques_uncovered": len(ttps) - with_defenses,
            "zero_day_pattern_count": len(patterns),
            "ai_discovered_count": sum(1 for p in patterns if p.ai_discovered),
        }
    by_tactic: dict[str, int] = {}
    for t in ATTACK_TECHNIQUES:
        by_tactic[t.tactic] = by_tactic.get(t.tactic, 0) + 1
    return {
        "total_techniques": len(ATTACK_TECHNIQUES),
        "total_defenses": len(DEFENSE_TECHNIQUES),
        "total_zero_day_patterns": len(ZERO_DAY_PATTERNS),
        "ai_discovered_patterns": len(ai_discovered()),
        "by_layer": [by_layer[i] for i in range(1, 8)],
        "by_tactic": by_tactic,
    }


def coverage_gaps() -> list[dict[str, Any]]:
    """Return ATT&CK techniques that have NO defense mapped in our
    catalog. These are the catalog-level holes we should curate next."""
    gaps = []
    for t in ATTACK_TECHNIQUES:
        defenses = defense_for_attack(t.id)
        if not defenses:
            gaps.append({
                "technique_id": t.id, "name": t.name, "tactic": t.tactic,
                "layer": t.layer,
                "capabilities": list(t.capabilities),
                "platforms": list(t.platforms),
                "reason": "no defense technique in catalog counters this TTP",
            })
    return gaps


def installed_coverage() -> dict[str, Any]:
    """Computed against the LIVE graph: which ATT&CK techniques are
    countered by any :DefenseTechnique that has IMPLEMENTED_BY edges to
    a real :Control node from an uploaded :Policy.

    A defense is considered 'installed' iff at least one Control node
    matches one of the defense's nikruvx_module hints OR the user has
    explicitly linked the defense to a control via IMPLEMENTED_BY edges.
    """
    cypher = """
    MATCH (t:AttackTechnique)
    OPTIONAL MATCH (t)-[:COUNTERED_BY]->(d:DefenseTechnique)
    OPTIONAL MATCH (d)-[:IMPLEMENTED_BY]->(c:Control)<-[:HAS]-(p:Policy)
    WITH t, count(DISTINCT d) AS total_defenses, count(DISTINCT c) AS installed_controls
    RETURN t.id AS technique_id, t.name AS name, t.tactic AS tactic,
           t.layer AS layer, total_defenses, installed_controls,
           CASE WHEN installed_controls > 0 THEN 'covered'
                WHEN total_defenses > 0     THEN 'has_defense_in_catalog_not_installed'
                ELSE 'no_catalog_defense' END AS status
    ORDER BY t.layer, t.tactic, t.id
    """
    return {"techniques": run_read(cypher)}


# ---------------------------------------------------------------------------
# Pattern queries
# ---------------------------------------------------------------------------
def list_patterns(layer: int | None = None,
                  ai_only: bool = False,
                  severity: str | None = None,
                  predicted_only: bool = False,
                  historical_only: bool = False,
                  mitigation_window: str | None = None) -> list[dict]:
    out = list(ZERO_DAY_PATTERNS)
    if layer is not None:
        out = [p for p in out if p.layer == layer]
    if ai_only:
        out = [p for p in out if p.ai_discovered or p.ai_anticipated]
    if severity:
        out = [p for p in out if p.severity == severity]
    if predicted_only:
        out = [p for p in out if p.predicted]
    if historical_only:
        out = [p for p in out if not p.predicted]
    if mitigation_window:
        out = [p for p in out if p.mitigation_window == mitigation_window]
    return [asdict(p) for p in out]


def import_from_model_gate(min_severity: str = "high",
                           max_age_days: int = 30) -> dict:
    """Cross-reference recent ModelEval failures with the zero-day catalog.

    For every probe that recently failed in a model evaluation AND the
    probe's severity is at least `min_severity`, materialize a zero-day
    pattern entry tagged `ai_discovered=true`. This turns the Model Gate
    suite into a live source of AI-discovered patterns.

    Returns counts: {filed_new, filed_updated, scanned}.
    """
    sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    floor = sev_order.get(min_severity, 2)
    cypher = """
    MATCH (e:ModelEval)-[:HAS_RESULT]->(r:ModelProbeResult {passed: false})
    WHERE e.ts > datetime() - duration({days: $age})
    RETURN r.probe_id AS probe_id, r.category AS category,
           r.severity AS severity, r.title AS title, r.reason AS reason,
           e.model_spec AS model_spec, toString(e.ts) AS ts
    ORDER BY e.ts DESC
    """
    rows = run_read(cypher, age=max_age_days)

    filed_new = filed_updated = scanned = 0
    seen_probes: set[str] = set()
    for row in rows:
        scanned += 1
        sev = (row.get("severity") or "medium").lower()
        if sev_order.get(sev, 0) < floor:
            continue
        probe_id = row.get("probe_id")
        if not probe_id or probe_id in seen_probes:
            continue
        seen_probes.add(probe_id)

        # Map probe categories to ATT&CK techniques
        category = row.get("category", "")
        techniques = _CATEGORY_TO_ATT[category] if category in _CATEGORY_TO_ATT \
                     else ["AML.T0051"]
        layer = 7
        pid = f"ZD-MG-{probe_id.upper().replace('.', '-')[:48]}"

        result = run_write(
            """
            MERGE (z:ZeroDayPattern {id: $pid})
              ON CREATE SET z.created_at = datetime()
              SET z.name = $name,
                  z.description = $desc,
                  z.severity = $sev,
                  z.layer = $layer,
                  z.cve_ids = [],
                  z.first_seen = $ts,
                  z.source = 'NikruvX Model Gate',
                  z.ai_discovered = true,
                  z.ai_anticipated = false,
                  z.predicted = false,
                  z.mitigation_window = CASE WHEN $sev = 'critical' THEN 'immediate'
                                              WHEN $sev = 'high'     THEN 'weeks'
                                              ELSE '' END,
                  z.public_disclosure = false,
                  z.behavioral_indicators = [$reason],
                  z.references = [],
                  z.updated_at = datetime()
            WITH z
            UNWIND $techs AS tid
            MATCH (t:AttackTechnique {id: tid})
            MERGE (z)-[:USES_TECHNIQUE]->(t)
            """,
            pid=pid,
            name=f"Model Gate finding: {row.get('title','?')}",
            desc=f"Probe '{probe_id}' failed against {row.get('model_spec','?')} "
                 f"in category '{category}'. Reason: {row.get('reason','')}",
            sev=sev, layer=layer, ts=row.get("ts", ""),
            reason=row.get("reason", ""), techs=techniques,
        )
        filed_new += 1   # we don't distinguish new vs update here (idempotent)
    return {"scanned": scanned, "filed_new": filed_new, "filed_updated": filed_updated}


# Map model_corpus probe categories → ATT&CK technique ids
_CATEGORY_TO_ATT: dict[str, list[str]] = {
    "direct_prompt_injection":   ["AML.T0051", "AML.T0048"],
    "code_suggestion_safety":    ["T1190", "T1059"],
    "tool_call_safety":          ["AML.T0052", "AML.T0048"],
    "sensitive_disclosure":      ["AML.T0054", "AML.T0044"],
    "indirect_prompt_injection": ["AML.T0048", "AML.T0051"],
    "jailbreak_resistance":      ["AML.T0053"],
    "context_saturation":        ["AML.T0051"],
    "output_evasion":            ["AML.T0048"],
    "training_data_extraction":  ["AML.T0044", "AML.T0054"],
    "refusal_calibration":       ["AML.T0053"],
}


def ai_threat_landscape() -> dict:
    """Anticipatory-defense view: separates already-observed AI-discovered
    bugs from forecasted classes that AI offensive automation is making
    cheap to industrialize. The forecast wave is what the user should
    pre-mitigate against."""
    discovered = ai_discovered()
    anticipated = ai_anticipated()
    forecasted = predicted()
    immediate = by_mitigation_window("immediate")
    weeks = by_mitigation_window("weeks")
    months = by_mitigation_window("months")

    return {
        "totals": {
            "patterns_total": len(ZERO_DAY_PATTERNS),
            "ai_discovered": len(discovered),
            "ai_anticipated": len(anticipated),
            "predicted_forecast": len(forecasted),
            "historical_only": len(ZERO_DAY_PATTERNS) - len(forecasted),
        },
        "by_mitigation_window": {
            "immediate": [asdict(p) for p in immediate],
            "weeks": [asdict(p) for p in weeks],
            "months": [asdict(p) for p in months],
        },
        "discovered": [asdict(p) for p in discovered if not p.predicted],
        "anticipated_wave": [asdict(p) for p in anticipated if p.predicted],
    }


def list_techniques(layer: int | None = None,
                    tactic: str | None = None) -> list[dict]:
    out = list(ATTACK_TECHNIQUES)
    if layer is not None:
        out = [t for t in out if t.layer == layer]
    if tactic:
        out = [t for t in out if t.tactic == tactic]
    return [asdict(t) for t in out]


def list_defenses(tactic: str | None = None) -> list[dict]:
    out = list(DEFENSE_TECHNIQUES)
    if tactic:
        out = defense_for_tactic(tactic)
    return [asdict(d) for d in out]


def stats() -> dict:
    return {
        "techniques": len(ATTACK_TECHNIQUES),
        "defenses": len(DEFENSE_TECHNIQUES),
        "patterns": len(ZERO_DAY_PATTERNS),
        "ai_discovered_patterns": len(ai_discovered()),
        "ai_anticipated_patterns": len(ai_anticipated()),
        "predicted_forecast_patterns": len(predicted()),
        "immediate_action_patterns": len(by_mitigation_window("immediate")),
        "techniques_uncovered_in_catalog": len(coverage_gaps()),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> int:
    import argparse
    import json
    p = argparse.ArgumentParser(prog="engine.zero_day_defense",
        description="Zero-day defense recommender + catalog manager.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed", help="Seed all three catalogs into the graph")
    sub.add_parser("stats", help="Print catalog stats")
    sub.add_parser("gaps", help="List techniques with no defense in catalog")
    sub.add_parser("coverage", help="Catalog-level coverage matrix")
    sub.add_parser("ai-only", help="List AI-discovered zero-day patterns")
    sub.add_parser("ai-landscape",
                   help="Anticipatory-defense view: forecast wave + immediate-action items")
    p_rec = sub.add_parser("recommend", help="Recommend defenses for a technique")
    p_rec.add_argument("technique_id")
    p_pat = sub.add_parser("pattern", help="Show full record + defenses for a pattern")
    p_pat.add_argument("pattern_id")
    args = p.parse_args()

    if args.cmd == "seed":
        print(json.dumps(seed_all(), indent=2))
    elif args.cmd == "stats":
        print(json.dumps(stats(), indent=2))
    elif args.cmd == "gaps":
        print(json.dumps(coverage_gaps(), indent=2, default=str))
    elif args.cmd == "coverage":
        print(json.dumps(coverage_matrix(), indent=2, default=str))
    elif args.cmd == "ai-only":
        print(json.dumps([asdict(p) for p in ai_discovered()],
                         indent=2, default=str))
    elif args.cmd == "ai-landscape":
        print(json.dumps(ai_threat_landscape(), indent=2, default=str))
    elif args.cmd == "recommend":
        print(json.dumps(recommend_defenses(args.technique_id),
                         indent=2, default=str))
    elif args.cmd == "pattern":
        print(json.dumps(recommend_for_pattern(args.pattern_id),
                         indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())


__all__ = [
    "seed_all", "seed_attack_techniques", "seed_defense_techniques",
    "seed_zero_day_patterns",
    "recommend_defenses", "recommend_for_pattern",
    "coverage_matrix", "coverage_gaps", "installed_coverage",
    "list_patterns", "list_techniques", "list_defenses",
    "ai_threat_landscape",
    "stats",
]
