"""
Personalized Zero-Day Risk View
================================
Cross-references the live Asset Inventory + Posture state against the
ATT&CK technique catalog and the zero-day pattern catalog to answer the
operational question every CISO actually asks:

    "What zero-day classes would land on MY stack, and which of them
     do I currently have NO defense against?"

Three inputs, one ranked output:

    Inventory  →  capability_class  →  ATT&CK technique  →  defense
    Inventory  →  category          →  ZeroDayPattern    →  layer
    PolicyStack →  Control          →  DefenseTechnique  →  technique

Output is a prioritized exposure list with:
    - Affected technique
    - Patterns (real + forecast) using that technique
    - Application(s) bringing the exposure
    - Defenses you ALREADY have (from posture)
    - Defenses you SHOULD have (gap)
    - Mitigation window (if any forecast pattern is immediate)
    - Severity score (capability × forecast urgency × defense gap)
"""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any

from .attack_catalog import ATTACK_TECHNIQUES, AttackTechnique, for_capability
from .defense_catalog import DefenseTechnique, for_attack
from .graph import run_read
from .zero_day_catalog import ZERO_DAY_PATTERNS, for_technique as patterns_for_technique


@dataclass
class ExposureItem:
    technique_id: str
    technique_name: str
    tactic: str
    layer: int
    severity_score: float
    capability_classes: list[str] = field(default_factory=list)
    affecting_apps: list[dict] = field(default_factory=list)
    related_patterns: list[dict] = field(default_factory=list)
    installed_defenses: list[dict] = field(default_factory=list)
    missing_defenses: list[dict] = field(default_factory=list)
    forecast_window: str = ""              # 'immediate' if any pattern says so
    has_ai_anticipated: bool = False


# ---------------------------------------------------------------------------
# Capability inference for a category of Application
# ---------------------------------------------------------------------------
# Loose mapping — each category implies a set of capability surfaces an
# attacker would target if the application is compromised. Used as the
# join key from inventory → ATT&CK.
_CATEGORY_TO_CAPS: dict[str, set[str]] = {
    "desktop_binary":  {"LOCAL_CODE", "READ_FS", "WRITE_FS", "PRIV_ESC"},
    "browser_ext":     {"AUTH_BYPASS", "DATA_EXFIL", "READ_FS"},
    "ide_ext":         {"LOCAL_CODE", "WRITE_FS", "DATA_EXFIL"},
    "mcp_server":      {"LOCAL_CODE", "RCE", "DATA_EXFIL", "MODEL_ACCESS"},
    "saas":            {"AUTH_BYPASS", "DATA_EXFIL"},
    "first_party_web": {"RCE", "AUTH_BYPASS", "DATA_EXFIL"},
    "first_party_api": {"RCE", "AUTH_BYPASS", "DATA_EXFIL"},
}


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------
_SEVERITY_WEIGHTS = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3}
_WINDOW_WEIGHTS = {"immediate": 3.0, "weeks": 2.0, "months": 1.0}


def _score(item: ExposureItem) -> float:
    if not item.related_patterns:
        return 0.0
    sev_max = max(_SEVERITY_WEIGHTS.get(p.get("severity", "medium"), 1.0)
                  for p in item.related_patterns)
    win = max(_WINDOW_WEIGHTS.get(p.get("mitigation_window", ""), 0.5)
              for p in item.related_patterns)
    gap_factor = 1.0 + (len(item.missing_defenses)
                        / max(1, len(item.missing_defenses) + len(item.installed_defenses)))
    n_apps = len(item.affecting_apps)
    return round(sev_max * win * gap_factor * (1 + 0.1 * n_apps), 2)


# ---------------------------------------------------------------------------
# Live graph queries
# ---------------------------------------------------------------------------
def _installed_defenses_for_technique(technique_id: str) -> list[dict]:
    """Return the :DefenseTechnique nodes that counter this technique
    AND have at least one IMPLEMENTED_BY edge to a live :Control node."""
    cypher = """
    MATCH (t:AttackTechnique {id: $tid})-[:COUNTERED_BY]->(d:DefenseTechnique)
    OPTIONAL MATCH (d)-[:IMPLEMENTED_BY]->(c:Control)
    WITH d, count(c) AS impl_count
    WHERE impl_count > 0
    RETURN d.id AS id, d.name AS name, d.tactic AS tactic, impl_count
    """
    return run_read(cypher, tid=technique_id)


def _apps_exposed_to_capability(capability: str) -> list[dict]:
    """Apps that imply this capability via category."""
    cats = [c for c, caps in _CATEGORY_TO_CAPS.items() if capability in caps]
    if not cats:
        return []
    cypher = """
    MATCH (a:Application)
    WHERE a.category IN $cats
    RETURN a.key AS key, a.name AS name, a.category AS category,
           coalesce(a.trust_score, 50) AS trust_score
    LIMIT 200
    """
    return run_read(cypher, cats=cats)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def compute_exposure(top_n: int = 50) -> list[dict]:
    """For every ATT&CK technique in the catalog, compute the user's
    exposure: which apps bring it in, which defenses they have / lack,
    which zero-day patterns target it, and a unified severity score."""
    items: list[ExposureItem] = []

    for t in ATTACK_TECHNIQUES:
        # 1) Which apps are exposed via capability
        apps: dict[str, dict] = {}
        for cap in t.capabilities:
            for app in _apps_exposed_to_capability(cap):
                apps.setdefault(app["key"], app)

        # 2) Patterns that use this technique
        related = patterns_for_technique(t.id)
        if not related and not apps:
            continue   # no exposure, no signal

        # 3) Defenses
        catalog_defenses = for_attack(t.id)
        installed = _installed_defenses_for_technique(t.id)
        installed_ids = {d["id"] for d in installed}
        missing = [{"id": d.id, "name": d.name, "tactic": d.tactic,
                    "description": d.description,
                    "nikruvx_module": d.nikruvx_module}
                   for d in catalog_defenses if d.id not in installed_ids]

        # 4) Window + AI-anticipated flags
        forecast_window = ""
        has_ai_ant = False
        for p in related:
            if p.mitigation_window == "immediate":
                forecast_window = "immediate"
            elif p.mitigation_window == "weeks" and forecast_window != "immediate":
                forecast_window = "weeks"
            elif p.mitigation_window == "months" and not forecast_window:
                forecast_window = "months"
            if p.ai_anticipated:
                has_ai_ant = True

        item = ExposureItem(
            technique_id=t.id,
            technique_name=t.name,
            tactic=t.tactic,
            layer=t.layer,
            severity_score=0.0,
            capability_classes=list(t.capabilities),
            affecting_apps=list(apps.values()),
            related_patterns=[
                {"id": p.id, "name": p.name, "severity": p.severity,
                 "ai_discovered": p.ai_discovered,
                 "ai_anticipated": p.ai_anticipated,
                 "predicted": p.predicted,
                 "mitigation_window": p.mitigation_window}
                for p in related
            ],
            installed_defenses=installed,
            missing_defenses=missing,
            forecast_window=forecast_window,
            has_ai_anticipated=has_ai_ant,
        )
        item.severity_score = _score(item)
        items.append(item)

    items.sort(key=lambda x: x.severity_score, reverse=True)
    return [asdict(i) for i in items[:top_n]]


def summary() -> dict:
    """Top-level numbers for the dashboard."""
    rows = compute_exposure(top_n=10_000)
    immediate = [r for r in rows if r["forecast_window"] == "immediate"]
    ai_anticipated = [r for r in rows if r["has_ai_anticipated"]]
    no_defense = [r for r in rows
                  if r["missing_defenses"] and not r["installed_defenses"]]
    return {
        "techniques_at_risk": len(rows),
        "immediate_action_techniques": len(immediate),
        "ai_anticipated_techniques": len(ai_anticipated),
        "techniques_with_no_installed_defense": len(no_defense),
        "top_5_by_score": rows[:5],
    }


__all__ = ["ExposureItem", "compute_exposure", "summary"]
