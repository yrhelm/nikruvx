"""
Predictive exposure-window engine.
====================================
Per-technique forecast: given the historical rate at which patterns
using each ATT&CK technique have been disclosed, plus the user's live
application exposure, plus their installed defenses, estimate how many
days until a landing pattern hits their stack.

The math is intentionally simple — Poisson arrival on a per-technique
basis, scaled by exposure surface and reduced by defense coverage:

    velocity(T)        = patterns_using(T) / months_observed
    exposure_factor(T) = n_apps_exposed_to(T)
    coverage(T)        = installed_defenses(T) / catalog_defenses(T)
    expected_days(T)   = 30 / (velocity(T) × exposure_factor(T) × (1 - coverage(T) × COVERAGE_DAMPING))

A few honest caveats:

1. The catalog is small and curated — velocities are estimates, not
   ground-truth incidence rates from the wild. Use exposure-window
   numbers as RELATIVE comparisons across techniques, not as absolute
   "you will be hit in 12 days" claims.
2. Coverage is binary in this model (you have D3-WAF or you don't).
   Real defenses have effectiveness gradients we don't model.
3. Forecast patterns (`predicted=True`) are weighted lower than
   historical patterns when computing velocity, since they aren't
   actual observations.

Even with those caveats, the relative ordering tells security teams
where to spend remediation effort first. That's the operational value.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .attack_catalog import ATTACK_TECHNIQUES, AttackTechnique, for_capability
from .defense_catalog import DEFENSE_TECHNIQUES, DefenseTechnique, for_attack
from .graph import run_read
from .zero_day_catalog import ZERO_DAY_PATTERNS, for_technique as patterns_for_technique


# How much an installed defense reduces the projected exposure window.
# 1.0 = a single defense reduces velocity to zero (over-optimistic).
# 0.0 = defenses don't reduce window at all.
# 0.7 = each layer of D3FEND coverage reduces effective velocity by 70%.
COVERAGE_DAMPING = 0.7

# Forecast patterns count as 0.4 of an observation when computing velocity
# (they're hypotheses, not real observations).
FORECAST_WEIGHT = 0.4

# Minimum velocity to avoid divide-by-zero for techniques with no patterns.
MIN_VELOCITY = 1e-3

# Same capability inference used by personalized_risk so the two views
# agree on which apps are exposed to what.
_CATEGORY_TO_CAPS: dict[str, set[str]] = {
    "desktop_binary":  {"LOCAL_CODE", "READ_FS", "WRITE_FS", "PRIV_ESC"},
    "browser_ext":     {"AUTH_BYPASS", "DATA_EXFIL", "READ_FS"},
    "ide_ext":         {"LOCAL_CODE", "WRITE_FS", "DATA_EXFIL"},
    "mcp_server":      {"LOCAL_CODE", "RCE", "DATA_EXFIL", "MODEL_ACCESS"},
    "saas":            {"AUTH_BYPASS", "DATA_EXFIL"},
    "first_party_web": {"RCE", "AUTH_BYPASS", "DATA_EXFIL"},
    "first_party_api": {"RCE", "AUTH_BYPASS", "DATA_EXFIL"},
}


@dataclass
class TechniqueForecast:
    technique_id: str
    technique_name: str
    tactic: str
    layer: int
    velocity_per_month: float           # weighted patterns per month
    historical_patterns: int
    forecast_patterns: int
    exposed_apps: int
    coverage_ratio: float               # 0–1, defenses installed / catalog defenses
    effective_velocity: float           # post-coverage damping
    expected_days_until_landing: float  # ∞ if no exposure or velocity is zero
    severity_weight: float              # 0–4 from worst pattern severity
    risk_index: float                   # composite ranking number
    recommended_defenses: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Velocity computation
# ---------------------------------------------------------------------------
def _months_between(d1: datetime, d2: datetime) -> float:
    return max(1.0, (d2 - d1).days / 30.0)


def _parse_first_seen(raw: str) -> datetime | None:
    """Best-effort parse of `first_seen` strings — accepts YYYY-MM,
    YYYY-MM-DD, ISO 8601, and 'forecast: 2025' style placeholders
    (which we ignore for velocity by returning None)."""
    if not raw or "forecast" in raw.lower() or "ongoing" in raw.lower():
        return None
    raw = raw.strip()
    formats = ["%Y-%m-%d", "%Y-%m", "%Y", "%Y-%m-%dT%H:%M:%S",
               "%Y-%m-%dT%H:%M:%SZ"]
    for fmt in formats:
        try:
            return datetime.strptime(raw[:len(fmt) + 5], fmt).replace(
                tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def velocity_per_technique() -> dict[str, dict[str, Any]]:
    """For each technique, compute observed patterns / months span / weighted
    velocity. Forecast (predicted) patterns count at FORECAST_WEIGHT."""
    now = datetime.now(timezone.utc)
    earliest_default = now.replace(year=now.year - 2)
    out: dict[str, dict[str, Any]] = {}
    for t in ATTACK_TECHNIQUES:
        patterns = patterns_for_technique(t.id)
        if not patterns:
            out[t.id] = {
                "historical": 0, "forecast": 0,
                "earliest": earliest_default.isoformat(),
                "months": _months_between(earliest_default, now),
                "weighted_count": 0.0,
                "velocity_per_month": MIN_VELOCITY,
            }
            continue
        historical = [p for p in patterns if not p.predicted]
        forecast = [p for p in patterns if p.predicted]
        weighted = len(historical) + FORECAST_WEIGHT * len(forecast)

        earliest = earliest_default
        for p in historical:
            d = _parse_first_seen(p.first_seen)
            if d and d < earliest:
                earliest = d
        months = _months_between(earliest, now)
        velocity = max(MIN_VELOCITY, weighted / months)
        out[t.id] = {
            "historical": len(historical),
            "forecast": len(forecast),
            "earliest": earliest.isoformat(),
            "months": round(months, 1),
            "weighted_count": round(weighted, 2),
            "velocity_per_month": round(velocity, 4),
        }
    return out


# ---------------------------------------------------------------------------
# Exposure surface (live graph)
# ---------------------------------------------------------------------------
def _apps_for_capability(capability: str) -> int:
    """How many :Application nodes imply this capability via category?"""
    cats = [c for c, caps in _CATEGORY_TO_CAPS.items()
            if capability in caps]
    if not cats:
        return 0
    cypher = ("MATCH (a:Application) WHERE a.category IN $cats "
              "RETURN count(a) AS n")
    rows = run_read(cypher, cats=cats)
    return rows[0]["n"] if rows else 0


def _apps_exposed_to_technique(t: AttackTechnique) -> int:
    """Total distinct apps exposed via any of the technique's capabilities.

    Conservative — we count an app once even if multiple of its
    capabilities map to the same technique."""
    if not t.capabilities:
        return 0
    cats = set()
    for cap in t.capabilities:
        cats.update(c for c, caps in _CATEGORY_TO_CAPS.items()
                    if cap in caps)
    if not cats:
        return 0
    cypher = ("MATCH (a:Application) WHERE a.category IN $cats "
              "RETURN count(a) AS n")
    rows = run_read(cypher, cats=list(cats))
    return rows[0]["n"] if rows else 0


# ---------------------------------------------------------------------------
# Coverage (live graph)
# ---------------------------------------------------------------------------
def _coverage_ratio(t: AttackTechnique) -> tuple[float, list[dict]]:
    """Return (ratio, missing_defense_list).

    ratio = installed_defenses / total_catalog_defenses for this technique.
    """
    catalog = for_attack(t.id)
    if not catalog:
        return 0.0, []
    catalog_ids = {d.id for d in catalog}
    cypher = """
    MATCH (t:AttackTechnique {id: $tid})-[:COUNTERED_BY]->(d:DefenseTechnique)
    OPTIONAL MATCH (d)-[:IMPLEMENTED_BY]->(c:Control)
    WITH d, count(c) AS impl_count
    WHERE impl_count > 0
    RETURN d.id AS id
    """
    rows = run_read(cypher, tid=t.id)
    installed_ids = {r["id"] for r in rows}
    ratio = len(installed_ids & catalog_ids) / len(catalog_ids)
    missing = [
        {"id": d.id, "name": d.name, "tactic": d.tactic,
         "description": d.description,
         "nikruvx_module": d.nikruvx_module}
        for d in catalog if d.id not in installed_ids
    ]
    return ratio, missing


# ---------------------------------------------------------------------------
# Severity weight
# ---------------------------------------------------------------------------
_SEVERITY_WEIGHT = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3}


def _max_severity_weight(t: AttackTechnique) -> float:
    patterns = patterns_for_technique(t.id)
    if not patterns:
        return 0.5
    return max(_SEVERITY_WEIGHT.get(p.severity, 1.0) for p in patterns)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def forecast_all() -> list[dict]:
    """Compute the full per-technique forecast list, sorted by risk_index."""
    velocities = velocity_per_technique()
    forecasts: list[TechniqueForecast] = []
    for t in ATTACK_TECHNIQUES:
        v = velocities[t.id]
        velocity = v["velocity_per_month"]
        exposed = _apps_exposed_to_technique(t)
        coverage, missing = _coverage_ratio(t)
        sev = _max_severity_weight(t)

        # Effective velocity reduced by coverage
        effective = max(MIN_VELOCITY,
                        velocity * (1 - coverage * COVERAGE_DAMPING))

        # Expected days until next landing pattern hits an exposed app.
        # If exposure is 0, this technique can't land on user's stack.
        if exposed == 0:
            days = float("inf")
        else:
            days = round(30.0 / (effective * exposed), 1)

        # Composite risk index — used for sorting. Higher = worse.
        # Penalize techniques with high severity and short window;
        # boost when exposure is large.
        risk = round(sev * (1.0 + 1.0 / max(1.0, days)) * (1 + 0.1 * exposed),
                     2)

        forecasts.append(TechniqueForecast(
            technique_id=t.id,
            technique_name=t.name,
            tactic=t.tactic,
            layer=t.layer,
            velocity_per_month=velocity,
            historical_patterns=v["historical"],
            forecast_patterns=v["forecast"],
            exposed_apps=exposed,
            coverage_ratio=round(coverage, 2),
            effective_velocity=round(effective, 4),
            expected_days_until_landing=days,
            severity_weight=sev,
            risk_index=risk,
            recommended_defenses=missing[:5],
        ))
    forecasts.sort(key=lambda f: (-f.risk_index, f.expected_days_until_landing))
    return [asdict(f) for f in forecasts]


def forecast_for_technique(technique_id: str) -> dict | None:
    """Single-technique deep-dive."""
    all_forecasts = forecast_all()
    for f in all_forecasts:
        if f["technique_id"] == technique_id:
            return f
    return None


def summary() -> dict:
    """Top-level numbers for a dashboard."""
    forecasts = forecast_all()
    inf = float("inf")
    landing_in_30 = [f for f in forecasts
                     if f["exposed_apps"] > 0
                     and f["expected_days_until_landing"] <= 30]
    landing_in_90 = [f for f in forecasts
                     if f["exposed_apps"] > 0
                     and f["expected_days_until_landing"] <= 90]
    no_coverage = [f for f in forecasts
                   if f["exposed_apps"] > 0 and f["coverage_ratio"] == 0]
    no_data_techs = [f for f in forecasts if f["historical_patterns"] == 0
                     and f["forecast_patterns"] == 0]
    return {
        "total_techniques": len(forecasts),
        "techniques_with_exposure": sum(1 for f in forecasts
                                        if f["exposed_apps"] > 0),
        "techniques_landing_within_30_days": len(landing_in_30),
        "techniques_landing_within_90_days": len(landing_in_90),
        "techniques_with_no_installed_coverage": len(no_coverage),
        "techniques_with_no_pattern_data": len(no_data_techs),
        "top_5_by_risk": forecasts[:5],
        "constants": {
            "coverage_damping": COVERAGE_DAMPING,
            "forecast_weight": FORECAST_WEIGHT,
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> int:
    import argparse
    import json
    p = argparse.ArgumentParser(prog="engine.predictive")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("summary", help="Top-level forecast summary")
    sub.add_parser("all", help="Full per-technique forecast list")
    sub.add_parser("velocity", help="Per-technique velocity (no exposure data)")
    p_one = sub.add_parser("technique", help="Forecast for one technique id")
    p_one.add_argument("technique_id")
    args = p.parse_args()

    if args.cmd == "summary":
        print(json.dumps(summary(), indent=2, default=str))
    elif args.cmd == "all":
        print(json.dumps(forecast_all(), indent=2, default=str))
    elif args.cmd == "velocity":
        print(json.dumps(velocity_per_technique(), indent=2, default=str))
    elif args.cmd == "technique":
        out = forecast_for_technique(args.technique_id)
        if not out:
            print(json.dumps({"error": "unknown technique"}))
            return 1
        print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())


__all__ = [
    "TechniqueForecast", "forecast_all", "forecast_for_technique",
    "velocity_per_technique", "summary",
    "COVERAGE_DAMPING", "FORECAST_WEIGHT",
]
