"""
Combined CVE + CWE Risk Scoring Engine
======================================
Computes a composite "Nexus Risk Score" (0-100) that goes beyond raw CVSS by
fusing:
   - CVSS base score (severity of the specific instance)
   - CWE weakness severity (class of weakness; some CWEs are inherently worse)
   - OSI layer impact (cross-layer = harder to mitigate)
   - PoC availability (real exploit code in the wild)
   - Package blast radius (how many ecosystems/packages are affected)
   - Age decay (recent CVEs weighted higher)

Output shape:
{
  "score": 87.4,
  "band": "CRITICAL",
  "components": {
      "cvss": 9.8, "cwe_severity": 8.0, "osi_breadth": 2,
      "poc_factor": 1.5, "blast_radius": 12, "age_factor": 0.95
  },
  "explanation": ["CVSS critical", "CWE-502 (deserialization) high inherent risk",
                  "Spans OSI layers 6,7", "2 public PoCs", "12 packages affected"]
}
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

# CWE inherent severity (0-10) - hand-curated for common CWEs.
# Reflects "how bad is this class of weakness" independent of any one CVE.
CWE_INHERENT_SEVERITY: dict[str, float] = {
    "CWE-78":   9.5, "CWE-77":   9.0, "CWE-94":   9.5, "CWE-89":   9.0,
    "CWE-79":   7.0, "CWE-352":  6.5, "CWE-918":  8.5, "CWE-22":   7.5,
    "CWE-434":  8.0, "CWE-502":  9.5, "CWE-611":  8.0, "CWE-91":   7.0,
    "CWE-787":  9.0, "CWE-125":  7.5, "CWE-119":  8.0, "CWE-416":  9.0,
    "CWE-415":  8.0, "CWE-190":  7.0, "CWE-191":  6.5, "CWE-476":  6.0,
    "CWE-362":  7.5, "CWE-367":  7.0, "CWE-269":  8.5, "CWE-732":  7.0,
    "CWE-639":  7.5, "CWE-862":  8.0, "CWE-863":  8.0, "CWE-287":  8.5,
    "CWE-288":  8.0, "CWE-294":  7.5, "CWE-307":  6.0, "CWE-384":  6.5,
    "CWE-613":  6.0, "CWE-326":  7.5, "CWE-327":  8.0, "CWE-295":  8.0,
    "CWE-297":  7.5, "CWE-310":  7.0, "CWE-347":  8.0, "CWE-1240": 7.0,
    "CWE-400":  6.5, "CWE-406":  6.0, "CWE-300":  8.0, "CWE-441":  7.0,
    "CWE-290":  7.0, "CWE-1300": 7.5, "CWE-1255": 7.0, "CWE-1247": 7.0,
    "CWE-1338": 7.5, "CWE-1391": 8.0,
}

DEFAULT_CWE_SEVERITY = 5.0


@dataclass
class RiskInput:
    cvss_score: float | None = None       # 0.0 - 10.0
    cwe_ids: list[str] | None = None
    osi_layers: list[int] | None = None
    poc_count: int = 0
    package_count: int = 0                # how many distinct packages affected
    published: datetime | str | None = None  # ISO date or datetime


@dataclass
class RiskResult:
    score: float
    band: str
    components: dict
    explanation: list[str]

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 2),
            "band": self.band,
            "components": self.components,
            "explanation": self.explanation,
        }


def _band(score: float) -> str:
    if score >= 90: return "CRITICAL+"
    if score >= 75: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"


def _age_factor(published: datetime | str | None) -> float:
    """Recent CVEs get up to 1.0; old ones decay toward 0.7."""
    if published is None:
        return 0.85
    if isinstance(published, str):
        try:
            published = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError:
            return 0.85
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    age_years = (datetime.now(timezone.utc) - published).days / 365.25
    return max(0.7, 1.0 - 0.04 * age_years)  # 0.04 per year, floor at 0.7


def _normalize_cwe(cwe: str) -> str:
    s = cwe.upper().strip()
    return s if s.startswith("CWE-") else f"CWE-{s}"


def score(inp: RiskInput) -> RiskResult:
    explanation: list[str] = []

    # ---- CVSS base (0-10 -> 0-50 weight) ----
    cvss = inp.cvss_score if inp.cvss_score is not None else 0.0
    cvss_part = cvss * 5.0
    if cvss >= 9: explanation.append(f"CVSS critical ({cvss})")
    elif cvss >= 7: explanation.append(f"CVSS high ({cvss})")
    elif cvss > 0: explanation.append(f"CVSS {cvss}")

    # ---- CWE severity (avg over linked CWEs, 0-10 -> 0-15 weight) ----
    cwe_ids = [_normalize_cwe(c) for c in (inp.cwe_ids or [])]
    if cwe_ids:
        sevs = [CWE_INHERENT_SEVERITY.get(c, DEFAULT_CWE_SEVERITY) for c in cwe_ids]
        cwe_sev = sum(sevs) / len(sevs)
        worst = max(zip(sevs, cwe_ids))
        explanation.append(f"{worst[1]} weakness inherent severity {worst[0]}")
    else:
        cwe_sev = DEFAULT_CWE_SEVERITY
    cwe_part = cwe_sev * 1.5

    # ---- OSI breadth (cross-layer is worse, 0-15 weight) ----
    layers = sorted(set(inp.osi_layers or []))
    osi_part = min(len(layers), 4) * 3.75
    if layers:
        explanation.append(f"Spans OSI layers {','.join(str(l) for l in layers)}")

    # ---- PoC factor (public exploit dramatically raises risk, 0-10 weight) ----
    if inp.poc_count > 0:
        poc_part = min(10.0, 4.0 + 1.5 * inp.poc_count)
        explanation.append(f"{inp.poc_count} public PoC{'s' if inp.poc_count != 1 else ''}")
    else:
        poc_part = 0.0

    # ---- Blast radius (packages affected, 0-10 weight, log-scaled) ----
    if inp.package_count > 0:
        from math import log
        blast_part = min(10.0, 2.0 * log(1 + inp.package_count, 2))
        explanation.append(f"{inp.package_count} package(s) affected")
    else:
        blast_part = 0.0

    # ---- Sum + age modifier ----
    raw = cvss_part + cwe_part + osi_part + poc_part + blast_part  # max ~100
    age = _age_factor(inp.published)
    final = min(100.0, raw * age)

    return RiskResult(
        score=final,
        band=_band(final),
        components={
            "cvss": cvss,
            "cwe_severity": round(cwe_sev, 2),
            "osi_breadth": len(layers),
            "poc_factor": round(poc_part, 2),
            "blast_radius": inp.package_count,
            "age_factor": round(age, 2),
        },
        explanation=explanation,
    )


def score_dict(d: dict) -> dict:
    """Convenience: compute risk from a plain dict."""
    return score(RiskInput(
        cvss_score=d.get("cvss_score"),
        cwe_ids=d.get("cwe_ids") or [],
        osi_layers=d.get("osi_layers") or [],
        poc_count=d.get("poc_count", 0),
        package_count=d.get("package_count", 0),
        published=d.get("published"),
    )).to_dict()


if __name__ == "__main__":
    import json
    demo = RiskInput(
        cvss_score=9.8,
        cwe_ids=["CWE-502"],
        osi_layers=[6, 7],
        poc_count=2,
        package_count=12,
        published="2024-12-01T00:00:00Z",
    )
    print(json.dumps(score(demo).to_dict(), indent=2))
