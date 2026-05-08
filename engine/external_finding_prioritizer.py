"""
External-finding prioritizer — re-score scanner output against your environment.
================================================================================
Scanners (Wiz / Snyk / Tenable / Qualys) report findings using their own
severity model — typically CVSS-based, with limited environmental context.
Two findings rated "Critical" by Wiz can have wildly different real-world
priority depending on whether the package is in your inventory, whether
you have D3FEND coverage for the underlying TTP, whether a public PoC
exists, whether it's in CISA KEV, and whether it falls into a known
forecast wave class.

This module re-scores each finding 0-100 with explicit adjustments:

    base_score = (original_cvss / 10.0) * 100
    +25  in CISA KEV (actively exploited)
    +20  public PoC available
    +15..+35  affects N apps in inventory (scaled by N)
    +20  matches AI-anticipated forecast pattern class
    +20  no D3FEND coverage for any technique CVE maps to
    -15  strong D3FEND coverage installed (defense in depth still warrants action)
    -10  not matched to any inventory app
    +10  has_fix true (bumps actionable items up the queue)
    +10  exploitable flag from scanner

Each adjustment is recorded in `adjustments` so the user sees WHY their
score moved. That transparency is the difference between a black-box
re-score and a defensible recommendation.
"""
from __future__ import annotations
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .graph import run_read, run_write
from ingest.external_findings import Finding


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class ScoredFinding:
    finding: dict[str, Any]                      # asdict(Finding)
    nikruvx_score: float                         # 0-100
    priority_band: str                           # critical | high | medium | low
    adjustments: list[dict[str, Any]] = field(default_factory=list)
    affected_apps: list[dict] = field(default_factory=list)
    matched_cve: bool = False
    in_kev: bool = False
    has_poc: bool = False
    matched_techniques: list[str] = field(default_factory=list)
    coverage_ratio: float = 0.0
    matches_forecast_pattern: bool = False
    recommended_action: str = ""


def _band(score: float) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 40: return "medium"
    return "low"


def _recommended_action(score: float, finding: Finding,
                         in_kev: bool, has_fix: bool,
                         apps_count: int, coverage: float) -> str:
    if in_kev:
        return ("PATCH IMMEDIATELY — actively exploited. If patch unavailable, "
                "deploy a temporary WAF rule blocking the technique class.")
    if score >= 80:
        if has_fix:
            return "Patch this week. Track in your normal change-mgmt cycle."
        return ("No fix yet — deploy compensating control (D3FEND coverage for "
                "underlying TTP) until patch ships.")
    if score >= 60 and apps_count > 0:
        return ("Patch within 30 days. Lower urgency than CRITICAL but still "
                "in your stack.")
    if apps_count == 0:
        return ("Not in current inventory — file as informational. Re-evaluate "
                "if inventory changes.")
    if coverage >= 0.5:
        return ("Strong D3FEND coverage in place — patch on regular cycle.")
    return "Deploy on standard maintenance cycle."


# ---------------------------------------------------------------------------
# Environment lookups (live graph)
# ---------------------------------------------------------------------------
def _cve_in_graph(cve_id: str) -> dict | None:
    rows = run_read(
        "MATCH (c:CVE {id: $cve}) "
        "RETURN c.id AS id, c.cvss_score AS cvss, c.severity AS severity, "
        "       coalesce(c.in_kev, false) AS in_kev",
        cve=cve_id,
    )
    return rows[0] if rows else None


def _has_public_poc(cve_id: str) -> bool:
    rows = run_read(
        "MATCH (:CVE {id: $cve})-[:HAS_POC]->(p:PoC) RETURN count(p) AS n LIMIT 1",
        cve=cve_id,
    )
    return bool(rows and rows[0].get("n", 0) > 0)


def _affected_apps_for_package(package: str, version: str | None = None) -> list[dict]:
    if not package:
        return []
    rows = run_read(
        """
        MATCH (a:Application)-[:DEPENDS_ON]->(p:Package)
        WHERE toLower(p.name) = toLower($pkg)
        RETURN a.key AS key, a.name AS name, a.category AS category,
               coalesce(a.trust_score, 50) AS trust_score
        LIMIT 50
        """,
        pkg=package,
    )
    return rows


def _techniques_for_cve(cve_id: str) -> list[str]:
    rows = run_read(
        """
        MATCH (c:CVE {id: $cve})-[:CLASSIFIED_AS]->(:CWE)
        OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(cwe:CWE)
        OPTIONAL MATCH (z:ZeroDayPattern)-[:OBSERVED_IN]->(c)
        OPTIONAL MATCH (z)-[:USES_TECHNIQUE]->(t:AttackTechnique)
        RETURN collect(DISTINCT t.id) AS technique_ids
        """,
        cve=cve_id,
    )
    if not rows:
        return []
    return [t for t in (rows[0].get("technique_ids") or []) if t]


def _coverage_ratio(technique_ids: list[str]) -> float:
    """Average coverage across all techniques the CVE maps to."""
    if not technique_ids:
        return 0.0
    rows = run_read(
        """
        UNWIND $tids AS tid
        MATCH (t:AttackTechnique {id: tid})-[:COUNTERED_BY]->(d:DefenseTechnique)
        OPTIONAL MATCH (d)-[:IMPLEMENTED_BY]->(c:Control)
        WITH tid, count(DISTINCT d) AS catalog_count,
             count(DISTINCT c) AS installed_count
        RETURN tid, catalog_count, installed_count
        """,
        tids=technique_ids,
    )
    if not rows:
        return 0.0
    ratios = []
    for r in rows:
        cat = r.get("catalog_count") or 0
        inst = r.get("installed_count") or 0
        if cat:
            ratios.append(min(1.0, inst / cat))
    return round(sum(ratios) / len(ratios), 2) if ratios else 0.0


_FORECAST_KEYWORDS: dict[str, set[str]] = {
    "ZD-AI-MASS-MEMORY-FUZZ": {"buffer overflow", "use-after-free", "memory corruption",
                               "stack overflow", "heap overflow", "integer overflow",
                               "out-of-bounds", "double free"},
    "ZD-AI-CRYPTO-SIDE-CHANNEL": {"side channel", "timing attack", "cache attack",
                                   "constant time", "spectre", "dmp"},
    "ZD-AI-DESERIALIZATION-WAVE": {"deserialization", "jndi", "marshalled",
                                   "yaml.load", "pickle", "objectinputstream"},
    "ZD-AI-CICD-INJECTION": {"github actions", "gitlab ci", "jenkinsfile",
                              "command injection", "ci/cd"},
    "ZD-AI-SAAS-SSRF-WAVE": {"ssrf", "server-side request forgery", "imdsv1"},
}


def _matches_forecast(finding: Finding) -> bool:
    """Does the finding's title/description match an AI-anticipated forecast class?"""
    blob = " ".join(filter(None, [finding.title, finding.description])).lower()
    if not blob:
        return False
    for kws in _FORECAST_KEYWORDS.values():
        if any(kw in blob for kw in kws):
            return True
    return False


# ---------------------------------------------------------------------------
# Core re-scoring
# ---------------------------------------------------------------------------
def re_score(finding: Finding) -> ScoredFinding:
    score = (finding.original_cvss / 10.0) * 100 if finding.original_cvss \
            else _SEVERITY_TO_BASE.get(finding.original_severity, 30.0)
    adjustments: list[dict[str, Any]] = []

    cve_data = _cve_in_graph(finding.cve_id) if finding.cve_id else None
    matched_cve = bool(cve_data)
    in_kev = bool(cve_data and cve_data.get("in_kev"))
    has_poc = _has_public_poc(finding.cve_id) if finding.cve_id else False

    apps = _affected_apps_for_package(finding.package, finding.version)
    technique_ids = _techniques_for_cve(finding.cve_id) if finding.cve_id else []
    coverage = _coverage_ratio(technique_ids)
    matches_forecast = _matches_forecast(finding)

    # ---- Adjustments ----
    if in_kev:
        adj = 25.0
        score += adj
        adjustments.append({"delta": adj, "reason": "in CISA KEV (actively exploited)"})

    if has_poc:
        adj = 20.0
        score += adj
        adjustments.append({"delta": adj, "reason": "public PoC available"})

    if apps:
        bump = min(35.0, 15.0 + 5.0 * len(apps))
        score += bump
        adjustments.append({
            "delta": bump,
            "reason": f"affects {len(apps)} app(s) in inventory: " +
                      ", ".join(a["name"] for a in apps[:3])
                      + ("" if len(apps) <= 3 else f" +{len(apps)-3} more"),
        })
    elif finding.package:
        adj = -10.0
        score += adj
        adjustments.append({
            "delta": adj,
            "reason": "package not in current inventory",
        })

    if technique_ids:
        if coverage == 0.0:
            adj = 20.0
            score += adj
            adjustments.append({
                "delta": adj,
                "reason": f"no D3FEND coverage for {len(technique_ids)} TTP(s) "
                          f"this CVE maps to",
            })
        elif coverage >= 0.5:
            adj = -15.0
            score += adj
            adjustments.append({
                "delta": adj,
                "reason": f"strong D3FEND coverage ({int(coverage*100)}%) "
                          f"already installed",
            })

    if matches_forecast:
        adj = 20.0
        score += adj
        adjustments.append({
            "delta": adj,
            "reason": "matches AI-anticipated forecast pattern class",
        })

    if finding.has_fix:
        adj = 10.0
        score += adj
        adjustments.append({"delta": adj, "reason": "fix available — actionable today"})

    if finding.exploitable:
        adj = 10.0
        score += adj
        adjustments.append({"delta": adj, "reason": "exploitable flag from scanner"})

    score = max(0.0, min(100.0, score))

    return ScoredFinding(
        finding=asdict(finding),
        nikruvx_score=round(score, 1),
        priority_band=_band(score),
        adjustments=adjustments,
        affected_apps=apps,
        matched_cve=matched_cve,
        in_kev=in_kev,
        has_poc=has_poc,
        matched_techniques=technique_ids,
        coverage_ratio=coverage,
        matches_forecast_pattern=matches_forecast,
        recommended_action=_recommended_action(
            score, finding, in_kev, finding.has_fix, len(apps), coverage,
        ),
    )


_SEVERITY_TO_BASE: dict[str, float] = {
    "critical": 90.0, "high": 70.0, "medium": 45.0, "low": 20.0, "unknown": 30.0,
}


def re_score_batch(findings: list[Finding]) -> list[ScoredFinding]:
    return [re_score(f) for f in findings]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def persist_batch(scored: list[ScoredFinding], source: str,
                   batch_label: str = "") -> str:
    """Write a :FindingBatch + :ExternalFinding nodes for one upload."""
    batch_id = f"fb:{uuid.uuid4().hex[:12]}"
    ts = datetime.now(timezone.utc).isoformat()
    rows = []
    for s in scored:
        f = s.finding
        fid = f"ef:{batch_id}:{f.get('external_id','?')}"
        rows.append({
            "id": fid,
            "cve_id": f.get("cve_id") or "",
            "package": f.get("package") or "",
            "version": f.get("version") or "",
            "title": f.get("title") or "",
            "original_severity": f.get("original_severity") or "",
            "original_cvss": f.get("original_cvss") or 0.0,
            "nikruvx_score": s.nikruvx_score,
            "priority_band": s.priority_band,
            "in_kev": s.in_kev,
            "has_poc": s.has_poc,
            "coverage_ratio": s.coverage_ratio,
            "recommended_action": s.recommended_action[:1000],
            "raw_json": json.dumps(s.finding, default=str)[:8000],
            "adjustments_json": json.dumps(s.adjustments)[:4000],
        })
    run_write(
        """
        MERGE (b:FindingBatch {id: $bid})
          SET b.source = $source, b.label = $label,
              b.uploaded_at = datetime($ts),
              b.count = $count
        WITH b
        UNWIND $rows AS r
        MERGE (f:ExternalFinding {id: r.id})
          SET f.source = $source,
              f.cve_id = r.cve_id, f.package = r.package, f.version = r.version,
              f.title = r.title,
              f.original_severity = r.original_severity,
              f.original_cvss = r.original_cvss,
              f.nikruvx_score = r.nikruvx_score,
              f.priority_band = r.priority_band,
              f.in_kev = r.in_kev, f.has_poc = r.has_poc,
              f.coverage_ratio = r.coverage_ratio,
              f.recommended_action = r.recommended_action,
              f.raw_json = r.raw_json,
              f.adjustments_json = r.adjustments_json,
              f.uploaded_at = datetime($ts)
        MERGE (b)-[:HAS_FINDING]->(f)
        WITH f, r
        OPTIONAL MATCH (c:CVE {id: r.cve_id})
        FOREACH (_ IN CASE WHEN c IS NOT NULL THEN [1] ELSE [] END |
          MERGE (f)-[:REFERS_TO_CVE]->(c)
        )
        """,
        bid=batch_id, source=source, label=batch_label or "(unlabeled)",
        ts=ts, count=len(scored), rows=rows,
    )
    return batch_id


def list_batches(limit: int = 50) -> list[dict]:
    cypher = """
    MATCH (b:FindingBatch)
    RETURN b.id AS batch_id, b.source AS source, b.label AS label,
           toString(b.uploaded_at) AS uploaded_at, b.count AS count
    ORDER BY b.uploaded_at DESC LIMIT $limit
    """
    return run_read(cypher, limit=limit)


def list_findings(batch_id: str | None = None,
                  priority_band: str | None = None,
                  limit: int = 500) -> list[dict]:
    where = []
    params: dict[str, Any] = {"limit": limit}
    if batch_id:
        where.append("b.id = $batch_id")
        params["batch_id"] = batch_id
    if priority_band:
        where.append("f.priority_band = $band")
        params["band"] = priority_band
    where_clause = (" WHERE " + " AND ".join(where)) if where else ""
    cypher = f"""
    MATCH (b:FindingBatch)-[:HAS_FINDING]->(f:ExternalFinding)
    {where_clause}
    RETURN f.id AS id, f.cve_id AS cve_id, f.package AS package,
           f.version AS version, f.title AS title,
           f.original_severity AS original_severity,
           f.original_cvss AS original_cvss,
           f.nikruvx_score AS nikruvx_score,
           f.priority_band AS priority_band,
           f.in_kev AS in_kev, f.has_poc AS has_poc,
           f.coverage_ratio AS coverage_ratio,
           f.recommended_action AS recommended_action,
           f.adjustments_json AS adjustments_json,
           b.id AS batch_id, b.source AS source
    ORDER BY f.nikruvx_score DESC LIMIT $limit
    """
    return run_read(cypher, **params)


# ---------------------------------------------------------------------------
# CSV export of re-prioritized findings
# ---------------------------------------------------------------------------
def to_export_csv(scored: list[ScoredFinding]) -> str:
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "nikruvx_score", "priority_band", "cve_id", "package", "version",
        "original_severity", "original_cvss", "in_kev", "has_poc",
        "coverage_ratio", "recommended_action", "title", "source",
        "matched_techniques", "adjustments",
    ])
    for s in scored:
        f = s.finding
        adj = "; ".join(
            f"{a['delta']:+.0f} {a['reason']}" for a in s.adjustments
        )
        w.writerow([
            s.nikruvx_score, s.priority_band, f.get("cve_id", ""),
            f.get("package", ""), f.get("version", ""),
            f.get("original_severity", ""), f.get("original_cvss", ""),
            s.in_kev, s.has_poc, s.coverage_ratio,
            s.recommended_action, f.get("title", ""), f.get("source", ""),
            ",".join(s.matched_techniques), adj,
        ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> int:
    import argparse
    p = argparse.ArgumentParser(prog="engine.external_finding_prioritizer")
    sub = p.add_subparsers(dest="cmd", required=True)
    p_imp = sub.add_parser("import", help="Import + re-score a CSV file")
    p_imp.add_argument("--file", required=True)
    p_imp.add_argument("--source", choices=["wiz", "snyk", "tenable",
                                             "qualys", "generic"])
    p_imp.add_argument("--label", default="")
    p_imp.add_argument("--persist", action="store_true")
    p_imp.add_argument("--export", help="Path to write re-prioritized CSV")
    sub.add_parser("batches", help="List uploaded batches")
    p_lst = sub.add_parser("findings", help="List findings (filterable)")
    p_lst.add_argument("--batch")
    p_lst.add_argument("--band",
                       choices=["critical", "high", "medium", "low"])
    p_lst.add_argument("--limit", type=int, default=200)
    args = p.parse_args()

    if args.cmd == "import":
        from ingest.external_findings import parse_csv_file
        detected, findings = parse_csv_file(args.file, source=args.source)
        scored = re_score_batch(findings)
        print(f"Detected source: {detected}")
        print(f"Imported {len(findings)} findings, scored {len(scored)}.")
        bands: dict[str, int] = {}
        for s in scored:
            bands[s.priority_band] = bands.get(s.priority_band, 0) + 1
        for band in ("critical", "high", "medium", "low"):
            print(f"  {band}: {bands.get(band, 0)}")
        if args.persist:
            bid = persist_batch(scored, source=detected, batch_label=args.label)
            print(f"Persisted batch: {bid}")
        if args.export:
            with open(args.export, "w", encoding="utf-8", newline="") as fh:
                fh.write(to_export_csv(scored))
            print(f"Wrote re-prioritized CSV to {args.export}")
        return 0

    if args.cmd == "batches":
        import json
        print(json.dumps(list_batches(), indent=2, default=str))
        return 0

    if args.cmd == "findings":
        import json
        print(json.dumps(
            list_findings(batch_id=args.batch, priority_band=args.band,
                          limit=args.limit),
            indent=2, default=str,
        ))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())


__all__ = [
    "ScoredFinding", "re_score", "re_score_batch",
    "persist_batch", "list_batches", "list_findings", "to_export_csv",
]
