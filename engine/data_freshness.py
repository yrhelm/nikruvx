"""
Data Freshness + on-demand refresh.
====================================
Per-source dashboard answering two questions:

    1. When was this source last refreshed?  (count + max timestamp)
    2. Refresh it NOW                          (fire-and-forget thread)

Long-running refreshes (full NVD sweep, full OSV) run in a background
thread so the API call returns immediately. State of in-progress jobs
is tracked in `_JOBS` so the UI can poll status.

Sources covered:
    - NVD CVE                   :CVE
    - MITRE CWE                 :CWE
    - OSV / package corpus      :Package, :PackageVersion
    - CISA KEV                  :CVE { in_kev: true }
    - Malicious-package feeds   data/feeds/* (engine.threat_feeds)
    - Threat-intel RSS          :ThreatAdvisory
    - ATT&CK technique catalog  :AttackTechnique
    - D3FEND defense catalog    :DefenseTechnique
    - Zero-day pattern catalog  :ZeroDayPattern
    - Asset Inventory           :Application
    - PHI Lineage               :Prompt, :BAATerm
    - Model Gate evals          :ModelEval
    - MCP Gate approvals        :McpApproval
"""
from __future__ import annotations
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .graph import run_read

log = logging.getLogger(__name__)


@dataclass
class DataSource:
    id: str
    name: str
    description: str
    count_query: str               # returns single 'n' column
    last_refresh_query: str        # returns single 'ts' column (ISO str) or empty
    refresher_module: str = ""     # 'ingest.nvd' / 'ingest.threat_intel_rss' / ...
    refresher_callable: str = ""   # name of function to call
    requires_token: str = ""       # env var, e.g. 'NVD_API_KEY'
    estimated_duration: str = "seconds"   # seconds | minutes | long
    refresher_kwargs: dict = field(default_factory=dict)


# Curated source registry. The count + last-refresh queries are tuned to
# whatever each ingester actually writes to the graph.
SOURCES: list[DataSource] = [
    DataSource(
        id="nvd_cve",
        name="NVD CVE catalog",
        description="National Vulnerability Database — every published CVE",
        count_query="MATCH (c:CVE) RETURN count(c) AS n",
        last_refresh_query=(
            "MATCH (c:CVE) WHERE c.last_modified IS NOT NULL "
            "RETURN toString(max(datetime(c.last_modified))) AS ts"
        ),
        refresher_module="ingest.nvd",
        refresher_callable="ingest_recent",
        refresher_kwargs={"days": 7},
        requires_token="NVD_API_KEY (recommended; rate-limit otherwise)",
        estimated_duration="minutes",
    ),
    DataSource(
        id="mitre_cwe",
        name="MITRE CWE catalog",
        description="Common Weakness Enumeration — full catalog",
        count_query="MATCH (c:CWE) RETURN count(c) AS n",
        last_refresh_query="MATCH (c:CWE) RETURN toString(max(c.updated_at)) AS ts",
        refresher_module="ingest.cwe",
        refresher_callable="ingest",
        estimated_duration="seconds",
    ),
    DataSource(
        id="osv_packages",
        name="OSV / Package corpus",
        description="OSV.dev advisories across npm/PyPI/Maven/Go/Cargo/RubyGems/OS",
        count_query="MATCH (p:Package) RETURN count(p) AS n",
        last_refresh_query=(
            "MATCH (p:Package) WHERE p.updated_at IS NOT NULL "
            "RETURN toString(max(p.updated_at)) AS ts"
        ),
        refresher_module="ingest.osv",
        refresher_callable="ingest",
        estimated_duration="minutes",
    ),
    DataSource(
        id="kev",
        name="CISA Known-Exploited Vulnerabilities",
        description="CISA KEV catalog — actively exploited CVEs",
        count_query="MATCH (c:CVE) WHERE c.in_kev = true RETURN count(c) AS n",
        last_refresh_query=(
            "MATCH (c:CVE) WHERE c.in_kev = true AND c.kev_added IS NOT NULL "
            "RETURN toString(max(c.kev_added)) AS ts"
        ),
        refresher_module="ingest.telemetry",
        refresher_callable="ingest_kev",
        estimated_duration="seconds",
    ),
    DataSource(
        id="malicious_feeds",
        name="Malicious-package threat feeds",
        description="OSSF malicious-packages + GHSA malware + PyPA advisory-db",
        count_query=("RETURN coalesce(size((:Package WHERE 1=1)), 0) AS n LIMIT 1"),
        last_refresh_query="RETURN '' AS ts",
        refresher_module="engine.threat_feeds",
        refresher_callable="refresh_all",
        estimated_duration="minutes",
    ),
    DataSource(
        id="threat_advisories",
        name="Threat-intel RSS (Project Zero / MSTIC / etc.)",
        description="Live RSS sweep across 7 curated security blogs",
        count_query="MATCH (a:ThreatAdvisory) RETURN count(a) AS n",
        last_refresh_query="MATCH (a:ThreatAdvisory) RETURN toString(max(a.last_seen)) AS ts",
        refresher_module="ingest.threat_intel_rss",
        refresher_callable="ingest_all",
        refresher_kwargs={"auto_file": True, "use_llm": False},
        estimated_duration="seconds",
    ),
    DataSource(
        id="attack_catalog",
        name="ATT&CK technique catalog",
        description="Curated MITRE ATT&CK + ATLAS subset (52 techniques)",
        count_query="MATCH (t:AttackTechnique) RETURN count(t) AS n",
        last_refresh_query="MATCH (t:AttackTechnique) RETURN toString(max(t.updated_at)) AS ts",
        refresher_module="engine.zero_day_defense",
        refresher_callable="seed_attack_techniques",
        estimated_duration="seconds",
    ),
    DataSource(
        id="defense_catalog",
        name="D3FEND defense catalog",
        description="MITRE D3FEND + AI/LLM extensions (51 defenses)",
        count_query="MATCH (d:DefenseTechnique) RETURN count(d) AS n",
        last_refresh_query="MATCH (d:DefenseTechnique) RETURN toString(max(d.updated_at)) AS ts",
        refresher_module="engine.zero_day_defense",
        refresher_callable="seed_defense_techniques",
        estimated_duration="seconds",
    ),
    DataSource(
        id="zero_day_catalog",
        name="Zero-day pattern catalog",
        description="Curated patterns + AI-anticipated forecast wave",
        count_query="MATCH (z:ZeroDayPattern) RETURN count(z) AS n",
        last_refresh_query="MATCH (z:ZeroDayPattern) RETURN toString(max(z.updated_at)) AS ts",
        refresher_module="engine.zero_day_defense",
        refresher_callable="seed_zero_day_patterns",
        estimated_duration="seconds",
    ),
    DataSource(
        id="application_inventory",
        name="Asset Inventory",
        description="Installed apps: desktop / browser / IDE / MCP",
        count_query="MATCH (a:Application) RETURN count(a) AS n",
        last_refresh_query="MATCH (a:Application) RETURN toString(max(a.first_seen)) AS ts",
        refresher_module="ingest.inventory",
        refresher_callable="scan_all",
        estimated_duration="seconds",
    ),
    DataSource(
        id="phi_lineage",
        name="PHI Lineage",
        description="Recorded prompt / response / BAA-coverage events",
        count_query="MATCH (p:Prompt) RETURN count(p) AS n",
        last_refresh_query="MATCH (p:Prompt) RETURN toString(max(p.ts)) AS ts",
        refresher_module="",
        refresher_callable="",
        estimated_duration="seconds",
    ),
    DataSource(
        id="model_evals",
        name="Model Gate evaluations",
        description="LLM regression-suite runs",
        count_query="MATCH (e:ModelEval) RETURN count(e) AS n",
        last_refresh_query="MATCH (e:ModelEval) RETURN toString(max(e.ts)) AS ts",
        refresher_module="",
        refresher_callable="",
        estimated_duration="seconds",
    ),
    DataSource(
        id="mcp_approvals",
        name="MCP Gate approvals",
        description="Pre-deployment review records for MCP servers",
        count_query="MATCH (a:McpApproval) RETURN count(a) AS n",
        last_refresh_query="MATCH (a:McpApproval) RETURN toString(max(a.reviewed_at)) AS ts",
        refresher_module="engine.mcp_gate",
        refresher_callable="review_inventory",
        estimated_duration="seconds",
    ),
]


# ---------------------------------------------------------------------------
# In-flight job tracking
# ---------------------------------------------------------------------------
_JOBS_LOCK = threading.Lock()
_JOBS: dict[str, dict[str, Any]] = {}     # source_id → status dict


def _set_job(source_id: str, status: str, **extras: Any) -> None:
    with _JOBS_LOCK:
        existing = _JOBS.get(source_id, {"source_id": source_id})
        existing.update({
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **extras,
        })
        _JOBS[source_id] = existing


def _get_jobs() -> list[dict]:
    with _JOBS_LOCK:
        return list(_JOBS.values())


# ---------------------------------------------------------------------------
# Status query
# ---------------------------------------------------------------------------
def _safe_count(query: str) -> int:
    try:
        rows = run_read(query)
        if rows:
            v = rows[0].get("n")
            return int(v) if v is not None else 0
    except Exception:
        pass
    return 0


def _safe_max_ts(query: str) -> str:
    try:
        rows = run_read(query)
        if rows:
            v = rows[0].get("ts")
            return str(v) if v else ""
    except Exception:
        pass
    return ""


def status_all() -> list[dict]:
    """Return per-source freshness data for the dashboard."""
    out: list[dict] = []
    job_map = {j["source_id"]: j for j in _get_jobs()}
    for s in SOURCES:
        out.append({
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "count": _safe_count(s.count_query),
            "last_refresh": _safe_max_ts(s.last_refresh_query),
            "refresher_module": s.refresher_module,
            "refresher_callable": s.refresher_callable,
            "requires_token": s.requires_token,
            "estimated_duration": s.estimated_duration,
            "supports_refresh": bool(s.refresher_module and s.refresher_callable),
            "job": job_map.get(s.id),
        })
    return out


def status_one(source_id: str) -> dict | None:
    src = next((s for s in SOURCES if s.id == source_id), None)
    if not src:
        return None
    return {
        "id": src.id,
        "name": src.name,
        "count": _safe_count(src.count_query),
        "last_refresh": _safe_max_ts(src.last_refresh_query),
        "supports_refresh": bool(src.refresher_module and src.refresher_callable),
        "job": next((j for j in _get_jobs() if j["source_id"] == source_id), None),
    }


# ---------------------------------------------------------------------------
# Refresh dispatch
# ---------------------------------------------------------------------------
def _import_callable(module_name: str, callable_name: str) -> Callable | None:
    try:
        import importlib
        mod = importlib.import_module(module_name)
        fn = getattr(mod, callable_name, None)
        return fn if callable(fn) else None
    except Exception as e:
        log.warning("import %s.%s failed: %s", module_name, callable_name, e)
        return None


def refresh(source_id: str) -> dict:
    """Trigger refresh of one source. Long-running tasks run in a daemon
    thread; the call returns immediately with a job id."""
    src = next((s for s in SOURCES if s.id == source_id), None)
    if not src:
        return {"status": "error", "error": f"unknown source: {source_id}"}
    if not (src.refresher_module and src.refresher_callable):
        return {"status": "error",
                "error": f"source {source_id} has no refresher configured"}
    fn = _import_callable(src.refresher_module, src.refresher_callable)
    if not fn:
        return {"status": "error",
                "error": f"refresher {src.refresher_module}.{src.refresher_callable} not importable"}

    # Idempotency: if a job is already in-flight, don't kick another off.
    existing = next((j for j in _get_jobs() if j["source_id"] == source_id), None)
    if existing and existing.get("status") == "running":
        return {"status": "already_running", "job": existing}

    job_id = f"job:{uuid.uuid4().hex[:12]}"
    _set_job(source_id, "running", job_id=job_id,
             started_at=datetime.now(timezone.utc).isoformat())

    def _run():
        try:
            kwargs = src.refresher_kwargs or {}
            result = fn(**kwargs) if kwargs else fn()
            _set_job(source_id, "completed",
                     finished_at=datetime.now(timezone.utc).isoformat(),
                     result_summary=str(result)[:300])
        except Exception as e:    # noqa: BLE001
            log.warning("refresh %s failed: %s", source_id, e)
            _set_job(source_id, "failed",
                     finished_at=datetime.now(timezone.utc).isoformat(),
                     error=f"{type(e).__name__}: {e}"[:300])

    threading.Thread(target=_run, daemon=True,
                     name=f"refresh-{source_id}").start()

    return {"status": "started", "job_id": job_id, "source_id": source_id,
            "estimated_duration": src.estimated_duration}


def refresh_all() -> dict:
    """Kick off refresh for every source that supports it."""
    results = []
    for s in SOURCES:
        if s.refresher_module and s.refresher_callable:
            results.append(refresh(s.id))
    return {"started": [r for r in results if r.get("status") == "started"],
            "skipped": [r for r in results if r.get("status") != "started"]}


__all__ = [
    "DataSource", "SOURCES",
    "status_all", "status_one", "refresh", "refresh_all",
]
