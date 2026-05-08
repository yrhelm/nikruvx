"""
External vulnerability-finding CSV importer.
=============================================
Parses CSV exports from common vuln scanners and normalizes them into
a single record format. Supports auto-detection for:

    Wiz       — 'CVE', 'Severity', 'Package Name', 'Resource'
    Snyk      — 'ISSUE_ID', 'PACKAGE', 'PROJECT_NAME'
    Tenable   — 'CVE', 'Severity', 'Plugin Name'
    Qualys    — 'QID', 'CVE ID', 'Vulnerability Severity'
    Generic   — explicit field-name mapping

The normalized record is consumed by `engine.external_finding_prioritizer`
which re-scores against the user's environment (inventory, KEV, PoC,
TTP coverage, forecast catalog).
"""
from __future__ import annotations
import csv
import hashlib
import io
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    """Normalized vulnerability finding from any scanner."""
    source: str                        # 'wiz' | 'snyk' | 'tenable' | 'qualys' | 'generic'
    external_id: str                   # vendor-specific id, or row hash
    cve_id: str | None = None
    cwe_id: str | None = None
    title: str = ""
    description: str = ""
    package: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    ecosystem: str | None = None       # npm | pypi | maven | go | os | container
    original_severity: str = "unknown" # critical | high | medium | low | unknown
    original_cvss: float = 0.0
    file_path: str | None = None
    asset_id: str | None = None
    project: str | None = None
    has_fix: bool = False
    exploitable: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------
_FIELD_SIGNATURES: dict[str, set[str]] = {
    "wiz":     {"resource", "issue", "wiz score", "subscription", "cloud account"},
    "snyk":    {"issue_id", "introduced through", "project_name", "issue url"},
    "tenable": {"plugin name", "plugin id", "plugin output", "host", "exploit available"},
    "qualys":  {"qid", "vuln status", "asset_name", "ssl"},
}


def detect_format(headers: list[str]) -> str:
    """Auto-detect the source scanner from CSV headers. Returns
    'wiz' | 'snyk' | 'tenable' | 'qualys' | 'generic'.

    Uses substring matching so a signature term `resource` matches a
    header `Resource ID`, `Source Resource`, etc. — header variants
    across vendor doc revisions don't break detection."""
    lower_headers = [h.strip().lower() for h in headers]
    header_blob = " | ".join(lower_headers)
    best = ("generic", 0)
    for name, sig in _FIELD_SIGNATURES.items():
        score = sum(1 for term in sig if term in header_blob)
        if score > best[1]:
            best = (name, score)
    return best[0] if best[1] > 0 else "generic"


# ---------------------------------------------------------------------------
# Per-format field mapping
# ---------------------------------------------------------------------------
def _get(row: dict[str, str], *keys: str, default: str = "") -> str:
    """Case-insensitive lookup across multiple candidate header names."""
    lower = {k.strip().lower(): v for k, v in row.items()}
    for k in keys:
        v = lower.get(k.lower(), "")
        if v:
            return str(v).strip()
    return default


def _to_float(s: str, default: float = 0.0) -> float:
    try:
        return float(s) if s else default
    except (ValueError, TypeError):
        return default


def _to_bool(s: str, default: bool = False) -> bool:
    if not s:
        return default
    return str(s).strip().lower() in ("true", "yes", "1", "y", "available")


def _normalize_severity(s: str) -> str:
    s = (s or "").strip().lower()
    if s in ("critical", "crit"):                return "critical"
    if s in ("high", "hi"):                      return "high"
    if s in ("medium", "med", "moderate"):       return "medium"
    if s in ("low", "lo", "info", "informational"): return "low"
    return "unknown"


def _ecosystem_from_package(pkg: str) -> str | None:
    if not pkg:
        return None
    p = pkg.strip()
    if p.startswith("@") or p.startswith("npm:"):           return "npm"
    if p.startswith("pypi:") or "::" in p:                  return "pypi"
    if ":" in p and p.count(":") == 1 and p.split(":")[0].count(".") >= 1:
        return "maven"
    if p.startswith("github.com/"):                         return "go"
    return None


def _row_hash(row: dict[str, str]) -> str:
    blob = "|".join(f"{k}={v}" for k, v in sorted(row.items()))
    return hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()[:16]


def _parse_wiz(row: dict[str, str]) -> Finding:
    cve = _get(row, "CVE", "CVE ID", "Vulnerability") or None
    pkg = _get(row, "Package Name", "Package", "Vulnerable Package") or None
    return Finding(
        source="wiz",
        external_id=_get(row, "Issue ID", "ID") or _row_hash(row),
        cve_id=cve,
        title=_get(row, "Issue", "Vulnerability Name", "Title")[:240],
        description=_get(row, "Description")[:2000],
        package=pkg,
        version=_get(row, "Version", "Vulnerable Version") or None,
        fixed_version=_get(row, "Fixed Version", "Remediation Version") or None,
        ecosystem=_ecosystem_from_package(pkg or ""),
        original_severity=_normalize_severity(_get(row, "Severity", "Vulnerability Severity")),
        original_cvss=_to_float(_get(row, "CVSS Score", "Wiz Score", "CVSS")),
        file_path=_get(row, "Path", "File", "Detected In") or None,
        asset_id=_get(row, "Resource ID", "Resource", "Asset ID") or None,
        project=_get(row, "Cloud Account", "Subscription", "Project") or None,
        has_fix=_to_bool(_get(row, "Has Fix", "Fix Available")),
        exploitable=_to_bool(_get(row, "Exploitable", "Exploitability")),
        raw=row,
    )


def _parse_snyk(row: dict[str, str]) -> Finding:
    pkg = _get(row, "PACKAGE", "Package", "package") or None
    return Finding(
        source="snyk",
        external_id=_get(row, "ISSUE_ID", "Issue ID", "issue_id") or _row_hash(row),
        cve_id=_get(row, "CVE", "Cve", "cve") or None,
        cwe_id=_get(row, "CWE", "Cwe", "cwe") or None,
        title=_get(row, "TITLE", "Title", "title")[:240],
        description=_get(row, "DESCRIPTION", "Description")[:2000],
        package=pkg,
        version=_get(row, "VERSION", "Version", "version") or None,
        fixed_version=_get(row, "FIXED_VERSION", "Fixed In", "REMEDIATION") or None,
        ecosystem=(_get(row, "ECOSYSTEM", "Ecosystem", "PACKAGE_MANAGER") or
                   _ecosystem_from_package(pkg or "")) or None,
        original_severity=_normalize_severity(
            _get(row, "SEVERITY", "Severity", "severity")),
        original_cvss=_to_float(_get(row, "CVSS_SCORE", "CVSS Score", "CVSS")),
        file_path=_get(row, "INTRODUCED_THROUGH", "File Path") or None,
        project=_get(row, "PROJECT_NAME", "Project", "PROJECT") or None,
        has_fix=_to_bool(_get(row, "FIXABLE", "FIXED_VERSION", "fixed_version")),
        exploitable=_to_bool(_get(row, "EXPLOIT_MATURITY", "EXPLOITABLE")),
        raw=row,
    )


def _parse_tenable(row: dict[str, str]) -> Finding:
    return Finding(
        source="tenable",
        external_id=_get(row, "Plugin ID", "ID") or _row_hash(row),
        cve_id=(_get(row, "CVE", "CVE ID").split(",")[0].strip() or None),
        title=_get(row, "Plugin Name", "Synopsis")[:240],
        description=_get(row, "Description", "Plugin Output")[:2000],
        original_severity=_normalize_severity(_get(row, "Severity", "Risk")),
        original_cvss=_to_float(_get(row, "CVSS3 Base Score", "CVSS Base Score", "CVSS")),
        asset_id=_get(row, "Host", "IP Address") or None,
        exploitable=_to_bool(_get(row, "Exploit Available")),
        raw=row,
    )


def _parse_qualys(row: dict[str, str]) -> Finding:
    return Finding(
        source="qualys",
        external_id=_get(row, "QID", "ID") or _row_hash(row),
        cve_id=(_get(row, "CVE ID", "CVE").split(",")[0].strip() or None),
        title=_get(row, "Title", "Vulnerability")[:240],
        description=_get(row, "Threat", "Description")[:2000],
        original_severity=_normalize_severity(_get(row, "Severity",
                                                     "Vulnerability Severity")),
        original_cvss=_to_float(_get(row, "CVSS3.1 Base", "CVSS Base", "CVSS")),
        asset_id=_get(row, "Asset Name", "DNS Name", "IP Address") or None,
        raw=row,
    )


def _parse_generic(row: dict[str, str]) -> Finding:
    pkg = _get(row, "Package", "Package Name", "PACKAGE") or None
    return Finding(
        source="generic",
        external_id=_get(row, "ID") or _row_hash(row),
        cve_id=_get(row, "CVE", "CVE ID", "cve_id") or None,
        cwe_id=_get(row, "CWE", "CWE ID") or None,
        title=_get(row, "Title", "Name", "Issue")[:240],
        package=pkg,
        version=_get(row, "Version") or None,
        fixed_version=_get(row, "Fixed Version") or None,
        ecosystem=(_get(row, "Ecosystem") or _ecosystem_from_package(pkg or "")) or None,
        original_severity=_normalize_severity(_get(row, "Severity", "Risk")),
        original_cvss=_to_float(_get(row, "CVSS", "CVSS Score")),
        file_path=_get(row, "Path", "File") or None,
        asset_id=_get(row, "Asset", "Resource ID") or None,
        has_fix=_to_bool(_get(row, "Has Fix", "Fixable")),
        raw=row,
    )


_PARSERS = {
    "wiz":     _parse_wiz,
    "snyk":    _parse_snyk,
    "tenable": _parse_tenable,
    "qualys":  _parse_qualys,
    "generic": _parse_generic,
}


# ---------------------------------------------------------------------------
# Public CSV ingestion
# ---------------------------------------------------------------------------
def parse_csv(content: str | bytes,
              source: str | None = None) -> tuple[str, list[Finding]]:
    """Parse a CSV blob, auto-detect the format unless `source` is set,
    return (detected_source, findings_list)."""
    if isinstance(content, bytes):
        content = content.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(content))
    headers = reader.fieldnames or []
    detected = source or detect_format(headers)
    parser = _PARSERS.get(detected, _parse_generic)
    findings = [parser(row) for row in reader]
    return detected, findings


def parse_csv_file(path: str, source: str | None = None) -> tuple[str, list[Finding]]:
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        return parse_csv(f.read(), source=source)


def to_dict(f: Finding) -> dict:
    return asdict(f)


__all__ = [
    "Finding", "detect_format", "parse_csv", "parse_csv_file", "to_dict",
]
