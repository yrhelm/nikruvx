"""
SIEM Query Template Generator
==============================
Turn a behavioral indicator + ATT&CK technique into deployable detection
rules across the three formats security teams actually use:

    - Sigma          (YAML, vendor-agnostic — translatable to anything)
    - KQL            (Microsoft Sentinel / Defender XDR / 365 Defender)
    - Splunk SPL
    - Elastic DSL    (bonus, for ELK shops)
    - CrowdStrike FQL

The pipeline:
    behavioral_indicator + technique_id  →  Detection
                                              ↓
                                    {sigma, kql, splunk, ...}

Approach is template-based for predictable / safe output. An optional
LLM-assisted generator fills in the trickier indicators by leveraging
the existing engine.llm wrapper (Ollama).

Public API:
    generate_for_indicator(indicator, technique_id) -> Detection
    generate_for_pattern(pattern_id) -> list[Detection]
    available_formats() -> list[str]
"""
from __future__ import annotations
import hashlib
import re
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Detection:
    indicator: str                    # source behavioral indicator string
    technique_id: str                 # ATT&CK technique
    title: str                        # human-readable rule title
    severity: str                     # 'critical' | 'high' | 'medium' | 'low'
    log_source: str                   # 'windows' | 'linux' | 'web' | 'cloud' | 'network'
    sigma: str = ""
    kql: str = ""
    splunk: str = ""
    elastic: str = ""
    falcon_fql: str = ""
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Indicator type detection
# ---------------------------------------------------------------------------
_INDICATOR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:syslog|/var/log|auth\.log|secure)\b", re.I),       "linux_auth"),
    (re.compile(r"\b(?:event ?id|wineventlog|sysmon|4624|4625|4688|7045)\b", re.I), "windows_event"),
    (re.compile(r"\b(?:powershell|cmd\.exe|wmic)\b", re.I),                "windows_process"),
    (re.compile(r"\b(?:ssh|sshd)\b", re.I),                                "linux_ssh"),
    (re.compile(r"\b(?:http|url|user-agent|referer|/api/|GET |POST )\b", re.I), "web_access"),
    (re.compile(r"\b(?:dns|cname|txt record|resolver)\b", re.I),           "dns"),
    (re.compile(r"\b(?:cloudtrail|aws|s3|iam)\b", re.I),                   "cloud_aws"),
    (re.compile(r"\b(?:azure|signins|conditional access)\b", re.I),        "cloud_azure"),
    (re.compile(r"\b(?:gcp|stackdriver|google cloud)\b", re.I),            "cloud_gcp"),
    (re.compile(r"\b(?:packet|flow|netflow|tcp|udp|connection)\b", re.I),  "network"),
    (re.compile(r"\b(?:process|exec|spawn|fork)\b", re.I),                 "process"),
    (re.compile(r"\$\{jndi:", re.I),                                       "web_access"),  # log4shell
    (re.compile(r"\b(?:xz/liblzma|lzma_)\b", re.I),                        "linux_process"),
    (re.compile(r"\b(?:rm\s+-rf|sudo|chmod 777|wget\s+http|curl\s+http)\b", re.I), "linux_process"),
]


def _classify_log_source(indicator: str) -> str:
    for pat, source in _INDICATOR_PATTERNS:
        if pat.search(indicator):
            return source
    return "generic"


_LOGSOURCE_TO_SIGMA: dict[str, dict[str, str]] = {
    "linux_auth":    {"product": "linux", "service": "auth"},
    "linux_ssh":     {"product": "linux", "service": "auth"},
    "linux_process": {"product": "linux", "category": "process_creation"},
    "windows_event": {"product": "windows", "service": "security"},
    "windows_process": {"product": "windows", "category": "process_creation"},
    "web_access":    {"category": "webserver"},
    "dns":           {"category": "dns"},
    "cloud_aws":     {"product": "aws", "service": "cloudtrail"},
    "cloud_azure":   {"product": "azure", "service": "signinlogs"},
    "cloud_gcp":     {"product": "gcp", "service": "audit"},
    "network":       {"category": "firewall"},
    "process":       {"category": "process_creation"},
    "generic":       {"category": "application"},
}


# ---------------------------------------------------------------------------
# Per-format generators
# ---------------------------------------------------------------------------
def _quote(s: str) -> str:
    """Quote a string for inclusion in YAML/SPL/etc."""
    return s.replace("\\", "\\\\").replace("\"", "\\\"")


def _sanitize_yaml(s: str) -> str:
    """Make a string safe to put in a YAML block scalar."""
    return s.replace("\n", " ").strip()


def _sigma_id(indicator: str, technique_id: str) -> str:
    """Stable UUID derived from (indicator, technique) so re-generating
    the same rule yields the same id."""
    seed = f"{indicator}|{technique_id}".encode("utf-8")
    h = hashlib.sha256(seed).digest()
    return str(uuid.UUID(bytes=h[:16]))


def _extract_keywords(indicator: str) -> list[str]:
    """Extract the most-distinctive substring from a behavioral indicator
    to use as a primary detection keyword. Heuristic but predictable."""
    # Try quoted strings first
    quoted = re.findall(r'"([^"]+)"', indicator) + re.findall(r"'([^']+)'", indicator)
    if quoted:
        return [q for q in quoted if len(q) >= 3]
    # Try {jndi:...} / ${...} sigils
    sigil = re.findall(r"\$\{[^}]+\}", indicator)
    if sigil:
        return sigil
    # Try long-enough alphanumeric tokens
    tokens = re.findall(r"\b[A-Za-z0-9_./\\:-]{4,}\b", indicator)
    # Filter out common english words
    stop = {"adversary", "attacker", "user", "system", "service", "with",
            "for", "the", "this", "that", "these", "those", "your", "their",
            "from", "into", "over", "under", "during", "after", "before",
            "appears", "running", "process", "command"}
    return [t for t in tokens if t.lower() not in stop and len(t) >= 4][:5]


def _gen_sigma(indicator: str, technique_id: str, severity: str,
               log_source: str, title: str) -> str:
    keywords = _extract_keywords(indicator)
    if not keywords:
        keywords = [indicator[:40]]
    rule_id = _sigma_id(indicator, technique_id)
    ls = _LOGSOURCE_TO_SIGMA.get(log_source, _LOGSOURCE_TO_SIGMA["generic"])
    ls_block = "\n".join(f"  {k}: {v}" for k, v in ls.items())
    detection_block = "  selection:\n    Keywords:\n" + "\n".join(
        f"      - \"{_quote(k)}\"" for k in keywords
    )
    sev_map = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}
    return (
        f"title: {_sanitize_yaml(title)}\n"
        f"id: {rule_id}\n"
        f"status: experimental\n"
        f"description: |\n  {_sanitize_yaml(indicator)}\n"
        f"references:\n  - https://attack.mitre.org/techniques/{technique_id}/\n"
        f"author: NikruvX SIEM Generator\n"
        f"tags:\n"
        f"  - attack.{technique_id.lower()}\n"
        f"logsource:\n{ls_block}\n"
        f"detection:\n{detection_block}\n"
        f"  condition: selection\n"
        f"falsepositives:\n  - Legitimate administrative activity\n  - Penetration testing\n"
        f"level: {sev_map.get(severity, 'medium')}\n"
    )


def _gen_kql(indicator: str, technique_id: str, log_source: str) -> str:
    keywords = _extract_keywords(indicator)
    if not keywords:
        return f"// no clear keyword extracted from indicator\n// raw: {indicator}"
    or_clauses = " or ".join(f'"{_quote(k)}"' for k in keywords)
    table = {
        "linux_auth":    "Syslog | where Facility == \"auth\"",
        "linux_ssh":     "Syslog | where ProcessName startswith \"sshd\"",
        "linux_process": "Syslog",
        "windows_event": "SecurityEvent",
        "windows_process": "DeviceProcessEvents",
        "web_access":    "AzureDiagnostics | where Category == \"ApplicationGatewayAccessLog\"",
        "dns":           "DnsEvents",
        "cloud_aws":     "AWSCloudTrail",
        "cloud_azure":   "SigninLogs",
        "cloud_gcp":     "GCPAuditLogs",
        "network":       "AzureNetworkAnalytics_CL",
        "process":       "DeviceProcessEvents",
        "generic":       "AppEvents",
    }.get(log_source, "AppEvents")
    return (
        f"// MITRE ATT&CK: {technique_id}\n"
        f"{table}\n"
        f"| where TimeGenerated > ago(24h)\n"
        f"| where * has_any ({or_clauses})\n"
        f"| project TimeGenerated, Computer = column_ifexists('Computer','-'), "
        f"Account = column_ifexists('Account','-'), Activity = column_ifexists('Activity','-')\n"
        f"| limit 100\n"
    )


def _gen_splunk(indicator: str, technique_id: str, log_source: str) -> str:
    keywords = _extract_keywords(indicator)
    if not keywords:
        return f"# no clear keyword extracted\n# raw: {indicator}"
    quoted = " OR ".join(f'"{_quote(k)}"' for k in keywords)
    sourcetype = {
        "linux_auth":    "linux_secure",
        "linux_ssh":     "linux_secure",
        "linux_process": "syslog",
        "windows_event": "WinEventLog:Security",
        "windows_process": "Sysmon",
        "web_access":    "access_combined",
        "dns":           "dns",
        "cloud_aws":     "aws:cloudtrail",
        "cloud_azure":   "azure:signin",
        "cloud_gcp":     "gcp:auditlog",
        "network":       "stream:tcp",
        "process":       "Sysmon",
        "generic":       "*",
    }.get(log_source, "*")
    return (
        f"# MITRE ATT&CK: {technique_id}\n"
        f"index=* sourcetype={sourcetype} ({quoted})\n"
        f"| stats count by host, source, sourcetype, user\n"
        f"| where count > 0\n"
        f"| sort -count\n"
    )


def _gen_elastic(indicator: str, technique_id: str, log_source: str) -> str:
    keywords = _extract_keywords(indicator)
    or_clauses = " OR ".join(f'"{_quote(k)}"' for k in keywords) or "*"
    return (
        '{\n'
        '  "query": {\n'
        '    "bool": {\n'
        '      "must": [\n'
        f'        {{ "query_string": {{ "query": "{or_clauses}" }} }}\n'
        '      ],\n'
        '      "filter": [\n'
        '        { "range": { "@timestamp": { "gte": "now-24h" } } }\n'
        '      ]\n'
        '    }\n'
        '  },\n'
        f'  "_meta": {{ "attack_technique": "{technique_id}", "log_source": "{log_source}" }}\n'
        '}\n'
    )


def _gen_falcon(indicator: str, technique_id: str) -> str:
    keywords = _extract_keywords(indicator)
    if not keywords:
        return f"// no clear keyword extracted\n// raw: {indicator}"
    or_clauses = ", ".join(f'"*{_quote(k)}*"' for k in keywords)
    return (
        f"// MITRE ATT&CK: {technique_id}\n"
        f"#event_simpleName=ProcessRollup2\n"
        f"| CommandLine=({or_clauses})\n"
        f"| stats count() by ComputerName, UserName, CommandLine\n"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def generate_for_indicator(
    indicator: str,
    technique_id: str,
    severity: str = "medium",
    title: str | None = None,
) -> Detection:
    """Produce all five rule formats for one (indicator, technique) pair."""
    log_source = _classify_log_source(indicator)
    title = title or f"NikruvX detect: {technique_id} — {indicator[:60]}"
    det = Detection(
        indicator=indicator,
        technique_id=technique_id,
        title=title,
        severity=severity,
        log_source=log_source,
        sigma=_gen_sigma(indicator, technique_id, severity, log_source, title),
        kql=_gen_kql(indicator, technique_id, log_source),
        splunk=_gen_splunk(indicator, technique_id, log_source),
        elastic=_gen_elastic(indicator, technique_id, log_source),
        falcon_fql=_gen_falcon(indicator, technique_id),
    )
    if not _extract_keywords(indicator):
        det.notes.append("No distinctive keyword extracted — review keyword list "
                         "manually before deploying.")
    return det


def generate_for_pattern(pattern_id: str) -> list[Detection]:
    """For a zero-day pattern, generate detections for each of its
    behavioral indicators × each of its mapped techniques."""
    from .zero_day_catalog import by_id
    pattern = by_id(pattern_id)
    if not pattern:
        return []
    out: list[Detection] = []
    for indicator in pattern.behavioral_indicators or [pattern.description]:
        for tid in pattern.techniques:
            det = generate_for_indicator(
                indicator, tid,
                severity=pattern.severity,
                title=f"{pattern.name} — {tid}",
            )
            out.append(det)
    return out


def available_formats() -> list[str]:
    return ["sigma", "kql", "splunk", "elastic", "falcon_fql"]


def to_dict(det: Detection) -> dict[str, Any]:
    return asdict(det)


__all__ = [
    "Detection",
    "generate_for_indicator", "generate_for_pattern",
    "available_formats", "to_dict",
]
