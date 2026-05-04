"""
AI Vendor Configuration Auditor
================================
Rule-based checker for AI-vendor / LLM-API configuration. Each rule
maps an observable config setting (zero-data-retention flag, region
lock, KMS key id, content-filter, IP allowlist, etc.) to a canonical
BAA term from `engine.phi_lineage.CANONICAL_BAA_TERMS`. Findings carry
HIPAA / BAA / FedRAMP citations and a copy-pasteable remediation snippet.

Architecture mirrors `engine.policy_capabilities`:
    - `VendorRule` is the unit of audit logic
    - `VENDOR_RULES` is the curated catalog
    - `audit(vendor_id, config)` runs every applicable rule and returns a
      structured findings report

Each parser in `ingest.ai_vendor_config` emits a normalized dict in the
expected shape; this module never reads files itself.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable

# Citations re-used from phi_lineage so the lineage and config audits
# speak the same language to the UI / report writer.
from engine.phi_lineage import CANONICAL_BAA_TERMS

_TERM_CITATIONS: dict[str, str] = {tid: cite for tid, _c, cite in CANONICAL_BAA_TERMS}

Status = str  # 'pass' | 'fail' | 'unknown'


@dataclass
class VendorRule:
    """One rule that an AI-vendor config is checked against."""
    rule_id: str
    vendor_ids: set[str]            # which vendors this applies to
    baa_term: str                   # canonical BAA term it satisfies
    title: str
    citation: str
    remediation: str
    severity: str                   # 'critical' | 'high' | 'medium' | 'low'
    check: Callable[[dict[str, Any]], tuple[Status, Any]] = field(repr=False)


# ---------------------------------------------------------------------------
# Helper predicates — keep individual checks tiny and obvious
# ---------------------------------------------------------------------------
def _bool_pass(val: Any, *, want: bool = True) -> tuple[Status, Any]:
    if val is None:
        return "unknown", None
    return ("pass" if bool(val) == want else "fail"), val


def _present(val: Any) -> tuple[Status, Any]:
    if val in (None, "", [], {}):
        return "fail", val
    return "pass", val


def _value_in(val: Any, allowed: set[str]) -> tuple[Status, Any]:
    if val is None or val == "":
        return "unknown", val
    return ("pass" if val in allowed else "fail"), val


def _value_matches(val: Any, predicate: Callable[[Any], bool]) -> tuple[Status, Any]:
    if val is None or val == "":
        return "unknown", val
    try:
        return ("pass" if predicate(val) else "fail"), val
    except Exception:
        return "unknown", val


_US_REGIONS_AWS = {
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "us-gov-east-1", "us-gov-west-1",
}
_US_REGIONS_AZURE = {
    "eastus", "eastus2", "westus", "westus2", "westus3",
    "centralus", "northcentralus", "southcentralus", "westcentralus",
    "usgovvirginia", "usgovarizona", "usgovtexas",
}
_US_REGIONS_GENERIC = _US_REGIONS_AWS | _US_REGIONS_AZURE | {"us"}


# ===========================================================================
# OPENAI
# ===========================================================================
_OPENAI_RULES: list[VendorRule] = [
    VendorRule(
        rule_id="openai_zdr_enabled",
        vendor_ids={"openai"},
        baa_term="zero_retention",
        title="Zero-Data-Retention enabled on the OpenAI organization",
        citation=_TERM_CITATIONS["zero_retention"],
        remediation="Email OpenAI sales for ZDR enrollment; set "
                    "`x-data-policy: zero-retention` if your org is enrolled.",
        severity="critical",
        check=lambda c: _bool_pass(c.get("zero_data_retention")),
    ),
    VendorRule(
        rule_id="openai_org_id_present",
        vendor_ids={"openai"},
        baa_term="audit_logging",
        title="OPENAI_ORG_ID set so calls are attributable",
        citation=_TERM_CITATIONS["audit_logging"],
        remediation="Set OPENAI_ORG_ID env var and use a per-tenant API key.",
        severity="medium",
        check=lambda c: _present(c.get("organization_id")),
    ),
    VendorRule(
        rule_id="openai_baa_signed",
        vendor_ids={"openai"},
        baa_term="baa_signed",
        title="OpenAI Enterprise BAA executed",
        citation=_TERM_CITATIONS["baa_signed"],
        remediation="Request and execute the OpenAI Enterprise BAA before "
                    "transmitting PHI; ChatGPT Plus / Team are NOT BAA-eligible.",
        severity="critical",
        check=lambda c: _bool_pass(c.get("baa_signed")),
    ),
    VendorRule(
        rule_id="openai_no_training_optout",
        vendor_ids={"openai"},
        baa_term="no_training_use",
        title="API traffic excluded from training (true by default; verify)",
        citation=_TERM_CITATIONS["no_training_use"],
        remediation="OpenAI API traffic is excluded from training by default. "
                    "Confirm at platform.openai.com/data-controls.",
        severity="high",
        check=lambda c: _bool_pass(c.get("training_excluded"), want=True),
    ),
    VendorRule(
        rule_id="openai_tls_in_transit",
        vendor_ids={"openai"},
        baa_term="encryption_in_transit",
        title="API base URL uses HTTPS",
        citation=_TERM_CITATIONS["encryption_in_transit"],
        remediation="Use https://api.openai.com (or your enterprise proxy "
                    "with TLS 1.2+).",
        severity="critical",
        check=lambda c: _value_matches(
            c.get("api_base"),
            lambda v: isinstance(v, str) and v.startswith("https://"),
        ),
    ),
]


# ===========================================================================
# ANTHROPIC
# ===========================================================================
_ANTHROPIC_RULES: list[VendorRule] = [
    VendorRule(
        rule_id="anthropic_zero_retention",
        vendor_ids={"anthropic"},
        baa_term="zero_retention",
        title="Anthropic Zero-Retention header enabled",
        citation=_TERM_CITATIONS["zero_retention"],
        remediation="Set `anthropic-beta: zero-retention` (enterprise tier) "
                    "or contact Anthropic sales.",
        severity="critical",
        check=lambda c: _bool_pass(c.get("zero_retention")),
    ),
    VendorRule(
        rule_id="anthropic_baa_signed",
        vendor_ids={"anthropic"},
        baa_term="baa_signed",
        title="Anthropic BAA executed",
        citation=_TERM_CITATIONS["baa_signed"],
        remediation="Execute the Anthropic Enterprise BAA before transmitting PHI. "
                    "Direct claude.ai consumer accounts are NOT BAA-eligible.",
        severity="critical",
        check=lambda c: _bool_pass(c.get("baa_signed")),
    ),
    VendorRule(
        rule_id="anthropic_tls_in_transit",
        vendor_ids={"anthropic"},
        baa_term="encryption_in_transit",
        title="API base URL uses HTTPS",
        citation=_TERM_CITATIONS["encryption_in_transit"],
        remediation="Use https://api.anthropic.com.",
        severity="critical",
        check=lambda c: _value_matches(
            c.get("api_base"),
            lambda v: isinstance(v, str) and v.startswith("https://"),
        ),
    ),
    VendorRule(
        rule_id="anthropic_no_training_optout",
        vendor_ids={"anthropic"},
        baa_term="no_training_use",
        title="API traffic excluded from training (default; verify in agreement)",
        citation=_TERM_CITATIONS["no_training_use"],
        remediation="Anthropic API traffic is excluded from training by default. "
                    "Confirm in your enterprise agreement and DPAs.",
        severity="high",
        check=lambda c: _bool_pass(c.get("training_excluded"), want=True),
    ),
]


# ===========================================================================
# AWS BEDROCK
# ===========================================================================
_BEDROCK_RULES: list[VendorRule] = [
    VendorRule(
        rule_id="bedrock_us_region",
        vendor_ids={"aws-bedrock", "anthropic-bedrock", "amazon-bedrock"},
        baa_term="us_only_region",
        title="Bedrock invoked in a US AWS region",
        citation=_TERM_CITATIONS["us_only_region"],
        remediation="Configure AWS_REGION to a US region (us-east-1 / us-west-2). "
                    "For FedRAMP High, use us-gov-* in AWS GovCloud.",
        severity="high",
        check=lambda c: _value_in(c.get("region"), _US_REGIONS_AWS),
    ),
    VendorRule(
        rule_id="bedrock_kms_cmk",
        vendor_ids={"aws-bedrock", "anthropic-bedrock", "amazon-bedrock"},
        baa_term="encryption_at_rest",
        title="Customer-managed KMS key configured for model invocation logs",
        citation=_TERM_CITATIONS["encryption_at_rest"],
        remediation="In Bedrock > Settings > Model invocation logging set "
                    "encryption to a customer-managed KMS CMK (not aws/bedrock).",
        severity="high",
        check=lambda c: _value_matches(
            c.get("kms_key_arn"),
            lambda v: isinstance(v, str) and "alias/aws/" not in v
                      and v.startswith("arn:aws"),
        ),
    ),
    VendorRule(
        rule_id="bedrock_guardrail",
        vendor_ids={"aws-bedrock", "anthropic-bedrock", "amazon-bedrock"},
        baa_term="minimum_necessary",
        title="Bedrock Guardrail attached (PII redaction / topic filters)",
        citation=_TERM_CITATIONS["minimum_necessary"],
        remediation="Create a Bedrock Guardrail with PII redaction enabled "
                    "and reference it via guardrailIdentifier in InvokeModel.",
        severity="medium",
        check=lambda c: _present(c.get("guardrail_id")),
    ),
    VendorRule(
        rule_id="bedrock_vpc_endpoint",
        vendor_ids={"aws-bedrock", "anthropic-bedrock", "amazon-bedrock"},
        baa_term="encryption_in_transit",
        title="Bedrock accessed via VPC endpoint (PrivateLink)",
        citation=_TERM_CITATIONS["encryption_in_transit"],
        remediation="Create com.amazonaws.<region>.bedrock-runtime VPC endpoint "
                    "and route SDK traffic through it; deny public egress.",
        severity="medium",
        check=lambda c: _bool_pass(c.get("vpc_endpoint_enabled")),
    ),
    VendorRule(
        rule_id="bedrock_invocation_logging",
        vendor_ids={"aws-bedrock", "anthropic-bedrock", "amazon-bedrock"},
        baa_term="audit_logging",
        title="Model invocation logging enabled (Bedrock data events)",
        citation=_TERM_CITATIONS["audit_logging"],
        remediation="Enable Bedrock model invocation logging to S3/CloudWatch "
                    "and turn on CloudTrail Data Events for bedrock.amazonaws.com.",
        severity="high",
        check=lambda c: _bool_pass(c.get("invocation_logging")),
    ),
    VendorRule(
        rule_id="bedrock_baa_via_aws",
        vendor_ids={"aws-bedrock", "anthropic-bedrock", "amazon-bedrock"},
        baa_term="baa_signed",
        title="AWS BAA covers Bedrock for this account",
        citation=_TERM_CITATIONS["baa_signed"],
        remediation="Bedrock is HIPAA-eligible. Confirm AWS BAA is executed "
                    "for this AWS account at aws.amazon.com/compliance/hipaa-compliance.",
        severity="critical",
        check=lambda c: _bool_pass(c.get("aws_baa_signed")),
    ),
]


# ===========================================================================
# AZURE OPENAI
# ===========================================================================
_AZURE_RULES: list[VendorRule] = [
    VendorRule(
        rule_id="aoai_us_region",
        vendor_ids={"azure-openai"},
        baa_term="us_only_region",
        title="Azure OpenAI deployed in a US region",
        citation=_TERM_CITATIONS["us_only_region"],
        remediation="Deploy the Cognitive Services account in a US region "
                    "(eastus, eastus2, westus, westus3, etc.).",
        severity="high",
        check=lambda c: _value_in(c.get("location"), _US_REGIONS_AZURE),
    ),
    VendorRule(
        rule_id="aoai_private_endpoint",
        vendor_ids={"azure-openai"},
        baa_term="encryption_in_transit",
        title="Private endpoint enabled (public network access disabled)",
        citation=_TERM_CITATIONS["encryption_in_transit"],
        remediation="Set publicNetworkAccess=Disabled and create a Private "
                    "Endpoint to your VNet for the Cognitive Services account.",
        severity="high",
        check=lambda c: _bool_pass(
            c.get("public_network_access") in ("Disabled", "disabled", False)
        ),
    ),
    VendorRule(
        rule_id="aoai_cmk_encryption",
        vendor_ids={"azure-openai"},
        baa_term="encryption_at_rest",
        title="Customer-managed key (Key Vault) configured for encryption",
        citation=_TERM_CITATIONS["encryption_at_rest"],
        remediation="Set properties.encryption.keySource=Microsoft.KeyVault "
                    "with a key from your subscription's Key Vault.",
        severity="high",
        check=lambda c: _bool_pass(c.get("cmk_enabled")),
    ),
    VendorRule(
        rule_id="aoai_diagnostic_logs",
        vendor_ids={"azure-openai"},
        baa_term="audit_logging",
        title="Diagnostic settings sending RequestResponse + Audit logs",
        citation=_TERM_CITATIONS["audit_logging"],
        remediation="Configure Diagnostic settings on the resource to send "
                    "RequestResponse and Audit categories to a Log Analytics workspace.",
        severity="high",
        check=lambda c: _bool_pass(c.get("diagnostic_logs_enabled")),
    ),
    VendorRule(
        rule_id="aoai_content_filter",
        vendor_ids={"azure-openai"},
        baa_term="minimum_necessary",
        title="Content filter (default Hate/Violence/Sexual/SelfHarm) enabled",
        citation=_TERM_CITATIONS["minimum_necessary"],
        remediation="Azure OpenAI ships content filters on by default; verify "
                    "they aren't dialed below 'Medium' for clinical deployments.",
        severity="medium",
        check=lambda c: _bool_pass(c.get("content_filter_enabled")),
    ),
    VendorRule(
        rule_id="aoai_baa_via_msft",
        vendor_ids={"azure-openai"},
        baa_term="baa_signed",
        title="Microsoft BAA covers Azure OpenAI for this tenant",
        citation=_TERM_CITATIONS["baa_signed"],
        remediation="Azure OpenAI is HIPAA-eligible. Confirm the Microsoft "
                    "Online Services HIPAA BAA is signed for your tenant in "
                    "the Microsoft Purview compliance portal.",
        severity="critical",
        check=lambda c: _bool_pass(c.get("microsoft_baa_signed")),
    ),
]


VENDOR_RULES: list[VendorRule] = (
    _OPENAI_RULES + _ANTHROPIC_RULES + _BEDROCK_RULES + _AZURE_RULES
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def applicable_rules(vendor_id: str) -> list[VendorRule]:
    return [r for r in VENDOR_RULES if vendor_id in r.vendor_ids]


def audit(vendor_id: str, config: dict[str, Any]) -> dict[str, Any]:
    """Run every rule applicable to `vendor_id` against `config`.

    `config` is a flat dict produced by one of the parsers in
    `ingest.ai_vendor_config` (or hand-supplied).
    """
    rules = applicable_rules(vendor_id)
    findings: list[dict[str, Any]] = []
    summary = {"pass": 0, "fail": 0, "unknown": 0}

    for r in rules:
        try:
            status, observed = r.check(config)
        except Exception as e:  # noqa: BLE001
            status, observed = "unknown", f"check-error: {e}"
        summary[status] = summary.get(status, 0) + 1
        findings.append({
            "rule_id": r.rule_id,
            "status": status,
            "observed": observed,
            "baa_term": r.baa_term,
            "title": r.title,
            "citation": r.citation,
            "remediation": r.remediation,
            "severity": r.severity,
        })

    return {
        "vendor_id": vendor_id,
        "rules_evaluated": len(rules),
        "summary": summary,
        "findings": findings,
    }


def all_known_vendor_ids() -> set[str]:
    out: set[str] = set()
    for r in VENDOR_RULES:
        out |= r.vendor_ids
    return out


__all__ = [
    "VendorRule", "VENDOR_RULES",
    "audit", "applicable_rules", "all_known_vendor_ids",
]
