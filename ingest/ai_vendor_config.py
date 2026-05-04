"""
Parsers that turn raw AI-vendor configuration sources into the flat
config dict expected by `engine.ai_vendor_config.audit()`.

Sources covered:
    - OpenAI         env vars + optional account JSON snapshot
    - Anthropic      env vars + optional account JSON snapshot
    - Azure OpenAI   ARM resource JSON (from `az cognitiveservices show`)
    - AWS Bedrock    pseudo-config built from AWS_REGION + invocation
                     logging config (`aws bedrock get-model-invocation-
                     logging-configuration`) + guardrail id

All parsers are pure-Python and side-effect free. They return a dict
suitable for direct use with `engine.ai_vendor_config.audit()`.

Usage:
    from ingest.ai_vendor_config import parse_openai_env
    cfg = parse_openai_env()
    from engine.ai_vendor_config import audit
    report = audit("openai", cfg)
"""
from __future__ import annotations
import os
from typing import Any


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------
def parse_openai_env(
    env: dict[str, str] | None = None,
    *,
    account_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an OpenAI config from env vars + an optional account snapshot.

    `account_snapshot` is a dict with any of these keys (typically pulled
    from the OpenAI dashboard or platform.openai.com data-controls API):
        zero_data_retention   bool
        baa_signed            bool
        training_excluded     bool      # default True for API
        organization_id       str
    """
    e = env if env is not None else dict(os.environ)
    snap = account_snapshot or {}
    return {
        "api_base": e.get("OPENAI_BASE_URL")
                    or e.get("OPENAI_API_BASE")
                    or "https://api.openai.com",
        "organization_id": e.get("OPENAI_ORG_ID") or snap.get("organization_id"),
        "zero_data_retention": snap.get("zero_data_retention"),
        "baa_signed": snap.get("baa_signed"),
        "training_excluded": snap.get("training_excluded", True),
    }


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------
def parse_anthropic_env(
    env: dict[str, str] | None = None,
    *,
    account_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an Anthropic config from env vars + optional account snapshot."""
    e = env if env is not None else dict(os.environ)
    snap = account_snapshot or {}
    # Detect zero-retention header on default headers (env-driven).
    headers_blob = (e.get("ANTHROPIC_DEFAULT_HEADERS") or "").lower()
    zr_in_header = "zero-retention" in headers_blob
    return {
        "api_base": e.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com",
        "zero_retention": snap.get("zero_retention", zr_in_header or None),
        "baa_signed": snap.get("baa_signed"),
        "training_excluded": snap.get("training_excluded", True),
    }


# ---------------------------------------------------------------------------
# Azure OpenAI — ARM resource JSON
# ---------------------------------------------------------------------------
def parse_azure_openai_arm(
    resource: dict[str, Any],
    *,
    diagnostic_settings: list[dict[str, Any]] | None = None,
    tenant_baa_signed: bool | None = None,
) -> dict[str, Any]:
    """Parse the JSON returned by:

        az cognitiveservices account show \\
           --name <acct> --resource-group <rg> -o json

    `diagnostic_settings` is the list returned by:
        az monitor diagnostic-settings list --resource <id> -o json
    """
    props = resource.get("properties") or {}
    encryption = props.get("encryption") or {}
    network = props.get("networkAcls") or {}

    diag_enabled = False
    for ds in diagnostic_settings or []:
        for log in ds.get("properties", {}).get("logs", []):
            if log.get("enabled") and log.get("category") in (
                "RequestResponse", "Audit", "AuditEvent",
            ):
                diag_enabled = True
                break

    return {
        "location": resource.get("location") or props.get("location"),
        "public_network_access": props.get("publicNetworkAccess"),
        "cmk_enabled": (encryption.get("keySource") == "Microsoft.KeyVault"),
        "diagnostic_logs_enabled": diag_enabled,
        "content_filter_enabled": props.get("contentFilters", True) is not False,
        "microsoft_baa_signed": tenant_baa_signed,
        "network_default_action": network.get("defaultAction"),
        "resource_id": resource.get("id"),
    }


# ---------------------------------------------------------------------------
# AWS Bedrock
# ---------------------------------------------------------------------------
def parse_bedrock_config(
    *,
    region: str | None = None,
    invocation_logging: dict[str, Any] | None = None,
    guardrail_id: str | None = None,
    vpc_endpoints: list[dict[str, Any]] | None = None,
    aws_baa_signed: bool | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a Bedrock config from typical AWS CLI snapshots.

    `invocation_logging` comes from:
        aws bedrock get-model-invocation-logging-configuration

    `vpc_endpoints` comes from:
        aws ec2 describe-vpc-endpoints --filters \\
           Name=service-name,Values=com.amazonaws.<region>.bedrock-runtime
    """
    e = env if env is not None else dict(os.environ)
    region = region or e.get("AWS_REGION") or e.get("AWS_DEFAULT_REGION")

    inv = invocation_logging or {}
    inv_cfg = inv.get("loggingConfig") or {}
    cw_cfg = inv_cfg.get("cloudWatchConfig") or {}
    s3_cfg = inv_cfg.get("s3Config") or {}
    kms_arn = (cw_cfg.get("logGroupName") and inv_cfg.get("kmsKeyArn")) \
              or s3_cfg.get("kmsKeyArn") \
              or inv_cfg.get("kmsKeyArn")
    inv_enabled = bool(inv_cfg)

    vpc_enabled = False
    for vpe in vpc_endpoints or []:
        if vpe.get("State") == "available":
            vpc_enabled = True
            break

    return {
        "region": region,
        "kms_key_arn": kms_arn,
        "guardrail_id": guardrail_id,
        "vpc_endpoint_enabled": vpc_enabled,
        "invocation_logging": inv_enabled,
        "aws_baa_signed": aws_baa_signed,
    }


# ---------------------------------------------------------------------------
# Convenience: audit + parse in one shot
# ---------------------------------------------------------------------------
def audit_openai_from_env(account_snapshot: dict[str, Any] | None = None) -> dict:
    from engine.ai_vendor_config import audit
    return audit("openai", parse_openai_env(account_snapshot=account_snapshot))


def audit_anthropic_from_env(account_snapshot: dict[str, Any] | None = None) -> dict:
    from engine.ai_vendor_config import audit
    return audit("anthropic", parse_anthropic_env(account_snapshot=account_snapshot))


def audit_azure_openai(
    resource: dict[str, Any],
    diagnostic_settings: list[dict[str, Any]] | None = None,
    tenant_baa_signed: bool | None = None,
) -> dict:
    from engine.ai_vendor_config import audit
    return audit("azure-openai", parse_azure_openai_arm(
        resource,
        diagnostic_settings=diagnostic_settings,
        tenant_baa_signed=tenant_baa_signed,
    ))


def audit_bedrock(
    *,
    region: str | None = None,
    invocation_logging: dict[str, Any] | None = None,
    guardrail_id: str | None = None,
    vpc_endpoints: list[dict[str, Any]] | None = None,
    aws_baa_signed: bool | None = None,
) -> dict:
    from engine.ai_vendor_config import audit
    return audit("aws-bedrock", parse_bedrock_config(
        region=region,
        invocation_logging=invocation_logging,
        guardrail_id=guardrail_id,
        vpc_endpoints=vpc_endpoints,
        aws_baa_signed=aws_baa_signed,
    ))


__all__ = [
    "parse_openai_env",
    "parse_anthropic_env",
    "parse_azure_openai_arm",
    "parse_bedrock_config",
    "audit_openai_from_env",
    "audit_anthropic_from_env",
    "audit_azure_openai",
    "audit_bedrock",
]
