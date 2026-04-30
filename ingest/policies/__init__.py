"""
Policy ingestion - format auto-detection + dispatch.

Public entry point:
    parse_any(content: str|bytes, hint: str|None) -> list[Policy]
    upsert_policies(policies: list[Policy]) -> int

The parse_any function sniffs JSON/XML/text content, detects the platform,
and routes to the right parser. Returns a list of normalized Policy objects.
"""
from __future__ import annotations
import json
import re
from typing import Iterable

from engine.policy_model import Policy
from . import aws, azure, gcp, generic
from .upsert import upsert_policies   # re-export


def parse_any(content: str | bytes, hint: str | None = None) -> list[Policy]:
    """Detect format from content + optional filename hint, return Policies."""
    if isinstance(content, bytes):
        try: content = content.decode("utf-8")
        except UnicodeDecodeError: content = content.decode("latin-1", errors="ignore")
    text = content.strip()
    h = (hint or "").lower()

    # ---------- filename hints first ----------
    if "iptables" in h or h.endswith(".rules") or "iptables-save" in text[:200]:
        return generic.parse_iptables(text)
    if "nftables" in h or h.endswith(".nft") or text.lstrip().startswith("table "):
        return generic.parse_nftables(text)
    if "modsec" in h or "SecRule" in text[:500]:
        return generic.parse_modsecurity(text)
    if "pfsense" in h or (text.lstrip().startswith("<?xml") and "pfsense" in text[:500].lower()):
        return generic.parse_pfsense(text)

    # ---------- JSON-based platforms ----------
    if text.lstrip().startswith(("{", "[")):
        try:
            doc = json.loads(text)
        except Exception:
            return []
        return _route_json(doc, hint)

    return []


def _route_json(doc: dict | list, hint: str | None) -> list[Policy]:
    h = (hint or "").lower()
    flat = json.dumps(doc)[:2000].lower() if isinstance(doc, (dict, list)) else ""

    # ---------- AWS family ----------
    if isinstance(doc, dict):
        # AWS IAM / SCP / S3 / KMS policy doc
        if "Statement" in doc and "Version" in doc:
            return aws.parse_iam_doc(doc, hint)
        # AWS Security Group describe-output
        if "SecurityGroups" in doc:
            return aws.parse_security_groups(doc)
        # AWS WAFv2 web ACL
        if "WebACL" in doc or "WebACLs" in doc or ("Rules" in doc and "VisibilityConfig" in flat):
            return aws.parse_waf(doc)
        # AWS S3 bucket policy returned by GetBucketPolicy { "Policy": "..." }
        if "Policy" in doc and isinstance(doc["Policy"], str) and "Statement" in doc["Policy"]:
            try:
                inner = json.loads(doc["Policy"])
                return aws.parse_iam_doc(inner, hint or "s3-bucket-policy")
            except Exception: pass

        # ---------- Azure family ----------
        # CA: Microsoft Graph identity/conditionalAccess/policies
        if "conditions" in doc and "grantControls" in doc:
            return azure.parse_conditional_access([doc])
        if "value" in doc and isinstance(doc["value"], list):
            sample = doc["value"][0] if doc["value"] else {}
            if isinstance(sample, dict):
                if "conditions" in sample and "grantControls" in sample:
                    return azure.parse_conditional_access(doc["value"])
                if "@odata.type" in sample and "deviceCompliancePolicy" in sample.get("@odata.type",""):
                    return azure.parse_intune_compliance(doc["value"])
                if "@odata.type" in sample and "deviceConfiguration" in sample.get("@odata.type",""):
                    return azure.parse_intune_configuration(doc["value"])
                if "securityRules" in sample or "destinationPortRange" in sample:
                    return azure.parse_nsg(doc["value"])
        # Azure NSG single object
        if "securityRules" in doc:
            return azure.parse_nsg([doc])

        # ---------- GCP family ----------
        # GCP IAM bindings doc
        if "bindings" in doc and isinstance(doc["bindings"], list):
            return gcp.parse_iam(doc, hint)
        # GCP VPC firewall rule (single)
        if ("direction" in doc and ("allowed" in doc or "denied" in doc)):
            return gcp.parse_vpc_firewall([doc])
        # GCP Org policy
        if "constraint" in doc and ("listPolicy" in doc or "booleanPolicy" in doc):
            return gcp.parse_org_policy([doc])

        # ---------- Cloudflare ----------
        if "filter" in doc and "action" in doc and ("expression" in flat):
            return generic.parse_cloudflare([doc])
        if "result" in doc and isinstance(doc["result"], list):
            return generic.parse_cloudflare(doc["result"])

    if isinstance(doc, list) and doc:
        # List of similar items - try each detector
        sample = doc[0]
        if isinstance(sample, dict):
            if "Statement" in sample:
                out = []
                for s in doc: out += aws.parse_iam_doc(s, hint)
                return out
            if "direction" in sample and ("allowed" in sample or "denied" in sample):
                return gcp.parse_vpc_firewall(doc)
            if "conditions" in sample and "grantControls" in sample:
                return azure.parse_conditional_access(doc)

    return []
