"""
Cloud connectors - read-only live policy import.
================================================
Optional helpers that pull policies directly from cloud APIs using
least-privilege credentials. Each connector is opt-in and only loads its
SDK when called, so the rest of Cyber Nexus has zero added dependency.

Required IAM permissions per connector are documented inline. Run from CLI:

    python -m ingest.policies.cloud_connectors aws    --profile prod
    python -m ingest.policies.cloud_connectors azure  --tenant <id>
    python -m ingest.policies.cloud_connectors gcp    --project my-proj
"""
from __future__ import annotations
import argparse
import json
from rich.console import Console

from . import aws, azure, gcp
from .upsert import upsert_policies

console = Console()


# ---------------------------------------------------------------------------
# AWS connector
# ---------------------------------------------------------------------------
# Required: read-only across IAM, EC2, WAFv2, S3, KMS. Suggested managed
# policies: SecurityAudit + IAMReadOnlyAccess.
def import_aws(profile: str | None = None, region: str | None = None) -> int:
    try:
        import boto3
    except ImportError:
        console.print("[red]boto3 not installed. `pip install boto3` to use the AWS connector.")
        return 0
    sess = boto3.Session(profile_name=profile, region_name=region)
    iam = sess.client("iam")
    ec2 = sess.client("ec2")
    waf = sess.client("wafv2")
    s3  = sess.client("s3")

    total = 0
    # IAM customer-managed policies
    pols: list = []
    try:
        for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
            for p in page.get("Policies", []) or []:
                ver = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])
                doc = ver["PolicyVersion"]["Document"]
                pols += aws.parse_iam_doc(doc, hint=p.get("PolicyName"))
        total += upsert_policies(pols)
    except Exception as e: console.print(f"[yellow]AWS IAM: {e}")

    # Security Groups (paginated per region)
    pols = []
    try:
        sgs = ec2.describe_security_groups()
        pols += aws.parse_security_groups(sgs)
        total += upsert_policies(pols)
    except Exception as e: console.print(f"[yellow]AWS SG: {e}")

    # WAFv2
    pols = []
    try:
        for scope in ("REGIONAL", "CLOUDFRONT"):
            try:
                lst = waf.list_web_acls(Scope=scope)
            except Exception: continue
            for s in lst.get("WebACLs", []) or []:
                acl = waf.get_web_acl(Name=s["Name"], Id=s["Id"], Scope=scope)
                pols += aws.parse_waf({"WebACL": acl["WebACL"]})
        total += upsert_policies(pols)
    except Exception as e: console.print(f"[yellow]AWS WAF: {e}")

    # S3 bucket policies
    pols = []
    try:
        for b in s3.list_buckets().get("Buckets", []) or []:
            try:
                p = s3.get_bucket_policy(Bucket=b["Name"])
                doc = json.loads(p["Policy"])
                pols += aws.parse_iam_doc(doc, hint=f"s3:{b['Name']}")
            except s3.exceptions.from_code("NoSuchBucketPolicy"):
                continue
            except Exception: continue
        total += upsert_policies(pols)
    except Exception as e: console.print(f"[yellow]AWS S3: {e}")

    console.print(f"[green]AWS connector loaded {total} policies")
    return total


# ---------------------------------------------------------------------------
# Azure connector
# ---------------------------------------------------------------------------
# Required: Microsoft Graph application permissions:
#   Policy.Read.All, DeviceManagementConfiguration.Read.All
# Suggested role: Security Reader.
def import_azure(tenant: str | None = None) -> int:
    try:
        from msgraph.core import GraphClient
        from azure.identity import DefaultAzureCredential
    except ImportError:
        console.print("[red]Azure SDK missing. `pip install azure-identity msgraph-core` to use Azure connector.")
        return 0
    cred = DefaultAzureCredential()
    client = GraphClient(credential=cred)
    total = 0

    # Conditional Access
    try:
        r = client.get("/identity/conditionalAccess/policies")
        items = r.json().get("value", [])
        total += upsert_policies(azure.parse_conditional_access(items))
    except Exception as e: console.print(f"[yellow]Azure CA: {e}")

    # Intune compliance
    try:
        r = client.get("/deviceManagement/deviceCompliancePolicies")
        items = r.json().get("value", [])
        total += upsert_policies(azure.parse_intune_compliance(items))
    except Exception as e: console.print(f"[yellow]Intune compliance: {e}")

    # Intune device configuration
    try:
        r = client.get("/deviceManagement/deviceConfigurations")
        items = r.json().get("value", [])
        total += upsert_policies(azure.parse_intune_configuration(items))
    except Exception as e: console.print(f"[yellow]Intune config: {e}")

    console.print(f"[green]Azure connector loaded {total} policies")
    return total


# ---------------------------------------------------------------------------
# GCP connector
# ---------------------------------------------------------------------------
# Required: roles/iam.securityReviewer, roles/compute.viewer
def import_gcp(project: str) -> int:
    try:
        from google.cloud import resourcemanager_v3, compute_v1
    except ImportError:
        console.print("[red]GCP SDK missing. `pip install google-cloud-resource-manager google-cloud-compute`")
        return 0
    total = 0
    # IAM bindings on the project
    try:
        rm = resourcemanager_v3.ProjectsClient()
        pol = rm.get_iam_policy(resource=f"projects/{project}")
        # The proto -> dict conversion
        doc = {"bindings": [{"role": b.role, "members": list(b.members)} for b in pol.bindings]}
        total += upsert_policies(gcp.parse_iam(doc, hint=project))
    except Exception as e: console.print(f"[yellow]GCP IAM: {e}")

    # VPC firewall rules
    try:
        fw = compute_v1.FirewallsClient()
        rules = []
        for r in fw.list(project=project):
            rules.append({
                "name": r.name, "direction": r.direction,
                "allowed": [{"IPProtocol": a.I_p_protocol} for a in (r.allowed or [])],
                "denied":  [{"IPProtocol": d.I_p_protocol} for d in (r.denied or [])],
                "sourceRanges": list(r.source_ranges or []),
                "targetTags": list(r.target_tags or []),
            })
        total += upsert_policies(gcp.parse_vpc_firewall(rules))
    except Exception as e: console.print(f"[yellow]GCP FW: {e}")

    console.print(f"[green]GCP connector loaded {total} policies")
    return total


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Live cloud policy import")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("aws"); a.add_argument("--profile"); a.add_argument("--region")
    z = sub.add_parser("azure"); z.add_argument("--tenant")
    g = sub.add_parser("gcp"); g.add_argument("--project", required=True)
    args = p.parse_args()
    if args.cmd == "aws":   import_aws(args.profile, args.region)
    if args.cmd == "azure": import_azure(args.tenant)
    if args.cmd == "gcp":   import_gcp(args.project)


if __name__ == "__main__":
    main()
