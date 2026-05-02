"""Tests for ingest.policies parsers + auto-detection."""
from __future__ import annotations
import json

from ingest.policies import parse_any
from ingest.policies.aws import parse_iam_doc, parse_security_groups, parse_waf
from ingest.policies.azure import parse_conditional_access, parse_intune_compliance
from ingest.policies.gcp import parse_iam, parse_vpc_firewall
from ingest.policies.generic import parse_iptables, parse_modsecurity, parse_cloudflare


# ---------------------------------------------------------------------------
# AWS IAM
# ---------------------------------------------------------------------------
def test_aws_iam_mfa_deny_tags_mfa_required():
    iam = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
        }],
    }
    pols = parse_iam_doc(iam, "mfa-policy")
    assert len(pols) == 1
    assert pols[0].source == "AWS-IAM"
    [c] = pols[0].controls
    assert c.effect == "BLOCK"
    assert "mfa-required" in c.capability_classes
    assert "AUTH_BYPASS" in c.capabilities_mitigated


def test_aws_iam_iam_star_deny_tags_no_standing_admin():
    iam = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}],
    }
    pols = parse_iam_doc(iam)
    [c] = pols[0].controls
    assert "no-standing-admin" in c.capability_classes


def test_aws_iam_kms_action_tags_kms_resource_policy():
    iam = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "*"}],
    }
    pols = parse_iam_doc(iam)
    assert "kms-resource-policy" in pols[0].controls[0].capability_classes


# ---------------------------------------------------------------------------
# AWS Security Groups
# ---------------------------------------------------------------------------
def test_aws_sg_restrictive_egress_tags_default_deny():
    sg = {"SecurityGroups": [{
        "GroupId": "sg-prod", "GroupName": "prod", "VpcId": "vpc-1",
        "IpPermissions": [],
        "IpPermissionsEgress": [{
            "IpProtocol": "-1", "FromPort": -1, "ToPort": -1,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        }],
    }]}
    pols = parse_security_groups(sg)
    egress = [c for c in pols[0].controls if c.action == "egress"]
    assert egress and "egress-default-deny" in egress[0].capability_classes


def test_aws_sg_open_egress_does_NOT_tag_default_deny():
    sg = {"SecurityGroups": [{
        "GroupId": "sg-1", "GroupName": "open", "VpcId": "vpc-1",
        "IpPermissions": [], "IpPermissionsEgress": [{
            "IpProtocol": "-1", "FromPort": -1, "ToPort": -1,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    }]}
    pols = parse_security_groups(sg)
    egress = [c for c in pols[0].controls if c.action == "egress"]
    if egress:
        assert "egress-default-deny" not in egress[0].capability_classes


# ---------------------------------------------------------------------------
# AWS WAF
# ---------------------------------------------------------------------------
def test_aws_waf_known_bad_inputs_tags_rce_rule():
    acl = {"WebACL": {"Name": "edge-acl", "Rules": [{
        "Name": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
        "Priority": 1,
        "Action": {"Block": {}},
        "Statement": {"ManagedRuleGroupStatement": {"Name": "AWSManagedRulesKnownBadInputsRuleSet"}},
    }]}}
    pols = parse_waf(acl)
    classes = pols[0].controls[0].capability_classes
    assert "waf-rce-rule" in classes


# ---------------------------------------------------------------------------
# Azure Conditional Access
# ---------------------------------------------------------------------------
def test_azure_ca_mfa_and_compliant_device():
    ca = [{
        "displayName": "Require MFA + compliant device",
        "state": "enabled",
        "conditions": {"users": {"includeRoles": ["Global Admin"]},
                       "applications": {"includeApplications": ["All"]}},
        "grantControls": {"operator": "AND", "builtInControls": ["mfa", "compliantDevice"]},
    }]
    pols = parse_conditional_access(ca)
    [c] = pols[0].controls
    assert "mfa-required" in c.capability_classes
    assert "device-compliant" in c.capability_classes


def test_azure_ca_disabled_policy_emits_no_controls():
    ca = [{"displayName": "Old policy", "state": "disabled",
           "conditions": {}, "grantControls": {"builtInControls": ["mfa"]}}]
    pols = parse_conditional_access(ca)
    assert pols and not pols[0].controls


# ---------------------------------------------------------------------------
# Intune
# ---------------------------------------------------------------------------
def test_intune_compliance_disk_encryption():
    items = [{"displayName": "Win10 base", "storageRequireEncryption": True}]
    pols = parse_intune_compliance(items)
    assert "disk-encryption" in pols[0].controls[0].capability_classes


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------
def test_gcp_iam_emits_one_control_per_binding():
    doc = {"bindings": [
        {"role": "roles/owner", "members": ["user:admin@example.com"]},
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
    ]}
    pols = parse_iam(doc, "my-project")
    assert len(pols[0].controls) == 2


def test_gcp_vpc_egress_deny_tags_metadata_block():
    rules = [{
        "name": "deny-metadata", "direction": "EGRESS",
        "denied": [{"IPProtocol": "all"}],
        "destinationRanges": ["169.254.169.254/32"],
    }]
    pols = parse_vpc_firewall(rules)
    assert "egress-deny-metadata" in pols[0].controls[0].capability_classes


# ---------------------------------------------------------------------------
# Generic firewall + WAF
# ---------------------------------------------------------------------------
def test_iptables_metadata_reject_tags_metadata_block():
    text = """*filter
-A OUTPUT -d 169.254.169.254 -j REJECT --reject-with icmp-net-unreachable
-A OUTPUT -j ACCEPT
COMMIT"""
    pols = parse_iptables(text)
    blocking = [c for c in pols[0].controls if c.effect == "BLOCK"]
    assert blocking
    assert "egress-deny-metadata" in blocking[0].capability_classes


def test_modsec_sqli_rule_tags_injection_class():
    text = 'SecRule ARGS "@detectSQLi" "id:9421,phase:2,deny,status:403,msg:SQLi"'
    pols = parse_modsecurity(text)
    assert pols[0].controls[0].capability_classes


def test_cloudflare_xss_block_rule():
    items = [{
        "filter": {"expression": "(http.request.uri.query contains \"<script\")"},
        "action": "block", "description": "block-xss",
    }]
    pols = parse_cloudflare(items)
    assert pols[0].controls[0].effect == "BLOCK"


# ---------------------------------------------------------------------------
# parse_any auto-detection
# ---------------------------------------------------------------------------
def test_parse_any_detects_iam_json():
    iam = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    pols = parse_any(json.dumps(iam), "iam-policy.json")
    assert pols and pols[0].source == "AWS-IAM"


def test_parse_any_detects_iptables():
    pols = parse_any("*filter\n-A OUTPUT -j ACCEPT\nCOMMIT", "iptables.rules")
    assert pols and pols[0].source == "iptables"


def test_parse_any_returns_empty_for_garbage():
    pols = parse_any("not json, not iptables, just text", "random.txt")
    assert pols == []
