"""
AWS policy parsers
==================
Coverage:
  - IAM policy documents (identity, resource, SCP, S3 bucket policy, KMS key policy)
  - EC2 Security Groups   (`aws ec2 describe-security-groups` JSON)
  - AWS WAFv2 Web ACLs    (`aws wafv2 get-web-acl` JSON)

Each parser emits engine.policy_model.Policy objects with Control children
tagged against engine.policy_capabilities.CONTROL_CLASSES.
"""
from __future__ import annotations
from typing import Any
from engine.policy_model import Policy, Control, make_id


# ---------------------------------------------------------------------------
# IAM policy doc
# ---------------------------------------------------------------------------
def parse_iam_doc(doc: dict, hint: str | None = None) -> list[Policy]:
    name = (doc.get("Id") or doc.get("PolicyName") or hint or "iam-policy")
    pid = make_id("AWS-IAM", "iam-policy", name, doc.get("Version", ""))
    pol = Policy(id=pid, source="AWS-IAM", type=hint or "iam-policy",
                 name=name, raw=doc)
    statements = doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for i, s in enumerate(statements):
        if not isinstance(s, dict):
            continue
        effect = "BLOCK" if s.get("Effect") == "Deny" else "ALLOW"
        actions = _as_list(s.get("Action") or s.get("NotAction"))
        resources = _as_list(s.get("Resource") or s.get("NotResource"))
        cond = s.get("Condition") or {}
        title = f"{effect} {','.join(actions[:3])}{'…' if len(actions)>3 else ''} on {','.join(resources[:2])}"

        # Flatten the whole statement for substring sniffing - condition keys
        # in IAM are inside DICT KEYS not values, so plain str() of the dict
        # is the most reliable way to detect them.
        import json as _json
        cond_blob = _json.dumps(cond)
        stmt_blob = _json.dumps(s)
        cap_classes: list[str] = []

        # MFA-required statements (key is "aws:MultiFactorAuthPresent")
        if "aws:MultiFactorAuthPresent" in cond_blob:
            cap_classes.append("mfa-required")
        # IMDSv2 enforcement
        if "ec2:RoleDelivery" in cond_blob or "ec2:MetadataHttpTokens" in cond_blob:
            cap_classes.append("imdsv2-required")
        # S3 public block
        if effect == "BLOCK" and any(a.startswith("s3:") for a in actions) and \
           ("PublicAccessBlock" in stmt_blob or "BlockPublicAcls" in stmt_blob):
            cap_classes.append("s3-public-block")
        # KMS resource policy decryption restrictions
        if any(a.startswith("kms:") for a in actions):
            cap_classes.append("kms-resource-policy")
        # Trusted location condition
        if "aws:SourceIp" in cond_blob or "aws:VpcSourceIp" in cond_blob:
            cap_classes.append("trusted-network-only")
        # NoStandingAdmin: explicit Deny on iam:* / *:* over time conditions
        privileged_actions = {"iam:*", "*:*", "iam:PassRole", "sts:AssumeRole"}
        if effect == "BLOCK" and any(a in privileged_actions for a in actions):
            cap_classes.append("no-standing-admin")
        # Privileged actions present (PRIV_ESC concerns) - track NoStandingAdmin missing
        privileged_patterns = ("iam:*", "*:*", "iam:PassRole", "sts:AssumeRole")
        if effect == "ALLOW" and any(any(p in a for p in privileged_patterns) for a in actions):
            # Note this is privileged - the ABSENCE of a Deny here is the gap.
            pass

        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        cid = make_id(pid, str(i), str(actions), str(resources))
        pol.controls.append(Control(
            id=cid, title=title, effect=effect, action=",".join(actions[:3]) or "*",
            layer=7, capability_classes=cap_classes, capabilities_mitigated=caps,
            scope={"resources": resources, "condition": cond, "principal": s.get("Principal")},
            raw=s,
        ))
    return [pol]


# ---------------------------------------------------------------------------
# EC2 Security Groups
# ---------------------------------------------------------------------------
def parse_security_groups(doc: dict) -> list[Policy]:
    out: list[Policy] = []
    for sg in doc.get("SecurityGroups", []) or []:
        sg_id = sg.get("GroupId", "")
        name = sg.get("GroupName", sg_id)
        pid = make_id("AWS-SG", "security-group", sg_id)
        pol = Policy(id=pid, source="AWS-SG", type="security-group",
                     name=f"{name} ({sg_id})",
                     scope={"vpc": sg.get("VpcId"), "tags": sg.get("Tags", [])},
                     raw=sg)

        for direction, key in [("egress", "IpPermissionsEgress"),
                                ("ingress", "IpPermissions")]:
            for r in sg.get(key, []) or []:
                proto = r.get("IpProtocol", "-1")
                from_p = r.get("FromPort", "-")
                to_p = r.get("ToPort", "-")
                cidrs = [c.get("CidrIp") for c in r.get("IpRanges", []) if c.get("CidrIp")]
                cidrs += [c.get("CidrIpv6") for c in r.get("Ipv6Ranges", []) if c.get("CidrIpv6")]
                title = f"{direction.upper()} {proto}/{from_p}-{to_p} from/to {','.join(cidrs) or '—'}"

                cap_classes: list[str] = []
                effect = "ALLOW"   # SG is allow-only by definition

                # Egress to metadata-service blocked? (we can't tell from SG alone since SG is allow-list,
                # but if egress doesn't include 169.254.169.254, the GAP is implicit; here we tag rules
                # that DO restrict egress to a tight set as positive coverage.)
                if direction == "egress":
                    if "0.0.0.0/0" not in cidrs and "::/0" not in cidrs:
                        cap_classes.append("egress-default-deny")
                        cap_classes.append("egress-deny-metadata")
                # Microsegmentation: SG references another SG (peer)
                if r.get("UserIdGroupPairs"):
                    cap_classes.append("microsegmentation")

                cap_classes = list(dict.fromkeys(cap_classes))
                caps = _flatten_caps(cap_classes)

                cid = make_id(pid, direction, proto, str(from_p), str(to_p), ",".join(cidrs))
                pol.controls.append(Control(
                    id=cid, title=title, effect=effect, action=direction,
                    layer=3 if proto in ("-1", "icmp") else 4,
                    capability_classes=cap_classes, capabilities_mitigated=caps,
                    scope={"protocol": proto, "from_port": from_p, "to_port": to_p,
                           "cidrs": cidrs}, raw=r,
                ))
        out.append(pol)
    return out


# ---------------------------------------------------------------------------
# AWS WAFv2
# ---------------------------------------------------------------------------
def parse_waf(doc: dict) -> list[Policy]:
    out: list[Policy] = []
    acls = doc.get("WebACLs") or ([doc.get("WebACL")] if doc.get("WebACL") else [doc])
    for acl in acls:
        if not isinstance(acl, dict):
            continue
        name = acl.get("Name") or acl.get("Id") or "WebACL"
        pid = make_id("AWS-WAF", "web-acl", name)
        pol = Policy(id=pid, source="AWS-WAF", type="web-acl", name=name, raw=acl)
        for rule in acl.get("Rules", []) or []:
            rname = rule.get("Name", "")
            action = (rule.get("Action") or rule.get("OverrideAction") or {})
            effect = "BLOCK" if "Block" in action else "ALLOW" if "Allow" in action else "MONITOR"
            stmt = rule.get("Statement") or {}
            ref = (stmt.get("ManagedRuleGroupStatement") or {}).get("Name") or rname

            cap_classes: list[str] = []
            r_low = (rname + " " + ref).lower()
            if any(x in r_low for x in ("knownbadinputs","phprule","javarule","linuxrule","unixrule","sqli")):
                cap_classes += ["waf-injection-rule", "waf-rce-rule"]
            if any(x in r_low for x in ("xss","crossite")):
                cap_classes.append("waf-injection-rule")
            if "common" in r_low or "core" in r_low:
                cap_classes.append("waf-injection-rule")
            cap_classes = list(dict.fromkeys(cap_classes))
            caps = _flatten_caps(cap_classes)

            cid = make_id(pid, rname or ref)
            pol.controls.append(Control(
                id=cid, title=f"{effect} {rname or ref}", effect=effect,
                action="http", layer=7,
                capability_classes=cap_classes, capabilities_mitigated=caps,
                scope={"priority": rule.get("Priority")}, raw=rule,
            ))
        out.append(pol)
    return out


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _as_list(v) -> list[str]:
    if v is None: return []
    if isinstance(v, str): return [v]
    if isinstance(v, list): return [str(x) for x in v]
    return [str(v)]


def _walk(v):
    """Yield every leaf in a nested dict/list."""
    if isinstance(v, dict):
        for x in v.values(): yield from _walk(x)
    elif isinstance(v, list):
        for x in v: yield from _walk(x)
    else:
        yield v


def _flatten_caps(class_names: list[str]) -> list[str]:
    """Resolve control class names -> set of mitigated capabilities."""
    from engine.policy_capabilities import by_name
    out: set[str] = set()
    for n in class_names:
        cc = by_name(n)
        if cc: out |= cc.capabilities
    return sorted(out)
