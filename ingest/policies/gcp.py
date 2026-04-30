"""
GCP policy parsers
==================
Coverage:
  - IAM policy bindings (`gcloud projects get-iam-policy`)
  - Org policies (gcloud resource-manager org-policies list --format=json)
  - VPC firewall rules
"""
from __future__ import annotations
from engine.policy_model import Policy, Control, make_id
from .aws import _flatten_caps


def parse_iam(doc: dict, hint: str | None = None) -> list[Policy]:
    name = hint or doc.get("etag","gcp-iam")
    pid = make_id("GCP-IAM", "iam", name)
    pol = Policy(id=pid, source="GCP-IAM", type="iam", name=f"GCP IAM ({name})", raw=doc)
    for b in doc.get("bindings", []) or []:
        role = b.get("role","")
        members = b.get("members", []) or []
        cap_classes: list[str] = []
        # Privileged role
        privileged = ("roles/owner","roles/editor","roles/iam.securityAdmin",
                      "roles/iam.serviceAccountTokenCreator","roles/resourcemanager.organizationAdmin")
        if role in privileged and any(m == "allUsers" or m == "allAuthenticatedUsers" for m in members):
            # Public privileged - very bad. Mark as ALLOW (gap is implicit)
            pass
        # Conditional bindings -> trusted-network-only / time-bound
        if "condition" in b:
            cond = (b.get("condition") or {}).get("expression","")
            if "request.auth" in cond:
                cap_classes.append("conditional-access")
            if "ipSubnetwork" in cond or "fromIp" in cond:
                cap_classes.append("trusted-network-only")
        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        title = f"GRANT {role} → {len(members)} member(s)"
        cid = make_id(pid, role, ",".join(members[:3]))
        pol.controls.append(Control(
            id=cid, title=title, effect="ALLOW", action="iam", layer=5,
            capability_classes=cap_classes, capabilities_mitigated=caps,
            scope={"members": members, "condition": b.get("condition")},
            raw=b,
        ))
    return [pol]


def parse_vpc_firewall(items: list[dict]) -> list[Policy]:
    out: list[Policy] = []
    for r in items:
        if not isinstance(r, dict): continue
        name = r.get("name","fw-rule")
        pid = make_id("GCP-FW", "firewall", name)
        pol = Policy(id=pid, source="GCP-FW", type="firewall", name=name, raw=r)
        direction = r.get("direction","INGRESS")
        denied = r.get("denied")
        allowed = r.get("allowed")
        effect = "BLOCK" if denied else "ALLOW"
        cap_classes: list[str] = []
        if direction == "EGRESS" and effect == "BLOCK":
            cap_classes += ["egress-default-deny","egress-deny-metadata"]
        if direction == "INGRESS" and effect == "ALLOW":
            srcs = r.get("sourceRanges") or []
            if srcs and "0.0.0.0/0" not in srcs:
                cap_classes.append("microsegmentation")

        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        title = f"{effect} {direction} {','.join((allowed or denied or [{}])[0].get('IPProtocol','any') for _ in [None])}"
        cid = make_id(pid, direction, str(allowed or denied))
        pol.controls.append(Control(
            id=cid, title=title, effect=effect,
            action="ingress" if direction=="INGRESS" else "egress",
            layer=3, capability_classes=cap_classes, capabilities_mitigated=caps,
            scope={"sources": r.get("sourceRanges"), "tags": r.get("targetTags"),
                   "service_accounts": r.get("targetServiceAccounts")},
            raw=r,
        ))
        out.append(pol)
    return out


def parse_org_policy(items: list[dict]) -> list[Policy]:
    out: list[Policy] = []
    for it in items:
        if not isinstance(it, dict): continue
        name = it.get("constraint","org-policy")
        pid = make_id("GCP-Org","org-policy",name)
        pol = Policy(id=pid, source="GCP-Org", type="org-policy", name=name, raw=it)
        cap_classes: list[str] = []
        if "compute.requireOsLogin" in name:
            cap_classes.append("phishing-resistant-auth")
        if "storage.publicAccessPrevention" in name:
            cap_classes.append("s3-public-block")
        if "compute.skipDefaultNetworkCreation" in name:
            cap_classes.append("microsegmentation")
        if "iam.disableServiceAccountKeyCreation" in name:
            cap_classes.append("phishing-resistant-auth")
        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        cid = make_id(pid, "main")
        pol.controls.append(Control(
            id=cid, title=f"Org policy: {name}", effect="REQUIRE", action="org",
            layer=7, capability_classes=cap_classes, capabilities_mitigated=caps,
            raw=it,
        ))
        out.append(pol)
    return out
