"""
Azure / Microsoft policy parsers
================================
Coverage:
  - Conditional Access policies (Microsoft Graph identity/conditionalAccess)
  - Intune device compliance policies (Graph deviceManagement)
  - Intune device configuration policies (subset of useful settings)
  - Network Security Groups (Azure Resource Manager export)
"""
from __future__ import annotations
from typing import Any
from engine.policy_model import Policy, Control, make_id
from .aws import _flatten_caps   # reuse


# ---------------------------------------------------------------------------
# Conditional Access
# ---------------------------------------------------------------------------
def parse_conditional_access(items: list[dict]) -> list[Policy]:
    out: list[Policy] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        name = it.get("displayName") or it.get("id", "ca-policy")
        state = it.get("state", "enabled")
        pid = make_id("Azure-CA", "ca-policy", name, state)
        pol = Policy(id=pid, source="Azure-CA", type="ca-policy", name=name,
                     scope={"state": state, "users": (it.get("conditions") or {}).get("users"),
                            "applications": (it.get("conditions") or {}).get("applications")},
                     raw=it)
        if state != "enabled":
            out.append(pol); continue   # disabled / report-only - keep visible but no controls

        gc = it.get("grantControls") or {}
        builtin = [str(x) for x in (gc.get("builtInControls") or [])]
        op = gc.get("operator", "OR")
        cap_classes: list[str] = []
        if "mfa" in builtin:
            cap_classes.append("mfa-required")
        if "compliantDevice" in builtin or "domainJoinedDevice" in builtin:
            cap_classes.append("device-compliant")
        if any(b in builtin for b in ("approvedApplication","compliantApplication")):
            cap_classes.append("conditional-access")
        if any(b in builtin for b in ("passwordChange","block")):
            cap_classes.append("conditional-access")
        # Phishing-resistant?
        auth_strength = gc.get("authenticationStrength") or {}
        if auth_strength.get("displayName","").lower().startswith("phishing"):
            cap_classes.append("phishing-resistant-auth")
        # Trusted-network-only?
        locs = (it.get("conditions") or {}).get("locations") or {}
        if locs.get("includeLocations") and "all" not in [str(x).lower() for x in locs.get("includeLocations") or []]:
            cap_classes.append("trusted-network-only")

        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        title = f"CA: {name} → require {', '.join(builtin) or 'block'}"
        effect = "BLOCK" if "block" in builtin else "REQUIRE"
        cid = make_id(pid, "main")
        pol.controls.append(Control(
            id=cid, title=title, effect=effect, action="auth", layer=5,
            capability_classes=cap_classes, capabilities_mitigated=caps,
            scope={"operator": op, "controls": builtin,
                   "auth_strength": auth_strength.get("displayName")},
            raw=it,
        ))
        out.append(pol)
    return out


# ---------------------------------------------------------------------------
# Intune compliance
# ---------------------------------------------------------------------------
def parse_intune_compliance(items: list[dict]) -> list[Policy]:
    out: list[Policy] = []
    for it in items:
        if not isinstance(it, dict): continue
        name = it.get("displayName") or it.get("id", "compliance")
        pid = make_id("Intune", "compliance", name)
        pol = Policy(id=pid, source="Intune", type="compliance", name=name, raw=it)
        cap_classes: list[str] = []

        # Common compliance flags (across iOS / Android / Windows variants)
        if it.get("storageRequireEncryption") or it.get("requireDeviceEncryption"):
            cap_classes.append("disk-encryption")
        if it.get("secureBootEnabled"):
            cap_classes.append("secure-boot")
        if it.get("activeFirewallRequired") or it.get("firewallEnabled"):
            cap_classes.append("egress-default-deny")
        if it.get("passwordRequired"):
            cap_classes.append("conditional-access")
        if it.get("antivirusRequired") or it.get("antiSpywareRequired"):
            cap_classes.append("rasp")
        if it.get("defenderEnabled") or it.get("defenderVersion"):
            cap_classes.append("attack-surface-reduction")

        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        cid = make_id(pid, "compliance")
        pol.controls.append(Control(
            id=cid, title=f"Intune compliance: {name}", effect="REQUIRE", action="device",
            layer=5, capability_classes=cap_classes, capabilities_mitigated=caps,
            scope={"platform": it.get("@odata.type")}, raw=it,
        ))
        out.append(pol)
    return out


# ---------------------------------------------------------------------------
# Intune device configuration
# ---------------------------------------------------------------------------
def parse_intune_configuration(items: list[dict]) -> list[Policy]:
    out: list[Policy] = []
    for it in items:
        if not isinstance(it, dict): continue
        name = it.get("displayName") or "config"
        pid = make_id("Intune", "configuration", name)
        pol = Policy(id=pid, source="Intune", type="configuration", name=name, raw=it)
        cap_classes: list[str] = []

        if it.get("bitLockerEncryption") or it.get("bitlockerSystemDriveEncryption"):
            cap_classes.append("disk-encryption")
        if it.get("smartScreenEnabled") or it.get("defenderSmartScreenEnabled"):
            cap_classes.append("attack-surface-reduction")
        if it.get("appLockerApplicationControl") or it.get("windowsDefenderApplicationControl"):
            cap_classes.append("app-allowlist")
        if it.get("attackSurfaceReductionRules"):
            cap_classes.append("attack-surface-reduction")

        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        cid = make_id(pid, "config")
        pol.controls.append(Control(
            id=cid, title=f"Intune config: {name}", effect="REQUIRE", action="device",
            layer=5, capability_classes=cap_classes, capabilities_mitigated=caps,
            raw=it,
        ))
        out.append(pol)
    return out


# ---------------------------------------------------------------------------
# Azure NSG
# ---------------------------------------------------------------------------
def parse_nsg(items: list[dict]) -> list[Policy]:
    out: list[Policy] = []
    for nsg in items:
        if not isinstance(nsg, dict): continue
        name = nsg.get("name") or nsg.get("id","nsg")
        pid = make_id("Azure-NSG", "nsg", name)
        pol = Policy(id=pid, source="Azure-NSG", type="nsg", name=name, raw=nsg)
        rules = nsg.get("securityRules") or nsg.get("properties", {}).get("securityRules") or []
        for r in rules:
            if isinstance(r, dict) and "properties" in r:
                p = r.get("properties", {})
            else:
                p = r
            if not isinstance(p, dict): continue
            access = p.get("access","Allow")
            direction = p.get("direction","Inbound")
            effect = "BLOCK" if access == "Deny" else "ALLOW"
            cap_classes: list[str] = []
            if direction == "Outbound" and effect == "BLOCK":
                cap_classes += ["egress-default-deny", "egress-deny-metadata"]
            if direction == "Inbound" and effect == "ALLOW" and p.get("sourceAddressPrefix") not in ("*","Internet"):
                cap_classes.append("microsegmentation")

            cap_classes = list(dict.fromkeys(cap_classes))
            caps = _flatten_caps(cap_classes)

            title = f"{effect} {direction} {p.get('protocol','*')} {p.get('destinationPortRange','*')}"
            cid = make_id(pid, p.get("name") or p.get("priority") or "rule", access, direction)
            pol.controls.append(Control(
                id=cid, title=title, effect=effect,
                action="ingress" if direction == "Inbound" else "egress",
                layer=4, capability_classes=cap_classes, capabilities_mitigated=caps,
                scope={"src": p.get("sourceAddressPrefix"), "dst": p.get("destinationAddressPrefix"),
                       "ports": p.get("destinationPortRange")}, raw=p,
            ))
        out.append(pol)
    return out
