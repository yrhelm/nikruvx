"""
Generic firewall + WAF parsers
==============================
Coverage:
  - iptables-save output
  - nftables output (`nft list ruleset`)
  - ModSecurity rule files
  - Cloudflare firewall rules JSON
  - pfSense XML config (lightweight)
"""
from __future__ import annotations
import re
from engine.policy_model import Policy, Control, make_id
from .aws import _flatten_caps


# ---------------------------------------------------------------------------
# iptables-save
# ---------------------------------------------------------------------------
def parse_iptables(text: str) -> list[Policy]:
    pid = make_id("iptables", "ruleset", "default")
    pol = Policy(id=pid, source="iptables", type="ruleset", name="iptables ruleset", raw={})
    for ln, line in enumerate(text.splitlines()):
        s = line.strip()
        if not s.startswith("-A "): continue
        chain = s.split()[1] if len(s.split()) > 1 else ""
        target = ("DROP" if " -j DROP" in s else
                  "REJECT" if " -j REJECT" in s else
                  "ACCEPT" if " -j ACCEPT" in s else "OTHER")
        effect = "BLOCK" if target in ("DROP","REJECT") else "ALLOW" if target == "ACCEPT" else "MONITOR"
        cap_classes: list[str] = []
        if effect == "BLOCK" and "169.254.169.254" in s:
            cap_classes += ["egress-deny-metadata","egress-default-deny"]
        if chain == "OUTPUT" and effect == "BLOCK" and not cap_classes:
            cap_classes.append("egress-default-deny")
        if chain in ("FORWARD","INPUT") and effect == "ALLOW" and "-s " in s:
            cap_classes.append("microsegmentation")
        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        cid = make_id(pid, str(ln), s[:80])
        pol.controls.append(Control(
            id=cid, title=f"{effect} {chain}: {s[:120]}",
            effect=effect, action=chain.lower(),
            layer=3 if "tcp" not in s and "udp" not in s else 4,
            capability_classes=cap_classes, capabilities_mitigated=caps,
            source_lineno=ln, raw={"line": s},
        ))
    return [pol]


# ---------------------------------------------------------------------------
# nftables
# ---------------------------------------------------------------------------
def parse_nftables(text: str) -> list[Policy]:
    pid = make_id("nftables", "ruleset", "default")
    pol = Policy(id=pid, source="nftables", type="ruleset", name="nftables ruleset", raw={})
    for ln, line in enumerate(text.splitlines()):
        s = line.strip()
        if not (("drop" in s) or ("accept" in s) or ("reject" in s)): continue
        effect = "BLOCK" if (" drop" in s or " reject" in s) else "ALLOW"
        cap_classes: list[str] = []
        if effect == "BLOCK" and "169.254.169.254" in s:
            cap_classes += ["egress-deny-metadata","egress-default-deny"]
        if effect == "BLOCK" and "oif" in s:
            cap_classes.append("egress-default-deny")
        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        cid = make_id(pid, str(ln), s[:80])
        pol.controls.append(Control(
            id=cid, title=f"{effect}: {s[:120]}", effect=effect, action="filter",
            layer=4 if ("tcp" in s or "udp" in s) else 3,
            capability_classes=cap_classes, capabilities_mitigated=caps,
            source_lineno=ln, raw={"line": s},
        ))
    return [pol]


# ---------------------------------------------------------------------------
# ModSecurity rules
# ---------------------------------------------------------------------------
_SEC = re.compile(r'^SecRule\s+([^\s"]+)\s+"?@?(\w+)?\s*([^"]*)"', re.I)


def parse_modsecurity(text: str) -> list[Policy]:
    pid = make_id("ModSecurity", "ruleset", "default")
    pol = Policy(id=pid, source="ModSecurity", type="ruleset", name="ModSecurity rules", raw={})
    for ln, line in enumerate(text.splitlines()):
        s = line.strip()
        if not s.startswith("SecRule"): continue
        action_match = re.search(r'phase:\d.+?(\bdeny|\ballow|\blog|\bdrop)\b', s)
        effect = "BLOCK" if action_match and action_match.group(1) in ("deny","drop") else \
                 "MONITOR" if "audit" in s.lower() or "log" in s.lower() else "ALLOW"
        sl = s.lower()
        cap_classes: list[str] = []
        if "sqli" in sl or "detectsqli" in sl or "950" in sl:
            cap_classes.append("waf-injection-rule")
        if "xss" in sl or "detectxss" in sl:
            cap_classes.append("waf-injection-rule")
        if "rce" in sl or "remote_code" in sl or "phpinjection" in sl:
            cap_classes.append("waf-rce-rule")
        if "lfi" in sl or "rfi" in sl or "traversal" in sl:
            cap_classes.append("waf-injection-rule")
        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        cid = make_id(pid, str(ln), s[:80])
        pol.controls.append(Control(
            id=cid, title=f"{effect}: ModSec {s[:120]}", effect=effect, action="http",
            layer=7, capability_classes=cap_classes, capabilities_mitigated=caps,
            source_lineno=ln, raw={"line": s},
        ))
    return [pol]


# ---------------------------------------------------------------------------
# Cloudflare firewall rules JSON
# ---------------------------------------------------------------------------
def parse_cloudflare(items: list[dict]) -> list[Policy]:
    out: list[Policy] = []
    for r in items:
        if not isinstance(r, dict): continue
        name = (r.get("description") or r.get("filter",{}).get("description")
                or r.get("id","cf-rule"))
        pid = make_id("Cloudflare", "firewall-rule", name)
        pol = Policy(id=pid, source="Cloudflare", type="firewall-rule", name=name, raw=r)
        action = r.get("action","")
        effect = "BLOCK" if action in ("block","challenge","js_challenge","managed_challenge") else \
                 "ALLOW" if action in ("allow","skip") else "MONITOR"
        expr = (r.get("filter") or {}).get("expression","").lower()
        cap_classes: list[str] = []
        if any(x in expr for x in ("sqli","cf.threat_score","wp-admin","\\beval","\\bselect")):
            cap_classes.append("waf-injection-rule")
        if "xss" in expr:
            cap_classes.append("waf-injection-rule")
        if "rce" in expr or "shell" in expr:
            cap_classes.append("waf-rce-rule")
        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)

        cid = make_id(pid, action, expr[:80])
        pol.controls.append(Control(
            id=cid, title=f"{effect} CF: {name}", effect=effect, action="http", layer=7,
            capability_classes=cap_classes, capabilities_mitigated=caps,
            scope={"expression": expr}, raw=r,
        ))
        out.append(pol)
    return out


# ---------------------------------------------------------------------------
# pfSense (lightweight)
# ---------------------------------------------------------------------------
def parse_pfsense(text: str) -> list[Policy]:
    # Just count rule blocks - full XML parsing of pfSense is large; we extract
    # any <rule> element type=block/pass and tag accordingly.
    pid = make_id("pfSense", "ruleset", "default")
    pol = Policy(id=pid, source="pfSense", type="ruleset", name="pfSense ruleset", raw={})
    for m in re.finditer(r"<rule>(.*?)</rule>", text, re.S):
        body = m.group(1)
        rtype = re.search(r"<type>(\w+)</type>", body)
        descr = re.search(r"<descr><!\[CDATA\[(.*?)\]\]></descr>", body)
        effect = "BLOCK" if rtype and rtype.group(1) == "block" else "ALLOW"
        cap_classes: list[str] = []
        if effect == "BLOCK" and "169.254.169.254" in body:
            cap_classes += ["egress-deny-metadata","egress-default-deny"]
        cap_classes = list(dict.fromkeys(cap_classes))
        caps = _flatten_caps(cap_classes)
        cid = make_id(pid, body[:80])
        pol.controls.append(Control(
            id=cid, title=f"{effect}: {(descr.group(1) if descr else 'rule')}",
            effect=effect, action="filter", layer=3,
            capability_classes=cap_classes, capabilities_mitigated=caps,
            raw={"xml_fragment": body[:500]},
        ))
    return [pol]
