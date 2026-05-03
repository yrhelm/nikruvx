"""
Third-party Application trust scoring.

Given a set of `trust_signals` (gathered by the per-category ingesters),
compute a 0-100 trust score with explanation. Transparent + tweakable.

Signals we look at:
    signed                 (bool)   - binary/extension is digitally signed
    publisher_verified     (bool)   - blue-check on the marketplace
    install_count          (int)    - downloads / installs (log-scaled)
    age_days               (int)    - days since first publish (older = more vetted)
    last_update_days       (int)    - recency of last update (fresh = active)
    cve_count              (int)    - CVEs known to affect this exact version
    in_kev                 (bool)   - any of those CVEs in CISA KEV
    incident_proximity     (int)    - days since the publisher had a confirmed
                                       supply-chain incident; 0 = never
    scorecard              (float)  - OpenSSF Scorecard 0-10 (if applicable)
    permissions_high_risk  (int)    - count of dangerous permissions
                                       (e.g. <all_urls>, exec, fs_full)
    open_audit             (bool)   - SOC2 / ISO / public audit available
"""
from __future__ import annotations
from math import log10
from dataclasses import dataclass


@dataclass
class TrustResult:
    score: float           # 0-100
    band: str              # TRUSTED / OK / CAUTION / RISKY / DANGEROUS
    components: dict       # individual contributions
    reasons: list[str]


def _band(score: float) -> str:
    if score >= 80: return "TRUSTED"
    if score >= 60: return "OK"
    if score >= 40: return "CAUTION"
    if score >= 20: return "RISKY"
    return "DANGEROUS"


def score(signals: dict) -> TrustResult:
    s = signals or {}
    reasons: list[str] = []
    components: dict[str, float] = {}

    # Start from neutral 50, push up or down based on signals.
    pts = 50.0

    # ---- signing / verification (+15) ----
    if s.get("signed") is True:
        pts += 8;  components["signed"] = 8;  reasons.append("digitally signed")
    elif s.get("signed") is False:
        pts -= 8;  components["signed"] = -8; reasons.append("UNSIGNED")
    if s.get("publisher_verified"):
        pts += 7;  components["publisher_verified"] = 7
        reasons.append("publisher verified by marketplace")

    # ---- install / install count (log scale, up to +10) ----
    n = int(s.get("install_count", 0) or 0)
    if n > 0:
        bonus = min(10.0, 2.0 * log10(max(n, 1)))
        pts += bonus; components["install_count"] = bonus
        reasons.append(f"{n:,} installs (+{bonus:.1f})")

    # ---- age (gentle bonus, max +5) ----
    age = int(s.get("age_days", 0) or 0)
    if age > 365:
        bonus = min(5.0, age / 730 * 5.0)
        pts += bonus; components["age"] = bonus
        reasons.append(f"{age // 30} months old (+{bonus:.1f})")
    elif age and age < 30:
        pts -= 5; components["age"] = -5
        reasons.append("less than 30 days old")

    # ---- last update freshness (small effect both ways) ----
    upd = int(s.get("last_update_days", 0) or 0)
    if upd:
        if upd < 90:
            pts += 3; components["update_fresh"] = 3
            reasons.append("actively maintained")
        elif upd > 730:
            pts -= 5; components["update_stale"] = -5
            reasons.append("not updated for 2+ years")

    # ---- CVEs (-3 each, capped at -15) ----
    cves = int(s.get("cve_count", 0) or 0)
    if cves > 0:
        penalty = min(15.0, 3.0 * cves)
        pts -= penalty; components["cves"] = -penalty
        reasons.append(f"{cves} known CVE(s)")

    # ---- CISA KEV (always severe) ----
    if s.get("in_kev"):
        pts -= 15; components["kev"] = -15
        reasons.append("CISA KEV - actively exploited in the wild")

    # ---- incident proximity (-15 if recent supply-chain incident) ----
    inc = int(s.get("incident_proximity", 0) or 0)
    if inc and inc < 90:
        pts -= 15; components["incident"] = -15
        reasons.append(f"publisher had a supply-chain incident {inc} days ago")
    elif inc and inc < 365:
        pts -= 7; components["incident_old"] = -7

    # ---- OpenSSF Scorecard (translate 0-10 → up to ±10) ----
    sc = s.get("scorecard")
    if isinstance(sc, (int, float)):
        contrib = (float(sc) - 5.0) * 2.0   # 0→-10, 5→0, 10→+10
        pts += contrib; components["scorecard"] = round(contrib, 1)
        reasons.append(f"Scorecard {sc:.1f}")

    # ---- High-risk permissions ----
    hp = int(s.get("permissions_high_risk", 0) or 0)
    if hp:
        penalty = min(10.0, 2.5 * hp)
        pts -= penalty; components["high_risk_perms"] = -penalty
        reasons.append(f"{hp} high-risk permission(s)")

    # ---- Open audit / cert ----
    if s.get("open_audit"):
        pts += 5; components["audit"] = 5
        reasons.append("public audit (SOC2/ISO/etc.)")

    final = max(0.0, min(100.0, pts))
    return TrustResult(
        score=round(final, 1), band=_band(final),
        components=components, reasons=reasons,
    )


def score_dict(signals: dict) -> dict:
    r = score(signals)
    return {"score": r.score, "band": r.band,
            "components": r.components, "reasons": r.reasons}


# ---------------------------------------------------------------------------
# High-risk permission heuristics, per category
# ---------------------------------------------------------------------------
HIGH_RISK_PERMS_BROWSER = {
    "<all_urls>", "tabs", "history", "cookies", "webRequest",
    "webRequestBlocking", "downloads", "clipboardRead", "management",
    "nativeMessaging", "debugger", "proxy", "browsingData", "privacy",
    "<all_origins>", "*://*/*",
}
HIGH_RISK_PERMS_IDE = {
    "process.spawn", "fs.writeAll", "shell.exec", "remote", "electron-remote",
}
HIGH_RISK_PERMS_MCP = {
    "filesystem.write", "filesystem.full", "shell", "exec",
    "network.outbound", "credentials", "secrets",
}


def count_high_risk(permissions: list[str], category: str) -> int:
    if not permissions:
        return 0
    table = {
        "browser_ext": HIGH_RISK_PERMS_BROWSER,
        "ide_ext": HIGH_RISK_PERMS_IDE,
        "mcp_server": HIGH_RISK_PERMS_MCP,
    }.get(category, set())
    return sum(1 for p in permissions if p in table or p.startswith("http"))
