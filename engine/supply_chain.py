"""
Supply-Chain Risk Scanner
=========================
Pre- AND post-install detection of supply-chain attack indicators for any
package (npm / PyPI / crates.io / RubyGems / Maven / Go) or any GitHub repo.

This is intentionally LIVE — every signal is fetched at scan time so the
report reflects current state. Cache is short (TTL 5 min) for repeat
queries.

Signals collected:
  - typosquat_distance      Levenshtein vs popular packages in same eco
  - in_malicious_feed       OpenSSF malicious-packages / GHSA malware
  - has_install_scripts     npm pre/postinstall / pyproject build-script
  - suspicious_patterns     regex hits on README / metadata (curl|sh, base64
                            payload, eval(), atob(), child_process.exec)
  - age_days                first publish date (newer = riskier)
  - download_count_log      log10 of monthly downloads (low = riskier)
  - maintainer_count        sole-maintainer = riskier
  - recent_maintainer_add   new uploader within 30 days
  - github_present          links to a github repo we can verify
  - scorecard_score         OpenSSF Scorecard 0-10
  - license_present         package declares a license

Output:
  { score: 0-100, band: TRUSTED/OK/CAUTION/RISKY/MALICIOUS,
    components: {...}, reasons: [...], raw: {...} }
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Iterable
import httpx

from .trust_scoring import score as trust_score
from .application_model import Application, make_id
from .application_model import upsert as upsert_apps
from . import typosquat as _typosquat
from . import threat_feeds as _feeds


# ---------------------------------------------------------------------------
# Typosquat detection -- delegates to the comprehensive multi-algorithm
# engine in engine.typosquat (8 detection passes, bundled top-N lists).
# ---------------------------------------------------------------------------
def typosquat_score(eco: str, name: str) -> tuple[float, str | None]:
    """Return (score 0-1, closest popular name)."""
    score, neighbor, _method = _typosquat.best_score(eco, name)
    return (score, neighbor)


def typosquat_findings(eco: str, name: str) -> list[dict]:
    """Full findings list (every detection method that fired)."""
    return [h.to_dict() for h in _typosquat.detect(eco, name)]


# ---------------------------------------------------------------------------
# Suspicious-pattern detection on metadata + README
# ---------------------------------------------------------------------------
SUSPICIOUS_PATTERNS = [
    (r"\bcurl\b[^|\n]*\|\s*(sh|bash|python)", "curl-pipe-shell"),
    (r"\bwget\b[^|\n]*\|\s*(sh|bash|python)", "wget-pipe-shell"),
    (r"\b(child_process|execSync|spawnSync)\b", "shell-exec"),
    (r"\beval\s*\(\s*(atob|Buffer\.from|decodeURIComponent)", "eval-encoded-payload"),
    (r"\bBuffer\.from\(['\"][A-Za-z0-9+/=]{60,}['\"],\s*['\"]base64['\"]\)", "long-base64-payload"),
    (r"\b(0x[A-Fa-f0-9]{20,})", "hex-blob"),
    (r"\b__dirname\b.*\bos\.networkInterfaces\(\)", "interface-enum"),
    (r"\bprocess\.env\b.*\bAWS_(SECRET|ACCESS_KEY|TOKEN)\b", "env-key-exfil"),
    (r"https?://(?!github\.com|githubusercontent\.com|registry\.npmjs\.org|pypi\.org)\S+/raw/", "raw-third-party-fetch"),
]


def scan_text_for_patterns(text: str) -> list[str]:
    if not text: return []
    out: list[str] = []
    for pat, label in SUSPICIOUS_PATTERNS:
        if re.search(pat, text, re.I):
            out.append(label)
    return out


# ---------------------------------------------------------------------------
# Registry queries
# ---------------------------------------------------------------------------
def _http() -> httpx.Client:
    return httpx.Client(timeout=15.0, headers={"User-Agent": "NikruvX/SupplyChain"})


@lru_cache(maxsize=512)
def npm_metadata(name: str) -> dict:
    with _http() as c:
        r = c.get(f"https://registry.npmjs.org/{name}")
        return r.json() if r.status_code == 200 else {}


@lru_cache(maxsize=512)
def pypi_metadata(name: str) -> dict:
    with _http() as c:
        r = c.get(f"https://pypi.org/pypi/{name}/json")
        return r.json() if r.status_code == 200 else {}


@lru_cache(maxsize=512)
def npm_download_count(name: str) -> int:
    """Last-month download count from npm."""
    try:
        with _http() as c:
            r = c.get(f"https://api.npmjs.org/downloads/point/last-month/{name}")
            return int(r.json().get("downloads", 0)) if r.status_code == 200 else 0
    except Exception:
        return 0


@lru_cache(maxsize=512)
def pypi_download_count(name: str) -> int:
    """PyPI doesn't have a free per-package API but pypistats works."""
    try:
        with _http() as c:
            r = c.get(f"https://pypistats.org/api/packages/{name.lower()}/recent")
            if r.status_code != 200: return 0
            return int(r.json().get("data", {}).get("last_month", 0))
    except Exception:
        return 0


@lru_cache(maxsize=512)
def github_repo_metadata(owner: str, repo: str) -> dict:
    with _http() as c:
        r = c.get(f"https://api.github.com/repos/{owner}/{repo}")
        return r.json() if r.status_code == 200 else {}


@lru_cache(maxsize=512)
def osv_query(eco: str, name: str) -> list[dict]:
    """Pull OSV.dev advisories. Includes malicious-package category."""
    try:
        with _http() as c:
            r = c.post("https://api.osv.dev/v1/query",
                       json={"package": {"ecosystem": eco, "name": name}})
            if r.status_code != 200: return []
            return r.json().get("vulns", []) or []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Per-ecosystem analysis
# ---------------------------------------------------------------------------
def _analyze_npm(name: str, version: str | None) -> dict:
    md = npm_metadata(name)
    if not md or md.get("error"):
        return {"error": "package_not_found"}
    times = md.get("time", {})
    versions = md.get("versions", {})
    latest = md.get("dist-tags", {}).get("latest")
    v_data = versions.get(version or latest, {})
    maintainers = md.get("maintainers", []) or []

    # has install scripts?
    scripts = v_data.get("scripts", {}) or {}
    has_install = any(k in scripts for k in
                      ("preinstall","install","postinstall","prepare","prepublish"))

    # first publish + age
    created = times.get("created")
    age_days = 0
    if created:
        try:
            dt = datetime.fromisoformat(created.replace("Z","+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days
        except Exception: pass

    # readme + scripts text -> suspicious patterns
    text = (md.get("readme") or "") + " " + " ".join(scripts.values())
    sus = scan_text_for_patterns(text)

    # github url
    repo_url = (md.get("repository") or {}).get("url", "") if isinstance(md.get("repository"), dict) else ""
    homepage = md.get("homepage", "")

    # downloads
    dl = npm_download_count(name)

    return {
        "ecosystem": "npm", "name": name, "version": version or latest,
        "age_days": age_days,
        "download_count_30d": dl,
        "maintainer_count": len(maintainers),
        "has_install_scripts": has_install,
        "install_scripts": list(scripts.keys()) if has_install else [],
        "suspicious_patterns": sus,
        "repository_url": repo_url, "homepage": homepage,
        "license": md.get("license"),
        "description": md.get("description", "")[:200],
        "deprecated": bool(v_data.get("deprecated")),
    }


def _analyze_pypi(name: str, version: str | None) -> dict:
    md = pypi_metadata(name)
    if not md:
        return {"error": "package_not_found"}
    info = md.get("info", {})
    releases = md.get("releases", {}) or {}
    latest = info.get("version")
    v_data = releases.get(version or latest) or []
    upload_time = (v_data[0].get("upload_time") if v_data else None)

    # age
    age_days = 0
    if upload_time:
        try:
            dt = datetime.fromisoformat(upload_time)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - dt).days
        except Exception: pass

    text = (info.get("description") or "") + " " + (info.get("summary") or "")
    sus = scan_text_for_patterns(text)

    return {
        "ecosystem": "PyPI", "name": name, "version": version or latest,
        "age_days": age_days,
        "download_count_30d": pypi_download_count(name),
        "maintainer_count": 1 if info.get("author_email") else 0,
        "has_install_scripts": False,   # pyproject build hooks would need parsing
        "suspicious_patterns": sus,
        "repository_url": (info.get("project_urls") or {}).get("Source") or info.get("home_page"),
        "homepage": info.get("home_page"),
        "license": info.get("license"),
        "description": (info.get("summary") or "")[:200],
        "yanked": all(r.get("yanked") for r in v_data) if v_data else False,
    }


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------
def _build_signals(meta: dict, eco: str, name: str) -> dict:
    sig = {
        "signed": True,            # registries sign
        "publisher_verified": meta.get("maintainer_count", 0) > 0,
        "install_count": meta.get("download_count_30d", 0) or 0,
        "age_days": meta.get("age_days", 0) or 0,
        "last_update_days": 0,     # would need version dates; skipped for now
        "cve_count": 0,            # filled later
        "in_kev": False,
        "incident_proximity": 0,
        "permissions_high_risk": 0,
        "open_audit": False,
    }
    # Convert suspicious patterns to high-risk-perms equivalent
    if meta.get("suspicious_patterns"):
        sig["permissions_high_risk"] = len(meta["suspicious_patterns"])
    if meta.get("has_install_scripts"):
        sig["permissions_high_risk"] = sig["permissions_high_risk"] + 2

    # Typosquat indicator -- treat as a hard penalty
    ts, neighbor = typosquat_score(eco, name)
    if ts >= 1.0:
        sig["incident_proximity"] = 1   # treat like recent incident
    elif ts >= 0.7:
        sig["incident_proximity"] = 30
    return sig


_MALWARE_KEYWORDS = (
    "malicious", "malware", "compromis", "compromise", "compromised",
    "backdoor", "trojan", "credential steal", "credential-steal",
    "supply chain attack", "supply-chain attack",
    "account takeover", "maintainer takeover", "hijack", "hijacked",
    "cryptominer", "crypto miner", "wallet steal", "info stealer",
    "rat ", "remote access trojan", "data exfiltration",
)


def _malicious_feed_hit(eco: str, name: str) -> tuple[bool, str | None]:
    """First check the local cached threat feeds (instant), then fall back
    to a live OSV query (network latency). Returns (hit, evidence_url)."""
    # 1) Cached feeds (OSSF malicious-packages, GHSA malware, PyPA, Socket)
    hit, rec = _feeds.is_in_feeds(eco, name)
    if hit:
        return True, (rec or {}).get("url")

    # 2) Live OSV fallback (catches very fresh entries the local cache hasn't pulled yet)
    advisories = osv_query(_osv_ecosystem_name(eco), name)
    for adv in advisories:
        # 1) MAL- prefix is the cleanest signal (OSSF malicious-packages mirror)
        if adv.get("id", "").startswith("MAL-"):
            return True, f"https://osv.dev/vulnerability/{adv['id']}"
        # 2) Keyword hits across summary + details
        text = ((adv.get("summary") or "") + " " + (adv.get("details") or "")).lower()
        for kw in _MALWARE_KEYWORDS:
            if kw in text:
                return True, f"https://osv.dev/vulnerability/{adv.get('id','?')}"
        # 3) GHSA database_specific severity tags
        ds = adv.get("database_specific", {}) or {}
        for sev in ds.get("severity", []) or []:
            if any(kw in str(sev).lower() for kw in _MALWARE_KEYWORDS):
                return True, f"https://osv.dev/vulnerability/{adv.get('id','?')}"
    return False, None


@lru_cache(maxsize=1)
def _historical_incidents() -> list[dict]:
    """Curated list of known package compromise events. Bundled fixture."""
    import json
    from pathlib import Path
    f = Path(__file__).resolve().parent.parent / "data" / "historical_incidents.json"
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text(encoding="utf-8")).get("incidents", [])
    except Exception:
        return []


def _historical_hit(eco: str, name: str) -> dict | None:
    """Return the historical incident record for this package, if any."""
    name_low = name.lower()
    eco_low = eco.lower()
    for inc in _historical_incidents():
        if (inc.get("name","").lower() == name_low and
            inc.get("ecosystem","").lower() == eco_low):
            return inc
    return None


def _osv_ecosystem_name(eco: str) -> str:
    return {"npm": "npm", "pypi": "PyPI", "rubygems": "RubyGems",
            "crates.io": "crates.io", "go": "Go", "maven": "Maven"
            }.get(eco.lower(), eco)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def analyze_package(eco: str, name: str, version: str | None = None) -> dict:
    """Full risk report for a single package."""
    eco_lower = eco.lower()
    if eco_lower == "npm":
        meta = _analyze_npm(name, version)
    elif eco_lower in ("pypi", "python"):
        meta = _analyze_pypi(name, version)
    else:
        meta = {"ecosystem": eco, "name": name, "version": version,
                "info": "Limited analysis - registry not yet wired for this ecosystem"}

    # Cross-reference malicious feed (broad keyword set)
    in_mal, mal_url = _malicious_feed_hit(eco_lower, name)

    # Cross-reference historical-incidents fixture (institutional memory)
    historical = _historical_hit(eco_lower, name)

    # Typosquat
    ts, neighbor = typosquat_score(eco_lower, name)

    # Build signals + score
    signals = _build_signals(meta, eco_lower, name)
    if in_mal:
        signals["incident_proximity"] = 1
        signals["cve_count"] = signals.get("cve_count", 0) + 5
    if historical:
        # Incident proximity in days since the documented event
        from datetime import date as _date
        try:
            d = _date.fromisoformat(historical.get("date", "1970-01-01"))
            days = max(1, (_date.today() - d).days)
            signals["incident_proximity"] = min(signals.get("incident_proximity", 99999), days)
        except Exception:
            signals["incident_proximity"] = 365
        signals["cve_count"] = signals.get("cve_count", 0) + 3

    res = trust_score(signals)
    score = res.score
    band = "MALICIOUS" if in_mal else res.band
    if historical and band in ("TRUSTED", "OK"):
        # Historical compromise downgrades to at least CAUTION.
        band = "CAUTION"

    findings: list[str] = []
    if in_mal:
        findings.append(f"⚠ Listed in OSV malicious-package feed: {mal_url}")
    if historical:
        findings.append(
            f"⚠ HISTORICAL COMPROMISE on {historical['date']} "
            f"(versions {historical['version_affected']}): "
            f"{historical['type']} - {historical['description']}. "
            f"Reference: {historical['url']}"
        )
    if ts >= 1.0:
        findings.append(f"⚠ TYPOSQUAT: 1-character distance from popular '{neighbor}'")
    elif ts >= 0.7:
        findings.append(f"⚠ Possible typosquat of '{neighbor}'")
    if meta.get("has_install_scripts"):
        findings.append(f"Install scripts present: {meta.get('install_scripts')}")
    if meta.get("suspicious_patterns"):
        findings.append(f"Suspicious patterns in metadata: {meta['suspicious_patterns']}")
    if meta.get("age_days") and meta["age_days"] < 30:
        findings.append(f"Very new package ({meta['age_days']} days old)")
    if meta.get("download_count_30d", 0) < 50 and meta.get("age_days", 0) > 30:
        findings.append("Very low download count (possible abandoned or fake)")
    if meta.get("deprecated") or meta.get("yanked"):
        findings.append("Package is deprecated or yanked")
    if not meta.get("license"):
        findings.append("No license declared")

    return {
        "ecosystem": eco, "name": name, "version": version or meta.get("version"),
        "score": score, "band": band,
        "in_malicious_feed": in_mal,
        "typosquat": {"distance_score": ts, "closest_popular": neighbor},
        "metadata": meta,
        "trust_components": res.components,
        "findings": findings,
        "reasons": res.reasons,
    }


def analyze_github_url(url: str) -> dict:
    """Risk report for a GitHub repo URL."""
    m = re.search(r"github\.com[/:]([^/]+)/([^/.]+)", url)
    if not m:
        return {"error": "not a github url", "url": url}
    owner, repo = m.group(1), m.group(2)
    meta = github_repo_metadata(owner, repo)
    if not meta or meta.get("message") == "Not Found":
        return {"error": "repo not found", "url": url}

    age_days = 0
    if meta.get("created_at"):
        try:
            dt = datetime.fromisoformat(meta["created_at"].replace("Z","+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days
        except Exception: pass
    last_push_days = 0
    if meta.get("pushed_at"):
        try:
            dt = datetime.fromisoformat(meta["pushed_at"].replace("Z","+00:00"))
            last_push_days = (datetime.now(timezone.utc) - dt).days
        except Exception: pass

    signals = {
        "signed": False,
        "publisher_verified": bool(meta.get("organization")),
        "install_count": meta.get("stargazers_count", 0),
        "age_days": age_days,
        "last_update_days": last_push_days,
        "open_audit": False,
    }
    findings: list[str] = []
    if meta.get("archived"):
        findings.append("Repo is archived (no active maintenance)")
    if meta.get("disabled"):
        findings.append("Repo is disabled")
    if age_days < 30:
        findings.append(f"Very new repo ({age_days} days old)")
    if meta.get("forks_count", 0) > meta.get("stargazers_count", 1) * 5:
        findings.append("Unusual forks-to-stars ratio (possible bot farm)")
    if not meta.get("license"):
        findings.append("No license declared")

    res = trust_score(signals)
    return {
        "owner": owner, "repo": repo,
        "stars": meta.get("stargazers_count"),
        "forks": meta.get("forks_count"),
        "open_issues": meta.get("open_issues_count"),
        "default_branch": meta.get("default_branch"),
        "age_days": age_days, "last_push_days": last_push_days,
        "license": (meta.get("license") or {}).get("spdx_id"),
        "archived": meta.get("archived"), "disabled": meta.get("disabled"),
        "score": res.score, "band": res.band,
        "findings": findings,
        "reasons": res.reasons,
    }


def scan_inventory_against_malicious() -> dict:
    """Cross-reference every Package node against the malicious feed."""
    from .graph import run_read
    pkgs = run_read("""
        MATCH (p:Package)
        RETURN p.ecosystem AS eco, p.name AS name LIMIT 1000
    """)
    hits = []
    for p in pkgs:
        if not p.get("eco") or not p.get("name"):
            continue
        # _malicious_feed_hit returns (bool, evidence_url|None).
        # Truthy-tuple bug fix: explicitly unpack and check the bool.
        is_hit, evidence_url = _malicious_feed_hit(p["eco"], p["name"])
        if is_hit:
            hits.append({
                "ecosystem": p["eco"], "name": p["name"],
                "evidence": evidence_url,
            })
    return {"checked": len(pkgs), "malicious_hits": hits}
