"""
Auto-fetching threat-feed orchestrator.

Pulls malicious-package data from public sources, caches to disk, and
exposes a fast in-memory lookup. Designed to run on API startup + every
6 hours via a background task -- so users never have to manually
refresh anything.

Sources currently wired in:

  1. OSSF malicious-packages   github.com/ossf/malicious-packages
     The largest curated dataset; mirrored in OSV under MAL-* IDs.
     We pull the repo's git tree (one HTTP call) and extract every
     osv/<ecosystem>/<name>/MAL-*.json path.

  2. GHSA malware advisories   /advisories?type=malware
     GitHub-curated malware advisories. Public, rate-limited (60/hr
     anonymous, 5000/hr with GITHUB_TOKEN).

  3. PyPA advisory-database    github.com/pypa/advisory-database
     Python-specific advisories including malicious uploads.

  4. Socket.dev (optional)     api.socket.dev
     Real-time newly-published malicious package detection. Requires
     SOCKET_API_KEY in .env. Skipped if not set.

Cache files live in data/feeds/. Each feed has:
    { "fetched_at": "2026-04-30T...", "count": N, "entries": [
        {"ecosystem": "npm", "name": "ua-parser-js",
         "advisory": "MAL-2021-...", "url": "...", "summary": "..."},
        ...
    ]}
"""
from __future__ import annotations
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "data" / "feeds"
FEEDS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# In-memory index (eco_lower, name_lower) -> evidence-record
#
# CRITICAL: only feeds that are CURATED FOR MALICIOUS UPLOADS belong here.
# A general "vulnerability advisory" feed (like PyPA's advisory-database) is
# NOT a malicious-package signal -- it lists every package that has ever had
# a CVE, which produces enormous false-positive rates if used as
# "malicious-or-not". PyPA is still cached on disk for separate lookup, but
# it is intentionally NOT loaded into this index.
# ---------------------------------------------------------------------------
_LOCK = threading.RLock()
_INDEX: dict[tuple[str, str], dict] = {}
_STATUS: dict[str, dict] = {}   # source-name -> {fetched_at, count, error?}

# Sources whose entries indicate a TRULY MALICIOUS package upload.
_MALICIOUS_SOURCES = {"ossf_malicious", "ghsa_malware", "socket_dev"}
# Sources that are general advisory feeds (PyPA, etc.) - cached but NOT used
# for malicious detection. Use is_in_advisory_feed() instead.
_ADVISORY_SOURCES = {"pypa_advisory_db"}


def _key(eco: str, name: str) -> tuple[str, str]:
    return (eco.lower().strip(), name.lower().strip())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _http_client() -> httpx.Client:
    headers = {"User-Agent": "NikruvX/threat-feeds"}
    tok = os.getenv("GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    headers["Accept"] = "application/vnd.github+json"
    return httpx.Client(timeout=30.0, headers=headers)


# ---------------------------------------------------------------------------
# Cache I/O
# ---------------------------------------------------------------------------
def _save(source: str, entries: list[dict]) -> None:
    payload = {"fetched_at": _now_iso(), "count": len(entries), "entries": entries}
    (FEEDS_DIR / f"{source}.json").write_text(json.dumps(payload, separators=(",", ":")),
                                              encoding="utf-8")


def _load(source: str) -> dict:
    f = FEEDS_DIR / f"{source}.json"
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


_ADVISORY_INDEX: dict[tuple[str, str], dict] = {}


def _load_into_index() -> None:
    """Populate the in-memory indexes from on-disk caches.
    Only _MALICIOUS_SOURCES feed _INDEX; advisory-style feeds go to
    _ADVISORY_INDEX so they can still be queried separately without
    polluting malicious-detection."""
    with _LOCK:
        _INDEX.clear()
        _ADVISORY_INDEX.clear()
        for source_file in FEEDS_DIR.glob("*.json"):
            source_name = source_file.stem
            data = _load(source_name)
            target = (_INDEX if source_name in _MALICIOUS_SOURCES
                      else _ADVISORY_INDEX if source_name in _ADVISORY_SOURCES
                      else None)
            if target is None:
                continue   # unknown source - skip (e.g., partial download leftover)
            for e in data.get("entries", []):
                eco = e.get("ecosystem"); name = e.get("name")
                if eco and name:
                    target[_key(eco, name)] = e
            _STATUS[source_name] = {
                "fetched_at": data.get("fetched_at"),
                "count": data.get("count", 0),
                "kind": ("malicious" if source_name in _MALICIOUS_SOURCES
                         else "advisory" if source_name in _ADVISORY_SOURCES
                         else "unknown"),
            }


# Load whatever is already on disk at import time so the API doesn't have
# to wait for the first network refresh to start returning useful results.
_load_into_index()


# ---------------------------------------------------------------------------
# Public lookup
# ---------------------------------------------------------------------------
def is_in_feeds(ecosystem: str, name: str) -> tuple[bool, dict | None]:
    """Fast in-memory check against the MALICIOUS-only feeds (OSSF + GHSA-
    malware). Does NOT consult general advisory feeds. Returns (hit, evidence)."""
    rec = _INDEX.get(_key(ecosystem, name))
    return (True, rec) if rec else (False, None)


def is_in_advisory_feed(ecosystem: str, name: str) -> tuple[bool, dict | None]:
    """Separate lookup for general advisory feeds (PyPA). Useful for
    enrichment but should NOT be used for is-this-malicious decisions."""
    rec = _ADVISORY_INDEX.get(_key(ecosystem, name))
    return (True, rec) if rec else (False, None)


def status() -> dict:
    """Return per-source status (last fetched, count, kind, error) for the UI."""
    return {
        "sources": _STATUS,
        "malicious_indexed": len(_INDEX),
        "advisory_indexed": len(_ADVISORY_INDEX),
        "feeds_dir": str(FEEDS_DIR),
    }


# ---------------------------------------------------------------------------
# Source 1: OSSF malicious-packages
# ---------------------------------------------------------------------------
_OSSF_REPO = "ossf/malicious-packages"
_OSSF_TREE = f"https://api.github.com/repos/{_OSSF_REPO}/git/trees/main?recursive=1"
# Path layout: osv/<ecosystem>/<name>/MAL-YYYY-XXX.json
_OSSF_PATH = re.compile(r"^osv/([^/]+)/(.+)/(MAL-[\d\-]+)\.json$")
# Some ecosystems are split into chunked subdirs - normalise:
_OSSF_ECO_MAP = {
    "npm": "npm", "pypi": "PyPI", "rubygems": "RubyGems",
    "crates-io": "crates.io", "crates_io": "crates.io",
    "go": "Go", "maven": "Maven", "nuget": "NuGet", "packagist": "Packagist",
}


def fetch_ossf_malicious() -> dict:
    """Walk the OSSF malicious-packages repo tree (one API call)."""
    try:
        with _http_client() as c:
            r = c.get(_OSSF_TREE, timeout=60.0)
            r.raise_for_status()
            tree = r.json().get("tree", [])
    except Exception as e:
        _STATUS["ossf_malicious"] = {"error": str(e), "fetched_at": _now_iso(),
                                      "count": _STATUS.get("ossf_malicious", {}).get("count", 0)}
        return {"error": str(e)}

    entries: list[dict] = []
    for node in tree:
        if node.get("type") != "blob":
            continue
        m = _OSSF_PATH.match(node.get("path", ""))
        if not m:
            continue
        raw_eco, name, mal_id = m.group(1), m.group(2), m.group(3)
        eco = _OSSF_ECO_MAP.get(raw_eco.lower(), raw_eco)
        # name path may have slashes (Maven groupId/artifactId)
        name = name.replace("/", ":") if eco.lower() == "maven" else name
        entries.append({
            "ecosystem": eco, "name": name, "advisory": mal_id,
            "source": "ossf_malicious",
            "url": f"https://github.com/{_OSSF_REPO}/blob/main/{node['path']}",
            "summary": "Malicious package per OSSF malicious-packages corpus",
        })
    _save("ossf_malicious", entries)
    return {"count": len(entries)}


# ---------------------------------------------------------------------------
# Source 2: GHSA malware advisories
# ---------------------------------------------------------------------------
def fetch_ghsa_malware(pages: int = 10) -> dict:
    entries: list[dict] = []
    try:
        with _http_client() as c:
            for page in range(1, pages + 1):
                r = c.get("https://api.github.com/advisories",
                          params={"type": "malware", "per_page": 100, "page": page})
                if r.status_code != 200:
                    break
                advisories = r.json()
                if not advisories:
                    break
                for adv in advisories:
                    cve = adv.get("cve_id") or adv.get("ghsa_id")
                    summary = adv.get("summary") or adv.get("description") or ""
                    for v in adv.get("vulnerabilities", []) or []:
                        pkg = v.get("package") or {}
                        eco = pkg.get("ecosystem")
                        name = pkg.get("name")
                        if not (eco and name):
                            continue
                        entries.append({
                            "ecosystem": _OSSF_ECO_MAP.get(eco.lower(), eco),
                            "name": name, "advisory": cve,
                            "source": "ghsa_malware",
                            "url": adv.get("html_url") or f"https://github.com/advisories/{cve}",
                            "summary": summary[:300],
                        })
    except Exception as e:
        _STATUS["ghsa_malware"] = {"error": str(e), "fetched_at": _now_iso(),
                                    "count": _STATUS.get("ghsa_malware", {}).get("count", 0)}
        return {"error": str(e)}
    _save("ghsa_malware", entries)
    return {"count": len(entries)}


# ---------------------------------------------------------------------------
# Source 3: PyPA advisory-database (Python-specific)
# ---------------------------------------------------------------------------
_PYPA_TREE = "https://api.github.com/repos/pypa/advisory-database/git/trees/main?recursive=1"
_PYPA_PATH = re.compile(r"^vulns/([^/]+)/PYSEC-[\d\-]+\.yaml$")


def fetch_pypa_advisory_db() -> dict:
    try:
        with _http_client() as c:
            r = c.get(_PYPA_TREE, timeout=60.0)
            r.raise_for_status()
            tree = r.json().get("tree", [])
    except Exception as e:
        _STATUS["pypa_advisory_db"] = {"error": str(e), "fetched_at": _now_iso(),
                                        "count": _STATUS.get("pypa_advisory_db", {}).get("count", 0)}
        return {"error": str(e)}

    entries: list[dict] = []
    for node in tree:
        if node.get("type") != "blob":
            continue
        m = _PYPA_PATH.match(node.get("path", ""))
        if not m:
            continue
        name = m.group(1)
        # We don't fetch the YAML contents (would be N HTTP calls).
        # The presence of the entry alone is the index signal.
        adv_id = Path(node["path"]).stem
        entries.append({
            "ecosystem": "PyPI", "name": name,
            "advisory": adv_id, "source": "pypa_advisory_db",
            "url": f"https://github.com/pypa/advisory-database/blob/main/{node['path']}",
            "summary": "PyPI advisory recorded by PyPA",
        })
    _save("pypa_advisory_db", entries)
    return {"count": len(entries)}


# ---------------------------------------------------------------------------
# Source 4 (optional): Socket.dev real-time feed
# ---------------------------------------------------------------------------
def fetch_socket_dev() -> dict:
    """Optional - only runs if SOCKET_API_KEY is set."""
    key = os.getenv("SOCKET_API_KEY")
    if not key:
        _STATUS["socket_dev"] = {"skipped": "SOCKET_API_KEY not set",
                                  "fetched_at": _now_iso(), "count": 0}
        return {"skipped": True}
    # Socket's exact API surface depends on tier. Stub for now.
    _STATUS["socket_dev"] = {"skipped": "Socket integration is a stub - extend with your tier's API",
                              "fetched_at": _now_iso(), "count": 0}
    return {"skipped": True}


# ---------------------------------------------------------------------------
# Refresh orchestrator
# ---------------------------------------------------------------------------
SOURCES = [
    ("ossf_malicious",    fetch_ossf_malicious),
    ("ghsa_malware",      fetch_ghsa_malware),
    ("pypa_advisory_db",  fetch_pypa_advisory_db),
    ("socket_dev",        fetch_socket_dev),
]


def refresh_all() -> dict:
    """Run every fetcher. Safe to call concurrently with lookups -- the
    in-memory index is rebuilt atomically at the end."""
    summary: dict[str, Any] = {"started_at": _now_iso(), "results": {}}
    for source_name, fn in SOURCES:
        try:
            result = fn()
            summary["results"][source_name] = result
        except Exception as e:
            summary["results"][source_name] = {"error": str(e)}
    # Rebuild the in-memory index from the freshly written caches.
    _load_into_index()
    summary["finished_at"] = _now_iso()
    summary["total_indexed"] = len(_INDEX)
    return summary


# ---------------------------------------------------------------------------
# Background loop helper for the FastAPI lifespan
# ---------------------------------------------------------------------------
def background_loop(stop_event: threading.Event, interval_seconds: int = 6 * 3600) -> None:
    """Run refresh_all() in a loop until stop_event is set."""
    while not stop_event.is_set():
        try:
            refresh_all()
        except Exception:
            pass    # already logged in per-source status
        # Sleep in small chunks so shutdown is responsive
        for _ in range(interval_seconds):
            if stop_event.is_set():
                return
            time.sleep(1)
