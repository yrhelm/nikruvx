"""
PoC Extractor
=============
For a given CVE-ID, search public sources for proof-of-concept code:
  1. trickest/cve   (curated index of PoCs by CVE-ID)
  2. nomi-sec/PoC-in-GitHub  (auto-aggregated GitHub repos with PoCs)
  3. GitHub code search (fallback) - finds repos whose names contain the CVE id
  4. ExploitDB CSV   (Offensive Security's exploit DB)

For each match we fetch a short raw snippet (first ~80 lines) and store the
PoC node + HAS_POC edge in Neo4j.

Usage:
    python -m ingest.poc CVE-2024-3094
    python -m ingest.poc --batch CVE-2024-3094 CVE-2023-44487
    python -m ingest.poc --missing 50    # find PoCs for the 50 CVEs in DB without one
"""

from __future__ import annotations

import argparse
import re

from rich.progress import Progress

from config import settings
from engine.graph import session

from .common import attach_poc, console, http_client, polite_sleep

TRICKEST_RAW = "https://raw.githubusercontent.com/trickest/cve/main"
NOMI_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
GH_SEARCH = "https://api.github.com/search/repositories"


def _gh_headers() -> dict:
    h = {"Accept": "application/vnd.github+json"}
    if settings.github_token:
        h["Authorization"] = f"Bearer {settings.github_token}"
    return h


def _fetch_raw(url: str) -> str | None:
    with http_client(timeout=20) as c:
        r = c.get(url)
        if r.status_code == 200:
            return r.text
    return None


def from_trickest(cve_id: str) -> list[tuple[str, str]]:
    """trickest/cve stores per-year markdown indexes with PoC links."""
    m = re.match(r"CVE-(\d{4})-\d+", cve_id, re.I)
    if not m:
        return []
    year = m.group(1)
    md = _fetch_raw(f"{TRICKEST_RAW}/{year}/{cve_id}.md")
    if not md:
        return []
    urls = re.findall(r"https?://github\.com/[^\s\)]+", md)
    out = [(u.rstrip(".,);"), "trickest") for u in urls[:5]]
    return out


def from_nomi(cve_id: str) -> list[tuple[str, str]]:
    m = re.match(r"CVE-(\d{4})-\d+", cve_id, re.I)
    if not m:
        return []
    year = m.group(1)
    txt = _fetch_raw(f"{NOMI_RAW}/{year}/{cve_id}.json")
    if not txt:
        return []
    import json

    try:
        data = json.loads(txt)
    except Exception:
        return []
    urls = []
    for item in data:
        url = item.get("html_url")
        if url:
            urls.append((url, "nomi-sec"))
    return urls[:5]


def from_github_search(cve_id: str) -> list[tuple[str, str]]:
    with http_client(headers=_gh_headers()) as c:
        r = c.get(GH_SEARCH, params={"q": cve_id, "per_page": 5, "sort": "stars"})
        if r.status_code != 200:
            return []
        items = r.json().get("items", [])
        return [(it["html_url"], "github-search") for it in items]


def from_exploitdb(cve_id: str) -> list[tuple[str, str]]:
    """ExploitDB has an aliases column with CVE references."""
    csv_text = _fetch_raw(EXPLOITDB_CSV)
    if not csv_text:
        return []
    out = []
    needle = cve_id.upper()
    for line in csv_text.splitlines():
        if needle in line.upper():
            # column 0 = id, column 1 = file path
            parts = line.split(",")
            if len(parts) > 1 and parts[0].isdigit():
                out.append((f"https://www.exploit-db.com/exploits/{parts[0]}", "exploitdb"))
                if len(out) >= 3:
                    break
    return out


def _snippet_for(url: str) -> tuple[str | None, str | None]:
    """If the URL is a GitHub raw-able file, fetch first ~80 lines."""
    raw = url
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)", url)
    if m:
        owner, repo, branch, path = m.groups()
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    if "raw.githubusercontent.com" in raw:
        text = _fetch_raw(raw)
        if text:
            lines = text.splitlines()[:80]
            lang = path.rsplit(".", 1)[-1] if m else None
            return ("\n".join(lines), lang)
    return (None, None)


def extract_for(cve_id: str) -> int:
    cve_id = cve_id.upper().strip()
    sources = []
    sources += from_trickest(cve_id)
    sources += from_nomi(cve_id)
    if not sources:
        sources += from_github_search(cve_id)
    sources += from_exploitdb(cve_id)
    seen = set()
    count = 0
    for url, src in sources:
        if url in seen:
            continue
        seen.add(url)
        snippet, lang = _snippet_for(url)
        attach_poc(cve_id, url, src, lang, snippet)
        count += 1
    if count:
        console.print(f"[green]{cve_id}: {count} PoC(s) attached")
    else:
        console.print(f"[yellow]{cve_id}: no public PoC found")
    return count


def find_missing(limit: int = 50) -> list[str]:
    cypher = """
    MATCH (c:CVE)
    WHERE NOT (c)-[:HAS_POC]->() AND c.severity IN ['CRITICAL','HIGH']
    RETURN c.id AS id ORDER BY c.cvss_score DESC LIMIT $limit
    """
    with session() as s:
        return [r["id"] for r in s.run(cypher, limit=limit)]


def main() -> None:
    p = argparse.ArgumentParser(description="Extract PoCs for CVEs")
    p.add_argument("cves", nargs="*", help="CVE IDs to fetch PoCs for")
    p.add_argument("--missing", type=int, help="Find PoCs for top-N CVEs in DB without one")
    args = p.parse_args()
    targets: list[str] = list(args.cves or [])
    if args.missing:
        targets += find_missing(args.missing)
    if not targets:
        p.print_help()
        return
    with Progress() as bar:
        task = bar.add_task("[cyan]PoC extract", total=len(targets))
        for cve in targets:
            extract_for(cve)
            polite_sleep(0.3)
            bar.update(task, advance=1)


if __name__ == "__main__":
    main()
