"""
GitHub Security Advisory ingester
=================================
Pulls GHSA advisories via the public REST endpoint:
  https://api.github.com/advisories?per_page=100&page=N

Each advisory contains rich CWE mappings + ecosystem package info.

A GitHub token (set GITHUB_TOKEN in .env) raises the rate limit from 60/hr to
5000/hr - strongly recommended for any meaningful pull.

Usage:
    python -m ingest.ghsa --pages 5
    python -m ingest.ghsa --severity critical --pages 10
"""

from __future__ import annotations

import argparse

from rich.progress import Progress

from config import settings

from .common import console, http_client, link_cve_package, polite_sleep, upsert_cve

GHSA_URL = "https://api.github.com/advisories"

# GitHub ecosystem strings mapped to OSV-style ecosystems we use
ECO_MAP = {
    "npm": "npm",
    "pip": "PyPI",
    "maven": "Maven",
    "go": "Go",
    "rubygems": "RubyGems",
    "rust": "crates.io",
    "composer": "Packagist",
    "nuget": "NuGet",
    "erlang": "Hex",
    "actions": "GitHub Actions",
    "pub": "Pub",
    "swift": "SwiftURL",
}


def _headers() -> dict:
    h = {"Accept": "application/vnd.github+json"}
    if settings.github_token:
        h["Authorization"] = f"Bearer {settings.github_token}"
    return h


def ingest_pages(pages: int = 5, severity: str | None = None) -> int:
    count = 0
    skipped = 0
    with http_client(headers=_headers()) as c, Progress() as bar:
        task = bar.add_task("[cyan]GHSA", total=pages)
        for page in range(1, pages + 1):
            params = {"per_page": 100, "page": page}
            if severity:
                params["severity"] = severity
            r = c.get(GHSA_URL, params=params)
            if r.status_code != 200:
                console.print(f"[red]GHSA HTTP {r.status_code}: {r.text[:200]}")
                break
            try:
                advisories = r.json()
            except Exception as e:
                console.print(f"[red]GHSA: bad JSON on page {page}: {e}")
                break
            # GitHub may return a dict (error envelope) or a list (data).
            if isinstance(advisories, dict):
                console.print(f"[yellow]GHSA: unexpected dict response: {str(advisories)[:200]}")
                break
            if not isinstance(advisories, list) or not advisories:
                break
            for adv in advisories:
                if not isinstance(adv, dict):
                    skipped += 1
                    continue
                try:
                    count += _ingest_one(adv)
                except Exception as e:
                    skipped += 1
                    console.print(
                        f"[yellow]  skip {adv.get('ghsa_id') or adv.get('cve_id') or '?'}: {e}"
                    )
            bar.update(task, advance=1)
            polite_sleep(0.5)
    console.print(f"[green]GHSA ingested {count} advisories ({skipped} skipped)")
    return count


def _coerce_str_list(field) -> list[str]:
    """Tolerate both ['CWE-79'] and [{'cwe_id': 'CWE-79', ...}] shapes."""
    out: list[str] = []
    if not field:
        return out
    if not isinstance(field, list):
        return out
    for item in field:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            v = item.get("cwe_id") or item.get("id") or item.get("name")
            if isinstance(v, str):
                out.append(v)
    return out


def _coerce_url_list(field) -> list[str]:
    out: list[str] = []
    if not isinstance(field, list):
        return out
    for item in field:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            v = item.get("url")
            if isinstance(v, str):
                out.append(v)
    return out


def _ingest_one(adv: dict) -> int:
    cve_id = adv.get("cve_id") or adv.get("ghsa_id")
    if not cve_id:
        return 0
    description = adv.get("description") or adv.get("summary") or ""

    # cwes can be ['CWE-79'] or [{'cwe_id': 'CWE-79', 'name': '...'}]
    cwe_ids = []
    for raw in _coerce_str_list(adv.get("cwes")):
        s = raw.upper().strip()
        if s and not s.startswith("CWE-"):
            s = f"CWE-{s}"
        if s.startswith("CWE-"):
            cwe_ids.append(s)

    # cvss can be a dict, missing, or null
    cvss = adv.get("cvss")
    if not isinstance(cvss, dict):
        cvss = {}
    cvss_score = cvss.get("score") if isinstance(cvss.get("score"), (int, float)) else None
    cvss_vector = cvss.get("vector_string") if isinstance(cvss.get("vector_string"), str) else None

    references = _coerce_url_list(adv.get("references"))

    upsert_cve(
        cve_id=cve_id,
        description=description if isinstance(description, str) else "",
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        published=adv.get("published_at") if isinstance(adv.get("published_at"), str) else None,
        modified=adv.get("updated_at") if isinstance(adv.get("updated_at"), str) else None,
        cwe_ids=cwe_ids,
        references=references,
    )

    vulns = adv.get("vulnerabilities") or []
    if not isinstance(vulns, list):
        vulns = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        pkg = vuln.get("package") if isinstance(vuln.get("package"), dict) else {}
        eco_raw = (
            (pkg.get("ecosystem") or "").lower() if isinstance(pkg.get("ecosystem"), str) else ""
        )
        ecosystem = ECO_MAP.get(eco_raw, eco_raw)
        name = pkg.get("name") if isinstance(pkg.get("name"), str) else None
        if not (ecosystem and name):
            continue
        affected = []
        vvr = vuln.get("vulnerable_version_range")
        if isinstance(vvr, str) and vvr:
            affected.append(vvr)
        fixed = []
        fpv = vuln.get("first_patched_version")
        if isinstance(fpv, str) and fpv:
            fixed.append(fpv)
        elif isinstance(fpv, dict) and isinstance(fpv.get("identifier"), str):
            fixed.append(fpv["identifier"])
        link_cve_package(cve_id, ecosystem, name, affected, fixed)
    return 1


def main() -> None:
    p = argparse.ArgumentParser(description="Ingest GitHub Security Advisories")
    p.add_argument("--pages", type=int, default=5)
    p.add_argument("--severity", choices=["low", "medium", "high", "critical"])
    args = p.parse_args()
    ingest_pages(args.pages, args.severity)


if __name__ == "__main__":
    main()
