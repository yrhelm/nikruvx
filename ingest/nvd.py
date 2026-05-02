"""
NVD CVE ingester
================
Pulls from the NVD 2.0 API (https://services.nvd.nist.gov/rest/json/cves/2.0).

Rate limits (Cloudflare-enforced):
    - No API key: 5 requests / 30 seconds
    - With API key: 50 requests / 30 seconds  (set NVD_API_KEY in .env)

Usage:
    python -m ingest.nvd --days 7
    python -m ingest.nvd --cve CVE-2024-3094
    python -m ingest.nvd --year 2024 --limit 500
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta

from rich.progress import Progress

from config import settings

from .common import console, http_client, polite_sleep, upsert_cve

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_cve(item: dict) -> dict | None:
    cve = item.get("cve") or item
    cve_id = cve.get("id")
    if not cve_id:
        return None
    descs = cve.get("descriptions", [])
    description = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_vector = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            cvss_score = data.get("baseScore")
            cvss_vector = data.get("vectorString")
            break
    cwes: list[str] = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = d.get("value", "")
            if v.startswith("CWE-"):
                cwes.append(v)
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_ids": list(dict.fromkeys(cwes)),
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "references": refs,
    }


def ingest_recent(days: int = 7, limit: int = 200) -> int:
    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(limit, 2000),
    }
    return _ingest(params, limit)


def ingest_year(year: int, limit: int = 500) -> int:
    start = datetime(year, 1, 1, tzinfo=UTC)
    end = datetime(year, 12, 31, 23, 59, 59, tzinfo=UTC)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(limit, 2000),
    }
    return _ingest(params, limit)


def ingest_one(cve_id: str) -> int:
    return _ingest({"cveId": cve_id, "resultsPerPage": 1}, limit=1)


def _request_with_retry(client, params: dict, max_retries: int = 5):
    """GET with exponential backoff on 429 / 503 / network errors."""
    backoff = 8.0
    for attempt in range(max_retries):
        try:
            resp = client.get(NVD_URL, params=params)
        except Exception as e:
            console.print(f"[yellow]NVD network error: {e} - retry in {backoff:.0f}s")
            polite_sleep(backoff)
            backoff *= 1.7
            continue
        if resp.status_code == 200:
            return resp
        if resp.status_code in (429, 503):
            wait = backoff
            ra = resp.headers.get("Retry-After")
            if ra and ra.isdigit():
                wait = max(wait, float(ra))
            console.print(
                f"[yellow]NVD {resp.status_code} rate-limited - waiting {wait:.0f}s "
                f"(attempt {attempt + 1}/{max_retries})"
            )
            polite_sleep(wait)
            backoff *= 1.7
            continue
        console.print(f"[red]NVD HTTP {resp.status_code}: {resp.text[:200]}")
        return resp
    console.print("[red]NVD: exceeded retry budget")
    return None


def _ingest(params: dict, limit: int) -> int:
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    # NVD without a key: 5 req per 30s. With a key: 50 per 30s.
    pause = 0.7 if settings.nvd_api_key else 6.5
    count = 0
    start_index = 0
    with http_client(headers=headers) as client, Progress() as bar:
        task = bar.add_task("[cyan]NVD CVE", total=limit)
        while count < limit:
            params["startIndex"] = start_index
            resp = _request_with_retry(client, params)
            if resp is None or resp.status_code != 200:
                break
            data = resp.json()
            items = data.get("vulnerabilities", [])
            if not items:
                break
            for it in items:
                parsed = _parse_cve(it)
                if not parsed:
                    continue
                upsert_cve(**parsed)
                count += 1
                bar.update(task, advance=1)
                if count >= limit:
                    break
            total = data.get("totalResults", 0)
            start_index += len(items)
            if start_index >= total:
                break
            polite_sleep(pause)
    console.print(f"[green]NVD ingested {count} CVEs")
    return count


def main() -> None:
    p = argparse.ArgumentParser(description="Ingest CVEs from NVD")
    p.add_argument("--days", type=int, help="Pull CVEs modified in the last N days")
    p.add_argument("--year", type=int, help="Pull CVEs published in this year")
    p.add_argument("--cve", type=str, help="Pull a single CVE by id")
    p.add_argument("--limit", type=int, default=200)
    args = p.parse_args()
    if args.cve:
        ingest_one(args.cve)
    elif args.year:
        ingest_year(args.year, args.limit)
    else:
        ingest_recent(args.days or 7, args.limit)


if __name__ == "__main__":
    main()
