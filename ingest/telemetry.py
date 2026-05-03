"""
Real-Time Exploit Telemetry
===========================
Marks CVEs as ACTIVELY_EXPLOITED based on:
  1. CISA Known Exploited Vulnerabilities catalog (free, no auth)
  2. (Optional) GreyNoise community / paid feeds (set GREYNOISE_KEY)
  3. (Optional) Exploit-DB recency

Each call refreshes the `:CVE.exploited_*` properties + an :ACTIVE_EXPLOIT
relationship for fast querying.

Usage:
    python -m ingest.telemetry              # full refresh
    python -m ingest.telemetry --kev-only
"""
from __future__ import annotations
import argparse
import os
from rich.console import Console

from .common import http_client, polite_sleep
from engine.graph import run_write, session

console = Console()
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GREYNOISE_URL = "https://api.greynoise.io/v3/community/"


def ingest_kev() -> int:
    """Ingest CISA Known Exploited Vulnerabilities catalog."""
    with http_client(timeout=30) as c:
        r = c.get(KEV_URL)
        if r.status_code != 200:
            console.print(f"[red]CISA KEV HTTP {r.status_code}")
            return 0
        data = r.json()
    items = data.get("vulnerabilities", [])
    cypher = """
    UNWIND $items AS item
        MERGE (c:CVE {id: item.cveID})
        SET c.exploited_kev          = true,
            c.exploited_kev_date     = item.dateAdded,
            c.exploited_known_ransom = item.knownRansomwareCampaignUse,
            c.exploited_required_action = item.requiredAction
    """
    payload = [{
        "cveID": v["cveID"],
        "dateAdded": v.get("dateAdded"),
        "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse", "Unknown"),
        "requiredAction": v.get("requiredAction"),
    } for v in items]
    with session() as s:
        s.run(cypher, items=payload)
    console.print(f"[green]CISA KEV: {len(items)} CVEs marked actively-exploited")
    return len(items)


def ingest_greynoise(cves: list[str] | None = None) -> int:
    """Optional: tag CVEs that GreyNoise has community telemetry on."""
    key = os.getenv("GREYNOISE_KEY")
    if not key:
        console.print("[yellow]GREYNOISE_KEY not set - skipping GreyNoise enrichment.")
        return 0
    # The community API is rate-limited; pull tag info per CVE we already track
    headers = {"key": key}
    if cves is None:
        from engine.graph import run_read
        rows = run_read("MATCH (c:CVE) WHERE c.severity IN ['CRITICAL','HIGH'] RETURN c.id AS id LIMIT 200")
        cves = [r["id"] for r in rows]
    count = 0
    with http_client(headers=headers) as c:
        for cve in cves:
            r = c.get(f"{GREYNOISE_URL}{cve}")
            if r.status_code != 200:
                continue
            data = r.json()
            run_write("""
                MATCH (c:CVE {id: $id})
                SET c.exploited_greynoise = true,
                    c.greynoise_classification = $cls,
                    c.greynoise_last_seen = $seen
            """, id=cve, cls=data.get("classification"), seen=data.get("last_seen"))
            count += 1
            polite_sleep(0.6)
    console.print(f"[green]GreyNoise enriched {count} CVEs")
    return count


def kev_summary() -> dict:
    from engine.graph import run_read
    rows = run_read("""
        MATCH (c:CVE) WHERE c.exploited_kev = true
        OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
        RETURN c.id AS id, c.cvss_score AS cvss, c.severity AS severity,
               c.exploited_kev_date AS added,
               c.exploited_known_ransom AS ransomware,
               collect(DISTINCT l.number) AS layers
        ORDER BY c.exploited_kev_date DESC LIMIT 100
    """)
    return {"count": len(rows), "cves": rows}


def main() -> None:
    p = argparse.ArgumentParser(description="Real-time exploit telemetry")
    p.add_argument("--kev-only", action="store_true")
    args = p.parse_args()
    ingest_kev()
    if not args.kev_only:
        ingest_greynoise()


if __name__ == "__main__":
    main()
