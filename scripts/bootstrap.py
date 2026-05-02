"""
Bootstrap the Cybersecurity Nexus database.

Run:
    python scripts/bootstrap.py

Steps performed:
    1. Apply graph schema (constraints + OSI layer seed)
    2. Ingest a curated set of marquee CVEs (so the UI is interesting from minute one)
    3. Ingest MITRE CWE catalog (full)
    4. Ingest OSV.dev seed packages (npm/PyPI/Maven/Go/RubyGems/crates/Debian/Alpine)
    5. Ingest GHSA last 5 pages
    6. Ingest AI threat catalog (ATLAS + OWASP LLM Top 10)
    7. Extract PoCs for the top 25 critical CVEs

Tip: set NVD_API_KEY in .env to dramatically speed up step 2 (free, takes 1 min:
     https://nvd.nist.gov/developers/request-an-api-key).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Make the project root importable when run directly
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console

from config import settings
from engine.graph import apply_schema
from ingest import ai_threats, cwe, ghsa, nvd, osv, poc

console = Console()
# NVD rate limit: 5 req per 30s without a key, 50 per 30s with one.
NVD_PAUSE = 0.8 if settings.nvd_api_key else 6.5

# A handful of high-impact, well-known CVEs to seed the graph.
SEED_CVES = [
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-45046",  # Log4j follow-up
    "CVE-2024-3094",  # xz backdoor
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2017-5638",  # Struts2 (Equifax)
    "CVE-2014-0160",  # Heartbleed
    "CVE-2014-6271",  # Shellshock
    "CVE-2019-0708",  # BlueKeep
    "CVE-2020-1472",  # Zerologon
    "CVE-2022-26134",  # Confluence OGNL
    "CVE-2023-46604",  # ActiveMQ deserialization
    "CVE-2023-29374",  # LangChain SQL injection (AI)
    "CVE-2024-21626",  # runc container escape
    "CVE-2023-50164",  # Struts file upload
]


def main() -> None:
    console.rule("[bold cyan]Cybersecurity Nexus - bootstrap[/bold cyan]")

    console.print("[1/7] Applying graph schema...")
    apply_schema()

    console.print(
        f"[2/7] Seeding {len(SEED_CVES)} marquee CVEs from NVD "
        f"(pacing {NVD_PAUSE:.1f}s; set NVD_API_KEY in .env for ~10x faster)..."
    )
    for i, cid in enumerate(SEED_CVES, 1):
        try:
            nvd.ingest_one(cid)
        except Exception as e:
            console.print(f"[yellow]  skipped {cid}: {e}")
        if i < len(SEED_CVES):
            time.sleep(NVD_PAUSE)

    console.print("[3/7] Ingesting MITRE CWE catalog...")
    try:
        cwe.ingest()
    except Exception as e:
        console.print(f"[yellow]  CWE ingest failed: {e}")

    console.print("[4/7] Ingesting OSV.dev seed packages...")
    try:
        osv.seed_all()
    except Exception as e:
        console.print(f"[yellow]  OSV seed failed: {e}")

    console.print("[5/7] Ingesting GHSA advisories (5 pages)...")
    try:
        ghsa.ingest_pages(pages=5)
    except Exception as e:
        console.print(f"[yellow]  GHSA failed: {e}")

    console.print("[6/7] Ingesting AI threat catalog...")
    try:
        ai_threats.ingest(refresh=False)
    except Exception as e:
        console.print(f"[yellow]  AI threats failed: {e}")

    console.print("[7/7] Extracting PoCs for top critical CVEs...")
    try:
        for cid in SEED_CVES:
            poc.extract_for(cid)
        for missing in poc.find_missing(limit=15):
            poc.extract_for(missing)
    except Exception as e:
        console.print(f"[yellow]  PoC extraction failed: {e}")

    console.rule("[bold green]Bootstrap complete[/bold green]")
    console.print("Start the API:   python -m api.server")
    console.print("Open the UI:     http://127.0.0.1:8000/")


if __name__ == "__main__":
    main()
