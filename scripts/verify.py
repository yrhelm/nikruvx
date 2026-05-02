"""
Quick smoke-test for the Cybersecurity Nexus.

Verifies:
  - Neo4j connectivity
  - Schema applied (OSI layers seeded)
  - Engines (OSI classifier + risk scoring) produce sane output
  - Ingester modules import cleanly

Run:  python scripts/verify.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console

console = Console()
ok = lambda s: console.print(f"[green]✓[/] {s}")
err = lambda s: console.print(f"[red]✗[/] {s}")


def main() -> int:
    failures = 0

    # 1) Engines (no DB required)
    try:
        from engine.osi_classifier import classify

        hits = classify(
            "SQL injection allows remote code execution via deserialization", ["CWE-89", "CWE-502"]
        )
        layers = [h["layer"] for h in hits]
        assert 7 in layers and 6 in layers, f"expected L6+L7, got {layers}"
        ok(f"OSI classifier returns {layers}")
    except Exception as e:
        err(f"OSI classifier: {e}")
        failures += 1

    try:
        from engine.risk_scoring import RiskInput, score

        r = score(
            RiskInput(
                cvss_score=9.8,
                cwe_ids=["CWE-502"],
                osi_layers=[6, 7],
                poc_count=2,
                package_count=12,
                published="2024-12-01T00:00:00Z",
            )
        )
        assert 70 <= r.score <= 100, f"expected high score, got {r.score}"
        ok(f"Risk engine returns score={r.score} band={r.band}")
    except Exception as e:
        err(f"Risk scoring: {e}")
        failures += 1

    # 2) Ingester imports
    for mod in (
        "ingest.nvd",
        "ingest.cwe",
        "ingest.osv",
        "ingest.ghsa",
        "ingest.poc",
        "ingest.ai_threats",
    ):
        try:
            __import__(mod)
            ok(f"Imported {mod}")
        except Exception as e:
            err(f"Import {mod}: {e}")
            failures += 1

    # 3) Neo4j
    try:
        from engine.graph import get_driver, run_read

        get_driver().verify_connectivity()
        ok("Neo4j connectivity")
        rows = run_read("MATCH (l:OSILayer) RETURN count(l) AS n")
        n = rows[0]["n"] if rows else 0
        if n != 7:
            err(f"OSILayer nodes = {n} (expected 7) — run schema first")
            failures += 1
        else:
            ok("7 OSI layers present")
        for label in ("CVE", "CWE", "Package", "AIThreat", "PoC"):
            rows = run_read(f"MATCH (n:{label}) RETURN count(n) AS n")
            console.print(f"   {label}: {rows[0]['n']}")
    except Exception as e:
        err(f"Neo4j: {e} — is `docker compose up -d` running?")
        failures += 1

    if failures:
        console.print(f"\n[red]{failures} check(s) failed[/red]")
        return 1
    console.print("\n[green]All checks passed[/green]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
