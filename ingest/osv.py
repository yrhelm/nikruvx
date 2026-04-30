"""
OSV.dev ingester
================
OSV.dev is the unified vulnerability DB across npm, PyPI, Maven, Go, RubyGems,
crates.io, Debian, Alpine, NuGet, etc.

We use the V1 query API:
  POST https://api.osv.dev/v1/querybatch  (batch lookups)
  GET  https://api.osv.dev/v1/vulns/<id>  (single)

Strategy here:
  1. For each ecosystem, pull a small set of "popular" packages and fetch all
     OSV records that affect them (this gives us instant CVE↔package mapping).
  2. For each OSV record:
       - Upsert/Merge CVE node with description + severity
       - Upsert Package node + AFFECTS edge with version ranges
       - Link CWEs (database_specific often has them)

Usage:
  python -m ingest.osv --ecosystem npm --packages express lodash
  python -m ingest.osv --seed
"""
from __future__ import annotations
import argparse
from rich.progress import Progress

from .common import http_client, upsert_cve, link_cve_package, console, polite_sleep

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN  = "https://api.osv.dev/v1/vulns"

# A small curated seed list - real users can extend or pipe in their own SBOM.
SEED_PACKAGES: dict[str, list[str]] = {
    "npm":      ["express", "lodash", "axios", "react", "next", "vue", "tar", "minimist", "node-fetch", "ws"],
    "PyPI":     ["django", "flask", "requests", "pyyaml", "numpy", "pillow", "cryptography", "fastapi", "tensorflow", "torch", "transformers", "langchain"],
    "Maven":    ["org.springframework:spring-core", "com.fasterxml.jackson.core:jackson-databind", "org.apache.logging.log4j:log4j-core", "org.apache.tomcat:tomcat-catalina"],
    "Go":       ["github.com/gin-gonic/gin", "github.com/gorilla/websocket", "github.com/labstack/echo"],
    "RubyGems": ["rails", "nokogiri", "rack", "devise"],
    "crates.io":["tokio", "serde", "actix-web", "openssl"],
    "Debian":   ["openssl", "openssh-server", "bind9", "sudo"],
    "Alpine":   ["openssl", "musl", "busybox"],
}


def _cwes_from_record(rec: dict) -> list[str]:
    out: list[str] = []
    db = rec.get("database_specific") or {}
    for c in db.get("cwe_ids", []) or []:
        out.append(c if c.upper().startswith("CWE-") else f"CWE-{c}")
    # GHSA records embed CWEs under the ghsa db_specific section
    for ref in rec.get("references", []):
        # Some records put CWEs in tags
        pass
    return list(dict.fromkeys(out))


def _cve_id_from_record(rec: dict) -> str | None:
    # Prefer CVE alias; fall back to OSV id
    for alias in rec.get("aliases", []) or []:
        if alias.startswith("CVE-"):
            return alias
    if rec.get("id", "").startswith("CVE-"):
        return rec["id"]
    return None


def _cvss_from_record(rec: dict) -> tuple[float | None, str | None]:
    for sev in rec.get("severity", []) or []:
        if sev.get("type") in ("CVSS_V3", "CVSS_V31", "CVSS_V40"):
            score_field = sev.get("score")
            if score_field is None:
                continue
            # Some records put the numeric score directly; most put the vector.
            try:
                return float(score_field), None
            except (TypeError, ValueError):
                pass
            return _base_score(score_field), score_field
    return None, None


def _base_score(vector: str | None) -> float | None:
    """Compute CVSS v3.x base score from a vector string.

    Returns None for unparseable input or v2/v4 vectors. Implements the
    canonical FIRST.org formula (Specification §7.1) so we don't need
    a third-party dependency. v4 is currently passed through as None
    (different metrics; not yet supported here).
    """
    if not vector or not isinstance(vector, str):
        return None
    v = vector.strip()
    if not v.upper().startswith("CVSS:3"):
        return None
    parts = {}
    try:
        for token in v.split("/")[1:]:
            k, _, val = token.partition(":")
            if k and val:
                parts[k.strip().upper()] = val.strip().upper()
    except Exception:
        return None

    # Required base metrics
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in parts for k in required):
        return None

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts["AV"])
    ac = {"L": 0.77, "H": 0.44}.get(parts["AC"])
    ui = {"N": 0.85, "R": 0.62}.get(parts["UI"])
    scope_changed = parts["S"] == "C"
    pr_table = {
        "N": 0.85,
        "L": 0.68 if scope_changed else 0.62,
        "H": 0.50 if scope_changed else 0.27,
    }
    pr = pr_table.get(parts["PR"])
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    c, i, a = cia.get(parts["C"]), cia.get(parts["I"]), cia.get(parts["A"])
    if None in (av, ac, ui, pr, c, i, a):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    # CVSS round-up to nearest 0.1
    import math
    return math.ceil(base * 10) / 10


def query_package(ecosystem: str, name: str) -> list[dict]:
    payload = {"package": {"ecosystem": ecosystem, "name": name}}
    with http_client() as c:
        r = c.post(OSV_QUERY, json=payload)
        if r.status_code != 200:
            console.print(f"[yellow]OSV {r.status_code} for {ecosystem}:{name}")
            return []
        return r.json().get("vulns", [])


def fetch_full(vuln_id: str) -> dict | None:
    with http_client() as c:
        r = c.get(f"{OSV_VULN}/{vuln_id}")
        if r.status_code != 200:
            return None
        return r.json()


def ingest_package(ecosystem: str, name: str) -> int:
    """Pull every OSV record affecting this package and load into Neo4j."""
    refs = query_package(ecosystem, name)
    count = 0
    for stub in refs:
        full = fetch_full(stub["id"]) or stub
        cve_id = _cve_id_from_record(full)
        if not cve_id:
            continue
        cvss_score, cvss_vector = _cvss_from_record(full)
        cwes = _cwes_from_record(full)
        description = full.get("details") or full.get("summary") or ""
        upsert_cve(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            published=full.get("published"),
            modified=full.get("modified"),
            cwe_ids=cwes,
            references=[r["url"] for r in (full.get("references") or []) if r.get("url")],
        )
        # Pull affected version ranges
        affected_versions: list[str] = []
        fixed_versions: list[str] = []
        for aff in full.get("affected", []) or []:
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != ecosystem or pkg.get("name") != name:
                continue
            for r in aff.get("ranges", []) or []:
                for ev in r.get("events", []) or []:
                    if "introduced" in ev: affected_versions.append(f">={ev['introduced']}")
                    if "fixed" in ev:      fixed_versions.append(ev["fixed"])
            for v in aff.get("versions", []) or []:
                affected_versions.append(v)
        link_cve_package(cve_id, ecosystem, name, affected_versions, fixed_versions)
        count += 1
        polite_sleep(0.1)
    console.print(f"[green]OSV {ecosystem}:{name} -> {count} CVEs linked")
    return count


def seed_all() -> int:
    total = 0
    with Progress() as bar:
        for eco, pkgs in SEED_PACKAGES.items():
            t = bar.add_task(f"[cyan]OSV {eco}", total=len(pkgs))
            for p in pkgs:
                total += ingest_package(eco, p)
                bar.update(t, advance=1)
    console.print(f"[green]OSV seeded - total {total} CVE-package links")
    return total


def main() -> None:
    p = argparse.ArgumentParser(description="Ingest OSV.dev CVE-package mappings")
    p.add_argument("--ecosystem", help="npm | PyPI | Maven | Go | RubyGems | crates.io | Debian | Alpine")
    p.add_argument("--packages", nargs="+", help="Package names")
    p.add_argument("--seed", action="store_true", help="Use built-in seed list")
    args = p.parse_args()
    if args.seed or (not args.ecosystem and not args.packages):
        seed_all()
    else:
        for name in (args.packages or []):
            ingest_package(args.ecosystem, name)


if __name__ == "__main__":
    main()
