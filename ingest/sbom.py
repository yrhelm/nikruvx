"""
SBOM Ingester
=============
Parse a Software Bill of Materials in any common format, look every component
up in the Cyber Nexus graph, auto-fetch unknown components from OSV.dev, and
return a complete attack-surface snapshot:

    * matched components with their CVEs
    * org-wide aggregate Nexus risk score
    * per-OSI-layer breakdown
    * top 5 cross-layer attack chains for this stack

Supported formats (auto-detected by content/filename):
    - npm package.json  / package-lock.json
    - Python requirements.txt
    - Maven pom.xml (light parsing)
    - Go go.mod
    - Ruby Gemfile.lock
    - Rust Cargo.lock
    - CycloneDX JSON (any ecosystem)
    - SPDX JSON (any ecosystem)

Usage:
    from ingest.sbom import scan
    result = scan(file_bytes, filename="package.json")
"""
from __future__ import annotations
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from typing import Iterable

from rich.console import Console

from engine.graph import run_read
from engine.attack_chain import chains_for_packages
from engine.risk_scoring import RiskInput, score as nexus_score
from .osv import ingest_package as osv_ingest_package

console = Console()


# ---------------------------------------------------------------------------
# Format detection + parsers
# ---------------------------------------------------------------------------
def _detect(filename: str, content: str) -> str:
    name = (filename or "").lower()
    if name.endswith("package.json") or '"dependencies"' in content[:500]:
        return "npm"
    if name.endswith("package-lock.json"):
        return "npm-lock"
    if name.endswith(("requirements.txt", "requirements-dev.txt")):
        return "pypi"
    if name.endswith("pyproject.toml"):
        return "pypi-toml"
    if name.endswith("pom.xml"):
        return "maven"
    if name.endswith("go.mod"):
        return "go"
    if name.endswith("gemfile.lock"):
        return "rubygems"
    if name.endswith("cargo.lock"):
        return "cargo"
    # Heuristic JSON detection
    if content.strip().startswith("{"):
        if '"bomFormat"' in content[:1024] and '"CycloneDX"' in content[:1024]:
            return "cyclonedx"
        if '"spdxVersion"' in content[:1024]:
            return "spdx"
    return "unknown"


def _parse_npm(content: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    try:
        data = json.loads(content)
    except Exception:
        return out
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, ver in (data.get(section) or {}).items():
            out.append(("npm", name, str(ver).lstrip("^~>=<! ") or None))
    return out


def _parse_npm_lock(content: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    try:
        data = json.loads(content)
    except Exception:
        return out
    # v2/v3 lockfile
    for path, info in (data.get("packages") or {}).items():
        if not path or not isinstance(info, dict):
            continue
        # path is "node_modules/foo" or "node_modules/foo/node_modules/bar"
        m = re.search(r"node_modules/((?:@[^/]+/)?[^/]+)$", path)
        name = m.group(1) if m else info.get("name")
        ver = info.get("version")
        if name and ver:
            out.append(("npm", name, ver))
    # v1 lockfile fallback
    def _walk(d: dict) -> None:
        for n, sub in (d.get("dependencies") or {}).items():
            if isinstance(sub, dict):
                if sub.get("version"):
                    out.append(("npm", n, sub["version"]))
                _walk(sub)
    _walk(data)
    return out


def _parse_pypi(content: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        # Strip extras: foo[bar]==1.2 -> foo
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:==|>=|~=|!=|<|>)?\s*([0-9A-Za-z.\-+]*)?", line)
        if not m:
            continue
        name = m.group(1)
        ver = m.group(2) or None
        out.append(("PyPI", name, ver))
    return out


def _parse_maven(content: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    try:
        # strip namespace declarations to make XPath simpler
        cleaned = re.sub(r'\sxmlns(:\w+)?="[^"]+"', "", content, count=1)
        root = ET.fromstring(cleaned)
        for d in root.iterfind(".//dependency"):
            gid = (d.findtext("groupId") or "").strip()
            aid = (d.findtext("artifactId") or "").strip()
            ver = (d.findtext("version") or "").strip() or None
            if gid and aid:
                out.append(("Maven", f"{gid}:{aid}", ver))
    except Exception as e:
        console.print(f"[yellow]Maven parse error: {e}")
    return out


def _parse_go(content: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    in_block = False
    for line in content.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True; continue
        if in_block and s == ")":
            in_block = False; continue
        if in_block or s.startswith("require "):
            m = re.match(r"(?:require\s+)?([\w\-./]+)\s+([\w\-.+]+)", s)
            if m:
                out.append(("Go", m.group(1), m.group(2)))
    return out


def _parse_gemfile(content: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    for line in content.splitlines():
        m = re.match(r"\s+([\w\-]+)\s+\(([\w\-.+]+)\)", line)
        if m:
            out.append(("RubyGems", m.group(1), m.group(2)))
    return out


def _parse_cargo(content: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    # Cargo.lock entries look like:  name = "foo"\n version = "1.2.3"
    blocks = content.split("[[package]]")
    for b in blocks[1:]:
        n = re.search(r'name\s*=\s*"([^"]+)"', b)
        v = re.search(r'version\s*=\s*"([^"]+)"', b)
        if n:
            out.append(("crates.io", n.group(1), v.group(1) if v else None))
    return out


def _parse_cyclonedx(content: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    try:
        data = json.loads(content)
    except Exception:
        return out
    for c in data.get("components", []):
        purl = c.get("purl") or ""
        m = re.match(r"pkg:(\w+)/(?:([^/@]+)/)?([^@]+)@?([^?]*)?", purl)
        if m:
            eco_raw = m.group(1).lower()
            ecosystem = {"npm":"npm","pypi":"PyPI","maven":"Maven","golang":"Go",
                         "gem":"RubyGems","cargo":"crates.io","deb":"Debian","apk":"Alpine"}.get(eco_raw, eco_raw)
            ns = m.group(2)
            name = m.group(3)
            ver = m.group(4) or c.get("version")
            full = f"{ns}/{name}" if ns and ecosystem == "Go" else (f"{ns}:{name}" if ns and ecosystem == "Maven" else name)
            out.append((ecosystem, full, ver))
        elif c.get("name"):
            out.append((c.get("type", "unknown"), c["name"], c.get("version")))
    return out


def _parse_spdx(content: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    try:
        data = json.loads(content)
    except Exception:
        return out
    for p in data.get("packages", []):
        for ref in p.get("externalRefs", []) or []:
            loc = ref.get("referenceLocator", "")
            if loc.startswith("pkg:"):
                # Reuse cyclonedx purl parser
                tmp = json.dumps({"components": [{"purl": loc, "version": p.get("versionInfo")}]})
                out.extend(_parse_cyclonedx(tmp))
                break
    return out


PARSERS = {
    "npm": _parse_npm, "npm-lock": _parse_npm_lock, "pypi": _parse_pypi,
    "maven": _parse_maven, "go": _parse_go, "rubygems": _parse_gemfile,
    "cargo": _parse_cargo, "cyclonedx": _parse_cyclonedx, "spdx": _parse_spdx,
}


# ---------------------------------------------------------------------------
# Graph lookup + aggregate
# ---------------------------------------------------------------------------
def _purl(eco: str, name: str) -> str:
    return f"pkg:{eco.lower()}/{name}"


def _lookup(components: list[tuple[str, str, str | None]]) -> dict:
    """For each component, return matching CVEs from the graph."""
    purls = list({_purl(e, n) for e, n, _ in components})
    rows = run_read("""
        MATCH (p:Package)
        WHERE p.purl IN $purls
        OPTIONAL MATCH (p)<-[r:AFFECTS]-(c:CVE)
        OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
        OPTIONAL MATCH (c)-[:HAS_POC]->(po:PoC)
        RETURN p.purl AS purl, p.ecosystem AS eco, p.name AS name,
               c.id AS cve, c.cvss_score AS cvss, c.severity AS severity,
               c.published AS published,
               collect(DISTINCT w.id) AS cwes,
               collect(DISTINCT l.number) AS layers,
               count(DISTINCT po) AS poc_count
    """, purls=purls)
    return rows


def scan(content: bytes | str, filename: str = "") -> dict:
    """Main entry. Returns full attack-surface snapshot."""
    if isinstance(content, bytes):
        try: content = content.decode("utf-8")
        except UnicodeDecodeError: content = content.decode("latin-1", errors="ignore")
    fmt = _detect(filename, content)
    parser = PARSERS.get(fmt)
    if parser is None:
        return {"error": f"Unrecognized SBOM format. filename={filename}, hint={content[:80]!r}"}
    components = parser(content)
    if not components:
        return {"error": "No components parsed", "format": fmt}

    console.print(f"[cyan]SBOM detected as {fmt}, {len(components)} components")

    # Auto-ingest unknown packages from OSV (limit to avoid hammering)
    purl_set = {_purl(e, n) for e, n, _ in components}
    known_rows = run_read("""
        MATCH (p:Package) WHERE p.purl IN $purls RETURN p.purl AS purl
    """, purls=list(purl_set))
    known = {r["purl"] for r in known_rows}
    missing = [(e, n) for e, n, _ in components if _purl(e, n) not in known]
    if missing:
        # Cap auto-ingest at 30 to keep response time reasonable
        for eco, name in missing[:30]:
            try:
                osv_ingest_package(eco, name)
            except Exception as e:
                console.print(f"[yellow]  OSV {eco}:{name} fail: {e}")

    # Now gather everything we know
    rows = _lookup(components)

    by_purl: dict[str, dict] = {}
    layer_counter: Counter[int] = Counter()
    severity_counter: Counter[str] = Counter()
    cve_set: set[str] = set()
    cve_metrics: list[RiskInput] = []
    package_count = 0

    for r in rows:
        entry = by_purl.setdefault(r["purl"], {
            "ecosystem": r["eco"], "name": r["name"], "purl": r["purl"], "cves": [],
        })
        if not r["cve"]:
            continue
        if r["cve"] not in cve_set:
            cve_set.add(r["cve"])
            cve_metrics.append(RiskInput(
                cvss_score=r["cvss"], cwe_ids=[c for c in r["cwes"] if c],
                osi_layers=[l for l in r["layers"] if l], poc_count=r["poc_count"],
                package_count=1, published=r["published"],
            ))
        entry["cves"].append({
            "id": r["cve"], "cvss": r["cvss"], "severity": r["severity"],
            "cwes": [c for c in r["cwes"] if c],
            "layers": [l for l in r["layers"] if l],
            "poc_count": r["poc_count"],
        })
        for l in r["layers"] or []:
            if l: layer_counter[l] += 1
        if r["severity"]:
            severity_counter[r["severity"]] += 1
    package_count = len(by_purl)

    # Aggregate score: 75th-percentile of individual scores (resists single-noise)
    individual_scores = [nexus_score(m).score for m in cve_metrics]
    individual_scores.sort()
    aggregate = 0.0
    if individual_scores:
        idx = max(0, int(len(individual_scores) * 0.75) - 1)
        p75 = individual_scores[idx]
        # Pump it up by stack size + CVE count (more deps = bigger surface)
        aggregate = min(100.0, p75 + 0.05 * len(cve_metrics) + 0.4 * package_count ** 0.5)

    # Top attack chains starting from this stack
    try:
        chains = chains_for_packages(list(purl_set), per_seed=1)
    except Exception as e:
        console.print(f"[yellow]chain build failed: {e}")
        chains = []

    return {
        "format": fmt,
        "component_count": len(components),
        "matched_packages": package_count,
        "cve_count": len(cve_set),
        "severity_breakdown": dict(severity_counter),
        "layer_breakdown": {f"L{k}": v for k, v in sorted(layer_counter.items())},
        "aggregate_score": round(aggregate, 2),
        "aggregate_band": _band(aggregate),
        "packages": list(by_purl.values()),
        "attack_chains": chains,
    }


def _band(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"
