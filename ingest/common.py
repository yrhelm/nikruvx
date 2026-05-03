"""Shared utilities for ingesters."""
from __future__ import annotations
import time
from typing import Any
import httpx
from rich.console import Console

from config import settings
from engine.graph import session
from engine.osi_classifier import classify

console = Console()

USER_AGENT = "CyberNexus/1.0 (+local)"


def http_client(timeout: float = 30.0, headers: dict | None = None) -> httpx.Client:
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        h.update(headers)
    return httpx.Client(timeout=timeout, headers=h, follow_redirects=True)


def _severity_from_cvss(score: float | None) -> str:
    if score is None: return "UNKNOWN"
    if score >= 9: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 4: return "MEDIUM"
    if score > 0: return "LOW"
    return "NONE"


def upsert_cve(
    cve_id: str,
    description: str,
    cvss_score: float | None,
    cvss_vector: str | None,
    published: str | None,
    modified: str | None,
    cwe_ids: list[str],
    references: list[str] | None = None,
) -> list[dict]:
    """Create/merge a CVE node, link to CWE nodes, and map to OSI layers."""
    severity = _severity_from_cvss(cvss_score)
    osi = classify(description or "", cwe_ids)
    osi_numbers = [hit["layer"] for hit in osi]

    cypher = """
    MERGE (c:CVE {id: $cve_id})
    SET c.description = coalesce($description, c.description),
        c.cvss_score  = coalesce($cvss_score, c.cvss_score),
        c.cvss_vector = coalesce($cvss_vector, c.cvss_vector),
        c.severity    = $severity,
        c.published   = coalesce($published, c.published),
        c.modified    = coalesce($modified, c.modified),
        c.references  = coalesce($references, c.references),
        c.last_ingested = datetime()
    WITH c
    UNWIND $cwe_ids AS cwe_id
        MERGE (w:CWE {id: cwe_id})
        MERGE (c)-[:CLASSIFIED_AS]->(w)
    WITH c
    UNWIND $osi_layers AS layer_num
        MATCH (l:OSILayer {number: layer_num})
        MERGE (c)-[r:MAPS_TO]->(l)
    RETURN c.id AS id
    """
    with session() as s:
        s.run(
            cypher,
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            published=published,
            modified=modified,
            references=references or [],
            cwe_ids=cwe_ids,
            osi_layers=osi_numbers,
        )
    return osi


def upsert_package(ecosystem: str, name: str, purl: str | None = None) -> str:
    purl = purl or f"pkg:{ecosystem.lower()}/{name}"
    cypher = """
    MERGE (p:Package {purl: $purl})
    SET p.ecosystem = $ecosystem, p.name = $name
    RETURN p.purl AS purl
    """
    with session() as s:
        s.run(cypher, purl=purl, ecosystem=ecosystem, name=name)
    return purl


def link_cve_package(
    cve_id: str,
    ecosystem: str,
    package_name: str,
    affected_versions: list[str] | None = None,
    fixed_versions: list[str] | None = None,
) -> None:
    purl = upsert_package(ecosystem, package_name)
    cypher = """
    MATCH (c:CVE {id: $cve_id})
    MATCH (p:Package {purl: $purl})
    MERGE (c)-[r:AFFECTS]->(p)
    SET r.affected_versions = $affected,
        r.fixed_versions    = $fixed
    """
    with session() as s:
        s.run(
            cypher,
            cve_id=cve_id,
            purl=purl,
            affected=affected_versions or [],
            fixed=fixed_versions or [],
        )


def attach_poc(cve_id: str, url: str, source: str, language: str | None = None,
               snippet: str | None = None) -> None:
    cypher = """
    MERGE (p:PoC {url: $url})
    SET p.source = $source, p.language = $language, p.snippet = $snippet,
        p.fetched = datetime()
    WITH p
    MATCH (c:CVE {id: $cve_id})
    MERGE (c)-[:HAS_POC]->(p)
    """
    with session() as s:
        s.run(cypher, url=url, source=source, language=language, snippet=snippet, cve_id=cve_id)


def polite_sleep(seconds: float = 0.6) -> None:
    time.sleep(seconds)
