"""
Normalized Application data model + Neo4j upsert.

`Application` is distinct from `Package`:
  - `Package` is a code dependency (npm/PyPI/Maven entry inside a project)
  - `Application` is a deployed piece of software (browser extension,
    desktop binary, IDE plugin, MCP server, SaaS app, container image)

The two CAN be related (an Application USES_DEPENDENCY a Package), and a
single CVE can affect either.
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Literal

from .graph import session

Provenance = Literal["first_party", "third_party", "unknown"]
Category = Literal[
    "desktop_binary", "browser_ext", "ide_ext", "mcp_server",
    "saas", "cli_tool", "ml_model", "container_image", "library",
]


@dataclass
class Application:
    id: str                                # stable hash
    name: str                              # display name
    version: str | None = None
    publisher: str | None = None           # vendor / author / GitHub org
    homepage: str | None = None
    source_url: str | None = None          # download URL or repo URL
    category: Category = "desktop_binary"
    provenance: Provenance = "third_party"
    permissions: list[str] = field(default_factory=list)
    trust_signals: dict[str, Any] = field(default_factory=dict)
    trust_score: float = 0.0               # 0-100 (computed)
    raw: dict[str, Any] = field(default_factory=dict)


def make_id(*parts: str) -> str:
    return hashlib.sha1("|".join(p or "" for p in parts).encode("utf-8")).hexdigest()[:16]


def upsert(apps: list[Application]) -> int:
    if not apps:
        return 0
    import json as _json
    payload = []
    for a in apps:
        payload.append({
            "id": a.id, "name": a.name, "version": a.version,
            "publisher": a.publisher, "homepage": a.homepage,
            "source_url": a.source_url, "category": a.category,
            "provenance": a.provenance,
            "permissions": list(a.permissions or []),
            "trust_signals_json": _json.dumps(a.trust_signals or {}),
            "trust_score": float(a.trust_score),
        })
    cypher = """
    UNWIND $items AS app
        MERGE (a:Application {id: app.id})
        SET a.name        = app.name,
            a.version     = app.version,
            a.publisher   = app.publisher,
            a.homepage    = app.homepage,
            a.source_url  = app.source_url,
            a.category    = app.category,
            a.provenance  = app.provenance,
            a.permissions = app.permissions,
            a.trust_signals_json = app.trust_signals_json,
            a.trust_score = app.trust_score,
            a.last_ingested = datetime()
    """
    with session() as s:
        s.run(cypher, items=payload)
    return len(payload)


def link_dependency(app_id: str, package_purl: str) -> None:
    cypher = """
    MATCH (a:Application {id: $app_id})
    MATCH (p:Package {purl: $purl})
    MERGE (a)-[:USES_DEPENDENCY]->(p)
    """
    with session() as s:
        s.run(cypher, app_id=app_id, purl=package_purl)


def link_cve(cve_id: str, app_id: str) -> None:
    cypher = """
    MATCH (c:CVE {id: $cve_id})
    MATCH (a:Application {id: $app_id})
    MERGE (c)-[:AFFECTS]->(a)
    """
    with session() as s:
        s.run(cypher, cve_id=cve_id.upper(), app_id=app_id)
