"""Persist normalized Policy + Control objects into the Neo4j graph."""

from __future__ import annotations

import json

from engine.graph import session
from engine.policy_model import Policy


def upsert_policies(policies: list[Policy]) -> int:
    if not policies:
        return 0
    payload = []
    for p in policies:
        payload.append(
            {
                "id": p.id,
                "source": p.source,
                "type": p.type,
                "name": p.name,
                "scope_json": json.dumps(p.scope or {}),
                "controls": [
                    {
                        "id": c.id,
                        "title": c.title,
                        "effect": c.effect,
                        "action": c.action,
                        "layer": c.layer,
                        "capability_classes": list(c.capability_classes or []),
                        "capabilities_mitigated": list(c.capabilities_mitigated or []),
                        "scope_json": json.dumps(c.scope or {}),
                        "lineno": c.source_lineno,
                    }
                    for c in p.controls
                ],
            }
        )

    cypher = """
    UNWIND $policies AS pol
        MERGE (p:Policy {id: pol.id})
        SET p.source = pol.source, p.type = pol.type, p.name = pol.name,
            p.scope_json = pol.scope_json,
            p.last_ingested = datetime()
        WITH p, pol
        UNWIND pol.controls AS ctrl
            MERGE (c:Control {id: ctrl.id})
            SET c.title  = ctrl.title,
                c.effect = ctrl.effect,
                c.action = ctrl.action,
                c.layer  = ctrl.layer,
                c.capability_classes = ctrl.capability_classes,
                c.capabilities_mitigated = ctrl.capabilities_mitigated,
                c.scope_json = ctrl.scope_json,
                c.lineno = ctrl.lineno,
                c.last_ingested = datetime()
            MERGE (p)-[:CONTAINS]->(c)
            WITH c, ctrl
            OPTIONAL MATCH (l:OSILayer {number: ctrl.layer})
            FOREACH (_ IN CASE WHEN l IS NULL THEN [] ELSE [1] END |
                MERGE (c)-[:APPLIES_AT]->(l)
            )
    """
    with session() as s:
        s.run(cypher, policies=payload)
    return len(payload)
