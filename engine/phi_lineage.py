"""
PHI Lineage tracer
==================
Graph-native record of PHI flow across the AI stack.

Each LLM call becomes a path:
    (PHISource)-[:FED]->(Prompt)-[:CONTAINS]->(PHIElement)
    (Actor)-[:ISSUED]->(Prompt)-[:WITHIN]->(LineageSession)
    (Prompt)-[:SENT_VIA]->(Application)-[:CALLS]->(AIModel)
                  -[:HOSTED_BY]->(AIVendor)-[:OPERATES_IN]->(Region)
    (AIModel)-[:RETURNED]->(Response)-[:CONTAINS]->(PHIElement)
                                     -[:LOGGED_IN]->(Sink)
                                     -[:STORED_IN]->(Region)
                                     -[:GOVERNED_BY]->(RetentionPolicy)
    (BAA)-[:COVERS]->(AIVendor)
    (BAA)-[:INCLUDES_TERM]->(BAATerm)

Every movement edge carries:
    ts, evidence_grade ('OBSERVED' | 'ATTESTED' | 'DECLARED' | 'INFERRED'),
    evidence_ref (sha256 / url / contract section), confidence (0-100).

Raw PHI text is NEVER stored. Only counts per identifier_type.

Three flagship operations:
    record_call()             - persist a single call (used by every ingester)
    find_broken_baa_chains    - audit query: PHI flows missing/violating BAA
    replay_incident           - given a prompt_id, return the full hop list
"""
from __future__ import annotations
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .graph import run_read, run_write
from .phi_detector import summarize

EvidenceGrade = str  # 'OBSERVED' | 'ATTESTED' | 'DECLARED' | 'INFERRED'


# Canonical BAA term IDs — mirror policy_capabilities CONTROL_CLASSES
# (term_id, clause description, citation)
CANONICAL_BAA_TERMS: list[tuple[str, str, str]] = [
    ("encryption_at_rest",      "Encryption of PHI at rest (AES-256+)",                 "45 CFR §164.312(a)(2)(iv)"),
    ("encryption_in_transit",   "TLS 1.2+ for all PHI in transit",                      "45 CFR §164.312(e)(1)"),
    ("us_only_region",          "Processing locked to US regions",                      "BAA contract / data residency"),
    ("no_training_use",         "PHI excluded from model training / fine-tuning",       "BAA contract / 45 CFR §164.502(b)"),
    ("zero_retention",          "Vendor zero-retention mode (or <= 30 days)",           "BAA contract"),
    ("audit_logging",           "Vendor produces auditable access logs",                "45 CFR §164.312(b)"),
    ("subprocessor_disclosure", "Sub-processor list disclosed and approved",            "45 CFR §164.504(e)(2)(ii)(D)"),
    ("breach_notification",     "Vendor agrees to <= 60-day breach notification",       "45 CFR §164.410"),
    ("baa_signed",              "BAA executed and current",                             "45 CFR §164.504(e)"),
    ("minimum_necessary",       "Vendor handles only minimum-necessary PHI",            "45 CFR §164.502(b)"),
    ("right_to_delete",         "Vendor supports patient-record deletion / unlearning", "GDPR Art.17 / state law"),
    ("hitech_audit",            "HITECH Act audit-trail retention (>= 6 years)",        "45 CFR §164.316"),
]

REQUIRED_TERMS_FOR_PHI: list[str] = [
    "baa_signed",
    "encryption_at_rest",
    "encryption_in_transit",
    "us_only_region",
    "no_training_use",
    "zero_retention",
]


@dataclass
class CallEvent:
    """Normalized envelope every ingester produces."""
    prompt_text: str
    response_text: str = ""
    actor_id: str = "unknown"               # 'clinician:doe@hosp.org', 'agent:scribe-bot'
    session_id: str | None = None
    application_id: str | None = None       # links to existing :Application
    application_name: str = "unknown-app"
    model_id: str = ""                      # e.g. 'openai:gpt-4o-2024-11-20'
    model_name: str = ""
    vendor_id: str = ""                     # e.g. 'openai'
    vendor_name: str = ""
    region_code: str = ""                   # e.g. 'us-east-1'
    sinks: list[dict[str, Any]] = field(default_factory=list)
    # sinks: [{"id": "openai-prompt-cache", "kind": "cache", "encrypted": true, ...}]
    source_id: str = ""                     # e.g. 'epic-emr-prod'
    source_name: str = "unknown-source"
    ts: str = ""                            # ISO 8601; auto-set if blank
    evidence_grade: EvidenceGrade = "OBSERVED"
    evidence_ref: str = ""
    confidence: int = 100
    raw_payload_hash: str = ""              # sha256 over normalized payload


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_ids(ev: CallEvent) -> CallEvent:
    if not ev.ts:
        ev.ts = _now_iso()
    if not ev.session_id:
        ev.session_id = f"sess:{uuid.uuid4().hex[:12]}"
    if not ev.vendor_id and ev.vendor_name:
        ev.vendor_id = ev.vendor_name.lower().replace(" ", "-")
    if not ev.model_id:
        ev.model_id = f"{ev.vendor_id or 'unknown'}:{ev.model_name or 'unknown-model'}"
    if not ev.source_id:
        ev.source_id = ev.source_name.lower().replace(" ", "-")
    if not ev.raw_payload_hash:
        ev.raw_payload_hash = hashlib.sha256(
            (ev.prompt_text + "|" + ev.response_text).encode("utf-8", errors="replace")
        ).hexdigest()
    return ev


# ---------------------------------------------------------------------------
# Catalog upserts
# ---------------------------------------------------------------------------
def seed_baa_terms() -> int:
    """Idempotent seed of the canonical :BAATerm catalog."""
    cypher = """
    UNWIND $rows AS row
    MERGE (t:BAATerm {id: row.id})
      SET t.clause = row.clause,
          t.citation = row.citation,
          t.updated_at = datetime()
    """
    rows = [{"id": tid, "clause": clause, "citation": cite}
            for tid, clause, cite in CANONICAL_BAA_TERMS]
    run_write(cypher, rows=rows)
    return len(rows)


def register_vendor(
    *,
    vendor_id: str,
    name: str,
    region_code: str | None = None,
    subprocessors: Iterable[str] = (),
    operates_in_regions: Iterable[str] = (),
) -> None:
    """Upsert an :AIVendor and optional sub-processor edges."""
    regions = list(operates_in_regions) + ([region_code] if region_code else [])
    run_write(
        """
        MERGE (v:AIVendor {id: $vendor_id})
          SET v.name = $name,
              v.updated_at = datetime()
        WITH v
        UNWIND $regions AS rcode
        MERGE (r:Region {code: rcode})
        MERGE (v)-[:OPERATES_IN]->(r)
        """,
        vendor_id=vendor_id, name=name, regions=regions,
    )
    if subprocessors:
        run_write(
            """
            MATCH (v:AIVendor {id: $vendor_id})
            UNWIND $subs AS subId
            MERGE (sub:AIVendor {id: subId})
              ON CREATE SET sub.name = subId
            MERGE (v)-[:USES_SUBPROCESSOR]->(sub)
            """,
            vendor_id=vendor_id, subs=list(subprocessors),
        )


def register_baa(
    *,
    baa_id: str,
    counterparty_vendor_id: str,
    effective: str,
    expires: str,
    doc_hash: str = "",
    term_ids: Iterable[str] = (),
) -> None:
    """Upsert :BAA covering a vendor, with the list of terms it satisfies.

    `term_ids` should be a subset of CANONICAL_BAA_TERMS keys."""
    run_write(
        """
        MERGE (b:BAA {id: $baa_id})
          SET b.effective = $effective,
              b.expires = $expires,
              b.doc_hash = $doc_hash,
              b.updated_at = datetime()
        WITH b
        MATCH (v:AIVendor {id: $vendor_id})
        MERGE (b)-[:COVERS]->(v)
        WITH b
        UNWIND $terms AS tid
        MATCH (t:BAATerm {id: tid})
        MERGE (b)-[:INCLUDES_TERM]->(t)
        """,
        baa_id=baa_id, vendor_id=counterparty_vendor_id,
        effective=effective, expires=expires, doc_hash=doc_hash,
        terms=list(term_ids),
    )


# ---------------------------------------------------------------------------
# Core: record a call
# ---------------------------------------------------------------------------
def record_call(ev: CallEvent) -> dict:
    """Ingest one normalized call event. Returns ids + PHI summary."""
    ev = _ensure_ids(ev)

    prompt_phi = summarize(ev.prompt_text)
    response_phi = summarize(ev.response_text)
    prompt_id = f"prompt:{uuid.uuid4().hex[:16]}"
    response_id = f"resp:{uuid.uuid4().hex[:16]}"

    # We persist counts per identifier_type as separate :PHIElement nodes so
    # queries can group by type. We never store the raw text.
    elements: list[dict] = []
    for direction, summary_obj in (("prompt", prompt_phi), ("response", response_phi)):
        for det in summary_obj["detections"]:
            elements.append({
                "id": f"phi:{ev.raw_payload_hash[:16]}:{direction}:{det['identifier_type']}",
                "identifier_type": det["identifier_type"],
                "count": det["count"],
                "direction": direction,
            })

    cypher = """
    MERGE (src:PHISource {id: $source_id})
      SET src.name = $source_name
    MERGE (act:Actor {id: $actor_id})
      ON CREATE SET act.first_seen = datetime()
    MERGE (sess:LineageSession {id: $session_id})
      SET sess.last_seen = datetime()
    MERGE (app:Application {key: $application_key})
      ON CREATE SET app.name = $application_name,
                    app.first_seen = datetime()
    MERGE (m:AIModel {id: $model_id})
      SET m.name = $model_name,
          m.updated_at = datetime()
    MERGE (v:AIVendor {id: $vendor_id})
      SET v.name = $vendor_name
    MERGE (m)-[:HOSTED_BY]->(v)
    MERGE (reg:Region {code: $region_code})
    MERGE (v)-[:OPERATES_IN]->(reg)
    MERGE (p:Prompt {id: $prompt_id})
      SET p.ts = datetime($ts),
          p.payload_hash = $raw_payload_hash,
          p.evidence_grade = $evidence_grade
    MERGE (r:Response {id: $response_id})
      SET r.ts = datetime($ts),
          r.payload_hash = $raw_payload_hash
    MERGE (act)-[:ISSUED]->(p)
    MERGE (p)-[:WITHIN]->(sess)
    MERGE (p)-[se:SENT_VIA]->(app)
      SET se.ts = datetime($ts),
          se.evidence_grade = $evidence_grade,
          se.evidence_ref = $evidence_ref,
          se.confidence = $confidence
    MERGE (app)-[:CALLS]->(m)
    MERGE (m)-[ret:RETURNED]->(r)
      SET ret.ts = datetime($ts)
    MERGE (src)-[:FED]->(p)
    WITH p, r
    UNWIND $elements AS el
    MERGE (e:PHIElement {id: el.id})
      SET e.identifier_type = el.identifier_type,
          e.count = el.count,
          e.direction = el.direction,
          e.last_seen = datetime()
    FOREACH (_ IN CASE WHEN el.direction = 'prompt' THEN [1] ELSE [] END |
      MERGE (p)-[:CONTAINS]->(e)
    )
    FOREACH (_ IN CASE WHEN el.direction = 'response' THEN [1] ELSE [] END |
      MERGE (r)-[:CONTAINS]->(e)
    )
    """
    run_write(
        cypher,
        source_id=ev.source_id, source_name=ev.source_name,
        actor_id=ev.actor_id,
        session_id=ev.session_id,
        application_key=ev.application_id or ev.application_name,
        application_name=ev.application_name,
        model_id=ev.model_id, model_name=ev.model_name,
        vendor_id=ev.vendor_id or "unknown", vendor_name=ev.vendor_name or "unknown",
        region_code=ev.region_code or "unspecified",
        prompt_id=prompt_id, response_id=response_id,
        ts=ev.ts, raw_payload_hash=ev.raw_payload_hash,
        evidence_grade=ev.evidence_grade, evidence_ref=ev.evidence_ref,
        confidence=ev.confidence,
        elements=elements,
    )

    # Sinks are persisted as separate edges so we can attach evidence per sink.
    if ev.sinks:
        run_write(
            """
            MATCH (r:Response {id: $rid})
            UNWIND $sinks AS s
            MERGE (k:Sink {id: s.id})
              SET k.kind = coalesce(s.kind, 'unknown'),
                  k.encrypted = coalesce(s.encrypted, false),
                  k.public_access = coalesce(s.public_access, false)
            MERGE (r)-[lg:LOGGED_IN]->(k)
              SET lg.ts = datetime($ts),
                  lg.evidence_grade = coalesce(s.evidence_grade, 'INFERRED')
            FOREACH (_ IN CASE WHEN s.region IS NOT NULL THEN [1] ELSE [] END |
              MERGE (rr:Region {code: s.region})
              MERGE (k)-[:STORED_IN]->(rr)
            )
            FOREACH (_ IN CASE WHEN s.retention_days IS NOT NULL THEN [1] ELSE [] END |
              MERGE (rp:RetentionPolicy {id: 'days:' + toString(s.retention_days)})
                SET rp.days = s.retention_days
              MERGE (k)-[:GOVERNED_BY]->(rp)
            )
            """,
            rid=response_id, sinks=ev.sinks, ts=ev.ts,
        )

    return {
        "prompt_id": prompt_id,
        "response_id": response_id,
        "phi_in_prompt": prompt_phi,
        "phi_in_response": response_phi,
    }


# ---------------------------------------------------------------------------
# Audit + replay
# ---------------------------------------------------------------------------
def find_broken_baa_chains(window_hours: int = 24, limit: int = 200) -> list[dict]:
    """PHI prompts whose terminal vendor lacks a current BAA or whose BAA
    is missing required terms (baa_signed, encryption_at_rest,
    encryption_in_transit, us_only_region, no_training_use, zero_retention)."""
    cypher = """
    MATCH (p:Prompt)-[:CONTAINS]->(:PHIElement)
    WHERE p.ts > datetime() - duration({hours: $hours})
    MATCH (p)-[:SENT_VIA]->(:Application)-[:CALLS]->(m:AIModel)-[:HOSTED_BY]->(v:AIVendor)
    OPTIONAL MATCH (b:BAA)-[:COVERS]->(v)
      WHERE b.expires IS NULL OR datetime(b.expires) > datetime()
    OPTIONAL MATCH (b)-[:INCLUDES_TERM]->(t:BAATerm)
    WITH p, v, m, b, collect(DISTINCT t.id) AS satisfied
    WITH p, v, m, b,
         [req IN $required WHERE NOT req IN satisfied] AS missing_terms
    WHERE b IS NULL OR size(missing_terms) > 0
    RETURN p.id AS prompt_id,
           toString(p.ts) AS ts,
           v.name AS vendor,
           m.name AS model,
           CASE WHEN b IS NULL THEN 'NO_BAA' ELSE 'TERM_GAPS' END AS gap_kind,
           coalesce(b.id, '') AS baa_id,
           missing_terms
    ORDER BY p.ts DESC
    LIMIT $limit
    """
    return run_read(cypher, hours=window_hours,
                    required=REQUIRED_TERMS_FOR_PHI, limit=limit)


def replay_incident(prompt_id: str) -> dict:
    """Given a prompt id, return every downstream hop with the BAA status
    annotated at each :AIVendor node."""
    cypher = """
    MATCH (p:Prompt {id: $pid})
    OPTIONAL MATCH path = (p)-[:SENT_VIA|CALLS|HOSTED_BY|RETURNED|LOGGED_IN|USES_SUBPROCESSOR|OPERATES_IN|STORED_IN*1..6]->(node)
    WITH p, collect(DISTINCT node) AS nodes
    UNWIND nodes AS n
    OPTIONAL MATCH (n)<-[:COVERS]-(b:BAA)
      WHERE n:AIVendor AND (b.expires IS NULL OR datetime(b.expires) > datetime())
    OPTIONAL MATCH (b)-[:INCLUDES_TERM]->(t:BAATerm)
    WITH p, n, b, collect(DISTINCT t.id) AS terms
    RETURN p.id AS prompt_id,
           toString(p.ts) AS ts,
           collect({
             label: head(labels(n)),
             id: coalesce(n.id, n.code, n.key, n.name),
             name: coalesce(n.name, n.code, n.id, ''),
             kind: coalesce(n.kind, ''),
             baa: coalesce(b.id, ''),
             baa_terms: terms
           }) AS hops
    """
    rows = run_read(cypher, pid=prompt_id)
    return rows[0] if rows else {"prompt_id": prompt_id, "hops": []}


def vendor_coverage_report() -> list[dict]:
    """For each AIVendor that has seen PHI, list BAA + missing terms."""
    cypher = """
    MATCH (p:Prompt)-[:CONTAINS]->(:PHIElement)
    MATCH (p)-[:SENT_VIA]->(:Application)-[:CALLS]->(:AIModel)-[:HOSTED_BY]->(v:AIVendor)
    WITH v, count(DISTINCT p) AS phi_calls
    OPTIONAL MATCH (b:BAA)-[:COVERS]->(v)
      WHERE b.expires IS NULL OR datetime(b.expires) > datetime()
    OPTIONAL MATCH (b)-[:INCLUDES_TERM]->(t:BAATerm)
    WITH v, phi_calls, b, collect(DISTINCT t.id) AS satisfied
    RETURN v.id AS vendor_id, v.name AS vendor_name,
           phi_calls,
           coalesce(b.id, '') AS baa_id,
           [req IN $required WHERE NOT req IN satisfied] AS missing_terms
    ORDER BY phi_calls DESC
    """
    return run_read(cypher, required=REQUIRED_TERMS_FOR_PHI)


def stats() -> dict:
    """Counts for the lineage dashboard."""
    cypher = """
    CALL { MATCH (p:Prompt) RETURN count(p) AS prompts }
    CALL { MATCH (r:Response) RETURN count(r) AS responses }
    CALL { MATCH (e:PHIElement) RETURN count(e) AS phi_elements }
    CALL { MATCH (v:AIVendor) RETURN count(v) AS vendors }
    CALL { MATCH (b:BAA) RETURN count(b) AS baas }
    CALL { MATCH (k:Sink) RETURN count(k) AS sinks }
    CALL { MATCH (s:PHISource) RETURN count(s) AS sources }
    RETURN prompts, responses, phi_elements, vendors, baas, sinks, sources
    """
    rows = run_read(cypher)
    return rows[0] if rows else {}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> int:
    import json
    import sys
    args = sys.argv[1:]
    if not args:
        print("Usage: python -m engine.phi_lineage "
              "[seed-terms|stats|broken|replay <prompt_id>|coverage]")
        return 0
    cmd = args[0]
    if cmd == "seed-terms":
        n = seed_baa_terms()
        print(f"Seeded {n} BAA terms")
    elif cmd == "stats":
        print(json.dumps(stats(), indent=2, default=str))
    elif cmd == "broken":
        print(json.dumps(find_broken_baa_chains(window_hours=24),
                         indent=2, default=str))
    elif cmd == "coverage":
        print(json.dumps(vendor_coverage_report(), indent=2, default=str))
    elif cmd == "replay" and len(args) > 1:
        print(json.dumps(replay_incident(args[1]), indent=2, default=str))
    else:
        print(f"unknown command: {cmd}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())


__all__ = [
    "CallEvent", "EvidenceGrade", "CANONICAL_BAA_TERMS",
    "REQUIRED_TERMS_FOR_PHI",
    "record_call", "find_broken_baa_chains", "replay_incident",
    "register_vendor", "register_baa", "seed_baa_terms",
    "vendor_coverage_report", "stats",
]
