"""
MCP server inspector — find which MCPs handle PHI and seed the lineage graph.

Reads installed MCP servers (via existing ingest.inventory.mcp scanner)
and inspects each server's command, args, env keys, and tool descriptions
for PHI-handling indicators (FHIR, HL7, EMR, patient, ICD, etc.). Tags
matching :Application nodes with `handles_phi = true` and creates a
speculative :AIModel('mcp:<name>') so MCPs show up in the lineage graph
even before any live traffic is observed.

Optionally emits a DECLARED-grade synthetic CallEvent per PHI-handling
MCP so the broken-BAA query has something to surface from day one.

Run:
    python -m ingest.lineage.mcp_inspector
    python -m ingest.lineage.mcp_inspector --emit-call-events
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from typing import Any

from engine.graph import run_write
from engine.phi_lineage import CallEvent, record_call

try:
    from ingest.inventory.mcp import scan_mcp_servers
except Exception:  # pragma: no cover
    scan_mcp_servers = None  # type: ignore[assignment]


# clinical / PHI signals in tool descriptions, names, args, env
_PHI_SIGNALS = re.compile(
    r"\b(?:patient|clinic|clinical|health|hospital|emr|ehr|fhir|hl7|"
    r"dicom|icd-?10|cpt|ncpdp|prescription|diagnosis|lab[_\s-]?result|"
    r"medical[_\s-]?record|hipaa|protected[_\s-]?health|phi|"
    r"radiology|pathology|pharmacy|chart|admission|discharge)\b",
    re.IGNORECASE,
)


def _signals(server_doc: dict[str, Any]) -> list[str]:
    blob = json.dumps(server_doc, default=str)
    return sorted({m.lower() for m in _PHI_SIGNALS.findall(blob)})


def inspect(emit_call_events: bool = False) -> dict:
    if scan_mcp_servers is None:
        return {"phi_handling_mcps": [], "total": 0,
                "error": "ingest.inventory.mcp not importable"}
    try:
        servers = scan_mcp_servers()
    except Exception as e:  # noqa: BLE001
        return {"phi_handling_mcps": [], "total": 0, "error": str(e)}

    found: list[dict] = []
    for s in servers:
        if not isinstance(s, dict):
            try:
                s = s.__dict__  # type: ignore[assignment]
            except Exception:
                continue
        sigs = _signals(s)
        if not sigs:
            continue
        record = {
            "name": s.get("name") or s.get("id") or "unknown-mcp",
            "transport": s.get("transport", ""),
            "command": s.get("command", ""),
            "phi_signals": sigs,
            "tools": [t.get("name") for t in (s.get("tools") or [])
                      if isinstance(t, dict)],
        }
        found.append(record)

        run_write(
            """
            MERGE (a:Application {key: $key})
              SET a.name = $name,
                  a.handles_phi = true,
                  a.phi_signals = $sigs,
                  a.last_inspected = datetime()
            WITH a
            MERGE (m:AIModel {id: 'mcp:' + $key})
              SET m.name = $name,
                  m.kind = 'mcp_server'
            MERGE (a)-[:CALLS]->(m)
            MERGE (v:AIVendor {id: 'local-mcp'})
              ON CREATE SET v.name = 'Local MCP Host'
            MERGE (m)-[:HOSTED_BY]->(v)
            MERGE (reg:Region {code: 'local'})
            MERGE (v)-[:OPERATES_IN]->(reg)
            """,
            key=record["name"], name=record["name"], sigs=sigs,
        )

        if emit_call_events:
            ev = CallEvent(
                prompt_text=f"[mcp-inspect:{record['name']}] tool descriptions",
                application_name=record["name"],
                model_id=f"mcp:{record['name']}",
                model_name=record["name"],
                vendor_id="local-mcp", vendor_name="Local MCP Host",
                region_code="local",
                source_name="mcp-inventory",
                evidence_grade="DECLARED",
                evidence_ref=f"mcp-inspector:{record['name']}",
            )
            record_call(ev)

    return {"phi_handling_mcps": found, "total": len(found)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Inspect installed MCP servers for PHI signals"
    )
    p.add_argument("--emit-call-events", action="store_true",
                   help="Also emit a synthetic CallEvent per PHI-handling MCP")
    args = p.parse_args(argv)
    res = inspect(emit_call_events=args.emit_call_events)
    print(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
