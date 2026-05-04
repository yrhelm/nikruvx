"""
Azure OpenAI diagnostic-log ingester.

Azure OpenAI emits diagnostic logs (when enabled at the resource level)
to Azure Monitor / Log Analytics / blob storage in the standard
'RequestResponse' record format:

    {
      "category": "RequestResponse",
      "operationName": "ChatCompletions_Create",
      "resultType": "Succeeded",
      "properties": {
         "requestUri": "...",
         "modelDeploymentName": "gpt-4o-prod",
         "modelName": "gpt-4o-2024-11-20",
         "clientApplication": "..."
      },
      "resourceId": "/subscriptions/.../Microsoft.CognitiveServices/accounts/...",
      "location": "eastus2",
      "time": "2026-05-02T12:34:56Z",
      "identity": {"claims": {...}}
    }

Azure does not log prompt/response bodies by default. With "Audit"
diagnostic category enabled the body hash + token counts are present;
full bodies appear only with custom OTel instrumentation. We pick up
'prompt' / 'response' fields when present and fall back to metadata-only
records otherwise.

Usage:
    python -m ingest.lineage.azure_openai --path ./azure_diag/*.json
    python -m ingest.lineage.azure_openai --path ./azure_diag/*.jsonl
"""
from __future__ import annotations
import argparse
import glob
import json
import sys

from engine.phi_lineage import CallEvent, record_call


def _iter_records(paths: list[str]):
    for pat in paths:
        for f in glob.glob(pat):
            try:
                fh = open(f, encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:
                # Try as JSON-Lines first; fall back to single JSON object.
                first = fh.readline()
                fh.seek(0)
                first_stripped = first.strip()
                if not first_stripped:
                    continue
                if first_stripped.startswith("{") and first_stripped.endswith("}"):
                    # Likely JSONL
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(rec, dict) and "records" in rec:
                            yield from rec["records"]
                        else:
                            yield rec
                else:
                    try:
                        doc = json.load(fh)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(doc, dict) and "records" in doc:
                        yield from doc["records"]
                    elif isinstance(doc, list):
                        yield from doc
                    else:
                        yield doc


def _resource_to_account(resource_id: str) -> str:
    if not resource_id:
        return "azure-openai-unknown"
    parts = resource_id.split("/")
    try:
        i = parts.index("accounts")
        return parts[i + 1]
    except (ValueError, IndexError):
        return resource_id.rsplit("/", 1)[-1]


def replay(records) -> int:
    n = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        if rec.get("category") not in ("RequestResponse", "Audit", "AuditEvent"):
            continue
        op = rec.get("operationName", "")
        if not any(k in op for k in ("ChatCompletions", "Completions", "Embeddings")):
            continue

        props = rec.get("properties") or {}
        model_name = (props.get("modelName")
                      or props.get("modelDeploymentName")
                      or "azure-openai-unknown")
        region = rec.get("location") or props.get("location") or "azure-unknown"
        resource_id = rec.get("resourceId", "")
        account = _resource_to_account(resource_id)

        identity = rec.get("identity") or {}
        claims = identity.get("claims") or {}
        actor = (claims.get("appid")
                 or claims.get("upn")
                 or claims.get("oid")
                 or "azure-aad-unknown")

        # Bodies are only present with custom OTel instrumentation.
        prompt_text = props.get("prompt") or ""
        response_text = props.get("response") or ""

        ev = CallEvent(
            prompt_text=prompt_text, response_text=response_text,
            actor_id=f"azure:{actor}",
            application_name=props.get("clientApplication", "azure-openai-client"),
            model_id=f"azure-openai:{model_name}",
            model_name=model_name,
            vendor_id="azure-openai", vendor_name="Azure OpenAI",
            region_code=region,
            source_name=f"azure-account:{account}",
            sinks=[
                {"id": f"azure-monitor:{account}", "kind": "audit_log",
                 "encrypted": True, "region": region,
                 "evidence_grade": "OBSERVED"},
            ],
            ts=rec.get("time", ""),
            evidence_grade="OBSERVED",
            evidence_ref=f"azure-diag:{rec.get('correlationId', '')}",
        )
        record_call(ev)
        n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Replay Azure OpenAI diagnostic logs into NikruvX lineage"
    )
    p.add_argument("--path", nargs="+", required=True,
                   help="One or more .json/.jsonl glob patterns")
    args = p.parse_args(argv)
    n = replay(_iter_records(args.path))
    print(f"Replayed {n} Azure OpenAI events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
