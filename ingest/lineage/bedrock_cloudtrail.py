"""
AWS Bedrock CloudTrail ingester.

CloudTrail emits InvokeModel / InvokeModelWithResponseStream events for
Bedrock. Point this at a directory of CloudTrail JSON / JSON.gz exports
and it will replay them as lineage events.

Usage:
    python -m ingest.lineage.bedrock_cloudtrail \\
        --path /var/log/cloudtrail/2026/05/02/

CloudTrail records have shape:
    {"Records": [{"eventName": "InvokeModel", "awsRegion": "us-east-1",
                  "userIdentity": {...}, "requestParameters": {...},
                  "responseElements": {...}}]}

CloudTrail does not include request/response bodies by default — to get
prompt text you must enable Bedrock data events (CloudTrail Data Events).
We handle both: with-body events emit full PHI counts; without-body
events still record the metadata path (vendor / model / region / actor).
"""
from __future__ import annotations
import argparse
import gzip
import json
import sys
from pathlib import Path
from typing import Iterator

from engine.phi_lineage import CallEvent, record_call


_BEDROCK_VENDOR_BY_PREFIX: dict[str, tuple[str, str]] = {
    "anthropic.": ("anthropic", "Anthropic via Bedrock"),
    "amazon.":    ("amazon",    "Amazon via Bedrock"),
    "ai21.":      ("ai21",      "AI21 via Bedrock"),
    "cohere.":    ("cohere",    "Cohere via Bedrock"),
    "meta.":      ("meta",      "Meta via Bedrock"),
    "mistral.":   ("mistral",   "Mistral via Bedrock"),
    "stability.": ("stability", "Stability via Bedrock"),
}


def _vendor_for(model_id: str) -> tuple[str, str]:
    for prefix, vendor in _BEDROCK_VENDOR_BY_PREFIX.items():
        if model_id.startswith(prefix):
            return vendor
    return ("aws-bedrock", "AWS Bedrock")


def _iter_records(path: Path) -> Iterator[dict]:
    if path.is_dir():
        for f in sorted(path.rglob("*.json*")):
            yield from _iter_records(f)
        return
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return
    for rec in doc.get("Records", []):
        yield rec


def _extract_prompt(req_params: dict) -> str:
    if not isinstance(req_params, dict):
        return ""
    body = req_params.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except Exception:
            return body[:4000]
    if isinstance(body, dict):
        if "messages" in body:           # Anthropic-on-Bedrock
            parts = []
            for m in body["messages"]:
                content = m.get("content", "")
                if isinstance(content, list):
                    content = " ".join(
                        p.get("text", "") for p in content if isinstance(p, dict)
                    )
                parts.append(f"[{m.get('role', '')}] {content}")
            return "\n".join(parts)
        if "inputText" in body:          # Amazon Titan
            return str(body["inputText"])
        if "prompt" in body:             # AI21 / Cohere / others
            return str(body["prompt"])
    return ""


def _extract_response(resp_elements: dict) -> str:
    if not isinstance(resp_elements, dict):
        return ""
    body = resp_elements.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except Exception:
            return body[:4000]
    if isinstance(body, dict):
        if isinstance(body.get("content"), list):
            return " ".join(
                b.get("text", "") for b in body["content"] if isinstance(b, dict)
            )
        if isinstance(body.get("outputs"), list):
            return " ".join(
                o.get("text", "") for o in body["outputs"] if isinstance(o, dict)
            )
        if isinstance(body.get("results"), list):
            return " ".join(
                r.get("outputText", "") for r in body["results"] if isinstance(r, dict)
            )
        if "completion" in body:
            return str(body["completion"])
    return ""


def replay(records: Iterator[dict]) -> int:
    n = 0
    for rec in records:
        if rec.get("eventSource") != "bedrock.amazonaws.com":
            continue
        ev_name = rec.get("eventName", "")
        if not ev_name.startswith("InvokeModel"):
            continue

        req_params = rec.get("requestParameters") or {}
        resp_elements = rec.get("responseElements") or {}
        model_id = (
            req_params.get("modelId")
            or req_params.get("model")
            or (rec.get("resources", [{}])[0].get("ARN", "").rsplit("/", 1)[-1])
            or "unknown-bedrock-model"
        )
        vendor_id, vendor_name = _vendor_for(model_id)
        ident = rec.get("userIdentity") or {}
        actor = ident.get("arn") or ident.get("userName") or "aws-iam-unknown"

        ev = CallEvent(
            prompt_text=_extract_prompt(req_params),
            response_text=_extract_response(resp_elements),
            actor_id=f"aws:{actor}",
            application_name=ident.get("invokedBy", "bedrock-direct"),
            model_id=f"{vendor_id}:{model_id}",
            model_name=model_id,
            vendor_id=vendor_id, vendor_name=vendor_name,
            region_code=rec.get("awsRegion", "us-east-1"),
            source_name=f"aws-account:{rec.get('recipientAccountId', 'unknown')}",
            sinks=[
                {"id": f"cloudtrail:{rec.get('awsRegion', '')}",
                 "kind": "audit_log",
                 "encrypted": True, "region": rec.get("awsRegion"),
                 "evidence_grade": "OBSERVED"},
            ],
            ts=rec.get("eventTime", ""),
            evidence_grade="OBSERVED",
            evidence_ref=f"cloudtrail:{rec.get('eventID', '')}",
        )
        record_call(ev)
        n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Replay AWS Bedrock CloudTrail events into NikruvX lineage"
    )
    p.add_argument("--path", required=True,
                   help="File or directory of CloudTrail .json/.json.gz")
    args = p.parse_args(argv)
    n = replay(_iter_records(Path(args.path)))
    print(f"Replayed {n} Bedrock events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
