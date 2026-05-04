"""
OpenAI-compatible HTTP proxy that records lineage.

Run:
    uvicorn ingest.lineage.openai_proxy:app --host 0.0.0.0 --port 8800

Then point your OpenAI client at it:
    OPENAI_BASE_URL=http://localhost:8800/v1
    OPENAI_API_KEY=sk-...    # forwarded unchanged

The proxy forwards to OpenAI by default. To target another /v1-compatible
endpoint set NIKRUVX_PROXY_UPSTREAM, e.g.:
    NIKRUVX_PROXY_UPSTREAM=https://api.together.xyz
    NIKRUVX_PROXY_VENDOR_ID=together
    NIKRUVX_PROXY_VENDOR_NAME="Together AI"
    NIKRUVX_PROXY_REGION=us-east-2

Streaming responses (SSE) are buffered through and parsed at the end so a
final lineage record is emitted with the assembled response. Auth headers
pass through unchanged. The proxy never blocks the call on lineage failure.

Custom headers callers can set per-request to enrich the event:
    X-NikruvX-Actor          actor id
    X-NikruvX-App            application name
    X-NikruvX-PHI-Source     phi source label
"""
from __future__ import annotations
import json
import logging
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from engine.phi_lineage import CallEvent, record_call

log = logging.getLogger(__name__)

UPSTREAM = os.environ.get("NIKRUVX_PROXY_UPSTREAM", "https://api.openai.com")
VENDOR_ID = os.environ.get("NIKRUVX_PROXY_VENDOR_ID", "openai")
VENDOR_NAME = os.environ.get("NIKRUVX_PROXY_VENDOR_NAME", "OpenAI")
REGION = os.environ.get("NIKRUVX_PROXY_REGION", "us-east-1")

app = FastAPI(title="NikruvX PHI-Lineage Proxy", version="1.0.0")


def _flatten(messages: list[dict] | None) -> str:
    parts: list[str] = []
    for m in messages or []:
        role = m.get("role", "")
        content = m.get("content", "")
        if isinstance(content, list):
            content = " ".join(p.get("text", "") for p in content if isinstance(p, dict))
        parts.append(f"[{role}] {content}")
    return "\n".join(parts)


def _record(req_body: dict, resp_body: dict, headers: dict) -> None:
    try:
        prompt_text = _flatten(req_body.get("messages") or [])
        response_text = ""
        for ch in resp_body.get("choices", []) or []:
            msg = ch.get("message") or {}
            response_text += (msg.get("content") or "")
        ev = CallEvent(
            prompt_text=prompt_text, response_text=response_text,
            actor_id=headers.get("x-nikruvx-actor", "proxy-actor"),
            application_name=headers.get("x-nikruvx-app", "openai-proxy-client"),
            model_name=req_body.get("model", "unknown-model"),
            vendor_id=VENDOR_ID, vendor_name=VENDOR_NAME,
            region_code=REGION,
            source_name=headers.get("x-nikruvx-phi-source", "unknown-source"),
            evidence_grade="OBSERVED",
            evidence_ref=f"proxy:{UPSTREAM}",
            sinks=[
                {"id": f"{VENDOR_ID}-traffic-logs", "kind": "log",
                 "encrypted": True, "evidence_grade": "DECLARED"},
            ],
        )
        record_call(ev)
    except Exception as e:  # noqa: BLE001
        log.warning("openai_proxy record failed: %s", e)


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    body = await request.body()
    try:
        req_json = json.loads(body)
    except Exception:
        req_json = {}

    upstream_url = f"{UPSTREAM.rstrip('/')}/v1/chat/completions"
    fwd_headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in ("host", "content-length")}

    is_stream = bool(req_json.get("stream"))

    if is_stream:
        async def stream():
            buf = bytearray()
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream("POST", upstream_url,
                                         headers=fwd_headers,
                                         content=body) as resp:
                    async for chunk in resp.aiter_raw():
                        buf.extend(chunk)
                        yield chunk
            try:
                text = buf.decode("utf-8", errors="replace")
                parts = []
                for line in text.splitlines():
                    if line.startswith("data:"):
                        payload = line[5:].strip()
                        if payload and payload != "[DONE]":
                            try:
                                delta = json.loads(payload)
                                parts.append(
                                    delta.get("choices", [{}])[0]
                                         .get("delta", {})
                                         .get("content", "")
                                )
                            except Exception:
                                pass
                fake_resp = {"choices": [{"message": {"content": "".join(parts)}}]}
                _record(req_json, fake_resp, dict(request.headers))
            except Exception as e:  # noqa: BLE001
                log.warning("stream record failed: %s", e)

        return StreamingResponse(stream(), media_type="text/event-stream")

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(upstream_url, headers=fwd_headers, content=body)
    try:
        resp_json = resp.json()
    except Exception:
        resp_json = {}
    _record(req_json, resp_json, dict(request.headers))
    return JSONResponse(status_code=resp.status_code, content=resp_json)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "upstream": UPSTREAM,
            "vendor_id": VENDOR_ID, "region": REGION}
