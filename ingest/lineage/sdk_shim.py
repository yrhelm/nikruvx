"""
SDK Shim — instrument openai / anthropic Python SDKs to record lineage.

Two ways to use:

1) Programmatic install at process start (recommended for production agents):
       from ingest.lineage.sdk_shim import install
       install()

2) Context-managed (for one-off scripts / tests):
       from ingest.lineage.sdk_shim import enable
       with enable():
           client = openai.OpenAI()
           client.chat.completions.create(...)

Records every call as a CallEvent against the lineage graph. Designed to
fail open: if Neo4j is unreachable the call still goes through and a
warning is logged.

Environment variables that influence event labelling (all optional):
    NIKRUVX_ACTOR        actor id, e.g. 'clinician:doe@hosp.org'
    NIKRUVX_APP          application name, defaults to '<vendor>-sdk-app'
    NIKRUVX_PHI_SOURCE   phi source label, e.g. 'epic-emr-prod'
    OPENAI_REGION        defaults to 'us-east-1'
    ANTHROPIC_REGION     defaults to 'us-west-2'
"""
from __future__ import annotations
import contextlib
import functools
import logging
import os
from typing import Any, Callable

from engine.phi_lineage import CallEvent, record_call

log = logging.getLogger(__name__)
_INSTALLED = False
_ORIGINALS: dict[str, Callable[..., Any]] = {}


def _safe_record(ev: CallEvent) -> None:
    try:
        record_call(ev)
    except Exception as e:  # noqa: BLE001
        log.warning("phi_lineage.sdk_shim record failed: %s", e)


def _flatten_messages(messages: list[dict] | None) -> str:
    parts: list[str] = []
    for m in messages or []:
        role = m.get("role", "")
        content = m.get("content", "")
        if isinstance(content, list):
            content = " ".join(p.get("text", "") for p in content if isinstance(p, dict))
        parts.append(f"[{role}] {content}")
    return "\n".join(parts)


# --------------------------- OpenAI -----------------------------------------
def _wrap_openai_chat(orig: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(orig)
    def wrapper(self, *args, **kwargs):
        result = orig(self, *args, **kwargs)
        try:
            messages = kwargs.get("messages") or (args[0] if args else [])
            model_name = kwargs.get("model", "")
            prompt_text = _flatten_messages(messages)
            response_text = ""
            try:
                response_text = (result.choices[0].message.content or "")
            except Exception:
                pass
            ev = CallEvent(
                prompt_text=prompt_text,
                response_text=response_text,
                actor_id=os.environ.get("NIKRUVX_ACTOR", "unknown"),
                application_name=os.environ.get("NIKRUVX_APP", "openai-sdk-app"),
                model_name=model_name,
                vendor_id="openai", vendor_name="OpenAI",
                region_code=os.environ.get("OPENAI_REGION", "us-east-1"),
                source_name=os.environ.get("NIKRUVX_PHI_SOURCE", "unknown-source"),
                evidence_grade="OBSERVED",
                evidence_ref="sdk-shim:openai",
                sinks=[
                    {"id": "openai-traffic-logs", "kind": "log",
                     "encrypted": True, "evidence_grade": "DECLARED"},
                ],
            )
            _safe_record(ev)
        except Exception as e:  # noqa: BLE001
            log.warning("openai shim record failed: %s", e)
        return result
    return wrapper


# --------------------------- Anthropic --------------------------------------
def _wrap_anthropic_messages(orig: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(orig)
    def wrapper(self, *args, **kwargs):
        result = orig(self, *args, **kwargs)
        try:
            messages = kwargs.get("messages") or []
            model_name = kwargs.get("model", "")
            prompt_text = _flatten_messages(messages)
            response_text = ""
            try:
                blocks = getattr(result, "content", []) or []
                for b in blocks:
                    txt = getattr(b, "text", None) or (
                        b.get("text") if isinstance(b, dict) else ""
                    )
                    if txt:
                        response_text += txt
            except Exception:
                pass
            ev = CallEvent(
                prompt_text=prompt_text,
                response_text=response_text,
                actor_id=os.environ.get("NIKRUVX_ACTOR", "unknown"),
                application_name=os.environ.get("NIKRUVX_APP", "anthropic-sdk-app"),
                model_name=model_name,
                vendor_id="anthropic", vendor_name="Anthropic",
                region_code=os.environ.get("ANTHROPIC_REGION", "us-west-2"),
                source_name=os.environ.get("NIKRUVX_PHI_SOURCE", "unknown-source"),
                evidence_grade="OBSERVED",
                evidence_ref="sdk-shim:anthropic",
                sinks=[
                    {"id": "anthropic-zdr-cache", "kind": "cache",
                     "encrypted": True, "evidence_grade": "DECLARED"},
                ],
            )
            _safe_record(ev)
        except Exception as e:  # noqa: BLE001
            log.warning("anthropic shim record failed: %s", e)
        return result
    return wrapper


# --------------------------- Install / uninstall ----------------------------
def install() -> None:
    """Install monkey-patches. Idempotent; safe to call multiple times."""
    global _INSTALLED
    if _INSTALLED:
        return
    try:
        from openai.resources.chat.completions import Completions as _OAIComp
        if "openai_chat" not in _ORIGINALS:
            _ORIGINALS["openai_chat"] = _OAIComp.create
            _OAIComp.create = _wrap_openai_chat(_OAIComp.create)  # type: ignore[method-assign]
            log.info("phi_lineage: openai SDK shim installed")
    except Exception as e:  # noqa: BLE001
        log.debug("openai shim skipped: %s", e)

    try:
        from anthropic.resources.messages import Messages as _AnthMsg
        if "anthropic_messages" not in _ORIGINALS:
            _ORIGINALS["anthropic_messages"] = _AnthMsg.create
            _AnthMsg.create = _wrap_anthropic_messages(_AnthMsg.create)  # type: ignore[method-assign]
            log.info("phi_lineage: anthropic SDK shim installed")
    except Exception as e:  # noqa: BLE001
        log.debug("anthropic shim skipped: %s", e)

    _INSTALLED = True


def uninstall() -> None:
    global _INSTALLED
    try:
        from openai.resources.chat.completions import Completions as _OAIComp
        if "openai_chat" in _ORIGINALS:
            _OAIComp.create = _ORIGINALS.pop("openai_chat")  # type: ignore[method-assign]
    except Exception:
        pass
    try:
        from anthropic.resources.messages import Messages as _AnthMsg
        if "anthropic_messages" in _ORIGINALS:
            _AnthMsg.create = _ORIGINALS.pop("anthropic_messages")  # type: ignore[method-assign]
    except Exception:
        pass
    _INSTALLED = False


@contextlib.contextmanager
def enable():
    install()
    try:
        yield
    finally:
        uninstall()


__all__ = ["install", "uninstall", "enable"]
