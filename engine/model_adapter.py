"""
Model adapter layer for the regression suite.
==============================================
A thin uniform protocol for "send a chat-completion request, get a string
back". Lets the runner target any of:

    ollama:llama3.1:8b                        -> OllamaModel
    openai:gpt-4o-mini                        -> OpenAICompatModel  (api.openai.com)
    anthropic:claude-3-5-sonnet-20241022      -> AnthropicModel
    openai-compat:<base>:<model>              -> OpenAICompatModel  (any /v1)
    copilot:gpt-4o                            -> GitHubCopilotModel
    stub:<name>                               -> StubModel  (testing)

Specs are parsed by `make_model("vendor:model")`.

Each adapter:
    - reads its API key from a documented env var
    - never raises on transport errors — returns an error message string
      with prefix `[adapter-error]` so the grader can record a failure
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass
from typing import Any, Protocol


class Model(Protocol):
    spec: str
    vendor_id: str
    model_name: str
    region: str

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str: ...


@dataclass
class _Base:
    spec: str
    vendor_id: str
    model_name: str
    region: str = "unspecified"


# ===========================================================================
# Stub — used by tests + offline demos
# ===========================================================================
class StubModel(_Base):
    """Deterministic stub that returns a configurable response. Useful for
    tests and for showing the suite end-to-end without a live model."""

    DEFAULT_RESPONSE = (
        "I can't help with that — please ask me something else."
    )

    def __init__(self, spec: str, response: str | None = None) -> None:
        super().__init__(spec=spec, vendor_id="stub", model_name=spec.split(":", 1)[-1])
        self._response = response if response is not None else self.DEFAULT_RESPONSE

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        # Deterministic + ignores input by design
        return self._response


# ===========================================================================
# Ollama
# ===========================================================================
class OllamaModel(_Base):
    def __init__(self, spec: str) -> None:
        # spec like 'ollama:llama3.1:8b' — model is everything after the first ':'
        rest = spec.split(":", 1)[1]
        super().__init__(spec=spec, vendor_id="ollama", model_name=rest, region="local")
        self._base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        try:
            import httpx
        except Exception as e:  # noqa: BLE001
            return f"[adapter-error] httpx unavailable: {e}"
        try:
            r = httpx.post(
                f"{self._base}/api/chat",
                json={"model": self.model_name, "messages": messages, "stream": False},
                timeout=120.0,
            )
            r.raise_for_status()
            return (r.json().get("message") or {}).get("content", "") or ""
        except Exception as e:  # noqa: BLE001
            return f"[adapter-error] ollama: {e}"


# ===========================================================================
# OpenAI / OpenAI-compatible (covers OpenAI, Together, Groq, vLLM, Bedrock-via-LiteLLM, etc.)
# ===========================================================================
class OpenAICompatModel(_Base):
    def __init__(self, spec: str) -> None:
        # spec: 'openai:gpt-4o-mini'  OR  'openai-compat:<base_url>:<model_name>'
        parts = spec.split(":")
        if parts[0] == "openai-compat" and len(parts) >= 3:
            base = ":".join(parts[1:-1])
            model = parts[-1]
            vendor = "openai-compat"
        else:
            base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com")
            model = ":".join(parts[1:])
            vendor = "openai"
        super().__init__(spec=spec, vendor_id=vendor, model_name=model)
        self._base = base.rstrip("/")
        self._key = (os.environ.get("OPENAI_API_KEY") or "").strip()

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        try:
            import httpx
        except Exception as e:  # noqa: BLE001
            return f"[adapter-error] httpx unavailable: {e}"
        if not self._key:
            return "[adapter-error] OPENAI_API_KEY not set"
        try:
            r = httpx.post(
                f"{self._base}/v1/chat/completions",
                headers={"Authorization": f"Bearer {self._key}",
                         "content-type": "application/json"},
                json={"model": self.model_name, "messages": messages,
                      "temperature": kwargs.get("temperature", 0)},
                timeout=120.0,
            )
            r.raise_for_status()
            doc = r.json()
            return (doc.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        except Exception as e:  # noqa: BLE001
            return f"[adapter-error] openai-compat: {e}"


# ===========================================================================
# Anthropic
# ===========================================================================
class AnthropicModel(_Base):
    def __init__(self, spec: str) -> None:
        model = spec.split(":", 1)[1]
        super().__init__(spec=spec, vendor_id="anthropic", model_name=model)
        self._base = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        self._key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        try:
            import httpx
        except Exception as e:  # noqa: BLE001
            return f"[adapter-error] httpx unavailable: {e}"
        if not self._key:
            return "[adapter-error] ANTHROPIC_API_KEY not set"
        # Split off the system message if present (Anthropic API requires it as a sibling)
        sys_msg = ""
        msgs: list[dict[str, str]] = []
        for m in messages:
            if m.get("role") == "system":
                sys_msg += (m.get("content") or "") + "\n"
            else:
                msgs.append({"role": m["role"], "content": m["content"]})
        try:
            r = httpx.post(
                f"{self._base}/v1/messages",
                headers={"x-api-key": self._key,
                         "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": self.model_name,
                      "max_tokens": kwargs.get("max_tokens", 1024),
                      "system": sys_msg.strip() or None,
                      "messages": msgs,
                      "temperature": kwargs.get("temperature", 0)},
                timeout=120.0,
            )
            r.raise_for_status()
            doc = r.json()
            blocks = doc.get("content") or []
            return "".join(b.get("text", "") for b in blocks
                           if isinstance(b, dict))
        except Exception as e:  # noqa: BLE001
            return f"[adapter-error] anthropic: {e}"


# ===========================================================================
# GitHub Copilot — OpenAI-compatible chat endpoint
# ===========================================================================
class GitHubCopilotModel(_Base):
    """Targets the Copilot Chat API (OpenAI-compatible) once you have a
    Copilot token in $COPILOT_TOKEN. The endpoint shape is the same as
    OpenAICompatModel so we delegate."""

    DEFAULT_BASE = "https://api.githubcopilot.com"

    def __init__(self, spec: str) -> None:
        model = spec.split(":", 1)[1]
        super().__init__(spec=spec, vendor_id="github-copilot", model_name=model)
        self._base = os.environ.get("COPILOT_BASE_URL", self.DEFAULT_BASE)
        self._key = (os.environ.get("COPILOT_TOKEN")
                     or os.environ.get("GITHUB_COPILOT_TOKEN") or "").strip()

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        try:
            import httpx
        except Exception as e:  # noqa: BLE001
            return f"[adapter-error] httpx unavailable: {e}"
        if not self._key:
            return "[adapter-error] COPILOT_TOKEN not set"
        try:
            r = httpx.post(
                f"{self._base.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {self._key}",
                         "Editor-Version": "vscode/1.93",
                         "content-type": "application/json"},
                json={"model": self.model_name, "messages": messages,
                      "temperature": kwargs.get("temperature", 0),
                      "max_tokens": kwargs.get("max_tokens", 1024)},
                timeout=120.0,
            )
            r.raise_for_status()
            doc = r.json()
            return (doc.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        except Exception as e:  # noqa: BLE001
            return f"[adapter-error] copilot: {e}"


# ===========================================================================
# Factory
# ===========================================================================
def make_model(spec: str, **kwargs: Any) -> Model:
    """Parse a model spec string into a concrete adapter.

    Supported prefixes:
        ollama:<model>
        openai:<model>
        openai-compat:<base>:<model>
        anthropic:<model>
        copilot:<model>
        stub:<name>           (returns StubModel.DEFAULT_RESPONSE; pass
                              `response="..."` to override)
    """
    if not spec or ":" not in spec:
        raise ValueError(f"model spec must look like 'vendor:model', got {spec!r}")
    head = spec.split(":", 1)[0].lower()
    if head == "ollama":
        return OllamaModel(spec)
    if head == "openai":
        return OpenAICompatModel(spec)
    if head == "openai-compat":
        return OpenAICompatModel(spec)
    if head == "anthropic":
        return AnthropicModel(spec)
    if head == "copilot":
        return GitHubCopilotModel(spec)
    if head == "stub":
        return StubModel(spec, response=kwargs.get("response"))
    raise ValueError(f"unknown vendor prefix in spec: {spec!r}")


__all__ = [
    "Model", "make_model",
    "StubModel", "OllamaModel", "OpenAICompatModel",
    "AnthropicModel", "GitHubCopilotModel",
]
