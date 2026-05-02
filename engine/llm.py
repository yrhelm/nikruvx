"""
Local LLM client (Ollama)
=========================
Talks to a local Ollama daemon (default http://localhost:11434). All inference
stays on-device - no data ever leaves your machine.

Install Ollama: https://ollama.com/download
Recommended model: `ollama pull llama3.1:8b` (or `qwen2.5:7b`, `gemma2:9b`)
For embeddings:    `ollama pull nomic-embed-text`

Two main entry points:
    - generate_story(cve_data) -> narrative attack scenario
    - red_team_plan(stack_summary, attack_chains) -> full red-team report
    - embed(text) -> 768-dim embedding (used by Vulnerability DNA)
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable

import httpx

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")


class LLMUnavailable(Exception):
    pass


# ---------------------------------------------------------------------------
# Low-level client
# ---------------------------------------------------------------------------
def _client() -> httpx.Client:
    return httpx.Client(timeout=120.0)


def is_available() -> bool:
    try:
        with _client() as c:
            r = c.get(f"{OLLAMA_URL}/api/tags", timeout=4.0)
            return r.status_code == 200
    except Exception:
        return False


def generate(
    prompt: str,
    *,
    system: str | None = None,
    model: str = DEFAULT_MODEL,
    temperature: float = 0.6,
    max_tokens: int = 800,
) -> str:
    """Synchronous one-shot generation. Returns the full response string."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    if system:
        payload["system"] = system
    try:
        with _client() as c:
            r = c.post(f"{OLLAMA_URL}/api/generate", json=payload)
            if r.status_code != 200:
                raise LLMUnavailable(f"Ollama HTTP {r.status_code}: {r.text[:200]}")
            return r.json().get("response", "")
    except (httpx.ConnectError, httpx.ReadTimeout) as e:
        raise LLMUnavailable(f"Ollama unreachable at {OLLAMA_URL}: {e}")


def generate_stream(
    prompt: str,
    *,
    system: str | None = None,
    model: str = DEFAULT_MODEL,
    temperature: float = 0.6,
    max_tokens: int = 1500,
) -> Iterable[str]:
    """Yield response chunks as they arrive. Use for the UI streaming path."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": True,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    if system:
        payload["system"] = system
    try:
        with _client() as c:
            with c.stream("POST", f"{OLLAMA_URL}/api/generate", json=payload) as resp:
                if resp.status_code != 200:
                    raise LLMUnavailable(f"Ollama HTTP {resp.status_code}")
                for line in resp.iter_lines():
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if chunk.get("response"):
                        yield chunk["response"]
                    if chunk.get("done"):
                        break
    except (httpx.ConnectError, httpx.ReadTimeout) as e:
        raise LLMUnavailable(f"Ollama unreachable: {e}")


def embed(text: str, *, model: str = EMBED_MODEL) -> list[float]:
    """Return an embedding vector for the given text."""
    try:
        with _client() as c:
            r = c.post(f"{OLLAMA_URL}/api/embeddings", json={"model": model, "prompt": text})
            if r.status_code != 200:
                raise LLMUnavailable(f"Embeddings HTTP {r.status_code}")
            return r.json().get("embedding", [])
    except (httpx.ConnectError, httpx.ReadTimeout) as e:
        raise LLMUnavailable(f"Ollama unreachable: {e}")


# ---------------------------------------------------------------------------
# High-level prompts
# ---------------------------------------------------------------------------
STORYTELLER_SYSTEM = """You are a senior offensive-security researcher writing
a concise, technically accurate threat narrative for a defender. Focus on:
real adversary motivations, the exploitation flow, downstream blast radius,
and tangible defensive controls. Be vivid but factual. No fictional vendors."""

STORYTELLER_TEMPLATE = """Vulnerability: {cve_id}
CVSS: {cvss}  Severity: {severity}
CWE class(es): {cwes}
OSI layer(s) affected: {layers}
Affected packages: {packages}
Public PoCs available: {poc_count}
Description:
\"\"\"{description}\"\"\"

Write 4 short paragraphs (≤ 90 words each) titled exactly:
1. Adversary - who would weaponize this and why
2. Exploitation Flow - the technical chain at the affected OSI layer(s)
3. Blast Radius - what an attacker holds afterwards and what they can pivot to
4. Defender Action - the 2-3 highest-leverage mitigations

Be precise. Reference the OSI layers explicitly. If this is an AI/ML
vulnerability, mention model integrity and data flow risks specifically."""


def generate_story(cve: dict, packages: list[str] | None = None) -> str:
    """Produce a narrative attack scenario for a CVE."""
    prompt = STORYTELLER_TEMPLATE.format(
        cve_id=cve.get("id", "?"),
        cvss=cve.get("cvss_score", "?"),
        severity=cve.get("severity", "?"),
        cwes=", ".join(cve.get("cwes", [])) or "—",
        layers=", ".join(f"L{l}" for l in cve.get("layers", [])) or "—",
        packages=", ".join((packages or [])[:8]) or "—",
        poc_count=cve.get("poc_count", 0),
        description=(cve.get("description") or "").strip()[:1200],
    )
    return generate(prompt, system=STORYTELLER_SYSTEM, temperature=0.55)


def stream_story(cve: dict, packages: list[str] | None = None) -> Iterable[str]:
    prompt = STORYTELLER_TEMPLATE.format(
        cve_id=cve.get("id", "?"),
        cvss=cve.get("cvss_score", "?"),
        severity=cve.get("severity", "?"),
        cwes=", ".join(cve.get("cwes", [])) or "—",
        layers=", ".join(f"L{l}" for l in cve.get("layers", [])) or "—",
        packages=", ".join((packages or [])[:8]) or "—",
        poc_count=cve.get("poc_count", 0),
        description=(cve.get("description") or "").strip()[:1200],
    )
    yield from generate_stream(prompt, system=STORYTELLER_SYSTEM, temperature=0.55)


# ---------------------------------------------------------------------------
# Red-Team Mode
# ---------------------------------------------------------------------------
RED_TEAM_SYSTEM = """You are a senior red-team operator briefing a CISO. Use
graph-derived attack chains as ground truth. Output Markdown with these
sections (each ≤ 110 words):

## Executive Summary
## Realistic Attack Path  (numbered, refer to the supplied chain)
## Critical Findings  (3-5 bullets)
## Defensive Priorities  (top 5, ordered by leverage, each tied to an OSI layer)

Be ruthless about prioritization. Cite specific CVE-IDs from the input."""

RED_TEAM_PROMPT = """Stack description / SBOM summary:
{stack_summary}

Top cross-layer attack chains (from the Cyber Nexus graph):
{chains_block}

Aggregate Nexus risk score: {aggregate}/100  ({band})

Author the red-team brief now."""


def _format_chain(chain: dict, idx: int) -> str:
    lines = [f"Chain #{idx + 1}  (score {chain['score']}, layers {chain['layers_traversed']})"]
    for s in chain["steps"]:
        lo = s.get("layer_from")
        lt = s.get("layer_to")
        arrow = f"L{lo}→L{lt}" if lo else f"L{lt}"
        lines.append(
            f"  {arrow}  {s['cve']}  ({s.get('severity', '?')})  — {s.get('transition', '')}"
        )
    return "\n".join(lines)


def red_team_plan(
    stack_summary: str, attack_chains: list[dict], aggregate: float = 0.0, band: str = "UNKNOWN"
) -> str:
    chains_block = (
        "\n\n".join(_format_chain(c, i) for i, c in enumerate(attack_chains[:4])) or "(none)"
    )
    prompt = RED_TEAM_PROMPT.format(
        stack_summary=stack_summary[:2000],
        chains_block=chains_block,
        aggregate=aggregate,
        band=band,
    )
    return generate(prompt, system=RED_TEAM_SYSTEM, temperature=0.5, max_tokens=1500)


def stream_red_team(
    stack_summary: str, attack_chains: list[dict], aggregate: float = 0.0, band: str = "UNKNOWN"
) -> Iterable[str]:
    chains_block = (
        "\n\n".join(_format_chain(c, i) for i, c in enumerate(attack_chains[:4])) or "(none)"
    )
    prompt = RED_TEAM_PROMPT.format(
        stack_summary=stack_summary[:2000],
        chains_block=chains_block,
        aggregate=aggregate,
        band=band,
    )
    yield from generate_stream(prompt, system=RED_TEAM_SYSTEM, temperature=0.5, max_tokens=1500)
