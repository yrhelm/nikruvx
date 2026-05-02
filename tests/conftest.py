"""
Shared pytest fixtures.

The tests in this suite must be runnable WITHOUT a live Neo4j or Ollama.
We achieve that by stubbing out the `neo4j` driver and the `httpx` client
*before* anything in `engine/` or `ingest/` gets imported. That happens
in this conftest's top-level scope so it's effective for every test
file.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

# Make the project root importable as the source root for `engine`, `ingest`, etc.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Module stubs (only inserted when tests run before any real import).
# Tests that need a "live" Neo4j swap these out via the `graph_session` fixture.
# ---------------------------------------------------------------------------
class _Anything:
    """Cheap stand-in object used to satisfy attribute / call lookups."""

    def __getattr__(self, _):
        return _Anything()

    def __call__(self, *a, **kw):
        return _Anything()

    def __iter__(self):
        return iter([])

    def __bool__(self):
        return False


def _install_module(name: str, **attrs):
    if name in sys.modules:
        return
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod


# neo4j driver
_install_module(
    "neo4j",
    GraphDatabase=_Anything(),
    Driver=_Anything,
    Session=_Anything,
)
_install_module(
    "neo4j.time",
    DateTime=_Anything,
    Date=_Anything,
    Time=_Anything,
    Duration=_Anything,
)

# httpx -- stub Client + named exception classes that engine/llm.py imports
_install_module(
    "httpx",
    Client=_Anything,
    ConnectError=ConnectionError,
    ReadTimeout=TimeoutError,
)

# rich (used in console output -- silent stub)
_install_module("rich")
_install_module("rich.console", Console=_Anything)
_install_module("rich.progress", Progress=_Anything)

# python-dotenv -- no-op load
_install_module("dotenv", load_dotenv=lambda *a, **kw: None)


import pytest


# ---------------------------------------------------------------------------
# Public fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_graph(monkeypatch):
    """
    Override `engine.graph.run_read` and `run_write` with a tiny in-memory
    fake. Tests can pre-seed `data` to control what queries return.
    """
    state = {"reads": [], "writes": [], "data": []}

    def _run_read(_cypher, **_params):
        return list(state["data"])

    def _run_write(_cypher, **_params):
        state["writes"].append((_cypher, _params))
        return None

    from engine import graph as g

    monkeypatch.setattr(g, "run_read", _run_read)
    monkeypatch.setattr(g, "run_write", _run_write)
    return state


@pytest.fixture
def fake_ollama(monkeypatch):
    """Replace the LLM client with a deterministic echo so tests are stable."""
    from engine import llm

    def _generate(prompt, system=None, **kw):
        return f"<<MOCK_LLM>> system={bool(system)} prompt_len={len(prompt)}"

    def _embed(text, **kw):
        # Deterministic 8-d "embedding" so similarity stays stable per text
        return [hash(text + str(i)) % 1000 / 1000.0 for i in range(8)]

    def _is_available():
        return True

    monkeypatch.setattr(llm, "generate", _generate, raising=False)
    monkeypatch.setattr(llm, "embed", _embed, raising=False)
    monkeypatch.setattr(llm, "is_available", _is_available, raising=False)
