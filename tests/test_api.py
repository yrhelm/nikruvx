"""API tests — directly validate §1.4 fix (HTTPException not swallowed by
generic exception handler) by hitting an endpoint with a missing CVE id.

We monkeypatch `run_read` so no Neo4j connection is required."""
from __future__ import annotations
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient
import api.server as srv


@pytest.fixture
def client(monkeypatch):
    # Stub all DB access — every read returns no rows.
    monkeypatch.setattr(srv, "run_read", lambda *a, **kw: [])
    with TestClient(srv.app) as c:
        yield c


def test_missing_cve_returns_404_not_500(client):
    """Regression: previously the catch-all exception handler swallowed
    HTTPException and returned 500."""
    r = client.get("/api/cve/CVE-9999-99999")
    assert r.status_code == 404, r.text
    body = r.json()
    # FastAPI default: {"detail": "..."} for HTTPException
    assert "detail" in body or "error" in body


def test_missing_graph_returns_404(client):
    r = client.get("/api/graph/CVE-9999-99999")
    assert r.status_code == 404


def test_classify_endpoint_works_without_db(client):
    r = client.get("/api/classify", params={"text": "sql injection", "cwe": "CWE-89"})
    assert r.status_code == 200
    body = r.json()
    assert "layers" in body
    assert any(l.get("layer") == 7 for l in body["layers"])


def test_health_endpoint_present(client):
    # Health endpoint may exist; if not, this still ensures app boots.
    r = client.get("/api/health")
    # 200 if implemented, 404 if not — both acceptable; we just want no crash
    assert r.status_code in (200, 404, 503)
