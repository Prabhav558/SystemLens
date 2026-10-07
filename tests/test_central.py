"""Central server: agent registration, findings ingest/read, and the auth
boundaries between them. Exercises the real FastAPI app via TestClient
(same code path a real push/browser hits), not just the store layer.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from systemlens.central.auth import generate_api_key, hash_key, verify_key
from systemlens.central.server import build_central_app
from systemlens.central.store import CentralStore


# -- auth primitives ---------------------------------------------------

def test_generated_key_has_recognizable_prefix():
    key = generate_api_key()
    assert key.startswith("sla_")
    assert len(key) > 20


def test_verify_key_accepts_correct_and_rejects_wrong():
    key = generate_api_key()
    h = hash_key(key)
    assert verify_key(key, h) is True
    assert verify_key(generate_api_key(), h) is False


# -- store ---------------------------------------------------------------

def test_agent_by_key_round_trip(tmp_path):
    store = CentralStore(tmp_path / "central.db")
    key = generate_api_key()
    agent_id = store.register_agent("laptop", key)

    found = store.agent_by_key(key)
    assert found["id"] == agent_id
    assert found["name"] == "laptop"
    assert store.agent_by_key("sla_wrong") is None
    store.close()


# -- HTTP surface ----------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSTEMLENS_CENTRAL_ADMIN_KEY", "test-admin-key")
    app = build_central_app(tmp_path / "central.db", admin_key_env="SYSTEMLENS_CENTRAL_ADMIN_KEY")
    return TestClient(app)


def _register(client, name="laptop") -> str:
    resp = client.post("/agents/register", json={"name": name},
                        headers={"Authorization": "Bearer test-admin-key"})
    assert resp.status_code == 200
    return resp.json()["api_key"]


def test_register_requires_correct_admin_key(client):
    resp = client.post("/agents/register", json={"name": "x"},
                        headers={"Authorization": "Bearer wrong-admin-key"})
    assert resp.status_code == 401

    resp = client.post("/agents/register", json={"name": "x"})  # no header at all
    assert resp.status_code == 401


def test_register_fails_cleanly_when_admin_key_env_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("SYSTEMLENS_CENTRAL_ADMIN_KEY", raising=False)
    app = build_central_app(tmp_path / "central.db", admin_key_env="SYSTEMLENS_CENTRAL_ADMIN_KEY")
    client = TestClient(app)
    resp = client.post("/agents/register", json={"name": "x"},
                        headers={"Authorization": "Bearer anything"})
    assert resp.status_code == 503  # not a 500 crash


def test_ingest_requires_a_valid_agent_key(client):
    key = _register(client)
    payload = {"project": "demo", "fingerprint": "fp1",
               "analysis": {"verdict": "root_cause_identified", "root_cause": "x"},
               "created_at": 0.0}

    ok = client.post("/ingest/findings", json=payload, headers={"Authorization": f"Bearer {key}"})
    assert ok.status_code == 200

    bad = client.post("/ingest/findings", json=payload, headers={"Authorization": "Bearer sla_nope"})
    assert bad.status_code == 401

    none = client.post("/ingest/findings", json=payload)
    assert none.status_code == 401


def test_findings_are_isolated_per_agent(client):
    key_a = _register(client, "agent-a")
    key_b = _register(client, "agent-b")

    client.post("/ingest/findings", headers={"Authorization": f"Bearer {key_a}"}, json={
        "project": "demo", "fingerprint": "fp-a",
        "analysis": {"verdict": "root_cause_identified", "root_cause": "a's problem"},
        "created_at": 0.0,
    })

    a_findings = client.get("/findings", headers={"Authorization": f"Bearer {key_a}"}).json()
    b_findings = client.get("/findings", headers={"Authorization": f"Bearer {key_b}"}).json()

    assert len(a_findings) == 1
    assert a_findings[0]["fingerprint"] == "fp-a"
    assert b_findings == []  # agent B must never see agent A's data


def test_whoami_reflects_the_presented_key(client):
    key = _register(client, "my-laptop")
    resp = client.get("/agents/me", headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "my-laptop"


def test_dashboard_serves_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "<title>SystemLens</title>" in resp.text


# -- dashboard hardening -------------------------------------------------------

def test_dashboard_is_served_with_a_restrictive_csp(client):
    resp = client.get("/")
    csp = resp.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "default-src 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "<script src=\"/static/dashboard.js\"></script>" in resp.text
    assert "<style" not in resp.text and "style=" not in resp.text, "inline styles would break the CSP"


def test_dashboard_script_never_parses_api_data_as_html(client):
    js = client.get("/static/dashboard.js")
    assert js.status_code == 200
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert sink not in js.text, f"{sink} would render log-derived text as HTML"


def test_old_findings_are_pruned_on_startup(tmp_path):
    import time
    from systemlens.central.auth import generate_api_key
    store = CentralStore(tmp_path / "central.db")
    agent_id = store.register_agent("a", generate_api_key())
    for _ in range(2):
        store.record_finding(agent_id, "p", "fp", {"verdict": "probable_cause", "root_cause": "x"},
                              None, None, time.time())
    with store._conn:
        store._conn.execute("UPDATE findings SET received_at = ? WHERE id = 1",
                            (time.time() - 40 * 86400,))
    store.close()

    build_central_app(tmp_path / "central.db", retention_days=30)

    reopened = CentralStore(tmp_path / "central.db")
    assert len(reopened.findings_for_agent(agent_id)) == 1
    reopened.close()


def test_repeated_bad_keys_from_one_client_are_throttled(client):
    from systemlens.central import server
    for _ in range(server.MAX_AUTH_FAILURES):
        assert client.get("/findings", headers={"Authorization": "Bearer sla_wrong"}).status_code == 401
    blocked = client.get("/findings", headers={"Authorization": "Bearer sla_wrong"})
    assert blocked.status_code == 429
    assert client.get("/health").status_code == 429, "the block is per client, not per endpoint"


def test_oversized_request_body_is_rejected_before_it_is_read(client):
    key = _register(client)
    huge = {"project": "p", "fingerprint": "f", "analysis": {"root_cause": "x" * 400_000}, "created_at": 0.0}
    resp = client.post("/ingest/findings", json=huge, headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 413


def test_api_docs_are_not_exposed(client):
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code == 404
