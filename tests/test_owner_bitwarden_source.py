"""Owner HTTP boundary for source enrollment; no personal vault is opened."""

from contextlib import contextmanager
import threading

import httpx2 as httpx
import pytest

from account_access.errors import AccessError
from account_access.owner import make_owner_server


@contextmanager
def owner(broker):
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            yield client, {"Authorization": "Bearer " + token, "Origin": base}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def enrollment():
    return {"region": "us", "client_id": "user.a1111111-b222-4333-8444-c55555555555",
            "client_secret": "fictional-owner-api-key", "master_password": "fictional-master-password",
            "consent_vault_access": True}


@pytest.mark.parametrize("headers", [{}, {"Origin": "https://untrusted.test"},
                                     {"Authorization": "Bearer wrong"}])
def test_source_enrollment_needs_owner_capability_and_same_origin(env, monkeypatch, headers):
    _, broker, _ = env
    monkeypatch.setattr("account_access.bitwarden_source.connect", lambda *args: pytest.fail("unauthorized source enrollment"))
    with owner(broker) as (client, approved):
        response = client.post("/owner/bitwarden/connect", headers={**approved, **headers}
            if headers else {}, json=enrollment())
    assert response.status_code == 403
    assert response.json() == {"status": "DENIED", "reason": "owner_authorization_required"}
    assert enrollment()["master_password"] not in response.text


@pytest.mark.parametrize("body", [[], {}, {"region": "us"}, {**enrollment(), "command": "/tmp/other"}])
def test_source_enrollment_refuses_extra_or_missing_fields_before_provider(env, monkeypatch, body):
    _, broker, _ = env
    monkeypatch.setattr("account_access.bitwarden_source.connect", lambda *args: pytest.fail("invalid shape reached provider"))
    with owner(broker) as (client, headers):
        response = client.post("/owner/bitwarden/connect", headers=headers, json=body)
    assert response.status_code == 400
    assert response.json() == {"status": "DENIED", "reason": "invalid_request"}


def test_enrollment_and_restriction_use_exact_source_generation(env, monkeypatch):
    _, broker, _ = env
    metadata = {"id": "a" * 32, "generation": "b" * 32, "provider": "Bitwarden",
                "region": "us", "email": "fictional@example.test", "status": "CONNECTED", "checked": 1}
    calls = []

    def connect(store, data):
        assert store is broker.store and data == enrollment()
        calls.append("connect")
        return metadata

    def disconnect(store, ident, generation):
        assert store is broker.store and (ident, generation) == (metadata["id"], metadata["generation"])
        calls.append("disconnect")
        return {"status": "DISCONNECTED", "id": ident}

    monkeypatch.setattr("account_access.bitwarden_source.connect", connect)
    monkeypatch.setattr("account_access.bitwarden_source.disconnect", disconnect)
    with owner(broker) as (client, headers):
        response = client.post("/owner/bitwarden/connect", headers=headers, json=enrollment())
        assert response.status_code == 200 and response.json() == metadata
        assert enrollment()["client_secret"] not in response.text
        assert enrollment()["master_password"] not in response.text
        response = client.post("/owner/bitwarden/disconnect", headers=headers,
                               json={"id": metadata["id"], "generation": metadata["generation"]})
        assert response.status_code == 200 and response.json()["status"] == "DISCONNECTED"
    assert calls == ["connect", "disconnect"]


def test_provider_failure_does_not_return_exception_diagnostics(env, monkeypatch):
    _, broker, _ = env

    def broken(*args):
        raise RuntimeError(enrollment()["master_password"])

    monkeypatch.setattr("account_access.bitwarden_source.connect", broken)
    with owner(broker) as (client, headers):
        response = client.post("/owner/bitwarden/connect", headers=headers, json=enrollment())
        assert response.status_code == 400
        assert response.json() == {"status": "DENIED", "reason": "invalid_request"}

        def unavailable(*args):
            raise AccessError("NEEDS_USER", "password_source_runtime_unavailable")

        monkeypatch.setattr("account_access.bitwarden_source.connect", unavailable)
        response = client.post("/owner/bitwarden/connect", headers=headers, json=enrollment())
        assert response.status_code == 403
        assert response.json() == {"status": "NEEDS_USER", "reason": "password_source_runtime_unavailable"}
