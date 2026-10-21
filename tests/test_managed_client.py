from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import secrets
import socket
import threading

import httpx2 as httpx
import pytest
from fastapi.testclient import TestClient

from account_access.errors import AccessError
from account_access.managed_client import RECORD, enroll, installed, view
from account_access.owner import make_owner_server
from account_access.service import create_app


def test_enrollment_is_idempotent_digest_only_and_grants_nothing(env):
    _, broker, _ = env
    token = secrets.token_urlsafe(32)
    assert view(broker.store) == {"status": "NOT_CONNECTED"}
    expected = {
        "status": "ENROLLED",
        "client_id": hashlib.sha256(token.encode()).hexdigest(),
        "principal": "generic",
    }
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda _: enroll(broker.store, token), range(8))) == [expected] * 8
    assert broker.store.client(token) == "generic"
    assert broker.accounts("generic")["accounts"] == []
    assert view(broker.store) == expected
    with broker.store.db() as db:
        assert (
            db.execute("SELECT count(*) FROM clients WHERE principal='generic'").fetchone()[0] == 1
        )
        assert (
            db.execute("SELECT count(*) FROM grants WHERE principal='generic'").fetchone()[0] == 0
        )
    for path in broker.store.root.glob("state.db*"):
        assert token.encode() not in path.read_bytes()
    assert token not in json.dumps(broker.store.get(RECORD))
    with pytest.raises(AccessError, match="client_connection_conflict"):
        enroll(broker.store, secrets.token_urlsafe(32))
    assert broker.store.client(token) == "generic"
    assert (
        installed(broker.store, expected["client_id"], ["claude", "codex"])["status"] == "INSTALLED"
    )
    assert view(broker.store)["status"] == "INSTALLED"
    assert broker.store.get("agent-integrations") == ["claude", "codex"]
    assert broker.store.get("session-integrations") == {
        "claude": {"enabled": True},
        "codex": {"enabled": True},
    }


def test_enrollment_cannot_revive_or_replace_revoked_capability(env):
    _, broker, _ = env
    token = secrets.token_urlsafe(32)
    result = enroll(broker.store, token)
    broker.revoke(principal="generic")
    assert view(broker.store) == {"status": "REVOKED"}
    with pytest.raises(AccessError, match="portable_client_revoked"):
        enroll(broker.store, token)
    with pytest.raises(AccessError, match="client_connection_conflict"):
        enroll(broker.store, secrets.token_urlsafe(32))
    with pytest.raises(AccessError):
        installed(broker.store, result["client_id"], [])
    with pytest.raises(AccessError):
        broker.store.client(token)


@pytest.mark.parametrize(
    "token", [None, True, 1, [], {}, "", "a" * 42, "a" * 44, "+" * 43, "א" * 43]
)
def test_malformed_capabilities_are_not_registered(env, token):
    _, broker, _ = env
    with pytest.raises(AccessError, match="invalid_client_enrollment"):
        enroll(broker.store, token)
    assert view(broker.store) == {"status": "NOT_CONNECTED"}


@pytest.mark.parametrize(
    "hosts",
    [["shell"], ["claude", "claude"], ["codex", "claude", "extra"], "claude", [True], [["codex"]]],
)
def test_install_receipt_accepts_only_known_host_names(env, hosts):
    _, broker, _ = env
    result = enroll(broker.store, secrets.token_urlsafe(32))
    with pytest.raises(AccessError):
        installed(broker.store, result["client_id"], hosts)
    assert view(broker.store)["status"] == "ENROLLED"


def test_enrollment_preserves_existing_grants_and_rejects_legacy_generic_clients(env):
    _, broker, _ = env
    token = broker.store.new_client("generic")
    broker.grant("generic", "demo-api", ["summary"])
    with pytest.raises(AccessError, match="client_connection_conflict"):
        enroll(broker.store, token)
    with broker.store.db() as db:
        assert (
            db.execute("SELECT operation FROM grants WHERE principal='generic'").fetchone()[0]
            == "summary"
        )
    assert broker.store.client(token) == "generic"


@pytest.mark.parametrize("record", [[], "invalid", {"schema": True, "client_id": "a" * 64}])
def test_corrupt_metadata_never_creates_a_replacement(env, record):
    _, broker, _ = env
    broker.store.put(RECORD, record)
    assert view(broker.store)["status"] in {"NOT_CONNECTED", "NEEDS_REPAIR"}
    with pytest.raises(AccessError):
        enroll(broker.store, secrets.token_urlsafe(32))


def test_only_managed_private_owner_route_can_enroll_and_state_never_contains_token(env):
    _, broker, client_token = env
    api = TestClient(create_app(broker, worker=False))
    token = secrets.token_urlsafe(32)
    assert (
        api.post(
            "/owner/client/enroll",
            headers={"Authorization": "Bearer " + client_token},
            json={"token": token},
        ).status_code
        == 404
    )
    server, owner_token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = "http://127.0.0.1:" + str(server.server_port)
        assert (
            httpx.post(
                base + "/owner/client/enroll",
                headers={"Authorization": "Bearer " + owner_token, "Origin": base},
                json={"token": token},
            ).status_code
            == 403
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
    path = str(broker.store.root / "owner-managed.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    server, owner_token = make_owner_server(
        broker, guided=True, server_socket=listener, origin_port=8765, local_host_actions=False
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=path), base_url="http://127.0.0.1:8765"
        ) as owner:
            headers = {"Authorization": "Bearer " + owner_token, "Origin": "http://127.0.0.1:8765"}
            assert owner.post("/owner/client/enroll", json={"token": token}).status_code == 403
            assert (
                owner.post(
                    "/owner/client/enroll",
                    headers=headers,
                    json={"token": token, "principal": "admin"},
                ).status_code
                == 400
            )
            result = owner.post("/owner/client/enroll", headers=headers, json={"token": token})
            assert result.status_code == 200 and token not in result.text
            state = owner.get("/owner/state", headers=headers).json()
            assert state["managed_client"]["status"] == "ENROLLED" and token not in json.dumps(
                state
            )
            receipt = owner.post(
                "/owner/client/installed",
                headers=headers,
                json={"client_id": result.json()["client_id"], "hosts": ["claude", "codex"]},
            )
            assert receipt.status_code == 200 and token not in receipt.text
            assert (
                owner.get("/owner/state", headers=headers).json()["managed_client"]["status"]
                == "INSTALLED"
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_first_enrollment_cannot_inherit_orphaned_permissions(env):
    _, broker, _ = env
    broker.grant("generic", "demo-api", ["summary"])
    token = secrets.token_urlsafe(32)
    with pytest.raises(AccessError, match="client_connection_conflict"):
        enroll(broker.store, token)
    with pytest.raises(AccessError, match="invalid_client"):
        broker.store.client(token)
    with broker.store.db() as db:
        assert db.execute("SELECT count(*) FROM grants WHERE principal='generic'").fetchone()[0] == 1
