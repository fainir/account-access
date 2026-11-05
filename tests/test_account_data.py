import csv
import io
import json
import threading

import httpx2 as httpx
import pytest

from account_access.account_data import export_login, forget_login
from account_access.demo import DEMO_PASSWORD
from account_access.errors import AccessError
from account_access.owner import make_owner_server


def test_export_is_explicit_single_account_plaintext_csv_and_never_in_state(env):
    _, broker, _ = env
    store = broker.store
    account = "demo-web"
    username = "demo@example.test"
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            headers = {"Authorization": "Bearer " + token, "Origin": base}
            state = client.get("/owner/state", headers=headers).json()
            row = next(value for value in state["accounts"] if value["account"] == account)
            assert row["saved_login_available"] is True
            assert row["saved_login_exportable"] is True
            assert DEMO_PASSWORD not in json.dumps(state)
            assert username not in json.dumps(state)
            assert client.post("/owner/account/export", json={"account": account}).status_code == 403
            assert client.post("/owner/account/export", headers={**headers, "Origin": "http://127.0.0.1:1"},
                               json={"account": account}).status_code == 403
            response = client.post("/owner/account/export", headers=headers,
                                   json={"account": account})
            assert response.status_code == 200
            payload = response.json()
            assert payload["status"] == "EXPORTED"
            rows = list(csv.DictReader(io.StringIO(payload["csv"])))
            assert rows == [{"url": store.config().accounts[account].login_url,
                             "username": username, "password": DEMO_PASSWORD}]
            assert client.post("/owner/account/export", headers=headers,
                               json={"account": account, "path": "/tmp/unsafe"}).status_code == 400
            assert payload["csv"] not in json.dumps(state)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_forget_removes_local_login_and_session_but_keeps_connector_and_grants(env):
    _, broker, _ = env
    store = broker.store
    account = "demo-web"
    config_before = store.config().model_dump()
    with store.db() as db:
        store.put("password-link:" + account, {"fixture": "linked"}, db=db)
        store.put("password-sync-hint:" + account, {"fixture": "hint"}, db=db)
        store.put("browser-session-request:" + account, {"fixture": "pending"}, db=db)
    query = "SELECT principal,account,operation,fingerprint,expires FROM grants WHERE account=? ORDER BY principal,operation"
    with store.db() as db:
        grants_before = [tuple(row) for row in db.execute(query, (account,)).fetchall()]
    result = forget_login(store, account)
    assert result == {"status": "FORGOTTEN", "account": account}
    for key in ("credential:", "connection:", "password-link:", "password-sync-hint:", "browser-session-request:"):
        assert store.get(key + account) is None
    assert store.config().model_dump() == config_before
    with store.db() as db:
        grants_after = [tuple(row) for row in db.execute(query, (account,)).fetchall()]
        records = {row[0] for row in db.execute("SELECT id FROM records")}
    assert grants_after == grants_before
    assert not any(key + account in records for key in
                   ("credential:", "connection:", "password-link:", "password-sync-hint:",
                    "browser-session-request:"))


def test_forget_owner_route_rejects_invalid_requests_and_refreshes_saved_state(env):
    _, broker, _ = env
    store = broker.store
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            headers = {"Authorization": "Bearer " + token, "Origin": base}
            assert client.post("/owner/account/forget", headers=headers,
                               json={"account": "missing"}).status_code == 403
            assert client.post("/owner/account/forget", headers=headers,
                               json={"account": "demo-web", "keep_permissions": False}).status_code == 400
            response = client.post("/owner/account/forget", headers=headers, json={"account": "demo-web"})
            assert response.status_code == 200 and response.json()["status"] == "FORGOTTEN"
            state = client.get("/owner/state", headers=headers).json()
            row = next(value for value in state["accounts"] if value["account"] == "demo-web")
            assert row["saved_login_available"] is False
            assert row["saved_login_exportable"] is False
            assert store.principal_active("test")
            with store.db() as db:
                grants = db.execute("SELECT COUNT(*) FROM grants WHERE account='demo-web'").fetchone()[0]
            assert grants == len(store.config().accounts["demo-web"].operations)
            assert client.post("/owner/account/export", headers=headers,
                               json={"account": "demo-web"}).status_code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_export_refuses_unknown_or_missing_saved_login(env):
    _, broker, _ = env
    with pytest.raises(AccessError, match="unknown_account"):
        export_login(broker.store, "unknown")
    forget_login(broker.store, "demo-web")
    with pytest.raises(AccessError, match="saved_login_unavailable"):
        export_login(broker.store, "demo-web")
