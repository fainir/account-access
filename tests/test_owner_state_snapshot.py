"""Owner status snapshots are coherent; operation authority remains live."""

import threading

import httpx2 as httpx

from account_access.owner import make_owner_server
from account_access.password_import import SYNC_HINT, sync_suggestion


def test_owner_status_snapshot_stays_coherent_during_revocation_and_next_read_is_fresh(env, monkeypatch):
    provider, broker, _ = env
    store = broker.store
    account = "demo-web"
    config = store.config()
    saved = {"fingerprint": config.fingerprint(account), "state": {"cookies": [], "origins": []}}
    store.put("connection:" + account, saved)
    store.new_client("generic")
    broker.grant("generic", account, ["summary"])
    observed = threading.Event()
    committed = threading.Event()
    failures = []

    def revoke_after_observation():
        try:
            assert observed.wait(5)
            with store.db() as db:
                store.put("connection:" + account, {**saved, "revoked": True}, db=db)
                db.execute("UPDATE clients SET revoked=1 WHERE principal='generic'")
                db.execute("DELETE FROM grants WHERE principal='generic'")
                db.execute("INSERT INTO challenges (id,account,kind,reason,created) VALUES (?,?,?,?,?)",
                           ("fictional-concurrent-revocation", account, "unknown", "browser_state_unrecognized", 1))
        except Exception as error:
            failures.append(type(error).__name__)
        finally:
            committed.set()

    original = broker.connection_view
    armed = True

    def connection_view(handle, current, **kwargs):
        nonlocal armed
        result = original(handle, current, **kwargs)
        if handle == account and armed:
            armed = False
            observed.set()
            assert committed.wait(5)
        return result

    monkeypatch.setattr(broker, "connection_view", connection_view)
    writer = threading.Thread(target=revoke_after_observation, daemon=True)
    writer.start()
    server, token = make_owner_server(broker, guided=True)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + token, "Origin": base}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            first = client.get("/owner/state", headers=headers).json()
            assert not failures
            before = next(item for item in first["accounts"] if item["account"] == account)
            assert before["connected"] and before["challenges"] == []
            assert before["portable_ready"] and "generic" in first["principals"]
            assert any(item["principal"] == "generic" and item["account"] == account for item in first["grants"])
            # A status snapshot never becomes authority for an actual operation.
            assert broker.status("generic", account, "summary")["reason"] == "client_revoked"
            assert broker.run("generic", account, "summary")["reason"] == "client_revoked"
            assert provider.login_count == 0
            second = client.get("/owner/state", headers=headers).json()
            after = next(item for item in second["accounts"] if item["account"] == account)
            assert not after["connected"] and after["connection_state"] == "revoked"
            assert after["challenges"][0]["id"] == "fictional-concurrent-revocation"
            assert not after["portable_ready"] and "generic" not in second["principals"]
            assert not any(item["principal"] == "generic" for item in second["grants"])
    finally:
        observed.set()
        server.shutdown()
        server.server_close()
        serving.join(timeout=5)
        writer.join(timeout=5)


def test_missing_or_invalid_sync_hints_do_not_read_account_password(env, monkeypatch):
    _, broker, _ = env
    store = broker.store
    original = store.get
    calls = []

    def get(key, *args, **kwargs):
        calls.append(key)
        assert not key.startswith("credential:"), "Invalid hints must not fetch a password"
        return original(key, *args, **kwargs)

    monkeypatch.setattr(store, "get", get)
    assert sync_suggestion(store, "demo-web") is None
    store.put(SYNC_HINT + "demo-web", {"provider": "bitwarden", "item": "not-an-item"})
    assert sync_suggestion(store, "demo-web") is None
    assert calls == [SYNC_HINT + "demo-web", SYNC_HINT + "demo-web"]
