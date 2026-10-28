import threading
import time

import httpx2 as httpx
import pytest

from account_access.errors import AccessError
from account_access.mailboxes import enrollment
from account_access.owner import make_owner_server
from test_codes import gmail_message, gmail_source


@pytest.mark.parametrize("credential", [
    None, {}, {"enabled": None}, {"enabled": 1}, {"enabled": "true"},
    {"username": "demo@example.test", "password": "fictional-old-imap-password"},
])
def test_gmail_consent_without_explicit_source_enrollment_cannot_read_baseline(env, monkeypatch, credential):
    provider, broker, _ = env
    gmail_source(broker)
    broker.store.put("source:email", credential)
    connection = broker.store.get("connection:demo-api")

    def forbidden(*args, **kwargs):
        pytest.fail("Unenrolled Gmail source attempted mailbox/provider access")

    monkeypatch.setattr(broker.oauth, "token", forbidden)
    monkeypatch.setattr("account_access.codes.get_json", forbidden)
    with pytest.raises(AccessError) as error:
        broker.codes.begin("email", "demo-web", time.time())
    assert (error.value.status, error.value.reason, error.value.kind) == (
        "NEEDS_USER", "mailbox_not_connected", "email")
    assert broker.store.get("code-window:email") is None
    assert broker.store.get("source:email") == credential
    assert broker.store.get("connection:demo-api") == connection
    assert provider.login_count == 0


@pytest.mark.parametrize("credential,reason", [
    (None, "mailbox_not_connected"), ({"enabled": False}, "verification_source_disabled"),
])
def test_gmail_source_setup_is_required_before_website_password_submission(env, monkeypatch, credential, reason):
    provider, broker, _ = env
    gmail_source(broker)
    config = broker.store.config()
    config.accounts["demo-mfa"].login.code_source = "email"
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    broker.store.put("source:email", credential)

    def forbidden(*args, **kwargs):
        pytest.fail("Unenrolled/disabled Gmail source attempted provider access")

    monkeypatch.setattr(broker.oauth, "token", forbidden)
    monkeypatch.setattr("account_access.codes.get_json", forbidden)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER" and result["reason"] == reason, result
    assert provider.login_count == 0
    assert broker.store.get("code-window:email") is None


@pytest.mark.parametrize("credential,reason", [
    (None, "mailbox_not_connected"), ({}, "mailbox_not_connected"),
    ({"enabled": 1}, "mailbox_not_connected"),
    ({"enabled": False}, "verification_source_disabled"),
])
def test_pending_gmail_window_cannot_read_after_source_enrollment_disappears(env, monkeypatch, credential, reason):
    _, broker, _ = env
    gmail_source(broker)
    monkeypatch.setattr("account_access.codes.get_json", lambda *a, **k: {})
    started = time.time() - 1
    broker.codes.begin("email", "demo-web", started)
    broker.store.put("source:email", credential)

    def forbidden(*args, **kwargs):
        pytest.fail("Gmail window read mail after its enrollment disappeared")

    monkeypatch.setattr("account_access.codes.get_json", forbidden)
    used = set()
    with pytest.raises(AccessError, match="^" + reason + "$"):
        broker.codes.resolve("email", started, used)
    assert used == set()


def test_worker_owner_route_enables_only_the_selected_gmail_source_before_code_reads(env, monkeypatch):
    provider, broker, agent = env
    gmail_source(broker)
    broker.store.put("source:email", None)
    config = broker.store.config()
    config.code_sources["other-email"] = config.code_sources["email"].model_copy(deep=True)
    broker.store.configure(config)
    before = config.model_dump()
    calls = []
    fresh = False

    def gmail(url, **kwargs):
        calls.append(url)
        if url.endswith("/messages"):
            return {"messages": [{"id": "fresh"}]} if fresh else {}
        return gmail_message("fresh", time.time())

    monkeypatch.setattr("account_access.codes.get_json", gmail)
    server, owner = make_owner_server(broker, local_host_actions=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            payload = {"source": "email", "credential": {}}
            agent_headers = {"Authorization": "Bearer " + agent, "Origin": base}
            assert client.post("/owner/source", json=payload, headers=agent_headers).status_code == 403
            assert broker.store.get("source:email") is None and calls == []
            headers = {"Authorization": "Bearer " + owner, "Origin": base}
            response = client.post("/owner/source", json=payload, headers=headers)
            assert response.status_code == 200
            assert response.json() == {"status": "ENROLLED", "source": "email", "kind": "gmail"}
        assert enrollment(broker.store, "email") == {"enabled": True}
        assert calls == []  # Enrollment never lists or fetches mail.
        assert broker.store.get("source:other-email") is None
        assert broker.store.config().model_dump() == before
        started = time.time() - 1
        broker.codes.begin("email", "demo-web", started)
        fresh = True
        assert broker.codes.resolve("email", started, set()) == "123456"
        assert len(calls) == 3  # Baseline, fresh list, exact matching message.
        assert provider.login_count == 0
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
