import threading
import time

import httpx2 as httpx
import pytest

from account_access import sms_setup
from account_access.errors import AccessError
from account_access.owner import make_owner_server


def pilot(broker):
    config = broker.store.config()
    spec = config.accounts["demo-mfa"].model_copy(deep=True)
    spec.login_url = "https://github.com/login"
    spec.login.username_selector = "#login_field"
    spec.login.password_selector = "#password"
    spec.login_resources = [spec.login_url, "https://github.com/sessions/two-factor/app"]
    spec.login_post_urls = ["https://github.com/session", "https://github.com/sessions/two-factor"]
    spec.read_resources = [spec.login_url]
    spec.operations["summary"].url = "https://github.com/settings/profile"
    config.accounts["github-pilot"] = spec
    broker.store.configure(config)
    broker.grant("test", "github-pilot", ["summary"], expires=time.time() + 1000)
    return config


def test_sms_filter_enrollment_preserves_credentials_read_scope_and_expiry(env):
    _, broker, _ = env
    config = pilot(broker)
    original = config.accounts["github-pilot"].model_copy(deep=True)
    broker.store.put("credential:github-pilot", {"username": "fictional", "password": "fictional-password"})
    with broker.store.db() as db:
        grants = [dict(row) for row in db.execute("SELECT * FROM grants WHERE account='github-pilot'")]
    fingerprint = sms_setup.prepare(broker.store, "github-pilot", config.fingerprint("github-pilot"))
    prepared = broker.store.config().accounts["github-pilot"]
    assert set(prepared.login_post_urls) - set(original.login_post_urls) == {sms_setup.SMS_PAGE}
    assert prepared.operations == original.operations and prepared.read_resources == original.read_resources
    assert prepared.login.factor("sms") is None
    for template in ["Payment: {code}", "{code} is your GitHub authentication code. Private extra text"]:
        with pytest.raises(AccessError, match="invalid_sms_filter"):
            sms_setup.apply(broker.store, "github-pilot", fingerprint, "Example", template)
    result = sms_setup.apply(broker.store, "github-pilot", fingerprint, "Example", "{code} is your GitHub authentication code.")
    updated = broker.store.config()
    source = updated.code_sources[result["source"]]
    assert source.sender == "Example" and source.kind == "mac_messages"
    assert source.recipient == "messages-on-this-mac"
    assert broker.store.get("source:" + result["source"]) == {"enabled": True}
    assert broker.store.get("credential:github-pilot")["password"] == "fictional-password"
    assert updated.accounts["github-pilot"].operations == original.operations
    with broker.store.db() as db:
        assert [dict(row) for row in db.execute("SELECT * FROM grants WHERE account='github-pilot'")] == [
            {**row, "fingerprint": updated.fingerprint("github-pilot")} for row in grants]
    assert sms_setup.view(broker.store) == []
    assert broker.connection_view("github-pilot", updated)["connected"] is False
    with pytest.raises(AccessError, match="sms_setup_changed"):
        sms_setup.apply(broker.store, "github-pilot", fingerprint, "Example", source.template)


def test_sms_setup_endpoints_require_owner_origin_and_single_use(env, monkeypatch):
    _, broker, agent_token = env
    config = pilot(broker)
    def inspect(account, operation, spec, **kwargs):
        assert kwargs["setup_method"] == "sms" and kwargs["visible"] is True
        kwargs["on_code_request"]("sms", time.time())
        raise AccessError("NEEDS_USER", "browser_sms_required", "sms")
    monkeypatch.setattr(broker.browser, "read", inspect)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            owner = {"Authorization": "Bearer " + token, "Origin": base}
            request = {"account": "github-pilot", "fingerprint": config.fingerprint("github-pilot")}
            for headers in [{}, {"Authorization": "Bearer " + agent_token, "Origin": base},
                            {"Authorization": "Bearer " + token, "Origin": "https://attacker.example"}]:
                assert client.post("/owner/sms/setup-start", json=request, headers=headers).status_code == 403
            assert broker.store.config().model_dump() == config.model_dump()
            assert client.post("/owner/sms/setup-start", json={**request, "url": "https://attacker.example"}, headers=owner).status_code == 400
            started = client.post("/owner/sms/setup-start", json=request, headers=owner).json()
            ident = started["id"]
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                state = client.get("/owner/state", headers=owner).json()
                if state["connection_jobs"][ident]["status"] != "RUNNING":
                    break
                time.sleep(.01)
            assert state["connection_jobs"][ident]["code_requested"]["kind"] == "sms"
            payload = {"id": ident, "sender": "Example", "template": "{code} is your GitHub authentication code."}
            assert client.post("/owner/sms/setup-apply", json=payload).status_code == 403
            assert client.post("/owner/sms/setup-apply", json=payload, headers=owner).status_code == 200
            assert client.post("/owner/sms/setup-apply", json=payload, headers=owner).status_code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("change", ["account_changed", "source_collision"])
def test_sms_setup_rejects_configuration_drift_or_an_existing_source(env, change):
    _, broker, _ = env
    config = pilot(broker)
    fingerprint = sms_setup.prepare(broker.store, "github-pilot", config.fingerprint("github-pilot"))
    if change == "account_changed":
        config = broker.store.config()
        config.accounts["github-pilot"].operations["summary"].description = "A changed owner approval"
        broker.store.configure(config)
    else:
        import hashlib
        source = "github-sms-" + hashlib.sha256(b"github-pilot").hexdigest()[:16]
        broker.store.put("source:" + source, {"preserve": "existing-owner-value"})
    before = broker.store.config().model_dump()
    with pytest.raises(AccessError, match="sms_setup_changed"):
        sms_setup.apply(broker.store, "github-pilot", fingerprint, "Example", "{code} is your GitHub authentication code.")
    assert broker.store.config().model_dump() == before
    if change == "source_collision":
        assert broker.store.get("source:" + source) == {"preserve": "existing-owner-value"}


def test_cancelling_queued_sms_setup_cannot_request_a_text_after_it_is_discarded(env, monkeypatch):
    _, broker, _ = env
    config = pilot(broker)
    real_thread = threading.Thread
    queued = []
    reads = []
    monkeypatch.setattr(broker.browser, "read", lambda *args, **kwargs: reads.append(True))
    class Deferred:
        def __init__(self, target, args):
            self.target, self.args = target, args
        def start(self):
            queued.append((self.target, self.args))
    def thread_factory(*args, **kwargs):
        if getattr(kwargs.get("target"), "__name__", "") == "verify":
            return Deferred(kwargs["target"], kwargs["args"])
        return real_thread(*args, **kwargs)
    monkeypatch.setattr("account_access.owner.threading.Thread", thread_factory)
    server, token = make_owner_server(broker, guided=True)
    worker = real_thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + token, "Origin": base}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            payload = {"account": "github-pilot", "fingerprint": config.fingerprint("github-pilot")}
            response = client.post("/owner/sms/setup-start", json=payload, headers=headers)
            assert response.status_code == 200
            ident = response.json()["id"]
            assert client.post("/owner/sms/setup-discard", json={"id": ident}, headers=headers).status_code == 200
            assert len(queued) == 1
            target, args = queued[0]
            target(*args)
            state = client.get("/owner/state", headers=headers).json()
            assert state["connection_jobs"][ident]["status"] == "CANCELLED"
            assert reads == []
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
