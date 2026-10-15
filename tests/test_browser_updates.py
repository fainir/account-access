import threading
import time

import httpx2 as httpx
import pytest

from account_access import browser_updates
from account_access.errors import AccessError
from account_access.owner import make_owner_server


def github_config(broker):
    config = broker.store.config()
    spec = config.accounts["demo-mfa"].model_copy(deep=True)
    spec.login_url = "https://github.com/login"
    spec.login.username_selector = "#login_field"
    spec.login.password_selector = "#password"
    spec.login_resources = [spec.login_url, browser_updates.APP_PAGE]
    spec.login_post_urls = ["https://github.com/session", "https://github.com/sessions/two-factor"]
    spec.read_resources = [spec.login_url]
    spec.operations["summary"].url = "https://github.com/settings/profile"
    config.accounts["github-pilot"] = spec
    broker.store.configure(config)
    broker.grant("test", "github-pilot", ["summary"], expires=time.time() + 300)
    return config


def test_reviewed_login_repair_preserves_read_scope_recipients_and_expiry(env):
    _, broker, _ = env
    config = github_config(broker)
    before = config.accounts["github-pilot"].model_copy(deep=True)
    fingerprint = config.fingerprint("github-pilot")
    broker.store.put("credential:github-pilot", {"username": "fictional", "password": "fictional-password"})
    broker.store.put("connection:github-pilot", {"fingerprint": fingerprint, "state": {"cookies": [], "origins": []}})
    with broker.store.db() as db:
        grants = [dict(row) for row in db.execute("SELECT * FROM grants WHERE account='github-pilot'")]
    assert browser_updates.apply(broker, "github-pilot", fingerprint)["status"] == "UPDATED"
    updated = broker.store.config()
    spec = updated.accounts["github-pilot"]
    assert spec.operations == before.operations and spec.read_resources == before.read_resources
    assert spec.login_post_urls == before.login_post_urls and spec.login.sources() == before.login.sources()
    assert set(spec.login_resources) - set(before.login_resources) == {browser_updates.METHOD_PAGE, browser_updates.SMS_PAGE}
    assert browser_updates.SMS_LINK in spec.challenge_selectors["method"]
    assert browser_updates.SMS_PAGE not in spec.login_post_urls
    assert spec.login.choices[0].url == browser_updates.APP_PAGE
    assert spec.login.choices[1].kind == "sms" and spec.login.factor("sms") is None
    assert spec.login.factor("totp").code_source == before.login.code_source
    assert broker.store.get("credential:github-pilot")["password"] == "fictional-password"
    assert broker.store.get("connection:github-pilot")["fingerprint"] == updated.fingerprint("github-pilot")
    with broker.store.db() as db:
        after = [dict(row) for row in db.execute("SELECT * FROM grants WHERE account='github-pilot'")]
    assert after == [{**row, "fingerprint": updated.fingerprint("github-pilot")} for row in grants]
    assert browser_updates.view(broker.store) == []
    with pytest.raises(AccessError, match="browser_update_changed"):
        browser_updates.apply(broker, "github-pilot", fingerprint)


def test_update_requires_authenticated_owner_and_matching_preview(env):
    _, broker, agent_token = env
    config = github_config(broker)
    old = config.model_dump()
    server, token = make_owner_server(broker, guided=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            payload = {"account": "github-pilot", "fingerprint": config.fingerprint("github-pilot")}
            for headers in [{}, {"Authorization": "Bearer " + agent_token, "Origin": base},
                            {"Authorization": "Bearer " + token, "Origin": "https://attacker.example"}]:
                assert client.post("/owner/browser-update", json=payload, headers=headers).status_code == 403
            assert broker.store.config().model_dump() == old
            owner = {"Authorization": "Bearer " + token, "Origin": base}
            assert client.post("/owner/browser-update", json={**payload, "url": "https://attacker.example"}, headers=owner).status_code == 400
            assert client.post("/owner/browser-update", json=payload, headers=owner).status_code == 200
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
