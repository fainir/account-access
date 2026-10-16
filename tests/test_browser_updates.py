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
    assert set(spec.login_resources) - set(before.login_resources) == {browser_updates.METHOD_PAGE, browser_updates.SMS_PAGE, browser_updates.RECOVERY_PAGE}
    assert browser_updates.RECOVERY_PAGE not in spec.login_post_urls
    assert 'input[name="recovery_code"]' in spec.challenge_selectors["recovery"]
    assert spec.challenge_selectors["action"] == before.challenge_selectors["action"]
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


@pytest.mark.parametrize("case", ["recovery_only", "mixed", "independent", "duplicate"])
def test_recovery_marker_repair_never_resolves_transaction_authorizations(env, case):
    _, broker, _ = env
    config = github_config(broker)
    selector = browser_updates.RECOVERY_SELECTOR
    spec = config.accounts["github-pilot"]
    spec.challenge_selectors["action"] = "#transaction, " + selector if case == "mixed" else selector
    broker.store.configure(config)
    reason = "owner_action_required" if case == "independent" else "browser_action_required"
    original = broker.store.challenge("github-pilot", "action", reason)
    if case == "duplicate":
        broker.store.challenge("github-pilot", "recovery", "browser_recovery_required")
    browser_updates.apply(broker, "github-pilot", config.fingerprint("github-pilot"))
    pending = broker.store.pending("github-pilot")
    assert len(pending) == 1
    expected = "action" if case in {"mixed", "independent"} else "recovery"
    assert pending[0]["kind"] == expected
    if expected == "action":
        assert pending[0]["id"] == original["id"]
    if case == "mixed":
        assert broker.store.config().accounts["github-pilot"].challenge_selectors["action"] == "#transaction"
    broker.store.resolve_login("github-pilot")
    assert bool(broker.store.pending("github-pilot")) == (expected == "action")


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


def test_signed_asset_refresh_preserves_enrolled_sms_and_read_grants(env):
    from account_access import sms_setup
    from account_access.google_messages import connect

    _, broker, _ = env
    config = github_config(broker)
    connect(broker.store, "github-pilot", config.fingerprint("github-pilot"))
    config = broker.store.config()
    spec = config.accounts["github-pilot"]
    spec.login_assets = spec.login_assets[:1]
    broker.store.configure(config)
    broker.grant("test", "github-pilot", ["summary"])
    before = spec.model_copy(deep=True)
    source = before.login.factor("sms").code_source
    enrollment = broker.store.get("source:" + source)
    assert not sms_setup.eligible(config, "github-pilot")
    assert browser_updates.view(broker.store)
    browser_updates.apply(broker, "github-pilot", config.fingerprint("github-pilot"))
    current = broker.store.config()
    updated = current.accounts["github-pilot"]
    assert set(updated.login_assets) == set(browser_updates.github_assets())
    assert updated.operations == before.operations and updated.read_resources == before.read_resources
    assert updated.login_post_urls == before.login_post_urls
    assert updated.login.factors == before.login.factors
    assert broker.store.get("source:" + source) == enrollment
    assert not browser_updates.view(broker.store)
    broker.permit("test", "github-pilot", "summary")


@pytest.mark.parametrize("selector", ["h1", "main h1", "#settings-frame h1", "#settings-frame h2"])
def test_reviewed_profile_marker_repair_keeps_only_the_existing_heading_read(env, selector):
    _, broker, _ = env
    config = github_config(broker)
    spec = config.accounts["github-pilot"]
    spec.operations["summary"].fields = {"heading": selector}
    broker.store.configure(config)
    broker.grant("test", "github-pilot", ["summary"], expires=time.time() + 300)
    before = spec.model_copy(deep=True)
    broker.store.challenge("github-pilot", "action", "owner_action_required")
    with broker.store.db() as db:
        grants = [dict(row) for row in db.execute("SELECT * FROM grants WHERE account='github-pilot'")]
    browser_updates.apply(broker, "github-pilot", config.fingerprint("github-pilot"))
    current = broker.store.config()
    updated = current.accounts["github-pilot"]
    assert updated.ready_selector == browser_updates.PROFILE_HEADING
    assert updated.operations["summary"] == before.operations["summary"].model_copy(
        update={"fields": {"heading": browser_updates.PROFILE_HEADING}})
    assert updated.read_resources == before.read_resources
    assert updated.login_post_urls == before.login_post_urls
    assert broker.store.pending("github-pilot")[0]["kind"] == "action"
    with broker.store.db() as db:
        assert [dict(row) for row in db.execute("SELECT * FROM grants WHERE account='github-pilot'")] == [
            {**row, "fingerprint": current.fingerprint("github-pilot")} for row in grants]


@pytest.mark.parametrize("change", ["field", "url", "selector", "description"])
def test_profile_marker_guard_refuses_any_expanded_or_reinterpreted_read(env, change):
    _, broker, _ = env
    config = github_config(broker)
    old = config.accounts["github-pilot"]
    old.operations["summary"].fields = {"heading": "h1"}
    updated = old.model_copy(deep=True)
    updated.operations["summary"].fields = {"heading": browser_updates.PROFILE_HEADING}
    operation = updated.operations["summary"]
    if change == "field":
        operation.fields["email"] = "input[type=email]"
    elif change == "url":
        operation.url = "https://github.com/settings/emails"
    elif change == "selector":
        operation.fields["heading"] = "body"
    else:
        operation.description = "Read all private profile settings"
    assert not browser_updates.profile_marker_repair(old, updated)
