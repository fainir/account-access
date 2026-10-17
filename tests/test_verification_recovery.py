import json
import time

import pytest

from account_access.demo import DEMO_PASSWORD
from account_access.demo import connect_demo
from account_access.broker import Broker
from account_access.errors import AccessError
from account_access.factors import enroll, revoke
from account_access.mailboxes import check, connect, link, update_password
from account_access.mailbox_health import check as check_source
from account_access.models import TaskRequest
from account_access.storage import Store
from account_access.verification_demo import environment
from account_access.verification_recovery import PREFIX, recover
from test_codes import gmail_source


def mailbox_data(mailbox, password=DEMO_PASSWORD):
    return {"label": "Example email", "host": "127.0.0.1", "port": mailbox.port,
            "username": "demo@example.test", "password": password}


def permissions(broker, accounts=("example-email",)):
    broker.store.new_client("fixture")
    for account in accounts:
        broker.grant("fixture", account, ["summary"])
        broker.store.put("credential:" + account, {"username": "demo@example.test", "password": DEMO_PASSWORD})


def source_error(broker, account="example-email", source="example-email", reason="mailbox_connection_failed"):
    error = AccessError("NEEDS_USER", reason, "email")
    error.source_id = source
    return broker.error(error, account)["challenge"]


@pytest.mark.parametrize("mode", ["reusable", "inline"])
def test_verified_mailbox_repair_resumes_original_task_and_preserves_completed_steps(tmp_path, mode):
    with environment(tmp_path) as (provider, broker, mailbox):
        permissions(broker, ("demo-web", "example-email"))
        if mode == "reusable":
            saved = connect(broker, mailbox_data(mailbox, "wrong-example-password"))
            link(broker.store, "example-email", saved["id"])
        else:
            enroll(broker.store, "example-email", {"username": "demo@example.test", "password": "wrong-example-password"})
        task = broker.submit("fixture", TaskRequest.model_validate({"key": "repair-preserves-work",
            "steps": [{"account": account, "operation": "summary"} for account in ["demo-web", "example-email"]]}))
        broker.tick()
        waiting = broker.task("fixture", task["task_id"])
        assert waiting["status"] == "NEEDS_USER" and waiting["progress"] == 1
        assert waiting["blocked"]["reason"] == "mailbox_connection_failed"
        challenge = waiting["blocked"]["challenge"]
        assert broker.store.get(PREFIX + challenge["id"])["source"] == "example-email"
        assert provider.login_count == 1 and provider.email_count == mailbox.fetches == 0
        completed = waiting["results"]
        if mode == "reusable":
            update_password(broker, saved["id"], DEMO_PASSWORD)
        else:
            enroll(broker.store, "example-email", {"username": "demo@example.test", "password": DEMO_PASSWORD})
            check_source(broker, "example-email")
        # Simulate reopening the broker after the owner repair. The original
        # task, private source context and fresh verification must survive.
        broker = Broker(Store(tmp_path, (tmp_path / "demo.key").read_bytes()))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            broker.tick()
            result = broker.task("fixture", task["task_id"])
            if result["status"] == "COMPLETED":
                break
            time.sleep(.05)
        assert result["status"] == "COMPLETED", result
        assert result["task_id"] == task["task_id"] and result["progress"] == 2
        assert result["results"][:1] == completed
        assert provider.login_count == 2 and provider.email_count == mailbox.fetches == 1
        assert broker.store.pending("example-email") == []
        assert DEMO_PASSWORD not in json.dumps(result)
        assert "fingerprint" not in json.dumps(waiting["blocked"]["challenge"])


@pytest.mark.parametrize("case", ["stale_check", "disabled", "changed_connector", "revoked_grant", "legacy", "legacy_new_error", "wrong_source", "delivery_failure"])
def test_mailbox_repair_cannot_clear_unproven_or_changed_access(tmp_path, case):
    with environment(tmp_path) as (provider, broker, mailbox):
        permissions(broker)
        saved = connect(broker, mailbox_data(mailbox))
        link(broker.store, "example-email", saved["id"])
        if case in {"legacy", "legacy_new_error"}:
            challenge = broker.store.challenge("example-email", "email", "mailbox_connection_failed")
            if case == "legacy_new_error":
                source_error(broker, reason="mailbox_scope_missing")
        else:
            challenge = source_error(broker, source="unknown-source" if case == "wrong_source" else "example-email",
                reason="login_code_not_received" if case == "delivery_failure" else "mailbox_connection_failed")
        if case == "disabled":
            revoke(broker.store, "example-email")
        elif case == "changed_connector":
            config = broker.store.config()
            config.code_sources["example-email"].subject = "Different approved template"
            broker.store.configure(config)
        elif case == "revoked_grant":
            broker.revoke(account="example-email")
        if case != "stale_check":
            check(broker, saved["id"])
        assert recover(broker.store) == recover(broker.store) == 0
        assert [x["id"] for x in broker.store.pending("example-email")] == [challenge["id"]]
        assert provider.login_count == mailbox.fetches == 0


def test_repaired_mailbox_does_not_clear_independent_presence_or_action_challenges(tmp_path):
    with environment(tmp_path) as (provider, broker, mailbox):
        permissions(broker)
        saved = connect(broker, mailbox_data(mailbox))
        link(broker.store, "example-email", saved["id"])
        source_error(broker)
        protected = [broker.store.challenge("example-email", kind, "browser_" + kind + "_required")
                     for kind in ["captcha", "device", "passkey", "admin", "action", "unknown", "recovery"]]
        check(broker, saved["id"])
        assert recover(broker.store) == 1
        assert {x["id"] for x in broker.store.pending("example-email")} == {x["id"] for x in protected}
        assert broker.run("fixture", "example-email", "summary")["status"] == "NEEDS_USER"
        assert provider.login_count == mailbox.fetches == 0


def test_recovery_scan_cannot_starve_later_accounts_behind_unrepaired_gates(tmp_path):
    with environment(tmp_path) as (provider, broker, mailbox):
        saved = connect(broker, mailbox_data(mailbox))
        link(broker.store, "example-email", saved["id"])
        config = broker.store.config()
        handles = ["waiting-" + str(index) for index in range(21)]
        for handle in handles:
            config.accounts[handle] = config.accounts["example-email"].model_copy(deep=True)
        broker.store.configure(config)
        permissions(broker, (handles[-1],))
        for handle in handles:
            source_error(broker, account=handle)
        check(broker, saved["id"])
        assert recover(broker.store) == 0
        assert recover(broker.store) == 1
        assert broker.store.pending(handles[-1]) == []
        assert all(broker.store.pending(handle) for handle in handles[:-1])
        assert provider.login_count == mailbox.fetches == 0


def test_reusable_mailbox_password_is_redacted_from_provider_results(tmp_path, monkeypatch):
    with environment(tmp_path) as (_, broker, mailbox):
        permissions(broker)
        secret = "fictional-unique-mailbox-application-secret"
        saved = connect(broker, mailbox_data(mailbox, secret))
        link(broker.store, "example-email", saved["id"])
        monkeypatch.setattr(broker.browser, "read", lambda *args, **kwargs: {"summary": "Echo: " + secret})
        result = broker.run("fixture", "example-email", "summary")
        assert result["status"] == "COMPLETED"
        assert secret not in json.dumps(result)
        assert "[REDACTED]" in result["data"]["summary"]


@pytest.mark.parametrize("case", ["verified_reconnect", "unverified_reconnect", "wrong_identity", "changed_parent"])
def test_gmail_repair_requires_current_verified_authorization_and_unchanged_parent(env, monkeypatch, case):
    _, broker, _ = env
    gmail_source(broker)
    enroll(broker.store, "email", {})
    config = broker.store.config()
    config.accounts["demo-mfa"].login.code_source = "email"
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    challenge = source_error(broker, account="demo-mfa", source="email", reason="account_not_connected")
    monkeypatch.setattr("account_access.mailbox_health.get_json", lambda *args, **kwargs: {"emailAddress": "demo@example.test"})
    check_source(broker, "email")
    if case in {"verified_reconnect", "unverified_reconnect", "wrong_identity"}:
        connect_demo(broker)
        if case == "verified_reconnect":
            check_source(broker, "email")
        elif case == "wrong_identity":
            monkeypatch.setattr("account_access.mailbox_health.get_json", lambda *args, **kwargs: {"emailAddress": "other@example.test"})
            with pytest.raises(AccessError, match="mailbox_identity_mismatch"):
                check_source(broker, "email")
    else:
        config = broker.store.config()
        config.accounts["demo-api"].authorization_params["prompt"] = "consent"
        broker.store.configure(config)
    assert recover(broker.store) == (1 if case == "verified_reconnect" else 0)
    pending = broker.store.pending("demo-mfa")
    assert [x["id"] for x in pending] == ([] if case == "verified_reconnect" else [challenge["id"]])
