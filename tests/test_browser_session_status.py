"""Session-status grants prove authentication without exporting account text."""

import json

import pytest
from pydantic import ValidationError

from account_access.models import BrowserAccount, BrowserOperation, TaskRequest


def status_operation(spec):
    return BrowserOperation(description="Confirm the authenticated session", session_only=True,
                            url=spec.operations["summary"].url)


def configure(broker, account):
    config = broker.store.config()
    spec = config.accounts[account]
    spec.operations["status"] = status_operation(spec)
    broker.store.configure(config)
    broker.grant("test", account, ["status"])


@pytest.mark.parametrize("fields,status", [({}, False), ({"name": "#name"}, True)])
def test_session_result_and_page_reads_are_mutually_exclusive(fields, status):
    with pytest.raises(ValidationError):
        BrowserOperation(description="Check", url="https://example.test/", fields=fields, session_only=status)


def test_existing_field_grants_keep_their_fingerprint(env, monkeypatch):
    _, broker, _ = env
    config = broker.store.config()
    current = config.fingerprint("demo-web")
    original = BrowserAccount.model_dump

    def old_dump(self, **kwargs):
        data = original(self, **kwargs)
        for op in data["operations"].values():
            op.pop("session_only", None)
        return data

    with monkeypatch.context() as patch:
        patch.setattr(BrowserAccount, "model_dump", old_dump)
        assert config.fingerprint("demo-web") == current
    config.accounts["demo-web"].operations["summary"] = status_operation(config.accounts["demo-web"])
    assert config.fingerprint("demo-web") != current


def test_status_task_recovers_and_reuses_session_without_exporting_page_text(env, monkeypatch):
    from playwright.sync_api import Locator

    def refuse_page_text(*args, **kwargs):
        raise AssertionError("A session-status operation must not extract page text")

    monkeypatch.setattr(Locator, "inner_text", refuse_page_text)
    provider, broker, _ = env
    configure(broker, "demo-web")
    job = broker.submit("test", TaskRequest(key="session-status", steps=[
        {"account": "demo-web", "operation": "status"}]))
    broker.advance(job["task_id"])
    result = broker.task("test", job["task_id"])
    assert result["status"] == "COMPLETED"
    assert result["results"][0]["data"] == {"authenticated": True}
    assert "987.65" not in json.dumps(result)
    assert provider.login_count == 1
    assert broker.run("test", "demo-web", "status")["data"] == {"authenticated": True}
    assert provider.login_count == 1
    assert broker.run("test", "demo-web", "summary")["status"] == "DENIED"
    provider.sessions.clear()
    broker.store.put("login-attempt:demo-web", 0)
    assert broker.run("test", "demo-web", "status")["data"] == {"authenticated": True}
    assert provider.login_count == 2


def test_status_operation_keeps_factor_and_transaction_boundaries(env):
    provider, broker, _ = env
    configure(broker, "demo-mfa")
    assert broker.run("test", "demo-mfa", "status")["data"] == {"authenticated": True}
    assert provider.totp_count == 1
    provider.transaction_challenge = True
    result = broker.run("test", "demo-mfa", "status")
    assert result["status"] == "NEEDS_USER" and result["challenge"]["kind"] == "action"
    assert "data" not in result and provider.totp_count == 1


def test_status_operation_refuses_unknown_page_without_submitting_a_login(env):
    provider, broker, _ = env
    config = broker.store.config()
    config.accounts["demo-web"].challenge_selectors = {}
    broker.store.configure(config)
    configure(broker, "demo-web")
    result = broker.run("test", "demo-web", "status")
    assert result["status"] == "NEEDS_USER"
    assert "data" not in result and provider.login_count == 0


def test_changing_status_to_read_fields_requires_a_new_grant(env):
    _, broker, _ = env
    configure(broker, "demo-web")
    config = broker.store.config()
    spec = config.accounts["demo-web"]
    spec.operations["status"] = spec.operations["summary"].model_copy(deep=True)
    broker.store.configure(config)
    assert broker.run("test", "demo-web", "status")["status"] == "DENIED"
