"""One stopped fictional attempt; no external requests, credentials or messages."""

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from playwright.sync_api import sync_playwright

from account_access import browser_diagnostics as diagnostics
from account_access.broker import Broker
from account_access.catalog import namecheap
from account_access.errors import AccessError
from account_access.models import Configuration, TaskRequest
from account_access.storage import Store


def structural():
    return {"schema": 1, "page": "origin_0:/auth/?/email",
            "forms": [{"method": "POST", "visible": True, "reviewed_action": False, "controls": 3}],
            "fields": {name: name == "one_time_code" for name in diagnostics.FIELDS},
            "field_counts": {name: int(name == "one_time_code") for name in diagnostics.FIELDS},
            "visible_field_counts": {name: int(name == "one_time_code") for name in diagnostics.FIELDS},
            "markers": {name: False for name in diagnostics.MARKERS},
            "progress": {"password_submit_attempted": True}}


@pytest.fixture
def isolated(tmp_path):
    store = Store(tmp_path / "fictional-store", b"f" * 32)
    store.configure(Configuration(accounts={"site": namecheap()}))
    broker = Broker(store)
    token = store.new_client("agent")
    broker.grant("agent", "site", ["status"])
    return broker, token


def failed_read(monkeypatch, broker, *, duplicate=False):
    calls = []

    def read(account, operation, config, **kwargs):
        calls.append(account)
        kwargs["on_attention"]("NEEDS_USER", "browser_state_unrecognized", "unknown", structural())
        if duplicate:
            kwargs["on_attention"]("NEEDS_USER", "browser_state_unrecognized", "unknown", {})
        raise AccessError("NEEDS_USER", "browser_state_unrecognized", "unknown")

    monkeypatch.setattr(broker.browser, "read", read)
    return calls


def test_collector_excludes_filled_values_csrf_tokens_names_ids_and_unreviewed_actions():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
        page = browser.new_page()
        requests = []
        page.route("**/*", lambda route: (requests.append(route.request.url), route.abort()))
        page.set_content("""<form method='post' action='https://private.example/verify/private-token?csrf=private-csrf'>
            <input type='hidden' name='private-csrf-name' id='private-hidden-id' value='private-csrf-value'>
            <input name='private-code-name' id='private-code-id' autocomplete='one-time-code'
                   inputmode='numeric' value='384921'>
            <input type='password' name='private-password-name' value='private-password-value'>
            <input type='email' value='private-person@example.test'>
            <button>Private account text</button></form>
            <form style='display:none' method='get' action='https://www.namecheap.com/myaccount/login/'>
            <input autocomplete='one-time-code' value='726485'></form>""")
        # A value getter that throws proves collection never consults a filled value.
        page.evaluate("""Object.defineProperty(HTMLInputElement.prototype, 'value', {
            get() { throw new Error('must not read values'); }
        })""")
        stopped = SimpleNamespace(locator=page.locator,
            url="https://www.namecheap.com/auth/private-person/email?token=private-token#private-fragment",
            context=SimpleNamespace(_login_progress={"password_submit_attempted": True,
                "method": "email", "private-untrusted-key": "private-untrusted-value"}))
        result = diagnostics.capture(stopped, namecheap())
        browser.close()
    assert requests == []
    encoded = json.dumps(result)
    assert not any(item in encoded for item in ["private", "384921", "726485", "https://", "csrf",
                                                "example.test", "token=", "<input", "Private account"])
    assert result["page"] == "origin_0:/auth/?/email"
    assert result["forms"] == [
        {"method": "POST", "visible": True, "reviewed_action": False, "controls": 5},
        {"method": "GET", "visible": False, "reviewed_action": True, "controls": 1}]
    assert result["field_counts"]["one_time_code"] == 2
    assert result["visible_field_counts"]["one_time_code"] == 1
    assert result["fields"]["password"] and result["fields"]["numeric_input"]
    assert result["progress"] == {"password_submit_attempted": True, "method": "email"}
    assert not any(result["markers"].values())  # Structure does not infer Namecheap email support.


def test_named_controls_cannot_shadow_native_form_diagnostics():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
        page = browser.new_page()
        page.route("**/*", lambda route: route.abort())
        page.set_content("""<form method='post' action='https://www.namecheap.com/myaccount/login/'>
            <input name='method' value='private-method'><input name='action' value='private-action'>
            <input name='elements' value='private-elements'><input name='getClientRects' value='private-rects'>
            </form>""")
        stopped = SimpleNamespace(locator=page.locator, url="https://www.namecheap.com/myaccount/login/",
                                  context=SimpleNamespace())
        result = diagnostics.capture(stopped, namecheap())
        browser.close()
    assert result["forms"] == [{"method": "POST", "visible": True, "reviewed_action": True, "controls": 4}]
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("change", ["url", "extra", "count", "bool-count", "form", "phase", "marker"])
def test_arbitrary_or_malformed_metadata_is_refused(change):
    value = structural()
    if change == "url":
        value["page"] = "https://private.example/?token=384921"
    elif change == "extra":
        value["input_value"] = "384921"
    elif change == "count":
        value["visible_field_counts"]["one_time_code"] = 9
    elif change == "bool-count":
        value["field_counts"]["password"] = True
    elif change == "form":
        value["forms"][0]["method"] = "private-method"
    elif change == "phase":
        value["progress"]["password_submit_attempted"] = "private-value"
    else:
        value["markers"]["private-selector"] = True
    with pytest.raises(ValueError, match="invalid_browser_diagnostics"):
        diagnostics.validate(value)


def test_first_failure_is_encrypted_bound_and_not_recaptured_by_agent_or_task_polling(isolated, monkeypatch):
    broker, _ = isolated
    calls = failed_read(monkeypatch, broker, duplicate=True)
    before = broker.store.config().model_dump()
    task = broker.submit("agent", TaskRequest.model_validate({"key": "unknown-code-page",
        "steps": [{"account": "site", "operation": "status"}]}))
    broker.advance(task["task_id"])
    first = broker.task("agent", task["task_id"])
    challenge = first["blocked"]["challenge"]
    record = broker.store.get(diagnostics.PREFIX + "site")
    assert record["challenge_id"] == challenge["id"]
    assert record["account"] == "site" and record["operation"] == "status"
    assert record["fingerprint"] == broker.store.config().fingerprint("site")
    assert record["diagnostics"] == structural()
    with broker.store.db() as db:
        blob = db.execute("SELECT value FROM records WHERE id=?", (diagnostics.PREFIX + "site",)).fetchone()[0]
    assert b"one_time_code" not in blob and b"password_submit_attempted" not in blob
    for result in (broker.run("agent", "site", "status"), broker.status("agent", "site", "status"),
                   broker.task("agent", task["task_id"])):
        assert "diagnostics" not in json.dumps(result)
    broker.advance(task["task_id"])
    assert broker.task("agent", task["task_id"])["blocked"]["challenge"]["id"] == challenge["id"]
    assert calls == ["site"] and broker.store.pending("site")[0]["id"] == challenge["id"]
    assert broker.store.get("connection:site") is None
    assert broker.store.config().model_dump() == before
    assert diagnostics.owner_view(broker.store.config(), "site", broker.store.pending("site"), record) == {
        "challenge_id": challenge["id"], "diagnostics": structural()}


@pytest.mark.parametrize("change", ["stale", "future", "replaced", "resolved", "changed-spec",
                                     "operation", "account", "reason", "malformed"])
def test_owner_projection_excludes_stale_replaced_resolved_or_changed_binding(isolated, monkeypatch, change):
    broker, _ = isolated
    failed_read(monkeypatch, broker)
    broker.run("agent", "site", "status")
    record = broker.store.get(diagnostics.PREFIX + "site")
    pending = broker.store.pending("site")
    config = broker.store.config()
    if change == "stale":
        record["recorded_at"] -= diagnostics.MAX_AGE + 1
    elif change == "future":
        record["recorded_at"] += 1000
    elif change == "replaced":
        pending[0]["id"] = "replacement"
    elif change == "resolved":
        pending[0]["resolved"] = record["recorded_at"]
    elif change == "changed-spec":
        config.accounts["site"].ready_selector = "#changed-ready-marker"
    elif change == "operation":
        record["operation"] = "unapproved-operation"
    elif change == "account":
        record["account"] = "other-account"
    elif change == "reason":
        record["reason"] = "browser_email_required"
    else:
        record["diagnostics"]["fields"]["password"] = "private-value"
    assert diagnostics.owner_view(config, "site", pending, record) is None


def stopped_browser(monkeypatch, broker, *, fail_capture=False):
    """Exercise Browser.read's real stop/callback boundary without any navigation."""
    calls = []
    context = SimpleNamespace(_login_progress={})
    page = SimpleNamespace(context=context, url="https://www.namecheap.com/myaccount/login/",
                           goto=lambda *args, **kwargs: calls.append("configured-navigation"))
    launched = SimpleNamespace(close=lambda: calls.append("closed"))

    @contextmanager
    def playwright():
        yield SimpleNamespace(chromium=SimpleNamespace(launch=lambda **kwargs: launched))

    def check(*_args):
        raise AccessError("NEEDS_USER", "browser_state_unrecognized", "unknown")

    def capture(*_args):
        calls.append("capture")
        if fail_capture:
            raise ValueError("private collector error must not escape")
        return structural()

    monkeypatch.setattr("account_access.browser.sync_playwright", playwright)
    monkeypatch.setattr(broker.browser, "context", lambda *args, **kwargs: context)
    monkeypatch.setattr(broker.browser, "page", lambda *_args: page)
    monkeypatch.setattr(broker.browser, "wait_state", lambda *args, **kwargs: None)
    monkeypatch.setattr(broker.browser, "check", check)
    monkeypatch.setattr(broker.browser, "challenge", lambda *args: None)
    monkeypatch.setattr(diagnostics, "capture", capture)
    return calls


@pytest.mark.parametrize("fail_capture", [False, True])
def test_live_page_is_captured_once_and_collector_refusal_preserves_failure(isolated, monkeypatch, fail_capture):
    broker, _ = isolated
    calls = stopped_browser(monkeypatch, broker, fail_capture=fail_capture)
    result = broker.run("agent", "site", "status")
    assert result["status"] == "NEEDS_USER" and result["reason"] == "browser_state_unrecognized"
    assert result["challenge"]["kind"] == "unknown"
    assert calls == ["configured-navigation", "capture", "closed"]
    record = broker.store.get(diagnostics.PREFIX + "site")
    assert (record is None) == fail_capture
    assert broker.run("agent", "site", "status")["challenge"]["id"] == result["challenge"]["id"]
    assert calls == ["configured-navigation", "capture", "closed"]


def test_owner_state_projects_snapshot_but_agent_token_cannot_read_it(isolated, monkeypatch):
    from account_access import owner

    broker, agent_token = isolated
    failed_read(monkeypatch, broker)
    challenge = broker.run("agent", "site", "status")["challenge"]

    class NoNetworkServer:
        def __init__(self, _address, handler):
            self.server_port = 43210
            self.RequestHandlerClass = handler

    monkeypatch.setattr(owner, "ThreadingHTTPServer", NoNetworkServer)
    monkeypatch.setattr("account_access.phone.PhoneRelay.restore", lambda _self: None)
    monkeypatch.setattr("account_access.bitwarden_source.available", lambda _store: False)
    server, owner_token = owner.make_owner_server(broker)
    handler = server.RequestHandlerClass.__new__(server.RequestHandlerClass)
    handler.server, handler.path = server, "/owner/state"
    output = []
    handler.send = lambda status, body: output.append((status, body))
    handler.headers = {"Host": "127.0.0.1:43210", "Authorization": "Bearer " + agent_token}
    handler.do_GET()
    assert output.pop() == (401, {"status": "DENIED", "reason": "owner_authorization_required"})
    handler.headers["Authorization"] = "Bearer " + owner_token
    handler.do_GET()
    status, state = output.pop()
    assert status == 200
    assert state["accounts"][0]["challenges"] == [{**challenge, "diagnostics": structural()}]
    assert "diagnostics" not in json.dumps(broker.challenge_view(broker.store.pending("site")[0]))
    broker.store.resolve_login("site")
    handler.do_GET()
    assert output.pop()[1]["accounts"][0]["challenges"] == []


def test_invalid_or_failed_record_publication_never_changes_pending_gate(isolated, monkeypatch):
    broker, _ = isolated
    failed_read(monkeypatch, broker)
    original = broker.store.put

    def refuse(key, *args, **kwargs):
        if key.startswith(diagnostics.PREFIX):
            raise OSError("fictional publication refusal")
        return original(key, *args, **kwargs)

    monkeypatch.setattr(broker.store, "put", refuse)
    result = broker.run("agent", "site", "status")
    assert result["status"] == "NEEDS_USER" and result["challenge"]["kind"] == "unknown"
    assert broker.store.pending("site")[0]["id"] == result["challenge"]["id"]
    assert broker.store.get(diagnostics.PREFIX + "site") is None


def test_current_challenge_keeps_first_evidence_and_changed_configuration_cannot_publish(isolated, monkeypatch):
    broker, _ = isolated
    failed_read(monkeypatch, broker)
    challenge = broker.run("agent", "site", "status")["challenge"]
    original = broker.store.get(diagnostics.PREFIX + "site")
    changed = structural()
    changed["page"] = "origin_0:/login"
    assert not diagnostics.remember(broker.store, "site", "status", original["fingerprint"], challenge,
        {"status": "NEEDS_USER", "kind": "unknown", "reason": "browser_state_unrecognized", "diagnostics": changed})
    assert broker.store.get(diagnostics.PREFIX + "site") == original
    broker.store.resolve_login("site")

    def changed_during_attempt(account, operation, config, **kwargs):
        kwargs["on_attention"]("NEEDS_USER", "browser_state_unrecognized", "unknown", structural())
        edited = broker.store.config()
        edited.accounts[account].ready_selector = "#changed-during-attempt"
        broker.store.configure(edited)
        raise AccessError("NEEDS_USER", "browser_state_unrecognized", "unknown")

    monkeypatch.setattr(broker.browser, "read", changed_during_attempt)
    result = broker.run("agent", "site", "status")
    assert result["status"] == "NEEDS_USER" and result["challenge"]["id"] != challenge["id"]
    assert broker.store.get(diagnostics.PREFIX + "site") == original
    assert diagnostics.owner_view(broker.store.config(), "site", broker.store.pending("site"), original) is None


def test_ordinary_github_operation_does_not_activate_legacy_owner_collector(isolated, monkeypatch):
    broker, _ = isolated
    config = broker.store.config()
    config.accounts["site"].login_url = "https://github.com/login"
    broker.store.configure(config)
    broker.grant("agent", "site", ["status"])
    calls = []

    def read(account, operation, spec, **kwargs):
        assert kwargs["on_attention"] is None
        calls.append(account)
        raise AccessError("NEEDS_USER", "browser_state_unrecognized", "unknown")

    monkeypatch.setattr(broker.browser, "read", read)
    result = broker.run("agent", "site", "status")
    assert result["status"] == "NEEDS_USER" and result["challenge"]["kind"] == "unknown"
    assert broker.store.get(diagnostics.PREFIX + "site") is None and calls == ["site"]
