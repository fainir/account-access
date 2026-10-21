import json
import threading
import time
from contextlib import contextmanager

import httpx2 as httpx
import pytest
from playwright.sync_api import sync_playwright

from account_access.demo import DEMO_PASSWORD
from account_access.errors import AccessError
from account_access.factors import enroll
from account_access.mailboxes import check, connect, link, remove, update_password, view
from account_access.mailbox_health import check as check_source, view as source_health
from account_access.models import CodeSource, TaskRequest
from account_access.owner import make_owner_server
from account_access.verification_demo import environment, write_password_export


def data(mailbox):
    return {"label": "Example email", "host": "127.0.0.1", "port": mailbox.port,
            "username": "demo@example.test", "password": DEMO_PASSWORD}


def test_mailbox_can_connect_before_a_website_and_does_not_grant_agent_access(tmp_path):
    with environment(tmp_path) as (provider, broker, mailbox):
        config = broker.store.config().model_dump()
        client = broker.store.new_client("fixture")
        before = broker.accounts("fixture")
        saved = connect(broker, data(mailbox))
        assert saved["connection_check"]["status"] == "VERIFIED" and saved["login_delivery_verified"] is False
        assert mailbox.fetches == provider.login_count == 0
        assert broker.accounts("fixture") == before
        assert broker.store.client(client) == "fixture"
        assert broker.store.config().model_dump() == config
        assert DEMO_PASSWORD not in json.dumps(saved) + json.dumps(view(broker.store))
        assert DEMO_PASSWORD.encode() not in broker.store.path.read_bytes()
        assert check(broker, saved["id"])["status"] == "VERIFIED"
        assert mailbox.fetches == provider.login_count == 0


def test_one_mailbox_supplies_multiple_exact_approved_sources_and_session_recovery(tmp_path):
    with environment(tmp_path) as (provider, broker, mailbox):
        saved = connect(broker, data(mailbox))
        config = broker.store.config()
        config.code_sources["second-email"] = config.code_sources["example-email"].model_copy(deep=True)
        broker.store.configure(config)
        for source in ["example-email", "second-email"]:
            assert enroll(broker.store, source, {"mailbox": saved["id"]})["status"] == "ENROLLED"
            assert check_source(broker, source)["status"] == "VERIFIED"
        broker.store.put("credential:example-email", {"username": "demo@example.test", "password": DEMO_PASSWORD})
        broker.store.new_client("fixture")
        broker.grant("fixture", "example-email", ["summary"])
        for _ in range(2):
            result = broker.run("fixture", "example-email", "summary")
            assert result["status"] == "COMPLETED", result
        assert provider.login_count == provider.email_count == 1 and mailbox.fetches == 1
        assert DEMO_PASSWORD not in json.dumps(result)
        assert broker.store.get("source:example-email") == {"mailbox": saved["id"], "enabled": True}
        remove(broker.store, saved["id"])
        assert view(broker.store) == [] and source_health(broker.store, "example-email")["status"] == "UNTESTED"
        assert broker.run("fixture", "example-email", "summary")["status"] == "COMPLETED"  # Existing website session.
        provider.sessions.clear()
        broker.store.put("login-attempt:example-email", 0)
        result = broker.run("fixture", "example-email", "summary")
        assert result["reason"] == "mailbox_not_connected"
        assert provider.login_count == 1  # No new password submission without the mailbox.


@pytest.mark.parametrize("change", ["host", "port", "recipient", "kind"])
def test_mailbox_link_cannot_widen_server_recipient_or_source_kind(tmp_path, change):
    with environment(tmp_path) as (_, broker, mailbox):
        saved = connect(broker, data(mailbox))
        config = broker.store.config()
        source = config.code_sources["example-email"]
        if change == "host":
            source.host = "different.example.test"
        elif change == "port":
            source.port += 1
        elif change == "recipient":
            source.recipient = "different@example.test"
        else:
            config.code_sources["example-email"] = CodeSource(kind="totp")
        broker.store.configure(config)
        before = broker.store.config().model_dump()
        with pytest.raises(AccessError, match="mailbox_source_mismatch"):
            link(broker.store, "example-email", saved["id"])
        assert broker.store.get("source:example-email") is None
        assert broker.store.config().model_dump() == before


@pytest.mark.parametrize("change", ["remove", "password", "source"])
def test_pending_code_window_stops_after_linked_mailbox_changes(tmp_path, change):
    with environment(tmp_path) as (_, broker, mailbox):
        saved = connect(broker, data(mailbox))
        link(broker.store, "example-email", saved["id"])
        started = time.time() - 1
        broker.codes.begin("example-email", "example-email", started)
        mailbox.deliver("123456")
        if change == "remove":
            remove(broker.store, saved["id"])
        elif change == "password":
            result = update_password(broker, saved["id"], "wrong-example-password")
            assert result["connection_check"]["status"] == "NEEDS_USER"
        else:
            config = broker.store.config()
            config.code_sources["example-email"].recipient = "different@example.test"
            broker.store.configure(config)
        with pytest.raises(AccessError):
            broker.codes.resolve("example-email", started, set())
        assert mailbox.fetches == 0


def test_failed_mailbox_setup_is_saved_for_local_repair_without_false_success(tmp_path):
    with environment(tmp_path) as (provider, broker, mailbox):
        saved = connect(broker, {**data(mailbox), "password": "wrong-example-password"})
        assert saved["status"] == "SAVED" and saved["connection_check"]["status"] == "NEEDS_USER"
        assert view(broker.store)[0]["connection_check"]["reason"] == "mailbox_connection_failed"
        with pytest.raises(AccessError, match="mailbox_already_connected"):
            connect(broker, data(mailbox))
        repaired = update_password(broker, saved["id"], DEMO_PASSWORD)
        assert repaired["connection_check"]["status"] == "VERIFIED"
        assert mailbox.fetches == provider.login_count == 0
        assert DEMO_PASSWORD not in json.dumps(repaired) + json.dumps(view(broker.store))


def test_rechecking_mailbox_health_does_not_interrupt_a_pending_login(tmp_path):
    with environment(tmp_path) as (_, broker, mailbox):
        saved = connect(broker, data(mailbox))
        link(broker.store, "example-email", saved["id"])
        started = time.time() - 1
        broker.codes.begin("example-email", "example-email", started)
        assert check(broker, saved["id"])["status"] == "VERIFIED"
        mailbox.deliver("123456")
        assert broker.codes.resolve("example-email", started, set()) == "123456"
        assert mailbox.fetches == 1


def test_mailbox_outage_recovers_the_original_task_without_owner_input(tmp_path, monkeypatch):
    with environment(tmp_path) as (provider, broker, mailbox):
        saved = connect(broker, data(mailbox))
        link(broker.store, "example-email", saved["id"])
        broker.store.new_client("fixture")
        broker.grant("fixture", "example-email", ["summary"])
        broker.store.put("credential:example-email", {"username": "demo@example.test", "password": DEMO_PASSWORD})
        original = broker.codes.mailbox
        offline = True

        @contextmanager
        def flaky(*args):
            nonlocal offline
            if offline:
                offline = False
                raise TimeoutError("fictional-private-network-detail")
            with original(*args) as connection:
                yield connection

        monkeypatch.setattr(broker.codes, "mailbox", flaky)
        task = broker.submit("fixture", TaskRequest.model_validate({"key": "mailbox-recovers-without-owner",
            "steps": [{"account": "example-email", "operation": "summary"}]}))
        broker.tick()
        waiting = broker.task("fixture", task["task_id"])
        assert waiting["status"] == "RETRYABLE" and waiting["blocked"]["reason"] == "mailbox_temporarily_unavailable"
        assert broker.store.pending("example-email") == [] and provider.login_count == 0
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            broker.tick()
            result = broker.task("fixture", task["task_id"])
            if result["status"] == "COMPLETED":
                break
            time.sleep(.05)
        assert result["status"] == "COMPLETED", result
        assert result["task_id"] == task["task_id"]
        assert provider.login_count == provider.email_count == mailbox.fetches == 1
        assert broker.store.pending("example-email") == []


@pytest.mark.parametrize("field,value", [("host", "https://imap.example.test/"), ("host", "imap.example.test/path"),
                                       ("username", "invalid"), ("username", "a@example.test\r\nother"),
                                       ("port", True), ("password", "")])
def test_mailbox_setup_rejects_invalid_destinations_and_credentials(tmp_path, field, value):
    with environment(tmp_path) as (_, broker, mailbox):
        with pytest.raises(AccessError, match="invalid_mailbox_setup"):
            connect(broker, {**data(mailbox), field: value})
        assert view(broker.store) == []


def test_mailbox_routes_are_owner_only_and_do_not_accept_identity_changes(tmp_path):
    with environment(tmp_path) as (provider, broker, mailbox):
        agent = broker.store.new_client("fixture")
        server, token = make_owner_server(broker, guided=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        headers = {"Authorization": "Bearer " + token, "Origin": base}
        try:
            with httpx.Client(base_url=base, trust_env=False) as client:
                for wrong in [{}, {"Authorization": "Bearer " + agent, "Origin": base},
                              {"Authorization": "Bearer " + token, "Origin": "https://other.example"}]:
                    assert client.post("/owner/mailbox/connect", json=data(mailbox), headers=wrong).status_code == 403
                saved = client.post("/owner/mailbox/connect", json=data(mailbox), headers=headers).json()
                assert saved["connection_check"]["status"] == "VERIFIED"
                state = client.get("/owner/state", headers=headers).json()
                assert state["mailboxes"][0]["id"] == saved["id"] and DEMO_PASSWORD not in json.dumps(state)
                assert client.post("/owner/mailbox/password", headers=headers,
                    json={"id": saved["id"], "password": DEMO_PASSWORD, "host": "other.example"}).status_code == 400
                for route in ["check", "password", "remove"]:
                    body = {"id": saved["id"], **({"password": DEMO_PASSWORD} if route == "password" else {})}
                    assert client.post("/owner/mailbox/" + route, json=body).status_code == 403
                    assert client.post("/owner/mailbox/" + route, json=body, headers=headers).status_code == 200
                assert provider.login_count == mailbox.fetches == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def test_owner_browser_connects_one_mailbox_then_completes_approved_email_login(tmp_path, monkeypatch):
    with environment(tmp_path) as (provider, broker, mailbox):
        monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
        broker.store.new_client("generic")
        server, token = make_owner_server(broker, guided=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        headers = {"Authorization": "Bearer " + token, "Origin": base}
        try:
            with httpx.Client(base_url=base, trust_env=False) as client:
                staged = client.post("/owner/import/preview", headers=headers,
                    json={"csv": write_password_export(tmp_path, broker.store.config()).read_text()}).json()
                imported = client.post("/owner/import/apply", headers=headers,
                    json={"id": staged["id"], "selections": [{"row": staged["rows"][0]["id"],
                        "account": "example-email", "operations": ["summary"]}]}).json()
                first_id = imported["jobs"][0]["id"]
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    state = client.get("/owner/state", headers=headers).json()
                    if state["connection_jobs"][first_id]["status"] != "RUNNING":
                        break
                    time.sleep(.05)
                assert state["connection_jobs"][first_id]["status"] == "NEEDS_USER"
                assert provider.login_count == 0
                assert not broker.store.get("login-attempt:example-email")
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
                    page = browser.new_page()
                    try:
                        page.goto(base + "/#" + token)
                        page.get_by_role("button", name="Verification", exact=True).click()
                        page.get_by_text("Connect Gmail or email", exact=True).click()
                        page.get_by_label("Email provider", exact=True).select_option(label="Other email · TLS IMAP")
                        page.get_by_label("Email address", exact=True).fill("demo@example.test")
                        page.get_by_label("Application password", exact=True).fill(DEMO_PASSWORD)
                        page.get_by_label("IMAP server", exact=True).fill("127.0.0.1")
                        page.get_by_label("TLS port", exact=True).fill(str(mailbox.port))
                        page.get_by_role("button", name="Connect mailbox", exact=True).click()
                        page.get_by_text("Email · demo@example.test", exact=True).wait_for()
                        assert provider.login_count == mailbox.fetches == 0
                        assert DEMO_PASSWORD not in page.locator("body").inner_text()
                        state = client.get("/owner/state", headers=headers).json()
                        mailbox_id = state["mailboxes"][0]["id"]
                        assert page.get_by_label("Use a connected mailbox", exact=True).input_value() == mailbox_id
                        source_card = page.locator(".account").filter(has=page.get_by_text("Example EMAIL verification account", exact=True))
                        source_card.get_by_role("button", name="Enable verification", exact=True).click()
                        deadline = time.monotonic() + 20
                        while time.monotonic() < deadline:
                            state = client.get("/owner/state", headers=headers).json()
                            if any(job["status"] == "CONNECTED" for job in state["connection_jobs"].values()):
                                break
                            time.sleep(.1)
                        assert any(job["status"] == "CONNECTED" for job in state["connection_jobs"].values())
                        assert provider.login_count == provider.email_count == mailbox.fetches == 1
                    finally:
                        browser.close()
                result = broker.run("generic", "example-email", "summary")
                assert result["status"] == "COMPLETED", result
                assert provider.login_count == 1
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
