from contextlib import ExitStack
import io
import json
import queue
import struct
import threading
import time

import pytest

from playwright.sync_api import sync_playwright

from account_access.google_messages_host import RESOURCES, extension_id, run_host
from account_access.models import LoginFactor
from account_access.errors import AccessError
from test_google_messages import source
from test_google_messages_bridge import private_bridge


@pytest.mark.parametrize("tab_available,protected", [(True, False), (False, False), (True, True)])
def test_password_to_messages_reader_to_native_host_to_browser(env, monkeypatch, request, tab_available, protected):
    provider, broker, _ = env
    source(broker)
    config = broker.store.config()
    spec = config.accounts["demo-mfa"].model_copy(deep=True)
    spec.login_url = spec.login_url.replace("/mfa/", "/sms/")
    for name in ["login_resources", "login_post_urls", "read_resources"]:
        setattr(spec, name, [url.replace("/mfa/", "/sms/") for url in getattr(spec, name)])
    for operation in spec.operations.values():
        operation.url = operation.url.replace("/mfa/", "/sms/")
    spec.login.code_source = spec.login.code_selector = spec.login.code_submit_selector = None
    spec.login.factors = {
        "sms": LoginFactor(
            code_source="google-sms", code_selector="#code", code_submit_selector="#code-submit"
        )
    }
    spec.challenge_selectors.pop("totp")
    spec.challenge_selectors["sms"] = "#sms-challenge"
    config.accounts["google-login"] = spec
    broker.store.configure(config)
    broker.store.put("credential:google-login", broker.store.get("credential:demo-mfa"))
    broker.grant("test", "google-login", ["summary"])
    if not tab_available:

        def unavailable(*args):
            raise AccessError("RETRYABLE", "google_messages_tab_unavailable", "sms")

        monkeypatch.setattr(broker.codes, "begin", unavailable)
        result = broker.run("test", "google-login", "summary")
        assert result["status"] == "RETRYABLE" and provider.login_count == 0
        return
    origin = "chrome-extension://" + extension_id() + "/"
    broker.store.put("google-messages-extension-origin", origin)
    mailbox = queue.Queue()
    provider.delivery = lambda kind, code: mailbox.put(code) if kind == "sms" else None

    cleanup = ExitStack()
    request.addfinalizer(cleanup.close)
    bridge = cleanup.enter_context(private_bridge(broker)) if protected else None
    accepted_windows = set()
    def exchange(body):
        if bridge is not None:
            response = bridge.post("/owner/browser-message", json={"message": body})
            result = response.json()
            window = (body.get("source"), body.get("window"))
            if response.status_code == 403:
                # As in the extension/native protocol, a repeated poll may race
                # with successful consumption or final window cleanup. Only a
                # window whose first delivery succeeded may take this path.
                assert body["method"] == "deliver" and window in accepted_windows
                assert result["reason"] in {
                    "google_messages_window_finished", "login_code_window_missing",
                    "login_code_window_expired",
                }, result
            else:
                assert response.status_code == 200, result
                if body["method"] == "deliver":
                    assert result == {"status": "RECEIVED"}
                    accepted_windows.add(window)
            return result
        raw = json.dumps({"id": 1, "body": body}).encode()
        outgoing = io.BytesIO()
        assert (
            run_host(broker.store, io.BytesIO(struct.pack("=I", len(raw)) + raw), outgoing, origin)
            == 0
        )
        return json.loads(outgoing.getvalue()[4:])["result"]

    fixture = """<mws-conversations-list><nav><mws-conversation-list-item><a data-e2e-conversation href="/web/conversations/cached"></a>
        <mws-conversation-snippet>111111 is your GitHub authentication code.</mws-conversation-snippet>
        <mws-relative-timestamp><div aria-label="Now"></div></mws-relative-timestamp></mws-conversation-list-item></nav></mws-conversations-list>"""
    result = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(chromium_sandbox=True)
        context = browser.new_context()
        context.route("**/*", lambda route: route.fulfill(body=fixture, content_type="text/html"))
        page = context.new_page()
        page.goto("https://messages.google.com/web/conversations")
        page.evaluate("""() => {window.chrome={runtime:{id:'fixture',onMessage:{addListener:handler=>window.receive=handler}}};
            window.pollSMS=request=>new Promise(resolve=>window.receive({method:'poll',request},{id:'fixture'},resolve));}""")
        page.add_script_tag(path=RESOURCES / "reader.js")
        worker = threading.Thread(
            target=lambda: result.append(broker.run("test", "google-login", "summary"))
        )
        worker.start()
        deadline = time.monotonic() + 25
        while worker.is_alive() and time.monotonic() < deadline:
            try:
                incoming = mailbox.get_nowait()
                page.evaluate(
                    """code=>{const row=document.querySelector('mws-conversation-list-item').cloneNode(true);
                    row.querySelector('a').setAttribute('href','/web/conversations/current');
                    row.querySelector('mws-conversation-snippet').textContent=code+' is your GitHub authentication code.';
                    document.querySelector('nav').prepend(row);}""",
                    incoming,
                )
            except queue.Empty:
                pass
            for pending in exchange({"method": "pending"}).get("pending", []):
                snapshot = page.evaluate("request=>window.pollSMS(request)", pending)
                base = {"source": pending["source"], "window": pending["window"]}
                if snapshot.get("armed"):
                    assert provider.login_count == 0
                    exchange({"method": "armed", **base})
                if snapshot.get("candidates"):
                    exchange({"method": "deliver", **base, "messages": snapshot["candidates"]})
            page.wait_for_timeout(50)
        worker.join(timeout=5)
        browser.close()
    assert not worker.is_alive()
    assert result and result[0]["status"] == "COMPLETED"
    assert provider.login_count == 1 and provider.sms_count == 1
    assert provider.last_login_code not in json.dumps(result)
    cleanup.close()
