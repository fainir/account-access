import io
import json
import struct
import threading
import time

import pytest
from playwright.sync_api import sync_playwright

from account_access.codes import Codes
from account_access.errors import AccessError
from account_access.google_messages import TEMPLATE, connect, handle
from account_access.google_messages_host import RESOURCES, extension_id, prepare, run_host
from account_access.models import CodeSource


def source(broker):
    config = broker.store.config()
    config.code_sources["google-sms"] = CodeSource(
        kind="google_messages",
        sender="github-login-rotating-senders",
        recipient="paired-google-messages",
        template=TEMPLATE,
    )
    broker.store.configure(config)
    broker.store.put("source:google-sms", {"enabled": True})
    return Codes(broker.store, None)


def test_sms_extension_has_no_site_access_until_owner_connects():
    manifest = json.loads((RESOURCES / "manifest.json").read_text())
    assert set(manifest["permissions"]) == {"nativeMessaging", "storage", "alarms", "scripting"}
    assert manifest["optional_host_permissions"] == ["https://messages.google.com/*"]
    assert not manifest.get("host_permissions") and not manifest.get("content_scripts")


def test_sms_extension_loads_with_its_registered_identity_without_site_access(tmp_path):
    with sync_playwright() as pw:
        context = pw.chromium.launch_persistent_context(
            str(tmp_path / "isolated-browser"),
            headless=True,
            channel="chromium",
            chromium_sandbox=True,
            args=[
                "--disable-extensions-except=" + str(RESOURCES),
                "--load-extension=" + str(RESOURCES),
            ],
        )
        worker = (
            context.service_workers[0]
            if context.service_workers
            else context.wait_for_event("serviceworker", timeout=10000)
        )
        assert worker.evaluate("chrome.runtime.id") == extension_id()
        assert not worker.evaluate("chrome.permissions.getAll()").get("origins")
        context.close()


def test_google_messages_revocation_removes_delivery_authority(env):
    from account_access.factors import revoke

    _, broker, _ = env
    _, _, base = armed(broker)
    revoke(broker.store, "google-sms")
    assert handle(broker.store, {"method": "pending"}) == {"pending": [], "source_enabled": False}
    with pytest.raises(AccessError):
        handle(broker.store, delivery(base))


def armed(broker):
    codes = source(broker)
    started = time.time()
    errors = []

    def begin():
        try:
            codes.begin("google-sms", "demo-web", started)
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=begin)
    worker.start()
    deadline = time.monotonic() + 3
    pending = []
    while time.monotonic() < deadline and not pending:
        pending = handle(broker.store, {"method": "pending"})["pending"]
        time.sleep(0.01)
    assert len(pending) == 1
    request = pending[0]
    assert request["phase"] == "baseline" and "code" not in request
    base = {"source": request["source"], "window": request["window"]}
    handle(broker.store, {"method": "armed", **base})
    worker.join(timeout=3)
    assert not worker.is_alive() and not errors
    return codes, started, base


def delivery(base, code="123456", ident="a" * 64, observed=None):
    return {
        "method": "deliver",
        **base,
        "messages": [
            {
                "id": ident,
                "code": code,
                "observed_at": time.time() if observed is None else observed,
            }
        ],
    }


def test_google_messages_waits_for_baseline_and_consumes_locally_once(env):
    _, broker, _ = env
    codes, started, base = armed(broker)
    result = handle(broker.store, delivery(base))
    assert result == {"status": "RECEIVED"} and "123456" not in str(result)
    handle(broker.store, delivery(base))  # A lost acknowledgement cannot duplicate a message.
    assert codes.resolve("google-sms", started, set()) == "123456"
    assert handle(broker.store, {"method": "pending"}) == {"pending": [], "source_enabled": True}
    with pytest.raises(AccessError, match="finished"):
        handle(broker.store, delivery(base, ident="b" * 64))
    codes.finish("google-sms", started)
    assert handle(broker.store, {"method": "pending"}) == {"pending": [], "source_enabled": True}


@pytest.mark.parametrize(
    "change",
    [
        "wrong_window",
        "before_start",
        "future",
        "nonfinite",
        "bad_code",
        "revoked",
        "expired",
        "changed",
        "lost",
    ],
)
def test_google_messages_rejects_stale_or_unbound_delivery(env, change):
    _, broker, _ = env
    codes, started, base = armed(broker)
    message = delivery(base)
    if change == "wrong_window":
        message["window"] = "0" * 32
    if change == "before_start":
        message["messages"][0]["observed_at"] = started - 1
    if change == "future":
        message["messages"][0]["observed_at"] = time.time() + 60
    if change == "nonfinite":
        message["messages"][0]["observed_at"] = float("nan")
    if change == "bad_code":
        message["messages"][0]["code"] = "payment"
    if change == "revoked":
        broker.store.put("source:google-sms", {"enabled": False})
    if change == "changed":
        broker.store.put("source:google-sms", {"enabled": True, "changed": True})
    if change == "expired":
        current = broker.store.get("code-window:google-sms")
        current["expires"] = time.time() - 1
        broker.store.put("code-window:google-sms", current)
    if change == "lost":
        handle(broker.store, {"method": "lost", **base})
    with pytest.raises(AccessError):
        handle(broker.store, message)
    assert not broker.store.get("code-window:google-sms")["incoming"]


def test_google_messages_ambiguity_is_committed_as_one_batch(env):
    _, broker, _ = env
    codes, started, base = armed(broker)
    message = delivery(base)
    message["messages"] += delivery(base, "654321", "b" * 64)["messages"]
    handle(broker.store, message)
    with pytest.raises(AccessError, match="ambiguous_login_code"):
        codes.resolve("google-sms", started, set())


def test_google_messages_connection_preserves_existing_read_permissions(env):
    from test_sms_setup import pilot

    _, broker, _ = env
    config = pilot(broker)
    previous = config.accounts["github-pilot"].model_copy(deep=True)
    with broker.store.db() as db:
        grants = [
            dict(row) for row in db.execute("SELECT * FROM grants WHERE account='github-pilot'")
        ]
    assert (
        connect(broker.store, "github-pilot", config.fingerprint("github-pilot"))["status"]
        == "CONNECTED"
    )
    updated = broker.store.config()
    factor = updated.accounts["github-pilot"].login.factor("sms")
    assert updated.code_sources[factor.code_source].kind == "google_messages"
    assert updated.accounts["github-pilot"].operations == previous.operations
    with broker.store.db() as db:
        assert [
            dict(row) for row in db.execute("SELECT * FROM grants WHERE account='github-pilot'")
        ] == [{**row, "fingerprint": updated.fingerprint("github-pilot")} for row in grants]
    assert handle(broker.store, {"method": "accounts"})["accounts"][0]["connected"]


def test_google_messages_host_is_exact_origin_and_never_echoes_input(env, tmp_path):
    _, broker, _ = env
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    info = prepare(broker.store, home=home)
    assert info["extension_id"] == extension_id()
    manifests = list(home.rglob("com.account_access.google_messages.json"))
    manifest = json.loads(manifests[0].read_text())
    expected = "chrome-extension://" + extension_id() + "/"
    assert manifest["allowed_origins"] == [expected]
    incoming = {"id": 1, "body": {"method": "read_inbox", "code": "123456"}}
    raw = json.dumps(incoming).encode()
    framed = struct.pack("=I", len(raw)) + raw
    output = io.BytesIO()
    assert run_host(broker.store, io.BytesIO(framed), output, "chrome-extension://other/") == 2
    assert not output.getvalue()
    assert run_host(broker.store, io.BytesIO(framed), output, expected) == 0
    assert b"123456" not in output.getvalue() and b"DENIED" in output.getvalue()
    assert (
        run_host(broker.store, io.BytesIO(struct.pack("=I", 100_000)), io.BytesIO(), expected) == 2
    )


@pytest.mark.parametrize(
    "change",
    ["new", "same_thread", "cached", "old", "scroll", "multiple", "localized", "changed_page"],
)
def test_google_messages_reader_rejects_cached_changed_or_unrecognized_messages(change):
    fixture = """<mws-conversations-list><nav><mws-conversation-list-item><a data-e2e-conversation href="/web/conversations/old"></a>
        <mws-conversation-snippet>111111 is your GitHub authentication code.</mws-conversation-snippet>
        <mws-relative-timestamp><div aria-label="Now"></div></mws-relative-timestamp></mws-conversation-list-item></nav></mws-conversations-list>"""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(chromium_sandbox=True)
        context = browser.new_context()
        context.route("**/*", lambda route: route.fulfill(body=fixture, content_type="text/html"))
        page = context.new_page()
        page.goto("https://messages.google.com/web/conversations")
        page.evaluate("""() => { window.chrome = {runtime:{id:'fixture',onMessage:{addListener:handler=>window.receive=handler}}};
            window.pollSMS = request => new Promise(resolve=>window.receive({method:'poll',request},{id:'fixture'},resolve)); }""")
        page.add_script_tag(path=RESOURCES / "reader.js")
        request = {
            "window": "a" * 32,
            "template": TEMPLATE,
            "phase": "baseline",
            "expires": time.time() + 120,
        }
        assert page.evaluate("request=>window.pollSMS(request)", request) == {"armed": True}
        request["phase"] = "watch"
        assert page.evaluate("request=>window.pollSMS(request)", request) == {"candidates": []}
        if change in {"new", "old", "multiple", "localized"}:
            page.evaluate(
                """change => {const row = document.querySelector('mws-conversation-list-item').cloneNode(true);
                row.querySelector('a').setAttribute('href','/web/conversations/new');
                row.querySelector('mws-conversation-snippet').textContent='222222 is your GitHub authentication code.';
                row.querySelector('[aria-label]').setAttribute('aria-label', change==='old'?'30 min ago':change==='localized'?'unrecognized':'Now');
                document.querySelector('nav').prepend(row);
                if(change==='multiple'){const second=row.cloneNode(true);second.querySelector('a').setAttribute('href','/web/conversations/second');second.querySelector('mws-conversation-snippet').textContent='333333 is your GitHub authentication code.';document.querySelector('nav').prepend(second);}}""",
                change,
            )
        if change == "same_thread":
            page.locator("mws-conversation-snippet").evaluate(
                "e=>e.textContent='222222 is your GitHub authentication code.'"
            )
        if change == "scroll":
            page.evaluate("document.dispatchEvent(new Event('scroll'))")
        if change == "changed_page":
            page.evaluate("history.replaceState(null,'','/web/conversations/another')")
        result = page.evaluate("request=>window.pollSMS(request)", request)
        if change in {"new", "same_thread"}:
            assert [item["code"] for item in result["candidates"]] == ["222222"]
        elif change == "multiple":
            assert len(result["candidates"]) == 2
        elif change == "scroll":
            assert result == {"lost": True}
        elif change == "changed_page":
            assert result == {"unavailable": True}
        else:
            assert result == {"candidates": []}
        browser.close()
