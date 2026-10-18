"""Disposable Mac CI: signed Chrome transport and a synthetic SMS runtime join.

The exact packaged extension runs in a new, empty profile under the temporary
agent UID. Chrome launches the existing hash-pinned fixture Mach-O directly.
The second empty profile uses a narrowly changed fixture manifest to represent
an already approved Messages permission. Its unchanged production scripts read
an in-memory HTTPS fixture, then deliver through the real native/XPC boundary.
No owner profile, permission approval, private account or external site is used.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import select
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

from account_access.storage import private_file
from account_access.worker_bootstrap import root_managed_path

CHROME_APP = "/Applications/Google Chrome.app"
CHROME_BINARY = CHROME_APP + "/Contents/MacOS/Google Chrome"
CHROME_REQUIREMENT = (
    'anchor apple generic and identifier "com.google.Chrome" '
    'and certificate leaf[subject.OU] = "EQHXZ8M8AV" '
    'and !(entitlement["com.apple.security.get-task-allow"] exists)'
)
EXTENSION_ID = "nidjfmpcbbneapibefbhniaiijgigofo"
EXTENSION_ORIGIN = "chrome-extension://" + EXTENSION_ID + "/"
HOST = "com.account_access.google_messages"
RESOURCES = {"manifest.json", "background.js", "reader.js", "popup.js", "popup.html", "popup.css"}
PROFILE_NAME = "signed-chrome-profile"
SMS_PROFILE_NAME = "signed-chrome-sms-profile"
SMS_EXTENSION_NAME = "signed-chrome-sms-extension"
MESSAGES_ORIGIN = "https://messages.google.com/*"
MESSAGES_URL = "https://messages.google.com/web/conversations"
SMS_ACCOUNT = "chrome-sms"
OUTPUT_LIMIT = 65536
# Each Client.request permits 60 seconds. Account for Python startup/output
# draining per sequential child, rather than sharing a shorter 55-second cap.
CLI_READ_SECONDS = 60 + 10
CLI_READS_SECONDS = 2 * CLI_READ_SECONDS
CHILD_SECONDS = 90 + CLI_READS_SECONDS
STAGES = {"guard", "profile", "signature", "negative-parent", "launch", "load", "first-pending", "reload",
          "sms-launch", "sms-load", "sms-dom", "sms-login", "sms-cleanup", "cleanup"}
CURRENT_STAGE = "guard"
SMS_FAILURE_PROGRESS = None
SMS_FAILURE_DETAILS = None
HTTP_ERROR_CLASSES = {
    "ConnectTimeout", "ReadTimeout", "WriteTimeout", "PoolTimeout", "ConnectError",
    "ReadError", "WriteError", "CloseError", "RemoteProtocolError", "LocalProtocolError",
    "ProxyError", "UnsupportedProtocol", "DecodingError", "TooManyRedirects", "HTTPError",
}
HTTP_STAGES = {"unavailable", "started", "completed", "http_error"}
HTTP_DIAGNOSTIC = "signed-chrome-cli-http.json"
FAILURES = {
    "browser_fixture_cli_failed", "browser_fixture_cli_login_retry_cooldown",
    "browser_fixture_cli_google_messages_tab_unavailable", "browser_fixture_cli_google_messages_tab_reloaded",
    "browser_fixture_cli_google_messages_not_connected", "browser_fixture_cli_service_unavailable",
    "browser_fixture_deadline_expired", "signed_chrome_fixture_delivery_invalid",
    "signed_chrome_sms_journey_failed",
}


def stage(value):
    global CURRENT_STAGE
    if value not in STAGES:
        raise RuntimeError("signed_chrome_invalid_diagnostic_stage")
    CURRENT_STAGE = value


def require_fixture(prefix, roles=None, *, child=False):
    if (
        sys.platform != "darwin"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.getuid() != os.geteuid()
        or (os.getuid() == 0) == child
    ):
        raise RuntimeError("signed_chrome_requires_disposable_mac_ci")
    if (
        prefix.parent != Path("/Library/PrivilegedHelperTools")
        or re.fullmatch(r"account-access-worker-qa-[A-Za-z0-9]{8}", prefix.name) is None
    ):
        raise RuntimeError("signed_chrome_requires_fixture_identity")
    agent = pwd.getpwuid(os.getuid()) if child else roles["agent"]
    if (
        agent.pw_uid == 0
        or agent.pw_dir != str(prefix / "agent-home")
        or (not child and agent.pw_uid == roles["broker"].pw_uid)
    ):
        raise RuntimeError("signed_chrome_requires_fixture_identity")
    root_managed_path(prefix)
    info = (prefix / "agent-home").lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != agent.pw_uid or info.st_mode & 0o777 != 0o700:
        raise RuntimeError("signed_chrome_requires_fixture_identity")
    return agent


def native_manifest(binary):
    return {"name": HOST, "description": "Account Access disposable signed-Chrome check",
            "path": str(binary), "type": "stdio", "allowed_origins": [EXTENSION_ORIGIN]}


def launch_options(profile, home):
    return {
        "user_data_dir": str(profile), "executable_path": CHROME_BINARY,
        "headless": True, "chromium_sandbox": True,
        "ignore_default_args": ["--disable-extensions"],
        "args": ["--enable-unsafe-extension-debugging", "--password-store=basic", "--use-mock-keychain"],
        "env": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home),
                "TMPDIR": str(home / "signed-chrome-tmp"), "GITHUB_ACTIONS": "true"},
        "timeout": 25000,
    }


def resource_hashes(extension):
    if {item.name for item in extension.iterdir()} != RESOURCES:
        raise RuntimeError("signed_chrome_extension_resources_changed")
    hashes = {}
    for name in sorted(RESOURCES):
        target = root_managed_path(extension / name)
        if not target.is_file() or target.stat().st_size > 131072:
            raise RuntimeError("signed_chrome_extension_resources_changed")
        hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    return hashes


def fixture_manifest(original):
    """A declared CI enrollment substitute, never an installed product change."""
    if (
        type(original) is not dict or "host_permissions" in original
        or original.get("optional_host_permissions") != [MESSAGES_ORIGIN, "https://github.com/*"]
    ):
        raise RuntimeError("signed_chrome_fixture_manifest_changed")
    value = dict(original)
    value["optional_host_permissions"] = ["https://github.com/*"]
    value["host_permissions"] = [MESSAGES_ORIGIN]
    return value


def validate_fixture_manifest(original, candidate):
    return candidate == fixture_manifest(original)


def sms_page():
    # The cached row must remain the baseline boundary when the fresh row is
    # prepended. Neither this document nor its relative links contact Google.
    return """<!doctype html><meta charset="utf-8"><title>Controlled SMS fixture</title>
    <mws-conversations-list><nav><mws-conversation-list-item>
    <a data-e2e-conversation href="/web/conversations/cached-fixture"></a>
    <mws-conversation-snippet>111111 is your GitHub authentication code.</mws-conversation-snippet>
    <mws-relative-timestamp><span aria-label="10 min ago"></span></mws-relative-timestamp>
    </mws-conversation-list-item></nav></mws-conversations-list>"""


def fictional_message(raw):
    if type(raw) is not dict or set(raw) != {"code"} or type(raw["code"]) is not str or not re.fullmatch(r"[0-9]{6}", raw["code"]):
        raise RuntimeError("signed_chrome_fixture_delivery_invalid")
    return raw["code"]


def http_diagnostic(value):
    if (type(value) is not dict or set(value) != {"stage", "error"}
            or type(value["stage"]) is not str or value["stage"] not in HTTP_STAGES
            or type(value["error"]) is not str
            or (value["stage"] == "http_error" and value["error"] not in HTTP_ERROR_CLASSES)
            or (value["stage"] != "http_error" and value["error"] != "none")):
        return None
    return value.copy()


def read_http_diagnostic(home):
    empty = {"stage": "unavailable", "error": "none"}
    try:
        path = home / "signed-chrome-tmp" / HTTP_DIAGNOSTIC
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or not 0 < info.st_size <= 512):
            return empty
        return http_diagnostic(json.loads(path.read_bytes())) or empty
    except (OSError, ValueError):
        return empty


def diagnostic_cli(prefix):
    """Fixture-only HTTP classification; ordinary CLI output and budget stay intact."""
    agent = require_fixture(prefix, child=True)
    import httpx2 as httpx
    from account_access.cli import main as cli_main

    path = Path(agent.pw_dir) / "signed-chrome-tmp" / HTTP_DIAGNOSTIC
    original = httpx.Client.request

    def record(stage, error="none"):
        try:
            private_file(path, json.dumps({"stage": stage, "error": error}).encode(), replace=True)
        except Exception:
            pass  # Diagnostics cannot change the CLI's result.

    def request(client, *args, **kwargs):
        record("started")
        try:
            value = original(client, *args, **kwargs)
        except httpx.HTTPError as error:
            kind = type(error).__name__
            record("http_error", kind if kind in HTTP_ERROR_CLASSES else "HTTPError")
            raise
        record("completed")
        return value

    previous = os.environ.get("ACCESS_CLIENT_CONFIG")
    os.environ["ACCESS_CLIENT_CONFIG"] = str(prefix / "agent-client/native-host-client.json")
    httpx.Client.request = request
    try:
        return cli_main(["run", SMS_ACCOUNT, "summary"])
    finally:
        httpx.Client.request = original
        if previous is None:
            os.environ.pop("ACCESS_CLIENT_CONFIG", None)
        else:
            os.environ["ACCESS_CLIENT_CONFIG"] = previous


def pending_diagnostic(value):
    if (type(value) is not dict or set(value) != {"status", "present", "phase", "source_enabled"}
            or type(value["status"]) is not str or value["status"] not in {"available", "timeout", "unavailable"}
            or type(value["present"]) is not bool or type(value["source_enabled"]) is not bool
            or type(value["phase"]) is not str or value["phase"] not in {"none", "baseline", "watch"}
            or value["present"] != (value["phase"] != "none")
            or (value["status"] != "available" and (value["present"] or value["source_enabled"]))):
        return None
    return value.copy()


def read_pending_diagnostic(worker):
    empty = {"status": "unavailable", "present": False, "phase": "none", "source_enabled": False}
    if worker is None:
        return empty
    try:
        value = worker.evaluate("""async () => {
            const unavailable = {status:'unavailable',present:false,phase:'none',source_enabled:false};
            return await Promise.race([
                (async () => {
                    try {
                        const value = await native({method:'pending'});
                        if (!Array.isArray(value?.pending) || typeof value.source_enabled !== 'boolean') return unavailable;
                        const own = value.pending.filter(item => item?.source === 'chrome-sms');
                        if (own.length > 1 || (own.length === 1 && !['baseline','watch'].includes(own[0].phase))) return unavailable;
                        return {status:'available',present:own.length === 1,
                            phase:own.length ? own[0].phase : 'none',source_enabled:value.source_enabled};
                    } catch { return unavailable; }
                })(),
                new Promise(resolve => setTimeout(() => resolve({status:'timeout',present:false,
                    phase:'none',source_enabled:false}), 1500))
            ]);
        }""")
        return pending_diagnostic(value) or empty
    except Exception:
        return empty  # Never retain exception text or extension/native response data.


def failure_details(value):
    if type(value) is not dict or set(value) != {"http", "pending"}:
        return None
    http, pending = http_diagnostic(value["http"]), pending_diagnostic(value["pending"])
    return {"http": http, "pending": pending} if http and pending else None


def run_sms_journey(playwright, prefix, home, original, original_hashes):
    """Join the unchanged background/content scripts to a fresh worker login.

    Only the manifest enrollment is synthetic. Chrome's normal public content
    script APIs, the production polling loop, and native framing remain in use.
    """
    global SMS_FAILURE_PROGRESS, SMS_FAILURE_DETAILS
    SMS_FAILURE_PROGRESS = None
    SMS_FAILURE_DETAILS = None
    stage("sms-launch")
    extension = root_managed_path(prefix / SMS_EXTENSION_NAME)
    candidate = json.loads((extension / "manifest.json").read_bytes())
    if not validate_fixture_manifest(original, candidate):
        raise RuntimeError("signed_chrome_fixture_manifest_changed")
    hashes = resource_hashes(extension)
    unchanged = {name: digest for name, digest in hashes.items() if name != "manifest.json"}
    if unchanged != {name: digest for name, digest in original_hashes.items() if name != "manifest.json"}:
        raise RuntimeError("signed_chrome_fixture_scripts_changed")
    profile = home / SMS_PROFILE_NAME
    info = profile.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700
        or {item.name for item in profile.iterdir()} != {"NativeMessagingHosts"}
    ):
        raise RuntimeError("signed_chrome_profile_not_empty")
    if json.loads((profile / "NativeMessagingHosts" / (HOST + ".json")).read_bytes()) != native_manifest(
        root_managed_path(prefix / "root-owner-client")
    ):
        raise RuntimeError("signed_chrome_manifest_changed")
    helper = root_managed_path(prefix / "protected-browser-fixture.py")
    client_type = runpy.run_path(str(helper))["ClientReads"]
    config = prefix / "agent-client/native-host-client.json"
    clients = None
    context = None
    worker = None
    checks = {"separate_empty_fixture_profile_used": True,
              "fixture_account_and_code_source_are_separate_from_prior_transport_journey": True,
              "only_messages_host_permission_moved_from_optional_to_required": True,
              "all_five_packaged_script_html_css_resources_unchanged": True}
    incoming = bytearray()
    delivered = False
    fulfilled = []
    try:
        context = playwright.chromium.launch_persistent_context(**launch_options(profile, home))

        def local_document(route):
            if route.request.url == MESSAGES_URL and route.request.resource_type == "document":
                fulfilled.append(MESSAGES_URL)
                route.fulfill(status=200, content_type="text/html", body=sms_page())
            else:
                route.abort()

        context.route("**/*", local_document)
        browser = context.browser
        if browser is None:
            raise RuntimeError("signed_chrome_browser_not_available")
        cdp = browser.new_browser_cdp_session()
        stage("sms-load")
        loaded = cdp.send("Extensions.loadUnpacked", {"path": str(extension)})
        checks["same_extension_key_and_id_loaded"] = loaded == {"id": EXTENSION_ID}
        worker = next((item for item in context.service_workers
                       if item.url == EXTENSION_ORIGIN + "background.js"), None)
        if worker is None:
            worker = context.wait_for_event("serviceworker", predicate=lambda item:
                                            item.url == EXTENSION_ORIGIN + "background.js", timeout=15000)
        stage("sms-dom")
        page = context.new_page()
        page.goto(MESSAGES_URL, wait_until="domcontentloaded", timeout=10000)
        checks["https_messages_document_fulfilled_in_memory"] = fulfilled == [MESSAGES_URL]
        prepared = worker.evaluate("""async () => {
            const pages = await tabs();
            if (pages.length !== 1) return false;
            await chrome.scripting.registerContentScripts([{id:'account-access-sms',
                matches:['https://messages.google.com/web/conversations*'], js:['reader.js'],
                runAt:'document_idle', persistAcrossSessions:true}]);
            await chrome.scripting.executeScript({target:{tabId:pages[0].id},files:['reader.js']});
            await chrome.storage.local.set({enabled:true});
            return true;
        }""")
        checks["production_reader_registered_and_injected_by_public_chrome_api"] = prepared is True
        permissions = worker.evaluate("chrome.permissions.getAll()")
        checks["only_messages_origin_granted_without_cookie_or_github_access"] = (
            permissions.get("origins") == [MESSAGES_ORIGIN]
            and set(permissions.get("permissions", [])) == set(original["permissions"])
        )
        if not all(checks.values()):
            raise RuntimeError("signed_chrome_fixture_prepare_failed")
        # Browser startup and enrollment substitutes have their own bounded
        # calls and remain inside the controller's hard outer cap. Give
        # the two actual CLI reads their full budget only after setup finishes.
        clients = client_type(
            [sys.executable, "-I", "-B", str(root_managed_path(prefix / "signed-chrome-probe.py")),
             "--prefix", str(prefix), "--cli-diagnostic"],
            {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "ACCESS_CLIENT_CONFIG": str(config)},
            time.monotonic() + CLI_READS_SECONDS,
            account=SMS_ACCOUNT,
            read_timeout=CLI_READ_SECONDS,
        )
        stage("sms-login")
        while not clients.tick():
            # This pipe carries only the fictional provider's single new code;
            # the controller does not submit it to the worker or native host.
            if select.select([sys.stdin.buffer], [], [], 0)[0]:
                part = os.read(sys.stdin.buffer.fileno(), 256)
                if not part or len(incoming) + len(part) > 128:
                    raise RuntimeError("signed_chrome_fixture_delivery_invalid")
                incoming.extend(part)
                if b"\n" in incoming:
                    if delivered or incoming.count(b"\n") != 1 or not incoming.endswith(b"\n"):
                        raise RuntimeError("signed_chrome_fixture_delivery_invalid")
                    code = fictional_message(json.loads(incoming))
                    page.evaluate("""code => {
                        const row = document.createElement('mws-conversation-list-item');
                        const link = document.createElement('a');
                        link.setAttribute('data-e2e-conversation','');
                        link.setAttribute('href','/web/conversations/fresh-fixture');
                        const snippet = document.createElement('mws-conversation-snippet');
                        snippet.textContent = code + ' is your GitHub authentication code.';
                        const stamp = document.createElement('mws-relative-timestamp');
                        const age = document.createElement('span'); age.setAttribute('aria-label','now');
                        stamp.append(age); row.append(link,snippet,stamp);
                        document.querySelector('mws-conversations-list nav').prepend(row);
                    }""", code)
                    incoming.clear()
                    delivered = True
            # Pump Chrome normally; the unchanged background's one-second
            # interval, rather than a harness delivery call, reads and forwards.
            page.wait_for_timeout(50)
        checks["single_fresh_synthetic_text_inserted_into_dom"] = delivered
        checks["unchanged_background_polling_completed_fresh_password_sms_login"] = delivered and len(clients.values) == 2
        checks["second_cli_read_reused_saved_session"] = len(clients.values) == 2
        checks["cli_returns_only_reviewed_data_without_login_codes"] = re.search(
            r"\b[0-9]{6}\b", json.dumps(clients.values)
        ) is None
        checks["completed_window_no_longer_pending"] = worker.evaluate(
            "async () => await native({method:'pending'})"
        ) == {"pending": [], "source_enabled": True}
        checks["fixture_resources_unchanged_after_login"] = resource_hashes(extension) == hashes
    except Exception:
        # Capture before close() clears the child. These finite counts/booleans
        # distinguish delivery from first/second-read exhaustion without a code,
        # URL, account output, page contents or exception string.
        SMS_FAILURE_PROGRESS = {
            "completed_cli_reads": len(clients.values) if clients is not None else 0,
            "synthetic_dom_inserted": delivered,
            "active_cli": clients is not None and clients.process is not None,
        }
        SMS_FAILURE_DETAILS = {"http": read_http_diagnostic(home),
                               "pending": read_pending_diagnostic(worker) if clients is not None else
                                   read_pending_diagnostic(None)}
        raise
    finally:
        previous = CURRENT_STAGE
        stage("sms-cleanup")
        try:
            if clients is not None:
                clients.close()
        finally:
            if context is not None:
                context.close()
        stage(previous)
    checks["fixture_chrome_context_and_cli_children_closed"] = True
    if not all(value is True for value in checks.values()):
        raise RuntimeError("signed_chrome_sms_journey_failed")
    return {"status": "PASSED", "checks": checks, "script_resources_sha256": unchanged,
            "fixture_account": SMS_ACCOUNT, "fixture_code_source": SMS_ACCOUNT,
            "synthetic_manifest_sha256": hashes["manifest.json"],
            "synthetic_manifest_pre_enrollment_used": True,
            "synthetic_google_messages_dom_used": True,
            "actual_content_script_and_background_polling_used": True,
            "password_sms_browser_login_verified": True,
            "production_extension_manifest_used": False,
            "genuine_browser_permission_approval_verified": False,
            "physical_sms_delivery_verified": False,
            "production_entrypoint_run_verified": False}


def run_child(prefix):
    stage("guard")
    agent = require_fixture(prefix, child=True)
    stage("profile")
    home = Path(agent.pw_dir)
    profile = home / PROFILE_NAME
    info = profile.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
        or info.st_mode & 0o777 != 0o700
        or {item.name for item in profile.iterdir()} != {"NativeMessagingHosts"}
    ):
        raise RuntimeError("signed_chrome_profile_not_empty")
    binary = root_managed_path(prefix / "root-owner-client")
    expected_manifest = native_manifest(binary)
    actual_manifest = profile / "NativeMessagingHosts" / (HOST + ".json")
    if json.loads(actual_manifest.read_bytes()) != expected_manifest:
        raise RuntimeError("signed_chrome_manifest_changed")
    from account_access import __file__ as package_file

    extension = root_managed_path(Path(package_file).parent / "google_messages_extension")
    hashes = resource_hashes(extension)
    manifest = json.loads((extension / "manifest.json").read_bytes())
    checks = {"fresh_profile_has_no_existing_user_data": True,
              "isolated_native_manifest_points_to_pinned_binary": True}
    stage("signature")
    verified = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
         "-R=" + CHROME_REQUIREMENT, CHROME_APP],
        capture_output=True, timeout=15, env={"PATH": "/usr/bin:/bin"},
    )
    checks["stable_chrome_matches_production_signature_requirement"] = verified.returncode == 0
    if not checks["stable_chrome_matches_production_signature_requirement"]:
        raise RuntimeError("signed_chrome_publisher_not_verified")
    stage("negative-parent")
    denied = subprocess.run([str(binary), EXTENSION_ORIGIN], capture_output=True, timeout=10,
                            env={"PATH": "/usr/bin:/bin", "GITHUB_ACTIONS": "true"})
    checks["shell_parent_cannot_launch_native_bridge"] = denied.returncode == 78 and not denied.stdout
    if not checks["shell_parent_cannot_launch_native_bridge"]:
        raise RuntimeError("signed_chrome_shell_parent_accepted")
    from playwright.sync_api import sync_playwright

    context = None
    with sync_playwright() as playwright:
        try:
            stage("launch")
            context = playwright.chromium.launch_persistent_context(**launch_options(profile, home))
            # Native messaging needs no network or website. Abort every page
            # request, and do not navigate any page to Google Messages or a login.
            context.route("**/*", lambda route: route.abort())
            browser = context.browser
            if browser is None:
                raise RuntimeError("signed_chrome_browser_not_available")
            cdp = browser.new_browser_cdp_session()
            version = cdp.send("Browser.getVersion")["product"]
            stage("load")
            loaded = cdp.send("Extensions.loadUnpacked", {"path": str(extension)})
            checks["actual_packaged_extension_id_loaded"] = loaded == {"id": EXTENSION_ID}
            if not checks["actual_packaged_extension_id_loaded"]:
                raise RuntimeError("signed_chrome_extension_id_changed")
            worker = next((item for item in context.service_workers
                           if item.url == EXTENSION_ORIGIN + "background.js"), None)
            if worker is None:
                worker = context.wait_for_event(
                    "serviceworker", predicate=lambda item: item.url == EXTENSION_ORIGIN + "background.js",
                    timeout=15000,
                )
            stage("first-pending")
            result = worker.evaluate("""async () => {
                const permissions = await chrome.permissions.getAll();
                const first = await native({method:'pending'});
                const saved = port;
                const refused = await native({method:'session-import'});
                const second = await native({method:'pending'});
                const reused = saved === port;
                return {first, second, refused, reused, permissions};
            }""")
            expected = {"pending": [], "source_enabled": True}
            checks["extension_native_pending_reaches_enrolled_worker"] = result.get("first") == expected
            checks["second_roundtrip_reuses_native_port"] = result.get("reused") is True and result.get("second") == expected
            checks["unsupported_cookie_import_refused"] = result.get("refused") == {
                "status": "DENIED", "reason": "unsupported_browser_connection_request",
            }
            stage("reload")
            with worker.expect_event("close", timeout=10000):
                cdp.send("Extensions.uninstall", {"id": EXTENSION_ID})
            with context.expect_event("serviceworker", predicate=lambda item:
                                      item.url == EXTENSION_ORIGIN + "background.js", timeout=15000) as started:
                reloaded = cdp.send("Extensions.loadUnpacked", {"path": str(extension)})
            renewed = started.value
            third = renewed.evaluate("async () => await native({method:'pending'})")
            checks["extension_reload_reconnects_same_enrolled_worker"] = (
                reloaded == {"id": EXTENSION_ID} and renewed is not worker and third == expected
            )
            permissions = result.get("permissions", {})
            checks["optional_host_and_cookie_permissions_stay_ungranted"] = (
                permissions.get("origins", []) == []
                and set(permissions.get("permissions", [])) == set(manifest["permissions"])
            )
            checks["no_external_website_opened"] = all(
                page.url in {"about:blank", "chrome://newtab/"} for page in context.pages
            )
            checks["packaged_extension_resources_unchanged"] = resource_hashes(extension) == hashes
        finally:
            if context is not None:
                previous = CURRENT_STAGE
                stage("cleanup")
                context.close()
                stage(previous)
        stage("cleanup")
        checks["fresh_chrome_context_closed"] = True
        sms_journey = run_sms_journey(playwright, prefix, home, manifest, hashes)
    if not all(value is True for value in checks.values()):
        raise RuntimeError("signed_chrome_roundtrip_failed")
    return {"status": "PASSED", "chrome_version": version, "extension_id": EXTENSION_ID,
            "extension_resources_sha256": hashes, "checks": checks, "sms_journey": sms_journey}


def stop_process(process):
    """Bound cleanup for the one process group created by this controller."""
    if process.poll() is not None:
        process.wait(timeout=0)
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)


def failure_diagnostic(value):
    diagnostic = value.get("stage") if type(value) is dict else None
    return diagnostic if type(diagnostic) is str and diagnostic in STAGES else None


def failure_reason(error):
    return str(error) if type(error) is RuntimeError and str(error) in FAILURES else "runtime_unavailable"


def failure_progress(value):
    if (type(value) is not dict
            or set(value) != {"completed_cli_reads", "synthetic_dom_inserted", "active_cli"}
            or type(value["completed_cli_reads"]) is not int or not 0 <= value["completed_cli_reads"] <= 2
            or type(value["synthetic_dom_inserted"]) is not bool
            or type(value["active_cli"]) is not bool):
        return None
    return value.copy()


def service_diagnostic(roles, identity):
    empty = dict.fromkeys(["checked", "root_host_alive", "worker_alive",
                           "root_identity_matches", "worker_identity_matches"], False)
    if (type(identity) is not dict or set(identity) != {"root_pid", "worker_pid"}
            or any(type(value) is not int or value <= 1 for value in identity.values())):
        return empty

    def process(pid, expected):
        try:
            result = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "uid=,gid=,pgid=,ppid="],
                capture_output=True, timeout=2, env={"PATH": "/usr/bin:/bin"})
            if result.returncode:
                return True, False, False
            values = result.stdout.split()
            if len(values) != 4 or any(re.fullmatch(rb"[0-9]{1,10}", item) is None for item in values):
                return False, False, False
            return True, True, [int(value) for value in values] == expected
        except (OSError, subprocess.TimeoutExpired):
            return False, False, False

    root = identity["root_pid"]
    root_checked, root_alive, root_match = process(root, [0, 0, root, 1])
    worker_checked, worker_alive, worker_match = process(identity["worker_pid"],
        [roles["broker"].pw_uid, roles["broker"].pw_gid, root, root])
    return {"checked": root_checked and worker_checked, "root_host_alive": root_alive,
            "worker_alive": worker_alive, "root_identity_matches": root_match,
            "worker_identity_matches": worker_match}


def provider_diagnostic(provider, previous):
    result = {"checked": False, "identity_submissions": 0, "password_submissions": 0, "sms_submissions": 0}
    try:
        values = [provider.login_count - previous[0], provider.sms_count - previous[1],
                  provider.identity_count - previous[2]]
        if any(type(value) is not int or not 0 <= value <= 2 for value in values):
            return result
        return {"checked": True, "identity_submissions": values[2],
                "password_submissions": values[0], "sms_submissions": values[1]}
    except (AttributeError, TypeError, IndexError):
        return result


def failure_report(value):
    """Allow only fixed failure classes and finite fictional-fixture metadata."""
    required = {"status", "stage", "failure", "fixture_sms_forwarded", "service", "provider",
                "production_ready", "private_signins"}
    if (type(value) is not dict or not required <= set(value)
            or set(value) - required - {"sms_progress", "sms_details"}
            or value["status"] != "FAILED" or value["production_ready"] is not False
            or type(value["private_signins"]) is not int or value["private_signins"] != 0
            or type(value["stage"]) is not str or value["stage"] not in STAGES
            or type(value["failure"]) is not str or value["failure"] not in FAILURES | {"runtime_unavailable"}
            or type(value["fixture_sms_forwarded"]) is not bool):
        return None
    service, provider = value["service"], value["provider"]
    if (type(service) is not dict or set(service) != {"checked", "root_host_alive", "worker_alive",
            "root_identity_matches", "worker_identity_matches"}
            or any(type(item) is not bool for item in service.values())
            or (service["root_identity_matches"] and not service["root_host_alive"])
            or (service["worker_identity_matches"] and not service["worker_alive"])
            or type(provider) is not dict or set(provider) != {"checked", "identity_submissions",
                "password_submissions", "sms_submissions"} or type(provider["checked"]) is not bool
            or any(type(provider[key]) is not int or not 0 <= provider[key] <= 2
                   for key in ["identity_submissions", "password_submissions", "sms_submissions"])
            or (not provider["checked"] and any(provider[key] for key in provider if key != "checked"))
            or ("sms_progress" in value and failure_progress(value["sms_progress"]) is None)
            or ("sms_details" in value and failure_details(value["sms_details"]) is None)):
        return None
    return json.loads(json.dumps(value))


def exercise_signed_chrome_gateway(prefix, roles, fixture=None, client_config=None, *, service_identity=None):
    agent = require_fixture(prefix, roles)
    home = Path(agent.pw_dir)
    profile, sms_profile, temporary = home / PROFILE_NAME, home / SMS_PROFILE_NAME, home / "signed-chrome-tmp"
    extension = prefix / SMS_EXTENSION_NAME
    directories = [profile, sms_profile, temporary, extension]
    if any(directory.exists() or directory.is_symlink() for directory in directories):
        raise RuntimeError("signed_chrome_profile_already_exists")
    controller = root_managed_path(prefix / "signed-chrome-probe.py")
    binary = root_managed_path(prefix / "root-owner-client")
    root_managed_path(prefix / "browser-host-owner-policy.json")
    process = None
    output = prefix / "signed-chrome-child.json"
    if output.exists() or output.is_symlink():
        raise RuntimeError("signed_chrome_output_already_exists")
    created = []
    incoming, lock = [], threading.Lock()
    delivered = 0
    if fixture is None or client_config != prefix / "agent-client/native-host-client.json":
        raise RuntimeError("signed_chrome_fixture_provider_missing")
    prior_delivery = fixture.provider.delivery
    started = fixture.provider.login_count, fixture.provider.sms_count, fixture.provider.identity_count

    def delivery(kind, code):
        fictional_message({"code": code})
        if kind != "sms":
            raise RuntimeError("signed_chrome_fixture_delivery_invalid")
        with lock:
            incoming.append({"code": code})

    try:
        for directory in [profile, sms_profile, temporary]:
            directory.mkdir(mode=0o700)
            created.append(directory)
            os.chown(directory, agent.pw_uid, agent.pw_gid)
        for browser_profile in [profile, sms_profile]:
            hosts = browser_profile / "NativeMessagingHosts"
            hosts.mkdir(mode=0o700)
            os.chown(hosts, agent.pw_uid, agent.pw_gid)
            target = hosts / (HOST + ".json")
            private_file(target, json.dumps(native_manifest(binary)).encode())
            os.chown(target, agent.pw_uid, agent.pw_gid)
        from account_access import __file__ as package_file

        original = root_managed_path(Path(package_file).parent / "google_messages_extension")
        resource_hashes(original)
        extension.mkdir(mode=0o755)
        created.append(extension)
        for name in sorted(RESOURCES):
            target = extension / name
            value = ((json.dumps(fixture_manifest(json.loads((original / name).read_bytes()))).encode())
                     if name == "manifest.json" else (original / name).read_bytes())
            private_file(target, value)
            target.chmod(0o644)
        extension.chmod(0o755)
        fixture.provider.sessions.clear()
        fixture.provider.delivery = delivery
        dropped = ["/bin/launchctl", "asuser", str(agent.pw_uid), "/usr/bin/sudo", "-n", "-H",
                   "-u", "#" + str(agent.pw_uid), "-g", "#" + str(agent.pw_gid), "--"]
        with output.open("xb", buffering=0) as destination:
            output.chmod(0o600)
            process = subprocess.Popen(
                [*dropped, "/usr/bin/env", "GITHUB_ACTIONS=true", sys.executable, "-I", "-B",
                 str(controller), "--prefix", str(prefix)],
                stdin=subprocess.PIPE, stdout=destination, stderr=subprocess.DEVNULL,
                start_new_session=True,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GITHUB_ACTIONS": "true"},
            )
            deadline = time.monotonic() + CHILD_SECONDS
            while process.poll() is None:
                if time.monotonic() >= deadline or os.fstat(destination.fileno()).st_size > OUTPUT_LIMIT:
                    raise RuntimeError("signed_chrome_child_bound_exceeded")
                with lock:
                    queued = list(incoming)
                    incoming.clear()
                if queued:
                    if delivered or len(queued) != 1:
                        raise RuntimeError("signed_chrome_fixture_delivery_invalid")
                    process.stdin.write(json.dumps(queued[0]).encode() + b"\n")
                    process.stdin.flush()
                    delivered += 1
                time.sleep(0.05)
            process.wait(timeout=0)
        if output.stat().st_size > OUTPUT_LIMIT:
            raise RuntimeError("signed_chrome_child_bound_exceeded")
        value = json.loads(output.read_bytes())
        from_checker = Path(__file__).with_name("check_mac_signed_chrome_report.py")
        # The controller runs from an installed fixture directory, so its
        # checker is copied there as public immutable code as well.
        root_managed_path(from_checker)
        validate_child = runpy.run_path(str(from_checker))["validate_child"]
        if process.returncode != 0 or not validate_child(value):
            diagnostic = failure_diagnostic(value)
            if diagnostic is not None:
                detail = value.get("failure")
                detail = detail if type(detail) is str and detail in FAILURES else "runtime_unavailable"
                progress = failure_progress(value.get("sms_progress"))
                details = failure_details(value.get("sms_details"))
                failure = failure_report({"status": "FAILED", "stage": diagnostic, "failure": detail,
                    "fixture_sms_forwarded": delivered == 1, "production_ready": False, "private_signins": 0,
                    "service": service_diagnostic(roles, service_identity),
                    "provider": provider_diagnostic(fixture.provider, started),
                    **({"sms_progress": progress} if progress is not None else {}),
                    **({"sms_details": details} if details is not None else {})})
                if failure is not None:
                    try:
                        private_file(Path("/tmp/account-access-mac-signed-chrome-failure.json"),
                                     json.dumps(failure).encode(), replace=True)
                    except Exception:
                        pass  # Keep the original failed acceptance result.
                    print(json.dumps({**failure, "stage": "signed_chrome_failed_" + diagnostic}),
                          file=sys.stderr, flush=True)
            raise RuntimeError("signed_chrome_child_failed")
        value["sms_journey"]["checks"]["provider_recorded_one_fresh_password_sms_and_identity_submission"] = (
            delivered == 1 and (fixture.provider.login_count, fixture.provider.sms_count,
                               fixture.provider.identity_count) == tuple(number + 1 for number in started)
        )
    finally:
        fixture.provider.delivery = prior_delivery
        try:
            if process is not None:
                try:
                    stop_process(process)
                finally:
                    if process.stdin is not None:
                        process.stdin.close()
        finally:
            # Remove only this controller's three newly created identity-local
            # directories and the root-owned synthetic manifest resource copy.
            # No default Chrome profile is ever selected.
            for directory in created:
                shutil.rmtree(directory)
    value["checks"]["temporary_chrome_profile_removed"] = not profile.exists() and not temporary.exists()
    value["sms_journey"]["checks"]["fixture_profile_and_pre_enrollment_manifest_removed"] = (
        not sms_profile.exists() and not extension.exists()
    )
    if not all(item is True for item in value["sms_journey"]["checks"].values()):
        raise RuntimeError("signed_chrome_fixture_provider_or_cleanup_failed")
    value.update({"platform": "macos", "environment": "controlled-demo", "production_ready": False,
                  "private_signins": 0,
                  **dict.fromkeys([
                      "actual_stable_chrome_used", "signed_chrome_parent_verified", "actual_chrome_extension_used",
                      "actual_native_framing_used", "actual_desktop_connection_used", "actual_native_xpc_used",
                      "production_composed_host_used", "system_key_used", "actual_distinct_uids",
                      "native_pending_roundtrip_verified",
                  ], True),
                  **dict.fromkeys([
                      "production_entrypoint_run_verified", "production_manifest_google_messages_dom_used", "physical_sms_delivery_verified",
                      "genuine_owner_approval_verified", "publisher_signed_peers", "consumer_deployment_verified",
                      "production_manifest_password_sms_browser_login_verified", "extension_marketplace_install_verified",
                  ], False)})
    return value


def main(argv=None):
    global SMS_FAILURE_PROGRESS, SMS_FAILURE_DETAILS
    stage("guard")
    SMS_FAILURE_PROGRESS, SMS_FAILURE_DETAILS = None, None
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--cli-diagnostic", action="store_true")
    args = parser.parse_args(argv)
    try:
        require_fixture(args.prefix, child=True)
        if args.cli_diagnostic:
            return diagnostic_cli(args.prefix)

        def interrupted(*_):
            raise InterruptedError("signed_chrome_child_interrupted")

        previous = signal.signal(signal.SIGTERM, interrupted)
        try:
            value = run_child(args.prefix)
        finally:
            signal.signal(signal.SIGTERM, previous)
    except Exception as error:
        progress = failure_progress(SMS_FAILURE_PROGRESS)
        details = failure_details(SMS_FAILURE_DETAILS)
        print(json.dumps({"status": "FAILED", "reason": "signed_chrome_roundtrip_failed", "stage": CURRENT_STAGE,
                          "failure": failure_reason(error),
                          **({"sms_progress": progress} if progress is not None else {}),
                          **({"sms_details": details} if details is not None else {})}))
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
