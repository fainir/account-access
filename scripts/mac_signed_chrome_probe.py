"""Disposable Mac CI: real stable Chrome/native/XPC round trips, no websites.

The exact packaged extension runs in a new, empty profile under the temporary
agent UID. Chrome launches the existing hash-pinned fixture Mach-O directly.
No Chrome profile, setting, account, owner approval or production service is used.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
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
OUTPUT_LIMIT = 65536
STAGES = {"guard", "profile", "signature", "negative-parent", "launch", "load", "first-pending", "reload", "cleanup"}
CURRENT_STAGE = "guard"


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
    if not all(value is True for value in checks.values()):
        raise RuntimeError("signed_chrome_roundtrip_failed")
    return {"status": "PASSED", "chrome_version": version, "extension_id": EXTENSION_ID,
            "extension_resources_sha256": hashes, "checks": checks}


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


def exercise_signed_chrome_gateway(prefix, roles):
    agent = require_fixture(prefix, roles)
    home = Path(agent.pw_dir)
    profile, temporary = home / PROFILE_NAME, home / "signed-chrome-tmp"
    if profile.exists() or profile.is_symlink() or temporary.exists() or temporary.is_symlink():
        raise RuntimeError("signed_chrome_profile_already_exists")
    controller = root_managed_path(prefix / "signed-chrome-probe.py")
    binary = root_managed_path(prefix / "root-owner-client")
    root_managed_path(prefix / "browser-host-owner-policy.json")
    process = None
    output = prefix / "signed-chrome-child.json"
    if output.exists() or output.is_symlink():
        raise RuntimeError("signed_chrome_output_already_exists")
    created = []
    try:
        for directory in [profile, temporary]:
            directory.mkdir(mode=0o700)
            created.append(directory)
            os.chown(directory, agent.pw_uid, agent.pw_gid)
        hosts = profile / "NativeMessagingHosts"
        hosts.mkdir(mode=0o700)
        os.chown(hosts, agent.pw_uid, agent.pw_gid)
        target = hosts / (HOST + ".json")
        private_file(target, json.dumps(native_manifest(binary)).encode())
        os.chown(target, agent.pw_uid, agent.pw_gid)
        dropped = ["/bin/launchctl", "asuser", str(agent.pw_uid), "/usr/bin/sudo", "-n", "-H",
                   "-u", "#" + str(agent.pw_uid), "-g", "#" + str(agent.pw_gid), "--"]
        with output.open("xb", buffering=0) as destination:
            output.chmod(0o600)
            process = subprocess.Popen(
                [*dropped, "/usr/bin/env", "GITHUB_ACTIONS=true", sys.executable, "-I", "-B",
                 str(controller), "--prefix", str(prefix)],
                stdin=subprocess.DEVNULL, stdout=destination, stderr=subprocess.DEVNULL,
                start_new_session=True,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GITHUB_ACTIONS": "true"},
            )
            deadline = time.monotonic() + 90
            while process.poll() is None:
                if time.monotonic() >= deadline or os.fstat(destination.fileno()).st_size > OUTPUT_LIMIT:
                    raise RuntimeError("signed_chrome_child_bound_exceeded")
                time.sleep(0.05)
            process.wait(timeout=0)
        if output.stat().st_size > OUTPUT_LIMIT:
            raise RuntimeError("signed_chrome_child_bound_exceeded")
        value = json.loads(output.read_bytes())
        from_checker = Path(__file__).with_name("check_mac_signed_chrome_report.py")
        # The controller runs from an installed fixture directory, so its
        # checker is copied there as public immutable code as well.
        import runpy

        root_managed_path(from_checker)
        validate_child = runpy.run_path(str(from_checker))["validate_child"]
        if process.returncode != 0 or not validate_child(value):
            diagnostic = failure_diagnostic(value)
            if diagnostic is not None:
                print(json.dumps({"stage": "signed_chrome_failed_" + diagnostic}), file=sys.stderr, flush=True)
            raise RuntimeError("signed_chrome_child_failed")
    finally:
        try:
            if process is not None:
                stop_process(process)
        finally:
            # Only the two newly created directories in the dedicated fixture
            # identity are removed. No default Chrome profile is ever selected.
            for directory in created:
                shutil.rmtree(directory)
    value["checks"]["temporary_chrome_profile_removed"] = not profile.exists() and not temporary.exists()
    value.update({"platform": "macos", "environment": "controlled-demo", "production_ready": False,
                  "private_signins": 0,
                  **dict.fromkeys([
                      "actual_stable_chrome_used", "signed_chrome_parent_verified", "actual_chrome_extension_used",
                      "actual_native_framing_used", "actual_desktop_connection_used", "actual_native_xpc_used",
                      "production_composed_host_used", "system_key_used", "actual_distinct_uids",
                      "native_pending_roundtrip_verified",
                  ], True),
                  **dict.fromkeys([
                      "production_entrypoint_run_verified", "google_messages_dom_used", "physical_sms_delivery_verified",
                      "genuine_owner_approval_verified", "publisher_signed_peers", "consumer_deployment_verified",
                      "password_sms_browser_login_verified", "extension_marketplace_install_verified",
                  ], False)})
    return value


def main(argv=None):
    stage("guard")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require_fixture(args.prefix, child=True)

        def interrupted(*_):
            raise InterruptedError("signed_chrome_child_interrupted")

        previous = signal.signal(signal.SIGTERM, interrupted)
        try:
            value = run_child(args.prefix)
        finally:
            signal.signal(signal.SIGTERM, previous)
    except Exception:
        print(json.dumps({"status": "FAILED", "reason": "signed_chrome_roundtrip_failed", "stage": CURRENT_STAGE}))
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
