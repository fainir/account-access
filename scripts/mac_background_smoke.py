"""Opt-in Mac service-manager QA with an isolated signed app and fictional data.

Uses one fresh fixture Keychain namespace. Never registers the production app
identity, reads private accounts, changes Login Items approval, or logs secrets.
Requires a signed candidate and the maintainer's existing signing identity.
"""

import argparse
import base64
import hashlib
import json
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import keyring

from account_access.demo import environment
from account_access.desktop import running, stop
from account_access.models import TaskRequest
from account_access.storage import private_file
from account_access.supervisor import lease
from macos.notarize import Notarization


class ProbeFailure(Exception):
    pass


def wait_for(check, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.2)
    raise ProbeFailure("background_probe_timed_out")


def check(source, team, report_path):
    if sys.platform != "darwin" or not re.fullmatch(r"[A-Z0-9]{10}", team):
        raise ProbeFailure("macos_and_expected_team_required")
    source = source.resolve()
    if source.name != "Account Access.app":
        raise ProbeFailure("signed_candidate_app_required")
    certificate = subprocess.run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
                                 capture_output=True, text=True, check=True)
    identities = re.findall(r'"(Developer ID Application: [^"\n]+ \(' + team + r'\))"', certificate.stdout)
    if len(identities) != 1:
        raise ProbeFailure("existing_developer_id_identity_required")
    identifier = "com.fainir.accountaccess.qa." + uuid.uuid4().hex
    temporary = Path(tempfile.mkdtemp(prefix="aab-", dir="/tmp")).resolve()
    root = temporary / "data"
    runtime = temporary / "runtime"
    app = temporary / "Fixture.app"
    log_path = Path("artifacts/video/work/private-pilot/background-service-58-tools.txt")
    log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = {"version": "0.8.0-candidate", "application_build": 58,
              "environment": "controlled-demo", "production_ready": False,
              "registration": "not_attempted", "os_managed_crash_recovery": False,
              "pause_prevents_restart": False, "keyring_namespace_cleaned": False,
              "service_unregistered": False, "private_account_sign_ins": 0,
              "owner_settings_or_approval_changed": False,
              "limits": ["Fictional provider only; not private account/MFA acceptance",
                         "No actual logout or reboot", "No OS credential isolation or Apple notarization acceptance"]}
    created_key = False
    registered = False
    frozen = None
    service = "account-access:" + hashlib.sha256(str(root).encode()).hexdigest()[:24]
    helper = app / "Contents/MacOS/AccountAccess"
    logs = log_path.open("w")
    def run(command, *, timeout=90):
        completed = subprocess.run([str(item) for item in command], capture_output=True, timeout=timeout)
        # Tool output stays in an ignored private diagnostic, never the report.
        logs.write(completed.stdout.decode(errors="replace"))
        logs.write(completed.stderr.decode(errors="replace"))
        logs.flush()
        if completed.returncode:
            raise ProbeFailure("background_probe_tool_failed")
        return completed.stdout
    def control(action):
        return json.loads(run([helper, action], timeout=25))
    def job_pid():
        job = subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{identifier}.background"],
                             capture_output=True, text=True, timeout=5)
        match = re.search(r"^\s*pid = ([0-9]+)\s*$", job.stdout, re.MULTILINE)
        return int(match[1]) if job.returncode == 0 and match else None
    def job_absent():
        return subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{identifier}.background"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode != 0
    try:
        verifier = Notarization(temporary / "input-check")
        with verifier.locked():
            verifier.app_info(source, team)
        result["signed_input_and_helper_verified"] = True
        shutil.copytree(source, app)
        info_path = app / "Contents/Info.plist"
        info = plistlib.loads(info_path.read_bytes())
        wheel = app / "Contents/Resources/account_access.whl"
        if (info.get("AccountAccessBackgroundFormat") != 1
                or hashlib.sha256(wheel.read_bytes()).hexdigest() != info.get("AccountAccessWheelSHA256")):
            raise ProbeFailure("background_candidate_pin_required")
        install_wheel = temporary / "account_access-0.8.0-py3-none-any.whl"
        shutil.copy2(wheel, install_wheel)
        info.update(CFBundleIdentifier=identifier, CFBundleName="Account Access QA", CFBundleDisplayName="Account Access QA",
                    AccountAccessDataDirectory=str(root),
                    AccountAccessInstallDirectory=str(runtime))
        info_path.write_bytes(plistlib.dumps(info))
        agent_path = app / "Contents/Library/LaunchAgents/com.fainir.accountaccess.background.plist"
        agent = plistlib.loads(agent_path.read_bytes())
        agent["Label"] = identifier + ".background"
        agent_path.write_bytes(plistlib.dumps(agent))
        run(["/usr/bin/xcrun", "swiftc", "-O", "-parse-as-library", "-framework", "Foundation",
             "-framework", "CryptoKit", "-framework", "ServiceManagement",
             "macos/BackgroundRecovery.swift", "macos/Tests/BackgroundServiceProbe.swift", "-o", helper])
        run(["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp", "--sign", identities[0], app])
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app])
        for directory in [runtime, runtime / "environments"]:
            directory.mkdir(mode=0o700, parents=True)
        environment_path = runtime / "environments/account-access-fixture"
        environment_path.mkdir(mode=0o700)
        uv = shutil.which("uv")
        if not uv:
            raise ProbeFailure("uv_required")
        run([uv, "venv", "--no-config", "--python", sys.executable, environment_path])
        environment_path.chmod(0o700)
        python = environment_path / "bin/python"
        requirements = temporary / "requirements.txt"
        requirements.write_text(Path("account_access/runtime-requirements.txt").read_text() + "\n" + install_wheel.as_uri()
                                + " --hash=sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest() + "\n")
        run([uv, "pip", "sync", "--no-config", "--python", python, "--require-hashes", "--no-build",
             "--strict", requirements], timeout=120)
        with environment(root) as (_, broker, _):
            if not type(keyring.get_keyring()).__module__.startswith("keyring.backends.macOS"):
                raise ProbeFailure("secure_macos_keyring_required")
            if keyring.get_password(service, "master") is not None:
                raise ProbeFailure("fixture_keyring_namespace_occupied")
            created_key = True
            keyring.set_password(service, "master", base64.b64encode((root / "demo.key").read_bytes()).decode())
            broker.grant("fixture", "demo-api", ["summary"])
            private_file(root / "supervisor.json", json.dumps({"generation": uuid.uuid4().hex * 2,
                "runtime": str(python), "version": "0.8.0"}).encode())
            try:
                registered = True  # Even an uncertain registration needs scoped cleanup.
                registration = control("register")
                result["registration"] = registration["status"]
                if registration["status"] != "enabled":
                    raise ProbeFailure("background_approval_or_registration_required")
                initial = wait_for(lambda: running(root))
                guardian_pid = wait_for(job_pid)
                frozen = initial["pid"]
                os.kill(frozen, signal.SIGSTOP)
                job = broker.submit("fixture", TaskRequest(key="os-crash-recovery", steps=[
                    {"account": "demo-api", "operation": "summary"}]))
                if job["status"] != "QUEUED":
                    raise ProbeFailure("fixture_task_was_not_queued")
                os.kill(frozen, signal.SIGKILL)
                frozen = None
                os.kill(guardian_pid, signal.SIGKILL)
                def completed():
                    current = broker.task("fixture", job["task_id"])
                    return current if current["status"] == "COMPLETED" else None
                finished = wait_for(completed)
                replacement = wait_for(lambda: running(root))
                replacement_guardian = wait_for(lambda: (pid := job_pid()) and pid != guardian_pid and pid)
                result["os_managed_crash_recovery"] = (finished["task_id"] == job["task_id"]
                    and replacement["pid"] != initial["pid"] and replacement_guardian != guardian_pid)
                stop(root)
                wait_for(lambda: not running(root) and not job_pid(), timeout=20)
                time.sleep(12)  # Longer than this job's restart throttle.
                result["pause_prevents_restart"] = running(root) is None and job_pid() is None
                # A fresh job invocation, like RunAtLoad, must still honor Pause.
                control("register")
                time.sleep(2)
                result["paused_new_job_invocation_stays_stopped"] = running(root) is None and (root / "service.paused").exists()
            finally:
                if frozen:
                    try:
                        os.kill(frozen, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
                try:
                    stop(root)
                finally:
                    if registered:
                        if control("unregister")["status"] == "not_registered":
                            wait_for(job_absent, timeout=10)
                            result["service_unregistered"] = True
                with lease(root, timeout=20):
                    pass
                with lease(root, "service", timeout=20):
                    pass
    except Exception as exc:
        result["failure"] = str(exc) if isinstance(exc, ProbeFailure) else "unexpected_background_probe_error"
    finally:
        if created_key:
            try:
                if keyring.get_password(service, "master") is not None:
                    keyring.delete_password(service, "master")
                result["keyring_namespace_cleaned"] = keyring.get_password(service, "master") is None
            except Exception:
                result["failure"] = "fixture_keyring_cleanup_required"
        logs.close()
        if (not registered or result["service_unregistered"]) and (not created_key or result["keyring_namespace_cleaned"]):
            shutil.rmtree(temporary)
        else:
            # Keep only this fixture for cleanup; never delete a still-registered
            # app and leave an unexplained broken Login Item behind.
            private_file(Path("artifacts/video/work/private-pilot/background-service-58-cleanup.json"),
                         json.dumps({"app": str(app), "root": str(root), "label": identifier + ".background",
                                     "keyring_service": service}).encode(), replace=True)
        result["passed"] = all(result.get(key) for key in ["os_managed_crash_recovery", "pause_prevents_restart",
            "paused_new_job_invocation_stays_stopped", "keyring_namespace_cleaned", "service_unregistered"])
        result["source_revision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    outcome = check(args.app, args.team_id, args.report)
    print(json.dumps(outcome))
    raise SystemExit(0 if outcome["passed"] else 1)
