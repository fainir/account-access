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
from account_access.errors import AccessError
from account_access.models import TaskRequest
from account_access.runtime_bootstrap import INSTALLATION_MARKER, MARKER, write_installation, write_launcher
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
    probe_name = "background-service-" + identifier.rsplit(".", 1)[1]
    log_path = Path("artifacts/video/work/private-pilot") / (probe_name + "-tools.txt")
    log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = {"version": "0.8.0-candidate", "application_build": None,
              "environment": "controlled-demo", "production_ready": False,
              "registration": "not_attempted", "os_managed_crash_recovery": False,
              "pause_prevents_restart": False, "keyring_namespace_cleaned": False,
              "service_unregistered": False, "private_account_sign_ins": 0,
              "owner_settings_or_approval_changed": False,
              "limits": ["Fictional provider only; not private account/MFA acceptance",
                         "No actual logout or reboot", "No OS credential isolation or Apple notarization acceptance"]}
    created_key = False
    registered = False
    processes_quiesced = True
    frozen = None
    service = "account-access:" + hashlib.sha256(str(root).encode()).hexdigest()[:24]
    helper = app / "Contents/MacOS/AccountAccess"
    logs = log_path.open("w")
    def run(command, *, timeout=90, env=None, expected_exit=0):
        completed = subprocess.run([str(item) for item in command], capture_output=True, timeout=timeout, env=env)
        # Tool output stays in an ignored private diagnostic, never the report.
        logs.write(completed.stdout.decode(errors="replace"))
        logs.write(completed.stderr.decode(errors="replace"))
        logs.flush()
        if completed.returncode != expected_exit:
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
        if not re.fullmatch(r"[0-9]+", str(info.get("CFBundleVersion", ""))):
            raise ProbeFailure("candidate_build_required")
        result["application_build"] = int(info["CFBundleVersion"])
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
        launcher = runtime / "bin/account-access"
        launcher.parent.mkdir(mode=0o700)
        write_launcher(launcher, [str(python), "-I", "-m", "account_access.cli"], MARKER)
        write_installation(runtime / "installed-wheel.json", json.dumps({"managed_by": INSTALLATION_MARKER,
            "schema": 2, "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "runtime": str(python), "launcher_sha256": hashlib.sha256(launcher.read_bytes()).hexdigest()}).encode())
        with environment(root) as (_, broker, _):
            if not type(keyring.get_keyring()).__module__.startswith("keyring.backends.macOS"):
                raise ProbeFailure("secure_macos_keyring_required")
            if keyring.get_password(service, "master") is not None:
                raise ProbeFailure("fixture_keyring_namespace_occupied")
            created_key = True
            keyring.set_password(service, "master", base64.b64encode((root / "demo.key").read_bytes()).decode())
            client_token = broker.store.new_client("fixture")
            broker.grant("fixture", "demo-api", ["summary"])
            client_directory = root / "clients/fixture"
            client_directory.mkdir(mode=0o700, parents=True)
            private_file(client_directory / "token", client_token.encode())
            client_config = client_directory / "client.json"
            private_file(client_config, json.dumps({"socket": str(root / "service.sock"),
                "token_file": str(client_directory / "token"), "auto_start": True}).encode())
            private_file(root / "supervisor.json", json.dumps({"generation": uuid.uuid4().hex * 2,
                "runtime": str(python), "version": "0.8.0"}).encode())
            try:
                preflight = control("validate")
                if preflight["status"] != "valid":
                    result["activation_preflight"] = preflight["checks"]
                    raise ProbeFailure("activation_preflight_failed")
                result["native_activation_preflight"] = "passed"
                registered = True  # Even an uncertain registration needs scoped cleanup.
                processes_quiesced = False
                registration = control("register")
                result["registration"] = registration["status"]
                if registration["status"] != "enabled":
                    raise ProbeFailure("background_approval_or_registration_required")
                initial = wait_for(lambda: running(root))
                result["initial_fixture_service_ready"] = True
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
                # Run the same candidate client from a retained environment,
                # separately from the activated interpreter. No old release's
                # behavior is claimed, and no global agent settings are used.
                retained = runtime / "environments/account-access-retained"
                shutil.copytree(environment_path, retained, symlinks=True)
                retained_python = retained / "bin/python"
                client_environment = dict(os.environ)
                client_environment["ACCESS_CLIENT_CONFIG"] = str(client_config)
                client_command = [retained_python, "-I", "-m", "account_access.cli", "accounts"]
                paused_result = json.loads(run(client_command, env=client_environment, expected_exit=2))
                result["paused_managed_client_stays_stopped"] = (paused_result.get("reason") == "service_paused"
                    and running(root) is None and job_pid() is None)
                if control("unregister")["status"] != "not_registered":
                    raise ProbeFailure("fixture_job_unregister_required")
                wait_for(job_absent, timeout=10)
                result["service_unregistered"] = True
                registered = False
                # Fixture owner explicitly resumes, then maintenance shutdown
                # leaves an unpaused cold service for the retained client.
                run([launcher, "--root", root, "start", "--no-open"])
                stop(root, updating=True)
                if (root / "service.paused").exists():
                    raise ProbeFailure("fixture_maintenance_shutdown_was_paused")
                cold_result = json.loads(run(client_command, env=client_environment))
                cold_service = wait_for(lambda: running(root))
                result["retained_managed_client_uses_activated_runtime"] = (cold_result.get("status") == "OK"
                    and cold_service.get("runtime") == str(python) and cold_service.get("runtime") != str(retained_python))
                result["retained_client_scope"] = "Same candidate code in a second managed environment; not an unmodified pre-60 client"
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
                processes_quiesced = True
    except Exception as exc:
        result["failure"] = (str(exc) if isinstance(exc, ProbeFailure) else
                             exc.reason if isinstance(exc, AccessError) else "unexpected_background_probe_error")
    finally:
        if created_key and processes_quiesced:
            try:
                if keyring.get_password(service, "master") is not None:
                    keyring.delete_password(service, "master")
                result["keyring_namespace_cleaned"] = keyring.get_password(service, "master") is None
            except Exception:
                result["failure"] = "fixture_keyring_cleanup_required"
        elif created_key:
            result["failure"] = "fixture_process_cleanup_required"
        result["service_processes_quiesced"] = processes_quiesced
        logs.close()
        if processes_quiesced and (not registered or result["service_unregistered"]) and (not created_key or result["keyring_namespace_cleaned"]):
            shutil.rmtree(temporary)
        else:
            # Keep only this fixture for cleanup; never delete a still-registered
            # app and leave an unexplained broken Login Item behind.
            private_file(Path("artifacts/video/work/private-pilot") / (probe_name + "-cleanup.json"),
                         json.dumps({"app": str(app), "root": str(root), "label": identifier + ".background",
                                     "keyring_service": service}).encode(), replace=True)
        result["passed"] = all(result.get(key) for key in ["os_managed_crash_recovery", "pause_prevents_restart",
            "paused_new_job_invocation_stays_stopped", "paused_managed_client_stays_stopped",
            "retained_managed_client_uses_activated_runtime", "service_processes_quiesced", "keyring_namespace_cleaned", "service_unregistered"])
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
