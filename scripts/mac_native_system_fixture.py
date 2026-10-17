"""Disposable CI: production system host, real System key, synthetic SMS site."""

import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
import time
from types import SimpleNamespace

from account_access.storage import private_file
from account_access.worker_bootstrap import root_managed_path


def exercise_native_system(
    prefix, roles, key_policy, phase, client_token, probe, command, fixture_class
):
    if sys.platform != "darwin" or os.getuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("native_system_requires_disposable_mac_ci")
    root_managed_path(prefix)
    fixture = fixture_class(prefix, roles["agent"], tag="native-host")
    try:
        return _exercise(prefix, roles, key_policy, phase, client_token, probe, command, fixture)
    finally:
        fixture.close()


def _exercise(prefix, roles, key_policy, phase, client_token, probe, command, fixture):
    binary = prefix / "root-key-checks"

    def signature(path):
        root_managed_path(path)
        result = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, timeout=10
        )
        found = re.findall(rb"^CDHash=([a-f0-9]{40})$", result.stderr, re.MULTILINE)
        assert result.returncode == 0 and len(found) == 1
        return found[0].decode()

    source = json.loads(key_policy.read_bytes())
    state = prefix / "native-host-state"
    state.mkdir(mode=0o700)
    os.chown(state, roles["broker"].pw_uid, roles["broker"].pw_gid)
    worker = dict(
        json.loads((prefix / "policy.json").read_bytes()),
        root=str(state),
        agent_socket=str(prefix / "public/native-host.sock"),
        owner_socket=str(prefix / "control/native-host.sock"),
        owner_port=8767,
    )
    private_file(prefix / "native-host-worker.json", json.dumps(worker).encode())
    (prefix / "native-host-worker.json").chmod(0o644)
    launcher = dict(
        json.loads((prefix / "mac-launcher.json").read_bytes()),
        worker_policy=str(prefix / "native-host-worker.json"),
    )
    private_file(prefix / "native-host-launcher.json", json.dumps(launcher).encode())
    (prefix / "native-host-launcher.json").chmod(0o644)
    private_file(
        prefix / "native-host-fixture.json",
        json.dumps(
            {
                "fixture": "account-access-native-system-browser-ci-v1",
                "vault_id": source["vault_id"],
                "provider_url": fixture.provider.base,
                "client_digest": hashlib.sha256(client_token.encode()).hexdigest(),
                "helper_hash": signature(prefix / "native-messages-helper"),
                "owner_hash": signature(prefix / "root-owner-client"),
            }
        ).encode(),
    )
    (prefix / "native-host-fixture.json").chmod(0o644)
    private_file(
        prefix / "native-host-profile.json",
        json.dumps({"owner_uid": roles["agent"].pw_uid, "parent_hash": signature(binary)}).encode(),
    )
    (prefix / "native-host-profile.json").chmod(0o644)
    config = prefix / "agent-client/native-host-client.json"
    private_file(
        config,
        json.dumps(
            {"token_file": str(prefix / "agent-client/token"), "socket": worker["agent_socket"]}
        ).encode(),
    )
    os.chown(config, roles["agent"].pw_uid, roles["agent"].pw_gid)
    initialized = phase("native-host-init", collect=False)
    assert initialized and all(value is True for value in initialized.values())
    label = "com.fainir.accountaccess.qa.native-system-browser"
    target = "system/" + label
    assert subprocess.run(["/bin/launchctl", "print", target], capture_output=True).returncode != 0
    launch = prefix / "native-system-browser.plist"
    private_file(
        launch,
        plistlib.dumps(
            {
                "Label": label,
                "ProgramArguments": [str(binary), "--policy", str(key_policy), "native-host"],
                "UserName": "root",
                "GroupName": "wheel",
                "RunAtLoad": True,
                "KeepAlive": False,
                "ExitTimeOut": 20,
                "AbandonProcessGroup": False,
                "Umask": 0o077,
                "ProcessType": "Background",
                "StandardOutPath": "/dev/null",
                "StandardErrorPath": "/dev/null",
                "MachServices": {"com.fainir.accountaccess.broker.owner": True},
                "Sockets": {
                    "AccountAccessAgent": {
                        "SockPathName": worker["agent_socket"],
                        "SockPathOwner": 0,
                        "SockPathGroup": roles["agent"].pw_gid,
                        "SockPathMode": 0o660,
                    },
                    "AccountAccessOwner": {
                        "SockPathName": worker["owner_socket"],
                        "SockPathOwner": 0,
                        "SockPathGroup": 0,
                        "SockPathMode": 0o600,
                    },
                },
            }
        ),
    )
    launch.chmod(0o644)
    booted = False
    ready_file, stopped_file = (
        prefix / "native-host-ready.json",
        prefix / "native-host-stopped.json",
    )

    def start(previous=0):
        nonlocal booted
        command(["/bin/launchctl", "bootstrap", "system", str(launch)])
        booted = True
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                ready = json.loads(ready_file.read_bytes())
            except (OSError, ValueError):
                ready = {}
            service = command(["/bin/launchctl", "print", target])
            pids = re.findall(rb"\bpid = ([0-9]+)", service)
            if (
                ready.get("status") == "READY"
                and ready.get("pid") != previous
                and pids == [str(ready.get("pid")).encode()]
            ):
                assert (
                    ready["system_key_used"] is True
                    and ready["production_composed_host_used"] is True
                )
                assert ready["socket_activation_one_shot"] is True
                identity = command(
                    ["/bin/ps", "-p", str(ready["worker_pid"]), "-o", "uid=,gid=,pgid=,ppid="]
                )
                assert [int(v) for v in identity.split()] == [
                    roles["broker"].pw_uid,
                    roles["broker"].pw_gid,
                    ready["pid"],
                    ready["pid"],
                ]
                return ready
            time.sleep(0.1)
        raise RuntimeError("native_system_start_timed_out")

    def stop(ready):
        nonlocal booted
        command(["/bin/launchctl", "bootout", target])
        booted = False
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                receipt = json.loads(stopped_file.read_bytes())
            except (OSError, ValueError):
                receipt = {}
            absent = [
                subprocess.run(
                    ["/bin/ps", "-p", str(ready[key]), "-o", "pid="], capture_output=True
                ).returncode
                != 0
                for key in ["pid", "worker_pid"]
            ]
            if all(absent) and receipt == {
                "status": "STOPPED",
                "pid": ready["pid"],
                "owned_worker_stopped": True,
            }:
                return
            time.sleep(0.05)
        raise RuntimeError("native_system_owned_process_did_not_stop")

    try:
        first = start()
        print(json.dumps({"stage": "native_system_first_ready"}), file=sys.stderr, flush=True)
        checks = probe(
            prefix,
            roles,
            SimpleNamespace(pid=first["worker_pid"]),
            worker,
            "native-sms",
            client_config=config,
        )
        assert fixture.provider.login_count == fixture.provider.sms_count == fixture.delivered == 1
        print(
            json.dumps({"stage": "native_system_first_cli_completed"}), file=sys.stderr, flush=True
        )
        stop(first)
        print(json.dumps({"stage": "native_system_first_stopped"}), file=sys.stderr, flush=True)
        # The saved website cookie is now expired independently of the service.
        # A new root host must reopen the same System-key store and collect anew.
        fixture.provider.sessions.clear()
        second = start(previous=first["pid"])
        assert second["worker_pid"] != first["worker_pid"]
        print(json.dumps({"stage": "native_system_second_ready"}), file=sys.stderr, flush=True)
        repeated = probe(
            prefix,
            roles,
            SimpleNamespace(pid=second["worker_pid"]),
            worker,
            "native-sms-recover",
            client_config=config,
        )
        assert repeated.pop("durable_task_retries_cooldown_without_owner") is True
        assert (
            repeated == checks
            and fixture.provider.login_count == fixture.provider.sms_count == fixture.delivered == 2
        )
        print(
            json.dumps({"stage": "native_system_second_cli_completed"}), file=sys.stderr, flush=True
        )
        stop(second)
        print(json.dumps({"stage": "native_system_second_stopped"}), file=sys.stderr, flush=True)
        checks.update(
            {
                "system_key_initialized_private_worker_store": True,
                "durable_task_retries_cooldown_without_owner": True,
                "production_composed_host_started": True,
                "kernel_worker_parent_group_identity_verified": True,
                "launchd_socket_activation_one_shot": True,
                "two_fresh_password_sms_logins_completed": True,
                "saved_sessions_reused_after_each_login": True,
                "cold_host_reopened_same_store": True,
                "both_hosts_stopped_owned_workers": True,
                "temporary_jobs_removed": subprocess.run(
                    ["/bin/launchctl", "print", target], capture_output=True
                ).returncode
                != 0,
            }
        )
    finally:
        if booted:
            command(["/bin/launchctl", "bootout", target])
        phase("coordinator-cleanup", collect=False)
    checks["fixture_setup_policy_removed"] = True
    assert all(v is True for v in checks.values())
    return {
        "status": "PASSED",
        "platform": "macos",
        "environment": "controlled-demo",
        "production_ready": False,
        "private_signins": 0,
        "system_key_used": True,
        "production_composed_host_used": True,
        "actual_native_collector_used": True,
        "actual_distinct_uids": True,
        "full_worker_browser_sms_journey_verified": True,
        "real_messages_database_used": False,
        "physical_sms_delivery_verified": False,
        "genuine_owner_approval_verified": False,
        "genuine_full_disk_access_verified": False,
        "consumer_deployment_verified": False,
        "publisher_signed_peers": False,
        "checks": checks,
    }
