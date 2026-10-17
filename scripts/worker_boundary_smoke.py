"""Root-only CI harness for a real cross-UID broker boundary, using fake accounts.

Run only in a disposable CI VM. The runtime must already be installed in a
protected root-owned prefix. Two new, non-sudo system
identities are created and removed; no existing user or account is enrolled.
This is not a production supervisor, installer or owner enrollment gateway.
"""

import argparse
import base64
from contextlib import closing, contextmanager
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import selectors
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import urlsplit

from account_access.demo import DEMO_PASSWORD, environment
from account_access.storage import private_file
from account_access.verification_demo import ExampleMailbox, setup_config
from account_access.worker_bootstrap import root_managed_path


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("127.0.0.1", 8765, timeout=10)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def command(arguments, *, timeout=30):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    if result.returncode:
        raise RuntimeError("fixture_setup_command_failed")
    return result.stdout


def stage(name):
    print(json.dumps({"stage": name}), file=sys.stderr, flush=True)


@contextmanager
def fixture_mailbox(prefix):
    folder = prefix / "mail-fixture"
    folder.mkdir(mode=0o700)
    mailbox = ExampleMailbox(folder)
    try:
        yield mailbox
    finally:
        mailbox.close()
        shutil.rmtree(folder)


@contextmanager
def identities(prefix):
    if sys.platform == "darwin":
        with mac_identities(prefix) as roles:
            yield roles
        return
    created = []
    try:
        roles = {}
        for role in ["broker", "agent"]:
            name = "aaw" + role[0] + secrets.token_hex(4)
            home = prefix / (role + "-home")
            command(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
                     "--home-dir", str(home), "--shell", "/usr/sbin/nologin", name])
            created.append(name)
            user = pwd.getpwnam(name)
            home.mkdir(mode=0o700)
            os.chown(home, user.pw_uid, user.pw_gid)
            roles[role] = user
            assert user.pw_uid != 0 and user.pw_gid != 0
            assert not any(name in entry.gr_mem for entry in grp.getgrall())
        assert roles["broker"].pw_uid != roles["agent"].pw_uid
        yield roles
    finally:
        for name in reversed(created):
            # The worker and probes have exited before this context is left.
            command(["/usr/sbin/userdel", name])
            try:
                grp.getgrnam(name)
            except KeyError:
                continue
            command(["/usr/sbin/groupdel", name])


@contextmanager
def mac_identities(prefix):
    # Never create Directory Services records on the operator's Mac. This path
    # runs only in disposable hosted CI, under its already-authorized root role.
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("mac_worker_qa_requires_disposable_ci")
    created_users, created_groups, created_domains = [], [], []
    try:
        roles = {}
        for role in ["broker", "agent"]:
            while True:
                candidate = 50000 + secrets.randbelow(10000)
                try:
                    pwd.getpwuid(candidate)
                except KeyError:
                    try:
                        grp.getgrgid(candidate)
                    except KeyError:
                        break
            name = "aaw" + role[0] + secrets.token_hex(4)
            group_path, user_path = "/Groups/" + name, "/Users/" + name
            home = prefix / (role + "-home")
            command(["/usr/bin/dscl", ".", "-create", group_path])
            created_groups.append(group_path)
            command(["/usr/bin/dscl", ".", "-create", group_path, "PrimaryGroupID", str(candidate)])
            command(["/usr/bin/dscl", ".", "-create", user_path])
            created_users.append(user_path)
            for field, value in {"UniqueID": str(candidate), "PrimaryGroupID": str(candidate),
                "NFSHomeDirectory": str(home), "UserShell": "/usr/bin/false", "IsHidden": "1", "Password": "*"}.items():
                command(["/usr/bin/dscl", ".", "-create", user_path, field, value])
            command(["/usr/bin/dscacheutil", "-flushcache"])
            user = pwd.getpwnam(name)
            assert user.pw_uid == candidate and user.pw_gid == candidate
            home.mkdir(mode=0o700)
            os.chown(home, user.pw_uid, user.pw_gid)
            roles[role] = user
            # A UID switch does not adopt its Mach bootstrap/audit session.
            # Create only this newly allocated account's user domain, and
            # remove it before deleting the temporary Directory Services entry.
            command(["/bin/launchctl", "bootstrap", "user/" + str(candidate)])
            created_domains.append("user/" + str(candidate))
        yield roles
    finally:
        for domain in reversed(created_domains):
            command(["/bin/launchctl", "bootout", domain])
        for record in reversed(created_users):
            command(["/usr/bin/dscl", ".", "-delete", record])
        for record in reversed(created_groups):
            command(["/usr/bin/dscl", ".", "-delete", record])
        command(["/usr/bin/dscacheutil", "-flushcache"])


def dropped(user):
    if sys.platform == "darwin":
        return ["/bin/launchctl", "asuser", str(user.pw_uid), "/usr/bin/sudo", "-n", "-H",
                "-u", "#" + str(user.pw_uid), "-g", "#" + str(user.pw_gid), "--"]
    return ["/usr/bin/setpriv", "--reuid=" + str(user.pw_uid), "--regid=" + str(user.pw_gid),
            "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all",
            "--ambient-caps=-all", "--reset-env"]


def chown_tree(root, user):
    for path in [*root.rglob("*"), root]:
        assert not path.is_symlink()
        os.chown(path, user.pw_uid, user.pw_gid)
        path.chmod(0o700 if path.is_dir() else 0o600)


def owner_request(path, token, route, body):
    with UnixHTTP(path) as channel:
        channel.request("POST", route, json.dumps(body), {"Authorization": "Bearer " + token,
                        "Origin": "http://127.0.0.1:8765", "Content-Type": "application/json"})
        response = channel.getresponse()
        result = json.loads(response.read())
        assert response.status == 200, "fixture_owner_operation_failed"
        return result


def probe(prefix, roles, worker, policy, phase):
    module = __import__("account_access.worker_host", fromlist=["__file__"]).__file__
    arguments = [*dropped(roles["agent"]), sys.executable, "-I", "-B", str(prefix / "probe.py"),
        "--phase", phase, "--config", str(prefix / "agent-client/client.json"),
        "--state", policy["root"], "--worker-module", module, "--policy", str(prefix / "policy.json"),
        "--owner-socket", policy["owner_socket"], "--agent-socket", policy["agent_socket"],
        "--worker-pid", str(worker.pid), "--worker-uid", str(roles["broker"].pw_uid)]
    if sys.platform == "darwin":
        arguments += ["--mac-bootstrap", str(prefix / "mac-worker-bootstrap")]
    completed = subprocess.run(arguments, capture_output=True, timeout=240,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    result = json.loads(completed.stdout)
    if completed.returncode:
        # This harness is also executed as an isolated standalone script; it
        # cannot import a sibling script through a user-controlled search path.
        diagnostic_stages = {"account_discovery", "revoked_read", "ungranted_read", "boundary_checks",
                             "demo-api", "demo-web", "demo-mfa", "example-email", "example-sms"}
        safe_reasons = {"browser_guard_unavailable", "internal_error", "service_unavailable", "worker_unavailable",
                       "login_failed", "verification_code_unavailable", "invalid_credentials", "request_failed",
                       "browser_execution_failed", "login_code_not_received", "verification_code_rejected",
                       "verification_source_not_connected", "browser_state_unrecognized", "login_retry_cooldown"}
        # Closed fixture labels only. Never copy raw CLI/provider output.
        if result.get("stage") in diagnostic_stages:
            stage("probe_" + result["stage"])
        if result.get("operation_status") in {"COMPLETED", "DENIED", "NEEDS_USER", "RETRYABLE", "OK"}:
            stage("operation_" + result["operation_status"])
        if result.get("operation_reason") in safe_reasons:
            stage(result["operation_reason"])
        raise RuntimeError("fixture_boundary_probe_failed")
    assert result["status"] == "PASSED", "fixture_boundary_probe_failed"
    return result["checks"]


def root_owner_gateway(prefix, roles, policy, capability, worker):
    """Deploy only in the disposable VM; never install on the operator's Mac."""
    if sys.platform != "darwin" or os.getuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("root_owner_qa_requires_disposable_mac_ci")
    label = "com.fainir.accountaccess.broker.owner"
    if subprocess.run(["/bin/launchctl", "print", "system/" + label], capture_output=True).returncode == 0:
        raise RuntimeError("root_owner_namespace_already_occupied")
    daemon, trusted, denied = (prefix / name for name in ["root-owner-gateway", "root-owner-client", "root-owner-client-denied"])
    def code_hash(path):
        root_managed_path(path)
        signed = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, timeout=10)
        matches = re.findall(rb"^CDHash=([a-f0-9]{40})$", signed.stderr, re.MULTILINE)
        assert signed.returncode == 0 and len(matches) == 1
        return matches[0].decode()
    daemon_hash, trusted_hash = code_hash(daemon), code_hash(trusted)
    assert code_hash(denied) != trusted_hash
    source_path = prefix / "control/boot.sock"
    public_policy = prefix / "root-owner.json"
    value = {"fixture": "account-access-root-owner-ci-v1", "owner_uid": roles["agent"].pw_uid,
             "owner_hash": trusted_hash, "server_hash": daemon_hash, "owner_socket": policy["owner_socket"],
             "owner_port": policy["owner_port"], "bootstrap_socket": str(source_path)}
    public_policy.write_text(json.dumps(value))
    public_policy.chmod(0o644)
    wrong_server = prefix / "root-owner-wrong-server.json"
    wrong_server.write_text(json.dumps({**value, "server_hash": "0" * 40}))
    wrong_server.chmod(0o644)
    launch = prefix / "root-owner.plist"
    launch.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": [str(daemon), "--policy", str(public_policy)],
        "UserName": "root", "GroupName": "wheel", "RunAtLoad": True, "KeepAlive": False,
        "MachServices": {label: True}, "ProcessType": "Background", "ExitTimeOut": 10,
        "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}))
    launch.chmod(0o644)
    checks, booted, held = {}, False, None
    def client(binary, user, mode, policy_path=public_policy):
        result = subprocess.run([*dropped(user), str(binary), "--policy", str(policy_path), mode],
            capture_output=True, timeout=100, env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
        assert capability.encode() not in result.stdout + result.stderr
        report = json.loads(result.stdout)
        assert result.returncode == 0 and report["status"] == "PASSED" and all(item is True for item in report["checks"].values())
        return report["checks"]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bootstrap:
        bootstrap.bind(str(source_path))
        bootstrap.listen(1)
        bootstrap.settimeout(40)
        source_path.chmod(0o600)
        issued = threading.Event()
        def supply():
            try:
                channel, _ = bootstrap.accept()
                with channel:
                    import ctypes
                    system = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
                    system.getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
                    system.getpeereid.restype = ctypes.c_int
                    uid, gid = ctypes.c_uint(), ctypes.c_uint()
                    assert system.getpeereid(channel.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0 and uid.value == 0
                    channel.sendall(capability.encode())
                    channel.shutdown(socket.SHUT_WR)
                issued.set()
            except Exception:
                pass  # Fixed timeout/failure below; no capability/exception text.
        sender = threading.Thread(target=supply, daemon=True)
        sender.start()
        try:
            stage("root_owner_launchd_bootstrap")
            command(["/bin/launchctl", "bootstrap", "system", str(launch)])
            booted = True
            assert issued.wait(45), "root_owner_bootstrap_failed"
            checks["root_only_capability_handoff"] = True
            service = command(["/bin/launchctl", "print", "system/" + label])
            matches = re.findall(rb"\bpid = ([0-9]+)", service)
            assert len(matches) == 1
            pid = int(matches[0])
            assert command(["/bin/ps", "-p", str(pid), "-o", "uid="]).strip() == b"0"
            checks["daemon_root_uid_verified"] = True
            stage("root_owner_signed_client")
            checks.update(client(trusted, roles["agent"], "accepted"))
            for name, binary, user, client_policy in [
                ("wrong_client", denied, roles["agent"], public_policy),
                ("wrong_user", trusted, roles["broker"], public_policy),
                ("wrong_server", trusted, roles["agent"], wrong_server),
            ]:
                stage("root_owner_" + name)
                result = client(binary, user, "denied", client_policy)
                for suffix, source in [("refused", "prepare_refused"), ("setup_refused", "failed_prepare_refuses_setup"),
                                       ("credential_input_refused", "failed_prepare_refuses_credential_input")]:
                    checks[name + "_" + suffix] = result[source]
            stage("root_owner_stop_live_connection")
            held = subprocess.Popen([*dropped(roles["agent"]), str(trusted), "--policy", str(public_policy), "hold"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
            with selectors.DefaultSelector() as ready:
                ready.register(held.stdout, selectors.EVENT_READ)
                assert ready.select(45)
                assert json.loads(held.stdout.readline(256)) == {"stage": "owner_connection_ready"}
            command(["/bin/launchctl", "bootout", "system/" + label])
            booted = False
            stdout, stderr = held.communicate(b"continue\n", timeout=45)
            assert capability.encode() not in stdout + stderr
            report = json.loads(stdout)
            assert held.returncode == 0 and report["status"] == "PASSED"
            checks.update(report["checks"])
            checks["launchd_service_removed"] = subprocess.run(["/bin/launchctl", "print", "system/" + label], capture_output=True).returncode != 0
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("root_owner_daemon_did_not_exit")
            checks["daemon_process_exited"] = True
            checks["gateway_stop_keeps_worker_alive"] = worker.poll() is None
            checks["capability_absent_from_client_output"] = True
            assert checks and all(item is True for item in checks.values())
            return {"status": "PASSED", "environment": "controlled-demo", "platform": "macos", "production_ready": False,
                    "private_signins": 0, "root_service_installed": True, "consumer_deployment_verified": False,
                    "real_owner_auth_approval_tested": False, "authorization_database_changed": False,
                    "publisher_signed_peers": False, "checks": checks}
        finally:
            if held is not None and held.poll() is None:
                os.killpg(held.pid, signal.SIGTERM)
                held.communicate(timeout=10)
            if booted:
                command(["/bin/launchctl", "bootout", "system/" + label])
            bootstrap.close()
            sender.join(timeout=2)
            source_path.unlink(missing_ok=True)


def root_coordinator(prefix, roles, key_policy, phase):
    """Crash the actual composed host, using launchd-owned listeners and groups."""
    if sys.platform != "darwin" or os.getuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("coordinator_requires_disposable_mac_ci")
    stage("coordinator_prepare")
    binary, client = prefix / "root-key-checks", prefix / "root-owner-client"
    ready = prefix / "root-coordinator-ready.json"
    public = prefix / "root-coordinator-client.json"
    plan = json.loads((prefix / "key-worker-policy.json").read_bytes())
    paths = [Path(plan["agent_socket"]), Path(plan["owner_socket"])]
    assert all(not item.exists() and not item.is_symlink() for item in paths)
    def signature(path):
        result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, timeout=10)
        hashes = re.findall(rb"^CDHash=([a-f0-9]{40})$", result.stderr, re.MULTILINE)
        assert result.returncode == 0 and len(hashes) == 1
        return hashes[0].decode()
    private_file(prefix / "root-coordinator.json", json.dumps({"fixture": "account-access-root-coordinator-ci-v1",
        "owner_hash": signature(client)}).encode())
    private_file(public, json.dumps({"fixture": "account-access-root-owner-ci-v1", "owner_uid": roles["agent"].pw_uid,
        "owner_hash": signature(client), "server_hash": signature(binary), "owner_socket": str(paths[1]),
        "owner_port": plan["owner_port"], "bootstrap_socket": str(prefix / "control/coordinator-unused.sock")}).encode())
    public.chmod(0o644)
    label = "com.fainir.accountaccess.qa.coordinator"
    target = "system/" + label
    if subprocess.run(["/bin/launchctl", "print", target], capture_output=True).returncode == 0:
        raise RuntimeError("coordinator_namespace_already_occupied")
    launch = prefix / (label + ".plist")
    launch.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": [str(binary), "--policy", str(key_policy), "coordinator"],
        "UserName": "root", "GroupName": "wheel", "RunAtLoad": True, "KeepAlive": True,
        "ThrottleInterval": 1, "ExitTimeOut": 20, "AbandonProcessGroup": False, "Umask": 0o077,
        "ProcessType": "Background", "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
        "MachServices": {"com.fainir.accountaccess.broker.owner": True},
        "Sockets": {"AccountAccessAgent": {"SockPathName": str(paths[0]), "SockPathOwner": 0,
            "SockPathGroup": roles["agent"].pw_gid, "SockPathMode": 0o660},
            "AccountAccessOwner": {"SockPathName": str(paths[1]), "SockPathOwner": 0, "SockPathGroup": 0, "SockPathMode": 0o600}}}))
    launch.chmod(0o644)
    checks, booted, held = {}, False, None
    known_sockets = {}
    def snapshot(*, previous=0, state="running"):
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            try:
                value = json.loads(ready.read_bytes())
            except (OSError, ValueError):
                value = {}
            if value.get("status") == "READY" and value.get("pid") != previous and value.get("worker_state") == state:
                assert set(value) == {"status", "pid", "uid", "group", "worker_pid", "worker_group", "worker_state", "setup_policy_registered", "socket_activation_one_shot"}
                assert value["uid"] == 0 and type(value["pid"]) is int and value["pid"] > 0
                assert value["group"] == value["pid"] and value["setup_policy_registered"] is True
                assert value["socket_activation_one_shot"] is True
                if state == "running":
                    assert type(value["worker_pid"]) is int and value["worker_pid"] > 0
                    assert value["worker_group"] == value["group"]
                    output = command(["/bin/ps", "-p", str(value["worker_pid"]), "-o", "uid=,gid=,pgid=,ppid="])
                    assert [int(item) for item in output.split()] == [roles["broker"].pw_uid, roles["broker"].pw_gid, value["pid"], value["pid"]]
                else:
                    assert value["worker_pid"] == 0 and value["worker_group"] == 0
                return value
            failure = prefix / "key-coordinator.json"
            if failure.exists():
                detail = json.loads(failure.read_bytes())
                if detail.get("reason") in {"broker_socket_activation_unavailable", "broker_socket_activation_invalid",
                        "broker_socket_activation_context_invalid", "broker_socket_activation_metadata_invalid", "broker_socket_activation_identity_changed",
                        "broker_socket_activation_in_use", "owner_policy_changed", "owner_policy_unavailable", "owner_policy_readback_invalid",
                        "worker_process_unavailable", "worker_bootstrap_code_rejected", "vault_key_missing", "system_keychain_unavailable"}:
                    stage(detail["reason"])
                raise RuntimeError("coordinator_start_failed")
            time.sleep(0.1)
        stage("coordinator_ready_timed_out")
        raise RuntimeError("coordinator_ready_timed_out")
    def stopped(pid):
        # Observation only. Never signal a process from metadata.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.1)
        return False
    def read_client(prefix_name):
        result = subprocess.run([*dropped(roles["agent"]), str(client), "--policy", str(public), "coordinator"],
            capture_output=True, timeout=50, env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
        value = json.loads(result.stdout)
        assert result.returncode == 0 and value["status"] == "PASSED" and value["checks"]
        for name, passed in value["checks"].items():
            assert passed is True
            checks[prefix_name + "_" + name] = True
    def denied_client(who, executable, policy=public):
        result = subprocess.run([*dropped(who), str(executable), "--policy", str(policy), "denied"],
            capture_output=True, timeout=50, env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
        value = json.loads(result.stdout)
        return result.returncode == 0 and value.get("status") == "PASSED" and value.get("checks") == {
            "prepare_refused": True, "failed_prepare_refuses_setup": True, "failed_prepare_refuses_credential_input": True}
    try:
        stage("coordinator_first_bootstrap")
        command(["/bin/launchctl", "bootstrap", "system", str(launch)])
        booted = True
        first = snapshot()
        checks["composed_system_host_started"] = True
        checks["worker_kernel_identity_and_job_group_verified"] = True
        checks["socket_activation_cannot_replay"] = first["socket_activation_one_shot"]
        for item in paths:
            info = item.lstat()
            known_sockets[item] = (info.st_dev, info.st_ino)
        read_client("initial")
        checks["unapproved_client_code_refused"] = denied_client(roles["agent"], prefix / "root-owner-client-denied")
        checks["wrong_owner_uid_refused"] = denied_client(roles["broker"], client)
        wrong = prefix / "root-coordinator-wrong-server.json"
        wrong_value = json.loads(public.read_bytes())
        wrong_value["server_hash"] = "0" * 40
        private_file(wrong, json.dumps(wrong_value).encode())
        wrong.chmod(0o644)
        checks["wrong_server_signature_refused"] = denied_client(roles["agent"], client, wrong)
        stage("coordinator_hold_owner_connection")
        held = subprocess.Popen([*dropped(roles["agent"]), str(client), "--policy", str(public), "hold"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
        with selectors.DefaultSelector() as selector:
            selector.register(held.stdout, selectors.EVENT_READ)
            assert selector.select(45) and json.loads(held.stdout.readline(256)) == {"stage": "owner_connection_ready"}
        stage("coordinator_parent_sigkill")
        command(["/bin/launchctl", "kill", "SIGKILL", target])
        recovered = snapshot(previous=first["pid"])
        checks["system_manager_restarted_crashed_parent"] = recovered["pid"] != first["pid"]
        checks["old_worker_exited_without_pid_adoption"] = stopped(first["worker_pid"])
        checks["replacement_worker_has_new_process_identity"] = recovered["worker_pid"] != first["worker_pid"]
        checks["activated_socket_identity_survives_parent_crash"] = all((item.lstat().st_dev, item.lstat().st_ino) == identity
            for item, identity in known_sockets.items())
        stdout, _ = held.communicate(b"continue\n", timeout=45)
        old = json.loads(stdout)
        checks["crashed_parent_owner_channel_retired"] = held.returncode == 0 and old["status"] == "PASSED" and old["checks"] == {"stopped_service_channel_refused": True}
        read_client("recovered")
        stage("coordinator_cold_service_start")
        command(["/bin/launchctl", "bootout", target])
        booted = False
        checks["old_parent_exits_on_service_removal"] = stopped(recovered["pid"])
        checks["old_worker_exits_on_service_removal"] = stopped(recovered["worker_pid"])
        command(["/bin/launchctl", "bootstrap", "system", str(launch)])
        booted = True
        cold = snapshot(previous=recovered["pid"])
        checks["cold_service_reopens_system_key_store"] = cold["worker_pid"] != recovered["worker_pid"]
        read_client("cold")
        stage("coordinator_pause_then_parent_crash")
        pause = Path(plan["root"]) / "service.paused"
        private_file(pause, b"paused\n")
        paused = snapshot(state="paused")
        checks["pause_stops_owned_worker_before_parent_crash"] = paused["worker_pid"] == 0
        command(["/bin/launchctl", "kill", "SIGKILL", target])
        later = snapshot(previous=paused["pid"], state="paused")
        checks["pause_survives_parent_restart"] = later["worker_pid"] == 0
        result = subprocess.run([*dropped(roles["agent"]), str(client), "--policy", str(public), "coordinator-paused"],
            capture_output=True, timeout=50, env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
        value = json.loads(result.stdout)
        checks["paused_parent_keeps_native_gateway_alive"] = later["pid"] != paused["pid"] and result.returncode == 0 and value == {
            "status": "PASSED", "checks": {"coordinator_paused_peer_prepared": True,
                "coordinator_paused_state_refused": True, "coordinator_paused_ungranted_setup_refused": True}}
        assert checks and all(value is True for value in checks.values())
    finally:
        if held is not None and held.poll() is None:
            os.killpg(held.pid, signal.SIGTERM)
            held.communicate(timeout=10)
        if booted:
            command(["/bin/launchctl", "bootout", target])
        phase("coordinator-cleanup", collect=False)
        checks["fixture_setup_policy_removed"] = True
        (Path(plan["root"]) / "service.paused").unlink(missing_ok=True)
    checks["system_job_removed"] = subprocess.run(["/bin/launchctl", "print", target], capture_output=True).returncode != 0
    assert checks and all(value is True for value in checks.values())
    return checks


def root_key_custody(prefix, roles):
    """Touch only a new fixture UUID in the disposable VM's System keychain."""
    if sys.platform != "darwin" or os.getuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("key_custody_requires_disposable_mac_ci")
    binary, denied = prefix / "root-key-checks", prefix / "root-key-checks-denied"
    for path in (binary, denied):
        root_managed_path(path)
    identity = str(uuid.uuid4())
    policy = prefix / "root-key.json"
    signed = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(prefix / "mac-worker-bootstrap")], capture_output=True, timeout=10)
    hashes = re.findall(rb"^CDHash=([a-f0-9]{40})$", signed.stderr, re.MULTILINE)
    assert signed.returncode == 0 and len(hashes) == 1
    policy.write_text(json.dumps({"fixture": "account-access-system-key-ci-v1", "vault_id": identity, "root": str(prefix),
        "launcher": str(prefix / "mac-launcher.json"), "worker_launcher": str(prefix / "key-worker-launcher.json"),
        "bootstrap_hash": hashes[0].decode()}))
    policy.chmod(0o644)
    label = "com.fainir.accountaccess.qa.key-custody"
    if subprocess.run(["/bin/launchctl", "print", "system/" + label], capture_output=True).returncode == 0:
        raise RuntimeError("key_custody_namespace_already_occupied")
    checks, pids = {}, []
    handoff_state = prefix / "key-handoff-state"
    handoff_state.mkdir(mode=0o700)
    os.chown(handoff_state, roles["broker"].pw_uid, roles["broker"].pw_gid)
    worker_policy = json.loads((prefix / "policy.json").read_bytes())
    worker_policy.update(root=str(handoff_state), agent_socket=str(prefix / "public/key-worker.sock"),
                         owner_socket=str(prefix / "control/key-owner.sock"), owner_port=8766)
    private_file(prefix / "key-worker-policy.json", json.dumps(worker_policy).encode())
    (prefix / "key-worker-policy.json").chmod(0o644)
    launcher = json.loads((prefix / "mac-launcher.json").read_bytes())
    launcher["worker_policy"] = str(prefix / "key-worker-policy.json")
    private_file(prefix / "key-worker-launcher.json", json.dumps(launcher).encode())
    (prefix / "key-worker-launcher.json").chmod(0o644)
    def phase(mode, *, collect=True):
        stage("key_custody_" + mode)
        launch = prefix / "root-key.plist"
        launch.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": [str(binary), "--policy", str(policy), mode],
            "UserName": "root", "GroupName": "wheel", "RunAtLoad": True, "KeepAlive": False,
            "ProcessType": "Background", "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}))
        launch.chmod(0o644)
        command(["/bin/launchctl", "bootstrap", "system", str(launch)])
        try:
            path = prefix / ("key-" + mode + ".json")
            # These phases contain several independently bounded worker
            # starts/stops; their aggregate budget must cover the full journey.
            deadline = time.monotonic() + {"handoff": 240, "supervisor": 420}.get(mode, 45)
            while time.monotonic() < deadline:
                service = command(["/bin/launchctl", "print", "system/" + label])
                exited = re.findall(rb"last exit code = ([0-9]+)", service)
                if path.exists() and exited:
                    result = json.loads(path.read_bytes())
                    if result.get("status") != "PASSED" or exited != [b"0"]:
                        reason = result.get("reason")
                        if reason in {"system_daemon_context_required", "invalid_vault_identity", "vault_key_missing",
                            "vault_key_already_enrolled", "invalid_vault_key_record", "system_keychain_unavailable", "root_key_checks_failed",
                            "vault_key_reference_result_invalid", "vault_key_data_result_invalid", "vault_key_enrollment_readback_invalid",
                            "worker_secret_channel_unavailable", "worker_secret_channel_already_consumed",
                            "worker_process_invalid_state", "worker_process_unavailable", "worker_socket_already_occupied",
                            "worker_bootstrap_code_rejected", "worker_process_ownership_lost", "worker_socket_identity_changed",
                            "worker_store_paused"}:
                            stage(reason)
                        if result.get("checkpoint") in {"policy", "context", "invalid_identity", "initial_missing", "enrollment",
                            "encryption", "duplicate_enrollment", "other_vault", "restart_recovery", "fixture_removal", "system_location",
                            "native_handoff", "native_worker_service", "native_worker_supervisor"}:
                            stage("key_checkpoint_" + result["checkpoint"])
                        failed_checks = result.get("failed_checks")
                        if (isinstance(failed_checks, list) and len(failed_checks) <= 100
                                and all(isinstance(name, str) and re.fullmatch(r"[a-z_]{1,100}", name) for name in failed_checks)):
                            print(json.dumps({"failed_native_checks": failed_checks}), file=sys.stderr, flush=True)
                        if result.get("record_shape") in {"array", "data", "dictionary", "absent", "other"}:
                            stage("key_record_shape_" + result["record_shape"])
                        if type(result.get("record_count")) is int and 0 <= result["record_count"] <= 10_000:
                            print(json.dumps({"key_record_count": result["record_count"]}), file=sys.stderr, flush=True)
                        if type(result.get("unique_reference_count")) is int and 0 <= result["unique_reference_count"] <= 10_000:
                            print(json.dumps({"unique_key_reference_count": result["unique_reference_count"]}), file=sys.stderr, flush=True)
                        if result.get("keychain_operation") in {"load", "enroll", "remove"}:
                            stage("keychain_" + result["keychain_operation"])
                        if type(result.get("keychain_status")) is int:
                            print(json.dumps({"keychain_status": result["keychain_status"]}), file=sys.stderr, flush=True)
                        raise RuntimeError("key_custody_phase_failed")
                    assert set(result) == {"status", "checks", "pid", "uid"} and result["uid"] == 0
                    assert type(result["pid"]) is int and result["pid"] > 0
                    assert result["checks"] and all(item is True for item in result["checks"].values())
                    if collect:
                        pids.append(result["pid"])
                        for key, value in result["checks"].items():
                            checks[mode + "_" + key] = value
                    return result["checks"]
                time.sleep(0.1)
            stage("key_custody_phase_timed_out")
            raise RuntimeError("key_custody_phase_timed_out")
        finally:
            command(["/bin/launchctl", "bootout", "system/" + label])
    try:
        phase("create")
        phase("reopen")
        handoff = phase("handoff", collect=False)
        supervisor = phase("supervisor", collect=False)
        coordinator = root_coordinator(prefix, roles, policy, phase)
        stage("key_custody_unprivileged_direct_read")
        result = subprocess.run([*dropped(roles["agent"]), str(denied), "--policy", str(policy), "unprivileged"],
            capture_output=True, timeout=45, env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
        value = json.loads(result.stdout)
        if result.returncode and type(value.get("probe_status")) is int:
            print(json.dumps({"keychain_probe_status": value["probe_status"]}), file=sys.stderr, flush=True)
        assert result.returncode == 0 and set(value) == {"status", "checks", "pid", "uid", "probe_status"}
        assert value["status"] == "PASSED" and value["uid"] == roles["agent"].pw_uid
        assert value["checks"] and all(item is True for item in value["checks"].values())
        for key, verified in value["checks"].items():
            checks["unprivileged_" + key] = verified
    finally:
        phase("remove")
    checks["separate_daemon_processes_used"] = len(set(pids)) == 3
    def signature(path):
        signed = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, timeout=10)
        matches = re.findall(rb"^CDHash=([a-f0-9]{40})$", signed.stderr, re.MULTILINE)
        assert signed.returncode == 0 and len(matches) == 1
        return matches[0]
    checks["unprivileged_probe_has_different_code_signature"] = signature(binary) != signature(denied)
    assert checks and all(item is True for item in checks.values())
    handoff_report = {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
        "private_signins": 0, "system_key_used": True, "production_python_reader_used": True, "production_storage_used": True,
        "consumer_deployment_verified": False, "production_supervision_verified": False, "actual_worker_store_handoff_verified": True,
        "fixture_key_removed": True, "checks": handoff}
    evidence = Path("/tmp/account-access-mac-key-handoff.json")
    private_file(evidence, (json.dumps(handoff_report, indent=2) + "\n").encode())
    evidence.chmod(0o644)
    coordinator_report = {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
        "private_signins": 0, "system_key_used": True, "actual_worker_used": True, "consumer_deployment_verified": False,
        "actual_root_composition_verified": True, "parent_daemon_recovery_verified": True, "machine_reboot_verified": False,
        "genuine_owner_approval_verified": False, "authorization_database_changed": True, "fixture_policy_removed": True,
        "fixture_key_removed": True, "publisher_signed_peers": False, "checks": coordinator}
    evidence = Path("/tmp/account-access-mac-root-coordinator.json")
    private_file(evidence, (json.dumps(coordinator_report, indent=2) + "\n").encode())
    evidence.chmod(0o644)
    supervisor_report = {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
        "private_signins": 0, "system_key_used": True, "actual_worker_used": True, "consumer_deployment_verified": False,
        "parent_daemon_recovery_verified": False, "genuine_owner_approval_verified": False,
        "owner_session_checks": "synthetic-in-process", "controlled_monotonic_clock": True,
        "fixture_key_removed": True, "checks": supervisor}
    evidence = Path("/tmp/account-access-mac-root-supervisor.json")
    private_file(evidence, (json.dumps(supervisor_report, indent=2) + "\n").encode())
    evidence.chmod(0o644)
    return {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
            "private_signins": 0, "personal_keychain_used": False, "consumer_deployment_verified": False,
            "fixture_namespace": True, "fixture_key_removed": True, "direct_read_status": value["probe_status"], "checks": checks}


def root_owner_policy(prefix, roles):
    """Provision/remove only the QA right in a disposable VM system session."""
    if sys.platform != "darwin" or os.getuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("owner_policy_requires_disposable_mac_ci")
    binary, guard = prefix / "root-owner-policy-checks", prefix / "owner-policy-guard-checks"
    for path in (binary, guard):
        root_managed_path(path)
    label = "com.fainir.accountaccess.qa.owner-policy"
    if subprocess.run(["/bin/launchctl", "print", "system/" + label], capture_output=True).returncode == 0:
        raise RuntimeError("owner_policy_namespace_already_occupied")
    policy = prefix / "owner-policy.json"
    policy.write_text(json.dumps({"fixture": "account-access-owner-policy-ci-v1", "root": str(prefix)}))
    policy.chmod(0o644)
    launch = prefix / "owner-policy.plist"
    launch.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": [str(binary), "--policy", str(policy)],
        "UserName": "root", "GroupName": "wheel", "RunAtLoad": True, "KeepAlive": False,
        "ProcessType": "Background", "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}))
    launch.chmod(0o644)
    stage("owner_policy_system_provisioning")
    command(["/bin/launchctl", "bootstrap", "system", str(launch)])
    try:
        report = prefix / "owner-policy-report.json"
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            service = command(["/bin/launchctl", "print", "system/" + label])
            exited = re.findall(rb"last exit code = ([0-9]+)", service)
            if report.exists() and exited:
                value = json.loads(report.read_bytes())
                if value.get("status") != "PASSED" or exited != [b"0"]:
                    if value.get("reason") in {"owner_policy_requires_system_daemon", "owner_policy_changed",
                        "owner_policy_unavailable", "owner_policy_readback_invalid", "owner_policy_checks_failed"}:
                        stage(value["reason"])
                    if value.get("checkpoint") in {"policy", "namespace", "install", "root_shortcut", "changed_policy",
                        "permissive_proof", "restore", "cleanup"}:
                        stage("owner_policy_checkpoint_" + value["checkpoint"])
                    fields = value.get("definition_fields")
                    if (isinstance(fields, list) and len(fields) <= 32
                            and all(isinstance(item, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", item) for item in fields)):
                        print(json.dumps({"fixture_definition_fields": fields}), file=sys.stderr, flush=True)
                    raise RuntimeError("owner_policy_acceptance_failed")
                assert set(value) == {"status", "checks", "pid", "uid"} and value["uid"] == 0
                assert type(value["pid"]) is int and value["pid"] > 0
                checks = value["checks"]
                assert checks and all(item is True for item in checks.values())
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("owner_policy_acceptance_timed_out")
    finally:
        command(["/bin/launchctl", "bootout", "system/" + label])
    result = subprocess.run([*dropped(roles["agent"]), str(guard)], capture_output=True, timeout=30,
                            env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
    assert result.returncode == 0 and json.loads(result.stdout) == {"status": "PASSED",
        "unprivileged_policy_install_refused": True, "authorization_database_changed": False}
    checks["unprivileged_policy_install_refused"] = True
    return {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
            "private_signins": 0, "authorization_database_changed": True, "fixture_namespace": True,
            "fixture_right_removed": True, "synthetic_permissive_rule_used": True,
            "real_owner_auth_approval_tested": False, "consumer_deployment_verified": False, "checks": checks}


def exercise(prefix, roles):
    if sys.platform == "darwin":
        # No login data is provided to this canary. It checks whether the
        # dedicated identity can start sandboxed Chromium in the CI session.
        stage("credential_free_browser_canary")
        # sudo resets its environment. Place these fixed, non-secret settings
        # after the identity switch so the canary uses the installed browser.
        canary = subprocess.run([*dropped(roles["broker"]), "/usr/bin/env",
            "PLAYWRIGHT_BROWSERS_PATH=" + str(prefix / "browsers"), "HOME=" + roles["broker"].pw_dir,
            "LANG=en_US.UTF-8", sys.executable, "-I", "-B", str(prefix / "browser-probe.py")],
            capture_output=True, timeout=45, env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
        if canary.returncode:
            result = json.loads(canary.stdout)
            allowed = {"mach_bootstrap_registration_failed", "browser_profile_unavailable", "browser_not_installed",
                       "browser_launch_not_permitted", "browser_launch_permission_denied",
                       "browser_closed_during_launch", "browser_canary_failed"}
            if result.get("reason") in allowed:
                stage(result["reason"])
            for site in result.get("chromium_sites", [])[:8]:
                if isinstance(site, str) and re.fullmatch(r"[a-z_]+\.(?:cc|mm):[0-9]{1,6}", site):
                    stage("chromium_site_" + site)
            raise RuntimeError("fixture_browser_canary_failed")
    stage("prepare_fictional_state")
    state = prefix / "state"
    agent_directory, control_directory = prefix / "public", prefix / "control"
    agent_directory.mkdir(mode=0o755)
    agent_directory.chmod(0o755)
    control_directory.mkdir(mode=0o700)
    api_path, owner_path = str(agent_directory / "api.sock"), str(control_directory / "owner.sock")
    policy = {"managed_by": "account-access-worker-v1", "schema": 1,
              "broker_uid": roles["broker"].pw_uid, "agent_uid": roles["agent"].pw_uid,
              "root": str(state), "agent_socket": api_path, "owner_socket": owner_path, "owner_port": 8765}
    private_file(prefix / "policy.json", json.dumps(policy).encode())
    (prefix / "policy.json").chmod(0o644)
    worker = None
    reader = writer = None
    with environment(state) as (provider, broker, _), fixture_mailbox(prefix) as mailbox:
        config = broker.store.config()
        verification = setup_config(provider.base, mailbox, relay=True)
        for account in ["example-email", "example-sms"]:
            config.accounts[account] = verification.accounts[account]
            broker.store.put("credential:" + account, {"username": "demo@example.test", "password": DEMO_PASSWORD})
        config.code_sources.update(verification.code_sources)
        broker.store.configure(config)
        broker.store.put("source:example-email", {"username": "demo@example.test", "password": DEMO_PASSWORD})
        # Only the public test CA crosses into the worker. Mail credentials are
        # encrypted in its private store, never environment/argv/bootstrap logs.
        private_file(prefix / "fixture-mail-ca.pem", mailbox.cert_path.read_bytes())
        (prefix / "fixture-mail-ca.pem").chmod(0o644)
        phone = {}
        delivered_sms = []
        def deliver(kind, code):
            if kind == "email":
                mailbox.deliver(code)
            elif kind == "sms":
                address = urlsplit(phone["url"])
                certificate = (state / "phone/certificate.pem").read_bytes()
                fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate.decode())).hexdigest()
                assert secrets.compare_digest(fingerprint, phone["certificate_sha256"])
                context = ssl.create_default_context(cadata=certificate.decode())
                with closing(http.client.HTTPSConnection(
                        address.hostname, address.port, context=context, timeout=10)) as channel:
                    channel.request("POST", address.path, json.dumps({"id": secrets.token_hex(16),
                        "sender": "Example", "recipient": "demo@example.test", "body": "Example sign-in: " + code,
                        "received_at": time.time()}), {"Authorization": "Bearer " + phone["token"],
                        "Content-Type": "application/json"})
                    response = channel.getresponse()
                    assert response.status == 200 and json.loads(response.read())["status"] == "RECEIVED"
                delivered_sms.append(True)
        provider.delivery = deliver
        token = broker.store.new_client("fixture-agent")
        for account in ["demo-api", "demo-web", "demo-mfa", "example-email", "example-sms"]:
            broker.grant("fixture-agent", account, ["summary"])
        payload = (state / "demo.key").read_bytes() + secrets.token_bytes(32)
        (state / "demo.key").unlink()
        owner_token = base64.urlsafe_b64encode(payload[32:]).decode().rstrip("=")
        client = prefix / "agent-client"
        private_file(client / "token", token.encode())
        private_file(client / "client.json", json.dumps({"token_file": str(client / "token"),
                                                       "socket": api_path}).encode())
        chown_tree(client, roles["agent"])
        chown_tree(state, roles["broker"])
        # From this point, root uses HTTP only; it must not open the worker Store.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as agent_socket, \
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as owner_socket:
            agent_socket.bind(api_path)
            agent_socket.listen(128)
            os.chown(api_path, 0, roles["agent"].pw_gid)
            os.chmod(api_path, 0o660)
            owner_socket.bind(owner_path)
            owner_socket.listen(128)
            os.chmod(owner_path, 0o600)
            reader, writer = os.pipe()
            try:
                arguments = [*dropped(roles["broker"]), "/usr/bin/env",
                    "PLAYWRIGHT_BROWSERS_PATH=" + str(prefix / "browsers"),
                    "SSL_CERT_FILE=" + str(prefix / "fixture-mail-ca.pem"),
                    sys.executable, "-I", "-B", "-m", "account_access.worker_host",
                    "--policy", str(prefix / "policy.json"), "--bootstrap-fd", str(reader),
                    "--agent-fd", str(agent_socket.fileno()), "--owner-fd", str(owner_socket.fileno()),
                    "--controlled-fixture"]
                if sys.platform == "darwin":
                    launcher = {"managed_by": "account-access-mac-worker-v1", "schema": 1,
                        "python": sys.executable, "runtime": sys.prefix, "worker_policy": str(prefix / "policy.json"),
                        "broker_gid": roles["broker"].pw_gid, "broker_home": roles["broker"].pw_dir,
                        "browsers": str(prefix / "browsers"), "fixture": True,
                        "fixture_ca": str(prefix / "fixture-mail-ca.pem")}
                    private_file(prefix / "mac-launcher.json", json.dumps(launcher).encode())
                    (prefix / "mac-launcher.json").chmod(0o644)
                    root_managed_path(prefix / "mac-worker-bootstrap")
                    arguments = ["/bin/launchctl", "asuser", str(roles["broker"].pw_uid),
                        str(prefix / "mac-worker-bootstrap"), "--policy", str(prefix / "mac-launcher.json"),
                        "--bootstrap-fd", str(reader), "--agent-fd", str(agent_socket.fileno()),
                        "--owner-fd", str(owner_socket.fileno())]
                    # A protected top-level directory alone cannot attest code
                    # inside it. An unsafe descendant must stop native launch
                    # before any key handoff; only this disposable CI tree changes.
                    import account_access.worker_host as worker_module
                    unsafe = Path(worker_module.__file__).with_name("qa-writable-descendant.py")
                    assert not unsafe.exists()
                    try:
                        unsafe.write_text("# Inert CI fixture, never imported.\n")
                        unsafe.chmod(0o666)
                        rejected = subprocess.run(arguments, capture_output=True, timeout=30)
                        assert rejected.returncode == 78 and json.loads(rejected.stdout).get("reason") == "worker_runtime_tree_writable"
                    finally:
                        unsafe.unlink(missing_ok=True)
                    outside = prefix / "qa-external-module"
                    alias = unsafe.with_name("qa-external-module-alias")
                    outside.mkdir(mode=0o755)
                    try:
                        (outside / "untrusted.py").write_text("# Inert external-directory fixture.\n")
                        (outside / "untrusted.py").chmod(0o666)
                        alias.symlink_to(outside, target_is_directory=True)
                        rejected = subprocess.run(arguments, capture_output=True, timeout=30)
                        assert rejected.returncode == 78 and json.loads(rejected.stdout).get("reason") == "worker_runtime_tree_writable"
                    finally:
                        alias.unlink(missing_ok=True)
                        shutil.rmtree(outside)
                worker = subprocess.Popen(arguments, pass_fds=(reader, agent_socket.fileno(), owner_socket.fileno()),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
                os.close(reader)
                reader = None
                os.write(writer, payload)
                os.close(writer)
                writer = None
                del payload
                stage("wait_for_worker")
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if worker.poll() is not None:
                        stdout, _ = worker.communicate(timeout=5)
                        try:
                            reason = json.loads(stdout)["reason"]
                        except (ValueError, KeyError, TypeError):
                            reason = "no_worker_startup_report"
                        allowed = {"invalid_worker_bootstrap", "worker_bootstrap_timed_out", "invalid_worker_listener",
                            "untrusted_worker_runtime", "invalid_worker_policy", "invalid_worker_identity",
                            "worker_requires_isolated_python", "unsafe_worker_privileges", "unsafe_worker_state",
                            "invalid_worker_descriptors", "invalid_worker_configuration_mode", "worker_unavailable",
                            "worker_launcher_requires_root", "invalid_worker_launcher_arguments", "invalid_worker_launcher_policy",
                            "unsafe_worker_launcher_runtime", "invalid_worker_launcher_identity", "invalid_worker_launcher_descriptors",
                            "worker_identity_drop_failed", "worker_execution_failed", "worker_runtime_tree_owner_mismatch",
                            "worker_runtime_tree_writable", "worker_runtime_tree_special_object", "worker_runtime_tree_unreadable",
                            "worker_runtime_tree_too_large"}
                        stage(reason if reason in allowed else "no_worker_startup_report")
                        print(json.dumps({"worker_exit_code": worker.returncode}), file=sys.stderr)
                        raise RuntimeError("fixture_worker_exited_before_ready")
                    try:
                        with UnixHTTP(api_path) as channel:
                            channel.request("GET", "/v1/accounts", headers={"Authorization": "Bearer " + token})
                            response = channel.getresponse()
                            result = json.loads(response.read())
                            if response.status == 200 and result["status"] == "OK":
                                break
                    except (OSError, TimeoutError, http.client.HTTPException):
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("fixture_worker_start_timed_out")
                phone.update(owner_request(owner_path, owner_token, "/owner/phone/pair", {"source": "example-sms"}))
                identity = command(["/bin/ps", "-p", str(worker.pid), "-o", "uid=,gid="]).split()
                assert identity == [str(roles["broker"].pw_uid).encode(), str(roles["broker"].pw_gid).encode()]
                assert mailbox.fetches == provider.login_count == 0
                stage("different_user_signins_and_denials")
                checks = probe(prefix, roles, worker, policy, "initial")
                assert provider.login_count == 4 and provider.totp_count == provider.email_count == provider.sms_count == 1
                checks["provider_confirmed_four_passwords_all_factors"] = True
                checks["tls_imap_message_fetched"] = mailbox.fetches == 1
                checks["pinned_https_sms_delivered"] = len(delivered_sms) == 1
                owner_report = None
                if sys.platform == "darwin":
                    owner_report = root_owner_gateway(prefix, roles, policy, owner_token, worker)
                    owner_report["checks"].update(probe(prefix, roles, worker, policy, "after-owner-stop"))
                    key_report = root_key_custody(prefix, roles)
                    policy_report = root_owner_policy(prefix, roles)
                else:
                    owner_request(owner_path, owner_token, "/owner/revoke", {"account": "demo-api"})
                stage("revoked_read")
                checks.update(probe(prefix, roles, worker, policy, "revoked"))
                if owner_report is not None:
                    owner_report["checks"]["revocation_confirmed_by_agent"] = checks["revoked_operation_denied"]
                    assert provider.login_count == 4
                checks["worker_still_alive_after_denied_attacks"] = worker.poll() is None
                worker.send_signal(signal.SIGTERM)
                stage("graceful_exit")
                stdout, stderr = worker.communicate(timeout=15)
                checks["graceful_worker_exit"] = worker.returncode == 0
                checks["worker_output_has_no_credentials"] = not stdout and not stderr
                if sys.platform == "darwin":
                    checks["native_broker_identity_drop_verified"] = True
                    checks["native_runtime_writable_descendant_rejected"] = True
                assert all(checks.values()), "fixture_worker_final_checks_failed"
                if owner_report is not None:
                    assert all(item is True for item in owner_report["checks"].values())
                    evidence = Path("/tmp/account-access-mac-root-owner.json")
                    private_file(evidence, (json.dumps(owner_report, indent=2) + "\n").encode())
                    evidence.chmod(0o644)  # Fixed non-secret metadata for the unprivileged CI validator.
                    custody_evidence = Path("/tmp/account-access-mac-key-custody.json")
                    private_file(custody_evidence, (json.dumps(key_report, indent=2) + "\n").encode())
                    custody_evidence.chmod(0o644)
                    policy_evidence = Path("/tmp/account-access-mac-owner-policy.json")
                    private_file(policy_evidence, (json.dumps(policy_report, indent=2) + "\n").encode())
                    policy_evidence.chmod(0o644)
                return {"status": "PASSED", "environment": "controlled-demo", "production_ready": False,
                        "private_signins": 0, "platform": "macos" if sys.platform == "darwin" else "linux", "real_distinct_uids": True,
                        "checks": checks,
                        "remaining": ["trusted production supervisor and lifecycle", "trusted owner enrollment gateway",
                                      "consumer installer integration", "private-account and physical-phone acceptance"]}
            finally:
                for fd in [reader, writer]:
                    if fd is not None:
                        os.close(fd)
                if worker is not None and worker.poll() is None:
                    # Only the session created for this synthetic worker.
                    os.killpg(worker.pid, signal.SIGTERM)
                    try:
                        worker.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(worker.pid, signal.SIGKILL)
                        worker.communicate(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    args = parser.parse_args()
    prefix = args.prefix.resolve(strict=True)
    expected_parent = Path("/Library/PrivilegedHelperTools") if sys.platform == "darwin" else Path("/var/lib")
    if (sys.platform not in {"linux", "darwin"} or os.getuid() != 0 or prefix.parent != expected_parent
            or not prefix.name.startswith("account-access-worker-qa-") or not sys.flags.isolated):
        parser.error("Requires a disposable root-owned CI runtime in the platform's protected prefix")
    os.umask(0o077)
    try:
        stage("validate_immutable_runtime")
        for label, path in [("prefix", prefix), ("environment", sys.prefix), ("interpreter", sys.executable),
                            ("harness", __file__), ("probe", prefix / "probe.py")]:
            stage("validate_" + label)
            root_managed_path(path)
        os.chdir(prefix)
        with identities(prefix) as roles:
            report = exercise(prefix, roles)
    except Exception as exc:
        # Fixed metadata only, never provider payloads, token or key material.
        print(json.dumps({"status": "FAILED", "reason": "worker_boundary_acceptance_failed",
                          "exception_type": type(exc).__name__, "production_ready": False}))
        return 1
    print(json.dumps(report, indent=2))
    # No long-lived users or fictional vault state are left after this check.
    for path in [prefix / "state", prefix / "control", prefix / "public", prefix / "agent-client"]:
        shutil.rmtree(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
