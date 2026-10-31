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
import runpy
import selectors
import secrets
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import traceback
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


def wait_for_launch_job_absence(target, *, timeout=10, run=subprocess.run,
                               pause=time.sleep, clock=time.monotonic):
    """Boundedly wait for launchd's job registry to reflect a completed bootout."""
    deadline = clock() + timeout
    while clock() < deadline:
        result = run(["/bin/launchctl", "print", target], capture_output=True)
        if result.returncode != 0:
            return True
        pause(min(0.1, deadline - clock()))
    return False


def fixture_listener_prefix(agent_socket, owner_socket, agent_path, owner_path):
    """Describe the disposable CI parent's real direct-bind descriptors.

    mac-worker-bootstrap independently validates this public prefix, canonical
    nodes and root ownership before dropping identity and consuming any keys.
    Linux retains its existing64-byte handoff.
    """
    prefix = bytearray(struct.pack(">8sHBBI", b"AALSN002", 2, 2, 0, 280))
    for role, listener, path in [(1, agent_socket, agent_path), (2, owner_socket, owner_path)]:
        descriptor, node = os.fstat(listener.fileno()), os.lstat(path)
        if (listener.family != socket.AF_UNIX or not stat.S_ISSOCK(descriptor.st_mode)
                or not stat.S_ISSOCK(node.st_mode) or listener.getsockname() != path
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM):
            raise RuntimeError("fixture_listener_binding_invalid")
        path_digest = hashlib.sha256(path.encode("utf-8")).digest()
        prefix.extend(struct.pack(">BBHqQqQ32s32s", role, 0, 0,
            descriptor.st_dev, descriptor.st_ino, node.st_dev, node.st_ino, path_digest, path_digest))
    return bytes(prefix)


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


def probe(prefix, roles, worker, policy, phase, *, client_config=None):
    module = __import__("account_access.worker_host", fromlist=["__file__"]).__file__
    arguments = [*dropped(roles["agent"]), sys.executable, "-I", "-B", str(prefix / "probe.py"),
        "--phase", phase, "--config", str(client_config or prefix / "agent-client/client.json"),
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
                             "demo-api", "demo-web", "demo-mfa", "example-email", "example-sms", "native-sms",
                             "native-sms-recover", "native-sms-retry-check", "native-sms-task-submit", "native-sms-task-wait"}
        safe_reasons = {"browser_guard_unavailable", "internal_error", "service_unavailable", "worker_unavailable",
                       "login_failed", "verification_code_unavailable", "invalid_credentials", "request_failed",
                       "browser_execution_failed", "login_code_not_received", "verification_code_rejected",
                       "verification_source_not_connected", "browser_state_unrecognized", "login_retry_cooldown",
                       "mac_messages_reader_unavailable", "mac_messages_permission_required"}
        # Closed fixture labels only. Never copy raw CLI/provider output.
        if result.get("stage") in diagnostic_stages:
            stage("probe_" + result["stage"])
        if result.get("operation_status") in {"COMPLETED", "DENIED", "NEEDS_USER", "RETRYABLE", "OK", "QUEUED", "RUNNING", "FAILED"}:
            stage("operation_" + result["operation_status"])
        if result.get("operation_reason") in safe_reasons:
            stage(result["operation_reason"])
        if result.get("wait_timed_out") is True:
            stage("task_wait_timed_out")
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


def system_broker_waiting(prefix, roles):
    """Use the shipping entrypoint with its gated CI policy, real XPC and no key."""
    if sys.platform != "darwin" or os.getuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("system_broker_requires_disposable_mac_ci")
    binary, client = prefix / "system-broker", prefix / "root-owner-client"
    for path in [binary, client]:
        root_managed_path(path)
    def signature(path):
        result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, timeout=10)
        hashes = re.findall(rb"^CDHash=([a-f0-9]{40})$", result.stderr, re.MULTILINE)
        assert result.returncode == 0 and len(hashes) == 1
        return hashes[0].decode()
    enrollment = json.loads((prefix / "entry-enrollment-launch.json").read_bytes())
    worker_path = prefix / "entry-enrollment-base-launcher.json"
    plan = json.loads((prefix / "entry-enrollment-base.json").read_bytes())
    settings = prefix / "system-broker.json"
    private_file(settings, json.dumps({"managed_by": "account-access-system-host-v1", "schema": 1,
        "worker_launcher": str(worker_path), "enrollment_policy": str(prefix / "entry-enrollment-launch.json"),
        "bootstrap": str(prefix / "mac-worker-bootstrap"), "vault_id": enrollment["vault_id"],
        "owner_uid": roles["agent"].pw_uid, "publisher_team": "fixture",
        "owner_identifier": "fixture.owner", "owner_hashes": [signature(client)],
        "bootstrap_identifier": "fixture.bootstrap", "bootstrap_hashes": [signature(prefix / "mac-worker-bootstrap")]}).encode())
    public = prefix / "system-broker-client.json"
    private_file(public, json.dumps({"fixture": "account-access-root-owner-ci-v1", "owner_uid": roles["agent"].pw_uid,
        "owner_hash": signature(client), "server_hash": signature(binary), "owner_socket": plan["owner_socket"],
        "owner_port": plan["owner_port"], "bootstrap_socket": str(prefix / "control/entry-unused.sock")}).encode())
    public.chmod(0o644)
    desktop = prefix / "desktop-owner.json"
    private_file(desktop, json.dumps({"managed_by": "account-access-desktop-owner-v1", "schema": 1,
        "owner_uid": roles["agent"].pw_uid, "publisher_team": "fixture",
        "server_identifier": "com.fainir.accountaccess.broker", "server_hashes": [signature(binary)]}).encode())
    desktop.chmod(0o644)
    label = "com.fainir.accountaccess.qa.system-broker"
    target = "system/" + label
    assert subprocess.run(["/bin/launchctl", "print", target], capture_output=True).returncode != 0
    ready = prefix / "system-broker-ready.json"
    cleanup_output = prefix / "system-broker-cleanup.json"
    assert not ready.exists() and not cleanup_output.exists()
    launch = prefix / (label + ".plist")
    launch.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": [str(binary), "--fixture-policy", str(settings)],
        "UserName": "root", "GroupName": "wheel", "RunAtLoad": True, "KeepAlive": False,
        "AbandonProcessGroup": False, "ExitTimeOut": 20, "Umask": 0o077, "ProcessType": "Background",
        "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
        "MachServices": {"com.fainir.accountaccess.broker.owner": True},
        "Sockets": {"AccountAccessAgent": {"SockPathName": plan["agent_socket"], "SockPathOwner": 0,
            "SockPathGroup": roles["agent"].pw_gid, "SockPathMode": 0o660},
            "AccountAccessOwner": {"SockPathName": plan["owner_socket"], "SockPathOwner": 0,
                "SockPathGroup": 0, "SockPathMode": 0o600}}}))
    launch.chmod(0o644)
    checks, booted = {}, False
    def snapshot():
        deadline = time.monotonic() + 55
        while time.monotonic() < deadline:
            try:
                value = json.loads(ready.read_bytes())
            except (OSError, ValueError):
                value = {}
            if value.get("status") == "READY":
                assert set(value) == {"status", "pid", "uid", "group", "worker_pid", "worker_state", "enrollment_state", "setup_policy_registered", "fixture_key_absent"}
                assert value["uid"] == 0 and value["group"] == value["pid"]
                assert value["worker_pid"] == 0 and value["worker_state"] == "idle"
                assert value["enrollment_state"] == "needs_owner" and value["fixture_key_absent"] is True
                assert value["setup_policy_registered"] is True
                return value
            time.sleep(0.1)
        raise RuntimeError("system_broker_ready_timed_out")
    def run_client(role, executable, mode, policy=public):
        result = subprocess.run([*dropped(role), str(executable), "--policy", str(policy), mode],
            capture_output=True, timeout=50, env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
        value = json.loads(result.stdout)
        if value.get("status") != "PASSED":
            failures = value.get("failed_checks")
            if (isinstance(failures, list) and len(failures) <= 100
                    and all(isinstance(name, str) and re.fullmatch(r"[a-z_]{1,100}", name) for name in failures)):
                print(json.dumps({"failed_initial_gateway_checks": failures}), file=sys.stderr, flush=True)
        assert result.returncode == 0 and value.get("status") == "PASSED" and value.get("checks")
        assert all(item is True for item in value["checks"].values())
        return value["checks"]
    def denied(role, executable, policy=public):
        return run_client(role, executable, "denied", policy) == {
            "prepare_refused": True, "failed_prepare_refuses_setup": True, "failed_prepare_refuses_credential_input": True}
    try:
        stage("system_broker_waiting_bootstrap")
        command(["/bin/launchctl", "bootstrap", "system", str(launch)])
        booted = True
        snapshot()
        checks["system_entrypoint_hosts_initial_owner_gateway"] = True
        checks["no_initial_worker_or_key_created"] = True
        checks.update(run_client(roles["agent"], client, "first-enrollment"))
        checks["unapproved_initial_owner_code_refused"] = denied(roles["agent"], prefix / "root-owner-client-denied")
        checks["wrong_initial_owner_uid_refused"] = denied(roles["broker"], client)
        wrong = prefix / "system-broker-wrong-server.json"
        wrong_value = json.loads(public.read_bytes())
        wrong_value["server_hash"] = "0" * 40
        private_file(wrong, json.dumps(wrong_value).encode())
        wrong.chmod(0o644)
        checks["wrong_initial_server_code_refused"] = denied(roles["agent"], client, wrong)
    finally:
        if booted:
            command(["/bin/launchctl", "bootout", target])
        cleanup_label = label + ".cleanup"
        cleanup_target = "system/" + cleanup_label
        cleanup = prefix / (cleanup_label + ".plist")
        cleanup.write_bytes(plistlib.dumps({"Label": cleanup_label, "ProgramArguments": [str(binary), "--fixture-policy", str(settings), "--cleanup-fixture-policy"],
            "UserName": "root", "GroupName": "wheel", "RunAtLoad": True, "KeepAlive": False,
            "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}))
        cleanup.chmod(0o644)
        command(["/bin/launchctl", "bootstrap", "system", str(cleanup)])
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                state = command(["/bin/launchctl", "print", cleanup_target])
                exited = re.findall(rb"last exit code = ([0-9]+)", state)
                if cleanup_output.exists() and exited:
                    assert exited == [b"0"] and json.loads(cleanup_output.read_bytes()) == {"status": "PASSED", "fixture_right_removed": True, "fixture_key_absent": True}
                    checks["entrypoint_fixture_setup_policy_removed"] = True
                    checks["rejected_setup_never_creates_a_key"] = True
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("system_broker_cleanup_timed_out")
        finally:
            command(["/bin/launchctl", "bootout", cleanup_target])
    checks["entrypoint_system_jobs_removed"] = subprocess.run(["/bin/launchctl", "print", target], capture_output=True).returncode != 0
    assert checks and all(item is True for item in checks.values())
    return checks


def provisioned_system_broker(prefix, roles):
    """Prepare fresh policies/identity with the consumer publisher, then real XPC."""
    from account_access.system_provision import Layout, activate, prepare, remove_ci_identity, root_json

    layout = Layout.ci_fixture(prefix, name="_aaq" + secrets.token_hex(6))
    checks, installed, booted = {}, False, False
    target = "system/" + layout.label
    try:
        stage("provision_fresh_system_installation")
        first = prepare(layout, roles["agent"].pw_uid)
        installed = True
        stage("provision_repeat_system_installation")
        before = (layout.base / "broker/install.json").read_bytes()
        repeated = prepare(layout, roles["agent"].pw_uid)
        checks["prepared_installation_is_idempotent"] = (
            first == repeated and before == (layout.base / "broker/install.json").read_bytes()
        )
        broker = pwd.getpwnam(layout.broker_name)
        checks["dedicated_nonlogin_identity_created"] = (
            broker.pw_uid == first["broker_uid"] and broker.pw_shell == "/usr/bin/false"
        )
        checks["broker_and_owner_identities_differ"] = (
            broker.pw_uid != roles["agent"].pw_uid and broker.pw_gid != roles["agent"].pw_gid
        )
        checks["broker_home_is_private"] = (
            layout.base / "home"
        ).stat().st_uid == broker.pw_uid and (layout.base / "home").stat().st_mode & 0o777 == 0o700
        stage("provision_private_directory_crash_recovery")
        private_probe = runpy.run_path(str(prefix / "private-directory-probe.py"))
        checks.update(private_probe["check_recovery"](prefix, broker.pw_uid))
        checks["new_store_and_stage_are_empty"] = not any((layout.base / "vault/data").iterdir())
        transaction = root_json(layout.base / "broker/install.json")
        staged = layout.base / "vault" / (".enrollment-" + transaction["enrollment_id"])
        checks["new_store_and_stage_are_empty"] &= not any(staged.iterdir())
        command(["/bin/launchctl", "print", "user/" + str(broker.pw_uid)])
        checks["nonlogin_user_bootstrap_domain_ready"] = True
        profile = json.loads((layout.base / "owner.json").read_bytes())
        host = json.loads((layout.base / "broker/host.json").read_bytes())
        worker = json.loads((layout.base / "broker/worker.json").read_bytes())
        checks["public_profile_binds_owner_and_server"] = (
            profile["owner_uid"] == roles["agent"].pw_uid and bool(profile["server_hashes"])
        )
        checks["published_policies_preserve_empty_fixed_enrollment"] = (
            host["vault_id"] == first["vault_id"] and worker["broker_uid"] == broker.pw_uid
        )
        client_policy = layout.base / "client-probe.json"
        private_file(
            client_policy,
            json.dumps(
                {
                    "fixture": "account-access-root-owner-ci-v1",
                    "owner_uid": roles["agent"].pw_uid,
                    "owner_hash": host["owner_hashes"][0],
                    "server_hash": profile["server_hashes"][0],
                    "owner_socket": worker["owner_socket"],
                    "owner_port": worker["owner_port"],
                    "bootstrap_socket": str(layout.base / "control/unused.sock"),
                }
            ).encode(),
        )
        client_policy.chmod(0o644)
        registered = activate(layout, roles["agent"].pw_uid)
        booted = True
        persisted = layout.base / "launchdaemons" / (layout.label + ".plist")
        checks["exact_prepared_job_is_persisted_and_registered"] = (
            registered["status"] == "REGISTERED"
            and persisted.read_bytes() == (layout.base / "broker/service.plist").read_bytes()
        )
        ready = layout.base / "broker/system-broker-ready.json"
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not ready.exists():
            time.sleep(0.1)
        snapshot = json.loads(ready.read_bytes())
        # Exercise the provisioner's real launchd repair path with this same
        # prepared fixture. The fixed consumer coordinator calls this path on
        # completed-image retries; its dispatch is tested separately. This is
        # not a downloaded consumer-package or genuine owner-enrollment test.
        stage("provision_restore_removed_registration")
        policy_paths = [
            layout.base / "broker" / name
            for name in [
                "install.json", "worker.json", "stage.json", "worker-launch.json",
                "stage-launch.json", "enrollment.json", "host.json", "service.plist",
            ]
        ] + [layout.base / "owner.json", persisted]

        def public_identity(path):
            info = path.stat()
            return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode

        policy_snapshot = {
            path: (public_identity(path), path.read_bytes()) for path in policy_paths
        }
        private_paths = [layout.base / "home", layout.base / "vault/data", staged]
        private_snapshot = {path: public_identity(path) for path in private_paths}
        command(["/bin/launchctl", "bootout", target])
        booted = False
        if not wait_for_launch_job_absence(target):
            raise RuntimeError("system_broker_bootout_not_observed")
        ready.unlink()
        repaired = activate(layout, roles["agent"].pw_uid)
        booted = True
        command(["/bin/launchctl", "print", target])
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not ready.exists():
            time.sleep(0.1)
        restored = json.loads(ready.read_bytes())
        checks["same_prepared_installation_restores_removed_service_registration"] = (
            repaired == registered and restored["status"] == "READY"
            and restored["uid"] == 0 and restored["pid"] != snapshot["pid"]
            and restored["enrollment_state"] == "needs_owner"
            and restored["fixture_key_absent"] is True and restored["worker_pid"] == 0
        )
        checks["registration_repair_preserves_policies_identity_and_empty_vault"] = (
            pwd.getpwnam(layout.broker_name) == broker
            and all((public_identity(path), path.read_bytes()) == value
                    for path, value in policy_snapshot.items())
            and all(public_identity(path) == value for path, value in private_snapshot.items())
            and not any((layout.base / "vault/data").iterdir()) and not any(staged.iterdir())
        )
        # Test the actual daemon's cold-domain repair, without re-running the
        # provisioner (which also prepares that domain). No vault exists yet.
        stage("provision_cold_service_restart")
        command(["/bin/launchctl", "bootout", target])
        booted = False
        command(["/bin/launchctl", "bootout", "user/" + str(broker.pw_uid)])
        ready.unlink()
        command(["/bin/launchctl", "bootstrap", "system", str(persisted)])
        booted = True
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not ready.exists():
            time.sleep(0.1)
        cold = json.loads(ready.read_bytes())
        checks["generated_installation_starts_actual_system_entrypoint"] = (
            snapshot["status"] == "READY" and snapshot["uid"] == 0
        )
        checks["fresh_install_waits_without_key_or_worker"] = (
            snapshot["enrollment_state"] == "needs_owner"
            and snapshot["fixture_key_absent"] is True
            and snapshot["worker_pid"] == 0
        )
        command(["/bin/launchctl", "print", "user/" + str(broker.pw_uid)])
        checks["system_entrypoint_recreates_nonlogin_user_domain"] = (
            cold["status"] == "READY" and cold["enrollment_state"] == "needs_owner"
            and cold["fixture_key_absent"] is True and cold["worker_pid"] == 0
        )
        result = subprocess.run(
            [
                *dropped(roles["agent"]),
                str(prefix / "root-owner-client"),
                "--policy",
                str(client_policy),
                "provisioned-install",
            ],
            capture_output=True,
            timeout=50,
            env={"PATH": "/usr/bin:/bin"},
        )
        value = json.loads(result.stdout)
        assert (
            result.returncode == 0
            and value["status"] == "PASSED"
            and all(item is True for item in value["checks"].values())
        )
        checks.update(value["checks"])
    finally:
        if booted:
            command(["/bin/launchctl", "bootout", target])
            booted = False
            cleanup_target = target + ".cleanup"
            cleanup_file = layout.base / "broker/cleanup.plist"
            cleanup_file.write_bytes(
                plistlib.dumps(
                    {
                        "Label": layout.label + ".cleanup",
                        "ProgramArguments": [
                            str(layout.broker),
                            "--fixture-policy",
                            str(layout.base / "broker/host.json"),
                            "--cleanup-fixture-policy",
                        ],
                        "UserName": "root",
                        "GroupName": "wheel",
                        "RunAtLoad": True,
                        "KeepAlive": False,
                        "StandardOutPath": "/dev/null",
                        "StandardErrorPath": "/dev/null",
                    }
                )
            )
            cleanup_file.chmod(0o644)
            command(["/bin/launchctl", "bootstrap", "system", str(cleanup_file)])
            try:
                cleanup = layout.base / "broker/system-broker-cleanup.json"
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline and not cleanup.exists():
                    time.sleep(0.1)
                value = json.loads(cleanup.read_bytes())
                checks["rejected_setup_keeps_new_key_absent"] = value["fixture_key_absent"] is True
                checks["fixture_setup_policy_removed"] = value["fixture_right_removed"] is True
            finally:
                command(["/bin/launchctl", "bootout", cleanup_target])
        if installed:
            remove_ci_identity(layout)
            checks["created_service_identity_and_domain_removed"] = True
    checks["temporary_system_jobs_removed"] = (
        subprocess.run(["/bin/launchctl", "print", target], capture_output=True).returncode != 0
    )
    assert checks and all(value is True for value in checks.values())
    report = {
        "status": "PASSED",
        "platform": "macos",
        "environment": "controlled-demo",
        "production_ready": False,
        "private_signins": 0,
        "actual_provisioner_used": True,
        "actual_system_entrypoint_used": True,
        "actual_native_xpc_used": True,
        "consumer_package_verified": False,
        "genuine_owner_approval_verified": False,
        "publisher_signed_peers": False,
        "fixture_identity_removed": True,
        "checks": checks,
    }
    evidence = Path("/tmp/account-access-mac-provisioning.json")
    private_file(
        evidence,
        (json.dumps(report, indent=2) + "\n").encode(),
    )
    evidence.chmod(0o644)  # Fixed non-secret booleans for the ordinary CI validator/uploader.
    return checks


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


def root_key_custody(prefix, roles, client_token):
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
    native_system_report = None
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
    def prepare_enrollment(tag, vault):
        enrollment_id = str(uuid.uuid4())
        destination = prefix / (tag + "-destination")
        stage_root = prefix / (".enrollment-" + enrollment_id)
        for directory in [destination, stage_root]:
            directory.mkdir(mode=0o700)
            os.chown(directory, roles["broker"].pw_uid, roles["broker"].pw_gid)
        base = dict(worker_policy, root=str(destination), agent_socket=str(prefix / ("public/" + tag + "-agent.sock")),
                    owner_socket=str(prefix / ("control/" + tag + "-owner.sock")))
        staged = dict(base, root=str(stage_root))
        base_path, staged_path = prefix / (tag + "-base.json"), prefix / (tag + "-stage.json")
        base_launcher = prefix / (tag + "-base-launcher.json")
        for path, contents in [(base_path, base), (staged_path, staged),
                (base_launcher, dict(launcher, worker_policy=str(base_path))),
                (prefix / (tag + "-stage-launcher.json"), dict(launcher, worker_policy=str(staged_path))),
                (prefix / (tag + "-launch.json"), {"managed_by": "account-access-worker-enrollment-v1", "schema": 1,
                    "worker_launcher": str(base_launcher), "stage_policy": str(staged_path),
                    "vault_id": vault, "enrollment_id": enrollment_id})]:
            private_file(path, json.dumps(contents).encode())
            path.chmod(0o644)
    prepare_enrollment("enrollment", identity)
    prepare_enrollment("first-enrollment", str(uuid.uuid4()))
    prepare_enrollment("entry-enrollment", str(uuid.uuid4()))
    native_settings = {"owner_uid": roles["agent"].pw_uid}
    for name, path in [("helper_hash", prefix / "native-messages-helper"), ("parent_hash", binary)]:
        signed = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, timeout=10)
        found = re.findall(rb"^CDHash=([a-f0-9]{40})$", signed.stderr, re.MULTILINE)
        assert signed.returncode == 0 and len(found) == 1
        native_settings[name] = found[0].decode()
    private_file(prefix / "native-messages-fixture.json", json.dumps(native_settings).encode())
    (prefix / "native-messages-fixture.json").chmod(0o644)
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
            deadline = time.monotonic() + {"handoff": 240, "supervisor": 420, "initializer": 180, "initial-setup": 240, "native-messages": 90}.get(mode, 45)
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
                            "worker_store_paused", "vault_publication_busy", "vault_publication_unsafe_state",
                            "vault_publication_requires_verified_stage", "vault_publication_unavailable",
                            "client_prepare_process_failed", "client_install_process_failed",
                            "client_probe_response_invalid", "client_enrollment_response_invalid"}:
                            stage(reason)
                        if reason in {"native_messages_reader_unavailable", "native_messages_reader_rejected",
                            "native_messages_reader_code_rejected", "native_messages_reader_identity_rejected",
                            "native_messages_reader_ancestry_rejected", "native_messages_reader_handshake_rejected"}:
                            stage(reason)
                        if result.get("checkpoint") in {"policy", "context", "invalid_identity", "initial_missing", "enrollment",
                            "encryption", "duplicate_enrollment", "other_vault", "restart_recovery", "fixture_removal", "system_location",
                            "native_handoff", "native_worker_service", "native_worker_supervisor", "native_staged_initializer", "native_initial_enrollment", "native_messages", "native_host_initialization", "native_system_browser"}:
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
        native_checks = phase("native-messages", collect=False)
        unprivileged_reader = subprocess.run(
            [*dropped(roles["agent"]), str(prefix / "native-messages-helper"),
             str(prefix / "native-messages-profile.json"), str(prefix / "native-messages-owner/messages.sqlite")],
            input=json.dumps({"action": "begin", "source": "fixture-sms", "sender": "Example",
                              "template": "Example login: {code}", "started": time.time()}).encode(),
            capture_output=True, timeout=10, env={"PATH": "/usr/bin:/bin"})
        native_checks["untrusted_invoker_cannot_read_codes"] = (
            unprivileged_reader.returncode == 0
            and json.loads(unprivileged_reader.stdout) == {"status": "NEEDS_USER", "reason": "owner_authorization_required"})
        assert all(value is True for value in native_checks.values())
        native_evidence = Path("/tmp/account-access-mac-native-messages.json")
        private_file(native_evidence, json.dumps({"status": "PASSED", "environment": "controlled-demo",
            "production_ready": False, "private_signins": 0, "actual_separate_owner_uid_reader": True,
            "real_messages_database_used": False, "physical_sms_delivery_verified": False,
            "full_worker_browser_sms_journey_verified": False, "genuine_full_disk_access_verified": False,
            "checks": native_checks}, indent=2).encode())
        native_evidence.chmod(0o644)
        stage("native_system_host_browser_journey")
        controller = prefix / "native-system-fixture.py"
        native_fixture = prefix / "native-sms-fixture.py"
        root_managed_path(controller)
        root_managed_path(native_fixture)
        native_system_report = runpy.run_path(str(controller))["exercise_native_system"](
            prefix, roles, policy, phase, client_token, probe, command,
            runpy.run_path(str(native_fixture))["NativeSMSFixture"])
        handoff = phase("handoff", collect=False)
        supervisor = phase("supervisor", collect=False)
        initializer = phase("initializer", collect=False)
        initial_setup = phase("initial-setup", collect=False)
        initial_gateway = system_broker_waiting(prefix, roles)
        provisioned_system_broker(prefix, roles)
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
        try:
            phase("initial-setup-cleanup", collect=False)
        finally:
            phase("remove")
    if native_system_report is not None:
        native_system_report["checks"]["fixture_system_key_removed"] = checks["remove_fixture_key_removed_and_not_recreated"]
        browser_report = native_system_report["protected_browser"]
        browser_report["checks"]["fixture_system_key_removed"] = checks["remove_fixture_key_removed_and_not_recreated"]
        browser_report["checks"]["fixture_setup_policy_removed"] = native_system_report["checks"]["fixture_setup_policy_removed"]
        browser_report["checks"]["temporary_jobs_removed"] = native_system_report["checks"]["temporary_jobs_removed"]
        evidence = Path("/tmp/account-access-mac-native-system-browser.json")
        private_file(evidence, json.dumps(native_system_report, indent=2).encode())
        evidence.chmod(0o644)
        evidence = Path("/tmp/account-access-mac-protected-browser.json")
        private_file(evidence, json.dumps(browser_report, indent=2).encode())
        evidence.chmod(0o644)
        chrome_report = native_system_report["signed_chrome"]
        chrome_report["checks"]["fixture_system_key_removed"] = checks["remove_fixture_key_removed_and_not_recreated"]
        chrome_report["checks"]["fixture_setup_policy_removed"] = native_system_report["checks"]["fixture_setup_policy_removed"]
        chrome_report["checks"]["temporary_jobs_removed"] = native_system_report["checks"]["temporary_jobs_removed"]
        evidence = Path("/tmp/account-access-mac-signed-chrome.json")
        private_file(evidence, json.dumps(chrome_report, indent=2).encode())
        evidence.chmod(0o644)
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
    initial_gateway_report = {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
        "private_signins": 0, "actual_system_entrypoint_used": True, "actual_native_xpc_used": True,
        "consumer_deployment_verified": False, "genuine_owner_approval_verified": False,
        "positive_enrollment_verified": False, "authorization_database_changed": True,
        "fixture_policy_removed": True, "publisher_signed_peers": False, "checks": initial_gateway}
    evidence = Path("/tmp/account-access-mac-initial-gateway.json")
    private_file(evidence, (json.dumps(initial_gateway_report, indent=2) + "\n").encode())
    evidence.chmod(0o644)
    initial_setup_report = {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
        "private_signins": 0, "system_key_used": True, "actual_initial_setup_used": True,
        "consumer_deployment_verified": False, "genuine_owner_approval_verified": False,
        "synthetic_setup_approval_used": True, "authorization_database_changed": False, "fixture_key_removed": True,
        "controlled_initializer_gate": True, "publisher_signed_peers": False, "checks": initial_setup}
    evidence = Path("/tmp/account-access-mac-initial-setup.json")
    private_file(evidence, (json.dumps(initial_setup_report, indent=2) + "\n").encode())
    evidence.chmod(0o644)
    initialization_report = {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
        "private_signins": 0, "system_key_used": True, "actual_initializer_used": True,
        "consumer_deployment_verified": False, "genuine_owner_approval_verified": False, "stage_published": True,
        "key_enrollment_authorization_verified": False, "fixture_key_removed": True, "publisher_signed_peers": False,
        "checks": initializer}
    evidence = Path("/tmp/account-access-mac-staged-enrollment.json")
    private_file(evidence, (json.dumps(initialization_report, indent=2) + "\n").encode())
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


@contextmanager
def composed_native_sms(prefix, roles, broker):
    if sys.platform != "darwin":
        yield None
        return
    # Isolated Python has no sibling search path. Load only this explicitly
    # Root-validated CI file under the already protected runtime prefix.
    path = prefix / "native-sms-fixture.py"
    root_managed_path(path)
    with runpy.run_path(str(path))["native_sms_fixture"](prefix, roles, broker) as fixture:
        yield fixture


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
    with environment(state) as (provider, broker, _), fixture_mailbox(prefix) as mailbox, \
            composed_native_sms(prefix, roles, broker) as native_sms:
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
        for account in ["demo-api", "demo-web", "demo-mfa", "example-email", "example-sms"] + (["native-sms"] if native_sms else []):
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
                    payload = fixture_listener_prefix(agent_socket, owner_socket, api_path, owner_path) + payload
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
                if native_sms is not None:
                    stage("composed_native_sms_browser_login")
                    with native_sms.collector(owner_token, policy):
                        native_checks = probe(prefix, roles, worker, policy, "native-sms")
                        assert native_sms.provider.login_count == native_sms.provider.sms_count == native_sms.delivered == 1
                        native_checks["provider_verified_password_and_fresh_sms"] = True
                        native_checks["session_reuse_avoids_second_password_and_sms"] = True
                        native_checks["real_distinct_reader_and_worker_uids"] = roles["agent"].pw_uid != roles["broker"].pw_uid
                    native_checks["root_collector_stops_cleanly"] = True
                    native_checks["temporary_collector_job_removed"] = subprocess.run(
                        ["/bin/launchctl", "print", "system/" + native_sms.label], capture_output=True).returncode != 0
                    assert all(item is True for item in native_checks.values())
                    private_file(Path("/tmp/account-access-mac-native-browser.json"), json.dumps({
                        "status": "PASSED", "environment": "controlled-demo", "production_ready": False,
                        "private_signins": 0, "platform": "macos", "full_worker_browser_sms_journey_verified": True,
                        "actual_native_collector_used": True, "actual_distinct_uids": True,
                        "real_messages_database_used": False, "physical_sms_delivery_verified": False,
                        "genuine_full_disk_access_verified": False, "system_key_used": False,
                        "checks": native_checks}, indent=2).encode())
                    Path("/tmp/account-access-mac-native-browser.json").chmod(0o644)
                if sys.platform == "darwin":
                    owner_report = root_owner_gateway(prefix, roles, policy, owner_token, worker)
                    owner_report["checks"].update(probe(prefix, roles, worker, policy, "after-owner-stop"))
                    key_report = root_key_custody(prefix, roles, token)
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
        diagnostic = {"status": "FAILED", "reason": "worker_boundary_acceptance_failed",
                      "exception_type": type(exc).__name__, "production_ready": False}
        # Source locations contain no exception message, locals or provider data.
        frames = traceback.extract_tb(exc.__traceback__)
        if frames:
            diagnostic["source"] = {"file": Path(frames[-1].filename).name,
                                    "line": frames[-1].lineno, "function": frames[-1].name}
        if len(frames) > 1:
            diagnostic["caller"] = {"file": Path(frames[-2].filename).name,
                                    "line": frames[-2].lineno, "function": frames[-2].name}
        from account_access.system_provision import ProvisionError
        if isinstance(exc, ProvisionError) and str(exc) in {
            "provisioning_command_failed", "service_identity_conflict",
            "directory_services_unavailable", "unsafe_install_directory",
            "unsafe_private_directory", "unsafe_install_record",
            "existing_installation_requires_repair", "invalid_payload_signature",
            "invalid_fixture_signature", "payload_publishers_disagree",
            "service_identity_unavailable", "disposable_provisioning_required",
        }:
            diagnostic["provisioning_reason"] = str(exc)
        print(json.dumps(diagnostic))
        return 1
    print(json.dumps(report, indent=2))
    # No long-lived users or fictional vault state are left after this check.
    for path in [prefix / "state", prefix / "control", prefix / "public", prefix / "agent-client"]:
        shutil.rmtree(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
