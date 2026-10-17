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
import pwd
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
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
                owner_request(owner_path, owner_token, "/owner/revoke", {"account": "demo-api"})
                stage("revoked_read")
                checks.update(probe(prefix, roles, worker, policy, "revoked"))
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
