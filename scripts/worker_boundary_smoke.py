"""Root-only CI harness for a real cross-UID broker boundary, using fake accounts.

Run only in a disposable Linux CI VM. The runtime must already be installed in
a root-owned /var/lib/account-access-worker-qa-* directory. Two new, non-sudo system
identities are created and removed; no existing user or account is enrolled.
This is not a production supervisor, installer or owner enrollment gateway.
"""

import argparse
import base64
from contextlib import contextmanager
import grp
import http.client
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time

from account_access.demo import environment
from account_access.storage import private_file
from account_access.worker_bootstrap import root_managed_path


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("127.0.0.1", 8765, timeout=10)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def command(arguments, *, timeout=30):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    if result.returncode:
        raise RuntimeError("fixture_setup_command_failed")
    return result.stdout


def stage(name):
    print(json.dumps({"stage": name}), file=sys.stderr, flush=True)


@contextmanager
def identities(prefix):
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


def dropped(user):
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
    result = json.loads(command(arguments, timeout=240))
    assert result["status"] == "PASSED", "fixture_boundary_probe_failed"
    return result["checks"]


def exercise(prefix, roles):
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
    with environment(state) as (provider, broker, _):
        token = broker.store.new_client("fixture-agent")
        for account in ["demo-api", "demo-web", "demo-mfa"]:
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
                    sys.executable, "-I", "-B", "-m", "account_access.worker_host",
                    "--policy", str(prefix / "policy.json"), "--bootstrap-fd", str(reader),
                    "--agent-fd", str(agent_socket.fileno()), "--owner-fd", str(owner_socket.fileno()),
                    "--controlled-fixture"]
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
                stage("different_user_signins_and_denials")
                checks = probe(prefix, roles, worker, policy, "initial")
                assert provider.login_count == 2 and provider.totp_count == 1
                checks["provider_confirmed_two_passwords_one_totp"] = True
                owner_request(owner_path, owner_token, "/owner/revoke", {"account": "demo-api"})
                stage("revoked_read")
                checks.update(probe(prefix, roles, worker, policy, "revoked"))
                checks["worker_still_alive_after_denied_attacks"] = worker.poll() is None
                worker.send_signal(signal.SIGTERM)
                stage("graceful_exit")
                stdout, stderr = worker.communicate(timeout=15)
                checks["graceful_worker_exit"] = worker.returncode == 0
                checks["worker_output_has_no_credentials"] = not stdout and not stderr
                assert all(checks.values()), "fixture_worker_final_checks_failed"
                return {"status": "PASSED", "environment": "controlled-demo", "production_ready": False,
                        "private_signins": 0, "platform": "linux", "real_distinct_uids": True,
                        "checks": checks,
                        "remaining": ["trusted production supervisor and lifecycle", "trusted owner enrollment gateway",
                                      "consumer installer integration", "macOS and private-account acceptance"]}
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
    if (sys.platform != "linux" or os.getuid() != 0 or prefix.parent != Path("/var/lib")
            or not prefix.name.startswith("account-access-worker-qa-") or not sys.flags.isolated):
        parser.error("Requires a disposable root-owned Linux CI runtime under /var/lib")
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
