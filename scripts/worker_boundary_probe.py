"""Unprivileged adversarial probe for the ephemeral, synthetic Linux CI service.

The root test harness starts this script under a new, non-sudo agent identity.
It does not open any installed user's Account Access store or browser account.
"""

import argparse
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def cli(config, *arguments):
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "ACCESS_CLIENT_CONFIG": str(config)}
    result = subprocess.run([sys.executable, "-I", "-B", "-m", "account_access.cli", *arguments],
                            env=environment, capture_output=True, timeout=100)
    # Do not include subprocess output in assertion failures or the report.
    if result.returncode not in {0, 1, 2}:
        raise RuntimeError("fixture_client_did_not_finish")
    return json.loads(result.stdout)


def denied(action):
    try:
        action()
    except PermissionError:
        return True
    return False


def write_existing(path):
    # Never truncate a file: the failed open is the permission check.
    with Path(path).open("r+b"):
        pass


def run(args):
    if os.getuid() == 0 or os.getuid() == args.worker_uid:
        raise RuntimeError("probe_requires_distinct_unprivileged_identity")
    config = Path(args.config)
    if args.phase == "revoked":
        result = cli(config, "run", "demo-api", "summary")
        assert result["status"] == "DENIED"
        return {"revoked_operation_denied": True}

    accounts = cli(config, "accounts")
    assert accounts["status"] == "OK"
    for account in ["demo-api", "demo-web", "demo-mfa"]:
        result = cli(config, "run", account, "summary")
        assert result["status"] == "COMPLETED" and "balance" in result["data"]
    result = cli(config, "run", "demo-api", "details")
    assert result["status"] == "DENIED"

    checks = {
        "different_nonroot_uid": True,
        "approved_api_password_totp_reads": True,
        "ungranted_operation_denied": True,
        "vault_database_read_denied": denied(lambda: (Path(args.state) / "state.db").read_bytes()),
        "vault_database_write_denied": denied(lambda: write_existing(Path(args.state) / "state.db")),
        "owner_configuration_read_denied": denied(lambda: (Path(args.state) / "config.json").read_bytes()),
        "runtime_write_denied": denied(lambda: write_existing(args.worker_module)),
        "runtime_replacement_denied": denied(lambda: Path(args.worker_module).rename(args.worker_module + ".moved")),
        "policy_write_denied": denied(lambda: write_existing(args.policy)),
        "worker_memory_read_denied": denied(lambda: Path(f"/proc/{args.worker_pid}/mem").open("rb")),
        "worker_environment_read_denied": denied(lambda: Path(f"/proc/{args.worker_pid}/environ").read_bytes()),
        "worker_descriptors_denied": denied(lambda: list(Path(f"/proc/{args.worker_pid}/fd").iterdir())),
        "worker_signal_denied": denied(lambda: os.kill(args.worker_pid, 0)),
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        checks["private_owner_channel_denied"] = denied(lambda: channel.connect(args.owner_socket))
    with UnixHTTP(args.agent_socket) as channel:
        token = Path(json.loads(config.read_text())["token_file"]).read_text().strip()
        channel.request("POST", "/owner/revoke", "{}", {"Authorization": "Bearer " + token,
                                                     "Content-Type": "application/json"})
        response = channel.getresponse()
        response.read()
        checks["agent_api_has_no_owner_routes"] = response.status == 404
    sudo = subprocess.run(["/usr/bin/sudo", "-n", "true"], capture_output=True, timeout=5)
    checks["agent_has_no_passwordless_sudo"] = sudo.returncode != 0
    launch = subprocess.run([sys.executable, "-I", "-B", "-m", "account_access.worker_host",
        "--policy", args.policy, "--bootstrap-fd", "9", "--agent-fd", "10", "--owner-fd", "11",
        "--controlled-fixture"], capture_output=True, timeout=10)
    checks["agent_cannot_impersonate_worker"] = (launch.returncode == 78
        and json.loads(launch.stdout).get("reason") == "invalid_worker_identity")
    assert all(checks.values()), "worker_boundary_probe_failed"
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["initial", "revoked"], required=True)
    for name in ["config", "state", "worker-module", "policy", "owner-socket", "agent-socket"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--worker-pid", type=int, required=True)
    parser.add_argument("--worker-uid", type=int, required=True)
    args = parser.parse_args()
    try:
        result = run(args)
    except Exception:
        print(json.dumps({"status": "FAILED", "reason": "worker_boundary_probe_failed"}))
        return 1
    print(json.dumps({"status": "PASSED", "checks": result}))
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    raise SystemExit(main())
