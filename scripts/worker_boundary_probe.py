"""Unprivileged adversarial probe for the ephemeral, synthetic CI service.

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


ACCOUNTS = ("demo-api", "demo-web", "demo-mfa", "example-email", "example-sms")
DIAGNOSTIC_STAGES = {"account_discovery", "revoked_read", "ungranted_read", "boundary_checks", *ACCOUNTS}
SAFE_REASONS = {"browser_guard_unavailable", "internal_error", "service_unavailable", "worker_unavailable",
                "login_failed", "verification_code_unavailable", "invalid_credentials", "request_failed",
                "browser_execution_failed", "login_code_not_received", "verification_code_rejected",
                "verification_source_not_connected", "browser_state_unrecognized", "login_retry_cooldown"}


class ProbeFailure(Exception):
    def __init__(self, stage, result=None):
        self.stage = stage if stage in DIAGNOSTIC_STAGES else "boundary_checks"
        self.status = result.get("status") if isinstance(result, dict) else None
        reason = result.get("reason") if isinstance(result, dict) else None
        self.reason = reason if reason in SAFE_REASONS else "not_reported"


def require_result(condition, stage, result):
    if not condition:
        raise ProbeFailure(stage, result)


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


def mac_task_port_denied(pid):
    # A task port would permit memory inspection/control. Request it, never
    # read process memory, and release it if the platform unexpectedly grants it.
    import ctypes
    system = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    own = ctypes.c_uint.in_dll(system, "mach_task_self_").value
    target = ctypes.c_uint(0)
    system.task_for_pid.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
    system.task_for_pid.restype = ctypes.c_int
    status = system.task_for_pid(own, pid, ctypes.byref(target))
    if status == 0 and target.value:
        system.mach_port_deallocate.argtypes = [ctypes.c_uint, ctypes.c_uint]
        system.mach_port_deallocate(own, target.value)
        return False
    return status != 0


def run(args):
    if os.getuid() == 0 or os.getuid() == args.worker_uid:
        raise RuntimeError("probe_requires_distinct_unprivileged_identity")
    config = Path(args.config)
    if args.phase == "after-owner-stop":
        result = cli(config, "run", "demo-web", "summary")
        require_result(result["status"] == "COMPLETED", "demo-web", result)
        return {"worker_operates_after_owner_gateway_stop": True}
    if args.phase == "revoked":
        result = cli(config, "run", "demo-api", "summary")
        require_result(result["status"] == "DENIED", "revoked_read", result)
        return {"revoked_operation_denied": True}

    accounts = cli(config, "accounts")
    require_result(accounts["status"] == "OK", "account_discovery", accounts)
    for account in ACCOUNTS:
        result = cli(config, "run", account, "summary")
        require_result(result["status"] == "COMPLETED" and "balance" in result.get("data", {}), account, result)
    result = cli(config, "run", "demo-api", "details")
    require_result(result["status"] == "DENIED", "ungranted_read", result)

    checks = {
        "different_nonroot_uid": True,
        "approved_api_password_email_sms_totp_reads": True,
        "ungranted_operation_denied": True,
        "vault_database_read_denied": denied(lambda: (Path(args.state) / "state.db").read_bytes()),
        "vault_database_write_denied": denied(lambda: write_existing(Path(args.state) / "state.db")),
        "owner_configuration_read_denied": denied(lambda: (Path(args.state) / "config.json").read_bytes()),
        "runtime_write_denied": denied(lambda: write_existing(args.worker_module)),
        "runtime_replacement_denied": denied(lambda: Path(args.worker_module).rename(args.worker_module + ".moved")),
        "policy_write_denied": denied(lambda: write_existing(args.policy)),
        "worker_signal_denied": denied(lambda: os.kill(args.worker_pid, 0)),
    }
    if sys.platform == "darwin":
        checks["worker_task_port_denied"] = mac_task_port_denied(args.worker_pid)
        refused = subprocess.run([args.mac_bootstrap, "--policy", str(Path(args.policy).with_name("mac-launcher.json")),
            "--bootstrap-fd", "9", "--agent-fd", "10", "--owner-fd", "11"], capture_output=True, timeout=10)
        checks["native_launcher_requires_root"] = (refused.returncode == 78
            and json.loads(refused.stdout).get("reason") == "worker_launcher_requires_root")
    else:
        checks.update({
            "worker_memory_read_denied": denied(lambda: Path(f"/proc/{args.worker_pid}/mem").open("rb")),
            "worker_environment_read_denied": denied(lambda: Path(f"/proc/{args.worker_pid}/environ").read_bytes()),
            "worker_descriptors_denied": denied(lambda: list(Path(f"/proc/{args.worker_pid}/fd").iterdir())),
        })
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
    parser.add_argument("--phase", choices=["initial", "revoked", "after-owner-stop"], required=True)
    for name in ["config", "state", "worker-module", "policy", "owner-socket", "agent-socket"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--worker-pid", type=int, required=True)
    parser.add_argument("--worker-uid", type=int, required=True)
    parser.add_argument("--mac-bootstrap")
    args = parser.parse_args()
    try:
        result = run(args)
    except ProbeFailure as exc:
        report = {"status": "FAILED", "reason": "worker_boundary_probe_failed", "stage": exc.stage,
                  "operation_reason": exc.reason}
        if exc.status in {"COMPLETED", "DENIED", "NEEDS_USER", "RETRYABLE", "OK"}:
            report["operation_status"] = exc.status
        print(json.dumps(report))
        return 1
    except Exception:
        print(json.dumps({"status": "FAILED", "reason": "worker_boundary_probe_failed"}))
        return 1
    print(json.dumps({"status": "PASSED", "checks": result}))
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    raise SystemExit(main())
