"""Disposable Mac CI: check launchctl stdout ordering inside a real Installer.

The ordinary runner creates a tiny no-payload package. Its script exercises only
a uniquely named system job running /bin/echo with a fixed public string. No
production Account Access namespace, account, keychain or user data is opened.
Never run this probe with elevated privileges on an owner's Mac.
"""

import argparse
import ast
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile


ROOT_PROBE = r'''"""Generated only by the gated disposable-CI package builder."""
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import time

TOKEN = "__TOKEN__"
LABEL = "com.fainir.accountaccess.qa.launchctl." + TOKEN
TARGET = "system/" + LABEL
ROOT = Path("/Library/Logs/AccountAccessLaunchctlQA-" + TOKEN)
REPORT = Path(str(ROOT) + ".json")
FIXED = b"ACCOUNT_ACCESS_LAUNCHCTL_INSTALLER_FIXTURE_V1\n"
ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}


def outcome(returncode, stdout=b"", stderr=b"", *, timed_out=False):
    # Only closed classifications are published. No command's raw output enters
    # the report, even if a future launchctl release changes its diagnostics.
    lowered = stderr[:4096].lower()
    error = ("timeout" if timed_out else "none" if returncode == 0 else
             "requires_root" if b"requires root privileges" in lowered else
             "permission_denied" if any(value in lowered for value in
                 [b"operation not permitted", b"permission denied", b"not privileged"]) else
             "not_found" if returncode == 113 else "command_failed")
    return {"returncode": returncode, "timed_out": timed_out,
            "error": error, "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
            "numeric_pid_response": bool(stdout.strip()) and stdout.strip().isdigit()}


def run(arguments, timeout=8):
    started = time.monotonic()
    try:
        child = subprocess.run(["/bin/launchctl"] + arguments,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=ENVIRONMENT, timeout=timeout, check=False)
        result = outcome(child.returncode, child.stdout, child.stderr)
    except subprocess.TimeoutExpired as error:
        result = outcome(None, error.stdout or b"", error.stderr or b"", timed_out=True)
    except OSError:
        result = {"returncode": None, "timed_out": False, "error": "invocation_failed"}
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def launch(arguments):
    try:
        return subprocess.Popen(["/bin/launchctl"] + arguments,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=ENVIRONMENT), None
    except OSError:
        return None, {"returncode": None, "timed_out": False, "error": "invocation_failed"}


def finish(child, *, expired=False):
    # Only our own launchctl client is terminated on timeout. The fixture is
    # removed separately through its exact unique service target.
    if child is None:
        return None
    timed_out = expired and child.poll() is None
    if timed_out:
        child.terminate()
    try:
        stdout, stderr = child.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        child.kill()
        stdout, stderr = child.communicate(timeout=1)
        timed_out = True
    return outcome(child.returncode, stdout, stderr, timed_out=timed_out)


def debug_and_start(path):
    started = time.monotonic()
    debug = start = None
    result = {"observation_bound_ms": 2000, "client_deadline_ms": 12000,
              "client_termination_bound_ms": 4000,
              "start_requested_while_debug_pending": False}
    try:
        debug, failed = launch(["debug", TARGET, "--stdout", str(path)])
        if failed is not None:
            result["debug"] = failed
            return result
        deadline = started + 2
        while debug.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        result["debug_pending_at_observation_bound"] = debug.poll() is None
        result["debug_observed_ms"] = round((time.monotonic() - started) * 1000)
        result["start_requested_while_debug_pending"] = debug.poll() is None
        # Never -k. Both clients remain asynchronous so a debug command waiting
        # for the next process invocation cannot prevent that invocation.
        start, failed = launch(["kickstart", "-p", TARGET])
        if failed is not None:
            result["start"] = failed
        deadline = started + 12
        while ((debug is not None and debug.poll() is None)
               or (start is not None and start.poll() is None)) and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        if debug is not None:
            result["debug"] = finish(debug, expired=True)
        if start is not None:
            result["start"] = finish(start, expired=True)
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def create(fd, name, data):
    child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=fd)
    try:
        with os.fdopen(child, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(child)
        return os.fstat(child).st_ino
    finally:
        os.close(child)


def successful_trial(value):
    return (value.get("debug", {}).get("returncode") == 0
            and not value.get("debug", {}).get("timed_out", True)
            and value.get("start", {}).get("returncode") == 0
            and not value.get("start", {}).get("timed_out", True)
            and value.get("start", {}).get("numeric_pid_response") is True)


def main():
    if (sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0
            or os.environ.get("ACCOUNT_ACCESS_CI_LAUNCHCTL_TOKEN") != TOKEN
            or len(sys.argv) != 1):
        return 2
    os.umask(0o077)
    report = {"schema": 1, "status": "FAILED", "environment": "disposable-mac-ci-installer",
              "fixture": "unique-system-job-fixed-public-echo", "actual_installer_script": True,
              "private_data_accessed": False, "production_namespace_accessed": False,
              "fixture_removed": False, "service_removed": False, "failure_stage": "preflight"}
    directory = capture_fd = None
    files = {}
    attempted_bootstrap = False
    try:
        parent = ROOT.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise RuntimeError("unsafe_public_parent")
        os.mkdir(ROOT, 0o700)
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(directory)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("unsafe_fixture_directory")
        before = run(["print", TARGET])
        report["preflight"] = before
        if before.get("returncode") != 113:
            raise RuntimeError("fixture_target_not_absent")
        capture_fd = os.open("stdout", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        files["stdout"] = os.fstat(capture_fd).st_ino
        value = {"Label": LABEL, "ProgramArguments": ["/bin/echo", FIXED.decode().strip()],
                 "RunAtLoad": False, "KeepAlive": False, "ThrottleInterval": 1,
                 "ProcessType": "Background", "StandardOutPath": "/dev/null",
                 "StandardErrorPath": "/dev/null"}
        files["service.plist"] = create(directory, "service.plist", plistlib.dumps(value))
        report["failure_stage"] = "bootstrap"
        attempted_bootstrap = True
        report["bootstrap"] = run(["bootstrap", "system", str(ROOT / "service.plist")])
        if report["bootstrap"].get("returncode") != 0:
            raise RuntimeError("fixture_bootstrap_failed")
        report["failure_stage"] = "redirect"
        report["redirect"] = debug_and_start(ROOT / "stdout")
        deadline = time.monotonic() + 2
        while not os.pread(capture_fd, 128, 0) and time.monotonic() < deadline:
            time.sleep(0.02)
        captured = os.pread(capture_fd, 128, 0)
        report["fixed_stdout_captured"] = captured == FIXED and os.fstat(capture_fd).st_size == len(FIXED)
        report["failure_stage"] = "reset"
        report["reset"] = debug_and_start(Path("/dev/null"))
        time.sleep(0.1)
        report["capture_unchanged_after_reset"] = (os.pread(capture_fd, 128, 0) == captured
            and os.fstat(capture_fd).st_size == len(captured))
        redirect_passed = successful_trial(report["redirect"]) and report["fixed_stdout_captured"]
        reset_passed = successful_trial(report["reset"]) and report["capture_unchanged_after_reset"]
        passed = redirect_passed and reset_passed
        report["failure_stage"] = "redirect" if not redirect_passed else "reset" if not reset_passed else None
        if passed:
            report["failure_stage"] = None
            report["status"] = "PASSED"
    except Exception:
        # failure_stage is assigned only from the fixed literals above.
        report["status"] = "FAILED"
    finally:
        if capture_fd is not None:
            os.close(capture_fd)
        if attempted_bootstrap:
            report["bootout"] = run(["bootout", TARGET])
            report["post_cleanup_lookup"] = run(["print", TARGET])
            report["service_removed"] = report["post_cleanup_lookup"].get("returncode") == 113
        else:
            report["service_removed"] = True
        if directory is not None:
            try:
                # Remove only the two exclusive files created by this helper,
                # and only after the exact unique job is confirmed absent.
                if not report["service_removed"]:
                    raise RuntimeError("fixture_service_still_registered")
                for name, inode in files.items():
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_ino != inode:
                        raise RuntimeError("fixture_file_changed")
                    os.unlink(name, dir_fd=directory)
                os.rmdir(ROOT)
                report["fixture_removed"] = True
            except Exception:
                report["status"] = "FAILED"
                report["failure_stage"] = "fixture_cleanup"
            finally:
                os.close(directory)
        if not report["service_removed"] or not report["fixture_removed"]:
            report["status"] = "FAILED"
        parent = os.open(REPORT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            create(parent, REPORT.name, json.dumps(report, sort_keys=True).encode() + b"\n")
            os.chmod(REPORT, 0o644)
        finally:
            os.close(parent)
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def root_source(token):
    if len(token) != 32 or any(value not in "0123456789abcdef" for value in token):
        raise ValueError("invalid_probe_token")
    value = ROOT_PROBE.replace("__TOKEN__", token)
    ast.parse(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "macOS"):
        parser.error("Requires an ordinary runner in a disposable Mac CI VM")
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("Requires a new evidence directory")
    output.mkdir(mode=0o700)
    token = secrets.token_hex(16)
    public_report = Path("/Library/Logs/AccountAccessLaunchctlQA-" + token + ".json")
    report = {"schema": 1, "status": "FAILED", "environment": "disposable-mac-ci-installer",
              "actual_installer_used": False, "private_data_accessed": False,
              "production_namespace_accessed": False, "production_ready": False}
    try:
        with tempfile.TemporaryDirectory(prefix="account-access-launchctl-ci-") as temporary:
            scratch = Path(temporary)
            scripts = scratch / "scripts"
            scripts.mkdir()
            (scripts / "probe.py").write_text(root_source(token))
            postinstall = scripts / "postinstall"
            postinstall.write_text(
                '#!/bin/sh\nset -eu\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\n'
                '[ "$(/usr/bin/id -u)" = 0 ] && [ "${3:-}" = / ] || exit 1\n'
                'AC_LAUNCHCTL_SCRIPTS=$(CDPATH= cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)\n'
                'export ACCOUNT_ACCESS_CI_LAUNCHCTL_TOKEN=' + token + '\n'
                'exec /usr/bin/python3 -I -S "$AC_LAUNCHCTL_SCRIPTS/probe.py"\n')
            postinstall.chmod(0o755)
            package = scratch / "launchctl-context.pkg"
            subprocess.run(["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(scripts),
                "--identifier", "com.fainir.accountaccess.qa.launchctl-installer." + token,
                "--version", "1.0", "--ownership", "recommended", "--install-location", "/", str(package)],
                check=True, capture_output=True, timeout=45)
            report["actual_installer_used"] = True
            try:
                installed = subprocess.run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package),
                    "-target", "/"], capture_output=True, check=False, timeout=100)
                report["installer_exit_code"] = installed.returncode
                (output / "installer-stdout.txt").write_bytes(installed.stdout[:65536])
                (output / "installer-stderr.txt").write_bytes(installed.stderr[:65536])
            except subprocess.TimeoutExpired:
                report["installer_timed_out"] = True
            if (public_report.is_file() and not public_report.is_symlink()
                    and public_report.stat().st_uid == 0 and public_report.stat().st_size <= 65536):
                value = json.loads(public_report.read_bytes())
                (output / "installer-context.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
                report["probe"] = value
                if report.get("installer_exit_code") == 0 and value.get("status") == "PASSED":
                    report["status"] = "PASSED"
            else:
                report["failure_stage"] = "installer_report_missing"
    except Exception:
        report["failure_stage"] = "probe_invocation_failed"
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
