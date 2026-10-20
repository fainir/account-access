"""Disposable Mac CI: measure persistent-disable registration exclusion.

The ordinary GitHub runner builds a no-payload package and invokes the real
Installer. Its root script touches only a unique system fixture and public
marker. This is never an owner-Mac updater, reboot test or production health
check. A unique explicit-false disable override can remain until VM teardown.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile


ROOT_PROBE = r'''"""Fixed public fixture, generated only by disposable-CI gating."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import selectors
import stat
import subprocess
import sys
import time

TOKEN = "__TOKEN__"
LABEL = "local.account-access-disable-probe." + TOKEN
TARGET = "system/" + LABEL
ROOT = Path("/Library/Logs/AccountAccessDisableQA-" + TOKEN)
REPORT = Path(str(ROOT) + ".json")
FIXED = b"ACCOUNT_ACCESS_DISABLE_FIXTURE_V1\n"
ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
ABSENT = ("Bad request.\nCould not find service \"" + LABEL
          + "\" in domain for system\n").encode()


def unambiguous(result):
    return (type(result.get("returncode")) is int and result.get("client_reaped") is True
            and result.get("timed_out") is False and result.get("output_limited") is False
            and result.get("invocation_failed") is False)


def succeeded(result):
    return unambiguous(result) and result["returncode"] == 0


def definitively_absent(result, output):
    return unambiguous(result) and result["returncode"] == 113 and output == ABSENT


def disabled_override(output):
    text = output.decode("utf-8")
    matches = [line.strip() for line in text.splitlines() if '"' + LABEL + '"' in line]
    if not matches:
        return "absent"
    if len(matches) != 1:
        raise ValueError("ambiguous_override")
    if matches[0] == '"' + LABEL + '" => true':
        return "true"
    if matches[0] == '"' + LABEL + '" => false':
        return "false"
    raise ValueError("unknown_override")


def run(arguments, timeout=6):
    allowed = (["print", TARGET], ["print-disabled", "system"], ["disable", TARGET],
               ["enable", TARGET], ["bootout", TARGET],
               ["bootstrap", "system", str(ROOT / "service.plist")])
    if arguments not in allowed:
        raise ValueError("outside_fixture_command")
    started = time.monotonic()
    output = bytearray()
    child = None
    result = {"returncode": None, "timed_out": False, "output_limited": False,
              "invocation_failed": False, "client_reaped": False}
    try:
        child = subprocess.Popen(["/bin/launchctl"] + arguments,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=ENVIRONMENT)
        os.set_blocking(child.stdout.fileno(), False)
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            eof = False
            while not eof or child.poll() is None:
                remaining = started + timeout - time.monotonic()
                if remaining <= 0:
                    result["timed_out"] = True
                    break
                for key, _ in ready.select(min(remaining, 0.05)):
                    try:
                        block = os.read(key.fd, 8192)
                    except BlockingIOError:
                        continue
                    if not block:
                        ready.unregister(key.fileobj)
                        eof = True
                    elif len(output) + len(block) > 128 * 1024:
                        result["output_limited"] = True
                        break
                    else:
                        output.extend(block)
                if result["output_limited"]:
                    break
    except OSError:
        result["invocation_failed"] = True
    finally:
        if child is not None:
            # Signal/reap only this direct unreaped child, never any service PID.
            if child.poll() is None:
                child.kill()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
            result["returncode"] = child.returncode
            result["client_reaped"] = child.returncode is not None
            if child.stdout is not None:
                child.stdout.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    result["output_bytes"] = len(output)
    result["output_sha256"] = hashlib.sha256(output).hexdigest()
    return result, bytes(output)


def create(parent, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise RuntimeError("fixture_write_failed")
            view = view[count:]
        os.fsync(fd)
        os.fsync(parent)
        return os.fstat(fd).st_ino
    finally:
        os.close(fd)


def marker(parent):
    try:
        fd = os.open("marker", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        data = os.read(fd, len(FIXED) + 1)
        after = os.fstat(fd)
        linked = os.stat("marker", dir_fd=parent, follow_symlinks=False)
        stable = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 <= before.st_size <= len(FIXED)
                or before.st_ino != linked.st_ino or before.st_dev != linked.st_dev
                or before.st_ino != after.st_ino or before.st_dev != after.st_dev):
            raise RuntimeError("fixture_marker_changed")
        if stable(before) != stable(after) or before.st_size < len(FIXED):
            return None  # The one tiny fixture write may still be in progress.
        if data != FIXED:
            raise RuntimeError("fixture_marker_changed")
        return before.st_ino
    finally:
        os.close(fd)


def await_marker(parent):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        found = marker(parent)
        if found is not None:
            return found
        time.sleep(0.02)
    raise RuntimeError("fixture_marker_not_created")


def absent_marker_window(parent):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.stat("marker", dir_fd=parent, follow_symlinks=False)
            return False
        except FileNotFoundError:
            pass
        time.sleep(0.02)
    try:
        os.stat("marker", dir_fd=parent, follow_symlinks=False)
        return False
    except FileNotFoundError:
        return True


def main():
    if (sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0
            or os.environ.get("ACCOUNT_ACCESS_CI_DISABLE_TOKEN") != TOKEN or len(sys.argv) != 1):
        return 2
    os.umask(0o077)
    report = {"schema": 1, "status": "FAILED", "actual_installer_script": True,
              "status_scope": "unique_system_job_registration_exclusion_while_disabled_no_reboot",
              "root_probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "private_data_accessed": False, "production_namespace_accessed": False,
              "production_ready": False, "service_health_verified": False, "reboot_tested": False,
              "persistence_basis": "launchctl(1) enable-disable documents persistence across boots",
              "fixture_removed": False, "service_removed": False,
              "effective_enabled_restored": False,
              "unique_false_override_retained_until_vm_teardown": False,
              "zero_override_state_claimed": False, "failure_stage": "preflight"}
    directory = None
    files = {}
    service_touched = False
    try:
        parent = ROOT.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise RuntimeError("unsafe_fixture_parent")
        os.mkdir(ROOT, 0o700)
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        folder = os.fstat(directory)
        if folder.st_uid != 0 or stat.S_IMODE(folder.st_mode) != 0o700:
            raise RuntimeError("unsafe_fixture_directory")
        report["preflight_lookup"], raw = run(["print", TARGET])
        report["preflight_definitively_absent"] = definitively_absent(report["preflight_lookup"], raw)
        if not report["preflight_definitively_absent"]:
            raise RuntimeError("target_not_definitively_absent")
        report["initial_disabled_query"], raw = run(["print-disabled", "system"])
        if not succeeded(report["initial_disabled_query"]):
            raise RuntimeError("initial_disabled_state_unavailable")
        report["initial_disabled_override"] = disabled_override(raw)
        if report["initial_disabled_override"] != "absent":
            raise RuntimeError("unique_target_has_existing_override")
        value = {"Label": LABEL, "ProgramArguments": ["/bin/sh", "-c",
            'umask 077; set -C; printf "%s\\n" "ACCOUNT_ACCESS_DISABLE_FIXTURE_V1" > "$1"',
            "disable-fixture", str(ROOT / "marker")], "RunAtLoad": True, "KeepAlive": False,
            "ProcessType": "Background", "StandardOutPath": "/dev/null",
            "StandardErrorPath": "/dev/null", "Umask": 0o077}
        files["service.plist"] = create(directory, "service.plist", plistlib.dumps(value))
        report["failure_stage"] = "initial_enabled_control"
        service_touched = True
        report["initial_bootstrap"], _ = run(["bootstrap", "system", str(ROOT / "service.plist")])
        if not succeeded(report["initial_bootstrap"]):
            raise RuntimeError("initial_bootstrap_failed")
        files["marker"] = await_marker(directory)
        report["initial_enabled_marker_created"] = True
        report["failure_stage"] = "persistent_disable"
        report["disable"], _ = run(["disable", TARGET])
        report["disabled_query"], raw = run(["print-disabled", "system"])
        if not succeeded(report["disable"]) or not succeeded(report["disabled_query"]):
            raise RuntimeError("disable_not_confirmed")
        report["disabled_override"] = disabled_override(raw)
        if report["disabled_override"] != "true":
            raise RuntimeError("disable_not_confirmed")
        report["bootout"], _ = run(["bootout", TARGET])
        report["after_bootout_lookup"], raw = run(["print", TARGET])
        report["after_bootout_definitively_absent"] = definitively_absent(report["after_bootout_lookup"], raw)
        if not succeeded(report["bootout"]) or not report["after_bootout_definitively_absent"]:
            raise RuntimeError("bootout_not_confirmed")
        if marker(directory) != files["marker"]:
            raise RuntimeError("initial_marker_changed")
        os.unlink("marker", dir_fd=directory)
        del files["marker"]
        os.fsync(directory)
        report["failure_stage"] = "disabled_registration_exclusion"
        report["disabled_bootstrap"], _ = run(["bootstrap", "system", str(ROOT / "service.plist")])
        report["disabled_lookup"], raw = run(["print", TARGET])
        report["disabled_definitively_absent"] = definitively_absent(report["disabled_lookup"], raw)
        report["disabled_marker_absent_for_2000ms"] = absent_marker_window(directory)
        report["disabled_query_after_attempt"], raw = run(["print-disabled", "system"])
        report["disabled_override_after_attempt"] = (disabled_override(raw)
            if succeeded(report["disabled_query_after_attempt"]) else "unverified")
        if (not unambiguous(report["disabled_bootstrap"]) or report["disabled_bootstrap"]["returncode"] == 0
                or not report["disabled_definitively_absent"]
                or not report["disabled_marker_absent_for_2000ms"]
                or report["disabled_override_after_attempt"] != "true"):
            raise RuntimeError("registration_exclusion_not_proven")
        # Characterize retry's already-removed state without interpreting any
        # generic bootout error as absence. The separate exact print proves it.
        report["bootout_already_absent"], _ = run(["bootout", TARGET])
        report["lookup_after_absent_bootout"], raw = run(["print", TARGET])
        report["already_absent_state_confirmed"] = definitively_absent(report["lookup_after_absent_bootout"], raw)
        if not unambiguous(report["bootout_already_absent"]) or not report["already_absent_state_confirmed"]:
            raise RuntimeError("already_absent_measurement_ambiguous")
        report["failure_stage"] = "reenabled_control"
        report["enable"], _ = run(["enable", TARGET])
        report["enabled_query"], raw = run(["print-disabled", "system"])
        report["enabled_override"] = disabled_override(raw) if succeeded(report["enabled_query"]) else "unverified"
        if not succeeded(report["enable"]) or report["enabled_override"] != "false":
            raise RuntimeError("enabled_state_not_confirmed")
        report["reenabled_bootstrap"], _ = run(["bootstrap", "system", str(ROOT / "service.plist")])
        if not succeeded(report["reenabled_bootstrap"]):
            raise RuntimeError("reenabled_bootstrap_failed")
        files["marker"] = await_marker(directory)
        report["reenabled_marker_created"] = True
        report["status"] = "PASSED"
        report["failure_stage"] = None
    except Exception:
        report["status"] = "FAILED"
    finally:
        report["measurement_failure_stage"] = report["failure_stage"]
        if service_touched:
            report["cleanup_bootout"], _ = run(["bootout", TARGET])
            report["cleanup_lookup"], raw = run(["print", TARGET])
            report["service_removed"] = definitively_absent(report["cleanup_lookup"], raw)
            report["cleanup_enable"], _ = run(["enable", TARGET])
            report["cleanup_disabled_query"], raw = run(["print-disabled", "system"])
            try:
                override = disabled_override(raw) if succeeded(report["cleanup_disabled_query"]) else "unverified"
            except Exception:
                override = "unverified"
            report["effective_enabled_restored"] = succeeded(report["cleanup_enable"]) and override == "false"
            report["unique_false_override_retained_until_vm_teardown"] = override == "false"
            if not unambiguous(report["cleanup_bootout"]):
                report["status"] = "FAILED"
        else:
            report["service_removed"] = report.get("preflight_definitively_absent", False)
            report["effective_enabled_restored"] = report.get("initial_disabled_override") == "absent"
        if directory is not None:
            try:
                if not report["service_removed"] or not report["effective_enabled_restored"]:
                    raise RuntimeError("service_cleanup_not_confirmed")
                actual = set(os.listdir(directory))
                if actual != set(files):
                    raise RuntimeError("fixture_has_unknown_children")
                for name, inode in files.items():
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                            or info.st_nlink != 1 or info.st_ino != inode):
                        raise RuntimeError("fixture_file_changed")
                    os.unlink(name, dir_fd=directory)
                linked = ROOT.lstat()
                if linked.st_ino != folder.st_ino or linked.st_dev != folder.st_dev:
                    raise RuntimeError("fixture_directory_changed")
                os.rmdir(ROOT)
                report["fixture_removed"] = True
            except Exception:
                report["status"] = "FAILED"
                report["failure_stage"] = "fixture_cleanup"
            finally:
                os.close(directory)
        if not all(report[key] for key in ("service_removed", "fixture_removed", "effective_enabled_restored")):
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
    if re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise ValueError("invalid_probe_token")
    source = ROOT_PROBE.replace("__TOKEN__", token)
    ast.parse(source)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "macOS"
            or re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", "")) is None
            or re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ATTEMPT", "")) is None):
        parser.error("Requires an ordinary GitHub runner in a disposable Mac CI VM")
    source_commit = os.environ.get("GITHUB_SHA", "")
    current = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], timeout=5, text=True).strip()
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None or current != source_commit:
        parser.error("Requires the exact checked-out GitHub source commit")
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("Requires a new evidence directory")
    output.mkdir(mode=0o700)
    token = secrets.token_hex(16)
    generated = root_source(token)
    repository = Path(__file__).resolve().parent.parent
    source_binding = {"git_head": current, "github_sha": source_commit,
        "probe_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "workflow_sha256": hashlib.sha256((repository / ".github/workflows/mac-worker.yml").read_bytes()).hexdigest(),
        "root_probe_sha256": hashlib.sha256(generated.encode()).hexdigest()}
    manual_path = Path("/usr/share/man/man1/launchctl.1")
    manual = manual_path.read_bytes()
    manual_reference = {"path": str(manual_path), "sha256": hashlib.sha256(manual).hexdigest(),
        "section": "enable | disable", "documented_persistence_text_present":
        b"This state persists across boots of the device" in manual}
    (output / "root-probe.py").write_text(generated)
    public_report = Path("/Library/Logs/AccountAccessDisableQA-" + token + ".json")
    report = {"schema": 1, "status": "FAILED", "environment": "disposable-mac-ci-installer",
        "status_scope": "unique_system_job_registration_exclusion_while_disabled_no_reboot",
        "source_binding": source_binding, "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "actual_installer_used": False,
        "manual_reference": manual_reference, "darwin_release": os.uname().release,
        "private_data_accessed": False, "production_namespace_accessed": False,
        "production_ready": False, "reboot_tested": False}
    try:
        with tempfile.TemporaryDirectory(prefix="account-access-disable-ci-") as temporary:
            scratch = Path(temporary)
            scripts = scratch / "scripts"
            scripts.mkdir()
            (scripts / "probe.py").write_text(generated)
            postinstall = scripts / "postinstall"
            postinstall.write_text(
                '#!/bin/sh\nset -eu\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\n'
                '[ "$(/usr/bin/id -u)" = 0 ] && [ "${3:-}" = / ] || exit 1\n'
                'AC_DISABLE_SCRIPTS=$(CDPATH= cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)\n'
                'export ACCOUNT_ACCESS_CI_DISABLE_TOKEN=' + token + '\n'
                'exec /usr/bin/python3 -I -B -S "$AC_DISABLE_SCRIPTS/probe.py"\n')
            postinstall.chmod(0o755)
            package = scratch / "disable-context.pkg"
            subprocess.run(["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(scripts),
                "--identifier", "local.account-access-disable-installer." + token, "--version", "1.0",
                "--ownership", "recommended", "--install-location", "/", str(package)],
                check=True, capture_output=True, timeout=45)
            report["actual_installer_used"] = True
            try:
                installed = subprocess.run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package),
                    "-target", "/"], capture_output=True, check=False, timeout=120)
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
                if (report.get("installer_exit_code") == 0 and value.get("status") == "PASSED"
                        and value.get("root_probe_sha256") == source_binding["root_probe_sha256"]):
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
