"""Bounded, owner-approved startup check for the exact installed build 76.

This is a one-use Installer script, not an agent or owner API. It never opens a
vault, journal, keychain, mailbox or user configuration. It temporarily captures
the existing broker's closed failure response and requests a non-killing start.
It does not replace code, edit the job, change arguments, or grant account access.
The fixed --inspect-retained mode only inspects an existing guarded target and
publishes a closed result; it never redirects, starts, resets or deletes.
"""

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time

BASE = Path("/Library/Application Support/Account Access")
BROKER = BASE / "bin/AccountAccess-broker"
PYTHON = BASE / "runtime/bin/python3.12"
JOB = Path("/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist")
SERVICE = "system/com.fainir.accountaccess.broker"
REPORTS = Path("/Library/Logs/AccountAccessStartupChecks")
MANAGED_BY = "account-access-startup-check-v1"
PINS = {
    "bin/AccountAccess-broker": "7d025c2ed00963e3b0ee7d8aa9351d00454ed54e6d73b2b4caaa3990424bf061",
    "runtime/bin/python3.12": "b21371592c32af6f23b2967c54ffc141f4e14fe1ce73cf45dfb69e5b71c5d762",
    "owner.app/Contents/Info.plist": "f0a07fc69db047341b8eec2c86284e556fada3aeb252c91c8b8c97668ff5357b",
    "package-identity.json": "4bd0ef5cf76e51cd38cb09f969da5d33b018bf764890c225ee1d361935dfe1e0",
}
FAILURE_REASONS = frozenset({
    "system_daemon_context_required", "invalid_vault_identity", "vault_key_missing",
    "vault_key_already_enrolled", "invalid_vault_key_record", "system_keychain_unavailable",
    "system_broker_invalid_arguments", "system_broker_invalid_policy", "system_broker_unavailable",
    "owner_policy_requires_system_daemon", "owner_policy_changed", "owner_policy_unavailable",
    "owner_policy_readback_invalid",
})
STATUSES = frozenset({
    "capture_unavailable", "capture_not_permitted", "start_request_unavailable",
    "failure_captured", "no_closed_failure_reported", "diagnostic_unavailable",
    "diagnostic_tool_unavailable", "installed_job_unavailable", "installed_job_changed",
    "service_is_running", "service_not_failing_with_78", "unsafe_capture_metadata",
    "unsafe_metadata", "build_76_binding_changed",
    "retained_capture_pending",
    "retained_capture_ambiguous", "retained_capture_metadata_unavailable",
    "retained_capture_oversize", "unknown_report_entry", "retained_capture_unavailable",
})
STAGES = frozenset({"preflight", "redirect", "start", "capture_wait", "reset", "cleanup", "retained_inspection"})
COMMAND_OUTCOMES = frozenset({
    "not_attempted", "success", "nonzero", "timeout", "invocation_error",
    "output_too_large", "invalid_output",
})


class Refused(Exception):
    """Only constant local reason codes may enter public results."""


class CommandFailure(Refused):
    def __init__(self, outcome):
        super().__init__("diagnostic_tool_unavailable")
        self.outcome = closed_outcome(outcome)


def closed_outcome(value):
    return value if type(value) is str and value in COMMAND_OUTCOMES else "invocation_error"


def no_acl(fd):
    library = ctypes.CDLL(None, use_errno=True)
    library.acl_get_fd.argtypes = [ctypes.c_int]
    library.acl_get_fd.restype = ctypes.c_void_p
    library.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_free.argtypes = [ctypes.c_void_p]
    library.acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = library.acl_get_fd(fd)
    if not acl:
        if ctypes.get_errno() != errno.ENOENT:
            raise Refused("unsafe_metadata")
        return
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        if library.acl_get_entry(acl, 0, ctypes.byref(entry)) != -1 or ctypes.get_errno() != errno.EINVAL:
            raise Refused("unsafe_metadata")
    finally:
        library.acl_free(acl)


def check_fd(fd, *, directory=False, owner=0):
    info = os.fstat(fd)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(info.st_mode) or info.st_uid != owner or info.st_mode & 0o7022
            or (not directory and info.st_nlink != 1)):
        raise Refused("unsafe_metadata")
    no_acl(fd)
    return info


def directory(path, *, create=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise Refused("unsafe_metadata")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        check_fd(fd, directory=True)
        for index, part in enumerate(path.parts[1:]):
            created = False
            if create and index == len(path.parts) - 2:
                try:
                    os.mkdir(part, 0o755, dir_fd=fd)
                    created = True
                except FileExistsError:
                    pass
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                check_fd(following, directory=True)
                if created:
                    os.fchmod(following, 0o755)
                if create and index == len(path.parts) - 2 and stat.S_IMODE(os.fstat(following).st_mode) != 0o755:
                    raise Refused("unsafe_metadata")
            except BaseException:
                os.close(following)
                raise
            os.close(fd)
            fd = following
        return fd
    except BaseException:
        os.close(fd)
        raise


def public_bytes(path, limit=32 * 1024 * 1024):
    parent = directory(Path(path).parent)
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = check_fd(fd)
        if before.st_size > limit:
            raise Refused("unsafe_metadata")
        data = bytearray()
        while len(data) <= limit:
            block = os.read(fd, min(1024 * 1024, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = check_fd(fd)
        def stamp(item):
            return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(data) != before.st_size or stamp(before) != stamp(after):
            raise Refused("unsafe_metadata")
        return bytes(data)
    finally:
        os.close(fd)


def command(arguments, *, limit=128 * 1024):
    # Neither arbitrary tools/arguments nor raw command output are published.
    # The limit applies while reading, rather than after an unbounded disk spool.
    if type(limit) is not int or not 1 <= limit <= 128 * 1024:
        raise CommandFailure("invocation_error")
    process = None
    try:
        try:
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL,
                                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
            deadline = time.monotonic() + 15
            data = bytearray()
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise CommandFailure("timeout")
                    if not ready.select(remaining):
                        raise CommandFailure("timeout")
                    block = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(data)))
                    if not block:
                        break
                    data.extend(block)
                    if len(data) > limit:
                        raise CommandFailure("output_too_large")
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            return process.returncode, bytes(data)
        except subprocess.TimeoutExpired:
            raise CommandFailure("timeout") from None
        except (OSError, ValueError):
            raise CommandFailure("invocation_error") from None
    finally:
        if process is not None:
            # Only our exact diagnostic child is signalled; never a service PID,
            # process group or descendant. launchctl side effects may be partial.
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
            if process.stdout is not None:
                process.stdout.close()


def validate_installation():
    for relative, checksum in PINS.items():
        if hashlib.sha256(public_bytes(BASE / relative)).hexdigest() != checksum:
            raise Refused("build_76_binding_changed")
    for executable in [BROKER, PYTHON]:
        if command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", str(executable)])[0] != 0:
            raise Refused("build_76_binding_changed")
    profile = json.loads(public_bytes(BASE / "owner.json", 4096))
    owner_uid = profile.get("owner_uid")
    if type(owner_uid) is not int or owner_uid <= 0 or profile.get("publisher_team") != "WBULD6N4NQ":
        raise Refused("build_76_binding_changed")
    try:
        owner_group = pwd.getpwuid(owner_uid).pw_gid
    except KeyError:
        raise Refused("build_76_binding_changed") from None
    expected = {
        "Label": "com.fainir.accountaccess.broker",
        "AssociatedBundleIdentifiers": ["com.fainir.accountaccess"],
        "ProgramArguments": [str(BROKER)], "UserName": "root", "GroupName": "wheel",
        "RunAtLoad": True, "KeepAlive": False, "AbandonProcessGroup": False,
        "ExitTimeOut": 20, "Umask": 0o077, "ProcessType": "Background",
        "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
        "MachServices": {"com.fainir.accountaccess.broker.owner": True},
        "Sockets": {
            "AccountAccessAgent": {"SockPathName": str(BASE / "run/agent.sock"),
                                   "SockPathOwner": 0, "SockPathGroup": owner_group, "SockPathMode": 0o660},
            "AccountAccessOwner": {"SockPathName": str(BASE / "control/owner.sock"),
                                   "SockPathOwner": 0, "SockPathGroup": 0, "SockPathMode": 0o600},
        },
    }
    if plistlib.loads(public_bytes(JOB, 16384)) != expected:
        raise Refused("installed_job_changed")


def require_failing_service():
    status, data = command(["/bin/launchctl", "print", SERVICE])
    if status != 0:
        raise Refused("installed_job_unavailable")
    text = data.decode("utf-8", "strict")
    if (not text.startswith(SERVICE + " = {")
            or not re.search(r"^\tprogram = " + re.escape(str(BROKER)) + r"$", text, re.M)):
        raise Refused("installed_job_changed")
    if re.search(r"^\tpid = [1-9][0-9]*$", text, re.M):
        raise Refused("service_is_running")
    if not re.search(r"^\tlast exit code = 78(?:: EX_CONFIG)?$", text, re.M):
        raise Refused("service_not_failing_with_78")


def wait_for_failing_service():
    # A crashing job may briefly have a PID while performing startup checks.
    # Observe its failure; never kill a process to manufacture the condition.
    deadline = time.monotonic() + 3
    while True:
        try:
            require_failing_service()
            return
        except Refused as error:
            if error.args != ("service_is_running",) or time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def closed_failure(data):
    if not data or len(data) > 4096:
        return None
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_field")
                result[key] = value
            return result

        value = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if (type(value) is dict and set(value) == {"status", "reason"}
            and value["status"] == "FAILED" and type(value["reason"]) is str
            and value["reason"] in FAILURE_REASONS):
        return value["reason"]
    return None


def capture(backend):
    """Only the production backend can perform launchctl or root-file actions."""
    reason = None
    status = "capture_unavailable"
    attempted = False
    restored = False
    stage = "preflight"
    failure_stage = None
    failure_outcome = None
    outcomes = dict.fromkeys(("redirect", "start", "reset"), "not_attempted")

    def operation(name, call):
        try:
            value = call()
        except CommandFailure as error:
            outcomes[name] = closed_outcome(error.outcome)
            raise
        except Exception:
            outcomes[name] = "invocation_error"
            raise
        if type(value) is not bool:
            outcomes[name] = "invalid_output"
            raise CommandFailure("invalid_output")
        outcomes[name] = "success" if value else "nonzero"
        return value

    try:
        backend.require_failing()
        stage = "redirect"
        attempted = True  # A failed debug command may still have taken effect.
        if not operation("redirect", backend.redirect):
            status = "capture_not_permitted"
            failure_stage, failure_outcome = stage, "nonzero"
        else:
            stage = "start"
            if not operation("start", backend.start_without_killing):
                status = "start_request_unavailable"
                failure_stage, failure_outcome = stage, "nonzero"
            else:
                stage = "capture_wait"
                reported = backend.wait_for_closed_failure()
                reason = reported if type(reported) is str and reported in FAILURE_REASONS else None
                status = "failure_captured" if reason else "no_closed_failure_reported"
                if reason is None:
                    failure_stage, failure_outcome = stage, "no_closed_failure"
    except Refused as error:
        # Do not render even an accidentally untrusted Refused argument.
        code = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
        status = code if code in STATUSES else "diagnostic_unavailable"
        failure_stage = stage
        failure_outcome = closed_outcome(error.outcome) if isinstance(error, CommandFailure) else "refused"
    except Exception:
        status = "diagnostic_unavailable"
        failure_stage, failure_outcome = stage, "unexpected_error"
    finally:
        if attempted:
            try:
                restored = operation("reset", backend.restore_default)
            except Exception:
                restored = False
            if not restored and failure_stage is None:
                failure_stage, failure_outcome = "reset", outcomes["reset"]
        safe_cleanup = not attempted or (reason is not None and restored)
        if safe_cleanup:
            try:
                backend.cleanup()
            except Exception:
                safe_cleanup = False
                if failure_stage is None:
                    failure_stage, failure_outcome = "cleanup", "unexpected_error"
    return {"status": status, "reason": reason, "cleanup_pending": not safe_cleanup,
            "default_stdout_requested": restored, "failure_capture_consumed": reason is not None,
            "failure_stage": failure_stage, "failure_outcome": failure_outcome,
            "command_outcomes": outcomes, "mode": "new_capture", "fresh_startup_verified": False}


def retained_capture_name(parent):
    """Inspect names only; do not create a second target beside retained output."""
    captures = []
    for name in os.listdir(parent):
        if re.fullmatch(r"capture-[0-9a-f]{32}", name):
            captures.append(name)
        elif not re.fullmatch(r"result-[0-9a-f]{32}\.json", name):
            raise Refused("unknown_report_entry")
    if len(captures) > 1:
        raise Refused("retained_capture_ambiguous")
    return captures[0] if captures else None


def inspect_retained_capture(parent, name):
    """Read only one existing exact-metadata target; never redirect, start or delete."""
    if type(name) is not str or not re.fullmatch(r"capture-[0-9a-f]{32}", name):
        raise Refused("retained_capture_metadata_unavailable")

    def metadata(fd, *, directory=False):
        info = check_fd(fd, directory=directory)
        if stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
            raise Refused("retained_capture_metadata_unavailable")
        return info

    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    folder = None
    output = None
    try:
        folder = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        folder_before = metadata(folder, directory=True)
        if os.listdir(folder) != ["stdout"]:
            raise Refused("retained_capture_metadata_unavailable")
        output = os.open("stdout", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=folder)
        before = metadata(output)
        if before.st_size > 4096:
            raise Refused("retained_capture_oversize")
        data = os.pread(output, 4097, 0)
        after = metadata(output)
        folder_after = metadata(folder, directory=True)
        if (len(data) != before.st_size or stamp(before) != stamp(after)
                or stamp(after) != stamp(os.stat("stdout", dir_fd=folder, follow_symlinks=False))
                or stamp(folder_before) != stamp(folder_after)
                or stamp(folder_after) != stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))):
            raise Refused("retained_capture_metadata_unavailable")
        reason = closed_failure(data)
        return {"status": "failure_captured" if reason else "no_closed_failure_reported", "reason": reason,
                "cleanup_pending": True, "default_stdout_requested": False,
                "failure_capture_consumed": reason is not None, "capture_is_historical": True,
                "fresh_startup_verified": False, "mode": "retained_capture_inspection",
                "failure_stage": None if reason else "retained_inspection",
                "failure_outcome": None if reason else "no_closed_failure",
                "command_outcomes": dict.fromkeys(("redirect", "start", "reset"), "not_attempted")}
    except OSError:
        raise Refused("retained_capture_metadata_unavailable") from None
    finally:
        if output is not None:
            os.close(output)
        if folder is not None:
            os.close(folder)


class InstalledCapture:
    def __init__(self, parent):
        self.parent = parent
        if retained_capture_name(parent) is not None:
            raise Refused("retained_capture_pending")
        self.name = "capture-" + secrets.token_hex(16)
        os.mkdir(self.name, 0o700, dir_fd=parent)
        self.directory = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        check_fd(self.directory, directory=True)
        self.fd = os.open("stdout", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.directory)
        self.original = check_fd(self.fd)

    def require_failing(self):
        wait_for_failing_service()

    def redirect(self):
        path = REPORTS / self.name / "stdout"
        return command(["/bin/launchctl", "debug", SERVICE, "--stdout", str(path)])[0] == 0

    def start_without_killing(self):
        # -p returns an existing PID if one won the race; -k is never allowed.
        status, value = command(["/bin/launchctl", "kickstart", "-p", SERVICE])
        if status != 0:
            return False
        if re.fullmatch(rb"[1-9][0-9]*\s*", value) is None:
            raise CommandFailure("invalid_output")
        return True

    def wait_for_closed_failure(self):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            current = check_fd(self.fd)
            if (current.st_dev, current.st_ino) != (self.original.st_dev, self.original.st_ino):
                raise Refused("unsafe_capture_metadata")
            if current.st_size > 4096:
                return None
            reason = closed_failure(os.pread(self.fd, 4097, 0))
            if reason is not None:
                return reason
            time.sleep(0.1)
        return None

    def restore_default(self):
        return command(["/bin/launchctl", "debug", SERVICE, "--stdout", "/dev/null"])[0] == 0

    def cleanup(self):
        info = os.stat("stdout", dir_fd=self.directory, follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (self.original.st_dev, self.original.st_ino):
            raise Refused("unsafe_capture_metadata")
        os.unlink("stdout", dir_fd=self.directory)
        os.rmdir(self.name, dir_fd=self.parent)

    def close(self):
        os.close(self.fd)
        os.close(self.directory)


def publish(parent, result):
    # Retain each public result separately; never overwrite a prior report.
    name = "result-" + secrets.token_hex(16) + ".json"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        data = json.dumps({"managed_by": MANAGED_BY, "schema": 1, "target_build": 76,
                           "target_code_sha256": PINS["bin/AccountAccess-broker"], **result}, sort_keys=True).encode() + b"\n"
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    return str(REPORTS / name)


def main():
    inspect_only = sys.argv[1:] == ["--inspect-retained"]
    if (sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0
            or (len(sys.argv) != 1 and not inspect_only)
            or sys.executable != str(PYTHON) or not sys.flags.isolated or not sys.flags.no_site):
        print('{"status":"REFUSED","reason":"trusted_installer_context_required"}')
        return 1
    os.umask(0o077)
    parent = None
    reports_valid = False
    stage = "preflight"
    mode = "retained_capture_inspection" if inspect_only else "new_capture"
    try:
        validate_installation()
        parent = directory(REPORTS, create=not inspect_only)
        if stat.S_IMODE(os.fstat(parent).st_mode) != 0o755:
            raise Refused("unsafe_metadata")
        reports_valid = True
        if inspect_only:
            stage = "retained_inspection"
        retained = retained_capture_name(parent)
        if retained is not None:
            stage = "retained_inspection"
            mode = "retained_capture_inspection"
            result = inspect_retained_capture(parent, retained)
        elif inspect_only:
            raise Refused("retained_capture_unavailable")
        else:
            backend = InstalledCapture(parent)
            try:
                result = capture(backend)
            finally:
                backend.close()
        report = publish(parent, result)
        succeeded = type(result.get("reason")) is str and result["reason"] in FAILURE_REASONS
        print(json.dumps({"status": "CHECK_COMPLETED", "public_report": report,
                          "diagnostic_succeeded": succeeded, "fresh_startup_verified": False}))
        return 0 if succeeded else 1
    except Refused as error:
        code = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
        reason = code if code in STATUSES else "startup_check_unavailable"
        outcome = closed_outcome(error.outcome) if isinstance(error, CommandFailure) else "refused"
        response = {"status": "REFUSED", "reason": reason, "failure_stage": stage,
                    "failure_outcome": outcome}
        if reports_valid:
            result = {"status": reason, "reason": None, "cleanup_pending": True,
                      "default_stdout_requested": False, "failure_capture_consumed": False,
                      "fresh_startup_verified": False, "mode": mode, "failure_stage": stage,
                      "failure_outcome": outcome,
                      "command_outcomes": dict.fromkeys(("redirect", "start", "reset"), "not_attempted")}
            try:
                response["public_report"] = publish(parent, result)
            except Exception:
                pass
        print(json.dumps(response))
        return 1
    except Exception:
        # Never render a framework, OS, path, raw tool or unexpected error.
        print(json.dumps({"status": "REFUSED", "reason": "startup_check_unavailable",
                          "failure_stage": stage, "failure_outcome": "unexpected_error"}))
        return 1
    finally:
        if parent is not None:
            os.close(parent)


if __name__ == "__main__":
    raise SystemExit(main())
