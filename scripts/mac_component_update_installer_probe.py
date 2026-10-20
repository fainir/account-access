"""Actual signed-native component candidate acceptance in a fresh hosted Mac VM.

This is not an owner-Mac command. It installs the retained public build76 image,
observes its fresh GUI closed, applies the exact reviewed candidate through native
Installer, and checks public files/policies and same-package reapplication. It
does not enroll a store, connect accounts, inspect a vault or inject a crash.
The VM is discarded after the job; only its created job is stopped here.
"""

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import grp
import re
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

BASE_SOURCE = "fbd2a733b60acde68e82fe796cb7abd971d5d625"
BASE_PACKAGE_SHA256 = "e525233e74ee942a53c389babac57eee6cad25b79ea178ff9a6384b0a5c5567c"
BASE_MANIFEST_SHA256 = "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8"
BASE = Path("/Library/Application Support/Account Access")
COMPONENTS = Path("/Library/Application Support/Account Access Components")
JOURNAL = Path("/Library/Application Support/Account Access Installer")
APP = Path("/Applications/Account Access.app")
JOB = Path("/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist")
LABEL = "com.fainir.accountaccess.broker"
TEAM = "WBULD6N4NQ"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
GIT_ENV = {**ENV, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}
MAX_SOURCE = 2 * 1024 * 1024
MAX_INSTALLER_LOG = 512 * 1024 * 1024
MAX_INSTALLER_DELTA = 128 * 1024
PRIVATE = {"broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"}
UNCHANGED_POLICIES = ("worker.json", "stage.json", "worker-launch.json", "stage-launch.json", "enrollment.json", "service.plist")
CHECKS = frozenset({"fresh_hosted_vm", "reviewed_public_inputs", "candidate_expansion_matches_review",
                    "genuine_signed_helper", "actual_base_installer", "base_public_image", "fresh_gui_closed",
                    "actual_candidate_installer", "target_public_image", "only_three_policy_values_changed",
                    "unchanged_worker_plans_and_original_journal", "verified_head", "same_package_reapplication",
                    "reapplication_preserved_bytes_and_ids", "created_job_stopped"})
REVALIDATION_NAMESPACE = Path("/Library/Application Support/Account Access Installation Binding")
REVALIDATION_RECEIPT = REVALIDATION_NAMESPACE / "revalidated-v1.json"
REVALIDATION_CHECKS = frozenset({"reviewed_revalidation_input", "genuine_signed_revalidation_helper",
    "exact_legacy_revalidation_no_receipt", "synthetic_device_mismatch_same_inodes",
    "actual_revalidation_installer", "protected_supplement_created", "revalidation_reapplication",
    "original_receipts_unchanged", "supplement_preserved_by_component", "bounded_pending_receipt_recovered",
    "revalidation_after_component"})


def require(value):
    if not value:
        raise ValueError("component_installer_acceptance_failed")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hex_value(value, size):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{" + str(size) + "}", value) is not None


def guard():
    require(sys.platform == "darwin" and platform.machine() == "arm64" and os.getuid() == os.geteuid() == 0
            and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("CI") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "macOS"
            and os.environ.get("RUNNER_ARCH") == "ARM64" and os.environ.get("GITHUB_REPOSITORY") == "fainir/account-access"
            and re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ID", "")) is not None
            and re.fullmatch(r"[1-9][0-9]{0,9}", os.environ.get("GITHUB_RUN_ATTEMPT", "")) is not None
            and hex_value(os.environ.get("GITHUB_SHA"), 40))


def report_path(run_id):
    require(isinstance(run_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None)
    return Path("/Library/Logs/AccountAccessComponentInstallerQA-" + run_id + "/report.json")


def protected_metadata(info, *, mode=None, directory=True):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == 0 and not info.st_mode & 0o7022
            and (directory or info.st_nlink == 1)
            and (mode is None or stat.S_IMODE(info.st_mode) == mode))


def deny_only_acl(descriptor):
    """A deny ACL cannot add write access omitted by the protected mode."""
    library = ctypes.CDLL(None, use_errno=True)
    library.acl_get_fd.argtypes, library.acl_get_fd.restype = [ctypes.c_int], ctypes.c_void_p
    library.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    library.acl_get_tag_type.restype = ctypes.c_int
    library.acl_free.argtypes = [ctypes.c_void_p]
    ctypes.set_errno(0)
    acl = library.acl_get_fd(descriptor)
    if not acl:
        require(ctypes.get_errno() == errno.ENOENT)
        return
    try:
        for position in [0] + [1] * 169:
            entry, tag = ctypes.c_void_p(), ctypes.c_int()
            ctypes.set_errno(0)
            result = library.acl_get_entry(acl, position, ctypes.byref(entry))
            if result == -1:
                require(ctypes.get_errno() == errno.EINVAL)
                return
            require(result == 0 and entry.value and library.acl_get_tag_type(entry, ctypes.byref(tag)) == 0
                    and tag.value == 2)  # ACL_EXTENDED_DENY only.
        require(False)
    finally:
        library.acl_free(acl)


class RootOutput:
    """Exclusive descriptor-anchored evidence publication below fixed root Logs."""

    def __init__(self, path, run_id):
        require(path == report_path(run_id))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open("/", flags)
        self.parent = self.descriptor = None
        try:
            protected_metadata(os.fstat(parent))
            deny_only_acl(parent)
            for name in ("Library", "Logs"):
                child = os.open(name, flags, dir_fd=parent)
                try:
                    protected_metadata(os.fstat(child))
                    deny_only_acl(child)
                    require(stamp(os.fstat(child)) == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)))
                except Exception:
                    os.close(child)
                    raise
                os.close(parent)
                parent = child
            self.name = path.parent.name
            os.mkdir(self.name, mode=0o700, dir_fd=parent)  # Never adopt an existing directory.
            self.descriptor = os.open(self.name, flags, dir_fd=parent)
            protected_metadata(os.fstat(self.descriptor), mode=0o700)
            deny_only_acl(self.descriptor)
            require(stamp(os.fstat(self.descriptor)) == stamp(os.stat(self.name, dir_fd=parent, follow_symlinks=False)))
            os.fsync(parent)
            self.parent = parent
            parent = None
        except Exception:
            self.close()
            raise
        finally:
            if parent is not None:
                os.close(parent)

    def write(self, name, raw):
        require(name == "report.json" or re.fullmatch(r"[a-z][a-z0-9-]{0,70}\.log", name) is not None)
        require(isinstance(raw, bytes) and len(raw) <= 256 * 1024)
        protected_metadata(os.fstat(self.descriptor), mode=0o700)
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.descriptor)
        try:
            protected_metadata(os.fstat(descriptor), mode=0o600, directory=False)
            with os.fdopen(os.dup(descriptor), "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
            require(stamp(os.fstat(descriptor)) == stamp(os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)))
            os.fsync(self.descriptor)
        finally:
            os.close(descriptor)

    def publish(self):
        current = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
        require(stamp(current) == stamp(os.fstat(self.descriptor)))
        protected_metadata(current, mode=0o700)
        os.fchmod(self.descriptor, 0o755)
        os.fsync(self.descriptor)
        os.fsync(self.parent)

    def close(self):
        for name in ("descriptor", "parent"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_file(path, *, maximum=16 * 1024 * 1024, owner=0):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1
                and not before.st_mode & 0o7022 and 0 <= before.st_size <= maximum)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(descriptor))
                and stamp(before) == stamp(path.lstat()))
        return raw
    finally:
        os.close(descriptor)


def stage_file(source, destination, expected, maximum):
    require(re.fullmatch(r"[a-f0-9]{64}", expected) is not None)
    incoming = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(incoming)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
        outgoing = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        digest = hashlib.sha256()
        with os.fdopen(outgoing, "wb") as output, os.fdopen(os.dup(incoming), "rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        require(stamp(before) == stamp(os.fstat(incoming)) and digest.hexdigest() == expected)
    finally:
        os.close(incoming)


def validate_review(value, source, candidate_hash, *, revalidation=False):
    require(hex_value(source, 40) and hex_value(candidate_hash, 64))
    require(isinstance(value, dict) and set(value) == {"schema", "managed_by", "component_source_commit", "base_source_commit",
            "package_sha256", "package_bytes", "plan_sha256", "scripts", "source_files"}
            and type(value["schema"]) is int and value["schema"] == 1
            and value["managed_by"] == ("account-access-root-revalidation-public-review-v1" if revalidation
                                        else "account-access-component-public-review-v1")
            and value["component_source_commit"] == source and value["base_source_commit"] == BASE_SOURCE
            and value["package_sha256"] == candidate_hash and type(value["package_bytes"]) is int
            and 0 < value["package_bytes"] <= 32 * 1024 * 1024
            and hex_value(value["plan_sha256"], 64)
            and isinstance(value["scripts"], dict) and len(value["scripts"]) == 15
            and isinstance(value["source_files"], dict) and 8 <= len(value["source_files"]) <= 100)
    required = {"macos/ComponentUpdate.swift", "macos/ComponentUpdatePolicies.swift", "macos/ComponentUpdateIdentity.swift",
                "macos/InstallerPayload.swift", "macos/build-component-update.py",
                "macos/InstallationRootBinding.swift", "macos/InstallationRootRevalidation.swift"}
    require(required <= set(value["source_files"]))
    for name, digest in value["source_files"].items():
        require(isinstance(name, str) and len(name) <= 512
                and re.fullmatch(r"(?:macos|scripts|account_access|\.github/workflows)/[A-Za-z0-9_./-]+", name) is not None
                and all(part not in {"", ".", ".."} for part in name.split("/"))
                and hex_value(digest, 64))
    for name, item in value["scripts"].items():
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,90}", name) is not None
                and isinstance(item, dict) and set(item) == {"sha256", "mode", "bytes"}
                and type(item["mode"]) is int and item["mode"] in {0o644, 0o755}
                and type(item["bytes"]) is int and 0 < item["bytes"] <= 16 * 1024 * 1024
                and hex_value(item["sha256"], 64))
    return value


def git_bytes(repository, arguments, *, maximum):
    # No inherited environment/config, replacement objects, hooks, fsmonitor,
    # pager, external diff or text conversion participates in source evidence.
    result = subprocess.run(["/usr/bin/git", "--no-pager", "--no-replace-objects", "--no-optional-locks",
        "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "safe.directory=" + str(repository),
        "-C", str(repository), *arguments], stdin=subprocess.DEVNULL, capture_output=True,
        timeout=10, env=GIT_ENV, check=False)
    require(result.returncode == 0 and len(result.stdout) <= maximum and len(result.stderr) <= 4096)
    return result.stdout


def bind_sources(review, repository, source):
    require(repository.is_absolute() and all(part not in {".", ".."} for part in repository.parts)
            and "\0" not in str(repository) and hex_value(source, 40))
    require(git_bytes(repository, ["rev-parse", "--show-object-format"], maximum=16) == b"sha1\n")
    require(git_bytes(repository, ["cat-file", "-t", source], maximum=16) == b"commit\n")
    for name, expected in review["source_files"].items():
        row = git_bytes(repository, ["ls-tree", "--full-tree", "-z", source, "--", name], maximum=1024)
        pattern = rb"100(?:644|755) blob ([a-f0-9]{40})\t" + re.escape(name.encode()) + rb"\x00"
        match = re.fullmatch(pattern, row)
        require(match is not None)
        size = git_bytes(repository, ["cat-file", "-s", match[1].decode()], maximum=16)
        require(re.fullmatch(rb"[0-9]{1,8}\n", size) is not None and 0 < int(size) <= MAX_SOURCE)
        raw = git_bytes(repository, ["show", "--no-ext-diff", "--no-textconv", source + ":" + name], maximum=MAX_SOURCE)
        require(len(raw) == int(size) and sha(raw) == expected)


def command(arguments, *, report, output, log, timeout=30, check=True):
    def record(returncode, stdout, stderr, *, timed_out=False, invocation_failed=False):
        limited = len(stdout) + len(stderr) > 128 * 1024

        def ends(value):
            if len(value) <= 16384:
                return value.decode("utf-8", errors="replace"), ""
            return (value[:8192].decode("utf-8", errors="replace"),
                    value[-8192:].decode("utf-8", errors="replace"))

        stdout_head, stdout_tail = ends(stdout)
        stderr_head, stderr_tail = ends(stderr)
        raw = json.dumps({"returncode": returncode, "timed_out": timed_out, "invocation_failed": invocation_failed,
            "output_limited": limited, "capture_format": "full_or_8k_head_tail_v1",
            "stdout": stdout_head, "stdout_tail": stdout_tail, "stderr": stderr_head, "stderr_tail": stderr_tail,
            "stdout_truncated": len(stdout) > 16384, "stderr_truncated": len(stderr) > 16384,
            "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
            "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}, sort_keys=True).encode() + b"\n"
        output.write(log, raw)
        report["logs"][log] = sha(raw)
        return limited

    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=timeout, env=ENV, check=False)
    except subprocess.TimeoutExpired as error:
        record(None, error.stdout or b"", error.stderr or b"", timed_out=True)
        report["command_failure"] = {"kind": "timeout", "log": log}
        raise
    except OSError:
        record(None, b"", b"", invocation_failed=True)
        report["command_failure"] = {"kind": "invocation_failed", "log": log}
        raise
    if record(result.returncode, result.stdout, result.stderr):
        report["command_failure"] = {"kind": "output_limit", "log": log}
        require(False)
    if check:
        require(result.returncode == 0)
    return result


class InstallerLogDelta:
    """Observe only the fixed daemon log's new bytes in this disposable CI VM."""

    def __init__(self):
        self.descriptor = self.parent = None
        self.reason = "checkpoint_unavailable"
        parent = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            parent = os.open("/", flags)
            for name in ("private", "var", "log"):
                protected_metadata(os.fstat(parent))
                deny_only_acl(parent)
                child = os.open(name, flags, dir_fd=parent)
                os.close(parent)
                parent = child
            protected_metadata(os.fstat(parent))
            deny_only_acl(parent)
            self.descriptor = os.open("install.log", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                      dir_fd=parent)
            before = os.fstat(self.descriptor)
            self.validate(before)
            self.identity = self.fixed_identity(before)
            require(self.fixed_identity(os.stat("install.log", dir_fd=parent, follow_symlinks=False)) == self.identity)
            self.offset = before.st_size  # No existing log content is read.
            self.parent, parent = parent, None
            self.reason = None
        except Exception:
            self.close()
        finally:
            if parent is not None:
                os.close(parent)

    @staticmethod
    def fixed_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)

    @staticmethod
    def validate(info):
        protected_metadata(info, directory=False)
        require(0 <= info.st_size <= MAX_INSTALLER_LOG)

    def capture(self, *, report, output, log):
        evidence = {"status": "unavailable", "reason": self.reason or "capture_unavailable",
                    "existing_bytes_read": 0}
        report.setdefault("installer_daemon_logs", {})[log] = evidence
        try:
            if self.reason is not None:
                return
            current = os.fstat(self.descriptor)
            self.validate(current)
            require(self.fixed_identity(current) == self.identity
                    and self.fixed_identity(os.stat("install.log", dir_fd=self.parent,
                                                   follow_symlinks=False)) == self.identity)
            if current.st_size < self.offset:
                evidence["reason"] = "log_truncated"
                return
            length = current.st_size - self.offset
            if length > MAX_INSTALLER_DELTA:
                evidence["reason"] = "append_limit_exceeded"
                return
            raw = os.pread(self.descriptor, length, self.offset)
            after = os.fstat(self.descriptor)
            self.validate(after)
            require(len(raw) == length and self.fixed_identity(after) == self.identity
                    and after.st_size >= current.st_size
                    and self.fixed_identity(os.stat("install.log", dir_fd=self.parent,
                                                   follow_symlinks=False)) == self.identity)
            output.write(log, raw)
            report["logs"][log] = sha(raw)
            evidence.update(status="captured", reason=None, start_offset=self.offset,
                            end_offset=current.st_size, observed_end_offset=after.st_size,
                            bytes=len(raw), sha256=sha(raw))
        except Exception:
            pass  # Diagnostic failure must not replace the actual Installer outcome.
        finally:
            self.close()

    def close(self):
        for name in ("descriptor", "parent"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, None)


def candidate_install(package, *, report, output, log, daemon_log):
    checkpoint = InstallerLogDelta()
    try:
        # Bounded domain teardown/restoration plus a failed-attempt rollback
        # can outlast three minutes. Do not start fresh-VM cleanup prematurely.
        return command(["/usr/sbin/installer", "-dumplog", "-verboseR", "-pkg", str(package), "-target", "/"],
                       report=report, output=output, log=log, timeout=420)
    finally:
        checkpoint.capture(report=report, output=output, log=daemon_log)


class ProcessBSDInfo(ctypes.Structure):
    # Fixed Darwin proc_bsdinfo from sys/proc_info.h; no argv/environment fields.
    _fields_ = [("pbi_" + name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved")]
    _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "jobc", "tdev", "tpgid")]
    _fields_ += [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]


class ProcessDiagnosticReader:
    """Fixed libproc metadata only; aggregate output never includes identities."""

    classes = {"/usr/sbin/cfprefsd": "cfprefsd", "/usr/sbin/securityd": "securityd",
               "/usr/libexec/trustd": "trustd", "/sbin/launchd": "launchd",
               str(BASE / "bin/AccountAccess-broker"): "broker",
               str(BASE / "bin/AccountAccess-bootstrap"): "bootstrap"}

    def __init__(self):
        require(ctypes.sizeof(ProcessBSDInfo) == 136)
        self.library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.library.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self.library.proc_listpidspath.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p,
                                                  ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self.library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        self.library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        for name in ("proc_listpids", "proc_listpidspath", "proc_pidinfo", "proc_pidpath"):
            getattr(self.library, name).restype = ctypes.c_int

    def listed(self, kind, info, *, path=None):
        buffer = (ctypes.c_int32 * 4096)()
        ctypes.set_errno(0)
        if path is None:
            count = self.library.proc_listpids(kind, info, buffer, ctypes.sizeof(buffer))
        else:
            count = self.library.proc_listpidspath(kind, info, os.fsencode(path), 0, buffer, ctypes.sizeof(buffer))
        error = ctypes.get_errno()
        value = {"status": "measured", "returned_bytes": count, "errno": error}
        if count < 0 or count >= ctypes.sizeof(buffer) or count % ctypes.sizeof(ctypes.c_int32):
            value["status"] = "api_failure" if count < 0 else "invalid_result"
            return value, []
        # proc_listpids maps syscall failure to zero with errno set. Successful
        # proc_listpidspath may leave EINVAL from its internal region search.
        if path is None and count == 0 and error:
            value["status"] = "api_failure"
            return value, []
        pids = [pid for pid in buffer[:count // 4] if pid > 1]
        value.update(count=len(pids), unique_count=len(set(pids)))
        return value, sorted(set(pids))

    def executable(self, pid, *, expected_uid=None):
        before, after = ProcessBSDInfo(), ProcessBSDInfo()
        size = ctypes.sizeof(before)
        ctypes.set_errno(0)
        if self.library.proc_pidinfo(pid, 3, 0, ctypes.byref(before), size) != size:
            return "unavailable", ctypes.get_errno(), None
        buffer = ctypes.create_string_buffer(4096)
        ctypes.set_errno(0)
        count = self.library.proc_pidpath(pid, buffer, ctypes.sizeof(buffer))
        if count <= 0 or count >= ctypes.sizeof(buffer) or b"\0" not in buffer.raw[:count + 1]:
            return "unavailable", ctypes.get_errno(), None
        ctypes.set_errno(0)
        if self.library.proc_pidinfo(pid, 3, 0, ctypes.byref(after), size) != size:
            return "unavailable", ctypes.get_errno(), None
        if (before.pbi_pid != pid or after.pbi_pid != pid or before.pbi_uid != after.pbi_uid
                or before.start_sec != after.start_sec or before.start_usec != after.start_usec
                or expected_uid is not None and before.pbi_uid != expected_uid):
            return "changed", 0, None
        try:
            return "measured", 0, buffer.value.decode("utf-8", errors="strict")
        except UnicodeError:
            return "unavailable", 0, None

    def observed(self, kind, info, *, path=None, expected_uid=None, include_unknown_names=False):
        require(not include_unknown_names or kind == 4 and expected_uid == info and 450 <= info < 500)
        value, pids = self.listed(kind, info, path=path)
        if value["status"] != "measured":
            return value
        if len(pids) > 256:
            value["classification_status"] = "limit_exceeded"
            return value
        value.update(classification_status="measured", classes=dict.fromkeys((*self.classes.values(), "unknown"), 0),
                     unavailable_count=0, changed_count=0, execution_matches=0, other_references=0, error_counts={})
        names = {}
        for pid in pids:
            status, error, executable = self.executable(pid, expected_uid=expected_uid)
            if status != "measured":
                value["changed_count" if status == "changed" else "unavailable_count"] += 1
                key = str(error) if 0 <= error <= 255 else "other"
                value["error_counts"][key] = value["error_counts"].get(key, 0) + 1
                continue
            value["classes"][self.classes.get(executable, "unknown")] += 1
            if (include_unknown_names and executable not in self.classes and executable.startswith("/")
                    and len(executable.encode()) <= 512 and not re.search(r"[\x00-\x1f\x7f]", executable)
                    and (executable in names or len(names) < 8)):
                names[executable] = names.get(executable, 0) + 1
            if path is not None:
                value["execution_matches" if executable == path else "other_references"] += 1
        if include_unknown_names:
            value["unknown_executables"] = [{"path": name, "basename": Path(name).name[:128], "count": count}
                                             for name, count in sorted(names.items())]
        return value


def missing_user_domain_diagnostic():
    # -2 is Darwin's nobody identity. Check this different fixed UID really has
    # no directory-service record before asking about its launchd domain.
    try:
        try:
            pwd.getpwuid(4294967293)
        except KeyError:
            pass
        else:
            return {"status": "identity_present"}
        result = subprocess.run(["/bin/launchctl", "print", "user/4294967293"], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=5, env=ENV, check=False)
        value = {"status": "measured", "returncode": result.returncode,
                 "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr),
                 "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)}
        if result.returncode == 0 or result.stdout:
            value["status"] = "unexpected_present"  # Never retain a domain process dump.
        elif len(result.stderr) > 512:
            value["status"] = "output_limit"
        else:
            value["stderr"] = result.stderr.decode("utf-8", errors="replace")
        return value
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except OSError:
        return {"status": "invocation_failed"}


def quiescence_diagnostics(report, install, plan_sha):
    value = {"status": "unavailable", "diagnostic_only": True, "affects_acceptance": False}
    report["quiescence_diagnostics"] = value
    try:
        guard()  # Never load libproc/read snapshots on an owner Mac or ordinary caller.
        require(all(report["checks"].get(name) is True for name in (
            "fresh_hosted_vm", "reviewed_public_inputs", "candidate_expansion_matches_review",
            "genuine_signed_helper", "actual_base_installer", "base_public_image")))
        require(type(install) is dict and install.get("managed_by") == "account-access-system-install-v1"
                and type(install.get("schema")) is int and install["schema"] == 1
                and install.get("broker_name") == "_accountaccess"
                and type(install.get("broker_uid")) is int and 450 <= install["broker_uid"] < 500
                and hex_value(plan_sha, 64))
        uid = install["broker_uid"]
        reader = ProcessDiagnosticReader()
        value["broker_identity_processes"] = reader.observed(4, uid, expected_uid=uid)
        value["fixed_executable_references"] = {name: reader.observed(1, 0, path=str(BASE / ("bin/AccountAccess-" + name)))
                                                for name in ("broker", "bootstrap")}
        value["saved_group"] = {"status": "not_collected"}
        value["missing_user_domain"] = missing_user_domain_diagnostic()
        value["status"] = "observed"
    except Exception:
        pass  # Never replace the Installer exception or affect acceptance.


def canary_service_identity(uid):
    guard()
    require(type(uid) is int and 450 <= uid < 500)
    user, group = pwd.getpwnam("_accountaccess"), grp.getgrnam("_accountaccess")
    require(user.pw_name == group.gr_name == "_accountaccess" and user.pw_uid == user.pw_gid == group.gr_gid == uid
            and user.pw_dir == str(BASE / "home") and user.pw_shell == "/usr/bin/false")


def canary_domain_command(action, uid):
    canary_service_identity(uid)  # Recheck immediately before every fixed-domain command.
    require(action in {"bootout", "bootstrap", "print"})
    try:
        result = subprocess.run(["/bin/launchctl", action, "user/" + str(uid)], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=15, env=ENV, check=False)
        value = {"status": "measured", "returncode": result.returncode,
                 "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr),
                 "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)}
        if len(result.stdout) + len(result.stderr) > 128 * 1024:
            value["status"] = "output_limit"
        if action == "print":
            first = result.stdout.split(b"\n", 1)[0]
            expected = ("user/" + str(uid) + " = {").encode()
            value["header"] = first.decode() if first == expected else None
            value["line_count"] = result.stdout.count(b"\n")
            # No process dictionary, service label or PID is retained.
            if result.returncode != 0 and not result.stdout and len(result.stderr) <= 512:
                value["stderr"] = result.stderr.decode("utf-8", errors="replace")
        elif len(result.stderr) <= 512:
            value["stderr"] = result.stderr.decode("utf-8", errors="replace")
        return value
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except OSError:
        return {"status": "invocation_failed"}


def canary_wait_uid_empty(reader, uid):
    deadline, attempts = time.monotonic() + 20, 0
    while True:
        attempts += 1
        value = reader.listed(4, uid)[0]
        if value["status"] != "measured" or value["errno"] != 0:
            return {"status": "api_failure", "attempts": attempts, "last": value}
        if value["count"] == 0:
            return {"status": "empty", "attempts": attempts, "last": value}
        if time.monotonic() >= deadline or attempts >= 81:
            return {"status": "not_empty", "attempts": attempts, "last": value}
        time.sleep(0.25)


def test_vm_domain_canary(report, install, plan_sha):
    """Explicitly authorized TEST-VM lifecycle experiment, after job cleanup."""
    value = {"status": "refused", "test_vm_only": True, "affects_acceptance": False,
             "domain_mutations_attempted": False, "steps": {}, "final_cleanup": {"status": "not_started"}}
    report["test_vm_domain_canary"] = value
    touched = False
    reader = uid = None
    try:
        guard()
        require("failure_reason" in report and "command_failure" not in report
                and report["checks"].get("actual_candidate_installer") is False
                and all(report["checks"].get(name) is True for name in (
                    "fresh_hosted_vm", "reviewed_public_inputs", "candidate_expansion_matches_review",
                    "genuine_signed_helper", "actual_base_installer", "base_public_image", "created_job_stopped")))
        require(type(install) is dict and install.get("managed_by") == "account-access-system-install-v1"
                and type(install.get("schema")) is int and install["schema"] == 1
                and install.get("broker_name") == "_accountaccess" and hex_value(plan_sha, 64)
                and type(install.get("broker_uid")) is int and 450 <= install["broker_uid"] < 500
                and type(install.get("owner_uid")) is int and install["owner_uid"] > 0
                and install["owner_uid"] != install["broker_uid"])
        uid = install["broker_uid"]
        canary_service_identity(uid)
        reader = ProcessDiagnosticReader()
        steps = value["steps"]
        steps["initial_processes"] = reader.observed(4, uid, expected_uid=uid, include_unknown_names=True)
        require(steps["initial_processes"]["status"] == "measured")
        touched = value["domain_mutations_attempted"] = True
        for name in ("first_bootout", "repeat_bootout"):
            steps[name] = canary_domain_command("bootout", uid)
            require(steps[name]["status"] == "measured")
            steps[name + "_processes"] = canary_wait_uid_empty(reader, uid)
            require(steps[name + "_processes"]["status"] == "empty")
        steps["bootstrap"] = canary_domain_command("bootstrap", uid)
        require(steps["bootstrap"]["status"] == "measured" and steps["bootstrap"]["returncode"] == 0)
        time.sleep(1)
        steps["bootstrapped_processes"] = reader.observed(4, uid, expected_uid=uid, include_unknown_names=True)
        steps["post_bootstrap_bootout"] = canary_domain_command("bootout", uid)
        require(steps["post_bootstrap_bootout"]["status"] == "measured")
        steps["post_bootstrap_bootout_processes"] = canary_wait_uid_empty(reader, uid)
        require(steps["post_bootstrap_bootout_processes"]["status"] == "empty")
        steps["print_after_bootout"] = canary_domain_command("print", uid)
        require(steps["print_after_bootout"]["status"] == "measured")
        time.sleep(1)
        steps["after_print_processes"] = reader.observed(4, uid, expected_uid=uid, include_unknown_names=True)
        value["status"] = "observed"
    except Exception:
        if touched:
            value["status"] = "incomplete"
    finally:
        if touched:
            try:
                result = canary_domain_command("bootout", uid)
                empty = canary_wait_uid_empty(reader, uid)
                value["final_cleanup"] = {"command": result, "processes": empty,
                    "status": "uid_empty" if result["status"] == "measured" and empty["status"] == "empty" else "unverified"}
            except Exception:
                value["final_cleanup"] = {"status": "unverified"}
        # No print follows final bootout; observing a domain may recreate it.


def fresh_gui_present(result):
    """pgrep is observational; no application name is resolved or launched."""
    require(type(result.returncode) is int and isinstance(result.stdout, bytes) and result.stderr == b"")
    if result.returncode == 1:
        require(result.stdout == b"")
        return False
    require(result.returncode == 0 and re.fullmatch(rb"(?:[1-9][0-9]{0,9}\n){1,8}", result.stdout) is not None)
    pids = [int(value) for value in result.stdout.splitlines()]
    require(len(pids) == len(set(pids)) and all(1 < value <= 2147483647 for value in pids))
    return True


def close_fresh_gui(console, *, report, output):
    require(type(console) is int and 0 < console <= 2147483647)
    report.update(gui_startup_grace_seconds=0, gui_startup_grace_is_readiness_proof=False,
                  normal_quit_requested=False, normal_quit_command_succeeded=False)

    def present(log, timeout=3):
        return fresh_gui_present(command(["/usr/bin/pgrep", "-u", str(console), "-x", "AccountAccess"],
            report=report, output=output, log=log, timeout=timeout, check=False))

    report["failure_stage"] = "fresh_gui_initial_presence"
    if not present("fresh-gui-initial-presence.log"):
        report["gui_close_outcome"] = "absent_when_checked"
        return
    # The retained GUI can spend two sequential 40s bounds preparing/requesting
    # its owner channel. Its busy termination delegate otherwise opens a modal.
    # This grace is a test precondition allowance, never GUI/account readiness.
    report["failure_stage"] = "fresh_gui_startup_grace"
    report["gui_startup_grace_seconds"] = 90
    time.sleep(90)
    report["failure_stage"] = "fresh_gui_settled_presence"
    if not present("fresh-gui-settled-presence.log"):
        report["gui_close_outcome"] = "absent_after_startup_grace"
        return
    report["failure_stage"] = "fresh_gui_normal_quit"
    report["normal_quit_requested"] = True
    command(["/bin/launchctl", "asuser", str(console), "/usr/bin/sudo", "-n", "-H", "-u", "#" + str(console), "--",
             "/usr/bin/osascript", "-e", 'tell application id "com.fainir.accountaccess" to quit'],
            report=report, output=output, log="fresh-gui-normal-quit.log", timeout=30)
    report["normal_quit_command_succeeded"] = True
    report["failure_stage"] = "fresh_gui_absence_after_quit"
    deadline = time.monotonic() + 10
    for index in range(20):
        remaining = deadline - time.monotonic()
        require(remaining > 0)
        if not present(f"fresh-gui-closed-{index:02d}.log", timeout=min(3, remaining)):
            report["gui_close_outcome"] = "normal_quit_and_absence_observed"
            return
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    require(False)


def archive_metadata(info):
    kind = ("file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode)
            else "symlink" if stat.S_ISLNK(info.st_mode) else "other")
    return {"type": kind, "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode), "bytes": info.st_size}


class ArchiveExpansion:
    """Read public archive bytes inside a root-private, descriptor-pinned stage.

    pkgutil can preserve the build user's archive UID. That UID is metadata,
    never installed ownership or permission to execute a resource. Installed
    files and Installer's executable-resource checks keep their root contract.
    """

    def __init__(self, staging_anchor, expanded, diagnostics, *, kind="component"):
        require(type(kind) is str and kind in {"component", "root-revalidation"})
        self.expansion_name = "root-expanded" if kind == "root-revalidation" else "expanded"
        require(expanded == staging_anchor / self.expansion_name)
        self.descriptors = []
        self.diagnostics = diagnostics
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            diagnostics["failure_stage"] = "candidate_stage_anchor"
            anchor = os.open(staging_anchor, flags)
            self.descriptors.append(anchor)
            protected_metadata(os.fstat(anchor), mode=0o700)
            deny_only_acl(anchor)
            require(stamp(os.fstat(anchor)) == stamp(staging_anchor.lstat()))
            self.anchor_path = staging_anchor
            self.anchor_before = os.fstat(anchor)
            self.directories = {}
            diagnostics["expanded_public_metadata"] = {
                "directories": {"stage": archive_metadata(self.anchor_before)}, "entries": {}, "entry_counts": {},
            }
            for name, parent in (("expanded", anchor), ("Scripts", None)):
                diagnostics["failure_stage"] = "candidate_" + name.lower() + "_directory"
                parent = parent if parent is not None else self.directories["expanded"][0]
                child = self.expansion_name if name == "expanded" else name
                linked = os.stat(child, dir_fd=parent, follow_symlinks=False)
                diagnostics["expanded_public_metadata"]["directories"][name] = archive_metadata(linked)
                descriptor = os.open(child, flags, dir_fd=parent)
                self.descriptors.append(descriptor)
                info = os.fstat(descriptor)
                require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o7022)
                deny_only_acl(descriptor)
                require(stamp(info) == stamp(linked) == stamp(os.stat(child, dir_fd=parent, follow_symlinks=False)))
                self.directories[name] = (descriptor, info, parent)
            diagnostics["failure_stage"] = "candidate_expanded_metadata"
            self.names = {}
            for name, (descriptor, _, _) in self.directories.items():
                names = sorted(os.listdir(descriptor))
                diagnostics["expanded_public_metadata"]["entries"][name] = []
                diagnostics["expanded_public_metadata"]["entry_counts"][name] = len(names)
                require(len(names) <= 64)
                for child in names:
                    require(re.fullmatch(r"[A-Za-z0-9._-]{1,128}", child) is not None and child not in {".", ".."})
                    value = archive_metadata(os.stat(child, dir_fd=descriptor, follow_symlinks=False))
                    diagnostics["expanded_public_metadata"]["entries"][name].append({"name": child, **value})
                self.names[name] = set(names)
            self.stable()
        except Exception:
            self.close()
            raise

    def stable(self):
        require(stamp(self.anchor_before) == stamp(os.fstat(self.descriptors[0]))
                and stamp(self.anchor_before) == stamp(self.anchor_path.lstat()))
        for name, (descriptor, before, parent) in self.directories.items():
            child = self.expansion_name if name == "expanded" else name
            require(stamp(before) == stamp(os.fstat(descriptor))
                    and stamp(before) == stamp(os.stat(child, dir_fd=parent, follow_symlinks=False)))

    def read(self, directory, name, *, maximum=16 * 1024 * 1024):
        require(name in self.names[directory])
        self.stable()
        parent = self.directories[directory][0]
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and not before.st_mode & 0o7022 and 0 <= before.st_size <= maximum)
            # Capture the archive UID rather than asserting active root
            # ownership. The enclosing root0700 stage prevents build-user access.
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                raw = stream.read(maximum + 1)
            require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(descriptor))
                    and stamp(before) == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)))
            self.stable()
            return raw, before
        finally:
            os.close(descriptor)

    def close(self):
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)
        self.descriptors.clear()


def candidate_scripts(expanded, review, *, staging_anchor, diagnostics, revalidation=False):
    archive = ArchiveExpansion(staging_anchor, expanded, diagnostics,
                               kind="root-revalidation" if revalidation else "component")
    try:
        diagnostics["failure_stage"] = "candidate_top_level"
        require({"PackageInfo", "Scripts"} <= archive.names["expanded"] <= {"PackageInfo", "Scripts", "Bom"})
        diagnostics["failure_stage"] = "candidate_package_info"
        info = ET.fromstring(archive.read("expanded", "PackageInfo", maximum=64 * 1024)[0])
        identifier = "com.fainir.accountaccess.installationrootrevalidation" if revalidation else "com.fainir.accountaccess.componentupdate76v2"
        require(info.get("identifier") == identifier and info.get("version") == "0.1.0")
        diagnostics["failure_stage"] = "candidate_payload"
        payload = info.find("payload")
        require(payload is None or all(int(payload.get(key, "0")) == 0 for key in ("numberOfFiles", "installKBytes")))
        diagnostics["failure_stage"] = "candidate_script_phase"
        phases = info.find("scripts")
        require(phases is not None and len(phases) == 1 and phases[0].tag == "postinstall"
                and phases[0].get("file") in {"./postinstall", "postinstall"})
        diagnostics["failure_stage"] = "candidate_resource_set"
        require(archive.names["Scripts"] == set(review["scripts"]))
        actual, resources = {}, {}
        for name in sorted(archive.names["Scripts"]):
            diagnostics["failure_stage"] = "candidate_resource_bytes"
            diagnostics["candidate_resource_name"] = name
            raw, metadata = archive.read("Scripts", name)
            actual[name] = {"sha256": sha(raw), "mode": stat.S_IMODE(metadata.st_mode), "bytes": len(raw)}
            require(actual[name] == review["scripts"][name])
            if name in {"ComponentPlan.json", "BaseManifest.json", "TargetManifest.json"}:
                resources[name] = raw
        diagnostics["failure_stage"] = "candidate_resource_map"
        require(actual == review["scripts"])
        diagnostics["failure_stage"] = "candidate_plan_binding"
        plan_raw = resources["ComponentPlan.json"]
        require(sha(plan_raw) == review["plan_sha256"])
        plan = json.loads(plan_raw)
        require(plan["component_source_commit"] == review["component_source_commit"]
                and plan["base_manifest_sha256"] == BASE_MANIFEST_SHA256
                and sha(resources["BaseManifest.json"]) == BASE_MANIFEST_SHA256
                and sha(resources["TargetManifest.json"]) == plan["target_manifest_sha256"])
        archive.stable()
        diagnostics.pop("candidate_resource_name", None)
        return expanded / "Scripts", plan, json.loads(resources["TargetManifest.json"])
    finally:
        archive.close()


def verify_image(manifest):
    require(set(manifest["roots"]) == {str(BASE), str(APP)})
    tree = manifest["roots"][str(BASE)]
    children = {}
    for name in tree:
        if name:
            parent, _, child = name.rpartition("/")
            children.setdefault(parent, set()).add(child)
    for relative, expected in tree.items():
        path = BASE / relative
        before = path.lstat()
        require(before.st_uid == 0)
        kind = expected["kind"]
        if kind == "directory":
            require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == expected["mode"])
            actual = {entry.name for entry in path.iterdir()}
            require(actual - (PRIVATE if not relative else set()) == children.get(relative, set()))
        elif kind == "symlink":
            require(stat.S_ISLNK(before.st_mode) and before.st_nlink == 1 and os.readlink(path) == expected["target"])
        else:
            require(kind == "file" and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) == expected["mode"] and before.st_size == expected["size"])
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                require(stamp(os.fstat(descriptor)) == stamp(before))
                digest = hashlib.sha256()
                with os.fdopen(os.dup(descriptor), "rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                require(digest.hexdigest() == expected["sha256"] and stamp(os.fstat(descriptor)) == stamp(before))
            finally:
                os.close(descriptor)
        require(stamp(path.lstat()) == stamp(before))
    alias = manifest["roots"][str(APP)]
    require(set(alias) == {""} and APP.is_symlink() and APP.lstat().st_uid == 0
            and os.readlink(APP) == alias[""]["target"])


def policies():
    return {name: json.loads(read_file(path, maximum=4096)) for name, path in (
        ("install", BASE / "broker/install.json"), ("host", BASE / "broker/host.json"), ("owner", BASE / "owner.json"))}


def fixed_records():
    names = [BASE / "broker" / name for name in UNCHANGED_POLICIES]
    names += [JOURNAL / name for name in ("intent.json", "ready.json", "published.json", "complete.json")]
    names += [BASE / "install-verification.json", JOB]
    return {str(path): (sha(read_file(path)), stamp(path.lstat())) for path in names}


def acceptance_passed(report):
    return (isinstance(report.get("checks"), dict) and set(report["checks"]) == CHECKS
            and all(value is True for value in report["checks"].values())
            and (report.get("root_revalidation_requested", False) is False or (
                report.get("root_revalidation_requested") is True
                and set(report.get("root_revalidation_checks", {})) == REVALIDATION_CHECKS
                and all(value is True for value in report["root_revalidation_checks"].values())))
            and "failure_reason" not in report and "cleanup_unverified" not in report)


def revalidation_requested(args):
    paths = [getattr(args, key, None) for key in ("root_revalidation", "root_revalidation_review")]
    hashes = [getattr(args, key, None) for key in ("root_revalidation_sha256", "root_revalidation_review_sha256")]
    require(not any([*paths, *hashes]) or (all(isinstance(path, Path) for path in paths)
                                          and all(hex_value(value, 64) for value in hashes)))
    return bool(hashes[0])


def synthetic_device_mismatch(report):
    """Mutate only this run's disposable, freshly-created empty test install.

    Never an owner repair API: the root/hosted-VM guard and all fresh-install
    gates run again before the first file write. Existing installations and
    private account enrollment cannot reach this fixture path.
    """
    guard()
    require(report.get("root_revalidation_requested") is True
            and report.get("environment") == "fresh-hosted-mac-actual-installer"
            and report.get("personal_accounts_used") == 0 and report.get("enrollment_attempted") is False
            and all(report["checks"].get(key) is True for key in (
                "fresh_hosted_vm", "actual_base_installer", "base_public_image", "fresh_gui_closed"))
            and report["checks"].get("actual_candidate_installer") is False
            and not os.path.lexists(REVALIDATION_NAMESPACE))
    ready = read_file(JOURNAL / "ready.json", maximum=8192)
    require(read_file(JOURNAL / "published.json", maximum=8192) == ready)
    value = json.loads(ready)
    require(set(value) == {"manifest_sha256", "roots"} and value["manifest_sha256"] == BASE_MANIFEST_SHA256
            and set(value["roots"]) == {str(BASE), str(APP)})
    original_inodes = {}
    for path in (BASE, APP):
        info = path.lstat()
        pair = value["roots"][str(path)]
        require(info.st_uid == 0 and pair == [info.st_dev, info.st_ino]
                and all(type(item) is int for item in pair) and 0 <= info.st_dev < 2**31 - 1)
        original_inodes[str(path)] = info.st_ino
        value["roots"][str(path)] = [info.st_dev + 1, info.st_ino]
    changed = json.dumps(value, sort_keys=True).encode() + b"\n"
    require(0 < len(changed) <= 8192)
    for name in ("ready.json", "published.json"):
        path = JOURNAL / name
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            protected_metadata(info, mode=0o600, directory=False)
            require(stamp(info) == stamp(path.lstat()))
            os.ftruncate(fd, 0)
            offset = 0
            while offset < len(changed):
                count = os.write(fd, changed[offset:])
                require(count > 0)
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        require(read_file(path, maximum=8192) == changed)
    require(all(path.lstat().st_ino == original_inodes[str(path)] for path in (BASE, APP)))
    report["synthetic_device_fixture"] = {"only_disposable_receipts_changed": True,
        "root_inodes_unchanged": True, "old_ready_sha256": sha(ready), "fixture_ready_sha256": sha(changed)}


def synthetic_pending_receipt(report, expected):
    """Arrange an interrupted publication only from this VM's generated proof."""
    guard()
    require(report.get("root_revalidation_requested") is True
            and report.get("environment") == "fresh-hosted-mac-actual-installer"
            and report.get("personal_accounts_used") == 0 and report.get("enrollment_attempted") is False
            and report["root_revalidation_checks"].get("actual_revalidation_installer") is True
            and report["checks"].get("actual_candidate_installer") is False
            and isinstance(expected, bytes) and 4 <= len(expected) <= 8192)
    fd = os.open(REVALIDATION_NAMESPACE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        protected_metadata(os.fstat(fd), mode=0o700)
        deny_only_acl(fd)
        require(set(os.listdir(fd)) == {"revalidated-v1.json"})
        require(read_file(REVALIDATION_RECEIPT, maximum=8192) == expected)
        # link is exclusive; a failed fixture leaves an inert conflict and fails QA.
        os.link("revalidated-v1.json", "pending-revalidated-v1.json", src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.unlink("revalidated-v1.json", dir_fd=fd)
        pending = os.open("pending-revalidated-v1.json", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            protected_metadata(os.fstat(pending), mode=0o600, directory=False)
            os.ftruncate(pending, len(expected) // 2)
            os.fsync(pending)
        finally:
            os.close(pending)
        os.fsync(fd)
    finally:
        os.close(fd)
    report["synthetic_pending_fixture"] = {"only_disposable_generated_attestation_changed": True,
        "fixture_kind": "truncated_generated_attestation", "expected_sha256": sha(expected)}


def run(args):
    guard()  # Before any filesystem, Installer, directory-account or job lookup.
    require(hex_value(args.source, 40) and hex_value(args.candidate_sha256, 64) and hex_value(args.review_sha256, 64))
    root_revalidation = revalidation_requested(args)
    output = RootOutput(args.report, os.environ["GITHUB_RUN_ID"])
    report = {"schema": 1, "status": "FAILED", "environment": "fresh-hosted-mac-actual-installer",
              "source_revision": args.source, "controller_revision": os.environ["GITHUB_SHA"],
              "candidate_sha256": args.candidate_sha256, "base_package_sha256": BASE_PACKAGE_SHA256,
              "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "review_sha256": args.review_sha256, "checks": dict.fromkeys(CHECKS, False), "logs": {},
              "root_revalidation_requested": root_revalidation,
              "root_revalidation_checks": dict.fromkeys(REVALIDATION_CHECKS, False) if root_revalidation else {},
              "failure_stage": "fresh_vm_preflight",
              "personal_accounts_used": 0, "enrollment_attempted": False, "private_vault_read": False,
              "crash_injection_tested": False, "physical_delivery_verified": False, "production_ready": False,
              "filesystem_cleanup": "hosted VM teardown; created service stopped explicitly"}
    touched = candidate_attempted = False
    diagnostic_install = diagnostic_plan = None
    try:
        for path in (BASE, COMPONENTS, JOURNAL, APP, JOB, REVALIDATION_NAMESPACE):
            require(not os.path.lexists(path))
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup("_accountaccess")
                raise ValueError("existing_service_identity")
            except KeyError:
                pass
        console = os.stat("/dev/console").st_uid
        person = pwd.getpwuid(console)
        require(console > 0 and person.pw_name == "runner" and person.pw_dir == "/Users/runner")
        report["checks"]["fresh_hosted_vm"] = True
        with tempfile.TemporaryDirectory(prefix="account-access-component-installer-") as temporary:
            stage = Path(temporary)
            report["failure_stage"] = "public_input_staging"
            stage_file(args.base, stage / "base.pkg", BASE_PACKAGE_SHA256, 300 * 1024 * 1024)
            stage_file(args.base_manifest, stage / "base-manifest.json", BASE_MANIFEST_SHA256, 16 * 1024 * 1024)
            stage_file(args.candidate, stage / "candidate.pkg", args.candidate_sha256, 32 * 1024 * 1024)
            stage_file(args.review, stage / "review.json", args.review_sha256, 1024 * 1024)
            review = validate_review(json.loads(read_file(stage / "review.json")), args.source, args.candidate_sha256)
            require((stage / "candidate.pkg").stat().st_size == review["package_bytes"])
            report["failure_stage"] = "public_source_binding"
            bind_sources(review, args.repository, args.source)
            report["source_files"] = review["source_files"]
            report["checks"]["reviewed_public_inputs"] = True
            report["failure_stage"] = "candidate_expand"
            command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "candidate.pkg"), str(stage / "expanded")],
                    report=report, output=output, log="expand.log", timeout=60)
            scripts, plan, target = candidate_scripts(stage / "expanded", review, staging_anchor=stage, diagnostics=report)
            report["checks"]["candidate_expansion_matches_review"] = True
            requirement = ('anchor apple generic and identifier "com.fainir.accountaccess.componentupdate" '
                'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                'and certificate leaf[subject.OU] = "WBULD6N4NQ" '
                'and !(entitlement["com.apple.security.get-task-allow"] exists)')
            report["failure_stage"] = "candidate_native_signature"
            command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R=" + requirement,
                     str(scripts / "AccountAccess-componentupdate")], report=report, output=output, log="signature.log")
            report["checks"]["genuine_signed_helper"] = True
            if root_revalidation:
                report["failure_stage"] = "root_revalidation_inputs"
                stage_file(args.root_revalidation, stage / "root-revalidation.pkg", args.root_revalidation_sha256, 32 * 1024 * 1024)
                stage_file(args.root_revalidation_review, stage / "root-revalidation-review.json", args.root_revalidation_review_sha256, 1024 * 1024)
                root_review = validate_review(json.loads(read_file(stage / "root-revalidation-review.json")), args.source,
                                              args.root_revalidation_sha256, revalidation=True)
                require(root_review["source_files"] == review["source_files"]
                        and root_review["plan_sha256"] == review["plan_sha256"]
                        and (stage / "root-revalidation.pkg").stat().st_size == root_review["package_bytes"])
                resources = set(review["scripts"]) - {"AccountAccess-componentupdate", "postinstall"}
                require(resources == set(root_review["scripts"]) - {"AccountAccess-componentupdate", "postinstall"}
                        and all(root_review["scripts"][name] == review["scripts"][name] for name in resources))
                bind_sources(root_review, args.repository, args.source)
                command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "root-revalidation.pkg"), str(stage / "root-expanded")],
                        report=report, output=output, log="root-revalidation-expand.log", timeout=60)
                root_scripts, root_plan, root_target = candidate_scripts(stage / "root-expanded", root_review,
                    staging_anchor=stage, diagnostics=report, revalidation=True)
                require(root_plan == plan and root_target == target)
                report["root_revalidation_checks"]["reviewed_revalidation_input"] = True
                command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R=" + requirement,
                         str(root_scripts / "AccountAccess-componentupdate")], report=report, output=output, log="root-revalidation-signature.log")
                report["root_revalidation_checks"]["genuine_signed_revalidation_helper"] = True
                report["root_revalidation_sha256"] = args.root_revalidation_sha256
                report["root_revalidation_review_sha256"] = args.root_revalidation_review_sha256
            touched = True
            report["failure_stage"] = "base_installer"
            command(["/usr/sbin/installer", "-pkg", str(stage / "base.pkg"), "-target", "/"],
                    report=report, output=output, log="base-installer.log", timeout=360)
            report["checks"]["actual_base_installer"] = True
            report["failure_stage"] = "base_public_image"
            verify_image(json.loads(read_file(stage / "base-manifest.json")))
            report["checks"]["base_public_image"] = True
            # Fresh disposable GUI only; the native updater independently binds
            # executable/PID/birth and enforces genuine absence before mutation.
            close_fresh_gui(console, report=report, output=output)
            report["checks"]["fresh_gui_closed"] = True
            if root_revalidation:
                report["failure_stage"] = "root_revalidation_exact_legacy"
                candidate_install(stage / "root-revalidation.pkg", report=report, output=output,
                    log="root-legacy-installer.log", daemon_log="root-legacy-daemon-install.log")
                require(not os.path.lexists(REVALIDATION_NAMESPACE))
                report["root_revalidation_checks"]["exact_legacy_revalidation_no_receipt"] = True
                report["failure_stage"] = "synthetic_device_fixture"
                synthetic_device_mismatch(report)
                report["root_revalidation_checks"]["synthetic_device_mismatch_same_inodes"] = True
                fixture_retained = fixed_records()
                report["failure_stage"] = "root_revalidation_installer"
                candidate_install(stage / "root-revalidation.pkg", report=report, output=output,
                    log="root-revalidation-installer.log", daemon_log="root-revalidation-daemon-install.log")
                report["root_revalidation_checks"]["actual_revalidation_installer"] = True
                protected_metadata(REVALIDATION_NAMESPACE.lstat(), mode=0o700)
                protected_metadata(REVALIDATION_RECEIPT.lstat(), mode=0o600, directory=False)
                supplement = (sha(read_file(REVALIDATION_RECEIPT, maximum=8192)), stamp(REVALIDATION_RECEIPT.lstat()))
                require(fixed_records() == fixture_retained)
                report["root_revalidation_checks"]["protected_supplement_created"] = True
                report["failure_stage"] = "root_revalidation_reapplication"
                candidate_install(stage / "root-revalidation.pkg", report=report, output=output,
                    log="root-revalidation-reapply-installer.log", daemon_log="root-revalidation-reapply-daemon-install.log")
                require((sha(read_file(REVALIDATION_RECEIPT, maximum=8192)), stamp(REVALIDATION_RECEIPT.lstat())) == supplement
                        and fixed_records() == fixture_retained)
                report["root_revalidation_checks"]["revalidation_reapplication"] = True
                report["root_revalidation_checks"]["original_receipts_unchanged"] = True
                report["failure_stage"] = "root_revalidation_pending_fixture"
                generated_supplement = read_file(REVALIDATION_RECEIPT, maximum=8192)
                synthetic_pending_receipt(report, generated_supplement)
                candidate_install(stage / "root-revalidation.pkg", report=report, output=output,
                    log="root-pending-recovery-installer.log", daemon_log="root-pending-recovery-daemon-install.log")
                require(read_file(REVALIDATION_RECEIPT, maximum=8192) == generated_supplement
                        and not os.path.lexists(REVALIDATION_NAMESPACE / "pending-revalidated-v1.json")
                        and fixed_records() == fixture_retained)
                supplement = (sha(generated_supplement), stamp(REVALIDATION_RECEIPT.lstat()))
                report["root_revalidation_checks"]["bounded_pending_receipt_recovered"] = True
            report["failure_stage"] = "baseline_public_records"
            before, retained = policies(), fixed_records()
            diagnostic_install, diagnostic_plan = before["install"], review["plan_sha256"]
            report["failure_stage"] = "candidate_installer"
            candidate_attempted = True
            candidate_install(stage / "candidate.pkg", report=report, output=output,
                              log="candidate-installer.log", daemon_log="candidate-daemon-install.log")
            report["checks"]["actual_candidate_installer"] = True
            report["failure_stage"] = "target_public_image"
            verify_image(target)
            report["checks"]["target_public_image"] = True
            report["failure_stage"] = "preserved_public_policy_values"
            expected = json.loads(json.dumps(before))
            expected["install"]["payload_fingerprint"] = plan["new_fingerprint"]
            expected["host"]["bootstrap_hashes"] = plan["new_signatures"]["bootstrap"]["hashes"]
            expected["owner"]["server_hashes"] = plan["new_signatures"]["broker"]["hashes"]
            require(policies() == expected)
            report["checks"]["only_three_policy_values_changed"] = True
            report["failure_stage"] = "preserved_original_receipts"
            require(fixed_records() == retained)
            report["checks"]["unchanged_worker_plans_and_original_journal"] = True
            report["failure_stage"] = "verified_head"
            head = json.loads(read_file(COMPONENTS / "head.json", maximum=4096))
            require(head == {"schema": 1, "managed_by": "account-access-component-head-v1", "plan_sha256": review["plan_sha256"],
                "base_manifest_sha256": BASE_MANIFEST_SHA256, "manifest_sha256": plan["target_manifest_sha256"],
                "state": "public_image_verified_gui_unverified", "automatic_reboot_recovery": False})
            report["checks"]["verified_head"] = True
            report["failure_stage"] = "candidate_reapply"
            candidate_install(stage / "candidate.pkg", report=report, output=output,
                              log="same-package-installer.log", daemon_log="same-package-daemon-install.log")
            report["checks"]["same_package_reapplication"] = True
            report["failure_stage"] = "reapplied_public_image"
            verify_image(target)
            require(policies() == expected and fixed_records() == retained
                    and json.loads(read_file(COMPONENTS / "head.json", maximum=4096)) == head)
            report["checks"]["reapplication_preserved_bytes_and_ids"] = True
            if root_revalidation:
                require((sha(read_file(REVALIDATION_RECEIPT, maximum=8192)), stamp(REVALIDATION_RECEIPT.lstat())) == supplement)
                report["root_revalidation_checks"]["supplement_preserved_by_component"] = True
                report["failure_stage"] = "root_revalidation_after_component"
                candidate_install(stage / "root-revalidation.pkg", report=report, output=output,
                    log="root-after-component-installer.log", daemon_log="root-after-component-daemon-install.log")
                require((sha(read_file(REVALIDATION_RECEIPT, maximum=8192)), stamp(REVALIDATION_RECEIPT.lstat())) == supplement
                        and policies() == expected and fixed_records() == retained)
                report["root_revalidation_checks"]["revalidation_after_component"] = True
            report["failure_stage"] = "public_staging_cleanup"
    except Exception:
        report["failure_reason"] = "actual_component_installer_acceptance_failed"
    finally:
        report["measurement_failure_stage"] = report["failure_stage"] if "failure_reason" in report else None
        if candidate_attempted and not report["checks"]["actual_candidate_installer"]:
            quiescence_diagnostics(report, diagnostic_install, diagnostic_plan)
        if touched:
            try:
                value = plistlib.loads(read_file(JOB, maximum=8192))
                require(value.get("Label") == LABEL and value.get("ProgramArguments") == [str(BASE / "bin/AccountAccess-broker")])
                command(["/bin/launchctl", "bootout", "system/" + LABEL], report=report,
                        output=output, log="cleanup-bootout.log", check=False)
                absent = command(["/bin/launchctl", "print", "system/" + LABEL], report=report,
                                 output=output, log="cleanup-lookup.log", check=False)
                require(absent.returncode == 113 and absent.stdout + absent.stderr == (
                    'Bad request.\nCould not find service "' + LABEL + '" in domain for system\n').encode())
                report["checks"]["created_job_stopped"] = True
            except Exception:
                report["cleanup_unverified"] = True
                report["failure_stage"] = "created_job_cleanup"
        if candidate_attempted and not report["checks"]["actual_candidate_installer"]:
            test_vm_domain_canary(report, diagnostic_install, diagnostic_plan)
        if acceptance_passed(report):
            report["status"] = "PASSED"
            report["failure_stage"] = None
        try:
            output.write("report.json", json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
            output.publish()
        finally:
            output.close()
    return 0 if report["status"] == "PASSED" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("base", "base-manifest", "candidate", "review", "report", "repository"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("review-sha256", "source", "candidate-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("root-revalidation", "root-revalidation-review"):
        parser.add_argument("--" + name, type=Path)
    for name in ("root-revalidation-sha256", "root-revalidation-review-sha256"):
        parser.add_argument("--" + name)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
