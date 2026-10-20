# ruff: noqa: E402 -- refuse unsafe bootstrap before source-backed imports.
"""Restore only reviewed build76 standard-library caches; never run account code."""

import sys

_PREFIX = "/Library/Logs/AccountAccessRuntimeRepairs76/bootstrap-"
_PYTHON = "/Library/Application Support/Account Access/runtime/bin/python3.12"
if __name__ == "__main__" and (
    sys.platform != "darwin" or sys.executable != _PYTHON or len(sys.argv) != 1
    or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
    or not isinstance(sys.pycache_prefix, str) or not sys.pycache_prefix.startswith(_PREFIX)
    or len(sys.pycache_prefix.removeprefix(_PREFIX)) != 12
    or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
           for c in sys.pycache_prefix.removeprefix(_PREFIX))
):
    print('{"status":"REFUSED","reason":"trusted_repair_context_required"}')
    raise SystemExit(1)

import os

if __name__ == "__main__" and (os.getuid() != 0 or os.geteuid() != 0):
    print('{"status":"REFUSED","reason":"trusted_repair_context_required"}')
    raise SystemExit(1)

if __name__ == "__main__":
    try:
        _prefix_fd = os.open(sys.pycache_prefix, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _info = os.fstat(_prefix_fd)
            if _info.st_uid != 0 or (_info.st_mode & 0o7777) != 0o700 or os.listdir(_prefix_fd):
                raise OSError()
        finally:
            os.close(_prefix_fd)
    except OSError:
        print('{"status":"REFUSED","reason":"bootstrap_prefix_changed"}')
        raise SystemExit(1) from None

import ctypes
import errno
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import re
import secrets
import stat
import struct
from types import SimpleNamespace

RUNTIME = Path("/Library/Application Support/Account Access/runtime")
REPORTS = Path("/Library/Logs/AccountAccessRuntimeRepairs76")
PLAN_SHA256 = "a5eb03806270e51779ee8f570316cbf134c481240c0ed3f934230016ba2dc4b0"
EXTRA_PATHS = frozenset("lib/python3.12/" + name + "__pycache__" for name in (
    "", "ctypes/", "urllib/", "xml/parsers/", "xml/", "json/", "collections/", "re/"))
BASELINE_PATHS = frozenset("lib/python3.12/encodings/__pycache__/" + name + ".cpython-312.pyc"
                           for name in ("aliases", "utf_8", "__init__"))
MAX_CACHE_BYTES = 2 * 1024 * 1024
PUBLIC_REASONS = frozenset((
    "package_input_changed", "unsafe_metadata", "atomic_cache_move_unavailable",
    "cache_metadata_changed", "pinned_source_changed", "cache_is_not_reviewed_generated_code",
    "unknown_cache_child", "observed_cache_identity_changed", "cache_backup_device_changed",
    "rollback_not_confirmed", "cache_changed_before_move", "cache_changed_during_move",
    "bootstrap_prefix_changed", "repair_reports_changed", "prior_repair_evidence_present",
    "build_76_binding_changed", "installed_job_changed", "installed_job_unavailable",
    "service_is_running", "service_not_failing_with_78",
))


class Refused(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def closed_reason(error):
    # No arbitrary exception text, paths, errno or command output is public.
    if len(error.args) == 1 and isinstance(error.args[0], str) and error.args[0] in PUBLIC_REASONS:
        return error.args[0]
    return "cache_repair_preconditions_unavailable"


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def package_bytes(parent, name, *, maximum=256 * 1024):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise Refused("package_input_changed")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o644 or not 0 < before.st_size <= maximum):
            raise Refused("package_input_changed")
        no_acl(fd)
        data = os.read(fd, maximum + 1)
        if (len(data) != before.st_size or stamp(before) != stamp(os.fstat(fd))
                or stamp(before) != stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))):
            raise Refused("package_input_changed")
        return data
    finally:
        os.close(fd)


def no_acl(fd):
    library = ctypes.CDLL(None, use_errno=True)
    library.acl_get_fd.argtypes = [ctypes.c_int]
    library.acl_get_fd.restype = ctypes.c_void_p
    library.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_free.argtypes = [ctypes.c_void_p]
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


def load_inputs():
    parent = os.open(Path(__file__).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(parent)
        if info.st_uid != 0 or info.st_mode & 0o7022:
            raise Refused("package_input_changed")
        no_acl(parent)
        raw = package_bytes(parent, "plan.json")
        if digest(raw) != PLAN_SHA256:
            raise Refused("package_input_changed")
        plan = json.loads(raw)
        if ({r["path"] for r in plan["baseline"]} != BASELINE_PATHS
                or {r["path"] for r in plan["extra_directories"]} != EXTRA_PATHS
                or len(plan["baseline"]) != 3 or len(plan["extra_directories"]) != 8
                or plan["schema"] != 1 or plan["target_build"] != 76):
            raise Refused("package_input_changed")
        common_raw = package_bytes(parent, "startup_check.py")
        if digest(common_raw) != plan["common_sha256"]:
            raise Refused("package_input_changed")
        namespace = {"__name__": "runtime_cache_repair_common", "__file__": str(Path(__file__).with_name("startup_check.py"))}
        exec(compile(common_raw, namespace["__file__"], "exec"), namespace)
        common = SimpleNamespace(**namespace)
        baseline = {}
        for row in plan["baseline"]:
            data = package_bytes(parent, row["package_file"])
            if digest(data) != row["sha256"] or len(data) != row["size"]:
                raise Refused("package_input_changed")
            baseline[row["path"]] = data
        return common, plan, baseline
    finally:
        os.close(parent)


def expected_generated_cache(source, source_info, filename):
    # Compile pinned public source as data. Never unmarshal or execute a cache.
    code = compile(source, filename, "exec", dont_inherit=True, optimize=0)
    return (importlib.util.MAGIC_NUMBER
            + struct.pack("<III", 0, int(source_info.st_mtime) & 0xffffffff, len(source))
            + marshal.dumps(code))


def rename_native(source_parent, source, destination_parent, destination, *, swap=False):
    library = ctypes.CDLL(None, use_errno=True)
    library.renameatx_np.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    library.renameatx_np.restype = ctypes.c_int
    # From the local Darwin sys/stdio.h: SWAP=2, EXCL=4. No overwrite rename.
    if library.renameatx_np(source_parent, os.fsencode(source), destination_parent,
                           os.fsencode(destination), 2 if swap else 4) != 0:
        raise Refused("atomic_cache_move_unavailable")


class Repair:
    def __init__(self, common, plan, baseline, reports, *, renamer=rename_native):
        self.common, self.plan, self.baseline = common, plan, baseline
        self.reports, self.rename = reports, renamer
        self.backup = None
        self.backup_created = False
        self.handles = []
        self.operations = []
        self.sequence = 0
        self.failure_reason = None

    def metadata(self, fd, *, directory=False, mode=None):
        info = self.common.check_fd(fd, directory=directory)
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            raise Refused("cache_metadata_changed")
        return info

    def read(self, parent, name, *, mode, maximum=MAX_CACHE_BYTES, allow_empty=False):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = self.metadata(fd, mode=mode)
            if not (0 if allow_empty else 1) <= before.st_size <= maximum:
                raise Refused("cache_metadata_changed")
            data = os.read(fd, maximum + 1)
            after = self.metadata(fd, mode=mode)
            if (len(data) != before.st_size or stamp(before) != stamp(after)
                    or stamp(after) != stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))):
                raise Refused("cache_metadata_changed")
            return data, after
        finally:
            os.close(fd)

    def source(self, name):
        row = self.plan["sources"][name]
        parent = self.common.directory((RUNTIME / name).parent)
        try:
            data, info = self.read(parent, Path(name).name, mode=row["mode"], allow_empty=True)
        finally:
            os.close(parent)
        if len(data) != row["size"] or digest(data) != row["sha256"]:
            raise Refused("pinned_source_changed")
        return data, info

    def generated(self, parent, name, source):
        data, info = self.read(parent, name, mode=0o600)
        text, source_info = self.source(source)
        if data != expected_generated_cache(text, source_info, str(RUNTIME / source)):
            raise Refused("cache_is_not_reviewed_generated_code")
        return {"stamp": stamp(info), "sha256": digest(data), "mode": 0o600}

    def tree(self, parent, name, row):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = self.metadata(fd, directory=True, mode=0o700)
            names = sorted(os.listdir(fd))
            if not names or len(names) > 128 or any(child not in row["allowed_children"] for child in names):
                raise Refused("unknown_cache_child")
            children = {child: self.generated(fd, child, row["allowed_children"][child]) for child in names}
            after = self.metadata(fd, directory=True, mode=0o700)
            if (stamp(before) != stamp(after) or names != sorted(os.listdir(fd))
                    or stamp(after) != stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))):
                raise Refused("cache_metadata_changed")
            return {"stamp": stamp(after), "children": children}
        finally:
            os.close(fd)

    def observed(self, info, row):
        expected = row["observed"]
        if (info[1] != expected["inode"] or info[3] != expected["uid"] or info[4] != expected["gid"]
                or stat.S_IMODE(info[2]) != int(expected["mode"], 8) or info[6] != expected["size"]):
            raise Refused("observed_cache_identity_changed")

    def preflight(self):
        for row in [*self.plan["baseline"], *self.plan["extra_directories"]]:
            parent = self.common.directory((RUNTIME / row["path"]).parent)
            self.handles.append(parent)
            name = Path(row["path"]).name
            kind = "file" if row in self.plan["baseline"] else "directory"
            before = self.generated(parent, name, row["source"]) if kind == "file" else self.tree(parent, name, row)
            self.observed(before["stamp"], row)
            if before["stamp"][0] != os.fstat(self.reports).st_dev:
                raise Refused("cache_backup_device_changed")
            self.operations.append({"kind": kind, "row": row, "parent": parent, "name": name, "before": before})

    def journal(self, event, index, state=None):
        name = "journal-" + str(self.sequence).zfill(4) + ".json"
        self.sequence += 1
        data = json.dumps({"schema": 1, "event": event, "operation": index, "state": state}, sort_keys=True).encode() + b"\n"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.backup)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.backup)

    def stage(self):
        name = "repair-" + secrets.token_hex(16)
        os.mkdir(name, 0o700, dir_fd=self.reports)
        self.backup_created = True
        self.backup = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.reports)
        self.metadata(self.backup, directory=True, mode=0o700)
        os.fsync(self.reports)
        self.journal("validated_plan", -1, [{"path": op["row"]["path"], "before": op["before"]} for op in self.operations])
        for index, operation in enumerate(self.operations):
            operation["slot"] = "prior-" + str(index).zfill(2)
            if operation["kind"] == "file":
                fd = os.open(operation["slot"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.backup)
                try:
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(self.baseline[operation["row"]["path"]])
                        stream.flush()
                        os.fchmod(fd, 0o644)
                        os.fsync(fd)
                    operation["replacement_inode"] = os.fstat(fd).st_ino
                finally:
                    os.close(fd)
        os.fsync(self.backup)
        self.journal("replacements_staged", -1, [
            {"path": op["row"]["path"], "slot": op["slot"],
             "inode": op["replacement_inode"], "sha256": op["row"]["sha256"]}
            for op in self.operations if op["kind"] == "file"
        ])

    def file_identity(self, parent, name, *, mode):
        data, info = self.read(parent, name, mode=mode)
        return info.st_ino, digest(data)

    def state(self, operation):
        if operation["kind"] == "file":
            try:
                row = operation["row"]
                current = self.file_identity(operation["parent"], operation["name"], mode=0o644)
                prior = self.file_identity(self.backup, operation["slot"], mode=0o600)
                if (current == (operation["replacement_inode"], row["sha256"])
                        and prior == (operation["before"]["stamp"][1], operation["before"]["sha256"])):
                    return "applied"
            except (OSError, Refused):
                pass
            try:
                row = operation["row"]
                current = self.file_identity(operation["parent"], operation["name"], mode=0o600)
                staged = self.file_identity(self.backup, operation["slot"], mode=0o644)
                if (current == (operation["before"]["stamp"][1], operation["before"]["sha256"])
                        and staged == (operation["replacement_inode"], row["sha256"])):
                    return "not_applied"
            except (OSError, Refused):
                pass
        else:
            try:
                try:
                    os.stat(operation["name"], dir_fd=operation["parent"], follow_symlinks=False)
                except FileNotFoundError:
                    moved = self.tree(self.backup, operation["slot"], operation["row"])
                    if moved["stamp"][1] == operation["before"]["stamp"][1] and moved["children"] == operation["before"]["children"]:
                        return "applied"
                else:
                    try:
                        os.stat(operation["slot"], dir_fd=self.backup, follow_symlinks=False)
                    except FileNotFoundError:
                        current = self.tree(operation["parent"], operation["name"], operation["row"])
                        if current == operation["before"]:
                            return "not_applied"
            except (OSError, Refused):
                pass
        return "conflict"

    def rollback(self):
        confirmed = True
        for index in reversed(range(len(self.operations))):
            operation = self.operations[index]
            if not operation.get("attempted"):
                continue
            try:
                state = self.state(operation)
                if state == "not_applied":
                    continue
                if state != "applied":
                    confirmed = False
                    self.journal("rollback_conflict", index)
                    continue
                self.journal("rollback_intent", index)
                self.rename(self.backup, operation["slot"], operation["parent"], operation["name"],
                            swap=operation["kind"] == "file")
                os.fsync(operation["parent"])
                os.fsync(self.backup)
                if operation["kind"] == "file":
                    restored = self.file_identity(operation["parent"], operation["name"], mode=0o600)
                    if restored != (operation["before"]["stamp"][1], operation["before"]["sha256"]):
                        raise Refused("rollback_not_confirmed")
                else:
                    restored = self.tree(operation["parent"], operation["name"], operation["row"])
                    if (restored["stamp"][1] != operation["before"]["stamp"][1]
                            or restored["children"] != operation["before"]["children"]):
                        raise Refused("rollback_not_confirmed")
                self.journal("rolled_back", index)
            except Exception:
                confirmed = False
        return confirmed

    def apply(self):
        try:
            self.stage()
            for index, operation in enumerate(self.operations):
                current = (self.generated(operation["parent"], operation["name"], operation["row"]["source"])
                           if operation["kind"] == "file" else self.tree(operation["parent"], operation["name"], operation["row"]))
                if current != operation["before"]:
                    raise Refused("cache_changed_before_move")
                self.journal("intent", index)
                operation["attempted"] = True
                if operation["kind"] == "file":
                    self.rename(self.backup, operation["slot"], operation["parent"], operation["name"], swap=True)
                else:
                    self.rename(operation["parent"], operation["name"], self.backup, operation["slot"], swap=False)
                os.fsync(operation["parent"])
                os.fsync(self.backup)
                if self.state(operation) != "applied":
                    raise Refused("cache_changed_during_move")
                self.journal("completed", index)
            self.journal("repair_completed", -1)
            return "restored_build76_cache", True
        except Exception as error:
            self.failure_reason = closed_reason(error)
            return "repair_failed_rollback_confirmed" if self.rollback() else "repair_failed_rollback_conflict", False

    def close(self):
        for fd in self.handles:
            os.close(fd)
        if self.backup is not None:
            os.close(self.backup)


def main():
    if (sys.platform != "darwin" or sys.executable != _PYTHON or os.getuid() != 0 or os.geteuid() != 0
            or len(sys.argv) != 1 or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or not isinstance(sys.pycache_prefix, str) or not sys.pycache_prefix.startswith(_PREFIX)):
        print('{"status":"REFUSED","reason":"trusted_repair_context_required"}')
        return 1
    os.umask(0o077)
    reports = prefix = None
    repair = None
    phase = "static_inputs"
    try:
        common, plan, baseline = load_inputs()
        phase = "bootstrap_prefix"
        prefix = common.directory(Path(sys.pycache_prefix))
        if stat.S_IMODE(os.fstat(prefix).st_mode) != 0o700 or os.listdir(prefix):
            raise Refused("bootstrap_prefix_changed")
        phase = "installed_build"
        common.validate_installation()
        phase = "failing_service"
        common.wait_for_failing_service()
        phase = "reports_namespace"
        reports = common.directory(REPORTS)
        if stat.S_IMODE(os.fstat(reports).st_mode) != 0o755:
            raise Refused("repair_reports_changed")
        if any(name.startswith("repair-") for name in os.listdir(reports)):
            raise Refused("prior_repair_evidence_present")
        repair = Repair(common, plan, baseline, reports)
        phase = "cache_preflight"
        repair.preflight()
        phase = "failing_service_recheck"
        common.wait_for_failing_service()
        phase = "cache_restore"
        status, succeeded = repair.apply()
        report = {"schema": 1, "status": status, "target_build": 76, "production_ready": False,
                  "failure_phase": None if succeeded else phase, "reason": repair.failure_reason,
                  "baseline_files_restored": 3 if succeeded else 0,
                  "extra_cache_directories_moved": 8 if succeeded else 0,
                  "private_backups_and_journal_retained": repair.backup_created,
                  "journal_recovery": "manual_review_only", "automatic_crash_recovery": False,
                  "service_started_or_stopped": False, "account_data_accessed": False}
        phase = "public_report"
        name = "result-" + secrets.token_hex(16) + ".json"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=reports)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(json.dumps(report, sort_keys=True).encode() + b"\n")
                stream.flush()
                os.fsync(fd)
                os.fchmod(fd, 0o644)
        finally:
            os.close(fd)
        os.fsync(reports)
        print(json.dumps({"status": status, "public_report": str(REPORTS / name)}))
        return 0 if succeeded else 1
    except Exception as error:
        print(json.dumps({"status": "REFUSED", "reason": closed_reason(error), "failure_phase": phase}))
        return 1
    finally:
        if repair is not None:
            repair.close()
        for fd in [prefix, reports]:
            if fd is not None:
                os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
