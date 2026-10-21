"""QA-only, kernel-bound process cleanup for disposable publisher-review Macs.

Importing this module does not inspect or signal processes. Callers must retain
their pre-launch snapshot and exclude those identities from cleanup. No command
arguments, environment, user files, or process names enter these identities.
"""

import ctypes
import errno
from functools import lru_cache
import math
import os
from pathlib import PurePosixPath
import signal
import subprocess
import sys
import time
from dataclasses import dataclass


ALLOWED_ROOTS = frozenset({"/Library/Application Support/Account Access", "/Applications/Google Chrome.app"})
PROC_PIDTBSDINFO = 3
PROC_PIDPATHINFO_MAXSIZE = 4096


class ProcessInspectionError(RuntimeError):
    """A fixed public reason, never a command or kernel diagnostic payload."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    start_sec: int
    start_usec: int
    path: str


@dataclass(frozen=True)
class _BSDIdentity:
    pid: int
    uid: int
    ruid: int
    start_sec: int
    start_usec: int


class _ProcBSDInfo(ctypes.Structure):
    # CLT SDK sys/proc_info.h: struct proc_bsdinfo, MAXCOMLEN=16,
    # uint32_t uid_t/gid_t, natural Darwin arm64/x86_64 alignment.
    _fields_ = [
        *[(name, ctypes.c_uint32) for name in (
            "pbi_flags", "pbi_status", "pbi_xstatus", "pbi_pid", "pbi_ppid", "pbi_uid", "pbi_gid",
            "pbi_ruid", "pbi_rgid", "pbi_svuid", "pbi_svgid", "rfu_1")],
        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
        *[(name, ctypes.c_uint32) for name in ("pbi_nfiles", "pbi_pgid", "pbi_pjobc", "e_tdev", "e_tpgid")],
        ("pbi_nice", ctypes.c_int32), ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def _uid(uid):
    if type(uid) is not int or not 0 < uid < 2**32:
        raise ProcessInspectionError("process_uid_invalid")


def _roots(roots):
    values = tuple(str(root) for root in roots)
    if not values or len(set(values)) != len(values) or not set(values) <= ALLOWED_ROOTS:
        raise ProcessInspectionError("process_roots_invalid")
    return values


def _pid(pid):
    return type(pid) is int and 1 < pid < 2**31


def _path(path, roots):
    if type(path) is not str or not path.startswith("/") or "\x00" in path or "\\" in path:
        return False
    parts = path.split("/")[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return False
    value = PurePosixPath(path)
    return any(value != PurePosixPath(root) and value.is_relative_to(root) for root in roots)


def _valid(identity, roots):
    return (type(identity) is ProcessIdentity and _pid(identity.pid) and type(identity.uid) is int
            and 0 < identity.uid < 2**32 and type(identity.start_sec) is int and identity.start_sec > 0
            and type(identity.start_usec) is int and 0 <= identity.start_usec < 1_000_000
            and _path(identity.path, roots))


@lru_cache(maxsize=1)
def _libproc():
    if sys.platform != "darwin":
        raise ProcessInspectionError("process_platform_invalid")
    if (ctypes.sizeof(_ProcBSDInfo), _ProcBSDInfo.pbi_start_tvsec.offset, _ProcBSDInfo.pbi_start_tvusec.offset) != (136, 120, 128):
        raise ProcessInspectionError("process_native_layout_invalid")
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    library.proc_pidinfo.restype = ctypes.c_int
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    return library


def _bsd(pid):
    info = _ProcBSDInfo()
    ctypes.set_errno(0)
    result = _libproc().proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, ctypes.byref(info), ctypes.sizeof(info))
    if result == 0 and ctypes.get_errno() in {errno.ESRCH, errno.ENOENT}:
        return None
    if result != ctypes.sizeof(info):
        raise ProcessInspectionError("process_identity_read_failed")
    return _BSDIdentity(info.pbi_pid, info.pbi_uid, info.pbi_ruid, info.pbi_start_tvsec, info.pbi_start_tvusec)


def _kernel_path(pid):
    buffer = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)
    ctypes.set_errno(0)
    result = _libproc().proc_pidpath(pid, buffer, len(buffer))
    if result == 0 and ctypes.get_errno() in {errno.ESRCH, errno.ENOENT}:
        return None
    if not 0 < result < len(buffer) or b"\x00" not in buffer.raw:
        raise ProcessInspectionError("process_path_read_failed")
    try:
        return buffer.value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ProcessInspectionError("process_path_read_failed") from None


def _scan():
    try:
        result = subprocess.run(["/bin/ps", "-axo", "pid="], capture_output=True, timeout=5, close_fds=True,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise ProcessInspectionError("process_scan_failed") from None
    if result.returncode or len(result.stdout) > 1_000_000 or result.stderr:
        raise ProcessInspectionError("process_scan_failed")
    try:
        rows = result.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise ProcessInspectionError("process_scan_failed") from None
    if len(rows) > 65536 or any(not row.strip().isdecimal() for row in rows):
        raise ProcessInspectionError("process_scan_failed")
    values = tuple(int(row.strip()) for row in rows)
    if len(set(values)) != len(values) or any(not 0 < pid < 2**31 for pid in values):
        raise ProcessInspectionError("process_scan_failed")
    return values


def _read(pid, uid, roots, bsd, path):
    before = bsd(pid)
    if before is None or before.pid != pid or before.uid != uid or before.ruid != uid:
        return None
    executable = path(pid)
    after = bsd(pid)
    if before != after:
        return None
    if executable is None:
        raise ProcessInspectionError("process_path_read_failed")
    identity = ProcessIdentity(pid, uid, before.start_sec, before.start_usec, executable)
    return identity if _valid(identity, roots) else None


def snapshot(uid, roots, *, scanner=None, bsd_reader=None, path_reader=None):
    """Return immutable identities under fixed protected roots for one nonroot UID."""
    _uid(uid)
    roots = _roots(roots)
    pids = tuple((scanner or _scan)())
    if (len(pids) > 65536 or any(type(pid) is not int or not 0 < pid < 2**31 for pid in pids)
            or len(set(pids)) != len(pids)):
        raise ProcessInspectionError("process_scan_failed")
    identities = []
    for pid in sorted(pids):
        if not _pid(pid):
            continue
        identity = _read(pid, uid, roots, bsd_reader or _bsd, path_reader or _kernel_path)
        if identity is not None:
            identities.append(identity)
    return tuple(identities)


def matches(identity, roots, *, bsd_reader=None, path_reader=None):
    """Check PID, both UIDs, start time, and executable without reading arguments."""
    roots = _roots(roots)
    if not _valid(identity, roots):
        raise ProcessInspectionError("process_identity_invalid")
    return _read(identity.pid, identity.uid, roots, bsd_reader or _bsd, path_reader or _kernel_path) == identity


def signal_identity(identity, signum, roots, *, bsd_reader=None, path_reader=None, kill=None,
                    deadline=None, clock=None):
    """Signal only an immediately revalidated identity; never a process group.

    Darwin has no pidfd signal API here: the final check and kill are distinct
    syscalls. Start-time binding minimizes PID reuse risk but is not atomic.
    """
    if type(signum) not in {int, signal.Signals} or signum not in {signal.SIGTERM, signal.SIGKILL}:
        raise ProcessInspectionError("process_signal_invalid")
    roots = _roots(roots)
    if not _valid(identity, roots):
        raise ProcessInspectionError("process_identity_invalid")
    if deadline is not None and (type(deadline) not in {int, float} or not math.isfinite(deadline)):
        raise ProcessInspectionError("process_stop_invalid")
    now = clock or time.monotonic
    if deadline is not None and now() >= deadline:
        return False
    if not matches(identity, roots, bsd_reader=bsd_reader, path_reader=path_reader):
        return False
    # Kernel reads can themselves consume the remaining budget. This final
    # monotonic check leaves no signal fan-out running after its deadline.
    if deadline is not None and now() >= deadline:
        return False
    try:
        (kill or os.kill)(identity.pid, signum)
    except ProcessLookupError:
        return False
    except OSError:
        raise ProcessInspectionError("process_signal_failed") from None
    return True


def stop(identities, roots, *, timeout=5, kill_after=1, bsd_reader=None, path_reader=None,
         kill=None, clock=None, sleep=None):
    """Bounded TERM/KILL and disappearance checks for only these frozen identities.

    These need not be this process's children; their existing parent performs
    wait/reap. Callers must separately scan for late children, excluding baseline.
    """
    roots = _roots(roots)
    identities = tuple(identities)
    if (len(identities) > 65536 or any(not _valid(item, roots) for item in identities)
            or len({item.pid for item in identities}) != len(identities)
            or type(timeout) not in {int, float} or not 0 < timeout <= 10
            or type(kill_after) not in {int, float} or not 0 <= kill_after < timeout):
        raise ProcessInspectionError("process_stop_invalid")
    read = {"bsd_reader": bsd_reader, "path_reader": path_reader}
    now, pause = clock or time.monotonic, sleep or time.sleep
    started = now()
    deadline = started + timeout
    for identity in identities:
        if now() >= deadline:
            return False
        signal_identity(identity, signal.SIGTERM, roots, kill=kill, deadline=deadline, clock=now, **read)
    killed = False
    while True:
        remaining = []
        for item in identities:
            if now() >= deadline:
                return False
            alive = matches(item, roots, **read)
            if now() >= deadline:
                return False
            if alive:
                remaining.append(item)
        if not remaining:
            return True
        elapsed = now() - started
        if elapsed >= timeout:
            return False
        if not killed and elapsed >= kill_after:
            for identity in remaining:
                if now() >= deadline:
                    return False
                signal_identity(identity, signal.SIGKILL, roots, kill=kill, deadline=deadline, clock=now, **read)
            killed = True
        left = deadline - now()
        if left <= 0:
            return False
        pause(min(0.1, left))
