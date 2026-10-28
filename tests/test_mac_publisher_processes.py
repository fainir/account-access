"""Pure public process identities; never inspect or signal a live process."""

import ctypes
from dataclasses import FrozenInstanceError, replace
import errno
import importlib.util
from pathlib import Path
import signal
from types import SimpleNamespace

import pytest

from scripts import mac_publisher_processes as processes


ROOTS = ("/Library/Application Support/Account Access", "/Applications/Google Chrome.app")
PATH = ROOTS[1] + "/Contents/MacOS/Google Chrome"
IDENTITY = processes.ProcessIdentity(1234, 501, 1700000000, 123456, PATH)


def bsd(identity=IDENTITY, *, ruid=None):
    return processes._BSDIdentity(identity.pid, identity.uid, identity.uid if ruid is None else ruid,
                                  identity.start_sec, identity.start_usec)


def readers(info=None, path=PATH):
    return {"bsd_reader": lambda pid: bsd() if info is None else info,
            "path_reader": lambda pid: path}


def test_import_never_loads_libproc_scans_processes_or_signals(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("import must be inert")
    monkeypatch.setattr(processes.ctypes, "CDLL", forbidden)
    monkeypatch.setattr(processes.subprocess, "run", forbidden)
    monkeypatch.setattr(processes.os, "kill", forbidden)
    spec = importlib.util.spec_from_file_location("public_process_import", Path(processes.__file__))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.PROC_PIDTBSDINFO == 3


def test_bsd_structure_matches_current_public_clt_native_layout():
    assert ctypes.sizeof(processes._ProcBSDInfo) == 136
    assert processes._ProcBSDInfo.pbi_uid.offset == 20
    assert processes._ProcBSDInfo.pbi_ruid.offset == 28
    assert processes._ProcBSDInfo.pbi_start_tvsec.offset == 120
    assert processes._ProcBSDInfo.pbi_start_tvusec.offset == 128


def test_snapshot_is_immutable_and_reads_identity_on_both_sides_of_kernel_path():
    calls = []
    def info(pid):
        calls.append(("bsd", pid))
        return bsd()
    def path(pid):
        calls.append(("path", pid))
        return PATH
    found = processes.snapshot(501, ROOTS, scanner=lambda: [1, 1234], bsd_reader=info, path_reader=path)
    assert found == (IDENTITY,)
    assert calls == [("bsd", 1234), ("path", 1234), ("bsd", 1234)]
    with pytest.raises(FrozenInstanceError):
        found[0].pid = 99


@pytest.mark.parametrize("uid", [0, -1, True, "501", 2**32])
def test_invalid_uid_refused_before_any_process_query(uid):
    with pytest.raises(processes.ProcessInspectionError, match="^process_uid_invalid$"):
        processes.snapshot(uid, ROOTS, scanner=lambda: pytest.fail("must not scan"))


@pytest.mark.parametrize("roots", [(), ("/",), ("/Applications",), (ROOTS[0] + "/../Other",),
                                   (ROOTS[0], ROOTS[0]), ("/Applications/Google Chrome.app/",)])
def test_only_exact_canonical_review_roots_allowed(roots):
    with pytest.raises(processes.ProcessInspectionError, match="^process_roots_invalid$"):
        processes.snapshot(501, roots, scanner=lambda: pytest.fail("must not scan"))


@pytest.mark.parametrize("path", [ROOTS[1], ROOTS[1] + "-other/Contents/MacOS/Chrome", "/tmp/Google Chrome",
                                  ROOTS[0] + "-old/runtime/python", ROOTS[0] + "/../Other/python",
                                  ROOTS[0] + "/./runtime/python", ROOTS[0] + "//runtime/python",
                                  ROOTS[0] + "/runtime/py\x00thon", "relative/python"])
def test_kernel_path_prefix_collisions_and_lexical_escapes_never_selected(path):
    assert processes.snapshot(501, ROOTS, scanner=lambda: [1234], **readers(path=path)) == ()


@pytest.mark.parametrize("field,value", [("pid", 1235), ("uid", 502), ("ruid", 0)])
def test_wrong_kernel_pid_effective_or_real_uid_never_reads_path(field, value):
    changed = replace(bsd(), **{field: value})
    assert processes.snapshot(501, ROOTS, scanner=lambda: [1234], bsd_reader=lambda pid: changed,
                              path_reader=lambda pid: pytest.fail("foreign process path")) == ()


@pytest.mark.parametrize("field,value", [("pid", 1235), ("uid", 502), ("ruid", 502),
                                         ("start_sec", 1700000001), ("start_usec", 123457)])
def test_double_read_pid_reuse_or_identity_race_discarded(field, value):
    observations = iter([bsd(), replace(bsd(), **{field: value})])
    assert processes.snapshot(501, ROOTS, scanner=lambda: [1234],
                              bsd_reader=lambda pid: next(observations), path_reader=lambda pid: PATH) == ()


@pytest.mark.parametrize("operation", ["snapshot", "matches", "stop"])
def test_unreadable_path_for_still_live_identity_is_inspection_failure(operation):
    options = readers(path=None)
    with pytest.raises(processes.ProcessInspectionError, match="^process_path_read_failed$"):
        if operation == "snapshot":
            processes.snapshot(501, ROOTS, scanner=lambda: [1234], **options)
        elif operation == "matches":
            processes.matches(IDENTITY, ROOTS, **options)
        else:
            processes.stop([IDENTITY], ROOTS, **options, kill=lambda *args: pytest.fail("unreadable process"))


@pytest.mark.parametrize("after", [None, replace(bsd(), start_usec=123457)])
def test_unreadable_path_only_counts_as_gone_after_bsd_disappearance_or_reuse(after):
    observations = iter([bsd(), after])
    assert processes.matches(IDENTITY, ROOTS, bsd_reader=lambda pid: next(observations),
                             path_reader=lambda pid: None) is False


@pytest.mark.parametrize("changed", [replace(IDENTITY, uid=502), replace(IDENTITY, start_sec=1700000001),
                                     replace(IDENTITY, start_usec=123457),
                                     replace(IDENTITY, path=ROOTS[0] + "/runtime/bin/python")])
def test_changed_identity_never_signalled(changed):
    assert processes.signal_identity(IDENTITY, signal.SIGTERM, ROOTS,
        **readers(info=bsd(changed), path=changed.path), kill=lambda *args: pytest.fail("reused process")) is False


def test_signal_rechecks_immediately_before_kill_and_never_uses_process_group():
    calls = []
    assert processes.signal_identity(IDENTITY, signal.SIGTERM, ROOTS,
        bsd_reader=lambda pid: calls.append("bsd") or bsd(),
        path_reader=lambda pid: calls.append("path") or PATH,
        kill=lambda pid, sig: calls.append((pid, sig))) is True
    assert calls == ["bsd", "path", "bsd", (IDENTITY.pid, signal.SIGTERM)]


@pytest.mark.parametrize("signum", [0, 1, -1, True, 15.0, "TERM"])
def test_only_term_and_kill_allowed(signum):
    with pytest.raises(processes.ProcessInspectionError, match="^process_signal_invalid$"):
        processes.signal_identity(IDENTITY, signum, ROOTS, kill=lambda *args: pytest.fail("invalid signal"))


def test_disappearance_between_last_check_and_signal_is_harmless():
    def gone(*args):
        raise ProcessLookupError()
    assert processes.signal_identity(IDENTITY, signal.SIGTERM, ROOTS, **readers(), kill=gone) is False


def test_permission_error_is_fixed_failure_and_not_disappearance():
    def denied(*args):
        raise PermissionError("fictional diagnostic must not escape")
    with pytest.raises(processes.ProcessInspectionError, match="^process_signal_failed$"):
        processes.signal_identity(IDENTITY, signal.SIGTERM, ROOTS, **readers(), kill=denied)


def test_kernel_unknown_failure_not_counted_as_process_gone(monkeypatch):
    def failed(*args):
        ctypes.set_errno(errno.EPERM)
        return 0
    monkeypatch.setattr(processes, "_libproc", lambda: SimpleNamespace(proc_pidinfo=failed, proc_pidpath=failed))
    for operation in [processes._bsd, processes._kernel_path]:
        with pytest.raises(processes.ProcessInspectionError):
            operation(1234)


def test_kernel_esrch_is_process_disappearance(monkeypatch):
    def gone(*args):
        ctypes.set_errno(errno.ESRCH)
        return 0
    monkeypatch.setattr(processes, "_libproc", lambda: SimpleNamespace(proc_pidinfo=gone, proc_pidpath=gone))
    assert processes._bsd(1234) is None
    assert processes._kernel_path(1234) is None


def test_scanner_uses_only_numeric_pids_fixed_environment_and_bounded_command(monkeypatch):
    def scan(arguments, **kwargs):
        assert arguments == ["/bin/ps", "-axo", "pid="]
        assert kwargs == {"capture_output": True, "timeout": 5, "close_fds": True,
                          "env": {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}}
        return SimpleNamespace(returncode=0, stdout=b" 1\n 1234\n", stderr=b"")
    monkeypatch.setattr(processes.subprocess, "run", scan)
    assert processes._scan() == (1, 1234)


@pytest.mark.parametrize("pids", [[0], [-1], [True], ["1234"], [1234, 1234], [{}]])
def test_malformed_injected_scanner_fails_closed(pids):
    with pytest.raises(processes.ProcessInspectionError, match="^process_scan_failed$"):
        processes.snapshot(501, ROOTS, scanner=lambda: pids)


def test_preexisting_snapshot_identities_can_be_excluded_before_cleanup():
    other = replace(IDENTITY, pid=2345, start_usec=123457)
    current = (IDENTITY, other)
    baseline = frozenset([IDENTITY])
    assert tuple(identity for identity in current if identity not in baseline) == (other,)


@pytest.mark.parametrize("exits_after", [signal.SIGTERM, signal.SIGKILL, None])
def test_stop_terms_then_bounded_kills_only_frozen_matching_identity(exits_after):
    clock, alive, calls = [0.0], [True], []
    def kill(pid, signum):
        calls.append((pid, signum))
        if signum == exits_after:
            alive[0] = False
    def sleep(seconds):
        clock[0] += seconds
    assert processes.stop([IDENTITY], ROOTS, timeout=2, kill_after=0.5,
        bsd_reader=lambda pid: bsd() if alive[0] else None, path_reader=lambda pid: PATH,
        kill=kill, clock=lambda: clock[0], sleep=sleep) is (exits_after is not None)
    assert calls == [(1234, signal.SIGTERM)] + ([] if exits_after == signal.SIGTERM else [(1234, signal.SIGKILL)])
    assert clock[0] <= 2


def test_stop_leaves_reused_pid_untouched_and_stops_observing_old_identity():
    calls = []
    assert processes.stop([IDENTITY], ROOTS, **readers(info=bsd(replace(IDENTITY, start_sec=1700000001))),
                          kill=lambda *args: calls.append(args)) is True
    assert calls == []


@pytest.mark.parametrize("phase", ["term", "scan", "kill"])
def test_stop_deadline_checked_inside_each_fanout_and_after_slow_kernel_reads(phase):
    identities = tuple(replace(IDENTITY, pid=pid) for pid in [1234, 2345, 3456])
    clock, signals, reads = [0.0], [], []

    def info(pid):
        # TERM: consume the budget during the second identity's initial
        # recheck. Scan: after all TERMs, during the first remaining check.
        # KILL: after its first signal, during the second identity's recheck.
        term_count = sum(signum == signal.SIGTERM for _, signum, _ in signals)
        kill_count = sum(signum == signal.SIGKILL for _, signum, _ in signals)
        slow = ((phase == "term" and pid == 2345) or
                (phase == "scan" and term_count == 3) or
                (phase == "kill" and kill_count == 1))
        reads.append(pid)
        if slow:
            clock[0] += 0.6
        return bsd(replace(IDENTITY, pid=pid))

    stopped = processes.stop(identities, ROOTS, timeout=1, kill_after=0,
        bsd_reader=info, path_reader=lambda pid: PATH,
        kill=lambda pid, signum: signals.append((pid, signum, clock[0])),
        clock=lambda: clock[0], sleep=lambda seconds: pytest.fail("budget already consumed"))
    assert stopped is False
    assert all(at < 1 for _, _, at in signals)
    if phase == "term":
        assert signals == [(1234, signal.SIGTERM, 0.0)]
        assert 3456 not in reads
    elif phase == "scan":
        assert signals == [(item.pid, signal.SIGTERM, 0.0) for item in identities]
        # No second remaining identity is inspected after the first exhausts
        # the deadline: each identity had exactly two initial TERM reads.
        assert reads.count(2345) == reads.count(3456) == 2
    else:
        assert signals == [(item.pid, signal.SIGTERM, 0.0) for item in identities] + [(1234, signal.SIGKILL, 0.0)]
        assert reads.count(3456) == 4  # TERM + remaining scan, no late KILL read.


def test_signal_with_expired_budget_never_reads_or_signals_live_identity():
    assert processes.signal_identity(IDENTITY, signal.SIGTERM, ROOTS, deadline=1, clock=lambda: 1,
        bsd_reader=lambda pid: pytest.fail("expired identity query"),
        kill=lambda *args: pytest.fail("expired signal")) is False


@pytest.mark.parametrize("identities,options", [([replace(IDENTITY, uid=0)], {}), ([IDENTITY, IDENTITY], {}),
    ([IDENTITY], {"timeout": 0}), ([IDENTITY], {"timeout": 11}), ([IDENTITY], {"kill_after": 5}),
    ([IDENTITY], {"timeout": float("nan")}), ([IDENTITY], {"timeout": True})])
def test_stop_refuses_invalid_identity_or_unbounded_timing(identities, options):
    with pytest.raises(processes.ProcessInspectionError, match="^process_stop_invalid$"):
        processes.stop(identities, ROOTS, **options, kill=lambda *args: pytest.fail("invalid cleanup"))
