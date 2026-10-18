"""SIGKILL private-directory publication only inside a disposable Mac CI prefix.

This creates empty synthetic directories for the fixture's already-created
service identity. It never opens a credential store or changes a user account.
"""

import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import uuid

from account_access.system_provision import _private_stage_name, private_directory
from account_access.worker_bootstrap import root_managed_path

BOUNDARIES = {
    "stage-created": "private_directory_crash_after_stage_creation_recovers",
    "directory-created": "private_directory_crash_after_directory_creation_recovers",
    "ownership-set": "private_directory_crash_after_ownership_change_recovers",
    "directory-published": "private_directory_crash_after_final_publication_recovers",
    "stage-removed": "private_directory_crash_after_staging_cleanup_recovers",
}


def require_context(prefix, uid):
    if (sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or type(uid) is not int or not 450 <= uid < 500):
        raise RuntimeError("disposable_private_directory_probe_required")
    prefix = Path(prefix)
    if (prefix.parent != Path("/Library/PrivilegedHelperTools")
            or re.fullmatch(r"account-access-worker-qa-[A-Za-z0-9]{8,64}", prefix.name) is None):
        raise RuntimeError("disposable_private_directory_probe_required")
    root_managed_path(prefix)
    return prefix


def child(target, uid, boundary):
    target = Path(target)
    prefix = require_context(target.parents[2], uid)
    if (target.parent != prefix / "provisioned/broker"
            or re.fullmatch(r"private-directory-qa-[a-f0-9]{32}", target.name) is None
            or boundary not in BOUNDARIES):
        raise RuntimeError("disposable_private_directory_probe_required")

    def checkpoint(event):
        if event == boundary:
            os.write(1, b"CHECKPOINT\n")
            # The parent observes a completed boundary, then kills this actual
            # process. No exception/finally cleanup simulates the interruption.
            while True:
                signal.pause()

    private_directory(target, uid, staging=target.parent, checkpoint=checkpoint)
    raise RuntimeError("private_directory_checkpoint_not_reached")


def check_recovery(prefix, uid):
    prefix = require_context(prefix, uid)
    broker = prefix / "provisioned/broker"
    root_managed_path(broker)
    helper = prefix / "private-directory-probe.py"
    root_managed_path(helper)
    checks = {}
    same_inode = exact_identity = no_intermediates = True
    for boundary, name in BOUNDARIES.items():
        target = broker / ("private-directory-qa-" + uuid.uuid4().hex)
        if os.path.lexists(target):
            raise RuntimeError("private_directory_probe_collision")
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(helper), "--child", str(target), str(uid), boundary],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "GITHUB_ACTIONS": "true"}, close_fds=True,
        )
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                if not ready.select(15) or os.read(process.stdout.fileno(), 64) != b"CHECKPOINT\n":
                    raise RuntimeError("private_directory_checkpoint_not_reached")
            process.kill()
            process.wait(timeout=10)
            if process.returncode != -signal.SIGKILL:
                raise RuntimeError("private_directory_child_not_killed")
            before = target.stat().st_ino if target.exists() else None
            private_directory(target, uid, staging=broker)
            first = target.stat()
            private_directory(target, uid, staging=broker)
            repeated = target.stat()
            same_inode &= (before is None or before == first.st_ino) and first.st_ino == repeated.st_ino
            exact_identity &= (stat.S_ISDIR(first.st_mode) and first.st_uid == uid
                               and first.st_gid == uid and stat.S_IMODE(first.st_mode) == 0o700)
            no_intermediates &= not os.path.lexists(broker / _private_stage_name(target, uid))
            checks[name] = True
            # Remove only the exact empty synthetic final; rmdir cannot erase
            # private contents if another process has added anything.
            os.rmdir(target)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            process.stdout.close()
            process.stderr.close()
    checks["private_directory_recovery_preserves_published_inode"] = same_inode
    checks["private_directory_recovery_sets_exact_private_identity"] = exact_identity
    checks["private_directory_recovery_leaves_no_intermediates"] = no_intermediates
    if not all(checks.values()):
        raise RuntimeError("private_directory_recovery_failed")
    return checks


def main():
    try:
        if len(sys.argv) != 5 or sys.argv[1] != "--child" or not sys.argv[3].isdecimal():
            raise RuntimeError("disposable_private_directory_probe_required")
        child(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    except Exception:
        return 78
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
