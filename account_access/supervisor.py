"""Supervise the local desktop service without loading its vault key.

This is process recovery under the current user's identity, not an OS credential
isolation boundary. Only the child process we created may be terminated. An
existing service is observed through its authenticated readiness response and
service lease; a PID or metadata file alone never proves it is running.
"""

import hashlib
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from filelock import FileLock, Timeout

from . import __version__
from .errors import AccessError
from .storage import check_private, private_file


def private_regular(path):
    check_private(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise AccessError("DENIED", "unsafe_service_control_file")


@contextmanager
def lease(root, name="desktop-supervisor", timeout=0):
    check_private(root)
    directory = root / "locks"
    directory.mkdir(mode=0o700, exist_ok=True)
    check_private(directory)
    path = directory / (hashlib.sha256(name.encode()).hexdigest() + ".lock")
    if path.exists() or path.is_symlink():
        private_regular(path)
    try:
        with FileLock(path, timeout=timeout, mode=0o600):
            private_regular(path)
            yield
    except Timeout:
        raise AccessError("RETRYABLE", "account_busy") from None


def attached(root):
    try:
        with lease(root):
            return False
    except AccessError as exc:
        if exc.reason != "account_busy":
            raise
        return True


def registration(root):
    path = root / "supervisor.json"
    fd = None
    try:
        # Pin one inode: Pause may unlink the generation while we read it.
        # A removed/replaced generation is inactive, not an unsafe live file.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if info.st_nlink == 0:
            return None
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_mode & 0o077 or info.st_uid != os.getuid()):
            raise AccessError("DENIED", "unsafe_service_control_file")
        if not 0 < info.st_size <= 4096:
            raise ValueError()
        data = bytearray()
        while len(data) <= 4096:
            part = os.read(fd, 4097 - len(data))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        if after.st_nlink == 0:
            return None
        named = path.lstat()
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            # A replaced path must not activate the old open generation.
            # Validate the replacement on the next read, without following it.
            return None
        if (after.st_nlink != 1 or after.st_mode != info.st_mode
                or after.st_uid != info.st_uid or len(data) != info.st_size
                or after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns):
            raise AccessError("DENIED", "unsafe_service_control_file")
        value = json.loads(data)
        if (not isinstance(value, dict) or set(value) != {"generation", "runtime", "version"}
                or not isinstance(value["generation"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", value["generation"])
                or not all(isinstance(value[k], str) and value[k] for k in ["runtime", "version"])):
            raise ValueError()
        return value
    except FileNotFoundError:
        return None
    except OSError:
        raise AccessError("DENIED", "unsafe_service_control_file") from None
    except (ValueError, TypeError):
        raise AccessError("NEEDS_USER", "invalid_service_supervision") from None
    finally:
        if fd is not None:
            os.close(fd)


def enable(root):
    generation = secrets.token_hex(32)
    path = root / "supervisor.json"
    if path.exists() or path.is_symlink():
        private_regular(path)
    private_file(path, json.dumps({"generation": generation, "runtime": sys.executable,
                                  "version": __version__}).encode(), replace=path.exists())
    return generation


def disable(root):
    path = root / "supervisor.json"
    if path.exists() or path.is_symlink():
        private_regular(path)
        path.unlink()


def active(root, generation):
    if (root / "service.paused").exists() or (root / "service.paused").is_symlink():
        return False
    saved = registration(root)
    return bool(saved and saved["generation"] == generation and saved["runtime"] == sys.executable
                and saved["version"] == __version__)


def spawn(root, action, *, key_file=None, generation=None, detached=False):
    if action not in {"desktop-host", "desktop-supervisor"} or generation is None:
        raise AccessError("DENIED", "invalid_service_process")
    command = [sys.executable, "-I", "-m", "account_access.cli", "--root", str(root)]
    if key_file:
        command += ["--development", "--key-file", str(key_file)]
    command += [action, "--generation", generation]
    log_path = root / "desktop.log"
    if not log_path.exists():
        private_file(log_path, b"")
    private_regular(log_path)
    environment = dict(os.environ)
    environment.pop("ACCESS_CLIENT_CONFIG", None)
    with log_path.open("ab") as log:
        return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                start_new_session=detached, env=environment)


def supervise(root, generation, *, key_file=None):
    from .desktop import running
    root = Path(root).expanduser()
    check_private(root)
    root = root.resolve()
    for name in ["config.json", "state.db"]:
        private_regular(root / name)
    stopped = threading.Event()
    with lease(root):
        previous = {}
        child = None
        try:
            for sig in [signal.SIGTERM, signal.SIGINT]:
                previous[sig] = signal.signal(sig, lambda *_: stopped.set())
            failures = 0
            while not stopped.is_set() and active(root, generation):
                # Adopt no PID and terminate no unrelated process. If the
                # authenticated existing service is temporarily unreachable,
                # its held lease still prevents spawning a competing host.
                if running(root):
                    stopped.wait(0.5)
                    continue
                try:
                    with lease(root, "service"):
                        pass
                except AccessError as exc:
                    if exc.reason != "account_busy":
                        raise
                    stopped.wait(0.5)
                    continue
                if stopped.is_set() or not active(root, generation):
                    break
                started = time.monotonic()
                child = spawn(root, "desktop-host", key_file=key_file, generation=generation)
                while child.poll() is None and not stopped.is_set() and active(root, generation):
                    stopped.wait(0.25)
                if child.poll() is None:
                    break
                code = child.returncode
                child = None  # poll reaped our exited child; never signal its former PID.
                if code == 78:
                    # Locked/missing keyring or invalid setup needs the owner.
                    # Do not turn an owner-authentication prompt into a loop.
                    if active(root, generation):
                        disable(root)
                    break
                failures = 1 if time.monotonic() - started >= 30 else min(failures + 1, 6)
                deadline = time.monotonic() + min(30, 2 ** (failures - 1))
                while time.monotonic() < deadline and not stopped.is_set() and active(root, generation):
                    stopped.wait(min(0.25, max(0, deadline - time.monotonic())))
        finally:
            # Holding the lease through child reaping makes stop/rollback's
            # quiescence check meaningful even before a new host acquired its
            # own service lease. A pending child must not outlive this lease.
            try:
                if child is not None and child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)


def guard_desktop(root, generation, *, key_file=None):
    """OS-managed standby: take over only after the existing supervisor exits.

    A normal exit tells the OS not to restart a paused or owner-blocked job.
    Waiting for the actual lease avoids adopting/signalling a guessed PID.
    """
    root = Path(root).expanduser()
    check_private(root)
    root = root.resolve()
    while active(root, generation):
        try:
            supervise(root, generation, key_file=key_file)
        except AccessError as exc:
            if exc.reason != "account_busy":
                raise
            time.sleep(0.5)
        else:
            return
