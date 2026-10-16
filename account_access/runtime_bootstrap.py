"""Standard-library-only installer, extracted from the checksum-verified wheel.

Each repair prepares a separate environment. Only its owned launcher is replaced;
the previous environment is retained so existing clients and rollback still work.
"""

import hashlib
import fcntl
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


MARKER = "# account-access-runtime-launcher-v1"
DESKTOP_MARKER = "# account-access-launcher-v1"


def launcher_snapshot(path, runtime):
    if path.is_symlink():
        target = os.readlink(path)
        expected = runtime / "tools/account-access/bin/account-access"
        if (path.parent / target).resolve() != expected.resolve():
            raise RuntimeError("Another application owns the runtime launcher. Installation stopped.")
        return ("symlink", target)
    if path.exists():
        data = path.read_bytes()
        if MARKER.encode() not in data.splitlines()[:3]:
            raise RuntimeError("Another application owns the runtime launcher. Installation stopped.")
        return ("file", data)
    return None


def write_launcher(path, command, marker):
    data = ("#!/bin/sh\n" + marker + "\nexec " + shlex.join(command) + ' "$@"\n').encode()
    descriptor, name = tempfile.mkstemp(prefix=".account-access-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.chmod(name, 0o700)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def restore_launcher(path, snapshot):
    if snapshot is None:
        path.unlink(missing_ok=True)
    elif snapshot[0] == "symlink":
        path.unlink(missing_ok=True)
        path.symlink_to(snapshot[1])
    else:
        descriptor, name = tempfile.mkstemp(prefix=".account-access-rollback-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(snapshot[1])
            os.chmod(name, 0o700)
            os.replace(name, path)
        finally:
            Path(name).unlink(missing_ok=True)


def install(uv, wheel, runtime, requirements, *, data_dir="", no_open=False, run=subprocess.run):
    runtime = Path(runtime).absolute()
    if runtime.is_symlink():
        raise RuntimeError("Refusing a linked installation directory.")
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(runtime / ".install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise RuntimeError("The installation lock is not private.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another Account Access installation is running.") from None
        _install(uv, wheel, runtime, requirements, data_dir=data_dir, no_open=no_open, run=run)
    finally:
        os.close(descriptor)


def _install(uv, wheel, runtime, requirements, *, data_dir, no_open, run):
    runtime = Path(runtime).absolute()
    wheel = Path(wheel).absolute()
    launcher = runtime / "bin/account-access"
    for directory in [runtime, launcher.parent, runtime / "environments"]:
        if directory.is_symlink():
            raise RuntimeError("Refusing a linked installation directory.")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    previous = launcher_snapshot(launcher, runtime)
    desktop = Path.home() / "Applications/Account Access.command"
    if desktop.is_symlink() or (desktop.exists() and DESKTOP_MARKER not in desktop.read_text()):
        raise RuntimeError("Another file owns the desktop launcher. Installation stopped.")
    environment = Path(tempfile.mkdtemp(prefix="account-access-", dir=runtime / "environments"))
    activated = False
    switched = False
    stopped = False
    env = {k: v for k, v in os.environ.items()
           if k not in {"PYTHONPATH", "PYTHONHOME", "UV_NO_VERIFY_HASHES", "UV_INSECURE_HOST",
                        "UV_OVERRIDE", "UV_EXCLUDE", "UV_CONSTRAINT", "UV_BUILD_CONSTRAINT"}}
    root_args = ["--root", data_dir] if data_dir else []
    try:
        python = environment / "bin/python"
        run([str(uv), "venv", "--no-config", "--python", "3.13", str(environment)],
            check=True, env=env)
        # Wheel and every transitive dependency require an approved SHA-256.
        # No source-distribution build code runs during installation.
        locked = environment / "requirements.txt"
        locked.write_text(Path(requirements).read_text() + "\n" + wheel.as_uri()
                          + " --hash=sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest() + "\n")
        os.chmod(locked, 0o600)
        run([str(uv), "pip", "sync", "--no-config", "--python", str(python),
             "--require-hashes", "--no-build", "--strict", str(locked)], check=True, env=env)
        print("4/4 Preparing website access…", flush=True)
        run([str(python), "-I", "-m", "playwright", "install", "chromium"], check=True, env=env)
        # Import health check runs before the saved service is interrupted.
        run([str(python), "-I", "-c", "import account_access.cli; import playwright.sync_api"],
            check=True, env=env)
        command = [str(python), "-I", "-m", "account_access.cli"]
        if previous is not None:
            run([str(launcher), *root_args, "stop"], check=True, env=env)
            stopped = True
        write_launcher(launcher, command, MARKER)
        switched = True
        run([str(launcher), *root_args, "start", *(["--no-open"] if no_open else [])],
            check=True, env=env)
        activated = True
        desktop.parent.mkdir(parents=True, exist_ok=True)
        write_launcher(desktop, [str(launcher), *root_args, "start"], DESKTOP_MARKER)
        print("Installation complete. Your saved accounts are preserved.", flush=True)
    except Exception:
        if switched:
            # A partially started replacement must release the saved service
            # before the old installation is restarted.
            try:
                run([str(launcher), *root_args, "stop"], check=True, env=env)
            except Exception:
                pass
            restore_launcher(launcher, previous)
        if stopped and previous is not None:
            try:
                run([str(launcher), *root_args, "start", "--no-open"], check=True, env=env)
            except Exception:
                print("The previous installation is preserved. Reopen Account Access to resume.", flush=True)
        raise
    finally:
        if not activated:
            shutil.rmtree(environment)


if __name__ == "__main__":
    try:
        install(*sys.argv[1:5], data_dir=sys.argv[5], no_open=sys.argv[6] == "1")
    except Exception:
        # Avoid printing inherited environment, account data or subprocess output.
        print("Installation failed. Existing accounts and the previous runtime were preserved.", file=sys.stderr)
        raise SystemExit(1) from None
