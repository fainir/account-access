"""Standard-library-only installer, extracted from the checksum-verified wheel.

Each repair prepares a separate environment. Only its owned launcher is replaced;
the previous environment is retained so existing clients and rollback still work.
"""

import hashlib
import fcntl
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import re
import stat
import subprocess
import sys
import tempfile


MARKER = "# account-access-runtime-launcher-v1"
DESKTOP_MARKER = "# account-access-launcher-v1"
INSTALLATION_MARKER = "account-access-runtime-v1"


def installation_snapshot(path):
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
            or info.st_nlink != 1 or info.st_size > 1024):
        raise RuntimeError("The installed payload record is not private.")
    data = path.read_bytes()
    try:
        value = json.loads(data)
        if (not isinstance(value, dict)
                or value.get("managed_by") != INSTALLATION_MARKER or type(value.get("schema")) is not int
                or value["schema"] not in {1, 2} or not isinstance(value.get("wheel_sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", value["wheel_sha256"])):
            raise ValueError()
        keys = {"managed_by", "schema", "wheel_sha256"}
        if value["schema"] == 2:
            keys |= {"runtime", "launcher_sha256"}
            executable = value.get("runtime")
            if (not isinstance(executable, str) or not executable.startswith("/")
                    or "\0" in executable or ".." in Path(executable).parts
                    or str(Path(executable)) != executable
                    or Path(executable).parent.name != "bin"
                    or Path(executable).parent.parent.parent.resolve() != (path.absolute().parent / "environments").resolve()
                    or not re.fullmatch(r"python(?:3(?:\.[0-9]+)?)?", Path(executable).name)
                    or not isinstance(value.get("launcher_sha256"), str)
                    or not re.fullmatch(r"[a-f0-9]{64}", value["launcher_sha256"])):
                raise ValueError()
        if set(value) != keys:
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise RuntimeError("Another file owns the installed payload record.") from None
    return data


def write_installation(path, data):
    descriptor, name = tempfile.mkstemp(prefix=".account-access-payload-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def installation_directory(path, *, private=True):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & (0o077 if private else 0o022)):
        raise RuntimeError("The installation directory is not private or owned by this user.")


def active_runtime_launcher(executable):
    """Use the activated runtime when an older managed client needs startup.

    This validates the installer transaction, not all installed code. OS identity
    separation is still required against an unrestricted same-user process.
    """
    python = Path(executable)
    environment = python.parent.parent
    if (python.parent.name != "bin" or environment.parent.name != "environments"
            or not environment.name.startswith("account-access-")
            or not re.fullmatch(r"python(?:3(?:\.[0-9]+)?)?", python.name)):
        return None  # Ordinary developer/standalone installations keep their path.
    runtime = environment.parent.parent
    try:
        installation_directory(runtime)
        snapshot = installation_snapshot(runtime / "installed-wheel.json")
        value = json.loads(snapshot) if snapshot else {}
        if value.get("schema") != 2:
            raise ValueError()
        activated = Path(value["runtime"])
        for path in [runtime / "environments", activated.parent.parent]:
            installation_directory(path)
        for path in [activated.parent, runtime / "bin"]:
            installation_directory(path, private=False)
        if not activated.is_file() or not os.access(activated, os.X_OK):
            raise ValueError()
        launcher = runtime / "bin/account-access"
        info = launcher.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_size > 8192):
            raise ValueError()
        data = launcher.read_bytes()
        expected = launcher_content([str(activated), "-I", "-m", "account_access.cli"], MARKER)
        if (data != expected or hashlib.sha256(data).hexdigest() != value["launcher_sha256"]):
            raise ValueError()
        return launcher
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        raise RuntimeError("The activated runtime needs installation repair.") from None


def launcher_snapshot(path, runtime):
    if path.is_symlink():
        if path.lstat().st_uid != os.getuid():
            raise RuntimeError("The runtime launcher is not owned by this user.")
        target = os.readlink(path)
        expected = runtime / "tools/account-access/bin/account-access"
        if (path.parent / target).resolve() != expected.resolve():
            raise RuntimeError("Another application owns the runtime launcher. Installation stopped.")
        return ("symlink", target)
    if path.exists():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink != 1 or info.st_size > 8192):
            raise RuntimeError("The runtime launcher is not private.")
        data = path.read_bytes()
        if MARKER.encode() not in data.splitlines()[:3]:
            raise RuntimeError("Another application owns the runtime launcher. Installation stopped.")
        return ("file", data)
    return None


def launcher_content(command, marker):
    return ("#!/bin/sh\n" + marker + "\nexec " + shlex.join(command) + ' "$@"\n').encode()


def write_launcher(path, command, marker):
    data = launcher_content(command, marker)
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
    if sys.platform == "darwin":
        version = platform.mac_ver()[0]
        if not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]+){0,2}", version) or int(version.split(".")[0]) < 14:
            raise RuntimeError("Account Access requires macOS 14 (Sonoma) or later.")
        if platform.machine() != "arm64":
            raise RuntimeError("This Account Access runtime requires an Apple silicon (M-series) Mac. "
                               "Intel Macs are not supported. On an M-series Mac, reopen the installer outside Rosetta.")
    runtime = Path(os.path.abspath(runtime))
    if runtime.is_symlink():
        raise RuntimeError("Refusing a linked installation directory.")
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    installation_directory(runtime)
    descriptor = os.open(runtime / ".install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
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
        installation_directory(directory, private=directory != launcher.parent)
    previous = launcher_snapshot(launcher, runtime)
    installation = runtime / "installed-wheel.json"
    previous_installation = installation_snapshot(installation)
    desktop = Path.home() / "Applications/Account Access.command"
    if desktop.is_symlink() or (desktop.exists() and DESKTOP_MARKER not in desktop.read_text()):
        raise RuntimeError("Another file owns the desktop launcher. Installation stopped.")
    previous_desktop = ("file", desktop.read_bytes()) if desktop.exists() else None
    environment = Path(tempfile.mkdtemp(prefix="account-access-", dir=runtime / "environments"))
    activated = False
    switched = False
    stopped = False
    payload_recorded = False
    desktop_switched = False
    replacement_stopped = True
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
        replacement_stopped = False
        run([str(launcher), *root_args, "start", *(["--no-open"] if no_open else [])],
            check=True, env=env)
        desktop.parent.mkdir(parents=True, exist_ok=True)
        write_launcher(desktop, [str(launcher), *root_args, "start"], DESKTOP_MARKER)
        desktop_switched = True
        write_installation(installation, json.dumps({"managed_by": INSTALLATION_MARKER, "schema": 2,
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(), "runtime": str(python),
            "launcher_sha256": hashlib.sha256(launcher.read_bytes()).hexdigest()}).encode())
        payload_recorded = True
        activated = True
        print("Installation complete. Your saved accounts are preserved.", flush=True)
    except Exception:
        if payload_recorded:
            if previous_installation is None:
                installation.unlink(missing_ok=True)
            else:
                write_installation(installation, previous_installation)
        if switched:
            # A partially started replacement must release the saved service
            # before the old installation is restarted.
            try:
                run([str(launcher), *root_args, "stop"], check=True, env=env)
                replacement_stopped = True
            except Exception:
                print("The replacement could not confirm that it stopped. Its runtime was kept. "
                      "Reopen Account Access to repair.", flush=True)
            restore_launcher(launcher, previous)
        if desktop_switched:
            restore_launcher(desktop, previous_desktop)
        if stopped and previous is not None and replacement_stopped:
            try:
                run([str(launcher), *root_args, "start", "--no-open"], check=True, env=env)
            except Exception:
                print("The previous installation is preserved. Reopen Account Access to resume.", flush=True)
        raise
    finally:
        # A failed start may still have launched the service. Never remove its
        # executable/dependencies or start a second runtime until stop succeeds.
        if not activated and replacement_stopped:
            shutil.rmtree(environment)


if __name__ == "__main__":
    try:
        install(*sys.argv[1:5], data_dir=sys.argv[5], no_open=sys.argv[6] == "1")
    except Exception:
        # Avoid printing inherited environment, account data or subprocess output.
        print("Installation failed. Existing accounts and the previous runtime were preserved.", file=sys.stderr)
        raise SystemExit(1) from None
