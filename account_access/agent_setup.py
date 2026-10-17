"""Owner-user half of isolated client setup. Never opens the broker store.

Production entrypoints use fixed installed locations, the OS account's home and
an immutable runtime. The native UI sends the locally generated capability to
its approved gateway; this helper's output never contains it.
"""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import sys

from .errors import AccessError
from .managed_client import identity
from .storage import private_file


BASE = Path("/Library/Application Support/Account Access")
RUNTIME = BASE / "runtime/bin/python"
SOCKET = BASE / "run/agent.sock"
RELATIVE = Path("Library/Application Support/Account Access/client-v1")
MARKER = "account-access-native-client-v1"


def _no_acl(fd):
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        libc.acl_get_fd.argtypes = [ctypes.c_int]
        libc.acl_get_fd.restype = ctypes.c_void_p
        libc.acl_free.argtypes = [ctypes.c_void_p]
        libc.acl_free.restype = ctypes.c_int
        ctypes.set_errno(0)
        value = libc.acl_get_fd(fd)
        if value:
            try:
                libc.acl_get_entry.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_int,
                    ctypes.POINTER(ctypes.c_void_p),
                ]
                libc.acl_get_entry.restype = ctypes.c_int
                libc.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
                libc.acl_get_tag_type.restype = ctypes.c_int
                entry, tag, position = ctypes.c_void_p(), ctypes.c_int(), 0
                while True:
                    ctypes.set_errno(0)
                    if libc.acl_get_entry(value, position, ctypes.byref(entry)) != 0:
                        if ctypes.get_errno() != errno.EINVAL:
                            raise AccessError("NEEDS_USER", "client_setup_permissions_need_review")
                        break
                    if libc.acl_get_tag_type(entry, ctypes.byref(tag)) != 0 or tag.value != 2:
                        raise AccessError("NEEDS_USER", "client_setup_permissions_need_review")
                    position = -1  # Darwin ACL_NEXT_ENTRY; allow restrictive deny entries only.
            finally:
                libc.acl_free(value)
            return
        if ctypes.get_errno() != errno.ENOENT:
            raise AccessError("NEEDS_USER", "client_setup_permissions_need_review")
    elif any(
        name in os.listxattr(fd) for name in ["system.posix_acl_access", "system.posix_acl_default"]
    ):
        raise AccessError("NEEDS_USER", "client_setup_permissions_need_review")


def _checked(path, *, directory=False, private=False, limit=65536):
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (
            info.st_uid != os.getuid()
            or (stat.S_IFMT(info.st_mode) != (stat.S_IFDIR if directory else stat.S_IFREG))
            or info.st_mode & (0o7077 if private else 0o7022)
            or (not directory and (info.st_nlink != 1 or info.st_size > limit))
        ):
            raise AccessError("NEEDS_USER", "client_setup_permissions_need_review")
        _no_acl(fd)
        if directory:
            return None
        data = os.read(fd, limit + 1)
        if len(data) > limit or len(data) != info.st_size:
            raise AccessError("NEEDS_USER", "client_setup_permissions_need_review")
        return data
    finally:
        os.close(fd)


def _directories(home, relative, *, create=False):
    _checked(home, directory=True)
    path = home
    for component in Path(relative).parts:
        if component in {".", "..", "/"}:
            raise AccessError("DENIED", "invalid_client_setup")
        path /= component
        try:
            _checked(path, directory=True)
        except FileNotFoundError:
            if not create:
                return path
            path.mkdir(mode=0o700)
            _checked(path, directory=True, private=True)
    return path


def _json(path, *, private=True):
    try:
        value = json.loads(_checked(path, private=private))
        if type(value) is not dict:
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise AccessError("NEEDS_USER", "client_setup_permissions_need_review") from None


def preflight(home, hosts):
    if (
        type(hosts) is not list
        or any(host not in {"codex", "claude"} for host in hosts)
        or len(hosts) != len(set(hosts))
    ):
        raise AccessError("DENIED", "invalid_client_setup")
    home = Path(home)
    _directories(home, RELATIVE)
    expected = home / RELATIVE / "client.json"
    targets = [Path(".agents/skills/account-access")]
    if "claude" in hosts:
        targets.append(Path(".claude/skills/account-access"))
    for relative in targets:
        _directories(home, relative)
        target = home / relative
        if target.exists():
            if _checked(target / ".account-access-install", private=True) != b"account-access-v1":
                raise AccessError("NEEDS_USER", "existing_skill_would_be_overwritten")
            if _json(target / "installation.json").get("client_config") != str(expected):
                raise AccessError("NEEDS_USER", "client_migration_required")
            for child in target.rglob("*"):
                _checked(child, directory=child.is_dir(), private=True)
    for host in hosts:
        directory = ".codex" if host == "codex" else ".claude"
        _directories(home, directory)
        names = (
            ["AGENTS.md", "AGENTS.override.md", "rules/account-access.rules"]
            if host == "codex"
            else ["CLAUDE.md"]
        )
        for name in names:
            _directories(home, Path(directory) / Path(name).parent)
            file = home / directory / name
            if file.exists() or file.is_symlink():
                _checked(file)
    return expected


def prepare(home, hosts, *, python=RUNTIME, socket=SOCKET):
    """Preflight all known targets before creating an unregistered capability."""
    home = Path(home)
    config = preflight(home, hosts)
    directory = _directories(home, RELATIVE, create=True)
    token_file = directory / "token"
    expected = {"socket": str(socket), "token_file": str(token_file), "auto_start": False}
    exists = token_file.exists() or token_file.is_symlink()
    if exists:
        token = _checked(token_file, private=True, limit=43).decode("ascii")
        client_id = identity(token)
    else:
        if config.exists() or config.is_symlink():
            raise AccessError("NEEDS_USER", "client_setup_needs_repair")
        token = secrets.token_urlsafe(32)
        private_file(token_file, token.encode())
        _checked(token_file, private=True, limit=43)
        client_id = identity(token)
    if config.exists() or config.is_symlink():
        if _json(config) != expected:
            raise AccessError("NEEDS_USER", "client_setup_needs_repair")
    else:
        private_file(config, json.dumps(expected).encode())
    return {"status": "PREPARED", "client_id": client_id}


def install(home, hosts, *, python=RUNTIME, socket=SOCKET):
    home = Path(home)
    prepared = prepare(home, hosts, python=python, socket=socket)
    config = home / RELATIVE / "client.json"
    from .client import Client

    # Confirm this exact locally held capability before publishing launchers.
    result = Client(config).request("GET", "/v1/accounts")
    if type(result) is not dict or type(result.get("accounts")) is not list:
        raise AccessError("NEEDS_USER", "client_connection_not_confirmed")
    from .install import sync_skill

    for relative in [
        Path(".agents/skills"),
        *([Path(".claude/skills")] if "claude" in hosts else []),
    ]:
        _directories(home, relative, create=True)
        sync_skill(home / relative / "account-access", config, python=python)
    from .integration import install_session_guidance

    automatic = install_session_guidance(home, hosts, home / ".codex")
    marker = home / RELATIVE / "installed.json"
    receipt = {
        "managed_by": MARKER,
        "schema": 1,
        "client_id": prepared["client_id"],
        "hosts": sorted(hosts),
        "python": str(python),
        "socket": str(socket),
    }
    private_file(marker, json.dumps(receipt).encode(), replace=marker.exists())
    return {
        "status": "INSTALLED",
        "client_id": prepared["client_id"],
        "hosts": sorted(hosts),
        "automatic_sessions": automatic,
    }


def status(home, hosts, *, python=RUNTIME, socket=SOCKET):
    config = preflight(home, hosts)
    path = Path(home) / RELATIVE / "installed.json"
    if not path.exists():
        return {"status": "NOT_INSTALLED"}
    receipt = _json(path)
    token_file = Path(home) / RELATIVE / "token"
    token = _checked(token_file, private=True, limit=43).decode("ascii")
    expected = {
        "managed_by": MARKER,
        "schema": 1,
        "client_id": identity(token),
        "hosts": sorted(hosts),
        "python": str(python),
        "socket": str(socket),
    }
    if receipt != expected or _json(config) != {
        "socket": str(socket),
        "token_file": str(token_file),
        "auto_start": False,
    }:
        return {"status": "NOT_INSTALLED"}
    for relative in [
        Path(".agents/skills"),
        *([Path(".claude/skills")] if "claude" in hosts else []),
    ]:
        target = Path(home) / relative / "account-access"
        if _json(target / "installation.json") != {
            "client_config": str(config),
            "python": str(python),
        }:
            return {"status": "NOT_INSTALLED"}
    from .install import launcher_text
    from .integration import codex_rule_block, session_guidance

    source = Path(__file__).resolve().parent / "skills/account-access"
    for relative in [
        Path(".agents/skills"),
        *([Path(".claude/skills")] if "claude" in hosts else []),
    ]:
        target = Path(home) / relative / "account-access"
        for template in source.rglob("*"):
            if template.is_file():
                destination = target / template.relative_to(source)
                expected = (
                    launcher_text(target, python).encode()
                    if template.relative_to(source) == Path("scripts/access")
                    else template.read_bytes()
                )
                if _checked(destination, private=True) != expected:
                    return {"status": "NOT_INSTALLED"}
    for host in hosts:
        directory = Path(home) / (".codex" if host == "codex" else ".claude")
        skill = Path(home) / (
            ".agents/skills/account-access" if host == "codex" else ".claude/skills/account-access"
        )
        files = [directory / ("AGENTS.md" if host == "codex" else "CLAUDE.md")]
        if host == "codex" and (directory / "AGENTS.override.md").exists():
            files.append(directory / "AGENTS.override.md")
        if any(session_guidance(skill) not in _checked(file).decode("utf-8") for file in files):
            return {"status": "NOT_INSTALLED"}
        if host == "codex" and codex_rule_block(skill) not in _checked(
            directory / "rules/account-access.rules"
        ).decode("utf-8"):
            return {"status": "NOT_INSTALLED"}
    return {"status": "INSTALLED", "client_id": receipt["client_id"], "hosts": sorted(hosts)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "install", "status"])
    args = parser.parse_args(argv)
    try:
        if sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid():
            raise AccessError("DENIED", "ordinary_owner_context_required")
        from .worker_bootstrap import root_managed_path

        if Path(sys.executable).resolve() != RUNTIME.resolve():
            raise AccessError("DENIED", "trusted_client_runtime_required")
        root_managed_path(RUNTIME)
        root_managed_path(Path(__file__))
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        hosts = [
            name
            for name in ["codex", "claude"]
            if (home / (".codex" if name == "codex" else ".claude")).exists()
        ]
        result = {"prepare": prepare, "install": install, "status": status}[args.action](
            home, hosts
        )
        print(json.dumps(result))
        return 0
    except Exception:
        # Never stringify input, token, filesystem contents or an exception.
        print('{"status":"NEEDS_USER","reason":"agent_setup_not_completed"}')
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
