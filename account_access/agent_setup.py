"""Owner-user half of isolated client setup. Never opens the broker store.

Production entrypoints use fixed installed locations, the OS account's home and
an immutable runtime. The native UI sends the locally generated capability to
its approved gateway; this helper's output never contains it.
"""

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import shutil
import stat
import sys
import tempfile

from .errors import AccessError
from .managed_client import identity
from .storage import private_file


BASE = Path("/Library/Application Support/Account Access")
RUNTIME = BASE / "runtime/bin/python"
SOCKET = BASE / "run/agent.sock"
RELATIVE = Path("Library/Application Support/Account Access/client-v1")
MARKER = "account-access-native-client-v1"
UPGRADE_SLOT = ".account-access-preview-backup-v1"
# Exact, coherent template pairs shipped by the public 0.7.4 preview and the
# subsequent managed 0.8 previews. A marker or arbitrary client file is not
# sufficient evidence that an existing directory belongs to this installer.
LEGACY_PAYLOADS = {
    ("28c4a4f28a129959f5b154b3e1f22a4b96e9439f41e2c9120dc92956b0f60e47",
     "7cacb84906c4699d6b220890263eec9caf9cc88c43a1944034d3d7897b595127", False),
    ("2edba07f411931d199549de5719bc10934b5622dfc3d8cccbde46553a3b0643d",
     "7cacb84906c4699d6b220890263eec9caf9cc88c43a1944034d3d7897b595127", False),
    ("4de6b1612d2bf2ff04206bfc1fc45d0728d931abd42f7a6b5a7957757b49d7bf",
     "7cacb84906c4699d6b220890263eec9caf9cc88c43a1944034d3d7897b595127", False),
    ("913c3bd979b610366910bf54798ef70c77dae3b53f4ad99afb88f0e2eeaff5f9",
     "8c01c85d5dadc74d1ac2d289fd2581527e29539434a117084873f097c87480f5", True),
}
LEGACY_AGENT_TEMPLATE = "fd20307cf6e0ff731323deccae9d4b645d16b32c5f0baf33be8c2a3ec4f320ed"
SKILL_FILES = {".account-access-install", "installation.json", "SKILL.md",
               "agents/openai.yaml", "scripts/access", "scripts/access.py"}
SKILL_DIRECTORIES = {"", "agents", "scripts"}
# Only these fixed setup failures may cross the native helper boundary. In
# particular, never serialize an exception, path, response, token or user file.
SETUP_FAILURES = {
    "client_migration_requires_review": "NEEDS_USER",
    "client_migration_required": "NEEDS_USER",
    "existing_skill_would_be_overwritten": "NEEDS_USER",
    "client_setup_permissions_need_review": "NEEDS_USER",
    "client_setup_needs_repair": "NEEDS_USER",
    "client_upgrade_needs_repair": "NEEDS_USER",
    "client_upgrade_not_supported": "NEEDS_USER",
    "client_connection_not_confirmed": "NEEDS_USER",
    "client_setup_busy": "RETRYABLE",
    "client_setup_changed": "RETRYABLE",
}


def setup_failure_payload(error):
    """Return fixed, non-sensitive diagnostics for the native owner UI."""
    reason = error.reason if isinstance(error, AccessError) else None
    status = SETUP_FAILURES.get(reason) if type(reason) is str else None
    if status is None:
        return {"status": "NEEDS_USER", "reason": "agent_setup_not_completed"}
    return {"status": status, "reason": reason}


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


def _targets(home, hosts):
    return [home / ".agents/skills/account-access", *(
        [home / ".claude/skills/account-access"] if "claude" in hosts else [])]


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _same_relocated(before, after):
    return (before.keys() == after.keys()
            and all(before[name] == after[name] for name in before if name)
            and before[""][:-1] == after[""][:-1])


def _skill_snapshot(target):
    """Bounded, non-following inventory. No client/token file is opened here."""
    result, contents = {}, {}
    for name in sorted(SKILL_DIRECTORIES):
        path = target / name
        before = path.lstat()
        _checked(path, directory=True, private=True)
        expected = {Path(item).name for item in SKILL_FILES | SKILL_DIRECTORIES
                    if item and Path(item).parent == Path(name or ".")}
        if (stat.S_IMODE(before.st_mode) != 0o700 or set(os.listdir(path)) != expected
                or _stamp(path.lstat()) != _stamp(before)):
            raise AccessError("NEEDS_USER", "client_migration_requires_review")
        result[name] = _stamp(before)
    for name in sorted(SKILL_FILES):
        path = target / name
        before = path.lstat()
        data = _checked(path, private=True, limit=16384)
        if stat.S_IMODE(before.st_mode) != (0o700 if name == "scripts/access" else 0o600):
            raise AccessError("NEEDS_USER", "client_migration_requires_review")
        if _stamp(path.lstat()) != _stamp(before):
            raise AccessError("RETRYABLE", "client_setup_changed")
        result[name] = (*_stamp(before), hashlib.sha256(data).hexdigest())
        contents[name] = data
    return result, contents


def _legacy_skill(home, target, *, launcher_target=None):
    launcher_target = launcher_target or target
    snapshot, data = _skill_snapshot(target)
    try:
        installed = json.loads(data["installation.json"])
        if (type(installed) is not dict or set(installed) != {"client_config", "python"}
                or any(type(value) is not str for value in installed.values())
                or data[".account-access-install"] != b"account-access-v1"):
            raise ValueError()
        client = Path(installed["client_config"])
        principal = client.parent.name
        roots = [home / ".local/share/account-access",
                 home / "Library/Application Support/AccountAccess"]
        # Preview installs could use a named root beneath the same owner-local
        # namespace. Recognize its exact managed templates and coherent paths;
        # never execute its runtime or reuse its credentials or permissions.
        candidate = client.parent.parent.parent
        if (candidate.parent == home / ".local/share"
                and re.fullmatch(r"account-access-[A-Za-z0-9][A-Za-z0-9_-]{0,79}", candidate.name)):
            roots.append(candidate)
        root = next((value for value in roots
                     if client == value / "clients" / principal / "client.json"), None)
        allowed = {"generic", "claude" if launcher_target.parent.parent.name == ".claude" else "codex"}
        if root is None or principal not in allowed or str(client) != installed["client_config"]:
            raise ValueError()
        # Check only old client metadata. Its token, service, vault and grants
        # are neither read nor reused by the protected connection.
        _directories(home, client.parent.relative_to(home))
        descriptor = os.open(client, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o7077 or info.st_nlink != 1 or info.st_size > 4096):
                raise ValueError()
            _no_acl(descriptor)
        finally:
            os.close(descriptor)
        python = Path(installed["python"])
        runtime = (root if root.parent == home / ".local/share"
                   else home / ".local/share/account-access") / "runtime"
        if (str(python) != installed["python"] or python.parent.name != "bin"
                or re.fullmatch(r"python(?:3(?:\.[0-9]{1,2})?)?", python.name) is None
                or not (python.parent.parent == runtime / "tools/account-access"
                        or (python.parent.parent.parent == runtime / "environments"
                            and re.fullmatch(r"account-access-[A-Za-z0-9_-]{1,80}",
                                             python.parent.parent.name)))):
            raise ValueError()
        _directories(home, python.parent.relative_to(home))
        skill_hash = hashlib.sha256(data["SKILL.md"]).hexdigest()
        reader_hash = hashlib.sha256(data["scripts/access.py"]).hexdigest()
        isolated = (skill_hash, reader_hash, True) in LEGACY_PAYLOADS
        if ((skill_hash, reader_hash, isolated) not in LEGACY_PAYLOADS
                or hashlib.sha256(data["agents/openai.yaml"]).hexdigest() != LEGACY_AGENT_TEMPLATE):
            raise ValueError()
        expected = ("#!/bin/sh\nexec " + shlex.quote(str(python))
                    + (" -I " if isolated else " ")
                    + shlex.quote(str(launcher_target / "scripts/access.py")) + ' "$@"\n').encode()
        if data["scripts/access"] != expected:
            raise ValueError()
        return snapshot
    except (ValueError, KeyError, TypeError, StopIteration):
        raise AccessError("NEEDS_USER", "client_migration_requires_review") from None


def _preflight(home, hosts, *, upgrade=False, codex_home=None):
    if (
        type(hosts) is not list
        or any(host not in {"codex", "claude"} for host in hosts)
        or len(hosts) != len(set(hosts))
    ):
        raise AccessError("DENIED", "invalid_client_setup")
    home = Path(home)
    codex_home = codex_home or home / ".codex"
    _directories(home, RELATIVE)
    expected = home / RELATIVE / "client.json"
    legacy = {}
    for target in _targets(home, hosts):
        _directories(home, target.relative_to(home))
        if target.exists():
            if _checked(target / ".account-access-install", private=True) != b"account-access-v1":
                raise AccessError("NEEDS_USER", "existing_skill_would_be_overwritten")
            if _json(target / "installation.json").get("client_config") != str(expected):
                legacy[target] = _legacy_skill(home, target)
                if not upgrade:
                    raise AccessError("NEEDS_USER", "client_migration_required")
            for child in target.rglob("*"):
                _checked(child, directory=child.is_dir(), private=True)
    for host in hosts:
        directory = codex_home.relative_to(home) if host == "codex" else Path(".claude")
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
    return expected, legacy


def preflight(home, hosts, *, upgrade=False, codex_home=None):
    from .integration import resolve_codex_home
    selected = resolve_codex_home(Path(home), codex_home)
    return _preflight(home, hosts, upgrade=upgrade, codex_home=selected)[0]


def prepare(home, hosts, *, python=RUNTIME, socket=SOCKET, upgrade=False, codex_home=None):
    """Preflight all known targets before creating an unregistered capability."""
    from .integration import resolve_codex_home
    home = Path(home)
    codex_home = resolve_codex_home(home, codex_home)
    return _prepare(home, hosts, python=python, socket=socket, upgrade=upgrade, codex_home=codex_home)


def _prepare(home, hosts, *, python, socket, upgrade, codex_home):
    config = _preflight(home, hosts, upgrade=upgrade, codex_home=codex_home)[0]
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


def _rename_directory(source, destination, *, exchange=False):
    """No missing-directory interval, and no replacement of an unknown name."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        operation, at, flag = libc.renameatx_np, -2, 2 if exchange else 4
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        operation, at, flag = libc.renameat2, -100, 2 if exchange else 1
    else:
        raise AccessError("NEEDS_USER", "client_upgrade_not_supported")
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    if operation(at, os.fsencode(source), at, os.fsencode(destination), flag) != 0:
        raise OSError(ctypes.get_errno(), "client_upgrade_publication_failed")


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _current_skill(path, target, config, python):
    from .install import launcher_text
    snapshot, data = _skill_snapshot(path)
    source = Path(__file__).resolve().parent / "skills/account-access"
    expected = {name: (source / name).read_bytes()
                for name in ["SKILL.md", "agents/openai.yaml", "scripts/access.py"]}
    expected.update({"scripts/access": launcher_text(target, python).encode(),
                     ".account-access-install": b"account-access-v1"})
    if (any(data[name] != value for name, value in expected.items())
            or json.loads(data["installation.json"]) != {
                "client_config": str(config), "python": str(python)}):
        raise AccessError("NEEDS_USER", "client_upgrade_needs_repair")
    return snapshot


def _upgrade_skills(home, hosts, config, python, finish, codex_home):
    """Publish only after enrollment; keep at most one credential-free backup.

    Atomic exchange means an interrupted alias is always either the complete
    preview skill or the complete new skill. A subsequent explicit upgrade can
    finish another host; it never adopts a backup as an executable connection.
    """
    from .install import launcher_text, sync_skill
    lock = home / RELATIVE / "upgrade.lock"
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o7077 or info.st_nlink != 1):
            raise AccessError("NEEDS_USER", "client_upgrade_needs_repair")
        _no_acl(descriptor)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AccessError("RETRYABLE", "client_setup_busy") from None
        _, legacy = _preflight(home, hosts, upgrade=True, codex_home=codex_home)
        staged, published = [], []
        try:
            for target in _targets(home, hosts):
                if target.exists() and target not in legacy:
                    _current_skill(target, target, config, python)
                    continue
                _directories(home, target.parent.relative_to(home), create=True)
                slot = target.parent / UPGRADE_SLOT
                if slot.exists() or slot.is_symlink():
                    # A fully staged new skill can survive a crash before its
                    # exchange. No partial or unknown directory is removed.
                    _current_skill(slot, target, config, python)
                else:
                    temporary = Path(tempfile.mkdtemp(prefix=".account-access-stage-", dir=target.parent))
                    try:
                        private_file(temporary / ".account-access-install", b"account-access-v1")
                        sync_skill(temporary, config, python=python)
                        (temporary / "scripts/access").write_text(launcher_text(target, python))
                        _current_skill(temporary, target, config, python)
                        _rename_directory(temporary, slot)
                        _sync_directory(slot.parent)
                    finally:
                        if temporary.exists():
                            shutil.rmtree(temporary)
                staged.append((target, slot, legacy.get(target),
                               _current_skill(slot, target, config, python)))
            for target, slot, old, new in staged:
                if (_skill_snapshot(slot)[0] != new
                        or (old is not None and _legacy_skill(home, target) != old)
                        or (old is None and (target.exists() or target.is_symlink()))):
                    raise AccessError("RETRYABLE", "client_setup_changed")
                _rename_directory(slot, target, exchange=old is not None)
                published.append((target, slot, old, new))
                if not _same_relocated(new, _current_skill(target, target, config, python)):
                    raise AccessError("RETRYABLE", "client_setup_changed")
                _sync_directory(target.parent)
            finish()
        except Exception:
            failed = False
            for target, slot, old, new in reversed(published):
                try:
                    if not _same_relocated(new, _current_skill(target, target, config, python)):
                        raise ValueError()
                    if old is not None and not _same_relocated(
                            old, _legacy_skill(home, slot, launcher_target=target)):
                        raise ValueError()
                    _rename_directory(target, slot, exchange=old is not None)
                    _sync_directory(target.parent)
                except Exception:
                    failed = True
            if failed:
                raise AccessError("NEEDS_USER", "client_upgrade_needs_repair") from None
            raise
    finally:
        os.close(descriptor)


def install(home, hosts, *, python=RUNTIME, socket=SOCKET, upgrade=False, codex_home=None):
    home = Path(home)
    from .integration import resolve_codex_home
    codex_home = resolve_codex_home(home, codex_home)
    prepared = _prepare(home, hosts, python=python, socket=socket, upgrade=upgrade, codex_home=codex_home)
    config = home / RELATIVE / "client.json"
    from .client import Client

    # Confirm this exact locally held capability before publishing launchers.
    result = Client(config).request("GET", "/v1/accounts")
    if type(result) is not dict or type(result.get("accounts")) is not list:
        raise AccessError("NEEDS_USER", "client_connection_not_confirmed")
    from .install import sync_skill

    from .integration import install_session_guidance

    marker = home / RELATIVE / "installed.json"
    receipt = {
        "managed_by": MARKER,
        "schema": 1,
        "client_id": prepared["client_id"],
        "hosts": sorted(hosts),
        "python": str(python),
        "socket": str(socket),
        "codex_home": str(codex_home),
    }
    automatic = None
    def finish():
        nonlocal automatic
        automatic = install_session_guidance(home, hosts, codex_home)
        private_file(marker, json.dumps(receipt).encode(), replace=marker.exists())
    if upgrade:
        _upgrade_skills(home, hosts, config, python, finish, codex_home)
    else:
        for target in _targets(home, hosts):
            _directories(home, target.parent.relative_to(home), create=True)
            sync_skill(target, config, python=python)
        finish()
    return {
        "status": "INSTALLED",
        "client_id": prepared["client_id"],
        "hosts": sorted(hosts),
        "automatic_sessions": automatic,
    }


def status(home, hosts, *, python=RUNTIME, socket=SOCKET, codex_home=None):
    from .integration import resolve_codex_home
    home = Path(home)
    codex_home = resolve_codex_home(home, codex_home)
    config, legacy = _preflight(home, hosts, upgrade=True, codex_home=codex_home)
    if legacy:
        return {"status": "MIGRATION_REQUIRED", "legacy_connections": len(legacy)}
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
        "codex_home": str(codex_home),
    }
    if codex_home == home / ".codex" and "codex_home" not in receipt:
        expected.pop("codex_home")  # Existing protected default-namespace receipt.
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
    from .install import SKILL_TEMPLATE_FILES, launcher_text
    from .integration import codex_rule_block, session_guidance

    source = Path(__file__).resolve().parent / "skills/account-access"
    for relative in [
        Path(".agents/skills"),
        *([Path(".claude/skills")] if "claude" in hosts else []),
    ]:
        target = Path(home) / relative / "account-access"
        for relative in SKILL_TEMPLATE_FILES:
            if _checked(target / relative, private=True) != (source / relative).read_bytes():
                return {"status": "NOT_INSTALLED"}
        if _checked(target / "scripts/access", private=True) != launcher_text(target, python).encode():
            return {"status": "NOT_INSTALLED"}
    for host in hosts:
        directory = codex_home if host == "codex" else home / ".claude"
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
    parser.add_argument("action", choices=["prepare", "install", "status", "prepare-upgrade", "install-upgrade"])
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
        from .integration import resolve_codex_home
        codex_home = resolve_codex_home(home)
        hosts = [
            name
            for name in ["codex", "claude"]
            if (codex_home if name == "codex" else home / ".claude").exists()
        ]
        action = args.action.removesuffix("-upgrade")
        options = {"upgrade": True} if args.action.endswith("-upgrade") else {}
        result = {"prepare": prepare, "install": install, "status": status}[action](
            home, hosts, codex_home=codex_home, **options)
        print(json.dumps(result))
        return 0
    except Exception as error:
        # Serialize only an explicitly allowlisted reason. Never stringify an
        # exception or include input, token, filesystem contents or response data.
        print(json.dumps(setup_failure_payload(error)))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
