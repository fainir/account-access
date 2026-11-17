"""Install the portable skill without editing unrelated host configuration."""

import json
import os
import shutil
import shlex
import stat
import sys
from pathlib import Path

from .errors import AccessError
from .storage import private_file

SKILL_SOURCE = Path(__file__).resolve().parent / "skills/account-access"
SKILL_TEMPLATE_FILES = ("SKILL.md", "agents/openai.yaml", "scripts/access.py")


def launcher_text(target, python):
    return ("#!/bin/sh\nexec " + shlex.quote(str(python)) + " -B -I "
            + shlex.quote(str(target / "scripts/access.py")) + ' "$@"\n')


def check_skill_target(target, config_file):
    """Never let a preview reconnect an existing skill to a different store.

    The native migration path publishes into a new staging directory before
    exchanging aliases. An ordinary refresh may only retain its own binding.
    This check also runs before any legacy client capability is rotated.
    """
    if target.is_symlink():
        raise AccessError("DENIED", "existing_skill_would_be_overwritten")
    if not target.exists():
        return
    if not target.is_dir():
        raise AccessError("DENIED", "existing_skill_would_be_overwritten")
    if any(path.is_symlink() for path in target.rglob("*")):
        raise AccessError("DENIED", "symlink_path")

    def read_metadata(path, limit):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                raise ValueError()
            data = os.read(descriptor, limit + 1)
            if len(data) != info.st_size or len(data) > limit:
                raise ValueError()
            return data
        finally:
            os.close(descriptor)

    try:
        if read_metadata(target / ".account-access-install", 64) != b"account-access-v1":
            raise ValueError()
        current = target / "installation.json"
        if not current.exists():
            # Only the native upgrader's empty, marked staging folder is new.
            if set(path.name for path in target.iterdir()) != {".account-access-install"}:
                raise ValueError()
            return
        binding = json.loads(read_metadata(current, 16384))
        if type(binding) is not dict or binding.get("client_config") != str(config_file):
            raise ValueError()
    except (OSError, ValueError, UnicodeError):
        raise AccessError("DENIED", "existing_skill_would_be_overwritten") from None


def sync_skill(target, config_file, *, python=None):
    python = str(python or sys.executable)
    source = SKILL_SOURCE
    marker = target / ".account-access-install"
    check_skill_target(target, config_file)
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    for relative in SKILL_TEMPLATE_FILES:
        entry = source / relative
        dest = target / relative
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(entry, dest)
    # A generated launcher avoids requiring python3 on the agent's PATH.
    launcher = target / "scripts/access"
    launcher.write_text(launcher_text(target, python))
    install_config = {"client_config": str(config_file), "python": python}
    private_file(target / "installation.json", json.dumps(install_config).encode(),
                 replace=(target / "installation.json").exists())
    private_file(marker, b"account-access-v1", replace=marker.exists())
    for path in target.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    os.chmod(launcher, 0o700)


def install_skill(store, agent, destination=None):
    if destination:
        target = Path(destination) / "account-access"
    elif agent == "claude":
        target = Path.home() / ".claude/skills/account-access"
    else:
        target = Path.home() / ".agents/skills/account-access"
    # Check the owned destination before issuing or revoking a client token.
    client_dir = store.root / "clients" / agent
    config_file = client_dir / "client.json"
    check_skill_target(target, config_file)
    client_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    token_file = client_dir / "token"
    # Rotate the installation's client token; the service stores only its digest.
    with store.db() as db:
        db.execute("UPDATE clients SET revoked=1 WHERE principal=?", (agent,))
    token = store.new_client(agent)
    private_file(token_file, token.encode(), replace=token_file.exists())
    config = {"socket": str(store.root / "service.sock"), "token_file": str(token_file),
              "auto_start": not store.config().test_mode and (store.root / "desktop.json").is_file()}
    private_file(config_file, json.dumps(config).encode(), replace=config_file.exists())
    sync_skill(target, config_file)
    return {"agent": agent, "skill_path": str(target), "principal": agent,
            "client_config": str(config_file)}


def install_detected(store):
    """Install one shared portable identity; host folders are discovery aliases."""
    from .integration import install_session_guidance, resolve_codex_home

    home = Path.home()
    codex_home = resolve_codex_home(home)
    detected = [agent for agent, folder, command in [("codex", codex_home, "codex"),
                                                     ("claude", home / ".claude", "claude")]
                if folder.exists() or shutil.which(command)]
    targets = [("generic", home / ".agents/skills")]
    if "claude" in detected:
        targets.append(("claude", home / ".claude/skills"))
    expected = store.root / "clients/generic/client.json"
    for _, destination in targets:
        check_skill_target(destination / "account-access", expected)
    installed = []
    for host, destination in targets:
        target = destination / "account-access"
        current = target / "installation.json"
        valid = False
        if current.is_file() and not current.is_symlink() and not target.is_symlink():
            try:
                from .storage import check_private
                check_private(current)
                valid = (json.loads(current.read_text()).get("client_config") == str(expected)
                         and expected.is_file() and (target / ".account-access-install").is_file())
                if valid:
                    check_private(expected)
                    client = json.loads(expected.read_text())
                    token_file = Path(client["token_file"])
                    check_private(token_file)
                    valid = store.client(token_file.read_text()) == "generic"
            except (AccessError, ValueError, KeyError, OSError):
                valid = False
        result = ({"agent": "generic", "skill_path": str(target), "principal": "generic",
                   "client_config": str(expected)} if valid else
                  install_skill(store, "generic", destination))
        if valid:
            client["auto_start"] = not store.config().test_mode and (store.root / "desktop.json").is_file()
            private_file(expected, json.dumps(client).encode(), replace=True)
            sync_skill(target, expected)
        installed.append({**result, "agent": host})
    primary = home / ".agents/skills/account-access"
    if "codex" in detected:
        installed.append({"agent": "codex", "skill_path": str(primary), "principal": "generic",
                          "client_config": str(store.root / "clients/generic/client.json")})
    store.put("agent-integrations", detected)
    automatic = install_session_guidance(home, detected, codex_home)
    store.put("session-integrations", automatic)
    return {"status": "INSTALLED", "clients": installed,
            "portable_cli": str(primary / "scripts/access"), "automatic_sessions": automatic}
