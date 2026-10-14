"""Install the portable skill without editing unrelated host configuration."""

import json
import os
import shutil
import shlex
import sys
from pathlib import Path

from .errors import AccessError
from .storage import private_file


def install_skill(store, agent, destination=None):
    source = Path(__file__).resolve().parent / "skills/account-access"
    if destination:
        target = Path(destination) / "account-access"
    elif agent == "claude":
        target = Path.home() / ".claude/skills/account-access"
    else:
        target = Path.home() / ".agents/skills/account-access"
    marker = target / ".account-access-install"
    if target.is_symlink() or (target.exists() and not marker.exists()):
        raise AccessError("DENIED", "existing_skill_would_be_overwritten")
    if target.exists() and any(path.is_symlink() for path in target.rglob("*")):
        raise AccessError("DENIED", "symlink_path")
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    for entry in source.iterdir():
        dest = target / entry.name
        if entry.is_dir():
            shutil.copytree(entry, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(entry, dest)
    # A generated launcher avoids requiring python3 on the agent's PATH.
    launcher = target / "scripts/access"
    launcher.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " "
                        + shlex.quote(str(target / "scripts/access.py")) + ' "$@"\n')
    client_dir = store.root / "clients" / agent
    client_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    token_file = client_dir / "token"
    # Rotate the installation's client token; the service stores only its digest.
    with store.db() as db:
        db.execute("UPDATE clients SET revoked=1 WHERE principal=?", (agent,))
    token = store.new_client(agent)
    private_file(token_file, token.encode(), replace=token_file.exists())
    config_file = client_dir / "client.json"
    config = {"socket": str(store.root / "service.sock"), "token_file": str(token_file)}
    private_file(config_file, json.dumps(config).encode(), replace=config_file.exists())
    # The skill holds references and executable paths, never credential material.
    install_config = {"client_config": str(config_file), "python": sys.executable}
    private_file(target / "installation.json", json.dumps(install_config).encode(),
                 replace=(target / "installation.json").exists())
    private_file(marker, b"account-access-v1", replace=marker.exists())
    for path in target.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    os.chmod(launcher, 0o700)
    return {"agent": agent, "skill_path": str(target), "principal": agent,
            "client_config": str(config_file)}


def install_detected(store):
    """One portable client plus host discovery; never change host approval settings."""
    home = Path.home()
    targets = [("generic", store.root / "skills")]
    for agent, folder, command in [("codex", ".codex", "codex"),
                                    ("claude", ".claude", "claude")]:
        if (home / folder).exists() or shutil.which(command):
            targets.append((agent, None))
    installed = []
    for agent, destination in targets:
        target = (destination / "account-access" if destination else
                  home / (".claude" if agent == "claude" else ".agents") / "skills/account-access")
        # Reopening setup must not invalidate a running client's token.
        current = target / "installation.json"
        expected = store.root / "clients" / agent / "client.json"
        valid = False
        if current.is_file() and not current.is_symlink():
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
                    valid = store.client(token_file.read_text()) == agent
            except (AccessError, ValueError, KeyError, OSError):
                valid = False
        result = ({"agent": agent, "skill_path": str(target), "principal": agent,
                   "client_config": str(expected)} if valid else
                  install_skill(store, agent, destination))
        installed.append(result)
    return {"status": "INSTALLED", "clients": installed,
            "portable_cli": str(store.root / "skills/account-access/scripts/access")}
