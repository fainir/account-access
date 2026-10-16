"""Install the portable skill without editing unrelated host configuration."""

import json
import os
import shutil
import shlex
import sys
from pathlib import Path

from .errors import AccessError
from .storage import private_file


def sync_skill(target, config_file):
    source = Path(__file__).resolve().parent / "skills/account-access"
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
    launcher.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I "
                        + shlex.quote(str(target / "scripts/access.py")) + ' "$@"\n')
    install_config = {"client_config": str(config_file), "python": sys.executable}
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
    if target.is_symlink() or (target.exists() and not (target / ".account-access-install").exists()):
        raise AccessError("DENIED", "existing_skill_would_be_overwritten")
    if target.exists() and any(path.is_symlink() for path in target.rglob("*")):
        raise AccessError("DENIED", "symlink_path")
    client_dir = store.root / "clients" / agent
    client_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    token_file = client_dir / "token"
    # Rotate the installation's client token; the service stores only its digest.
    with store.db() as db:
        db.execute("UPDATE clients SET revoked=1 WHERE principal=?", (agent,))
    token = store.new_client(agent)
    private_file(token_file, token.encode(), replace=token_file.exists())
    config_file = client_dir / "client.json"
    config = {"socket": str(store.root / "service.sock"), "token_file": str(token_file),
              "auto_start": not store.config().test_mode and (store.root / "desktop.json").is_file()}
    private_file(config_file, json.dumps(config).encode(), replace=config_file.exists())
    sync_skill(target, config_file)
    return {"agent": agent, "skill_path": str(target), "principal": agent,
            "client_config": str(config_file)}


def install_detected(store):
    """Install one shared portable identity; host folders are discovery aliases."""
    home = Path.home()
    codex_home = Path(os.environ.get("CODEX_HOME", str(home / ".codex"))).expanduser()
    detected = [agent for agent, folder, command in [("codex", codex_home, "codex"),
                                                     ("claude", home / ".claude", "claude")]
                if folder.exists() or shutil.which(command)]
    targets = [("generic", home / ".agents/skills")]
    if "claude" in detected:
        targets.append(("claude", home / ".claude/skills"))
    installed = []
    for host, destination in targets:
        target = destination / "account-access"
        current = target / "installation.json"
        expected = store.root / "clients/generic/client.json"
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
    from .integration import install_session_guidance
    automatic = install_session_guidance(home, detected, codex_home)
    store.put("session-integrations", automatic)
    return {"status": "INSTALLED", "clients": installed,
            "portable_cli": str(primary / "scripts/access"), "automatic_sessions": automatic}
