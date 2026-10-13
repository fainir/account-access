"""Install the portable skill without editing unrelated host configuration."""

import json
import os
import shutil
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
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    for entry in source.iterdir():
        dest = target / entry.name
        if entry.is_dir():
            shutil.copytree(entry, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(entry, dest)
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
    return {"agent": agent, "skill_path": str(target), "principal": agent,
            "client_config": str(config_file)}
