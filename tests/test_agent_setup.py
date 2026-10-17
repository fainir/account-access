import json
import os
import subprocess
import sys
import threading
import time

import pytest
import uvicorn

from account_access.agent_setup import RELATIVE, install, prepare, status
from account_access.errors import AccessError
from account_access.managed_client import enroll
from account_access.service import create_app


def home_at(tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    for name in [".codex", ".claude"]:
        (home / name).mkdir(mode=0o700)
    (home / ".codex/AGENTS.md").write_text("Keep my Codex preferences.\n")
    (home / ".claude/CLAUDE.md").write_text("Keep my Claude preferences.\n")
    return home


def test_prepare_is_private_idempotent_and_does_not_install_or_expose_capability(tmp_path):
    home = home_at(tmp_path)
    kwargs = {"python": sys.executable, "socket": tmp_path / "service.sock"}
    first = prepare(home, ["codex", "claude"], **kwargs)
    token = (home / RELATIVE / "token").read_text()
    assert len(token) == 43 and token not in json.dumps(first)
    assert prepare(home, ["codex", "claude"], **kwargs) == first
    assert not (home / ".agents/skills/account-access").exists()
    for file in (home / RELATIVE).iterdir():
        assert file.stat().st_mode & 0o077 == 0
    assert json.loads((home / RELATIVE / "client.json").read_text())["auto_start"] is False
    assert status(home, ["codex", "claude"], **kwargs) == {"status": "NOT_INSTALLED"}


def test_one_enrollment_installs_both_launchers_and_preserves_existing_guidance(env, tmp_path):
    _, broker, _ = env
    home = home_at(tmp_path)
    address = broker.store.root / "isolated-agent.sock"
    kwargs = {"python": sys.executable, "socket": address}
    prepared = prepare(home, ["codex", "claude"], **kwargs)
    token_file = home / RELATIVE / "token"
    token = token_file.read_text()
    assert enroll(broker.store, token)["client_id"] == prepared["client_id"]
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(broker, worker=False),
            uds=str(address),
            log_level="critical",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        installed = install(home, ["codex", "claude"], **kwargs)
        assert installed["status"] == "INSTALLED" and token not in json.dumps(installed)
        assert install(home, ["codex", "claude"], **kwargs) == installed
        assert token_file.read_text() == token
        assert status(home, ["codex", "claude"], **kwargs) == {
            k: installed[k] for k in ["status", "client_id", "hosts"]
        }
        broker.grant("generic", "demo-api", ["summary"])
        for relative in [".agents/skills/account-access", ".claude/skills/account-access"]:
            target = home / relative
            cli = subprocess.run(
                [str(target / "scripts/access"), "accounts"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert cli.returncode == 0 and [
                a["account"] for a in json.loads(cli.stdout)["accounts"]
            ] == ["demo-api"]
            assert token not in cli.stdout and token not in cli.stderr
            refused = subprocess.run(
                [str(target / "scripts/access"), "credential"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert (
                refused.returncode == 3
                and "DENIED" in refused.stdout
                and token not in refused.stdout
            )
        for name, original in [
            (".codex/AGENTS.md", "Keep my Codex preferences."),
            (".claude/CLAUDE.md", "Keep my Claude preferences."),
        ]:
            content = (home / name).read_text()
            assert (
                content.startswith(original)
                and content.count("<!-- account-access:automatic:start -->") == 1
            )
            assert token not in content
        script = home / ".agents/skills/account-access/SKILL.md"
        script.write_text("Outdated skill")
        assert status(home, ["codex", "claude"], **kwargs) == {"status": "NOT_INSTALLED"}
        install(home, ["codex", "claude"], **kwargs)
        (home / ".claude/CLAUDE.md").write_text("My preferences without an automatic integration")
        assert status(home, ["codex", "claude"], **kwargs) == {"status": "NOT_INSTALLED"}
    finally:
        server.should_exit = True
        thread.join(10)


@pytest.mark.parametrize("where", [".agents", ".agents/skills", ".claude", ".codex"])
def test_symlinked_host_paths_are_refused_before_creating_capability(tmp_path, where):
    home = home_at(tmp_path)
    target = home / where
    if target.exists():
        for file in target.iterdir():
            file.unlink()
        target.rmdir()
    target.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "unrelated"
    outside.mkdir()
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises((AccessError, OSError)):
        prepare(home, ["codex", "claude"])
    assert not (home / RELATIVE / "token").exists() and list(outside.iterdir()) == []


def test_existing_legacy_managed_skill_requires_migration_without_touching_it(tmp_path):
    home = home_at(tmp_path)
    target = home / ".agents/skills/account-access"
    target.mkdir(parents=True, mode=0o700)
    (target / ".account-access-install").write_text("account-access-v1")
    (target / ".account-access-install").chmod(0o600)
    old = {"client_config": str(tmp_path / "legacy-clients/client.json"), "python": sys.executable}
    file = target / "installation.json"
    file.write_text(json.dumps(old))
    file.chmod(0o600)
    before = file.read_bytes()
    with pytest.raises(AccessError, match="client_migration_required"):
        prepare(home, ["codex", "claude"])
    assert file.read_bytes() == before and not (home / RELATIVE / "token").exists()


@pytest.mark.parametrize("change", ["mode", "link", "config", "missing-token"])
def test_changed_client_files_do_not_trigger_capability_replacement(tmp_path, change):
    home = home_at(tmp_path)
    kwargs = {"python": sys.executable, "socket": tmp_path / "service.sock"}
    prepare(home, ["codex", "claude"], **kwargs)
    file = home / RELATIVE / "token"
    original = file.read_text()
    if change == "mode":
        file.chmod(0o644)
    elif change == "link":
        os.link(file, home / RELATIVE / "alias")
    elif change == "config":
        (home / RELATIVE / "client.json").write_text("{}")
    else:
        file.unlink()
    with pytest.raises((AccessError, OSError)):
        prepare(home, ["codex", "claude"], **kwargs)
    if change != "missing-token":
        assert file.read_text() == original
    else:
        assert not file.exists()


def test_unenrolled_capability_cannot_publish_success_or_launchers(env, tmp_path):
    _, broker, _ = env
    home = home_at(tmp_path)
    address = broker.store.root / "unenrolled.sock"
    kwargs = {"python": sys.executable, "socket": address}
    prepare(home, [], **kwargs)
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(broker, worker=False),
            uds=str(address),
            log_level="critical",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        with pytest.raises(AccessError, match="client_connection_not_confirmed"):
            install(home, [], **kwargs)
        assert not (home / RELATIVE / "installed.json").exists()
        assert not (home / ".agents/skills/account-access").exists()
    finally:
        server.should_exit = True
        thread.join(10)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin ACL metadata")
@pytest.mark.parametrize("permission", ["deny delete", "allow read"])
def test_darwin_home_acl_allows_restrictive_entries_but_refuses_grants(tmp_path, permission):
    home = home_at(tmp_path)
    subprocess.run(["/bin/chmod", "+a", "everyone " + permission, str(home)], check=True)
    try:
        if permission.startswith("deny"):
            assert prepare(home, ["codex", "claude"])["status"] == "PREPARED"
        else:
            with pytest.raises(AccessError, match="permissions_need_review"):
                prepare(home, ["codex", "claude"])
            assert not (home / RELATIVE / "token").exists()
    finally:
        subprocess.run(["/bin/chmod", "-N", str(home)], check=True)
