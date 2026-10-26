import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import threading
import time

import pytest
import uvicorn

from account_access.agent_setup import RELATIVE, UPGRADE_SLOT, install, prepare, status
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


@pytest.mark.parametrize("upgrade", [False, True])
def test_one_enrollment_installs_both_launchers_and_preserves_existing_guidance(env, tmp_path, upgrade):
    _, broker, _ = env
    home = home_at(tmp_path)
    if upgrade:
        legacy_skills(home)
    address = broker.store.root / "isolated-agent.sock"
    kwargs = {"python": sys.executable, "socket": address}
    prepared = prepare(home, ["codex", "claude"], upgrade=upgrade, **kwargs)
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
        installed = install(home, ["codex", "claude"], upgrade=upgrade, **kwargs)
        assert installed["status"] == "INSTALLED" and token not in json.dumps(installed)
        assert install(home, ["codex", "claude"], upgrade=upgrade, **kwargs) == installed
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
    with pytest.raises((AccessError, FileNotFoundError)):
        prepare(home, ["codex", "claude"])
    assert file.read_bytes() == before and not (home / RELATIVE / "token").exists()


def legacy_skills(home, hosts=("codex", "claude"), *, historical=True, root_name="account-access"):
    """Public 0.7.4 bytes, with generated owner-local paths and fake old secret."""
    root = home / ".local/share" / root_name
    client = root / "clients/generic/client.json"
    client.parent.mkdir(parents=True, mode=0o700)
    client.write_text('{"not_a_credential":"not_read_or_trusted"}')
    client.chmod(0o600)
    token = client.with_name("token")
    token.write_text("old-preview-token-must-never-be-read")
    token.chmod(0o600)
    python = root / "runtime/tools/account-access/bin/python"
    python.parent.mkdir(parents=True, mode=0o700)
    source = Path(__file__).parent / "fixtures/legacy-skill-074" if historical else (
        Path(__file__).parent.parent / "account_access/skills/account-access")
    targets = [home / ".agents/skills/account-access", *(
        [home / ".claude/skills/account-access"] if "claude" in hosts else [])]
    for target in targets:
        target.mkdir(parents=True, mode=0o700)
        for name in ["SKILL.md", "agents/openai.yaml", "scripts/access.py"]:
            path = target / name
            path.parent.mkdir(exist_ok=True, mode=0o700)
            shutil.copyfile(source / name, path)
        (target / ".account-access-install").write_text("account-access-v1")
        (target / "installation.json").write_text(json.dumps({"client_config": str(client), "python": str(python)}))
        (target / "scripts/access").write_text("#!/bin/sh\nexec " + shlex.quote(str(python))
            + (" " if historical else " -I ")
            + shlex.quote(str(target / "scripts/access.py")) + ' "$@"\n')
        for path in target.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        (target / "scripts/access").chmod(0o700)
    return targets, token


def file_bytes(target):
    return {str(path.relative_to(target)): path.read_bytes()
            for path in target.rglob("*") if path.is_file()}


@pytest.mark.parametrize("historical", [True, False])
@pytest.mark.parametrize("root_name", ["account-access", "account-access-review06"])
def test_reviewed_preview_status_and_explicit_prepare_do_not_read_old_tokens(tmp_path, monkeypatch, historical, root_name):
    from account_access import agent_setup
    home = home_at(tmp_path)
    targets, old_token = legacy_skills(home, historical=historical, root_name=root_name)
    before = [file_bytes(target) for target in targets]
    real_open = os.open
    def no_old_token(path, *args, **kwargs):
        assert Path(path) != old_token
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(agent_setup.os, "open", no_old_token)
    assert status(home, ["codex", "claude"]) == {"status": "MIGRATION_REQUIRED", "legacy_connections": 2}
    with pytest.raises(AccessError, match="client_migration_required"):
        prepare(home, ["codex", "claude"])
    prepared = prepare(home, ["codex", "claude"], upgrade=True)
    assert prepared["status"] == "PREPARED"
    assert (home / RELATIVE / "token").read_bytes() != b"old-preview-token-must-never-be-read"
    assert [file_bytes(target) for target in targets] == before


@pytest.mark.parametrize("change", ["extra", "template", "launcher", "client", "python", "symlink", "hardlink", "public"])
def test_unrecognized_preview_is_preserved_and_cannot_prepare_upgrade(tmp_path, change):
    home = home_at(tmp_path)
    targets, _ = legacy_skills(home)
    target = targets[0]
    if change == "extra":
        (target / "my-instructions.md").write_text("Keep this custom file.")
    elif change == "template":
        (target / "SKILL.md").write_text("Custom skill")
    elif change == "launcher":
        (target / "scripts/access").write_text("#!/bin/sh\necho arbitrary\n")
    elif change in {"client", "python"}:
        path = target / "installation.json"
        value = json.loads(path.read_text())
        value["client_config" if change == "client" else "python"] = str(home / "unrelated/file")
        path.write_text(json.dumps(value))
    elif change == "symlink":
        path = target / "agents/openai.yaml"
        path.unlink()
        path.symlink_to(targets[1] / "agents/openai.yaml")
    elif change == "hardlink":
        os.link(target / "SKILL.md", home / "linked-skill")
    else:
        (target / "SKILL.md").chmod(0o644)
    before = (target / "installation.json").read_bytes()
    with pytest.raises((AccessError, OSError)):
        prepare(home, ["codex", "claude"], upgrade=True)
    assert (target / "installation.json").read_bytes() == before
    assert not (home / RELATIVE / "token").exists()


@pytest.mark.parametrize("change", ["different-root", "root-alias", "public-root", "unrecognized-name"])
def test_named_preview_upgrade_refuses_incoherent_or_untrusted_roots(tmp_path, change):
    home = home_at(tmp_path)
    name = "unrelated-preview" if change == "unrecognized-name" else "account-access-review06"
    targets, _ = legacy_skills(home, root_name=name)
    root = home / ".local/share" / name
    if change == "different-root":
        target = targets[0]
        record = json.loads((target / "installation.json").read_text())
        python = home / ".local/share/account-access-other/runtime/tools/account-access/bin/python"
        python.parent.mkdir(parents=True, mode=0o700)
        record["python"] = str(python)
        (target / "installation.json").write_text(json.dumps(record))
        (target / "scripts/access").write_text("#!/bin/sh\nexec " + shlex.quote(str(python))
            + " " + shlex.quote(str(target / "scripts/access.py")) + ' "$@"\n')
    elif change == "root-alias":
        renamed = root.with_name("relocated-preview")
        root.rename(renamed)
        root.symlink_to(renamed, target_is_directory=True)
    elif change == "public-root":
        root.chmod(0o777)
    before = [file_bytes(target) for target in targets]
    with pytest.raises((AccessError, OSError)):
        prepare(home, ["codex", "claude"], upgrade=True)
    assert [file_bytes(target) for target in targets] == before
    assert not (home / RELATIVE / "token").exists()


def test_unapproved_protected_capability_cannot_replace_preview(tmp_path, monkeypatch):
    from account_access.client import Client
    home = home_at(tmp_path)
    targets, _ = legacy_skills(home)
    before = [file_bytes(target) for target in targets]
    monkeypatch.setattr(Client, "request", lambda *_: {"status": "DENIED"})
    with pytest.raises(AccessError, match="client_connection_not_confirmed"):
        install(home, ["codex", "claude"], upgrade=True)
    assert [file_bytes(target) for target in targets] == before
    assert not any(target.with_name(UPGRADE_SLOT).exists() for target in targets)


@pytest.mark.parametrize("root_name", ["account-access", "account-access-review06"])
def test_preview_upgrade_publishes_new_connection_and_preserves_owner_settings(tmp_path, monkeypatch, root_name):
    from account_access.client import Client
    home = home_at(tmp_path)
    targets, old_token = legacy_skills(home, root_name=root_name)
    original_token = old_token.read_bytes()
    settings = home / ".claude/settings.json"
    settings.write_text('{"hooks":{"SessionStart":["my-hook"]},"permissions":{"deny":["Bash(rm:*)"]}}')
    codex = home / ".codex/AGENTS.md"
    codex.write_text("Keep this owner's instructions.\n")
    rules = home / ".codex/rules/owner.rules"
    rules.parent.mkdir()
    rules.write_text('prefix_rule(pattern=["my-tool"],decision="deny")\n')
    preserved = {path: path.read_bytes() for path in [settings, rules]}
    monkeypatch.setattr(Client, "request", lambda *_: {"accounts": []})
    installed = install(home, ["codex", "claude"], python=sys.executable, socket=home / "new.sock", upgrade=True)
    assert installed["status"] == "INSTALLED"
    assert status(home, ["codex", "claude"], python=sys.executable, socket=home / "new.sock")["status"] == "INSTALLED"
    for target in targets:
        assert json.loads((target / "installation.json").read_text())["client_config"] == str(home / RELATIVE / "client.json")
        assert target.with_name(UPGRADE_SLOT).is_dir()
    assert all(path.read_bytes() == data for path, data in preserved.items())
    assert codex.read_text().startswith("Keep this owner's instructions.\n")
    assert old_token.read_bytes() == original_token


def test_second_alias_publication_failure_rolls_back_and_explicit_retry_works(tmp_path, monkeypatch):
    from account_access import agent_setup
    from account_access.client import Client
    home = home_at(tmp_path)
    targets, _ = legacy_skills(home)
    before = [file_bytes(target) for target in targets]
    monkeypatch.setattr(Client, "request", lambda *_: {"accounts": []})
    real_rename = agent_setup._rename_directory
    def fail_second(source, destination, *, exchange=False):
        if destination == targets[1] and exchange:
            raise OSError("injected second alias failure")
        return real_rename(source, destination, exchange=exchange)
    monkeypatch.setattr(agent_setup, "_rename_directory", fail_second)
    with pytest.raises(OSError, match="injected"):
        install(home, ["codex", "claude"], python=sys.executable, upgrade=True)
    assert [file_bytes(target) for target in targets] == before
    assert not (home / RELATIVE / "installed.json").exists()
    monkeypatch.setattr(agent_setup, "_rename_directory", real_rename)
    assert install(home, ["codex", "claude"], python=sys.executable, upgrade=True)["status"] == "INSTALLED"


def test_interrupted_upgrade_keeps_complete_aliases_and_resumes_remaining_host(tmp_path, monkeypatch):
    from account_access import agent_setup
    from account_access.client import Client
    home = home_at(tmp_path)
    targets, _ = legacy_skills(home)
    monkeypatch.setattr(Client, "request", lambda *_: {"accounts": []})
    original = agent_setup._rename_directory
    class ProcessInterrupted(BaseException):
        pass
    def die_before_second(source, destination, *, exchange=False):
        if destination == targets[1] and exchange:
            raise ProcessInterrupted()
        return original(source, destination, exchange=exchange)
    monkeypatch.setattr(agent_setup, "_rename_directory", die_before_second)
    with pytest.raises(ProcessInterrupted):
        install(home, ["codex", "claude"], python=sys.executable, upgrade=True)
    assert json.loads((targets[0] / "installation.json").read_text())["client_config"] == str(home / RELATIVE / "client.json")
    assert status(home, ["codex", "claude"], python=sys.executable) == {"status": "MIGRATION_REQUIRED", "legacy_connections": 1}
    token = (home / RELATIVE / "token").read_bytes()
    monkeypatch.setattr(agent_setup, "_rename_directory", original)
    assert install(home, ["codex", "claude"], python=sys.executable, upgrade=True)["status"] == "INSTALLED"
    assert (home / RELATIVE / "token").read_bytes() == token
    assert status(home, ["codex", "claude"], python=sys.executable)["status"] == "INSTALLED"
    assert all(target.with_name(UPGRADE_SLOT).is_dir() for target in targets)


@pytest.mark.parametrize("failure", ["sync", "guidance"])
def test_finalization_failure_restores_preview_connections(tmp_path, monkeypatch, failure):
    from account_access import agent_setup, integration
    from account_access.client import Client
    home = home_at(tmp_path)
    targets, _ = legacy_skills(home)
    before = [file_bytes(target) for target in targets]
    monkeypatch.setattr(Client, "request", lambda *_: {"accounts": []})
    if failure == "guidance":
        def fail(*_):
            raise OSError("injected guidance failure")
        monkeypatch.setattr(integration, "install_session_guidance", fail)
    else:
        original, calls = agent_setup._sync_directory, []
        def fail(path):
            calls.append(path)
            if len(calls) == 3:
                raise OSError("injected publication sync failure")
            return original(path)
        monkeypatch.setattr(agent_setup, "_sync_directory", fail)
    with pytest.raises(OSError, match="injected"):
        install(home, ["codex", "claude"], python=sys.executable, upgrade=True)
    assert [file_bytes(target) for target in targets] == before
    assert not (home / RELATIVE / "installed.json").exists()


def test_unknown_upgrade_slot_is_preserved_without_replacing_preview(tmp_path, monkeypatch):
    from account_access.client import Client
    home = home_at(tmp_path)
    targets, _ = legacy_skills(home)
    before = [file_bytes(target) for target in targets]
    slot = targets[0].with_name(UPGRADE_SLOT)
    slot.mkdir(mode=0o700)
    custom = slot / "keep-my-file"
    custom.write_text("Do not remove this unknown directory.")
    monkeypatch.setattr(Client, "request", lambda *_: {"accounts": []})
    with pytest.raises((AccessError, OSError)):
        install(home, ["codex", "claude"], python=sys.executable, upgrade=True)
    assert custom.read_text() == "Do not remove this unknown directory."
    assert [file_bytes(target) for target in targets] == before


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
