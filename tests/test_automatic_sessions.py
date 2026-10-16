import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpx2 as httpx
import pytest
import uvicorn

from account_access import __version__
from account_access.client import Client
from account_access.desktop import launch, stop
from account_access.errors import AccessError
from account_access.install import install_detected, install_skill
from account_access.integration import START, install_codex_rule, update_guidance
from account_access.service import create_app
from account_access.storage import private_file


def test_refresh_preserves_personal_instructions_tokens_and_grants(env, tmp_path, monkeypatch):
    _, broker, _ = env
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    monkeypatch.setattr("account_access.install.shutil.which", lambda name: None)
    original = {}
    for file in [".codex/AGENTS.md", ".codex/AGENTS.override.md", ".claude/CLAUDE.md"]:
        path = tmp_path / file
        path.parent.mkdir(exist_ok=True)
        original[file] = "My existing preferences stay here.\n"
        path.write_text(original[file])
        path.chmod(0o644)
    installed = install_detected(broker.store)
    broker.grant("generic", "demo-api", ["summary"])
    token = (broker.store.root / "clients/generic/token").read_text()
    skill = tmp_path / ".agents/skills/account-access/SKILL.md"
    expected = skill.read_bytes()
    skill.write_text("Outdated installed resources")
    with broker.store.db() as db:
        before = [tuple(row) for row in db.execute("SELECT * FROM grants")]
    refreshed = install_detected(broker.store)
    assert refreshed["automatic_sessions"] == installed["automatic_sessions"]
    assert skill.read_bytes() == expected
    assert (broker.store.root / "clients/generic/token").read_text() == token
    with broker.store.db() as db:
        assert [tuple(row) for row in db.execute("SELECT * FROM grants")] == before
    for file, content in original.items():
        path = tmp_path / file
        assert path.read_text().startswith(content)
        assert path.read_text().count(START) == 1
        assert token not in path.read_text()
        assert os.stat(path).st_mode & 0o777 == 0o644


def test_instruction_update_refuses_symlinks_and_partial_blocks(tmp_path):
    outside = tmp_path / "personal.md"
    outside.write_text("Keep this exactly")
    alias = tmp_path / "AGENTS.md"
    alias.symlink_to(outside)
    with pytest.raises(AccessError):
        update_guidance(alias, "New integration")
    assert outside.read_text() == "Keep this exactly"
    partial = tmp_path / "CLAUDE.md"
    partial.write_text("My rules\n" + START)
    with pytest.raises(AccessError):
        update_guidance(partial, "New integration")
    assert partial.read_text() == "My rules\n" + START


def test_codex_rule_is_narrow_idempotent_and_preserves_unrelated_policies(tmp_path):
    directory = tmp_path / ".codex"
    rules = directory / "rules"
    rules.mkdir(parents=True)
    unrelated = rules / "default.rules"
    original = 'prefix_rule(pattern=["restricted"], decision="forbidden")\n'
    unrelated.write_text(original)
    skill = tmp_path / ".agents/skills/account-access"
    path = Path(install_codex_rule(directory, skill))
    first = path.read_text()
    install_codex_rule(directory, skill)
    assert path.read_text() == first and unrelated.read_text() == original
    assert str(skill / "scripts/access") in first
    assert '"start"' not in first and '"python"' not in first and '"bash"' not in first
    assert path.stat().st_mode & 0o777 == 0o600
    path.write_text("My existing rule")
    with pytest.raises(AccessError):
        install_codex_rule(directory, skill)
    assert path.read_text() == "My existing rule"


def local_client(broker, tmp_path):
    install_skill(broker.store, "generic", tmp_path / "skills")
    broker.grant("generic", "demo-api", ["summary"])
    path = broker.store.root / "clients/generic/client.json"
    config = json.loads(path.read_text())
    config["auto_start"] = True
    private_file(path, json.dumps(config).encode(), replace=True)
    private_file(broker.store.root / "desktop.json", b"{}")
    return Client(path)


def test_connection_failure_wakes_service_and_keeps_agent_output_clean(env, tmp_path, monkeypatch):
    _, broker, _ = env
    client = local_client(broker, tmp_path)
    server = uvicorn.Server(uvicorn.Config(create_app(broker), uds=str(broker.store.root / "service.sock"), log_level="critical", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    commands = []
    def start(command, **kwargs):
        commands.append(command)
        assert command[1:3] == ["-I", "-m"]
        assert "ACCESS_CLIENT_CONFIG" not in kwargs["env"]
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.05)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr("account_access.client.subprocess.run", start)
    monkeypatch.setenv("ACCESS_CLIENT_CONFIG", "client-only")
    try:
        result = client.request("GET", "/v1/accounts")
        assert [a["account"] for a in result["accounts"]] == ["demo-api"]
        assert len(commands) == 1 and commands[0][-2:] == ["--no-open", "--on-demand"]
        assert client.request("POST", "/v1/run", {"account": "demo-api", "operation": "summary"})["status"] == "COMPLETED"
        assert len(commands) == 1
    finally:
        server.should_exit = True
        if thread.is_alive():
            thread.join(timeout=10)


def test_manual_pause_is_respected_and_timeouts_do_not_replay_operations(env, tmp_path, monkeypatch):
    _, broker, _ = env
    client = local_client(broker, tmp_path)
    private_file(broker.store.root / "service.paused", b"paused")
    called = []
    monkeypatch.setattr("account_access.client.subprocess.run", lambda *a, **k: called.append(a))
    with pytest.raises(AccessError) as error:
        client.request("GET", "/v1/accounts")
    assert error.value.reason == "service_paused" and not called
    client = Client(broker.store.root / "clients/generic/client.json")
    def timeout(request):
        raise httpx.ReadTimeout("Response timeout")
    client.transport = httpx.MockTransport(timeout)
    with pytest.raises(AccessError) as error:
        client.request("POST", "/v1/run", {"account": "demo-api", "operation": "summary"})
    assert error.value.reason == "service_unavailable" and not called


@pytest.mark.parametrize("changed", [{"version": "older-installed-version"},
                                     {"runtime": "/previous/installation/bin/python"}])
def test_service_upgrade_preserves_vault_grants_and_pause_intent(env, changed):
    _, broker, _ = env
    root = broker.store.root
    first = launch(root, key_file=root / "demo.key", open_browser=False)
    try:
        metadata = {**first, **changed}
        private_file(root / "desktop.json", json.dumps(metadata).encode(), replace=True)
        second = launch(root, key_file=root / "demo.key", open_browser=False)
        assert second["pid"] != first["pid"]
        assert second["version"] == __version__
        assert not (root / "service.paused").exists()
        assert broker.run("test", "demo-api", "summary")["status"] == "COMPLETED"
        stop(root)
        assert (root / "service.paused").is_file()
        with pytest.raises(AccessError) as error:
            launch(root, key_file=root / "demo.key", open_browser=False, on_demand=True)
        assert error.value.reason == "service_paused"
    finally:
        stop(root)
