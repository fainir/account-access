import json
import os
import subprocess
import sys
import threading
import time

import httpx2 as httpx
import pytest
import uvicorn

from account_access.errors import AccessError
from account_access.install import install_skill
from account_access.owner import make_owner_server
from account_access.service import create_app


def test_installed_skill_calls_real_private_service_and_worker(env, tmp_path):
    _, broker, _ = env
    installation = install_skill(broker.store, "generic", tmp_path)
    broker.grant("generic", "demo-api", ["summary"])
    socket = broker.store.root / "service.sock"
    server = uvicorn.Server(uvicorn.Config(create_app(broker), uds=str(socket), log_level="critical", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        script = str(tmp_path / "account-access/scripts/access.py")
        result = subprocess.run([sys.executable, script, "accounts"], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["accounts"][0]["account"] == "demo-api"
        hostile = tmp_path / "untrusted-project"
        (hostile / "account_access").mkdir(parents=True)
        marker = hostile / "project-code-ran"
        poison = ("from pathlib import Path\nPath(" + repr(str(marker))
                  + ").write_text('unexpected import')\nraise RuntimeError('untrusted project import')\n")
        for path in [hostile / "json.py", hostile / "sitecustomize.py", hostile / "account_access/__init__.py"]:
            path.write_text(poison)
        wrapper = tmp_path / "account-access/scripts/access"
        isolated = subprocess.run([str(wrapper), "accounts"], cwd=hostile,
                                 env={**os.environ, "PYTHONPATH": str(hostile)},
                                 capture_output=True, text=True, timeout=10)
        assert isolated.returncode == 0, isolated.stderr
        assert json.loads(isolated.stdout)["accounts"][0]["account"] == "demo-api"
        assert not marker.exists()
        submit = subprocess.run([sys.executable, script, "task", "submit", "--key", "cli-test", "--steps", "demo-api:summary"], capture_output=True, text=True, timeout=30)
        job = json.loads(submit.stdout)
        waiting = subprocess.run([sys.executable, script, "task", "wait", job["task_id"], "--timeout", "15"], capture_output=True, text=True, timeout=30)
        assert json.loads(waiting.stdout)["status"] == "COMPLETED"
        deadline = time.time() + 10
        while time.time() < deadline:
            completed = broker.task("generic", job["task_id"])
            if completed["status"] == "COMPLETED":
                break
            time.sleep(0.1)
        assert completed["status"] == "COMPLETED"
        rejected = subprocess.run([sys.executable, script, "credential", "demo-api"], capture_output=True, text=True, timeout=10)
        assert rejected.returncode == 3
        assert "DENIED" in rejected.stdout
        assert "token" not in (tmp_path / "account-access/installation.json").read_text()
        assert installation["principal"] == "generic"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_other_agents_install_and_preserve_unrelated_files(env, tmp_path):
    _, broker, _ = env
    unrelated = tmp_path / "existing-skill"
    unrelated.mkdir()
    (unrelated / "SKILL.md").write_text("existing")
    result = install_skill(broker.store, "generic", tmp_path)
    assert (unrelated / "SKILL.md").read_text() == "existing"
    assert os.stat(result["skill_path"]).st_mode & 0o077 == 0
    install_skill(broker.store, "generic", tmp_path)


def test_automatic_install_is_portable_detected_and_idempotent(env, tmp_path, monkeypatch):
    from pathlib import Path
    from account_access.install import install_detected
    _, broker, _ = env
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    monkeypatch.setattr("account_access.install.shutil.which", lambda name: None)
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".claude").mkdir()
    result = install_detected(broker.store)
    assert {c["agent"] for c in result["clients"]} == {"generic", "codex", "claude"}
    assert {c["principal"] for c in result["clients"]} == {"generic"}
    assert Path(result["portable_cli"]).is_file()
    token = (broker.store.root / "clients/generic/token").read_text()
    install_detected(broker.store)
    assert (broker.store.root / "clients/generic/token").read_text() == token
    assert broker.store.client(token) == "generic"


def test_installer_refuses_unknown_existing_skill(env, tmp_path):
    _, broker, _ = env
    (tmp_path / "account-access").mkdir()
    try:
        install_skill(broker.store, "generic", tmp_path)
        assert False
    except AccessError as exc:
        assert exc.reason == "existing_skill_would_be_overwritten"


@pytest.mark.parametrize("connection", ["protected", "other-preview"])
@pytest.mark.parametrize("entrypoint", ["install", "sync", "detected"])
def test_preview_preserves_foreign_connection_and_existing_client(
        env, tmp_path, monkeypatch, connection, entrypoint):
    from pathlib import Path
    from account_access.install import install_detected, sync_skill

    _, broker, _ = env
    home = tmp_path / "owner-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))
    monkeypatch.setattr("account_access.install.shutil.which", lambda _: None)
    (home / ".claude").mkdir()
    primary = home / ".agents/skills/account-access"
    alias = home / ".claude/skills/account-access"
    # Give this preview a working client that must survive a rejected switch.
    install_skill(broker.store, "generic", primary.parent)
    token_file = broker.store.root / "clients/generic/token"
    token = token_file.read_bytes()
    config_file = token_file.with_name("client.json")
    before_config = config_file.read_bytes()
    foreign = home / ("Library/Application Support/Account Access/client-v1/client.json"
                      if connection == "protected" else ".local/share/another-preview/clients/generic/client.json")
    target = alias if entrypoint == "detected" else primary
    if target == primary:
        binding = target / "installation.json"
        value = json.loads(binding.read_text())
        value["client_config"] = str(foreign)
        binding.write_text(json.dumps(value))
    else:
        sync_skill(alias, foreign)
    before = {str(path.relative_to(home)): path.read_bytes()
              for path in home.rglob("*") if path.is_file()}
    action = {"install": lambda: install_skill(broker.store, "generic", target.parent),
              "sync": lambda: sync_skill(target, config_file),
              "detected": lambda: install_detected(broker.store)}[entrypoint]
    with pytest.raises(AccessError, match="existing_skill_would_be_overwritten"):
        action()
    assert {str(path.relative_to(home)): path.read_bytes()
            for path in home.rglob("*") if path.is_file()} == before
    assert token_file.read_bytes() == token
    assert config_file.read_bytes() == before_config
    assert broker.store.client(token.decode()) == "generic"


@pytest.mark.parametrize("change", ["wrong-marker", "missing-binding", "hardlink", "directory", "oversized"])
def test_refresh_rejects_unrecognized_binding_metadata(env, tmp_path, change):
    from account_access.install import sync_skill

    _, broker, _ = env
    install_skill(broker.store, "generic", tmp_path)
    target = tmp_path / "account-access"
    config_file = broker.store.root / "clients/generic/client.json"
    binding = target / "installation.json"
    if change == "wrong-marker":
        (target / ".account-access-install").write_text("someone-else")
    elif change == "missing-binding":
        binding.unlink()
    elif change == "hardlink":
        os.link(binding, tmp_path / "binding-copy")
    elif change == "directory":
        binding.unlink()
        binding.mkdir()
    else:
        binding.write_bytes(b" " * 16385)
    launcher = (target / "scripts/access").read_bytes()
    with pytest.raises(AccessError, match="existing_skill_would_be_overwritten"):
        sync_skill(target, config_file)
    assert (target / "scripts/access").read_bytes() == launcher


def test_owner_console_auth_csrf_and_scope_reduction(env):
    _, broker, _ = env
    server, token = make_owner_server(broker)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            assert client.get("/owner/state").status_code == 401
            headers = {"Authorization": "Bearer " + token, "Origin": base}
            state = client.get("/owner/state", headers=headers).json()
            assert state["environment"] == "controlled-demo"
            from account_access.demo import DEMO_PASSWORD, DEMO_SEED
            public_state = json.dumps(state)
            assert DEMO_PASSWORD not in public_state and DEMO_SEED not in public_state
            assert '"password":' not in public_state
            assert client.post("/owner/revoke", json={"account": "demo-api"}, headers={"Authorization": "Bearer " + token}).status_code == 403
            result = client.post("/owner/grant", json={"account": "demo-api", "principal": "test", "operations": ["summary"]}, headers=headers)
            assert result.status_code == 200
            assert broker.run("test", "demo-api", "details")["status"] == "DENIED"
            assert client.get("/", headers={"Host": "evil.example"}).status_code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
