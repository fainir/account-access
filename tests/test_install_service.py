import json
import os
import subprocess
import sys
import threading
import time

import httpx2 as httpx
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
            assert "password" not in json.dumps(state)
            assert client.post("/owner/revoke", json={"account": "demo-api"}, headers={"Authorization": "Bearer " + token}).status_code == 403
            result = client.post("/owner/grant", json={"account": "demo-api", "principal": "test", "operations": ["summary"]}, headers=headers)
            assert result.status_code == 200
            assert broker.run("test", "demo-api", "details")["status"] == "DENIED"
            assert client.get("/", headers={"Host": "evil.example"}).status_code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
