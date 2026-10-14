import json
import os
import signal
import secrets
import subprocess
import threading
import time

import httpx2 as httpx

from account_access.catalog import add
from account_access.desktop import launch, running, stop
from account_access.errors import AccessError
from account_access.install import install_skill
from account_access.owner import make_owner_server
from account_access.storage import private_file


def test_guided_setup_connects_grants_and_never_returns_credentials(env, tmp_path, monkeypatch):
    provider, broker, _ = env
    spec = broker.store.config().accounts["demo-web"].model_copy(deep=True)
    spec.label = "Personal shopping account"
    monkeypatch.setattr("account_access.catalog.entries", lambda: {"personal-store": spec})
    actual_install = install_skill
    monkeypatch.setattr("account_access.install.install_skill",
                        lambda store, agent: actual_install(store, agent, tmp_path / agent))
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            headers = {"Authorization": "Bearer " + token, "Origin": base}
            assert client.get("/").headers["content-type"].startswith("text/html")
            assert client.get("/owner/state").status_code == 401
            assert client.post("/owner/install", json={"agents": ["codex"]}).status_code == 403
            assert client.post("/owner/install", json={"agents": ["codex", "claude"]}, headers=headers).status_code == 200
            from account_access.demo import DEMO_PASSWORD
            payload = {"service": "personal-store", "username": "demo@example.test",
                       "password": DEMO_PASSWORD, "agents": ["codex", "claude"]}
            invalid = {**payload, "service": "evil", "url": "https://attacker.example"}
            assert client.post("/owner/add", json=invalid, headers=headers).status_code == 400
            response = client.post("/owner/add", json=payload, headers=headers)
            assert response.status_code == 200
            ident = response.json()["id"]
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                state = client.get("/owner/state", headers=headers).json()
                if state["connection_jobs"][ident]["status"] != "RUNNING":
                    break
                time.sleep(0.1)
            assert state["connection_jobs"][ident]["status"] == "CONNECTED"
            assert DEMO_PASSWORD not in json.dumps(state)
            assert "demo@example.test" not in json.dumps(state)
            assert broker.run("codex", "personal-store", "summary")["status"] == "COMPLETED"
            assert broker.run("claude", "personal-store", "summary")["status"] == "COMPLETED"
            assert provider.login_count == 1  # One owner connection, both agents reuse it.
            assert client.post("/owner/add", json=payload, headers=headers).status_code == 403
            broker.store.put("connection:personal-store", None)
            broker.store.put("login-attempt:personal-store", 0)
            assert client.post("/owner/verify", json={"account": "personal-store"}).status_code == 403
            assert client.post("/owner/verify", json={"account": "evil"}, headers=headers).status_code == 403
            assert client.post("/owner/verify", json={"account": "personal-store", "url": "https://attacker.example"}, headers=headers).status_code == 400
            retry = client.post("/owner/verify", json={"account": "personal-store"}, headers=headers)
            assert retry.status_code == 200
            ident = retry.json()["id"]
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                state = client.get("/owner/state", headers=headers).json()
                if state["connection_jobs"][ident]["status"] != "RUNNING":
                    break
                time.sleep(0.1)
            assert state["connection_jobs"][ident]["status"] == "CONNECTED"
            assert provider.login_count == 2
            assert DEMO_PASSWORD not in json.dumps(state)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_catalog_rejects_unreviewed_destinations_and_preserves_existing(env):
    _, broker, _ = env
    before = broker.store.config().model_dump()
    try:
        add(broker.store, "https://attacker.example")
        assert False
    except AccessError as error:
        assert error.reason == "unsupported_service"
    assert broker.store.config().model_dump() == before


def test_generated_agent_launcher_does_not_need_python_on_path(env, tmp_path):
    _, broker, _ = env
    install_skill(broker.store, "generic", tmp_path)
    wrapper = tmp_path / "account-access/scripts/access"
    assert os.stat(wrapper).st_mode & 0o777 == 0o700
    result = subprocess.run([str(wrapper), "credential", "demo-api"],
                            env={**os.environ, "PATH": "/usr/bin:/bin"}, capture_output=True, text=True)
    assert result.returncode == 3
    assert "agent_command_not_supported" in result.stdout


def test_installer_preserves_files_outside_a_symlinked_skill(env, tmp_path):
    _, broker, _ = env
    install_skill(broker.store, "generic", tmp_path / "skills")
    outside = tmp_path / "outside"
    outside.write_text("preserve this file")
    wrapper = tmp_path / "skills/account-access/scripts/access"
    wrapper.unlink()
    wrapper.symlink_to(outside)
    try:
        install_skill(broker.store, "generic", tmp_path / "skills")
        assert False
    except AccessError as error:
        assert error.reason == "symlink_path"
    assert outside.read_text() == "preserve this file"


def test_background_app_reopens_existing_instance_and_keeps_key_private(env):
    _, broker, _ = env
    root = broker.store.root
    key_file = root / "demo.key"
    info = launch(root, key_file=key_file, open_browser=False)
    try:
        assert running(root)["pid"] == info["pid"]
        reopened = launch(root, key_file=key_file, open_browser=False)
        assert reopened["pid"] == info["pid"]
        assert os.stat(root / "desktop.json").st_mode & 0o077 == 0
        assert "token" not in (root / "desktop.log").read_text()
        base = info["url"].rstrip("/")
        with httpx.Client(trust_env=False) as client:
            assert client.post(base + "/owner/stop", json={}).status_code == 403
        stop(root)
    finally:
        deadline = time.monotonic() + 8
        while running(root) and time.monotonic() < deadline:
            time.sleep(0.1)
        if running(root):
            os.kill(info["pid"], signal.SIGTERM)


def test_reused_local_port_cannot_impersonate_the_background_app(tmp_path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Impostor(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"proof":"fake","accounts":[]}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Impostor)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    private_file(tmp_path / "desktop.json", json.dumps({"url": f"http://127.0.0.1:{server.server_port}/",
                 "token": secrets.token_urlsafe(32), "instance_key": secrets.token_hex(32)}).encode())
    try:
        assert running(tmp_path) is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
