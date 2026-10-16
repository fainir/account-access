"""Start/reopen the guided local app without asking users to maintain terminal processes."""

import json
import hashlib
import hmac
import os
import subprocess
import secrets
import sys
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

import httpx2 as httpx

from .errors import AccessError
from .models import Configuration
from .storage import Store, check_private, load_key, private_file
from . import __version__


def running(root):
    path = root / "desktop.json"
    if not path.exists():
        return None
    check_private(path)
    try:
        info = json.loads(path.read_text())
        if not isinstance(info, dict) or any(not isinstance(info.get(x), str)
                                            for x in ["url", "token", "instance_key"]):
            return None
        parts = urlsplit(info["url"])
        if (parts.scheme != "http" or parts.hostname != "127.0.0.1" or not parts.port
                or parts.path != "/" or parts.username or parts.password or parts.query or parts.fragment):
            return None
        key = bytes.fromhex(info["instance_key"])
        if len(key) != 32:
            return None
        challenge = secrets.token_hex(32)
        response = httpx.get(info["url"] + "owner/ready?challenge=" + challenge,
                             headers={"Authorization": "Bearer " + info["token"]},
                             trust_env=False, follow_redirects=False, timeout=1)
        expected = hmac.new(key, challenge.encode(), hashlib.sha256).hexdigest()
        payload = response.json() if response.status_code == 200 else {}
        proof = payload.get("proof", "") if isinstance(payload, dict) else ""
        return info if isinstance(proof, str) and secrets.compare_digest(proof, expected) else None
    except (ValueError, KeyError, httpx.HTTPError):
        return None


def launch(root, *, key_file=None, open_browser=True, on_demand=False):
    root = Path(root).expanduser()
    if root.is_symlink():
        raise AccessError("DENIED", "symlink_path")
    root = root.resolve()
    paused = root / "service.paused"
    if on_demand and paused.exists():
        raise AccessError("NEEDS_USER", "service_paused")
    if not on_demand:
        paused.unlink(missing_ok=True)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    store = Store(root, load_key(root, key_file, create=True))
    with store.lock("desktop-launch", timeout=20):
        info = running(root)
        if info and (info.get("version") != __version__ or info.get("runtime") != sys.executable):
            stop(root, updating=True)
            with store.lock("service", timeout=20):
                pass
            info = None
        if not info:
            from .upgrade import retire_development_routes
            retire_development_routes(store)
            if not (root / "config.json").exists():
                store.configure(Configuration(accounts={}))
            if len(str(root / "service.sock").encode()) >= 104:
                raise AccessError("DENIED", "socket_path_too_long")
            command = [sys.executable, "-m", "account_access.cli", "--root", str(root)]
            if key_file:
                command += ["--development", "--key-file", str(key_file)]
            command += ["desktop-host"]
            log_path = root / "desktop.log"
            if not log_path.exists():
                private_file(log_path, b"")
            check_private(log_path)
            with log_path.open("ab") as log:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                           start_new_session=True)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                info = running(root)
                if info:
                    break
                if process.poll() is not None:
                    raise AccessError("NEEDS_USER", "local_app_could_not_start")
                time.sleep(0.2)
            if not info:
                raise AccessError("RETRYABLE", "local_app_start_timed_out")
    if open_browser:
        webbrowser.open(info["url"] + "#" + info["token"])
        print("Account Access is ready. Setup opens in your browser.")
    else:
        print("Account Access is running. Reopen with start to see setup.")
    print("You can close this terminal. Reopen Account Access whenever you need it.")
    return info


def stop(root, *, updating=False):
    root = Path(root).expanduser()
    if not updating and (root / "config.json").is_file():
        paused = root / "service.paused"
        private_file(paused, b"paused", replace=paused.exists())
    info = running(root)
    if info:
        base = info["url"].rstrip("/")
        response = httpx.post(base + "/owner/stop", json={"updating": True} if updating else {},
                              headers={"Authorization": "Bearer " + info["token"], "Origin": base},
                              trust_env=False, follow_redirects=False, timeout=5)
        if response.status_code != 200:
            raise AccessError("DENIED", "could_not_stop_local_app")
    print("Account Access is stopped. Your saved connections are preserved.")


def host(broker):
    import uvicorn
    from .owner import make_owner_server
    from .service import create_app
    root = broker.store.root
    with broker.store.lock("service", timeout=0):
        socket = root / "service.sock"
        if socket.exists():
            socket.unlink()
        app = uvicorn.Server(uvicorn.Config(create_app(broker), uds=str(socket),
                                            log_level="critical", access_log=False))
        worker = threading.Thread(target=app.run, daemon=True)
        worker.start()
        deadline = time.monotonic() + 10
        while not app.started and worker.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not app.started:
            raise AccessError("RETRYABLE", "local_service_could_not_start")
        instance_key = secrets.token_bytes(32)
        server, token = make_owner_server(broker, guided=True, instance_key=instance_key)
        info = {"url": f"http://127.0.0.1:{server.server_port}/", "token": token,
                "instance_key": instance_key.hex(), "pid": os.getpid(), "version": __version__,
                "runtime": sys.executable}
        private_file(root / "desktop.json", json.dumps(info).encode(), replace=(root / "desktop.json").exists())
        try:
            with server:
                server.serve_forever()
        finally:
            app.should_exit = True
            worker.join(timeout=10)
