"""Thin agent-side client. It cannot load vault keys or change standing permissions."""

import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx2 as httpx

from .errors import AccessError
from .storage import check_private


def default_client_config():
    return Path(os.environ.get("ACCESS_CLIENT_CONFIG", str(Path.home() / ".config/account-access/client.json")))


class Client:
    def __init__(self, config_path=None):
        path = Path(config_path or default_client_config())
        check_private(path)
        config = json.loads(path.read_text())
        token_path = Path(config["token_file"])
        check_private(token_path)
        self.token = token_path.read_text().strip()
        self.start_root = None
        if "socket" in config:
            self.base_url = "http://localhost"
            self.transport = httpx.HTTPTransport(uds=config["socket"])
            root = path.resolve().parent.parent.parent
            if (config.get("auto_start") is True and path.parent.parent.name == "clients"
                    and Path(config["socket"]) == root / "service.sock"
                    and token_path == path.parent / "token"):
                self.start_root = root
        else:
            self.base_url = config["url"]
            parts = urlsplit(self.base_url)
            if parts.scheme != "https" or parts.username or parts.password or parts.query or parts.fragment:
                raise AccessError("DENIED", "secure_service_url_required")
            self.transport = httpx.HTTPTransport()

    def request(self, method, path, body=None):
        try:
            with httpx.Client(transport=self.transport, base_url=self.base_url, timeout=60,
                              follow_redirects=False, trust_env=False) as client:
                response = client.request(method, path, json=body,
                                          headers={"Authorization": "Bearer " + self.token})
                if 300 <= response.status_code < 400:
                    raise AccessError("DENIED", "service_redirect_blocked")
                if len(response.content) > 2_000_000:
                    raise AccessError("DENIED", "service_response_too_large")
                return response.json()
        except httpx.ConnectError:
            if self.start_root is not None:
                root, self.start_root = self.start_root, None
                if (root / "service.paused").exists():
                    raise AccessError("NEEDS_USER", "service_paused")
                check_private(root / "desktop.json")
                check_private(root / "config.json")
                check_private(root / "state.db")
                environment = dict(os.environ)
                environment.pop("ACCESS_CLIENT_CONFIG", None)
                try:
                    result = subprocess.run([sys.executable, "-I", "-m", "account_access.cli",
                        "--root", str(root), "start", "--no-open", "--on-demand"], capture_output=True,
                        timeout=35, env=environment)
                except (subprocess.TimeoutExpired, OSError):
                    raise AccessError("RETRYABLE", "local_app_could_not_start") from None
                if result.returncode == 0:
                    return self.request(method, path, body)
            raise AccessError("RETRYABLE", "service_unavailable") from None
        except httpx.HTTPError:
            raise AccessError("RETRYABLE", "service_unavailable") from None
