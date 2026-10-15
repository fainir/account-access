"""Reuse a vendor CLI's existing authorization for one fixed identity read.

No token is extracted, copied, persisted or returned. This adapter cannot run
arbitrary commands, hosts or API paths. It does not create browser sessions.
"""

import hashlib
import json
import os
import re
import secrets
import selectors
import subprocess
import time
from pathlib import Path

from .errors import AccessError
from .models import Configuration, GitHubCLIAccount

HANDLE = "github-connected"
DESCRIPTION = "Confirm the signed-in GitHub username"


def _execute(executable):
    # Never inherit an agent-supplied GH_TOKEN, host, config directory, debug
    # setting, proxy, pager or executable search path. Use the owner's normal
    # vendor CLI login. No auth/token command is ever invoked.
    environment = {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                   "LANG": "en_US.UTF-8", "GH_CONFIG_DIR": str(Path.home() / ".config/gh"),
                   "GH_PROMPT_DISABLED": "1", "GH_PAGER": "cat", "NO_COLOR": "1"}
    command = [executable, "api", "--hostname", "github.com", "--method", "GET", "user",
               "--jq", "{id,login}"]
    try:
        with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env=environment, cwd="/") as process:
            try:
                deadline = time.monotonic() + 20
                data = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise AccessError("RETRYABLE", "github_cli_timeout")
                        if not selector.select(min(remaining, 1)):
                            continue
                        chunk = os.read(process.stdout.fileno(), 8192)
                        if not chunk:
                            break
                        data.extend(chunk)
                        if len(data) > 16384:
                            raise AccessError("NEEDS_USER", "github_cli_response_changed", "unknown")
                result = process.wait(timeout=max(.01, deadline - time.monotonic()))
                if result != 0:
                    raise AccessError("NEEDS_USER", "github_cli_login_required", "login")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        value = json.loads(data)
        if (set(value) != {"id", "login"} or type(value["id"]) is not int or value["id"] <= 0
                or not isinstance(value["login"], str)
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,38}", value["login"])):
            raise ValueError()
        return value
    except AccessError:
        raise
    except subprocess.TimeoutExpired:
        raise AccessError("RETRYABLE", "github_cli_timeout") from None
    except (OSError, ValueError, TypeError, KeyError):
        raise AccessError("NEEDS_USER", "github_cli_response_changed", "unknown") from None


def _check_binary(spec):
    path = Path(spec.executable)
    try:
        if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                or not os.access(path, os.X_OK) or path.stat().st_size > 100_000_000):
            raise OSError()
        with path.open("rb") as binary:
            digest = hashlib.file_digest(binary, "sha256").hexdigest()
        if digest != spec.executable_sha256:
            raise OSError()
    except OSError:
        raise AccessError("NEEDS_USER", "github_cli_installation_changed", "device") from None


def identity(spec):
    _check_binary(spec)
    result = _execute(spec.executable)
    if result["id"] != spec.user_id or result["login"].lower() != spec.login.lower():
        raise AccessError("NEEDS_USER", "github_cli_account_changed", "login")
    return {"authenticated": True, "login": result["login"]}


def read(store, account, spec):
    saved = store.get("connection:" + account) or {}
    if saved.get("revoked"):
        raise AccessError("DENIED", "connection_revoked")
    if saved and saved.get("fingerprint") != store.config().fingerprint(account):
        raise AccessError("DENIED", "connection_configuration_changed")
    result = identity(spec)
    store.put("connection:" + account, {"fingerprint": store.config().fingerprint(account),
              "verified_at": time.time(), "provider": "github_cli"})
    return result


def installed_executable():
    return next((str(Path(path).resolve()) for path in
                       ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"]
                       if Path(path).is_file()), None)


def preview(store):
    executable = installed_executable()
    if not executable:
        raise AccessError("NEEDS_USER", "github_cli_not_installed", "login")
    with Path(executable).open("rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    result = _execute(executable)
    spec = GitHubCLIAccount(label="GitHub · " + result["login"], executable=executable,
                           executable_sha256=digest, user_id=result["id"], login=result["login"],
                           operations={"status": {}})
    _check_binary(spec)
    ident = secrets.token_hex(24)
    # One pending preview, replaced rather than accumulating account metadata.
    store.put("github-cli-preview", {"id": ident, "expires": time.time() + 600, "spec": spec.model_dump()})
    return {"status": "PREVIEW", "id": ident, "login": result["login"], "operation": DESCRIPTION}


def apply(broker, ident):
    store = broker.store
    if not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{48}", ident):
        raise AccessError("DENIED", "invalid_github_cli_preview")
    with store.lock("account:" + HANDLE), store.lock("catalog"):
        staged = store.get("github-cli-preview")
        if not staged or staged["id"] != ident or staged["expires"] < time.time():
            raise AccessError("DENIED", "github_cli_preview_expired")
        spec = GitHubCLIAccount.model_validate(staged["spec"])
        result = identity(spec)
        config = store.config()
        previous = config.accounts.get(HANDLE)
        if previous and (not isinstance(previous, GitHubCLIAccount) or previous.user_id != spec.user_id):
            raise AccessError("DENIED", "github_cli_connection_conflict")
        if not store.principal_active("generic"):
            raise AccessError("DENIED", "install_your_agent_first")
        config.accounts[HANDLE] = spec
        store.configure(Configuration.model_validate(config.model_dump()))
        with store.db() as db:
            db.execute("DELETE FROM grants WHERE account=?", (HANDLE,))
            db.execute("INSERT INTO grants VALUES (?,?,?,?,NULL)",
                       ("generic", HANDLE, "status", config.fingerprint(HANDLE)))
            store.put("connection:" + HANDLE, {"fingerprint": config.fingerprint(HANDLE),
                      "verified_at": time.time(), "provider": "github_cli"}, db=db)
            store.put("github-cli-preview", None, db=db)
        store.resolve_login(HANDLE)
        store.audit("owner", HANDLE, "status", "github_cli_connected")
    return {"status": "CONNECTED", "account": HANDLE, **result}
