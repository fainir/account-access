"""Explicitly enrolled Bitwarden Password Manager connections.

The protected worker alone keeps the encrypted CLI profile and unlock session.
Each bounded child uses a new private HOME, fixed executable, and exact item ID.
The master password is used only by the initial unlock child and is never saved.
"""

import base64
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

from .errors import AccessError
from .models import origin, validate_url
from .storage import private_file

PROVIDER = "bitwarden"
PREFIX = "password-source:bitwarden:"
IDENT = re.compile(r"^[a-f0-9]{32}$")
UUID = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
REGIONS = {"us": "https://vault.bitwarden.com", "eu": "https://vault.bitwarden.eu"}
RUNTIME = Path(sys.prefix) / "libexec/bitwarden"
CLI = RUNTIME / "build/bw.js"
NODE = Path(sys.prefix) / "lib/python3.12/site-packages/playwright/driver/node"
MANIFEST = RUNTIME / "runtime-manifest.json"
VERSION = "2026.10.0"
NODE_VERSION = "24.21.0"
ENTRYPOINT_SHA256 = "7cad23262b9ca168f22c12d7cdf64ef168e57d49784377c2b8cd02707759e4d7"
ARCHIVE_SHA256 = "2a04ebc02ca970bbadd2e6d6316e06d164526760e424e5c3bb050a8110197223"
CONNECT_DEADLINE = 65
FETCH_DEADLINE = 25
MAX_OUTPUT = 262144
MAX_PROFILE = 16 * 1024 * 1024
CLI_DEADLINE = 20


def fail(reason, status="DENIED"):
    raise AccessError(status, reason)


def _identifier(value):
    return isinstance(value, str) and IDENT.fullmatch(value) is not None


def _command(store):
    """The fixture exception cannot select an executable through owner input."""
    try:
        paths = ((NODE, True), (CLI, False), (MANIFEST, False))
        if not store.config().test_mode:
            from .worker_bootstrap import read_policy, require_worker_identity, root_managed_path
            policy = read_policy(store.root.parent.parent / "broker/worker.json")
            if require_worker_identity(policy, worker_module=__file__) != store.root:
                raise ValueError()
            if any(root_managed_path(path) != path.resolve(strict=True) for path, _ in paths):
                raise ValueError()
        for path, executable in paths:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_mode & 0o022 or (executable and not info.st_mode & 0o111)):
                raise ValueError()
        # Upstream gives this portable profile precedence over APPDATA_DIR.
        # A protected runtime must never silently adopt even a bundled profile.
        portable_profile = NODE.parent / "bw-data"
        if portable_profile.exists() or portable_profile.is_symlink():
            raise ValueError()
        if MANIFEST.stat().st_size > 16384:
            raise ValueError()
        manifest = _json(MANIFEST.read_bytes())
        expected = {"schema": 1, "version": VERSION, "architecture": "arm64",
                    "entrypoint": "build/bw.js",
                    "node_relative": "lib/python3.12/site-packages/playwright/driver/node",
                    "node_version": NODE_VERSION, "native_addons": False,
                    "entrypoint_sha256": ENTRYPOINT_SHA256,
                    "upstream_archive_sha256": ARCHIVE_SHA256}
        if (not isinstance(manifest, dict)
                or any(type(manifest.get(key)) is not type(value) or manifest[key] != value
                       for key, value in expected.items())
                or hashlib.sha256(CLI.read_bytes()).hexdigest() != ENTRYPOINT_SHA256):
            raise ValueError()
        # The fixed protected Node replaces the upstream older embedded Node.
        # Neither global module lookup nor native addons are available to it.
        return [str(NODE), "--no-global-search-paths", "--no-addons", str(CLI)]
    except Exception:
        fail("password_source_runtime_unavailable", "NEEDS_USER")


def available(store):
    try:
        _command(store)
        return True
    except AccessError:
        return False


def _run(command, args, directory, expires, *, secret_environment=None):
    """No shell, TTY, inherited secrets, provider diagnostics or unlimited pipes."""
    expires = min(expires, time.monotonic() + CLI_DEADLINE)
    # Upstream may discover Desktop IPC during startup even with nointeraction.
    # Its explicit missing override fails before searching /Applications or the
    # owner's app; the CLI catches that optional IPC failure and continues.
    disabled_proxy = Path(directory) / ".account-access-disabled-desktop-ipc"
    if disabled_proxy.exists() or disabled_proxy.is_symlink():
        fail("password_source_item_changed")
    environment = {"HOME": str(directory), "TMPDIR": str(directory),
                   "BITWARDENCLI_APPDATA_DIR": str(directory), "BW_NOINTERACTION": "true",
                   "BITWARDEN_DESKTOP_PROXY_PATH": str(disabled_proxy),
                   "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    environment.update(secret_environment or {})
    output = bytearray()
    process = None
    try:
        remaining = expires - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        process = subprocess.Popen([*command, *args, "--nointeraction"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=environment, cwd=directory,
                                   close_fds=True, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = expires - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError()
                chunk = os.read(process.stdout.fileno(), min(4096, MAX_OUTPUT + 1 - len(output)))
                if not chunk:
                    selector.unregister(process.stdout)
                else:
                    output.extend(chunk)
                    if len(output) > MAX_OUTPUT:
                        fail("password_source_item_changed")
        process.wait(timeout=max(0, expires - time.monotonic()))
        if process.returncode:
            # Diagnostics can contain secrets and have no stable error schema.
            # A nonzero exit never permits a cached credential to be used.
            fail("password_source_unavailable", "RETRYABLE")
        return bytes(output)
    except (OSError, TimeoutError, subprocess.TimeoutExpired):
        fail("password_source_unavailable", "RETRYABLE")
    finally:
        environment.clear()
        if process is not None:
            # Also stop a helper left behind by a successfully exited CLI.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.returncode is None:
                process.wait(timeout=2)
            process.stdout.close()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        fail("password_source_item_changed")


def _profile(directory, *, forbidden=None):
    path = Path(directory) / "data.json"
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or info.st_size > MAX_PROFILE or info.st_size == 0):
            raise ValueError()
        # Only this newly created, service-private profile is ever read.
        value = _json(path.read_bytes())
        if not isinstance(value, dict):
            raise ValueError()
        def contains(item):
            if isinstance(item, dict):
                return any(contains(child) for child in item.values())
            if isinstance(item, list):
                return any(contains(child) for child in item)
            return isinstance(item, str) and item == forbidden
        if forbidden is not None and contains(value):
            raise ValueError()
        return value
    except (OSError, ValueError, RecursionError):
        fail("password_source_item_changed")


def _identity(raw, region, *, expected_user=None, unlocked=True):
    value = _json(raw)
    if (not isinstance(value, dict) or value.get("serverUrl") not in
            ((None, REGIONS[region]) if region == "us" else (REGIONS[region],))
            or value.get("status") not in (("unlocked",) if unlocked else ("locked", "unlocked"))
            or not isinstance(value.get("userId"), str) or not UUID.fullmatch(value["userId"])
            or (expected_user is not None and value["userId"] != expected_user)
            or not isinstance(value.get("userEmail"), str)
            or not 3 <= len(value["userEmail"]) <= 320
            or "@" not in value["userEmail"] or any(ord(c) < 32 for c in value["userEmail"])):
        fail("password_source_access_removed")
    return value


def _timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        result = parsed.timestamp()
        if not math.isfinite(result):
            raise ValueError()
        return result
    except (AttributeError, TypeError, ValueError, OverflowError):
        fail("password_source_unavailable", "RETRYABLE")


def _sync(command, directory, expires, record):
    session = {"BW_SESSION": record["session"]}
    before = _identity(_run(command, ["status"], directory, expires,
                            secret_environment=session), record["region"],
                       expected_user=record["user_id"])
    started = time.time()
    _run(command, ["sync", "--force"], directory, expires, secret_environment=session)
    after = _identity(_run(command, ["status"], directory, expires,
                           secret_environment=session), record["region"],
                      expected_user=record["user_id"])
    fresh = _timestamp(after.get("lastSync"))
    if (after["userEmail"] != record["email"] or before["userEmail"] != record["email"]
            or fresh < started - 1 or fresh > time.time() + 5
            or (before.get("lastSync") and fresh <= _timestamp(before["lastSync"]))):
        fail("password_source_unavailable", "RETRYABLE")
    return after


def _public(record):
    return {key: record.get(key) for key in
            ["id", "generation", "provider", "region", "email", "status", "checked", "reason"]}


@contextmanager
def _database(store):
    try:
        with store.db() as db:
            # Source refresh must not spend the Store's normal twenty-second
            # write wait after using its bounded subprocess budget.
            db.execute("PRAGMA busy_timeout=1000")
            yield db
    except sqlite3.Error:
        fail("password_source_unavailable", "RETRYABLE")


def _audit(db, event):
    db.execute("INSERT INTO audit(at,principal,account,operation,event,reason) VALUES (?,?,?,?,?,?)",
               (time.time(), "owner", "", "", event, ""))


def _save(store, record):
    with _database(store) as db:
        store.put(PREFIX + record["id"], record, db=db)
        if record["status"] == "CONNECTED":
            return
        rows = db.execute("SELECT id,value FROM records WHERE id LIKE 'password-link:%'").fetchall()
        for row in rows:
            link = store.unseal(row[0], row[1])
            if (isinstance(link, dict) and link.get("provider") == PROVIDER
                    and link.get("connection") == record["id"]
                    and link.get("connection_generation") == record["generation"]):
                account = row[0].split(":", 1)[1]
                link.update(status="RETRYABLE" if record["status"] == "RETRYABLE" else "BLOCKED",
                            reason=record["reason"], next_at=time.time() + 60)
                store.put(row[0], link, db=db)
                store.put("credential:" + account, None, db=db)
                store.put("connection:" + account, None, db=db)


def _publish_connection(store, record):
    with store.lock(PREFIX + record["id"], timeout=2):
        with _database(store) as db:
            store.put(PREFIX + record["id"], record, db=db)
            rows = db.execute("SELECT id,value FROM records WHERE id LIKE 'password-link:%'").fetchall()
            for row in rows:
                link = store.unseal(row[0], row[1])
                if (isinstance(link, dict) and link.get("provider") == PROVIDER
                        and link.get("connection") == record["id"]
                        and link.get("connection_generation") != record["generation"]):
                    account = row[0].split(":", 1)[1]
                    link.update(status="BLOCKED", reason="bitwarden_connection_changed", next_at=0)
                    store.put(row[0], link, db=db)
                    store.put("credential:" + account, None, db=db)
                    store.put("connection:" + account, None, db=db)
            _audit(db, "bitwarden_source_connected")


def secret_values(store, link):
    """Defense-in-depth output redaction without returning a source to an agent."""
    if not isinstance(link, dict) or link.get("provider") != PROVIDER:
        return set()
    try:
        record = _record(store, link, retry=True)
    except AccessError:
        return set()
    values = {record["session"], *record.get("redactions", [])}
    def visit(value, depth=0):
        if depth > 32:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if (isinstance(key, str) and re.search(r"token|secret", key, re.I)
                        and isinstance(item, str) and 0 < len(item) <= 8192):
                    values.add(item)
                visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, depth + 1)
    visit(record["profile"])
    return values


def connections(store):
    with store.db() as db:
        keys = [row[0] for row in db.execute(
            "SELECT id FROM records WHERE id LIKE ? ORDER BY id LIMIT 100", (PREFIX + "%",))]
    return [_public(value) for key in keys if isinstance(value := store.get(key), dict)
            and value.get("status") != "DISCONNECTED"]


def _link_ids(link):
    if (not isinstance(link, dict) or not _identifier(link.get("connection"))
            or not _identifier(link.get("connection_generation"))):
        fail("invalid_password_sync_link")
    return link["connection"], link["connection_generation"]


def _record(store, link, *, retry=False):
    ident, generation = _link_ids(link)
    value = store.get(PREFIX + ident)
    if not isinstance(value, dict) or value.get("status") == "DISCONNECTED":
        fail("password_source_access_removed")
    if value.get("generation") != generation:
        fail("bitwarden_connection_changed")
    if value.get("status") == "BLOCKED":
        fail("password_source_access_removed")
    if value.get("status") == "RETRYABLE" and not retry:
        fail("password_source_unavailable", "RETRYABLE")
    if not isinstance(value.get("profile"), dict) or not isinstance(value.get("session"), str):
        fail("password_source_access_removed")
    return value


def check(store, link):
    """Revocation is checked even while a per-account sync interval is fresh."""
    _record(store, link)


@contextmanager
def authority(store, link):
    """Keep source revocation serialized with the final credential publication."""
    ident, _ = _link_ids(link)
    with store.lock(PREFIX + ident, timeout=2):
        _record(store, link)
        yield


def connect(store, data):
    required = {"region", "client_id", "client_secret", "master_password", "consent_vault_access"}
    if not isinstance(data, dict) or set(data) != required:
        fail("bitwarden_connection_invalid")
    if data["consent_vault_access"] is not True:
        fail("bitwarden_vault_consent_required")
    if (not isinstance(data["region"], str) or data["region"] not in REGIONS
            or not isinstance(data["client_id"], str)
            or not data["client_id"].startswith("user.") or not UUID.fullmatch(data["client_id"][5:])
            or not isinstance(data["client_secret"], str) or not 1 <= len(data["client_secret"]) <= 8192
            or any(c in data["client_secret"] for c in "\0\r\n")
            or not isinstance(data["master_password"], str) or not 1 <= len(data["master_password"]) <= 4096
            or "\0" in data["master_password"]):
        fail("bitwarden_connection_invalid")
    command = _command(store)
    expires = time.monotonic() + CONNECT_DEADLINE - 5
    with tempfile.TemporaryDirectory(prefix="bitwarden-enroll-", dir=store.root) as directory:
        if _run(command, ["--version"], directory, expires).strip() != VERSION.encode():
            fail("password_source_runtime_unavailable", "NEEDS_USER")
        _run(command, ["config", "server", REGIONS[data["region"]]], directory, expires)
        _run(command, ["login", "--apikey", "--raw"], directory, expires,
             secret_environment={"BW_CLIENTID": data["client_id"], "BW_CLIENTSECRET": data["client_secret"]})
        raw = _run(command, ["unlock", "--passwordenv", "ACCOUNT_ACCESS_BW_MASTER_PASSWORD", "--raw"],
                   directory, expires,
                   secret_environment={"ACCOUNT_ACCESS_BW_MASTER_PASSWORD": data["master_password"]})
        try:
            session = raw.decode("ascii").strip()
            if len(base64.b64decode(session, validate=True)) not in {32, 64}:
                raise ValueError()
        except (ValueError, UnicodeError):
            fail("password_source_access_removed")
        identity = _identity(_run(command, ["status"], directory, expires,
                                  secret_environment={"BW_SESSION": session}), data["region"],
                             expected_user=data["client_id"][5:])
        ident = hashlib.sha256((data["region"] + "\0" + identity["userId"]).encode()).hexdigest()[:32]
        record = {"id": ident, "generation": secrets.token_hex(16),
                  "provider": "Bitwarden", "region": data["region"], "user_id": identity["userId"],
                  "email": identity["userEmail"], "session": session,
                  "redactions": [data["client_secret"]]}
        _sync(command, directory, expires, record)
        record.update(profile=_profile(directory, forbidden=data["master_password"]),
                      status="CONNECTED", checked=time.time())
    _publish_connection(store, record)
    return _public(record)


def _credentials(item, link, expected_origin, *, test_mode=False):
    try:
        if (not isinstance(item, dict) or item.get("id") != link["item"]
                or type(item.get("type")) is not int or item["type"] != 1
                or item.get("deletedDate") is not None or item.get("archivedDate") is not None
                or item.get("isArchived", False) is not False or item.get("isDeleted", False) is not False
                or type(item.get("reprompt", 0)) is not int or item.get("reprompt", 0) != 0
                or not isinstance(item.get("login"), dict)):
            raise ValueError()
        login = item["login"]
        uris = login.get("uris")
        if not isinstance(uris, list) or not 1 <= len(uris) <= 64:
            raise ValueError()
        if origin(validate_url(expected_origin, test_mode)) != expected_origin:
            raise ValueError()
        websites = set()
        for entry in uris:
            if not isinstance(entry, dict):
                raise ValueError()
            match = entry.get("match")
            if match is not None and (type(match) is not int or not 0 <= match <= 5):
                raise ValueError()
            # Regex, Never, mobile-app and null entries confer no website
            # authority. Other match modes still use our exact approved origin.
            if match in {4, 5}:
                continue
            raw = entry.get("uri")
            if raw is None:
                continue
            if not isinstance(raw, str) or len(raw) > 4096:
                raise ValueError()
            raw.encode("utf-8")
            parts = urlsplit(raw)
            if parts.scheme not in {"http", "https"}:
                continue
            if parts.port == 0:
                raise ValueError()
            if (not parts.hostname or parts.username or parts.password
                    or (parts.scheme != "https" and not test_mode)):
                continue
            websites.add(origin(raw))
        if (expected_origin not in websites
                or any(not isinstance(login.get(key), str) or not 0 < len(login[key]) <= 4096
                       for key in ["username", "password"])):
            raise ValueError()
        return {key: login[key] for key in ["username", "password"]}
    except (ValueError, TypeError, AttributeError):
        fail("password_source_item_changed")


def fetch(store, link, expected_origin):
    ident, _ = _link_ids(link)
    if not isinstance(link.get("item"), str) or not UUID.fullmatch(link["item"]):
        fail("invalid_password_sync_link")
    expires = time.monotonic() + FETCH_DEADLINE - 5
    command = _command(store)
    with store.lock(PREFIX + ident, timeout=2):
        record = _record(store, link, retry=True)
        with tempfile.TemporaryDirectory(prefix="bitwarden-read-", dir=store.root) as directory:
            private_file(Path(directory) / "data.json", json.dumps(record["profile"]).encode())
            try:
                _sync(command, directory, expires, record)
                raw = _run(command, ["get", "item", link["item"]], directory, expires,
                           secret_environment={"BW_SESSION": record["session"]})
                credential = _credentials(_json(raw), link, expected_origin,
                                          test_mode=store.config().test_mode)
                if "username" in link and credential["username"] != link["username"]:
                    fail("password_sync_identity_mismatch")
                record.update(status="CONNECTED", checked=time.time())
                record.pop("reason", None)
            except AccessError as error:
                # Preserve rotated refresh-token state even if a later read
                # fails. Item/identity drift does not revoke other exact links.
                if error.reason not in {"password_source_item_changed", "password_sync_identity_mismatch"}:
                    record.update(status="RETRYABLE" if error.status == "RETRYABLE" else "BLOCKED",
                                  reason=error.reason)
                raise
            finally:
                invalid_profile = False
                try:
                    record["profile"] = _profile(directory)
                except AccessError:
                    record.update(status="BLOCKED", reason="password_source_item_changed")
                    invalid_profile = True
                _save(store, record)
                if invalid_profile:
                    fail("password_source_item_changed")
        return credential


def disconnect(store, ident, generation):
    if not _identifier(ident) or not _identifier(generation):
        fail("bitwarden_connection_invalid")
    with store.lock(PREFIX + ident, timeout=2):
        record = store.get(PREFIX + ident)
        if not isinstance(record, dict) or record.get("status") == "DISCONNECTED":
            fail("bitwarden_connection_not_found")
        if record.get("generation") != generation:
            fail("bitwarden_connection_changed")
        # Never acquire account locks after the source lock. One database
        # transaction invalidates only accounts still bound to this generation,
        # so concurrent manual edits/new imports cannot be erased accidentally.
        tombstone = {key: record[key] for key in ["id", "generation", "provider", "region", "email", "checked"]}
        tombstone.update(status="DISCONNECTED", reason="password_source_access_removed")
        with _database(store) as db:
            # Begin the write transaction before reading per-account links.
            # A concurrent manual save cannot commit between the read and clear.
            store.put(PREFIX + ident, tombstone, db=db)
            rows = db.execute("SELECT id,value FROM records WHERE id LIKE 'password-link:%'").fetchall()
            for row in rows:
                link = store.unseal(row[0], row[1])
                if (isinstance(link, dict) and link.get("provider") == PROVIDER
                        and link.get("connection") == ident
                        and link.get("connection_generation") == generation):
                    account = row[0].split(":", 1)[1]
                    link.update(status="BLOCKED", reason="password_source_access_removed", next_at=0)
                    store.put(row[0], link, db=db)
                    store.put("credential:" + account, None, db=db)
                    store.put("connection:" + account, None, db=db)
            _audit(db, "bitwarden_source_disconnected")
    return {"status": "DISCONNECTED", "id": ident}
