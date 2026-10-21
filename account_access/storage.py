"""Authenticated encryption, private files, durable state, and process-wide locks."""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import time
import tempfile
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from filelock import FileLock, Timeout

from .errors import AccessError
from .models import Configuration


def private_file(path: Path, contents: bytes, *, replace: bool = False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise AccessError("DENIED", "symlink_path")
    # Never truncate an existing inode (it may be a hard link or have unsafe
    # permissions). A replacement is fully written privately before publication.
    if replace:
        fd, name = tempfile.mkstemp(prefix=".access-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(contents)
        f.flush()
        os.fsync(f.fileno())


def check_private(path: Path):
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise AccessError("DENIED", "insecure_file_permissions")
    if hasattr(os, "getuid") and path.stat().st_uid != os.getuid():
        raise AccessError("DENIED", "wrong_file_owner")


def load_key(root: Path, key_file: Path | None = None, *, create=False) -> bytes:
    if key_file:
        if create and not key_file.exists():
            private_file(key_file, secrets.token_bytes(32))
        check_private(key_file)
        key = key_file.read_bytes()
    else:
        import keyring

        backend = keyring.get_keyring()
        allowed = ("keyring.backends.macOS", "keyring.backends.Windows", "keyring.backends.SecretService")
        if not type(backend).__module__.startswith(allowed):
            raise AccessError("NEEDS_USER", "secure_keyring_unavailable", "vault")
        service = "account-access:" + hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:24]
        try:
            encoded = keyring.get_password(service, "master")
            if not encoded and create:
                encoded = base64.b64encode(secrets.token_bytes(32)).decode()
                keyring.set_password(service, "master", encoded)
            if not encoded:
                raise AccessError("NEEDS_USER", "vault_not_initialized", "vault")
            key = base64.b64decode(encoded, validate=True)
        except AccessError:
            raise
        except Exception:
            raise AccessError("NEEDS_USER", "vault_locked", "vault") from None
    if len(key) != 32:
        raise AccessError("NEEDS_USER", "invalid_vault_key", "vault")
    return key


class Store:
    def __init__(self, root: Path, key: bytes):
        self.root = root.resolve()
        if root.is_symlink():
            raise AccessError("DENIED", "symlink_path")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        check_private(self.root)
        self.aes = AESGCM(key)
        self.path = self.root / "state.db"
        if self.path.exists():
            check_private(self.path)
        else:
            private_file(self.path, b"")
        (self.root / "locks").mkdir(mode=0o700, exist_ok=True)
        check_private(self.root / "locks")
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, value BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS grants (
                    principal TEXT, account TEXT, operation TEXT, fingerprint TEXT, expires REAL,
                    PRIMARY KEY(principal, account, operation));
                CREATE TABLE IF NOT EXISTS clients (
                    digest TEXT PRIMARY KEY, principal TEXT NOT NULL, revoked INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS challenges (
                    id TEXT PRIMARY KEY, account TEXT, kind TEXT, reason TEXT,
                    created REAL, resolved REAL, notified REAL);
                CREATE UNIQUE INDEX IF NOT EXISTS pending_challenge
                    ON challenges(account, kind) WHERE resolved IS NULL;
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, principal TEXT,
                    account TEXT, operation TEXT, event TEXT, reason TEXT);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, principal TEXT, request_key TEXT, status TEXT,
                    next_at REAL DEFAULT 0, UNIQUE(principal, request_key));
                CREATE TABLE IF NOT EXISTS schedules (
                    id TEXT PRIMARY KEY, principal TEXT, interval REAL, next_at REAL, enabled INTEGER);
            """)

    @contextmanager
    def db(self):
        for path in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            if path.is_symlink():
                raise AccessError("DENIED", "symlink_path")
        check_private(self.path)
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()
            for path in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
                try:
                    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR, follow_symlinks=False)
                except FileNotFoundError:
                    # SQLite removes WAL/SHM when the last other connection closes.
                    pass

    @contextmanager
    def lock(self, key: str, timeout=10):
        check_private(self.root / "locks")
        path = self.root / "locks" / (hashlib.sha256(key.encode()).hexdigest() + ".lock")
        if path.is_symlink():
            raise AccessError("DENIED", "symlink_path")
        try:
            with FileLock(path, timeout=timeout, mode=0o600):
                yield
        except Timeout:
            raise AccessError("RETRYABLE", "account_busy") from None

    def seal(self, key, value):
        nonce = secrets.token_bytes(12)
        return nonce + self.aes.encrypt(nonce, json.dumps(value).encode(), key.encode())

    def unseal(self, key, blob):
        try:
            return json.loads(self.aes.decrypt(blob[:12], blob[12:], key.encode()))
        except Exception:
            raise AccessError("NEEDS_USER", "vault_corrupt_or_wrong_key", "vault") from None

    def get(self, key, default=None):
        with self.db() as db:
            row = db.execute("SELECT value FROM records WHERE id=?", (key,)).fetchone()
        return self.unseal(key, row[0]) if row else default

    def put(self, key, value, db=None):
        blob = self.seal(key, value)
        if db:
            db.execute("INSERT OR REPLACE INTO records VALUES (?,?)", (key, blob))
        else:
            with self.db() as connection:
                connection.execute("INSERT OR REPLACE INTO records VALUES (?,?)", (key, blob))

    def config(self):
        path = self.root / "config.json"
        check_private(path)
        try:
            return Configuration.model_validate_json(path.read_bytes())
        except Exception:
            raise AccessError("DENIED", "invalid_owner_configuration") from None

    def configure(self, config: Configuration):
        with self.lock("configuration"):
            temp = self.root / ("config-" + secrets.token_hex(8) + ".tmp")
            private_file(temp, config.model_dump_json(indent=2).encode())
            temp.replace(self.root / "config.json")

    def audit(self, principal, account, operation, event, reason=""):
        # No free-form website strings, credential payloads, HTTP bodies, or business data.
        with self.db() as db:
            db.execute("INSERT INTO audit(at,principal,account,operation,event,reason) VALUES (?,?,?,?,?,?)",
                       (time.time(), principal, account, operation, event, reason))

    def challenge(self, account, kind, reason):
        with self.db() as db:
            if kind == "captcha" and reason == "browser_captcha_required":
                present = db.execute("SELECT 1 FROM challenges WHERE account=? AND kind='captcha' AND resolved IS NULL", (account,)).fetchone()
                if not present:
                    # Refine the same unknown login gate after an updated
                    # connector identifies it. Preserve its ID and pending
                    # status; this never approves or resumes authentication.
                    db.execute("UPDATE challenges SET kind='captcha',reason=? WHERE account=? AND kind='unknown' AND reason='browser_state_unrecognized' AND resolved IS NULL", (reason, account))
            db.execute("INSERT OR IGNORE INTO challenges VALUES (?,?,?,?,?,NULL,NULL)",
                       (secrets.token_hex(16), account, kind, reason, time.time()))
            row = db.execute("SELECT * FROM challenges WHERE account=? AND kind=? AND resolved IS NULL",
                             (account, kind)).fetchone()
        return dict(row)

    def pending(self, account):
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM challenges WHERE account=? AND resolved IS NULL",
                                               (account,))]

    def resolve_login(self, account, db=None):
        if db is None:
            with self.db() as connection:
                self.resolve_login(account, db=connection)
        else:
            db.execute("UPDATE challenges SET resolved=? WHERE account=? AND resolved IS NULL AND kind IN ('login','sms','email','totp','method','device','passkey','captcha','admin','recovery','unknown')",
                       (time.time(), account))

    def client(self, token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.db() as db:
            row = db.execute("SELECT principal FROM clients WHERE digest=? AND revoked=0", (digest,)).fetchone()
        if not row:
            raise AccessError("DENIED", "invalid_client")
        return row[0]

    def new_client(self, principal):
        token = secrets.token_urlsafe(32)
        with self.db() as db:
            db.execute("INSERT INTO clients VALUES (?,?,0)",
                       (hashlib.sha256(token.encode()).hexdigest(), principal))
        return token

    def principal_active(self, principal):
        with self.db() as db:
            return bool(db.execute("SELECT 1 FROM clients WHERE principal=? AND revoked=0", (principal,)).fetchone())
