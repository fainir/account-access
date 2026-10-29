"""Password-protected local backup and crash-safe restore of one vault."""

import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import time
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import AccessError
from .models import Configuration
from .storage import check_private, private_file


MAGIC = b"AABK\x01"
SALT_BYTES = 16
NONCE_BYTES = 12
MAX_BACKUP_BYTES = 128 * 1024 * 1024
MAX_CONFIG_BYTES = 4 * 1024 * 1024
SCHEMA_VERSION = 1
RESTORE_JOURNAL = ".account-access-restore.json"
RESTORE_ID = re.compile(r"^[a-f0-9]{24}$")
TABLES = {"records", "grants", "clients", "challenges", "audit", "jobs", "schedules"}


def _backup_key(passphrase, salt):
    if (type(passphrase) is not str or len(passphrase) < 12 or len(passphrase.encode("utf-8")) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in passphrase)):
        raise AccessError("DENIED", "backup_passphrase_invalid")
    try:
        return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2**15, r=8, p=1,
                              maxmem=128 * 1024 * 1024, dklen=32)
    except (ValueError, MemoryError):
        raise AccessError("RETRYABLE", "backup_key_derivation_failed") from None


def _fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _database_snapshot(store):
    with tempfile.TemporaryDirectory(prefix=".account-access-backup-", dir=store.root) as folder:
        snapshot = Path(folder) / "state.db"
        target = sqlite3.connect(snapshot)
        try:
            with store.db() as source:
                size = (source.execute("PRAGMA page_count").fetchone()[0]
                        * source.execute("PRAGMA page_size").fetchone()[0])
                if size > MAX_BACKUP_BYTES:
                    raise AccessError("DENIED", "backup_too_large")
                source.backup(target)
            target.commit()
        finally:
            target.close()
        os.chmod(snapshot, 0o600)
        data = snapshot.read_bytes()
    if len(data) > MAX_BACKUP_BYTES:
        raise AccessError("DENIED", "backup_too_large")
    return data


def _pack(store, passphrase):
    salt = os.urandom(SALT_BYTES)
    encryption_key = _backup_key(passphrase, salt)
    check_private(store.root / "config.json")
    config = (store.root / "config.json").read_bytes()
    if len(config) > MAX_CONFIG_BYTES:
        raise AccessError("DENIED", "backup_too_large")
    database = _database_snapshot(store)
    files = {"config.json": config, "state.db": database, "vault.key": store._key}
    manifest = {"schema": SCHEMA_VERSION, "created_at": int(time.time()),
                "sha256": {name: hashlib.sha256(value).hexdigest() for name, value in files.items()}}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as package:
        package.writestr("manifest.json", json.dumps(manifest, sort_keys=True, separators=(",", ":")))
        for name, value in files.items():
            package.writestr(name, value)
    plaintext = archive.getvalue()
    if len(plaintext) > MAX_BACKUP_BYTES:
        raise AccessError("DENIED", "backup_too_large")
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext, MAGIC)
    return MAGIC + salt + nonce + ciphertext


def create_backup(store, destination, passphrase):
    """Create a new encrypted backup without replacing an existing file."""
    target = Path(destination).expanduser()
    parent = target.parent.resolve(strict=True)
    target = parent / target.name
    if target.name in {"", ".", ".."} or target.exists() or target.is_symlink():
        raise AccessError("DENIED", "backup_destination_exists")
    if not parent.is_dir():
        raise AccessError("DENIED", "backup_destination_invalid")
    with store.lock("service", timeout=0):
        data = _pack(store, passphrase)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".account-access-backup-", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR, follow_symlinks=False)
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            raise AccessError("DENIED", "backup_destination_exists") from None
        _fsync_directory(parent)
    except AccessError:
        raise
    except OSError:
        raise AccessError("RETRYABLE", "backup_write_failed") from None
    finally:
        temporary.unlink(missing_ok=True)
    return {"status": "BACKED_UP", "file": str(target), "bytes": len(data)}


def _read_backup(source, passphrase):
    path = Path(source).expanduser()
    if path.is_symlink():
        raise AccessError("DENIED", "invalid_backup_file")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BACKUP_BYTES + 128:
                raise AccessError("DENIED", "invalid_backup_file")
            data = stream.read(MAX_BACKUP_BYTES + 129)
    except AccessError:
        raise
    except OSError:
        raise AccessError("DENIED", "invalid_backup_file") from None
    if len(data) < len(MAGIC) + SALT_BYTES + NONCE_BYTES + 16 or data[:len(MAGIC)] != MAGIC:
        raise AccessError("DENIED", "invalid_backup_file")
    start = len(MAGIC)
    salt = data[start:start + SALT_BYTES]
    nonce_start = start + SALT_BYTES
    nonce = data[nonce_start:nonce_start + NONCE_BYTES]
    try:
        plaintext = AESGCM(_backup_key(passphrase, salt)).decrypt(
            nonce, data[nonce_start + NONCE_BYTES:], MAGIC)
    except (InvalidTag, ValueError):
        raise AccessError("DENIED", "backup_password_or_file_invalid") from None
    try:
        with zipfile.ZipFile(io.BytesIO(plaintext), "r") as package:
            names = package.namelist()
            if len(names) != 4 or set(names) != {"manifest.json", "config.json", "state.db", "vault.key"}:
                raise ValueError()
            if (package.getinfo("manifest.json").file_size > 65536
                    or sum(package.getinfo(name).file_size for name in names) > MAX_BACKUP_BYTES
                    or any(package.getinfo(name).file_size > MAX_BACKUP_BYTES for name in names)):
                raise ValueError()
            manifest = json.loads(package.read("manifest.json"))
            files = {name: package.read(name) for name in ("config.json", "state.db", "vault.key")}
        if (type(manifest) is not dict or set(manifest) != {"schema", "created_at", "sha256"}
                or type(manifest["schema"]) is not int or manifest["schema"] != SCHEMA_VERSION
                or type(manifest["created_at"]) is not int or manifest["created_at"] < 0
                or type(manifest["sha256"]) is not dict or set(manifest["sha256"]) != set(files)):
            raise ValueError()
        for name, value in files.items():
            if (len(value) > (MAX_CONFIG_BYTES if name == "config.json" else 32 if name == "vault.key" else MAX_BACKUP_BYTES)
                    or not hmac.compare_digest(manifest["sha256"][name], hashlib.sha256(value).hexdigest())):
                raise ValueError()
        if len(files["vault.key"]) != 32:
            raise ValueError()
        if manifest["created_at"] > int(time.time()) + 300:
            raise ValueError()
        Configuration.model_validate_json(files["config.json"])
    except AccessError:
        raise
    except Exception:
        raise AccessError("DENIED", "invalid_backup_file") from None
    return files["state.db"], files["config.json"], files["vault.key"]


def _validate_database(store, database, key):
    cipher = AESGCM(key)
    with tempfile.TemporaryDirectory(prefix=".account-access-restore-check-", dir=store.root) as folder:
        path = Path(folder) / "state.db"
        path.write_bytes(database)
        os.chmod(path, 0o600)
        try:
            with sqlite3.connect(path) as db:
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError()
                names = {row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                if not TABLES <= names:
                    raise ValueError()
                if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                    raise ValueError()
                if db.execute("PRAGMA foreign_key_check").fetchall():
                    raise ValueError()
                for record_id, blob in db.execute("SELECT id,value FROM records"):
                    if type(record_id) is not str or not isinstance(blob, bytes) or len(blob) < 28:
                        raise ValueError()
                    value = cipher.decrypt(blob[:12], blob[12:], record_id.encode())
                    json.loads(value)
        except Exception:
            raise AccessError("DENIED", "backup_vault_key_or_data_invalid") from None


def _restore_paths(root, ident):
    prefix = ".account-access-restore-" + ident
    return {
        "old_db": root / (prefix + ".old-db"),
        "old_config": root / (prefix + ".old-config"),
        "new_db": root / (prefix + ".new-db"),
        "new_config": root / (prefix + ".new-config"),
    }


def _read_journal(root):
    path = root / RESTORE_JOURNAL
    if not path.exists() and not path.is_symlink():
        return None
    check_private(path)
    try:
        journal = json.loads(path.read_bytes())
        if (type(journal) is not dict or set(journal) != {"schema", "id", "phase", "had_db", "had_config",
                                                          "key_changed", "new_key_sha256"}
                or type(journal["schema"]) is not int or journal["schema"] != 1
                or type(journal["id"]) is not str or RESTORE_ID.fullmatch(journal["id"]) is None
                or journal["phase"] not in {"prepared", "applied", "rolled_back"}
                or type(journal["had_db"]) is not bool or type(journal["had_config"]) is not bool
                or type(journal["key_changed"]) is not bool
                or type(journal["new_key_sha256"]) is not str
                or re.fullmatch(r"[a-f0-9]{64}", journal["new_key_sha256"]) is None):
            raise ValueError()
        return journal
    except Exception:
        raise AccessError("NEEDS_USER", "vault_restore_recovery_required") from None


def _cleanup_restore(root, journal):
    paths = _restore_paths(root, journal["id"])
    for path in paths.values():
        path.unlink(missing_ok=True)
    (root / RESTORE_JOURNAL).unlink(missing_ok=True)
    _fsync_directory(root)


def recover_pending_restore(root, *, key):
    """Roll back an interrupted publication or finish its committed cleanup."""
    root = Path(root)
    journal = _read_journal(root)
    if journal is None:
        return
    paths = _restore_paths(root, journal["id"])
    key_was_published = (journal["key_changed"] and isinstance(key, bytes)
                         and hmac.compare_digest(hashlib.sha256(key).hexdigest(),
                                                 journal["new_key_sha256"]))
    if journal["phase"] == "applied" and journal["key_changed"] and not key_was_published:
        raise AccessError("NEEDS_USER", "vault_restore_recovery_required")
    if journal["phase"] == "prepared" and not key_was_published:
        targets = {"old_db": root / "state.db", "old_config": root / "config.json"}
        for old_key, destination, had_original in (
                ("old_db", targets["old_db"], journal["had_db"]),
                ("old_config", targets["old_config"], journal["had_config"])):
            old = paths[old_key]
            if had_original:
                if not old.is_file() or old.is_symlink():
                    raise AccessError("NEEDS_USER", "vault_restore_recovery_required")
                _restore_private_copy(old, destination, root)
            else:
                destination.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm"):
            (root / ("state.db" + suffix)).unlink(missing_ok=True)
        _fsync_directory(root)
        journal["phase"] = "rolled_back"
        private_file(root / RESTORE_JOURNAL, json.dumps(journal, sort_keys=True).encode(), replace=True)
        _fsync_directory(root)
    elif journal["phase"] == "prepared" and key_was_published:
        journal["phase"] = "applied"
        private_file(root / RESTORE_JOURNAL, json.dumps(journal, sort_keys=True).encode(), replace=True)
        _fsync_directory(root)
    else:
        if journal["phase"] != "rolled_back" and (
                not (root / "state.db").is_file() or not (root / "config.json").is_file()):
            raise AccessError("NEEDS_USER", "vault_restore_recovery_required")
    _cleanup_restore(root, journal)


def _copy_private(source, destination):
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as writer:
        with source.open("rb") as reader:
            shutil.copyfileobj(reader, writer, 1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())


def _restore_private_copy(source, destination, root):
    descriptor, name = tempfile.mkstemp(prefix=".account-access-recovery-", dir=root)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as writer:
            with source.open("rb") as reader:
                shutil.copyfileobj(reader, writer, 1024 * 1024)
                writer.flush()
                os.fsync(writer.fileno())
        os.chmod(temporary, 0o600, follow_symlinks=False)
        os.replace(temporary, destination)
        _fsync_directory(root)
    finally:
        temporary.unlink(missing_ok=True)


def _publish_restore(store, database, config, key):
    root = store.root
    ident = os.urandom(12).hex()
    paths = _restore_paths(root, ident)
    state_path = root / "state.db"
    config_path = root / "config.json"
    journal_path = root / RESTORE_JOURNAL
    journal_written = False
    key_changed = not hmac.compare_digest(store._key, key)
    journal = {"schema": 1, "id": ident, "phase": "prepared",
               "had_db": state_path.exists(), "had_config": config_path.exists(),
               "key_changed": key_changed, "new_key_sha256": hashlib.sha256(key).hexdigest()}
    try:
        private_file(paths["new_db"], database)
        private_file(paths["new_config"], config)
        if journal["had_db"]:
            check_private(state_path)
            _copy_private(state_path, paths["old_db"])
        if journal["had_config"]:
            check_private(config_path)
            _copy_private(config_path, paths["old_config"])
        _fsync_directory(root)
        private_file(journal_path, json.dumps(journal, sort_keys=True).encode(), replace=journal_path.exists())
        journal_written = True
        _fsync_directory(root)
        os.replace(paths["new_db"], state_path)
        os.replace(paths["new_config"], config_path)
        for suffix in ("-wal", "-shm"):
            (root / ("state.db" + suffix)).unlink(missing_ok=True)
        _fsync_directory(root)
        if key_changed:
            store.replace_key(key)
        journal["phase"] = "applied"
        private_file(journal_path, json.dumps(journal, sort_keys=True).encode(), replace=True)
        try:
            _cleanup_restore(root, journal)
        except OSError:
            # Startup will finish private backup cleanup from the applied journal.
            pass
    except Exception as exc:
        uncertain_key_state = (isinstance(exc, AccessError)
                               and exc.reason == "vault_restore_recovery_required")
        if journal_written and not uncertain_key_state:
            try:
                recover_pending_restore(root, key=store._key)
            except AccessError:
                pass
        else:
            if not journal_written:
                for path in paths.values():
                    path.unlink(missing_ok=True)
        if isinstance(exc, AccessError):
            raise
        raise AccessError("RETRYABLE", "backup_restore_failed") from None


def restore_backup(store, source, passphrase):
    """Restore a portable encrypted backup, refusing to race service or recovery."""
    with store.lock("service", timeout=0):
        with store.lock("vault-restore", timeout=0):
            database, config, key = _read_backup(source, passphrase)
            _validate_database(store, database, key)
            _publish_restore(store, database, config, key)
    return {"status": "RESTORED", "root": str(store.root)}
