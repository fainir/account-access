import hashlib
import json
import os

import pytest

from account_access.demo import DEMO_PASSWORD
from account_access.errors import AccessError
from account_access.storage import Store, private_file
from account_access.vault_backup import _restore_private_copy, create_backup, restore_backup


PASSPHRASE = "correct horse battery staple"


def test_encrypted_backup_round_trip_restores_config_and_vault(env, tmp_path):
    _, broker, token = env
    store = broker.store
    store.put("credential:demo-web", {"username": "demo@example.test", "password": DEMO_PASSWORD})
    original_config = store.config()
    original_label = original_config.accounts["demo-web"].label
    backup = tmp_path / "account-access.aabackup"
    master_key = (store.root / "demo.key").read_bytes()

    result = create_backup(store, backup, PASSPHRASE)
    assert result["status"] == "BACKED_UP"
    assert backup.stat().st_mode & 0o077 == 0
    assert DEMO_PASSWORD.encode() not in backup.read_bytes()
    assert master_key not in backup.read_bytes()

    store.put("credential:demo-web", {"username": "changed", "password": "changed"})
    changed_config = store.config()
    changed_config.accounts["demo-web"].label = "Changed after backup"
    store.configure(changed_config)
    restore_backup(store, backup, PASSPHRASE)

    assert store.get("credential:demo-web") == {
        "username": "demo@example.test", "password": DEMO_PASSWORD}
    assert store.config().accounts["demo-web"].label == original_label
    assert store.client(token) == "test"


def test_backup_restores_to_a_different_local_keyring(env, tmp_path):
    _, broker, _ = env
    broker.store.put("credential:demo-web", {"username": "portable", "password": "secret"})
    source_token = broker.store.new_client("restore-check")
    source = tmp_path / "portable.aabackup"
    create_backup(broker.store, source, PASSPHRASE)
    target_root = tmp_path / "new-vault"
    target_key_file = tmp_path / "new-vault.key"
    private_file(target_key_file, os.urandom(32))
    target = Store(target_root, target_key_file.read_bytes(), key_file=target_key_file)

    result = restore_backup(target, source, PASSPHRASE)

    assert result["status"] == "RESTORED"
    assert target.config().accounts.keys() == broker.store.config().accounts.keys()
    restored = Store(target_root, target_key_file.read_bytes(), key_file=target_key_file)
    assert restored.get("credential:demo-web") == {"username": "portable", "password": "secret"}
    assert restored.client(source_token) == "restore-check"


def test_failed_backup_password_never_changes_current_vault(env, tmp_path):
    _, broker, _ = env
    backup = tmp_path / "account-access.aabackup"
    create_backup(broker.store, backup, PASSPHRASE)
    before_db = hashlib.sha256(broker.store.path.read_bytes()).hexdigest()
    before_config = (broker.store.root / "config.json").read_bytes()

    with pytest.raises(AccessError, match="backup_password_or_file_invalid"):
        restore_backup(broker.store, backup, "incorrect passphrase value")

    assert hashlib.sha256(broker.store.path.read_bytes()).hexdigest() == before_db
    assert (broker.store.root / "config.json").read_bytes() == before_config


def test_tampered_backup_is_rejected_without_changing_current_vault(env, tmp_path):
    _, broker, _ = env
    original = tmp_path / "original.aabackup"
    tampered = tmp_path / "tampered.aabackup"
    create_backup(broker.store, original, PASSPHRASE)
    changed = bytearray(original.read_bytes())
    changed[-1] ^= 1
    tampered.write_bytes(changed)
    os.chmod(tampered, 0o600)
    before_db = hashlib.sha256(broker.store.path.read_bytes()).hexdigest()
    before_config = (broker.store.root / "config.json").read_bytes()

    with pytest.raises(AccessError, match="backup_password_or_file_invalid"):
        restore_backup(broker.store, tampered, PASSPHRASE)

    assert hashlib.sha256(broker.store.path.read_bytes()).hexdigest() == before_db
    assert (broker.store.root / "config.json").read_bytes() == before_config


def test_existing_backup_destination_is_never_overwritten(env, tmp_path):
    _, broker, _ = env
    destination = tmp_path / "existing.backup"
    destination.write_bytes(b"owner data")
    with pytest.raises(AccessError, match="backup_destination_exists"):
        create_backup(broker.store, destination, PASSPHRASE)
    assert destination.read_bytes() == b"owner data"


def test_backup_refuses_to_race_a_running_service(env, tmp_path):
    _, broker, _ = env
    with broker.store.lock("service"):
        with pytest.raises(AccessError, match="account_busy"):
            create_backup(broker.store, tmp_path / "active.backup", PASSPHRASE)


def test_restore_refuses_to_race_a_running_service(env, tmp_path):
    _, broker, _ = env
    backup = tmp_path / "active-restore.backup"
    create_backup(broker.store, backup, PASSPHRASE)
    before_db = hashlib.sha256(broker.store.path.read_bytes()).hexdigest()
    with broker.store.lock("service"):
        with pytest.raises(AccessError, match="account_busy"):
            restore_backup(broker.store, backup, PASSPHRASE)
    assert hashlib.sha256(broker.store.path.read_bytes()).hexdigest() == before_db


def test_interrupted_restore_rolls_back_before_store_opens(env):
    _, broker, _ = env
    store = broker.store
    store.put("credential:demo-web", {"username": "before", "password": "preserved"})
    original_db = store.path.read_bytes()
    config_path = store.root / "config.json"
    original_config = config_path.read_bytes()
    ident = "0123456789abcdef01234567"
    private_file(store.root / f".account-access-restore-{ident}.old-db", original_db)
    private_file(store.root / f".account-access-restore-{ident}.old-config", original_config)
    journal = {"schema": 1, "id": ident, "phase": "prepared",
               "had_db": True, "had_config": True, "key_changed": False,
               "new_key_sha256": hashlib.sha256((store.root / "demo.key").read_bytes()).hexdigest()}
    private_file(store.root / ".account-access-restore.json", json.dumps(journal).encode())
    store.path.write_bytes(b"partially published database")
    config_path.write_text("partial config")
    os.chmod(store.path, 0o600)
    os.chmod(config_path, 0o600)
    _restore_private_copy(store.root / f".account-access-restore-{ident}.old-db",
                          store.path, store.root)

    demo_key = (store.root / "demo.key").read_bytes()
    recovered = Store(store.root, demo_key)

    assert recovered.get("credential:demo-web") == {"username": "before", "password": "preserved"}
    assert config_path.read_bytes() == original_config
    assert not (store.root / ".account-access-restore.json").exists()


def test_backup_and_restore_cli_uses_hidden_passphrase_and_confirmation(env, tmp_path, monkeypatch, capsys):
    _, broker, _ = env
    store = broker.store
    key_file = store.root / "demo.key"
    backup = tmp_path / "cli.aabackup"
    store.put("credential:demo-web", {"username": "cli", "password": "cli-secret"})
    monkeypatch.setattr("account_access.cli.getpass.getpass", lambda _prompt: PASSPHRASE)
    monkeypatch.setattr("builtins.input", lambda _prompt: "RESTORE")
    prefix = ["--root", str(store.root), "--key-file", str(key_file), "--development"]

    from account_access.cli import main

    assert main(prefix + ["backup", "--file", str(backup)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "BACKED_UP"
    store.put("credential:demo-web", {"username": "changed", "password": "changed"})
    assert main(prefix + ["restore", "--file", str(backup)]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["status"] == "RESTORED"
    assert PASSPHRASE not in output
    assert store.get("credential:demo-web") == {"username": "cli", "password": "cli-secret"}


def test_schema_zero_migrates_additively_and_future_schema_refuses(tmp_path):
    root = tmp_path / "migration"
    key = os.urandom(32)
    store = Store(root, key)
    store.put("preserve", {"value": "kept"})
    with store.db() as db:
        db.execute("PRAGMA user_version=0")

    migrated = Store(root, key)
    assert migrated.get("preserve") == {"value": "kept"}
    with migrated.db() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        db.execute("PRAGMA user_version=99")
    with pytest.raises(AccessError, match="unsupported_vault_schema"):
        Store(root, key)
