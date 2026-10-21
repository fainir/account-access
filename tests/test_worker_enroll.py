import secrets
from concurrent.futures import ThreadPoolExecutor
import uuid

import pytest

from account_access.errors import AccessError
from account_access.models import Configuration
from account_access.storage import Store
from account_access.worker_bootstrap import BootstrapError
from account_access.worker_enroll import RECORD, canonical_uuid, initialize, receipt_message, verify_store_key


def private_stage(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    return stage


def identities():
    return str(uuid.uuid4()), str(uuid.uuid4())


def test_private_empty_store_has_authentic_enrollment_and_no_accounts(tmp_path):
    stage = private_stage(tmp_path)
    key = secrets.token_bytes(32)
    vault, enrollment = identities()
    store = initialize(stage, key, vault, enrollment)
    assert store.config() == Configuration(accounts={}, test_mode=False)
    assert store.get(RECORD) == {"schema": 1, "vault_id": vault, "enrollment_id": enrollment}
    verify_store_key(Store(stage, key))
    for file in stage.rglob("*"):
        if file.is_file():
            assert key not in file.read_bytes()


def test_wrong_key_cannot_report_ready_or_replace_verification_record(tmp_path):
    stage = private_stage(tmp_path)
    key = secrets.token_bytes(32)
    store = initialize(stage, key, *identities())
    original = store.get(RECORD)
    with pytest.raises(AccessError, match="vault_corrupt_or_wrong_key"):
        verify_store_key(Store(stage, secrets.token_bytes(32)))
    assert Store(stage, key).get(RECORD) == original


def test_existing_encrypted_legacy_record_authenticates_without_new_writes(tmp_path):
    stage = private_stage(tmp_path)
    key = secrets.token_bytes(32)
    store = Store(stage, key)
    store.configure(Configuration(accounts={}))
    store.put("legacy-secret", {"password": "fictional-legacy-only"})
    verify_store_key(store)
    with store.db() as database:
        assert [row[0] for row in database.execute("SELECT id FROM records")] == ["legacy-secret"]
    with pytest.raises(AccessError, match="vault_corrupt_or_wrong_key"):
        verify_store_key(Store(stage, secrets.token_bytes(32)))


def test_empty_legacy_store_cannot_claim_key_validation(tmp_path):
    stage = private_stage(tmp_path)
    store = Store(stage, secrets.token_bytes(32))
    store.configure(Configuration(accounts={}))
    with pytest.raises(BootstrapError, match="worker_vault_key_verification_required"):
        verify_store_key(store)
    with store.db() as database:
        assert database.execute("SELECT count(*) FROM records").fetchone()[0] == 0


def test_nonempty_stage_and_second_initialization_preserve_existing_data(tmp_path):
    stage = private_stage(tmp_path)
    existing = stage / "keep"
    existing.write_bytes(b"fixture-existing-data")
    with pytest.raises(BootstrapError, match="worker_enrollment_state_not_empty"):
        initialize(stage, secrets.token_bytes(32), *identities())
    assert existing.read_bytes() == b"fixture-existing-data" and not (stage / "state.db").exists()
    existing.unlink()
    key = secrets.token_bytes(32)
    store = initialize(stage, key, *identities())
    before = store.get(RECORD)
    with pytest.raises(BootstrapError, match="worker_enrollment_state_not_empty"):
        initialize(stage, secrets.token_bytes(32), *identities())
    assert Store(stage, key).get(RECORD) == before


@pytest.mark.parametrize("value", [None, 1, True, "invalid", "A" * 36, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "00000000-0000-0000-0000-000000000000x"])
def test_noncanonical_identities_fail_before_creating_any_file(tmp_path, value):
    stage = private_stage(tmp_path)
    with pytest.raises(BootstrapError, match="invalid_worker_enrollment_identity"):
        initialize(stage, secrets.token_bytes(32), value, str(uuid.uuid4()))
    assert not list(stage.iterdir())


@pytest.mark.parametrize("alter", ["schema", "vault_id", "extra"])
def test_encrypted_but_malformed_enrollment_marker_is_not_ready(tmp_path, alter):
    stage = private_stage(tmp_path)
    store = initialize(stage, secrets.token_bytes(32), *identities())
    marker = store.get(RECORD)
    if alter == "schema":
        marker["schema"] = True
    elif alter == "vault_id":
        marker["vault_id"] = "invalid"
    else:
        marker["extra"] = "unexpected"
    store.put(RECORD, marker)
    with pytest.raises(BootstrapError, match="invalid_worker_enrollment_identity"):
        verify_store_key(store)


def test_receipt_binds_both_ids_and_the_exact_private_stage(tmp_path):
    vault, enrollment = identities()
    first = receipt_message(vault, enrollment, tmp_path)
    assert first != receipt_message(str(uuid.uuid4()), enrollment, tmp_path)
    assert first != receipt_message(vault, str(uuid.uuid4()), tmp_path)
    assert first != receipt_message(vault, enrollment, tmp_path / "other")
    assert canonical_uuid(vault) == vault


def test_competing_initializers_cannot_replace_each_others_stage(tmp_path):
    stage = private_stage(tmp_path)
    key = secrets.token_bytes(32)
    vault, enrollment = identities()
    def attempt():
        try:
            initialize(stage, key, vault, enrollment)
            return True
        except (BootstrapError, FileExistsError):
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(results) == [False, True]
    store = Store(stage, key)
    verify_store_key(store)
    assert store.get(RECORD)["enrollment_id"] == enrollment


@pytest.mark.parametrize("key", [b"x" * 16, b"x" * 24, b"x" * 33, "not-bytes"])
def test_invalid_master_key_cannot_create_stage_files(tmp_path, key):
    stage = private_stage(tmp_path)
    with pytest.raises(BootstrapError, match="invalid_worker_bootstrap"):
        initialize(stage, key, *identities())
    assert not list(stage.iterdir())
