import json
import os

import pytest

from scripts.mac_package_smoke import verify_install_receipt


@pytest.fixture
def receipt(tmp_path):
    base = tmp_path / "installed-public-fixture"
    base.mkdir(mode=0o755)
    path = base / "install-verification.json"
    metadata = {"payload_manifest_sha256": "a" * 64,
                "payload_manifest_counts": {"files": 3, "directories": 5, "aliases": 2}}
    value = {"schema": 1, "status": "VERIFIED", "manifest_sha256": "a" * 64,
             **metadata["payload_manifest_counts"]}
    path.write_text(json.dumps(value))
    path.chmod(0o644)
    return base, path, metadata, value


def test_native_receipt_binds_the_exact_image_and_all_public_object_counts_without_writes(receipt):
    base, path, metadata, _ = receipt
    before = path.read_bytes()
    assert verify_install_receipt(base, metadata, owner_uid=os.getuid()) is True
    assert path.read_bytes() == before and list(base.iterdir()) == [path]


@pytest.mark.parametrize("damage", ["hash", "count", "schema-bool", "count-bool", "extra-field", "inspection-only", "array", "empty",
                                  "large", "mode", "hardlink", "symlink", "fifo", "parent-mode", "parent-alias"])
def test_unbound_unsafe_or_replaced_native_receipts_cannot_count_as_installer_acceptance(receipt, tmp_path, damage):
    base, path, metadata, value = receipt
    if damage == "hash":
        value["manifest_sha256"] = "b" * 64
    elif damage == "count":
        value["files"] += 1
    elif damage == "schema-bool":
        value["schema"] = True
    elif damage == "count-bool":
        value["files"] = True
    elif damage == "extra-field":
        value["unrecognized"] = True
    elif damage == "inspection-only":
        value["status"] = "INSPECTED"
    elif damage == "array":
        value = []
    path.write_text(json.dumps(value))
    if damage in {"empty", "large"}:
        path.write_bytes(b"" if damage == "empty" else b"x" * 4097)
    elif damage == "mode":
        path.chmod(0o600)
    elif damage == "parent-mode":
        base.chmod(0o775)
    elif damage == "hardlink":
        os.link(path, tmp_path / "other-link")
    elif damage == "symlink":
        target = tmp_path / "other-receipt"
        path.rename(target)
        path.symlink_to(target)
    elif damage == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif damage == "parent-alias":
        target = tmp_path / "other-directory"
        base.rename(target)
        base.symlink_to(target, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        verify_install_receipt(base, metadata, owner_uid=os.getuid())


@pytest.mark.parametrize("reason", ["installer_payload_changed", "synthetic-private-value", ["unexpected"], None])
def test_failed_native_verification_is_never_accepted_and_only_fixed_reasons_are_reported(receipt, reason):
    base, path, metadata, _ = receipt
    path.write_text(json.dumps({"schema": 1, "status": "FAILED", "reason": reason}))
    expected = "installer_payload_changed" if reason == "installer_payload_changed" else "unrecognized_reason"
    with pytest.raises(ValueError, match="native_installer_payload_not_verified:" + expected) as error:
        verify_install_receipt(base, metadata, owner_uid=os.getuid())
    assert "synthetic-private-value" not in str(error.value)


@pytest.mark.parametrize("owner", [True, -1, "0"])
def test_receipt_fixture_owner_selection_cannot_accept_ambiguous_ids(receipt, owner):
    with pytest.raises(ValueError, match="invalid_native_installer_receipt_owner"):
        verify_install_receipt(receipt[0], receipt[2], owner_uid=owner)


def test_read_only_receipt_owner_selection_cannot_hide_wrong_ownership(receipt):
    with pytest.raises(ValueError, match="unsafe_native_installer_receipt_parent"):
        verify_install_receipt(receipt[0], receipt[2], owner_uid=os.getuid() + 1)
