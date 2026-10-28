from __future__ import annotations

import importlib.util
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_owner_upgrade110_diagnostic",
    ROOT / "scripts/build_owner_upgrade110_diagnostic.py",
)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
PROOF_INVENTORY = BUILDER.runpy.run_path(
    str(ROOT / "scripts/build_owner_upgrade104_review.py")
)["proof_inventory"]


def filesystem_inventory(root: Path) -> dict[str, dict[str, object]]:
    def node(path: Path) -> dict[str, object]:
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            return {"kind": "symlink", "target": os.readlink(path), "mode": mode, "acl": "empty"}
        if path.is_dir():
            return {"kind": "directory", "mode": mode, "acl": "empty"}
        raw = path.read_bytes()
        return {"kind": "file", "mode": mode, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(), "acl": "empty"}

    result = {"": node(root)}
    for path in sorted(root.rglob("*")):
        result[path.relative_to(root).as_posix()] = node(path)
    return result


def test_completed_runtime_sets_checkpoints_before_its_snapshot_reads() -> None:
    source = (ROOT / "macos/source-fragments/CompletedRuntimeUpgrade.swift.inc").read_text()
    reads = (
        ("checkpoint(.predecessorFinalTreeHistoryRead)", "let localHistory = try trees.map"),
        ("checkpoint(.predecessorFinalHeadRead)", "let head = try ComponentFiles.read(namespace.fd, \"head.json\""),
        ("checkpoint(.predecessorFinalRootsRead)", "let roots = try InstallationRootBinding.capture(withVolumeUUID: true)"),
    )
    positions = []
    for checkpoint, read in reads:
        checkpoint_at = source.index(checkpoint)
        read_at = source.index(read)
        assert checkpoint_at < read_at
        positions.append(checkpoint_at)
    assert positions == sorted(positions)


def predecessor_fixture(root: Path) -> tuple[Path, Path]:
    source = root / "package95" / "Scripts"
    completed = source / "Predecessor/CompletedImage"
    for path in (
        source,
        source / "TargetImage",
        source / "Predecessor",
        completed,
        completed / "Predecessor",
        completed / "TargetImage",
    ):
        path.mkdir(parents=True, exist_ok=True, mode=0o755)
        path.chmod(0o755)
    source.chmod(0o700)
    files = (
        "TargetImage/unchanged-payload",
        "Predecessor/CompletedImage/FullImagePlan.json",
        "Predecessor/CompletedImage/BaseManifest.json",
        "Predecessor/CompletedImage/TargetManifest.json",
        "Predecessor/CompletedImage/BaseIdentity.json",
        "Predecessor/CompletedImage/TargetIdentity.json",
        "Predecessor/CompletedImage/ProviderManifest.json",
        "Predecessor/CompletedImage/RuntimeCAReceipt.json",
        "Predecessor/CompletedImage/AccountAccess-fullimageupdate",
        "Predecessor/CompletedImage/postinstall",
        "Predecessor/CompletedImage/TargetImage/verified-file",
        "Predecessor/CompletedImage/Predecessor/ComponentPlan.json",
        "Predecessor/CompletedImage/Predecessor/BaseManifest.json",
        "Predecessor/CompletedImage/Predecessor/TargetManifest.json",
        "Predecessor/CompletedImage/Predecessor/BaseIdentity.json",
        "Predecessor/CompletedImage/Predecessor/AccountAccess-componentupdate",
        "Predecessor/CompletedImage/Predecessor/postinstall",
    )
    for relative in files:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        path.write_bytes((relative + "\n").encode())
        path.chmod(0o755 if relative.endswith(("postinstall", "fullimageupdate", "componentupdate")) else 0o644)

    target = root / "target" / "Scripts"
    target.mkdir(parents=True, mode=0o700)
    target_predecessor = target / "Predecessor"
    shutil.copytree(source, target_predecessor, symlinks=True)
    shutil.rmtree(target_predecessor / "TargetImage")
    (target_predecessor / "TargetImage").mkdir(mode=0o755)
    shutil.rmtree(target_predecessor / "Predecessor/CompletedImage")
    (target_predecessor / "Predecessor/CompletedImage").mkdir(mode=0o755)
    target_predecessor.chmod(0o755)
    return source, target


def test_rebind_wrapper_changes_only_the_pinned_helper_digest() -> None:
    old = "a" * 64
    new = "b" * 64
    wrapper = (
        b"#!/bin/sh\n"
        b'AC_COMPONENT_HELPER="$AC_COMPONENT_SCRIPTS/AccountAccess-ownerupgrade"\n'
        b"[ \"$(/usr/bin/shasum -a 256 \\\"$AC_COMPONENT_HELPER\\\")\" = '"
        + old.encode()
        + b"' ] || exit 1\n"
        b"exec \"$AC_COMPONENT_HELPER\"\n"
    )

    updated = BUILDER.rebind_wrapper(wrapper, old, new)

    assert old.encode() not in updated
    assert updated.count(new.encode()) == 1
    assert updated.startswith(b"#!/bin/sh\n")


def test_rebind_wrapper_refuses_a_mismatched_or_ambiguous_guard() -> None:
    old = "a" * 64
    new = "b" * 64
    with pytest.raises(BUILDER.BuildRefused, match="base_wrapper_binding_invalid"):
        BUILDER.rebind_wrapper(b"#!/bin/sh\n", old, new)
    ambiguous = b" = '" + old.encode() + b"' ] || exit 1\n" * 2
    with pytest.raises(BUILDER.BuildRefused, match="base_wrapper_binding_invalid"):
        BUILDER.rebind_wrapper(ambiguous, old, new)


def test_package_info_update_requires_the_expected_base_identity_and_timeout() -> None:
    valid = (
        b'<pkg-info identifier="com.fainir.accountaccess.ownerupgrade110" install-location="/">'
        b'<postinstall file="./postinstall" timeout="600"/>'
    )

    updated = BUILDER.update_package_info(valid)
    assert b'timeout="1800"' in updated
    assert b'identifier="com.fainir.accountaccess.ownerupgrade110"' in updated
    assert b'ownerupgrade109' not in updated
    with pytest.raises(BUILDER.BuildRefused, match="generated_package_info_mismatch"):
        BUILDER.update_package_info(valid.replace(b"ownerupgrade110", b"ownerupgrade108"))
    with pytest.raises(BUILDER.BuildRefused, match="generated_package_info_mismatch"):
        BUILDER.update_package_info(valid.replace(b'timeout="600"', b'timeout="300"'))


def test_candidate_is_bound_to_the_previously_refused_package() -> None:
    assert BUILDER.BASE_PACKAGE_SHA256 == "0528d4a545c14c92c58a8ebe03660e8d75efd7d38b67db92ccc913a5249ce2a0"
    assert BUILDER.PACKAGE95_SHA256 == "0c7a83b47d405bd9b02686aceb938877c5cd2f36112cb0b8369069c643453371"
    assert BUILDER.INVENTORY95_SHA256 == "9072d9bce2fd9c1b6118e657c77cab3f32e5c44689f4bb230132f07bbbb0e1e1"
    assert BUILDER.PACKAGE_ID == "com.fainir.accountaccess.ownerupgrade110"


def test_predecessor_verifier_payload_is_restored_and_fully_projected(tmp_path: Path) -> None:
    source, target = predecessor_fixture(tmp_path)
    source_rows = filesystem_inventory(source)
    expected = PROOF_INVENTORY(source_rows)

    actual = BUILDER.restore_completed_image_payload(
        source, target, source_rows, filesystem_inventory, PROOF_INVENTORY
    )

    assert actual == expected
    assert (target / "Predecessor/Predecessor/CompletedImage/Predecessor/ComponentPlan.json").read_bytes() == b"Predecessor/CompletedImage/Predecessor/ComponentPlan.json\n"
    assert (target / "Predecessor/Predecessor/CompletedImage/TargetImage/verified-file").is_file()
    assert not (target / "Predecessor/TargetImage/unchanged-payload").exists()


def test_predecessor_builder_refuses_missing_component_plan(tmp_path: Path) -> None:
    source, target = predecessor_fixture(tmp_path)
    source_rows = filesystem_inventory(source)
    del source_rows["Predecessor/CompletedImage/Predecessor/ComponentPlan.json"]

    with pytest.raises(BUILDER.BuildRefused, match="package95_predecessor_revalidation_invalid"):
        BUILDER.restore_completed_image_payload(
            source, target, source_rows, lambda _: source_rows, PROOF_INVENTORY
        )


def test_predecessor_builder_refuses_nonempty_placeholder(tmp_path: Path) -> None:
    source, target = predecessor_fixture(tmp_path)
    destination = target / "Predecessor/Predecessor/CompletedImage"
    (destination / "stale").write_text("unexpected\n")
    source_rows = filesystem_inventory(source)

    with pytest.raises(BUILDER.BuildRefused, match="base_completed_image_not_empty"):
        BUILDER.restore_completed_image_payload(
            source, target, source_rows, filesystem_inventory, PROOF_INVENTORY
        )


def test_process_output_includes_gatekeeper_stderr() -> None:
    result = subprocess.CompletedProcess(["spctl"], 0, b"", b"accepted\nsource=Notarized Developer ID\n")

    assert BUILDER.process_output(result) == "accepted\nsource=Notarized Developer ID"


def test_flat_package_listing_requires_archived_scripts_component() -> None:
    BUILDER.validate_flat_package_listing(b"PackageInfo\nScripts\n")

    with pytest.raises(BUILDER.BuildRefused, match="package_scripts_archive_not_flat"):
        BUILDER.validate_flat_package_listing(b"PackageInfo\nScripts\nScripts/postinstall\n")
