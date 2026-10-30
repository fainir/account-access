from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from macos import direct_runtime_upgrade_plan as plan
from scripts import build_direct_runtime_upgrade_candidate as candidate


@pytest.mark.parametrize('field,value', [
    ('head_sha', 'b' * 40), ('status', 'in_progress'), ('conclusion', 'failure'),
    ('path', '.github/workflows/unrelated.yml'), ('repository', {'full_name': 'other/repo'}),
])
def test_compiled_helper_rejects_other_sources_or_workflows(field, value):
    metadata = {'head_sha': 'a' * 40, 'status': 'completed', 'conclusion': 'success',
                'path': '.github/workflows/mac-release-native-review.yml',
                'repository': {'full_name': 'fainir/account-access'}}
    candidate.validate_compile_run(metadata, 'a' * 40)
    metadata[field] = value
    with pytest.raises(ValueError, match='compiled_helper_run_not_qualified'):
        candidate.validate_compile_run(metadata, 'a' * 40)


def test_jose_patch_replaces_package_and_both_versioned_metadata_trees():
    package, old_info, new_info = plan.DIRECT_TREES[-3:]
    old = {'': {'kind': 'directory', 'mode': 0o755},
           package: {'kind': 'directory', 'mode': 0o755}, package + '/guard.py': file('a'),
           old_info: {'kind': 'directory', 'mode': 0o755}, old_info + '/RECORD': file('b')}
    new = {'': old[''], package: old[package], package + '/guard.py': file('c'),
           new_info: {'kind': 'directory', 'mode': 0o755}, new_info + '/RECORD': file('d')}
    changed, units = plan._units({'roots': {plan.SUPPORT: old}}, {'roots': {plan.SUPPORT: new}})
    assert [u['path'] for u in units] == [package, old_info, new_info]
    assert all(u['kind'] == 'public_tree' for u in units)
    assert units[1]['after'] is None and units[2]['before'] is None
    assert sorted(p for u in units for p in u['changed']) == changed


def test_ci_helper_refuses_unexpected_archive_paths(tmp_path, monkeypatch):
    import io
    import json
    import zipfile
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('../outside', b'not-a-reviewed-helper')
    raw = stream.getvalue()
    metadata = {'head_sha': 'a' * 40, 'status': 'completed', 'conclusion': 'success',
                'path': '.github/workflows/mac-release-native-review.yml',
                'repository': {'full_name': 'fainir/account-access'}}
    asset = {'id': 7, 'name': 'release-compiled-updater', 'expired': False,
             'size_in_bytes': len(raw), 'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}
    def checked(argv, **kwargs):
        if argv[-1].endswith('/zip'):
            return raw
        return json.dumps({'artifacts': [asset]} if argv[-1].endswith('/artifacts') else metadata).encode()
    monkeypatch.setattr(candidate, 'checked', checked)
    output = tmp_path / 'helper'
    with pytest.raises(ValueError, match='compiled_helper_archive_inventory_invalid'):
        candidate.reviewed_ci_helper(2, 'a' * 40, output)
    assert not output.exists()


def test_first_direct_update_recovers_root_binding_before_receipt_recheck():
    adapter = (Path(__file__).parents[1] / "macos/source-fragments/RuntimeUpgradeInstalledAdapter.swift.inc").read_text()
    recovery = adapter.index("private static func recoverDirectRootBindingIfRequired")
    run = adapter.index("static func runRuntimeUpgrade")
    resumed_receipt = adapter.index("if source.directRuntimeDelta && hasIntent { try originalReceipt")
    first_attempt = adapter.index("if source.directRuntimeDelta && !hasIntent {")
    recovery_call = adapter.index("try recoverDirectRootBindingIfRequired", first_attempt)
    post_recovery_receipt = adapter.index("try originalReceipt(original, ownerUID: ownerUID)", recovery_call)
    preparation = adapter.index("checkpoint(.preparation)", post_recovery_receipt)

    assert recovery < run < resumed_receipt < first_attempt < recovery_call < post_recovery_receipt < preparation
    assert "InstallationRootBinding.recoverySupplement" in adapter[recovery:run]
    assert "InstallationRootBinding.validateSupplement" in adapter[recovery:run]
    assert "try InstallationRootBinding.capture(withVolumeUUID: true) == current" in adapter[recovery:run]


def file(digest: str, size: int = 1, mode: int = 0o644):
    return {"kind": "file", "mode": mode, "size": size, "sha256": digest * 64}


def test_delta_uses_disjoint_fixed_trees_and_file_renames():
    old = {
        "": {"kind": "directory", "mode": 0o755},
        "runtime": {"kind": "directory", "mode": 0o755},
        "runtime/a.py": file("a", 10),
        "runtime/lib/python3.12/site-packages/authlib-1.8.0.dist-info": {"kind": "directory", "mode": 0o755},
        "runtime/lib/python3.12/site-packages/authlib-1.8.0.dist-info/METADATA": file("b", 20),
        "runtime/lib/python3.12/site-packages/authlib/oauth2": {"kind": "directory", "mode": 0o755},
        "runtime/lib/python3.12/site-packages/authlib/oauth2/client.py": file("c", 30),
    }
    new = {
        "": old[""],
        "runtime": old["runtime"],
        "runtime/a.py": file("d", 11),
        "runtime/lib/python3.12/site-packages/authlib-1.9.1.dist-info": {"kind": "directory", "mode": 0o755},
        "runtime/lib/python3.12/site-packages/authlib-1.9.1.dist-info/METADATA": file("e", 21),
        "runtime/lib/python3.12/site-packages/authlib/oauth2": old["runtime/lib/python3.12/site-packages/authlib/oauth2"],
        "runtime/lib/python3.12/site-packages/authlib/oauth2/client.py": file("f", 31),
        "runtime/lib/python3.12/site-packages/authlib/oauth2/drafts": {"kind": "directory", "mode": 0o755},
        "runtime/lib/python3.12/site-packages/authlib/oauth2/drafts/__init__.py": file("g", 41),
    }

    changed, units = plan._units({"roots": {plan.SUPPORT: old}}, {"roots": {plan.SUPPORT: new}})

    expected_changed = sorted(path for path in old.keys() | new.keys() if old.get(path) != new.get(path))
    assert changed == expected_changed
    assert [unit["path"] for unit in units if unit["kind"] == "public_tree"] == [
        plan.DIRECT_TREES[2], plan.DIRECT_TREES[3], plan.DIRECT_TREES[4]
    ]
    assert [unit["path"] for unit in units if unit["kind"] == "direct_file"] == [
        "runtime/a.py", "runtime/lib/python3.12/site-packages/authlib/oauth2/client.py"
    ]
    assert all(len(unit["changed"]) for unit in units)
    covered = [path for unit in units for path in unit["changed"]]
    assert sorted(covered) == changed
    assert len(covered) == len(set(covered))


def test_account_access_package_trees_can_be_replaced_in_place():
    project, metadata = plan.DIRECT_TREES[:2]
    old = {
        "": {"kind": "directory", "mode": 0o755},
        "runtime": {"kind": "directory", "mode": 0o755},
        project: {"kind": "directory", "mode": 0o755},
        project + "/service.py": file("a", 10),
        metadata: {"kind": "directory", "mode": 0o755},
        metadata + "/RECORD": file("b", 20),
    }
    new = {
        "": old[""],
        "runtime": old["runtime"],
        project: old[project],
        project + "/service.py": file("c", 11),
        project + "/vault_backup.py": file("d", 30),
        metadata: old[metadata],
        metadata + "/RECORD": file("e", 22),
    }

    changed, units = plan._units({"roots": {plan.SUPPORT: old}}, {"roots": {plan.SUPPORT: new}})

    assert changed == sorted(path for path in old.keys() | new.keys() if old.get(path) != new.get(path))
    assert [unit["path"] for unit in units if unit["kind"] == "public_tree"] == [project, metadata]
    assert all(unit["kind"] == "public_tree" for unit in units)
    assert units[0]["before"].get(project + "/service.py") == file("a", 10)
    assert units[0]["after"].get(project + "/vault_backup.py") == file("d", 30)


@pytest.mark.parametrize("path,node", [
    ("runtime/foreign", {"kind": "directory", "mode": 0o755}),
    ("broker/install.json", file("a")),
    ("runtime/escape/file", {"kind": "symlink", "target": "../../vault"}),
])
def test_delta_refuses_unplanned_directory_private_or_symlink_change(path, node):
    old = {"": {"kind": "directory", "mode": 0o755}, "runtime": {"kind": "directory", "mode": 0o755}}
    new = dict(old)
    new[path] = node
    with pytest.raises(plan.Refused):
        plan._units({"roots": {plan.SUPPORT: old}}, {"roots": {plan.SUPPORT: new}})


def test_delta_refuses_path_traversal_even_if_it_is_a_file():
    old = {"": {"kind": "directory", "mode": 0o755}, "runtime": {"kind": "directory", "mode": 0o755}}
    new = dict(old)
    new["runtime/../broker/install.json"] = file("a")
    with pytest.raises(plan.Refused):
        plan._units({"roots": {plan.SUPPORT: old}}, {"roots": {plan.SUPPORT: new}})


def test_updater_resource_carries_complete_signed_owner_bundle():
    tree = {
        "": {"kind": "directory", "mode": 0o755},
        "runtime": {"kind": "directory", "mode": 0o755},
        "runtime/update.py": file("a"),
        "owner.app": {"kind": "directory", "mode": 0o755},
        "owner.app/Contents": {"kind": "directory", "mode": 0o755},
        "owner.app/Contents/MacOS": {"kind": "directory", "mode": 0o755},
        "owner.app/Contents/MacOS/AccountAccess": file("b"),
        "owner.app/Contents/_CodeSignature": {"kind": "directory", "mode": 0o755},
        "owner.app/Contents/_CodeSignature/CodeResources": file("c"),
    }
    sparse, package = candidate.updater_payload_nodes({"units": [{
        "kind": "direct_file", "path": "runtime/update.py", "after": file("a"),
    }]}, {"roots": {candidate.SUPPORT_RELATIVE_ROOT: tree}})

    assert sparse == {
        "": tree[""], "runtime": tree["runtime"], "runtime/update.py": tree["runtime/update.py"],
    }
    assert package == tree


def test_updater_resource_refuses_incomplete_owner_bundle_signature():
    with pytest.raises(ValueError, match="target_owner_bundle_signature_resources_missing"):
        candidate.updater_payload_nodes({"units": []}, {"roots": {candidate.SUPPORT_RELATIVE_ROOT: {
            "": {"kind": "directory", "mode": 0o755},
            "owner.app": {"kind": "directory", "mode": 0o755},
        }}})


def test_expanded_installer_script_resources_are_exact_and_non_symlink(tmp_path):
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    for name in candidate.RESOURCE_NAMES:
        path = scripts / name
        if name == "TargetImage":
            path.mkdir()
        else:
            path.write_bytes(b"resource")
    assert candidate.expanded_script_resource_names(scripts) == candidate.RESOURCE_NAMES

    postinstall = scripts / "postinstall"
    postinstall.unlink()
    postinstall.symlink_to("RuntimeUpgradePlan.json")
    with pytest.raises(ValueError, match="signed_script_resource_invalid"):
        candidate.expanded_script_resource_names(scripts)

    postinstall.unlink()
    postinstall.write_bytes(b"resource")
    (scripts / "unexpected").write_bytes(b"not allowed")
    with pytest.raises(ValueError, match="signed_script_resource_count_mismatch"):
        candidate.expanded_script_resource_names(scripts)


def test_builder_public_inputs_are_owned_bounded_regular_files(tmp_path):
    public = tmp_path / "input.json"
    public.write_bytes(b"safe")
    assert candidate.read_owned_bytes(public, 4) == b"safe"
    with pytest.raises(ValueError, match="unsafe_public_input"):
        candidate.read_owned_bytes(public, 3)
    alias = tmp_path / "input-alias.json"
    alias.symlink_to(public)
    with pytest.raises(OSError):
        candidate.read_owned_bytes(alias, 4)


def test_publish_package_is_atomic_durable_and_does_not_replace(tmp_path):
    source = tmp_path / "candidate.pkg"
    source.write_bytes(b"qualified package")
    destination = tmp_path / "Downloads" / "Account-Access-Direct-Upgrade.pkg"
    destination.parent.mkdir()
    expected = hashlib.sha256(source.read_bytes()).hexdigest()

    assert candidate.publish_package(source, destination, expected) == destination
    assert destination.read_bytes() == source.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o644
    assert list(destination.parent.iterdir()) == [destination]

    with pytest.raises(ValueError, match="publish_destination_exists"):
        candidate.publish_package(source, destination, expected)
    assert destination.read_bytes() == source.read_bytes()


def test_publish_package_refuses_mismatch_and_unsafe_destinations(tmp_path):
    source = tmp_path / "candidate.pkg"
    source.write_bytes(b"qualified package")
    destination = tmp_path / "published.pkg"

    with pytest.raises(ValueError, match="publish_copy_digest_mismatch"):
        candidate.publish_package(source, destination, "0" * 64)
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == [source]

    alias = tmp_path / "alias.pkg"
    alias.symlink_to(source)
    with pytest.raises(ValueError, match="publish_source_invalid"):
        candidate.publish_package(alias, destination, hashlib.sha256(source.read_bytes()).hexdigest())

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    foreign_parent = tmp_path / "foreign"
    foreign_parent.symlink_to(real_parent, target_is_directory=True)
    foreign_destination = foreign_parent / "published.pkg"
    with pytest.raises(ValueError, match="publish_destination_parent_invalid"):
        candidate.publish_package(source, foreign_destination, hashlib.sha256(source.read_bytes()).hexdigest())


def test_sparse_materialization_copies_only_planned_files_and_symlinks(tmp_path):
    source_image = tmp_path / "source"
    source_support = source_image / candidate.SUPPORT_RELATIVE
    runtime = source_support / "runtime"
    runtime.mkdir(parents=True)
    (runtime / "module.py").write_text("safe")
    (runtime / "current").symlink_to("module.py")
    (runtime / "unplanned.py").write_text("must not ship")
    inventory = {
        "": {"kind": "directory", "mode": 0o755},
        "runtime": {"kind": "directory", "mode": 0o755},
        "runtime/module.py": candidate.public_payload_inventory(source_support)["runtime/module.py"],
        "runtime/current": {"kind": "symlink", "target": "module.py"},
    }
    target_image = tmp_path / "target"
    support, byte_count = candidate.materialize_sparse_target(source_image, target_image, inventory)
    assert byte_count == 4
    assert candidate.public_payload_inventory(support) == inventory
    assert (support / "runtime/current").is_symlink()
    assert not (support / "runtime/unplanned.py").exists()
    assert (source_support / "runtime/module.py").read_text() == "safe"
    assert (source_support / "runtime/current").is_symlink()


def test_target_image_manifest_is_checked_and_source_image_is_preserved(tmp_path):
    public = tmp_path / "PublicImage"
    applications = public / "Applications"
    support = public / candidate.SUPPORT_RELATIVE
    app = support / "owner.app"
    (applications).mkdir(parents=True)
    (app / "Contents/_CodeSignature").mkdir(parents=True)
    (app / "Contents/_CodeSignature/CodeResources").write_bytes(b"signed resources")
    (support / "runtime").mkdir()
    (support / "runtime/changed.py").write_bytes(b"source-current")
    app_target = "../Library/Application Support/Account Access/owner.app"
    (applications / "Account Access.app").symlink_to(app_target)
    before = candidate.public_payload_inventory(support)
    manifest = {"roots": {
        candidate.SUPPORT_RELATIVE_ROOT: before,
        "/Applications/Account Access.app": {"": {"kind": "symlink", "target": app_target}},
    }}
    plan = {"units": [{"kind": "direct_file", "path": "runtime/changed.py",
                       "after": before["runtime/changed.py"]}]}
    scripts = tmp_path / "scripts"
    scripts.mkdir()

    image, packaged_support, sparse_nodes, _bytes, app_nodes, inventory = candidate.extract_sparse_target(
        public, scripts, manifest, plan)

    assert image == scripts / "TargetImage"
    assert candidate.public_payload_inventory(support) == before
    assert candidate.public_payload_inventory(packaged_support) == inventory
    assert sparse_nodes == 3
    assert app_nodes > 0

    tampered = dict(manifest)
    tampered["roots"] = dict(manifest["roots"])
    tampered["roots"][candidate.SUPPORT_RELATIVE_ROOT] = {**before, "runtime/changed.py": file("f")}
    other_scripts = tmp_path / "other-scripts"
    other_scripts.mkdir()
    with pytest.raises(ValueError, match="target_public_image_manifest_mismatch"):
        candidate.extract_sparse_target(public, other_scripts, tampered, plan)


def test_sparse_inventory_preserves_symlinks_and_refuses_symlink_directories(tmp_path):
    support = tmp_path / "support"
    support.mkdir()
    (support / "module.py").write_text("safe")
    (support / "alias").symlink_to("module.py")
    nodes = candidate.public_payload_inventory(support)
    assert nodes["alias"] == {"kind": "symlink", "target": "module.py"}
    assert nodes["module.py"]["kind"] == "file"

    image = tmp_path / "image"
    parent = image / "Library" / "Application Support"
    parent.mkdir(parents=True)
    installed_support = parent / "Account Access"
    installed_support.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (installed_support / "runtime").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="sparse_directory_attachment_refused"):
        candidate.create_sparse_directories(image, {
            "": {"kind": "directory", "mode": 0o755},
            "runtime": {"kind": "directory", "mode": 0o755},
        })


def test_sparse_materialization_refuses_source_symlink_directories(tmp_path):
    source_image = tmp_path / "source"
    source_support = source_image / candidate.SUPPORT_RELATIVE
    source_support.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (source_support / "runtime").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="sparse_source_directory_refused"):
        candidate.materialize_sparse_target(source_image, tmp_path / "target", {
            "": {"kind": "directory", "mode": 0o755},
            "runtime": {"kind": "directory", "mode": 0o755},
        })
