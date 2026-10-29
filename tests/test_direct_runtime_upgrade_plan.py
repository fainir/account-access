from __future__ import annotations

import pytest

from macos import direct_runtime_upgrade_plan as plan
from scripts import build_direct_runtime_upgrade_candidate as candidate


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
        plan.DIRECT_TREES[0], plan.DIRECT_TREES[1], plan.DIRECT_TREES[2]
    ]
    assert [unit["path"] for unit in units if unit["kind"] == "direct_file"] == [
        "runtime/a.py", "runtime/lib/python3.12/site-packages/authlib/oauth2/client.py"
    ]
    assert all(len(unit["changed"]) for unit in units)
    covered = [path for unit in units for path in unit["changed"]]
    assert sorted(covered) == changed
    assert len(covered) == len(set(covered))


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


def test_sparse_materialization_moves_only_planned_files_and_symlinks(tmp_path):
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
