import hashlib
import json
import os

import pytest

from account_access import package_manifest as manifest


@pytest.fixture
def payload(tmp_path):
    root = tmp_path / "copied-payload"
    support, app = root / manifest.SUPPORT, root / manifest.CANONICAL_APP
    (support / "bin").mkdir(parents=True)
    (app / "Contents/MacOS").mkdir(parents=True)
    public = root / manifest.OWNER_APP
    public.parent.mkdir()
    public.symlink_to(manifest.APPLICATION_TARGET)
    (support / "bin/broker").write_bytes(b"synthetic broker code")
    (support / "bin/broker").chmod(0o755)
    (support / "requirements.txt").write_bytes(b"synthetic dependency lock")
    (app / "Contents/MacOS/AccountAccess").write_bytes(b"synthetic owner application")
    (app / "Contents/MacOS/AccountAccess").chmod(0o755)
    (support / "bin/current").symlink_to("broker")
    for path in [root, *root.rglob("*")]:
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & 0o777 & ~0o022)
    support.chmod(0o755)
    return root, support, app


def test_manifest_binds_fixed_roots_resources_native_files_and_internal_aliases(payload):
    root, support, app = payload
    before = {path: path.read_bytes() for path in [support / "requirements.txt", app / "Contents/MacOS/AccountAccess"]}
    encoded = manifest.build(root, "0.8.0", "arm64")
    assert encoded == manifest.build(root, "0.8.0", "arm64")
    value = json.loads(encoded)
    assert value["schema"] == 1 and value["architecture"] == "arm64"
    assert value["package_identifier"] == "com.fainir.accountaccess.system"
    assert set(value["roots"]) == {"/" + str(manifest.SUPPORT), "/" + str(manifest.OWNER_APP)}
    rows = value["roots"]["/" + str(manifest.SUPPORT)]
    assert rows[""] == {"kind": "directory", "mode": 0o755}
    assert rows["bin/broker"] == {
        "kind": "file", "size": 21, "mode": 0o755,
        "sha256": hashlib.sha256(b"synthetic broker code").hexdigest(),
    }
    assert rows["bin/current"] == {"kind": "symlink", "target": "broker"}
    assert rows["owner.app/Contents/MacOS/AccountAccess"]["kind"] == "file"
    assert value["roots"]["/" + str(manifest.OWNER_APP)] == {
        "": {"kind": "symlink", "target": "../Library/Application Support/Account Access/owner.app"}}
    assert {path: path.read_bytes() for path in before} == before
    (support / "requirements.txt").write_bytes(b"changed public lock")
    assert manifest.build(root, "0.8.0", "arm64") != encoded


@pytest.mark.parametrize("target", ["/Library/Application Support/Account Access/owner.app",
                                     "../Library/Application Support/Account Access/./owner.app",
                                     "../Library/Application Support/Account Access/other.app"])
def test_public_application_slot_accepts_only_the_exact_relative_literal(payload, target):
    root, _, _ = payload
    public = root / manifest.OWNER_APP
    public.unlink()
    public.symlink_to(target)
    before = public.lstat().st_ino
    with pytest.raises(ValueError, match="unsafe_install_manifest_application_alias"):
        manifest.build(root, "0.8.0", "arm64")
    assert public.lstat().st_ino == before and os.readlink(public) == target


def test_public_application_directory_is_not_a_second_authoritative_bundle(payload):
    root, _, _ = payload
    public = root / manifest.OWNER_APP
    public.unlink()
    public.mkdir()
    with pytest.raises(ValueError, match="unsafe_install_manifest_application_alias"):
        manifest.build(root, "0.8.0", "arm64")


def test_canonical_application_binary_cannot_be_an_alias_or_missing(payload):
    root, _, app = payload
    binary = app / "Contents/MacOS/AccountAccess"
    binary.rename(binary.with_name("other"))
    with pytest.raises(ValueError, match="unsafe_install_manifest_owner_application"):
        manifest.build(root, "0.8.0", "arm64")
    binary.symlink_to("other")
    with pytest.raises(ValueError, match="unsafe_install_manifest_owner_application"):
        manifest.build(root, "0.8.0", "arm64")


@pytest.mark.parametrize("version,architecture", [("0.7.4", "arm64"), ("0.8.0", "i386")])
def test_manifest_cannot_claim_another_package(payload, version, architecture):
    with pytest.raises(ValueError, match="unsupported_install_manifest_package"):
        manifest.build(payload[0], version, architecture)


@pytest.mark.parametrize("kind", ["absolute", "outside", "dangling", "cycle", "outside-return", "non-directory-hop"])
def test_manifest_refuses_aliases_that_leave_the_shipped_root(payload, tmp_path, kind):
    _, support, _ = payload
    alias = support / "alias"
    if kind == "absolute":
        alias.symlink_to(support / "requirements.txt")
    elif kind == "outside":
        outside = tmp_path / "outside"
        outside.write_text("unrelated fixture")
        alias.symlink_to(os.path.relpath(outside, support))
    elif kind == "dangling":
        alias.symlink_to("missing")
    elif kind == "cycle":
        alias.symlink_to("alias")
    elif kind == "non-directory-hop":
        alias.symlink_to("requirements.txt/../bin/broker")
    else:
        outside = support.parent / "outside"
        outside.mkdir()
        (outside / "back").symlink_to(support, target_is_directory=True)
        alias.symlink_to("../outside/back/requirements.txt")
    with pytest.raises(ValueError, match="unsafe_install_manifest_alias"):
        manifest.inventory(support)


def test_internal_directory_alias_is_recorded_without_traversing_it(payload):
    _, support, _ = payload
    (support / "current-bin").symlink_to("bin", target_is_directory=True)
    rows = manifest.inventory(support)
    assert rows["current-bin"] == {"kind": "symlink", "target": "bin"}
    assert "current-bin/broker" not in rows


@pytest.mark.parametrize("damage", ["hardlink", "special-mode", "fifo", "writable"])
def test_manifest_refuses_shared_privileged_and_special_objects(payload, damage):
    _, support, _ = payload
    if damage == "hardlink":
        os.link(support / "requirements.txt", support / "shared")
    elif damage == "special-mode":
        (support / "requirements.txt").chmod(0o4644)
    elif damage == "writable":
        (support / "requirements.txt").chmod(0o664)
    else:
        os.mkfifo(support / "pipe")
    with pytest.raises(ValueError, match="unsafe_install_manifest"):
        manifest.inventory(support)


@pytest.mark.parametrize("name", ["back\\slash", "colon:name", "line\nbreak"])
def test_manifest_rejects_ambiguous_or_control_character_paths(payload, name):
    _, support, _ = payload
    (support / name).write_bytes(b"fixture")
    with pytest.raises(ValueError, match="unsafe_install_manifest_name"):
        manifest.inventory(support)


def test_manifest_refuses_normalized_case_collisions_when_filesystem_allows_them(payload):
    _, support, _ = payload
    (support / "Case").write_bytes(b"first")
    (support / "case").write_bytes(b"second")
    if sum(path.name in {"Case", "case"} for path in support.iterdir()) == 1:
        pytest.skip("Filesystem already prevents this case collision")
    with pytest.raises(ValueError, match="install_manifest_collision_or_limit"):
        manifest.inventory(support)


@pytest.mark.parametrize("limit", ["entries", "file", "total", "manifest"])
def test_manifest_limits_are_enforced_without_partial_output(payload, monkeypatch, limit):
    root, support, _ = payload
    if limit == "entries":
        monkeypatch.setattr(manifest, "MAX_ENTRIES", 1)
    elif limit == "file":
        monkeypatch.setattr(manifest, "MAX_FILE_BYTES", 1)
    elif limit == "total":
        monkeypatch.setattr(manifest, "MAX_TOTAL_BYTES", 1)
    else:
        monkeypatch.setattr(manifest, "MAX_MANIFEST_BYTES", 1)
    with pytest.raises(ValueError):
        manifest.build(root, "0.8.0", "arm64")
    assert not (support / "RecoveryManifest.json").exists()


def test_changed_file_is_rejected_against_the_original_descriptor_snapshot(payload):
    _, support, _ = payload
    path = support / "requirements.txt"
    before = path.lstat()
    path.write_bytes(b"changed fixture")
    with pytest.raises(ValueError, match="install_manifest_payload_changed"):
        manifest._file(path, before)


def test_symlink_swap_cannot_make_file_hashing_follow_an_unrelated_file(payload, tmp_path):
    _, support, _ = payload
    path = support / "requirements.txt"
    before = path.lstat()
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_bytes(b"unrelated fixture")
    path.unlink()
    path.symlink_to(unrelated)
    with pytest.raises(OSError):
        manifest._file(path, before)


def test_changed_file_during_hashing_invalidates_the_manifest(payload, monkeypatch):
    _, support, _ = payload
    path = support / "requirements.txt"
    original = manifest.hashlib.sha256

    class Changed:
        def __init__(self):
            self.inner = original()

        def update(self, block):
            self.inner.update(block)
            path.write_bytes(b"changed during hashing")

        def hexdigest(self):
            return self.inner.hexdigest()

    monkeypatch.setattr(manifest.hashlib, "sha256", Changed)
    with pytest.raises(ValueError, match="install_manifest_payload_changed"):
        manifest._file(path, path.lstat())


def test_expected_root_ancestors_cannot_be_replaced_by_aliases(payload):
    root, _, _ = payload
    actual = root / "Library"
    renamed = root / "relocated"
    actual.rename(renamed)
    actual.symlink_to(renamed, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe_install_manifest_root"):
        manifest.build(root, "0.8.0", "arm64")


@pytest.mark.parametrize("mode", [0o775, 0o2755])
def test_manifest_requires_a_protected_unprivileged_staging_root(payload, mode):
    root, _, _ = payload
    root.chmod(mode)
    with pytest.raises(ValueError, match="unsafe_install_manifest_root"):
        manifest.build(root, "0.8.0", "arm64")


@pytest.mark.parametrize("owner", [True, -1, "0"])
def test_read_only_manifest_owner_selector_rejects_ambiguous_ids(payload, owner):
    with pytest.raises(ValueError, match="invalid_install_manifest_owner"):
        manifest.inventory(payload[1], owner_uid=owner)


def test_read_only_manifest_owner_selector_cannot_hide_wrong_file_ownership(payload):
    with pytest.raises(ValueError, match="unsafe_install_manifest_object"):
        manifest.inventory(payload[1], owner_uid=os.getuid() + 1)
