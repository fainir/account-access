import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

from account_access import system_provision as provision


def layout(tmp_path):
    return provision.Layout(
        tmp_path / "base",
        tmp_path / "runtime",
        tmp_path / "browsers",
        tmp_path / "Account Access.app",
        tmp_path / "broker",
        tmp_path / "bootstrap",
        "_aaq0123456789ab",
        "com.fainir.accountaccess.qa.provision",
        True,
    )


def signatures():
    return {
        key: {
            "team": "fixture",
            "identifier": "com.fainir.accountaccess" + suffix,
            "hashes": ["a" * 40],
        }
        for key, suffix in [("owner", ""), ("broker", ".broker"), ("bootstrap", ".bootstrap")]
    }


@pytest.mark.skipif(sys.platform != "darwin", reason="Uses Apple's actual requirement parser")
def test_production_requirement_is_parsed_and_rejects_an_untrusted_publisher(
    tmp_path, monkeypatch
):
    source = tmp_path / "fixture.c"
    binary = tmp_path / "fixture"
    source.write_text("int main(void) { return 0; }\n")
    subprocess.run(["/usr/bin/xcrun", "clang", str(source), "-o", str(binary)],
                   check=True, capture_output=True)
    subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier",
                    "com.fainir.accountaccess.qa.requirement", str(binary)],
                   check=True, capture_output=True)
    checked = []

    def command(arguments):
        result = subprocess.run(arguments, capture_output=True, timeout=20)
        if "-d" in arguments:
            # Synthetic team metadata reaches the production requirement call;
            # the actual ad-hoc binary must still fail Apple's publisher check.
            assert result.stderr.count(b"TeamIdentifier=not set") == 1
            result.stderr = result.stderr.replace(
                b"TeamIdentifier=not set", b"TeamIdentifier=ABCDEFGHIJ"
            )
        elif any(value.startswith("-R") for value in arguments):
            assert result.returncode != 0
            assert b"code failed to satisfy" in result.stderr
            assert b"invalid requirement specification" not in result.stderr
            assert b"No such file or directory" not in result.stderr
            checked.append(True)
            raise provision.ProvisionError("publisher_requirement_not_satisfied")
        assert result.returncode == 0
        return result

    monkeypatch.setattr(provision, "command", command)
    with pytest.raises(provision.ProvisionError, match="publisher_requirement_not_satisfied"):
        provision.signature(binary, "com.fainir.accountaccess.qa.requirement")
    assert checked == [True]


def test_fixed_production_layout_has_no_owner_path_or_command_override():
    actual = provision.Layout.installed()
    assert actual.base == Path("/Library/Application Support/Account Access")
    assert actual.runtime / "bin/python" == actual.base / "runtime/bin/python"
    assert actual.owner_app == actual.base / "owner.app"
    assert actual.broker_name == "_accountaccess" and actual.fixture is False
    with pytest.raises(provision.ProvisionError, match="disposable_provisioning_required"):
        provision.Layout.ci_fixture(Path("/tmp/forged"), name="_aaq0123456789ab")


def test_owner_bundle_path_is_protected_before_its_code_identity_is_considered(monkeypatch):
    actual = provision.Layout.installed()
    checked = []

    def protected(path):
        checked.append(path)
        if path == actual.owner_app:
            raise provision.ProvisionError("untrusted_owner_bundle")

    monkeypatch.setattr(provision, "root_managed_path", protected)
    monkeypatch.setattr(provision, "signature", lambda *args, **kwargs: pytest.fail("Unsafe owner code was inspected"))
    with pytest.raises(provision.ProvisionError, match="untrusted_owner_bundle"):
        provision.payload(actual)
    assert checked[-1] == actual.owner_app


def test_provisioning_requires_root_before_payload_or_identity_access(tmp_path, monkeypatch):
    monkeypatch.setattr(provision.os, "getuid", lambda: 501)
    called = []
    monkeypatch.setattr(provision, "payload", lambda _: called.append(True))
    with pytest.raises(provision.ProvisionError, match="system_install_requires_root"):
        provision.prepare(layout(tmp_path), 501)
    assert not called and list(tmp_path.iterdir()) == []


def test_generated_plans_bind_identities_paths_and_public_profile_without_secrets(tmp_path):
    actual = layout(tmp_path)
    record = {
        "broker_uid": 451,
        "owner_uid": 501,
        "vault_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "enrollment_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }
    values, profile, job = provision.plans(actual, record, signatures(), 20)
    assert set(values) == {
        "worker.json",
        "stage.json",
        "worker-launch.json",
        "stage-launch.json",
        "enrollment.json",
        "host.json",
    }
    assert values["worker.json"]["broker_uid"] == 451 and values["worker.json"]["agent_uid"] == 501
    assert values["stage.json"] == dict(
        values["worker.json"],
        root=str(actual.base / "vault/.enrollment-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
    )
    assert (
        values["worker-launch.json"]["broker_gid"] == 451
        and values["worker-launch.json"]["fixture"] is True
    )
    assert values["host.json"]["owner_uid"] == profile["owner_uid"] == 501
    assert profile["server_hashes"] == signatures()["broker"]["hashes"]
    assert job["ProgramArguments"] == [
        str(actual.broker),
        "--fixture-policy",
        str(actual.base / "broker/host.json"),
    ]
    assert job["Sockets"]["AccountAccessAgent"]["SockPathGroup"] == 20
    assert job["Sockets"]["AccountAccessOwner"]["SockPathMode"] == 0o600
    assert job["AbandonProcessGroup"] is False and job["MachServices"] == {provision.SERVICE: True}
    assert job["AssociatedBundleIdentifiers"] == ["com.fainir.accountaccess"]
    assert all(len(json.dumps(value).encode()) <= 4096 for value in values.values())
    assert plistlib.loads(plistlib.dumps(job)) == job
    assert not any(
        word in json.dumps([values, profile, job]).lower()
        for word in ["token", "password", "private_key"]
    )


def test_production_service_arguments_cannot_enable_fixture_paths(tmp_path):
    actual = layout(tmp_path)
    from dataclasses import replace

    actual = replace(actual, fixture=False)
    _, _, job = provision.plans(
        actual,
        {"broker_uid": 451, "owner_uid": 501, "vault_id": "a", "enrollment_id": "b"},
        signatures(),
        20,
    )
    assert job["ProgramArguments"] == [str(actual.broker)]


def test_atomic_publication_is_idempotent_never_overwrites_and_preserves_single_link(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(provision, "root_managed_path", lambda value: Path(value))
    file = tmp_path / "owner.json"
    provision.publish(file, b'{"public":"metadata"}')
    before = file.stat()
    provision.publish(file, file.read_bytes())
    assert file.stat().st_ino == before.st_ino and file.stat().st_nlink == 1
    assert file.stat().st_mode & 0o777 == 0o644 and not list(tmp_path.glob(".provision-*"))
    with pytest.raises(provision.ProvisionError, match="existing_installation_requires_repair"):
        provision.publish(file, b'{"changed":"metadata"}')
    assert file.read_bytes() == b'{"public":"metadata"}'


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "mode"])
def test_publication_refuses_unsafe_existing_objects(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(provision, "root_managed_path", lambda value: Path(value))
    outside = tmp_path / "outside"
    outside.write_bytes(b"preserve")
    file = tmp_path / "owner.json"
    if kind == "symlink":
        file.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, file)
    elif kind == "directory":
        file.mkdir()
    else:
        file.write_bytes(b"preserve")
        file.chmod(0o666)
    with pytest.raises(provision.ProvisionError):
        provision.publish(file, b"new data")
    assert outside.read_bytes() == b"preserve"


@pytest.fixture
def public_directories(tmp_path, monkeypatch):
    """Keep real directory/mode/ACL checks while simulating Root ownership."""
    from account_access.install_image import _check as real_check

    real_uid = os.getuid()
    root = tmp_path / "protected"
    root.mkdir(mode=0o700)
    owners = {}

    def check(fd, uid, directory, mode=None):
        info = real_check(fd, real_uid, directory, mode)
        owner, group = owners.get((info.st_dev, info.st_ino), (0, 0))
        if owner != uid:
            raise provision.ImageConflict("unsafe_image_object")
        metadata = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        return SimpleNamespace(**dict(metadata, st_uid=owner, st_gid=group))

    def forbidden(*args, **kwargs):
        pytest.fail("Public directory provisioning must never repair an existing object")

    proxy = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    proxy.fchmod, proxy.fchown = forbidden, forbidden
    monkeypatch.setattr(provision, "os", proxy)
    monkeypatch.setattr(provision, "_check", check)
    monkeypatch.setattr(provision, "root_managed_path", lambda path: Path(path))
    return root, owners


@pytest.mark.parametrize("mode", [0o755, 0o700])
def test_public_directory_recovers_interruption_immediately_after_mkdir_with_private_umask(
    public_directories, monkeypatch, mode
):
    root, _ = public_directories
    target = root / "policy"
    mkdir = provision.os.mkdir

    def interrupted(name, requested, *, dir_fd):
        mkdir(name, requested, dir_fd=dir_fd)
        assert os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode & 0o777 == mode
        raise KeyboardInterrupt("synthetic crash before post-mkdir validation")

    monkeypatch.setattr(provision.os, "mkdir", interrupted)
    previous = os.umask(0o777)
    try:
        with pytest.raises(KeyboardInterrupt):
            provision.root_directory(target, mode)
        assert os.umask(0o777) == 0o777
        before = target.stat()
        monkeypatch.setattr(provision.os, "mkdir", mkdir)
        assert provision.root_directory(target, mode) == target
        assert os.umask(0o777) == 0o777
        assert target.stat() == before
    finally:
        os.umask(previous)


def test_public_directory_restores_umask_when_mkdir_fails(public_directories, monkeypatch):
    root, _ = public_directories

    def fail(*args, **kwargs):
        raise OSError("synthetic mkdir failure")

    monkeypatch.setattr(provision.os, "mkdir", fail)
    previous = os.umask(0o777)
    try:
        with pytest.raises(provision.ProvisionError, match="unsafe_install_directory"):
            provision.root_directory(root / "policy")
        assert os.umask(0o777) == 0o777 and list(root.iterdir()) == []
    finally:
        os.umask(previous)


@pytest.mark.parametrize("kind", ["symlink", "file", "mode", "foreign-owner", "setid"])
def test_public_directory_preserves_conflicting_final(public_directories, kind):
    root, owners = public_directories
    outside = root / "outside"
    outside.mkdir(mode=0o755)
    outside.joinpath("keep").write_bytes(b"preserve")
    target = root / "policy"
    if kind == "symlink":
        target.symlink_to(outside, target_is_directory=True)
    elif kind == "file":
        target.write_bytes(b"preserve")
    else:
        target.mkdir(mode=0o755)
        if kind == "mode":
            target.chmod(0o700)
        elif kind == "setid":
            target.chmod(0o2755)
        else:
            info = target.stat()
            owners[(info.st_dev, info.st_ino)] = (451, 451)
    before = target.lstat()
    with pytest.raises(provision.ProvisionError, match="unsafe_install_directory"):
        provision.root_directory(target)
    assert target.lstat() == before and outside.joinpath("keep").read_bytes() == b"preserve"


def test_public_directory_retry_checks_metadata_without_traversing_contents(
    public_directories, monkeypatch
):
    root, owners = public_directories
    target = provision.root_directory(root / "policy")
    target.joinpath("keep").write_bytes(b"preserve")
    before = target.stat()
    # Root-managed paths may inherit a group; 0755 gives it no write authority.
    owners[(before.st_dev, before.st_ino)] = (0, 20)
    monkeypatch.setattr(provision, "_names", lambda _: pytest.fail("No contents traversal"))
    provision.root_directory(target)
    assert target.stat() == before and target.joinpath("keep").read_bytes() == b"preserve"


def test_public_directory_rejects_name_replacement_after_open(public_directories, monkeypatch):
    root, _ = public_directories
    target = root / "policy"
    target.mkdir(mode=0o755)
    target.joinpath("keep").write_bytes(b"preserve")
    moved = root / "moved"
    original = provision.os.open

    def replaced(name, flags, *args, **kwargs):
        descriptor = original(name, flags, *args, **kwargs)
        if name == target.name and kwargs.get("dir_fd") is not None:
            target.rename(moved)
            target.mkdir(mode=0o755)
        return descriptor

    monkeypatch.setattr(provision.os, "open", replaced)
    with pytest.raises(provision.ProvisionError, match="unsafe_install_directory"):
        provision.root_directory(target)
    assert target.is_dir() and moved.joinpath("keep").read_bytes() == b"preserve"


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACLs")
@pytest.mark.parametrize("location", ["parent", "final"])
def test_public_directory_rejects_allow_acl_without_repair(public_directories, location):
    root, _ = public_directories
    target = root / "policy"
    if location == "final":
        target.mkdir(mode=0o755)
    controlled = root if location == "parent" else target
    subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(controlled)], check=True)
    try:
        before = controlled.stat()
        with pytest.raises(provision.ProvisionError, match="unsafe_install_directory"):
            provision.root_directory(target)
        assert controlled.stat() == before and target.exists() == (location == "final")
    finally:
        subprocess.run(["/bin/chmod", "-N", str(controlled)], check=True)


@pytest.fixture
def private_directories(tmp_path, monkeypatch):
    """Exercise real descriptors/renames using synthetic ownership, never Root."""
    from account_access.install_image import _check as real_check

    real_uid = os.getuid()
    root = tmp_path / "protected"
    root.mkdir(mode=0o700)
    staging = root / "broker"
    staging.mkdir(mode=0o700)
    owners, ownership_changes = {}, []

    def identity(fd):
        info = os.fstat(fd)
        return info.st_dev, info.st_ino

    def metadata(fd):
        info = os.fstat(fd)
        owner, group = owners.get(identity(fd), (0, 0))
        return SimpleNamespace(st_uid=owner, st_gid=group, st_dev=info.st_dev,
                               st_ino=info.st_ino)

    def check(fd, uid, directory, mode=None):
        real_check(fd, real_uid, directory, mode)
        info = metadata(fd)
        if info.st_uid != uid:
            raise provision.ImageConflict("unsafe_image_object")
        return info

    def chown(fd, uid, gid):
        owners[identity(fd)] = (uid, gid)
        ownership_changes.append(identity(fd))

    proxy = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    proxy.fstat, proxy.fchown = metadata, chown
    monkeypatch.setattr(provision, "os", proxy)
    monkeypatch.setattr(provision, "_check", check)
    monkeypatch.setattr(provision, "root_managed_path", lambda path: Path(path))
    return root, staging, owners, ownership_changes


@pytest.mark.parametrize("boundary", [
    "stage-created", "directory-created", "ownership-set", "directory-published", "stage-removed",
])
def test_private_directory_recovers_each_atomic_publication_boundary(
    private_directories, boundary
):
    root, staging, owners, changes = private_directories
    target = root / "home"

    def interrupt(event):
        if event == boundary:
            raise KeyboardInterrupt("synthetic provisioning interruption")

    with pytest.raises(KeyboardInterrupt):
        provision.private_directory(target, 451, staging=staging, checkpoint=interrupt)
    published = target.stat().st_ino if target.exists() else None
    provision.private_directory(target, 451, staging=staging)
    before = target.stat()
    target.joinpath("private-data").write_bytes(b"synthetic private contents")
    provision.private_directory(target, 451, staging=staging)
    assert target.stat().st_ino == before.st_ino
    assert published is None or published == before.st_ino
    assert owners[(before.st_dev, before.st_ino)] == (451, 451)
    assert len(changes) == 1 and before.st_mode & 0o777 == 0o700
    assert list(staging.iterdir()) == []
    assert target.joinpath("private-data").read_bytes() == b"synthetic private contents"


def test_private_directory_handles_restrictive_umask(private_directories):
    root, staging, _, _ = private_directories
    previous = os.umask(0o777)
    try:
        provision.private_directory(root / "home", 451, staging=staging)
        assert os.umask(0o777) == 0o777
    finally:
        os.umask(previous)
    assert (root / "home").stat().st_mode & 0o777 == 0o700


def test_private_directory_sets_both_ids_after_root_group_inheritance(private_directories):
    root, staging, owners, changes = private_directories
    target = root / "home"
    stage = staging / provision._private_stage_name(target, 451)
    stage.mkdir(mode=0o700)
    child = stage / "directory"
    child.mkdir(mode=0o700)
    before = child.stat()
    owners[(before.st_dev, before.st_ino)] = (0, 20)
    provision.private_directory(target, 451, staging=staging)
    assert target.stat().st_ino == before.st_ino
    assert owners[(before.st_dev, before.st_ino)] == (451, 451)
    assert len(changes) == 1 and list(staging.iterdir()) == []


@pytest.mark.parametrize("kind", ["root-owned", "symlink", "mode", "group"])
def test_private_directory_never_adopts_or_rewrites_conflicting_final(
    private_directories, kind
):
    root, staging, owners, changes = private_directories
    outside = root / "outside"
    outside.mkdir(mode=0o700)
    outside.joinpath("keep").write_bytes(b"preserve")
    target = root / "home"
    if kind == "symlink":
        target.symlink_to(outside, target_is_directory=True)
    else:
        target.mkdir(mode=0o700)
        info = target.stat()
        owners[(info.st_dev, info.st_ino)] = (0, 0) if kind == "root-owned" else (451, 451)
        if kind == "mode":
            target.chmod(0o750)
        if kind == "group":
            owners[(info.st_dev, info.st_ino)] = (451, 452)
    before = target.lstat()
    with pytest.raises(provision.ProvisionError, match="unsafe_private_directory"):
        provision.private_directory(target, 451, staging=staging)
    assert target.lstat() == before and changes == [] and list(staging.iterdir()) == []
    assert outside.joinpath("keep").read_bytes() == b"preserve"


@pytest.mark.parametrize("kind", ["unknown-child", "nonempty-child", "symlink-child", "mode", "foreign-owner"])
def test_private_directory_preserves_conflicting_intermediate(private_directories, kind):
    root, staging, owners, changes = private_directories
    target = root / "home"
    stage = staging / provision._private_stage_name(target, 451)
    stage.mkdir(mode=0o700)
    if kind == "unknown-child":
        stage.joinpath("unknown").write_bytes(b"preserve")
    elif kind == "symlink-child":
        stage.joinpath("directory").symlink_to(root, target_is_directory=True)
    elif kind in {"nonempty-child", "foreign-owner"}:
        child = stage / "directory"
        child.mkdir(mode=0o700)
        if kind == "nonempty-child":
            child.joinpath("private-data").write_bytes(b"preserve")
        else:
            info = child.stat()
            owners[(info.st_dev, info.st_ino)] = (452, 452)
    else:
        stage.chmod(0o750)
    def identity(path):
        info = path.lstat()
        # A refusal may read a directory and update access time. Identity,
        # permissions, contents metadata and ownership must remain unchanged.
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    before = {path.name: identity(path) for path in stage.iterdir()}
    with pytest.raises(provision.ProvisionError, match="unsafe_private_directory"):
        provision.private_directory(target, 451, staging=staging)
    assert not target.exists() and changes == []
    assert {path.name: identity(path) for path in stage.iterdir()} == before


def test_private_directory_does_not_traverse_existing_private_contents(
    private_directories, monkeypatch
):
    root, staging, _, _ = private_directories
    target = root / "home"
    provision.private_directory(target, 451, staging=staging)
    private_inode = target.stat().st_ino
    original = provision._names

    def names(fd):
        assert os.fstat(fd).st_ino != private_inode
        return original(fd)

    monkeypatch.setattr(provision, "_names", names)
    provision.private_directory(target, 451, staging=staging)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACLs")
@pytest.mark.parametrize("location", ["stage", "final"])
def test_private_directory_rejects_allow_acl_without_changing_private_state(
    private_directories, location
):
    root, staging, _, changes = private_directories
    target = root / "home"
    if location == "final":
        provision.private_directory(target, 451, staging=staging)
        controlled = target
    else:
        controlled = staging / provision._private_stage_name(target, 451)
        controlled.mkdir(mode=0o700)
    count = len(changes)
    subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(controlled)], check=True)
    try:
        with pytest.raises(provision.ProvisionError, match="unsafe_private_directory"):
            provision.private_directory(target, 451, staging=staging)
        assert len(changes) == count and controlled.exists()
    finally:
        subprocess.run(["/bin/chmod", "-N", str(controlled)], check=True)


def test_privileged_private_directory_probe_refuses_local_execution(monkeypatch):
    from scripts import mac_private_directory_probe as probe

    monkeypatch.setattr(probe.os, "getuid", lambda: 501)
    monkeypatch.setattr(
        probe, "root_managed_path", lambda path: pytest.fail("No local protected path access")
    )
    with pytest.raises(RuntimeError, match="disposable_private_directory_probe_required"):
        probe.check_recovery(Path("/Library/PrivilegedHelperTools/account-access-worker-qa-12345678"), 451)


@pytest.mark.parametrize("boundary", ["stage-created", "public-755", "public-700"])
def test_privileged_directory_probe_child_refuses_local_execution(monkeypatch, boundary):
    from scripts import mac_private_directory_probe as probe

    monkeypatch.setattr(probe.os, "getuid", lambda: 501)
    monkeypatch.setattr(
        probe, "root_managed_path", lambda path: pytest.fail("No local protected path access")
    )
    target = Path("/Library/PrivilegedHelperTools/account-access-worker-qa-12345678"
                  "/provisioned/broker/private-directory-qa-" + "a" * 32)
    with pytest.raises(RuntimeError, match="disposable_private_directory_probe_required"):
        probe.child(target, 451, boundary)


@pytest.mark.parametrize(
    "code,out,err,expected",
    [
        (0, plistlib.dumps({"dsAttrTypeStandard:UniqueID": ["451"]}), b"", "451"),
        (0, plistlib.dumps({}), b"", None),
        (56, b"", b"DS Error: -14136 (eDSRecordNotFound)", None),
    ],
)
def test_directory_reader_distinguishes_missing_records_and_attributes(
    monkeypatch, code, out, err, expected
):
    monkeypatch.setattr(
        provision.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=code, stdout=out, stderr=err),
    )
    assert provision.directory_value("/Users/_accountaccess", "UniqueID") == expected


def test_directory_service_failure_is_not_treated_as_an_absent_account(monkeypatch):
    monkeypatch.setattr(
        provision.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout=b"", stderr=b"service unavailable"),
    )
    with pytest.raises(provision.ProvisionError, match="directory_services_unavailable"):
        provision.directory_value("/Users/_accountaccess", "UniqueID")


def test_directory_reader_uses_structured_values_for_long_native_fields(monkeypatch):
    home = "/Library/Application Support/" + "Long path " * 15 + "/home"
    calls = []

    def run(arguments, **kwargs):
        calls.append(arguments)
        return SimpleNamespace(
            returncode=0,
            stdout=plistlib.dumps({"dsAttrTypeNative:NFSHomeDirectory": [home]}),
            stderr=b"",
        )

    monkeypatch.setattr(provision.subprocess, "run", run)
    assert provision.directory_value("/Users/_accountaccess", "NFSHomeDirectory") == home
    assert calls[0][:4] == ["/usr/bin/dscl", "-plist", ".", "-read"]


@pytest.mark.parametrize(
    "value",
    [
        b"human-readable output",
        plistlib.dumps({"wrong": ["451"]}),
        plistlib.dumps({"dsAttrTypeStandard:UniqueID": ["451", "452"]}),
    ],
)
def test_directory_reader_refuses_malformed_or_ambiguous_values(monkeypatch, value):
    monkeypatch.setattr(
        provision.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=value, stderr=b""),
    )
    with pytest.raises(provision.ProvisionError):
        provision.directory_value("/Users/_accountaccess", "UniqueID")


def identity_fixture(monkeypatch, actual, records):
    calls = []
    monkeypatch.setattr(
        provision, "directory_value", lambda record, field: records.get(record, {}).get(field)
    )

    def absent(_):
        raise KeyError()

    monkeypatch.setattr(provision.pwd, "getpwuid", absent)
    monkeypatch.setattr(provision.grp, "getgrgid", absent)

    def run(arguments):
        calls.append(arguments)
        if arguments[0] == "/usr/bin/dscl":
            target = arguments[3]
            records.setdefault(target, {})
            if len(arguments) > 4:
                records[target][arguments[4]] = arguments[5]
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(provision, "command", run)
    monkeypatch.setattr(
        provision.pwd,
        "getpwnam",
        lambda _: SimpleNamespace(
            pw_name=actual.broker_name,
            pw_uid=451,
            pw_gid=451,
            pw_dir=str(actual.base / "home"),
            pw_shell="/usr/bin/false",
        ),
    )
    monkeypatch.setattr(
        provision.grp,
        "getgrnam",
        lambda _: SimpleNamespace(gr_name=actual.broker_name, gr_gid=451, gr_mem=[]),
    )
    monkeypatch.setattr(provision.grp, "getgrall", lambda: [])
    return calls


def test_interrupted_identity_creation_completes_only_missing_fields(tmp_path, monkeypatch):
    actual = layout(tmp_path)
    records = {
        "/Groups/" + actual.broker_name: {"PrimaryGroupID": "451"},
        "/Users/" + actual.broker_name: {"UniqueID": "451"},
    }
    calls = identity_fixture(monkeypatch, actual, records)
    provision.identity_record(actual, 451)
    changes = [call[4] for call in calls if call[0] == "/usr/bin/dscl" and len(call) > 4]
    assert "UniqueID" not in changes and "PrimaryGroupID" in changes
    assert records["/Users/" + actual.broker_name]["UserShell"] == "/usr/bin/false"
    assert records["/Users/" + actual.broker_name]["Password"] == "*"


def test_conflicting_identity_is_never_rewritten(tmp_path, monkeypatch):
    actual = layout(tmp_path)
    records = {"/Users/" + actual.broker_name: {"NFSHomeDirectory": "/unrelated/home"}}
    calls = identity_fixture(monkeypatch, actual, records)
    with pytest.raises(provision.ProvisionError, match="service_identity_conflict"):
        provision.identity_record(actual, 451)
    assert (
        calls == []
        and records["/Users/" + actual.broker_name]["NFSHomeDirectory"] == "/unrelated/home"
    )


def test_reallocated_uid_is_refused_before_creating_records(tmp_path, monkeypatch):
    actual = layout(tmp_path)
    calls = identity_fixture(monkeypatch, actual, {})
    monkeypatch.setattr(
        provision.pwd, "getpwuid", lambda _: SimpleNamespace(pw_name="another-service")
    )
    with pytest.raises(provision.ProvisionError, match="service_identity_conflict"):
        provision.identity_record(actual, 451)
    assert calls == []


def activation_fixture(tmp_path, monkeypatch, *, running=False):
    actual = layout(tmp_path)
    source = actual.base / "broker/service.plist"
    source.parent.mkdir(parents=True)
    source.write_bytes(plistlib.dumps({"Label": actual.label, "RunAtLoad": True}))
    source.chmod(0o644)
    prepared = {"status": "PREPARED", "broker_uid": 451, "owner_uid": 501}
    calls = []
    monkeypatch.setattr(provision, "prepare", lambda target, owner: dict(prepared))
    monkeypatch.setattr(provision, "root_managed_path", lambda path: Path(path))

    def directory(path, mode=0o755):
        path.mkdir(mode=mode, exist_ok=True)
        return path

    monkeypatch.setattr(provision, "root_directory", directory)
    monkeypatch.setattr(
        provision.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0 if running else 1)
    )
    monkeypatch.setattr(provision, "command", lambda arguments: calls.append(arguments))
    return actual, source, calls


def test_activation_persists_only_the_prepared_job_and_bootstraps_once(tmp_path, monkeypatch):
    actual, source, calls = activation_fixture(tmp_path, monkeypatch)
    result = provision.activate(actual, 501)
    destination = actual.base / "launchdaemons" / (actual.label + ".plist")
    assert result == {"status": "REGISTERED", "broker_uid": 451, "owner_uid": 501}
    assert destination.read_bytes() == source.read_bytes()
    assert destination.stat().st_nlink == 1 and destination.stat().st_mode & 0o777 == 0o644
    assert calls == [
        ["/bin/launchctl", "bootstrap", "system", str(destination)],
        ["/bin/launchctl", "print", "system/" + actual.label],
    ]


def test_activation_preserves_an_existing_registration(tmp_path, monkeypatch):
    actual, _, calls = activation_fixture(tmp_path, monkeypatch, running=True)
    provision.activate(actual, 501)
    provision.activate(actual, 501)
    assert calls == [["/bin/launchctl", "print", "system/" + actual.label]] * 2


def test_activation_refuses_conflicting_persistent_job_before_launchctl(tmp_path, monkeypatch):
    actual, _, calls = activation_fixture(tmp_path, monkeypatch)
    destination = actual.base / "launchdaemons" / (actual.label + ".plist")
    destination.parent.mkdir()
    destination.write_bytes(b"preserve unknown job")
    destination.chmod(0o644)
    with pytest.raises(provision.ProvisionError, match="existing_installation_requires_repair"):
        provision.activate(actual, 501)
    assert destination.read_bytes() == b"preserve unknown job" and not calls


def test_fresh_identity_sets_preflight_missing_fields_despite_record_defaults(
    tmp_path, monkeypatch
):
    actual = layout(tmp_path)
    records = {}
    calls = identity_fixture(monkeypatch, actual, records)
    original = provision.command

    def create(arguments):
        result = original(arguments)
        if (
            arguments[0] == "/usr/bin/dscl"
            and len(arguments) == 4
            and arguments[3].startswith("/Users/")
        ):
            records[arguments[3]].update(
                {"Password": "default-placeholder", "NFSHomeDirectory": "/var/empty"}
            )
        return result

    monkeypatch.setattr(provision, "command", create)
    provision.identity_record(actual, 451)
    assert records["/Users/" + actual.broker_name]["Password"] == "*"
    assert records["/Users/" + actual.broker_name]["NFSHomeDirectory"] == str(actual.base / "home")
    assert any(call[-2:] == ["Password", "*"] for call in calls)


@pytest.mark.parametrize("remaining", [None, "unexpected-record"])
def test_ci_identity_cleanup_checks_authoritative_records_not_cached_passwd(
    tmp_path, monkeypatch, remaining
):
    from dataclasses import replace

    actual = replace(
        layout(tmp_path),
        base=Path("/Library/PrivilegedHelperTools/account-access-worker-qa-inert/provisioned"),
    )
    monkeypatch.setattr(provision.sys, "platform", "darwin")
    monkeypatch.setattr(provision.os, "getuid", lambda: 0)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(provision, "root_json", lambda _: {"broker_uid": 451, "owner_uid": 501})
    cached = SimpleNamespace(
        pw_uid=451, pw_dir=str(actual.base / "home"), pw_shell="/usr/bin/false"
    )
    monkeypatch.setattr(provision.pwd, "getpwnam", lambda _: cached)
    calls = []

    def command(arguments):
        calls.append(arguments)
        return SimpleNamespace(stdout=b"501\n", stderr=b"")

    monkeypatch.setattr(provision, "command", command)
    monkeypatch.setattr(provision, "directory_value", lambda *a: remaining)
    if remaining:
        with pytest.raises(provision.ProvisionError, match="service_identity_conflict"):
            provision.remove_ci_identity(actual)
    else:
        provision.remove_ci_identity(actual)
    assert ["/usr/bin/dscl", ".", "-delete", "/Users/" + actual.broker_name] in calls
    assert ["/usr/bin/dscl", ".", "-delete", "/Groups/" + actual.broker_name] in calls
