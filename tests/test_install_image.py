"""Unprivileged public-image recovery, including real process death and locks."""

from contextlib import contextmanager
import hashlib
import errno
import json
import multiprocessing
import os
import shutil
import signal
from types import SimpleNamespace

import pytest

from account_access import install_image as image
from account_access import package_manifest


class Crash(BaseException):
    pass


def image_process(base, encoded, event):
    """Open only synthetic fixture handles in a fresh child interpreter.

    Forking the threaded test runner is unsafe on macOS. Reopening these
    directories also ensures that the contender inherits no installer lease.
    """
    paths = [
        base / "source" / package_manifest.SUPPORT,
        base / "source" / package_manifest.OWNER_APP.parent,
        base / "journal",
        base / "library",
        base / "applications",
    ]
    descriptors = []
    try:
        for path in paths:
            descriptors.append(os.open(path, image.DIRECTORY))

        def checkpoint(observed):
            if observed == event:
                os.kill(os.getpid(), signal.SIGKILL)

        engine = image.ImageRecovery(
            {image.SUPPORT: descriptors[0], image.APPLICATION: descriptors[1]},
            descriptors[2],
            {
                image.SUPPORT: (descriptors[3], "Account Access"),
                image.APPLICATION: (descriptors[4], "Account Access.app"),
            },
            image.ImageManifest(encoded, hashlib.sha256(encoded).hexdigest()),
            501,
            object_uid=os.getuid(),
            checkpoint=checkpoint,
        )
        if event is None:
            try:
                with engine:
                    raise AssertionError("Another process acquired the held lease")
            except BlockingIOError:
                return
        with engine:
            engine.materialize()
            engine.mark_complete()
        raise AssertionError("The requested SIGKILL checkpoint was not reached")
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


@contextmanager
def fixture(base, checkpoint=None, owner=501, readonly=False):
    source = base / "source"
    support = source / package_manifest.SUPPORT
    app = source / package_manifest.CANONICAL_APP
    (support / "bin").mkdir(parents=True)
    (app / "Contents/MacOS").mkdir(parents=True)
    public = source / package_manifest.OWNER_APP
    public.parent.mkdir()
    public.symlink_to(package_manifest.APPLICATION_TARGET)
    (support / "bin/tool").write_bytes(b"public fixture\n" * 80000)
    (support / "bin/tool").chmod(0o755)
    (support / "data").write_bytes(b"public data")
    (support / "current").symlink_to("bin")
    (app / "Contents/MacOS/AccountAccess").write_bytes(b"public app fixture")
    for path in [source, *source.rglob("*")]:
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & 0o777 & ~0o022)
    if readonly:
        (support / "data").chmod(0o444)
    encoded = package_manifest.build(source, "0.8.0", "arm64")
    manifest = image.ImageManifest(encoded, hashlib.sha256(encoded).hexdigest())
    journal = base / "journal"
    journal.mkdir(mode=0o700)
    library, applications = base / "library", base / "applications"
    library.mkdir()
    applications.mkdir(mode=0o775)
    applications.chmod(0o775)
    fds = [
        os.open(path, image.DIRECTORY) for path in [support, public.parent, journal, library, applications]
    ]

    def engine(hook=checkpoint, owner_uid=owner):
        return image.ImageRecovery(
            {image.SUPPORT: fds[0], image.APPLICATION: fds[1]},
            fds[2],
            {
                image.SUPPORT: (fds[3], "Account Access"),
                image.APPLICATION: (fds[4], "Account Access.app"),
            },
            manifest,
            owner_uid,
            object_uid=os.getuid(),
            checkpoint=hook,
        )

    try:
        yield {
            "engine": engine,
            "journal": journal,
            "manifest": manifest,
            "source": source,
            "support": library / "Account Access",
            "app": applications / "Account Access.app",
            "encoded": encoded,
        }
    finally:
        for fd in fds:
            os.close(fd)


def completed(value):
    with value["engine"]() as engine:
        result = engine.materialize()
        engine.mark_complete()
    assert result == {
        "schema": 1,
        "status": "VERIFIED",
        "manifest_sha256": value["manifest"].digest,
        "files": 3,
        "directories": 5,
        "aliases": 2,
    }
    assert (value["support"] / "data").read_bytes() == b"public data"
    assert os.readlink(value["support"] / "current") == "bin"
    assert value["app"].is_symlink()
    assert os.readlink(value["app"]) == package_manifest.APPLICATION_TARGET
    assert (value["support"] / "owner.app/Contents/MacOS/AccountAccess").read_bytes() == b"public app fixture"
    assert not (value["journal"] / "support").exists()
    assert not (value["journal"] / "application").exists()
    assert not (value["journal"] / "application").is_symlink()
    assert not list((value["journal"] / "temporary").iterdir())
    return result


def public_tree_snapshot(root):
    """Only synthetic public fixtures: preserve bytes and namespace identity."""
    result = {}
    for path in [root, *root.rglob("*")]:
        info = path.lstat()
        result[str(path.relative_to(root))] = (
            info.st_ino, info.st_mode, info.st_nlink,
            os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None,
        )
    return result


def test_space_estimate_covers_both_simultaneous_images_and_metadata(tmp_path):
    with fixture(tmp_path) as value:
        manifest = value["manifest"]
        actual_bytes = sum(node["size"] for tree in manifest.trees.values()
                           for node in tree.values() if node["kind"] == "file")
        entries = sum(map(len, manifest.trees.values()))
        first = manifest.required_space()
        both = manifest.required_space(copies=2)
        assert first >= actual_bytes + entries * 4096 + image.INSTALL_SPACE_RESERVE
        assert both >= 2 * actual_bytes + 2 * entries * 4096 + image.INSTALL_SPACE_RESERVE
        assert both - image.INSTALL_SPACE_RESERVE == 2 * (first - image.INSTALL_SPACE_RESERVE)


@pytest.mark.parametrize("blocks_below", [0, 1])
def test_capacity_boundary_uses_pinned_journal_and_refuses_before_image_writes(tmp_path, monkeypatch, blocks_below):
    with fixture(tmp_path) as value:
        blocks = value["manifest"].required_space() // 4096 - blocks_below
        checked = []

        def capacity(fd):
            checked.append(os.fstat(fd).st_ino)
            return SimpleNamespace(f_bavail=blocks, f_frsize=4096)

        monkeypatch.setattr(image.os, "fstatvfs", capacity)
        with value["engine"]() as engine:
            before = public_tree_snapshot(tmp_path)
            if blocks_below:
                with pytest.raises(image.ImageConflict, match="^insufficient_install_space$"):
                    engine.materialize()
                assert public_tree_snapshot(tmp_path) == before
                assert set(p.name for p in value["journal"].iterdir()) == {"lock"}
                assert not value["support"].exists() and not value["app"].is_symlink()
            else:
                engine.materialize()
                engine.mark_complete()
        assert checked == [value["journal"].stat().st_ino]
        if not blocks_below:
            # An already complete image allocates no second runtime, even if
            # the volume fills after installation.
            monkeypatch.setattr(image.os, "fstatvfs", lambda _: pytest.fail("No copy capacity needed for completed image"))
            completed(value)


@pytest.mark.parametrize("event", ["record-open:intent.json", "file-write:bin/tool"])
def test_low_space_retry_preserves_interrupted_records_and_bytes(tmp_path, monkeypatch, event):
    with fixture(tmp_path) as value:
        enough = value["manifest"].required_space() // 4096
        monkeypatch.setattr(image.os, "fstatvfs", lambda _: SimpleNamespace(f_bavail=enough, f_frsize=4096))

        def stop(observed):
            if observed == event:
                raise Crash()

        with pytest.raises(Crash):
            with value["engine"](hook=stop) as engine:
                engine.materialize()
        before = public_tree_snapshot(tmp_path)
        monkeypatch.setattr(image.os, "fstatvfs", lambda _: SimpleNamespace(f_bavail=0, f_frsize=4096))
        with pytest.raises(image.ImageConflict, match="^insufficient_install_space$"):
            with value["engine"]() as engine:
                engine.materialize()
        assert public_tree_snapshot(tmp_path) == before
        monkeypatch.setattr(image.os, "fstatvfs", lambda _: SimpleNamespace(f_bavail=enough, f_frsize=4096))
        completed(value)


def test_enospc_after_preflight_preserves_partial_bytes_for_safe_retry(tmp_path, monkeypatch):
    with fixture(tmp_path) as value:
        write, interrupted = os.write, False

        def disk_filled(fd, data):
            nonlocal interrupted
            if len(data) > 8192:
                if interrupted:
                    raise OSError(errno.ENOSPC, "synthetic local path")
                interrupted = True
                return write(fd, data[:4096])
            return write(fd, data)

        monkeypatch.setattr(image.os, "write", disk_filled)
        with pytest.raises(OSError) as error:
            with value["engine"]() as engine:
                engine.materialize()
        assert error.value.errno == errno.ENOSPC and interrupted
        assert not (value["journal"] / "complete.json").exists()
        temporary = list((value["journal"] / "temporary").iterdir())
        source = value["source"] / package_manifest.SUPPORT / "bin/tool"
        assert len(temporary) == 1 and temporary[0].read_bytes() == source.read_bytes()[:4096]
        assert not value["support"].exists() and not value["app"].is_symlink()
        monkeypatch.setattr(image.os, "write", write)
        completed(value)


def test_capacity_check_refuses_other_target_device_before_any_image_write(tmp_path, monkeypatch):
    with fixture(tmp_path) as value:
        with value["engine"]() as engine:
            before = public_tree_snapshot(tmp_path)
            check = image._check
            other_volume = engine.targets[image.APPLICATION][0]

            def checked(fd, *args, **kwargs):
                result = check(fd, *args, **kwargs)
                return SimpleNamespace(st_dev=result.st_dev + 1) if fd == other_volume else result

            monkeypatch.setattr(image, "_check", checked)
            monkeypatch.setattr(image.os, "fstatvfs", lambda _: pytest.fail("No volume estimate after mismatch"))
            with pytest.raises(image.ImageConflict, match="^installation_volume_mismatch$"):
                engine.materialize()
            assert public_tree_snapshot(tmp_path) == before


@pytest.mark.parametrize("capacity", [
    SimpleNamespace(f_bavail=-1, f_frsize=4096),
    SimpleNamespace(f_bavail=True, f_frsize=4096),
    SimpleNamespace(f_bavail=10**9, f_frsize=0),
    SimpleNamespace(f_bavail=10**9, f_frsize=True),
    SimpleNamespace(f_bavail=10**9, f_frsize=2**30),
    None,
])
def test_unavailable_or_invalid_capacity_never_starts_image_publication(tmp_path, monkeypatch, capacity):
    with fixture(tmp_path) as value:
        def inspect(_):
            if capacity is None:
                raise OSError("synthetic private pathname must not escape")
            return capacity
        monkeypatch.setattr(image.os, "fstatvfs", inspect)
        with value["engine"]() as engine:
            before = public_tree_snapshot(tmp_path)
            with pytest.raises(image.ImageConflict, match="^install_space_check_failed$"):
                engine.materialize()
            assert public_tree_snapshot(tmp_path) == before


def test_complete_repeated_image_recovery_preserves_files_and_identity(tmp_path):
    with fixture(tmp_path) as value:
        result = completed(value)
        before = {
            str(path): (
                path.lstat().st_ino,
                path.lstat().st_mode,
                path.read_bytes() if path.is_file() else None,
            )
            for root in [value["support"], value["app"]]
            for path in [root, *root.rglob("*")]
        }
        assert completed(value) == result
        after = {
            str(path): (
                path.lstat().st_ino,
                path.lstat().st_mode,
                path.read_bytes() if path.is_file() else None,
            )
            for root in [value["support"], value["app"]]
            for path in [root, *root.rglob("*")]
        }
        assert after == before


def test_resume_after_every_mutation_checkpoint(tmp_path):
    events = []
    with fixture(tmp_path / "reference", events.append) as value:
        completed(value)
    assert len(events) > 35
    for index, expected in enumerate(events):
        position = 0

        def crash(event):
            nonlocal position
            position += 1
            if position == index + 1:
                assert event == expected
                raise Crash()

        with fixture(tmp_path / ("crash-" + str(index)), crash) as value:
            with pytest.raises(Crash):
                completed(value)
            value["engine"] = (lambda original: lambda: original(hook=lambda event: None))(
                value["engine"]
            )
            try:
                completed(value)
            except Exception as error:
                raise AssertionError((index, expected)) from error


@pytest.mark.parametrize(
    "event",
    [
        "record-open:intent.json",
        "record-linked:intent.json",
        "file-write:bin/tool",
        "file-synced:bin/tool",
        "root-published:support",
        "root-published:application",
        "record-linked:published.json",
        "record-linked:complete.json",
    ],
)
def test_actual_sigkill_releases_lease_and_resumes_image(tmp_path, event):
    with fixture(tmp_path) as value:
        process = multiprocessing.get_context("spawn").Process(
            target=image_process, args=(tmp_path, value["encoded"], event)
        )
        process.start()
        try:
            process.join(20)
            assert not process.is_alive() and process.exitcode == -signal.SIGKILL
        finally:
            if process.is_alive():
                process.kill()
                process.join(10)
            process.close()
        completed(value)


def test_another_process_cannot_enter_during_the_transaction(tmp_path):
    with fixture(tmp_path) as value:
        with value["engine"]() as engine:
            process = multiprocessing.get_context("spawn").Process(
                target=image_process, args=(tmp_path, value["encoded"], None)
            )
            process.start()
            try:
                process.join(10)
                assert not process.is_alive() and process.exitcode == 0
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(10)
                process.close()
            engine.materialize()
        completed(value)


@pytest.mark.parametrize(
    "damage", ["different-bytes", "extra-file", "alias", "writable", "hardlink"]
)
def test_conflicting_staged_image_is_never_overwritten_or_deleted(tmp_path, damage):
    def stop(event):
        if event == "file-published:bin/tool":
            raise Crash()

    with fixture(tmp_path, stop) as value:
        with pytest.raises(Crash):
            with value["engine"]() as engine:
                engine.materialize()
        path = value["journal"] / "support/bin/tool"
        if damage == "different-bytes":
            path.write_bytes(b"preserve conflicting public fixture")
        elif damage == "extra-file":
            path = value["journal"] / "support/unknown"
            path.write_bytes(b"preserve unknown file")
        elif damage == "alias":
            path.unlink()
            path.symlink_to(tmp_path / "missing")
        elif damage == "writable":
            path.chmod(0o777)
        else:
            os.link(path, tmp_path / "external-link")
        before = (
            path.lstat().st_ino,
            path.lstat().st_mode,
            os.readlink(path) if path.is_symlink() else path.read_bytes(),
        )
        with pytest.raises((image.ImageConflict, OSError)):
            with value["engine"](hook=lambda event: None) as engine:
                engine.materialize()
        assert before == (
            path.lstat().st_ino,
            path.lstat().st_mode,
            os.readlink(path) if path.is_symlink() else path.read_bytes(),
        )


@pytest.mark.parametrize("same_bytes", [False, True])
def test_an_unmanaged_existing_install_is_never_adopted(tmp_path, same_bytes):
    with fixture(tmp_path) as value:
        if same_bytes:
            shutil.copytree(
                value["source"] / package_manifest.SUPPORT, value["support"], symlinks=True
            )
        else:
            value["support"].mkdir()
            (value["support"] / "unknown").write_bytes(b"preserve")
        before = value["support"].stat().st_ino
        with pytest.raises(image.ImageConflict, match="existing_installation_requires_repair"):
            with value["engine"]() as engine:
                engine.materialize()
        assert value["support"].stat().st_ino == before
        assert not (value["journal"] / "intent.json").exists()


@pytest.mark.parametrize(
    "damage",
    ["owner", "inventory", "unknown", "partial-record", "record-link", "phase", "bool-schema"],
)
def test_conflicting_journal_authority_is_preserved(tmp_path, damage):
    with fixture(tmp_path) as value:
        completed(value)
        path = value["journal"] / "intent.json"
        if damage in {"owner", "inventory", "bool-schema"}:
            data = json.loads(path.read_bytes())
            key = {"owner": "owner_uid", "inventory": "manifest_sha256", "bool-schema": "schema"}[
                damage
            ]
            data[key] = {"owner": 502, "inventory": "0" * 64, "bool-schema": True}[damage]
            path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")))
        elif damage == "unknown":
            path = value["journal"] / "unknown"
            path.write_bytes(b"preserve")
        elif damage == "partial-record":
            path = value["journal"] / ".pending-intent.json"
            path.write_bytes(b"preserve unexpected pending record")
            path.chmod(0o600)
        elif damage == "record-link":
            os.link(path, tmp_path / "external-link")
        else:
            path = value["journal"] / "published.json"
            path.write_text("{}")
        before = (path.stat().st_ino, path.read_bytes())
        with pytest.raises((image.ImageConflict, OSError)):
            completed(value)
        assert (path.stat().st_ino, path.read_bytes()) == before


def test_changed_source_is_refused_before_intent_or_publication(tmp_path):
    with fixture(tmp_path) as value:
        (value["source"] / package_manifest.SUPPORT / "data").write_bytes(b"changed")
        with pytest.raises(image.ImageConflict):
            with value["engine"]() as engine:
                engine.materialize()
        assert set(p.name for p in value["journal"].iterdir()) == {"lock"}
        assert not value["support"].exists() and not value["app"].exists()


def test_changed_source_public_alias_is_refused_without_following_it_or_recording_intent(tmp_path):
    with fixture(tmp_path) as value:
        public = value["source"] / package_manifest.OWNER_APP
        public.unlink()
        public.symlink_to("unrelated-missing-destination")
        inode = public.lstat().st_ino
        with pytest.raises(image.ImageConflict, match="image_alias_conflict"):
            with value["engine"]() as engine:
                engine.materialize()
        assert public.lstat().st_ino == inode
        assert set(path.name for path in value["journal"].iterdir()) == {"lock"}
        assert not value["support"].exists() and not value["app"].is_symlink()


def test_resume_after_completed_temporary_became_read_only(tmp_path):
    def stop(event):
        if event == "file-synced:data":
            raise Crash()

    with fixture(tmp_path, readonly=True) as value:
        with pytest.raises(Crash):
            with value["engine"](hook=stop) as engine:
                engine.materialize()
        completed(value)
        assert value["support"].joinpath("data").stat().st_mode & 0o777 == 0o444


def test_private_branches_remain_opaque_and_untouched_after_publication(tmp_path, monkeypatch):
    with fixture(tmp_path) as value:
        completed(value)
        private = value["support"] / "vault"
        private.mkdir(mode=0o700)
        (private / "synthetic-private").write_bytes(b"opaque synthetic fixture; not an account")
        original = os.open

        def opened(path, *args, **kwargs):
            assert "vault" not in str(path) and "synthetic-private" not in str(path)
            return original(path, *args, **kwargs)

        monkeypatch.setattr(os, "open", opened)
        completed(value)
        assert (
            private / "synthetic-private"
        ).read_bytes() == b"opaque synthetic fixture; not an account"


def test_replaced_application_namespace_is_refused_and_both_objects_are_preserved(tmp_path):
    with fixture(tmp_path) as value:
        moved = tmp_path / "moved-original"

        def replace(event):
            if event == "root-published:application":
                value["app"].rename(moved)
                value["app"].symlink_to(package_manifest.APPLICATION_TARGET)

        with pytest.raises(image.ImageConflict, match="image_namespace_changed"):
            with value["engine"](hook=replace) as engine:
                engine.materialize()
        assert moved.is_symlink() and value["app"].is_symlink()
        with pytest.raises(image.ImageConflict, match="image_namespace_changed"):
            completed(value)


def test_shared_application_parent_and_alias_are_never_opened_as_trusted_code(tmp_path, monkeypatch):
    with fixture(tmp_path) as value:
        original = os.open
        parent = value["app"].parent
        before = (parent.stat().st_ino, parent.stat().st_mode)

        def opened(path, *args, **kwargs):
            assert str(path) != "Account Access.app", "Never open or traverse the public alias"
            return original(path, *args, **kwargs)

        monkeypatch.setattr(os, "open", opened)
        completed(value)
        assert (parent.stat().st_ino, parent.stat().st_mode) == before
        assert parent.stat().st_mode & 0o777 == 0o775


@pytest.mark.parametrize("published", [False, True])
def test_same_literal_replacement_alias_cannot_resume_with_a_different_inode(tmp_path, published):
    def stop(event):
        if event == ("root-published:application" if published else "record-published:ready.json"):
            raise Crash()

    with fixture(tmp_path, stop) as value:
        with pytest.raises(Crash):
            with value["engine"]() as engine:
                engine.materialize()
        path = value["app"] if published else value["journal"] / "application"
        moved = tmp_path / "preserved-original-alias"
        path.rename(moved)
        path.symlink_to(package_manifest.APPLICATION_TARGET)
        inode = path.lstat().st_ino
        with pytest.raises(image.ImageConflict, match="image_namespace_changed"):
            with value["engine"](hook=lambda event: None) as engine:
                engine.materialize()
        assert path.lstat().st_ino == inode and moved.is_symlink()


@pytest.mark.parametrize("target", [package_manifest.APPLICATION_TARGET, "unrelated"])
def test_unmanaged_or_racing_public_alias_is_preserved_without_adoption(tmp_path, target):
    with fixture(tmp_path) as value:
        value["app"].symlink_to(target)
        before = value["app"].lstat().st_ino
        with pytest.raises(image.ImageConflict, match="existing_installation_requires_repair"):
            with value["engine"]() as engine:
                engine.materialize()
        assert value["app"].lstat().st_ino == before and os.readlink(value["app"]) == target
        assert not (value["journal"] / "intent.json").exists()


def test_exclusive_public_alias_publication_refuses_a_racing_new_name(tmp_path):
    with fixture(tmp_path) as value:
        def race(event):
            if event == "root-published:support":
                assert (value["support"] / "owner.app/Contents/MacOS/AccountAccess").is_file()
                value["app"].symlink_to("unrelated")

        with pytest.raises((image.ImageConflict, OSError)):
            with value["engine"](hook=race) as engine:
                engine.materialize()
        assert os.readlink(value["app"]) == "unrelated"
        assert (value["journal"] / "application").is_symlink()


@pytest.mark.parametrize("fault", ["target", "absolute", "children", "directory", "canonical-alias"])
def test_manifest_cannot_expand_the_literal_public_alias_exception(tmp_path, fault):
    with fixture(tmp_path) as value:
        data = json.loads(value["encoded"])
        nodes = data["roots"][image.APPLICATION]
        if fault == "target":
            nodes[""]["target"] += "/../owner.app"
        elif fault == "absolute":
            nodes[""]["target"] = image.OWNER_APPLICATION
        elif fault == "children":
            nodes["child"] = {"kind": "directory", "mode": 0o755}
        elif fault == "directory":
            nodes[""] = {"kind": "directory", "mode": 0o755}
        else:
            data["roots"][image.SUPPORT]["owner.app/Contents/MacOS/AccountAccess"] = {
                "kind": "symlink", "target": "../../../bin/tool"}
        encoded = json.dumps(data).encode()
        with pytest.raises(image.ImageConflict, match="invalid_image_inventory"):
            image.ImageManifest(encoded, hashlib.sha256(encoded).hexdigest())


@pytest.mark.parametrize(
    "fault", ["digest", "bool-schema", "outside-name", "unknown-root", "alias-cycle"]
)
def test_invalid_manifest_refused_without_filesystem_changes(tmp_path, fault):
    with fixture(tmp_path) as value:
        data = json.loads(value["encoded"])
        if fault == "bool-schema":
            data["schema"] = True
        elif fault == "unknown-root":
            data["roots"]["/unrelated"] = {}
        elif fault == "outside-name":
            data["roots"][image.SUPPORT]["../outside"] = {
                "kind": "file",
                "mode": 0o644,
                "size": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            }
        elif fault == "alias-cycle":
            data["roots"][image.SUPPORT]["current"]["target"] = "current"
        encoded = json.dumps(data).encode()
        with pytest.raises(image.ImageConflict):
            image.ImageManifest(
                encoded, "0" * 64 if fault == "digest" else hashlib.sha256(encoded).hexdigest()
            )
        assert not list(value["journal"].iterdir())
        assert not value["support"].exists() and not value["app"].exists()
