"""Unprivileged public-image recovery, including real process death and locks."""

from contextlib import contextmanager
import hashlib
import json
import multiprocessing
import os
import shutil
import signal

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
        base / "source" / package_manifest.OWNER_APP,
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
    app = source / package_manifest.OWNER_APP
    (support / "bin").mkdir(parents=True)
    (app / "Contents").mkdir(parents=True)
    (support / "bin/tool").write_bytes(b"public fixture\n" * 80000)
    (support / "bin/tool").chmod(0o755)
    (support / "data").write_bytes(b"public data")
    (support / "current").symlink_to("bin")
    (app / "Contents/resource").write_bytes(b"public app fixture")
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
    fds = [
        os.open(path, image.DIRECTORY) for path in [support, app, journal, library, applications]
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
        "directories": 4,
        "aliases": 1,
    }
    assert (value["support"] / "data").read_bytes() == b"public data"
    assert os.readlink(value["support"] / "current") == "bin"
    assert not (value["journal"] / "support").exists()
    assert not (value["journal"] / "application").exists()
    assert not list((value["journal"] / "temporary").iterdir())
    return result


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
                shutil.copytree(value["source"] / package_manifest.OWNER_APP, value["app"])

        with pytest.raises(image.ImageConflict, match="image_namespace_changed"):
            with value["engine"](hook=replace) as engine:
                engine.materialize()
        assert moved.is_dir() and value["app"].is_dir()
        with pytest.raises(image.ImageConflict, match="image_namespace_changed"):
            completed(value)


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
