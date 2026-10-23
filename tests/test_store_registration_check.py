"""Fictional registration metadata only; never inspect an installed store."""

import copy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from macos import store_registration_check as c

VAULT = "12345678-1234-4234-8234-123456789abc"
ENROLLMENT = "12345678-1234-4234-8234-123456789def"


def policies():
    enrollment = {
        "managed_by": "account-access-worker-enrollment-v1",
        "schema": 1,
        "worker_launcher": c.BASE + "/broker/worker-launch.json",
        "stage_policy": c.BASE + "/broker/stage.json",
        "vault_id": VAULT,
        "enrollment_id": ENROLLMENT,
    }
    worker = {
        "managed_by": "account-access-worker-v1",
        "schema": 1,
        "broker_uid": 450,
        "agent_uid": 501,
        "root": c.BASE + "/vault/data",
        "agent_socket": c.BASE + "/run/agent.sock",
        "owner_socket": c.BASE + "/control/owner.sock",
        "owner_port": 8765,
    }
    launcher = {
        "managed_by": "account-access-mac-worker-v1",
        "schema": 1,
        "python": c.BASE + "/runtime/bin/python",
        "runtime": c.BASE + "/runtime",
        "worker_policy": c.BASE + "/broker/worker.json",
        "broker_gid": 450,
        "broker_home": c.BASE + "/home",
        "browsers": c.BASE + "/browsers",
        "fixture": False,
        "fixture_ca": None,
    }
    return [enrollment, worker, launcher]


def record():
    return {
        "schema": 1,
        "vault": VAULT,
        "enrollment": ENROLLMENT,
        "stage": ".enrollment-" + ENROLLMENT,
        "destination": "data",
        "uid": 450,
        "gid": 450,
        "stagedIdentity": {"device": 10, "inode": 101},
        "emptyIdentity": {"device": 10, "inode": 102},
    }


def test_exact_fixed_program_policy_and_registration():
    vault, enrollment_id, broker, owner = c.policy(*policies())
    assert (vault, enrollment_id, broker, owner) == (VAULT, ENROLLMENT, 450, 501)
    assert c.registration(record(), vault=vault, enrollment_id=enrollment_id, broker=broker) == [
        (10, 101),
        (10, 102),
    ]


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "schema", True),
        (0, "stage_policy", "/private/secret"),
        (0, "worker_launcher", "/tmp/override"),
        (0, "vault_id", "../escape"),
        (0, "enrollment_id", ENROLLMENT.upper()),
        (1, "root", "/private/secret"),
        (1, "broker_uid", 0),
        (1, "broker_uid", 501),
        (1, "agent_uid", 450),
        (1, "owner_port", True),
        (1, "agent_socket", "/tmp/socket"),
        (2, "schema", True),
        (2, "fixture", 0),
        (2, "fixture", True),
        (2, "broker_gid", True),
        (2, "python", "/usr/bin/python3"),
        (2, "fixture_ca", "/tmp/ca"),
        (2, "extra", "private"),
    ],
)
def test_policy_cannot_choose_other_data_or_runtime(index, key, value):
    values = policies()
    values[index][key] = value
    with pytest.raises((c.Refused, ValueError)):
        c.policy(*values)


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema", True),
        ("uid", True),
        ("gid", 501),
        ("destination", "../data"),
        ("vault", ENROLLMENT),
        ("enrollment", VAULT),
        ("stage", "data"),
        ("extra", "private"),
        ("stagedIdentity", {"device": True, "inode": 101}),
        ("stagedIdentity", {"device": 10, "inode": 0}),
        ("stagedIdentity", {"device": 11, "inode": 101}),
        ("stagedIdentity", {"device": 10, "inode": 102}),
        ("stagedIdentity", {"device": 10, "inode": 101, "extra": "private"}),
    ],
)
def test_record_cannot_change_binding_or_metadata(key, value):
    item = record()
    item[key] = value
    with pytest.raises(c.Refused):
        c.registration(item, vault=VAULT, enrollment_id=ENROLLMENT, broker=450)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":1,"\\u0061":2}',
        b'{"nested":{"a":1,"a":2}}',
        b"[]",
        b"null",
        b'{"a":NaN}',
        b"x" * 4097,
    ],
)
def test_ambiguous_or_oversized_metadata_refused(raw):
    with pytest.raises((c.Refused, ValueError)):
        c.object(raw)


@pytest.mark.parametrize(
    "observed,ready,expected",
    [
        ([(10, 101), (10, 102)], False, "registration_not_published"),
        ([(10, 102), (10, 101)], True, "registration_matches"),
        ([(11, 101), (11, 102)], False, "device_number_changed"),
        ([(11, 102), (11, 101)], True, "device_number_changed"),
        ([(10, 102), (11, 101)], True, "directory_identity_mismatch"),
        ([(11, 102), (11, 999)], True, "directory_identity_mismatch"),
        ([(10, 101), (10, 101)], True, "directory_identity_mismatch"),
    ],
)
def test_closed_classification_never_accepts_device_only_change(observed, ready, expected):
    assert c.classify([(10, 101), (10, 102)], observed, ready=ready) == expected


def test_swapped_directory_requires_ready_marker():
    with pytest.raises(c.Refused):
        c.classify([(10, 101), (10, 102)], [(10, 102), (10, 101)], ready=False)


@pytest.fixture
def metadata(tmp_path, monkeypatch):
    support = tmp_path / "support"
    support.mkdir(mode=0o755)
    broker = support / "broker"
    broker.mkdir(mode=0o700)
    vault = support / "vault"
    vault.mkdir(mode=0o755)
    stage = vault / (".enrollment-" + ENROLLMENT)
    stage.mkdir(mode=0o700)
    data = vault / "data"
    data.mkdir(mode=0o700)
    journal = vault / (".enrollment-" + ENROLLMENT + ".publication")
    journal.mkdir(mode=0o700)

    def write(path, value, mode=0o600):
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        path.chmod(mode)

    for name, value in zip(["enrollment.json", "worker.json", "worker-launch.json"], policies()):
        write(broker / name, value, 0o644)
    write(vault / ".account-access-enrollment.lock", b"")
    value = record()
    value["stagedIdentity"] = {"device": data.stat().st_dev, "inode": data.stat().st_ino}
    value["emptyIdentity"] = {"device": stage.stat().st_dev, "inode": stage.stat().st_ino}
    write(journal / "plan.json", value)
    write(journal / "authorized", {"schema": 1, "owner_uid": 501})
    write(journal / "ready", b"account-access-publication-ready-v1\n")
    write(data / "state.db", b"fictional encrypted material must not be read")
    write(data / "config.json", b"fictional account data must not be read")
    real_check, real_stat, real_open = c.check, os.stat, os.open
    monkeypatch.setattr(
        c, "no_acl", lambda fd: None
    )  # Cross-platform fixture; production retains the native check.
    monkeypatch.setattr(c, "check", lambda fd, **kw: real_check(fd, **{**kw, "owner": os.getuid()}))
    vault_inode = vault.stat().st_ino

    def fixture_stat(path, **kw):
        value = real_stat(path, **kw)
        if path in {"data", ".enrollment-" + ENROLLMENT} and kw.get("dir_fd") is not None:
            assert os.fstat(kw["dir_fd"]).st_ino == vault_inode
            attrs = {
                name: getattr(value, name)
                for name in [
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_uid",
                    "st_gid",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                ]
            }
            attrs.update(st_uid=450, st_gid=450)
            return SimpleNamespace(**attrs)
        return value

    opened = []

    def fixture_open(path, flags, *args, **kw):
        if kw.get("dir_fd") is not None:
            assert path not in {"data", ".enrollment-" + ENROLLMENT, "state.db", "config.json"}
            assert flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC) == 0
            opened.append(path)
        return real_open(path, flags, *args, **kw)

    monkeypatch.setattr(c.os, "stat", fixture_stat)
    monkeypatch.setattr(c.os, "open", fixture_open)
    monkeypatch.setattr(
        c.os, "listdir", lambda *a: pytest.fail("Directory enumeration is forbidden")
    )
    fd = real_open(support, c.DIRECTORY)
    yield SimpleNamespace(
        fd=fd, journal=journal, vault=vault, record=value, write=write, opened=opened
    )
    os.close(fd)


def test_real_file_reader_never_opens_or_enumerates_private_store(metadata):
    assert c.inspect(metadata.fd) == "registration_matches"
    assert set(metadata.opened) == {
        "broker",
        "enrollment.json",
        "worker.json",
        "worker-launch.json",
        "vault",
        ".account-access-enrollment.lock",
        ".enrollment-" + ENROLLMENT + ".publication",
        "plan.json",
        "authorized",
        "ready",
    }


def test_reader_reports_device_change_without_writing_registration(metadata):
    item = copy.deepcopy(metadata.record)
    for name in ["stagedIdentity", "emptyIdentity"]:
        item[name]["device"] += 1
    metadata.write(metadata.journal / "plan.json", item)
    before = (metadata.journal / "plan.json").read_bytes()
    assert c.inspect(metadata.fd) == "device_number_changed"
    assert (metadata.journal / "plan.json").read_bytes() == before


def test_reader_preserves_owner_pause(metadata):
    metadata.write(metadata.journal / "paused", b"paused\n")
    assert c.inspect(metadata.fd) == "registration_paused"
    assert (metadata.journal / "paused").read_bytes() == b"paused\n"


def test_reader_cannot_interfere_with_active_enrollment(metadata):
    lock = os.open(metadata.vault / ".account-access-enrollment.lock", os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(c.Refused, match="registration_busy"):
            c.inspect(metadata.fd)
    finally:
        os.close(lock)


@pytest.mark.parametrize("change", ["symlink", "hardlink", "writable", "directory"])
def test_registration_file_substitution_is_refused(metadata, change):
    plan = metadata.journal / "plan.json"
    if change == "symlink":
        plan.rename(metadata.journal / "retained.json")
        plan.symlink_to(metadata.journal / "retained.json")
    elif change == "hardlink":
        os.link(plan, metadata.journal / "retained.json")
    elif change == "writable":
        plan.chmod(0o666)
    else:
        plan.unlink()
        plan.mkdir(mode=0o700)
    with pytest.raises((c.Refused, OSError)):
        c.inspect(metadata.fd)


def test_ordinary_entrypoint_refuses_before_installed_lookup(monkeypatch, capsys):
    monkeypatch.setattr(c, "open_support", lambda: pytest.fail("Installed path was touched"))
    assert c.main() == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "installer_context_required"


@pytest.mark.parametrize("flags", [[], ["-I"], ["-I", "-B"], ["-I", "-B", "-S"]])
def test_cli_refuses_ordinary_process_without_private_output(flags):
    p = subprocess.run(
        [sys.executable, *flags, str(Path(c.__file__).resolve())], capture_output=True, timeout=10
    )
    assert p.returncode == 1 and not p.stderr
    assert json.loads(p.stdout) == {
        "schema": 1,
        "status": "REFUSED",
        "reason": "installer_context_required",
    }
