"""Fixed native handoff and peer/lease contracts; no owner paths or root calls."""

import json
import os
import stat
from types import SimpleNamespace

import pytest

from account_access import install_image as image
from account_access import install_transaction as transaction
from account_access import system_provision as provision
from test_install_image import Crash, completed, fixture


@pytest.mark.parametrize("event", ["receipt-write", "receipt-synced", "receipt-published"])
def test_verification_receipt_resumes_without_replacing_existing_image(tmp_path, event):
    with fixture(tmp_path) as value:

        def stop(observed):
            if observed == event:
                raise Crash()

        with pytest.raises(Crash):
            with value["engine"](hook=stop) as engine:
                proof = engine.materialize()
                engine.publish_verification(proof)
        inode = value["support"].stat().st_ino
        with value["engine"]() as engine:
            proof = engine.materialize()
            engine.publish_verification(proof)
            engine.mark_complete()
        path = value["support"] / "install-verification.json"
        assert value["support"].stat().st_ino == inode
        assert json.loads(path.read_bytes()) == proof
        assert stat.S_IMODE(path.stat().st_mode) == 0o644 and path.stat().st_nlink == 1
        previous = path.stat().st_ino
        with value["engine"]() as engine:
            engine.publish_verification(engine.materialize())
        assert path.stat().st_ino == previous


def test_conflicting_public_receipt_is_preserved(tmp_path):
    with fixture(tmp_path) as value:
        completed(value)
        path = value["support"] / "install-verification.json"
        path.write_bytes(b"preserve conflicting public receipt")
        before = path.stat().st_ino
        with pytest.raises(image.ImageConflict):
            with value["engine"]() as engine:
                engine.publish_verification(engine.materialize())
        assert (
            path.stat().st_ino == before
            and path.read_bytes() == b"preserve conflicting public receipt"
        )


@pytest.mark.parametrize(
    "fault", [None, "hash", "schema-bool", "team", "identifier", "extra", "duplicate", "hash-bool"]
)
def test_package_identity_is_exact_and_bounded(tmp_path, fault):
    signatures = {
        key: {"team": "ABCDEFGHIJ", "identifier": identifier, "hashes": ["a" * 40]}
        for key, identifier in {
            "owner": "com.fainir.accountaccess",
            "broker": "com.fainir.accountaccess.broker",
            "bootstrap": "com.fainir.accountaccess.bootstrap",
        }.items()
    }
    value = {
        "schema": 1,
        "managed_by": "account-access-package-identity-v1",
        "signatures": signatures,
    }
    if fault == "hash":
        signatures["owner"]["hashes"] = ["wrong"]
    elif fault == "hash-bool":
        signatures["owner"]["hashes"] = [True]
    elif fault == "schema-bool":
        value["schema"] = True
    elif fault == "team":
        signatures["owner"]["team"] = "ZZZZZZZZZZ"
    elif fault == "identifier":
        signatures["owner"]["identifier"] = "unrelated"
    elif fault == "extra":
        signatures["owner"]["secret"] = "not accepted"
    elif fault == "duplicate":
        signatures["owner"]["hashes"] *= 2
    (tmp_path / "package-identity.json").write_text(json.dumps(value))
    fd = os.open(tmp_path, image.DIRECTORY)
    try:
        if fault:
            with pytest.raises(image.ImageConflict, match="invalid_package_identity"):
                transaction._peer_identity(fd, os.getuid())
        else:
            assert transaction._peer_identity(fd, os.getuid()) == signatures
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "real,effective,platform",
    [(501, 501, "darwin"), (501, 0, "darwin"), (0, 501, "darwin"), (0, 0, "linux")],
)
def test_entrypoint_refuses_before_descriptor_or_owner_access(
    monkeypatch, capsys, real, effective, platform
):
    monkeypatch.setattr(
        transaction, "os", SimpleNamespace(getuid=lambda: real, geteuid=lambda: effective)
    )
    monkeypatch.setattr(transaction.sys, "platform", platform)
    monkeypatch.setattr(
        transaction.sys,
        "argv",
        [
            "native-coordinator",
            "--source-fd",
            "3",
            "--manifest-fd",
            "4",
            "--manifest-sha256",
            "a" * 64,
        ],
    )
    monkeypatch.setattr(
        transaction,
        "run",
        lambda *a: pytest.fail("No descriptor or owner operation before root context"),
    )
    assert transaction.main() == 78
    assert json.loads(capsys.readouterr().out) == {
        "status": "FAILED",
        "reason": "system_install_not_completed",
    }


@pytest.mark.parametrize("fault", ["path-override", "negative-fd", "bool-fd", "digest", "extra"])
def test_entrypoint_refuses_unsupported_arguments_before_dispatch(monkeypatch, capsys, fault):
    args = [
        "native-coordinator",
        "--source-fd",
        "3",
        "--manifest-fd",
        "4",
        "--manifest-sha256",
        "a" * 64,
    ]
    if fault == "path-override":
        args[1] = "--source-path"
    elif fault == "negative-fd":
        args[2] = "-1"
    elif fault == "bool-fd":
        args[2] = "True"
    elif fault == "digest":
        args[6] = "unrelated"
    else:
        args += ["--fixture"]
    monkeypatch.setattr(transaction, "os", SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0))
    monkeypatch.setattr(transaction.sys, "platform", "darwin")
    monkeypatch.setattr(transaction.sys, "argv", args)
    monkeypatch.setattr(
        transaction, "run", lambda *a: pytest.fail("Arguments must be fixed before dispatch")
    )
    assert transaction.main() == 78
    assert "system_install_not_completed" in capsys.readouterr().out


def test_root_command_lease_is_narrow_and_does_not_survive_its_context(monkeypatch):
    calls = []
    info = SimpleNamespace(st_uid=0, st_nlink=1, st_mode=stat.S_IFREG | 0o600)
    monkeypatch.setattr(
        provision, "os", SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0, fstat=lambda fd: info)
    )

    def run(args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(provision.subprocess, "run", run)
    with provision.command_lease(7):
        provision.command(["/fixed/root-command"])
    provision.command(["/fixed/ordinary-app-launch"])
    assert calls[0]["pass_fds"] == (7,) and calls[0]["close_fds"] is True
    assert "pass_fds" not in calls[1] and calls[1]["close_fds"] is True
    assert calls[0]["env"] == {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}


@pytest.mark.parametrize("fd", [True, -1, 0, 1, 2])
def test_invalid_command_lease_refused_before_any_descriptor_read(monkeypatch, fd):
    monkeypatch.setattr(
        provision, "os", SimpleNamespace(fstat=lambda fd: pytest.fail("No invalid descriptor read"))
    )
    with pytest.raises(provision.ProvisionError, match="invalid_install_lease"):
        with provision.command_lease(fd):
            pytest.fail("No invalid lease context")


def test_no_completion_record_without_verified_materialization(tmp_path):
    with fixture(tmp_path) as value:
        with value["engine"]() as engine:
            with pytest.raises(image.ImageConflict, match="invalid_install_phase"):
                engine.mark_complete()
        assert not (value["journal"] / "complete.json").exists()


@pytest.mark.parametrize("peer", ["owner", "broker", "bootstrap"])
def test_changed_valid_peer_is_refused_before_provisioning_writes(tmp_path, monkeypatch, peer):
    from test_system_provision import layout, signatures

    expected, observed = signatures(), signatures()
    observed[peer]["hashes"] = ["b" * 40]
    monkeypatch.setattr(provision.sys, "platform", "darwin")
    monkeypatch.setattr(provision, "os", SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0))
    monkeypatch.setattr(
        provision.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="synthetic-owner")
    )
    monkeypatch.setattr(provision, "payload", lambda layout: observed)
    monkeypatch.setattr(
        provision,
        "root_directory",
        lambda *args: pytest.fail("No provisioning writes for changed peer"),
    )
    with pytest.raises(provision.ProvisionError, match="payload_identity_changed"):
        provision.prepare(layout(tmp_path), 501, expected_signatures=expected)
    assert not list(tmp_path.iterdir())
