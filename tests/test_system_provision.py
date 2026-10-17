import json
import os
from pathlib import Path
import plistlib
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


def test_fixed_production_layout_has_no_owner_path_or_command_override():
    actual = provision.Layout.installed()
    assert actual.base == Path("/Library/Application Support/Account Access")
    assert actual.runtime / "bin/python" == actual.base / "runtime/bin/python"
    assert actual.broker_name == "_accountaccess" and actual.fixture is False
    with pytest.raises(provision.ProvisionError, match="disposable_provisioning_required"):
        provision.Layout.ci_fixture(Path("/tmp/forged"), name="_aaq0123456789ab")


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
