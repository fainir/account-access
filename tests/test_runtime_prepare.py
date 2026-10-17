import base64
import copy
import csv
import hashlib
import io
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
from types import SimpleNamespace
import zipfile

import pytest

from macos import runtime_prepare as runtime
from test_payload_audit import thin


def wheel(path, *, native=False, record=True):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("package/code.py", "# unchanged source\n")
        if native:
            archive.writestr("package/native.so", thin(8) + b"library")
            archive.writestr("package/node", thin(2) + b"node")
        if record:
            archive.writestr("fixture.dist-info/RECORD", "original fixture record")
            archive.writestr("fixture.dist-info/RECORD.jws", "old signature")
            archive.writestr("fixture.dist-info/RECORD.p7s", "old signature")


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    payload = tmp_path / "private-copy"
    for name in ["python", "browsers", "wheels"]:
        (payload / name).mkdir(parents=True)
    (payload / "python/python").write_bytes(thin(2) + b"python")
    (payload / "browsers/browser").write_bytes(thin(2) + b"browser")
    original = tmp_path / "originals"
    original.mkdir()
    for name, native in [("native.whl", True), ("pure.whl", False), ("project.whl", False)]:
        wheel(original / name, native=native)
        shutil.copyfile(original / name, payload / "wheels" / name)
    requirements = b"".join(
        name.encode()
        + b"==1 --hash=sha256:"
        + runtime.digest(original / (name + ".whl")).encode()
        + b"\n"
        for name in ["native", "pure"]
    )
    project_hash = runtime.digest(original / "project.whl")
    # The transformer is tested on synthetic private copies. Its OS/location
    # guard is verified separately; no platform tool or Keychain is used here.
    monkeypatch.setattr(runtime, "build_stage", lambda path: Path(path).resolve(strict=True))
    plan = runtime.preparation_plan(payload, requirements, "project.whl", project_hash)
    for value in plan["executables"].values():
        if any(path.endswith("/package/node") for path in value["paths"]):
            value["entitlements"] = {"com.apple.security.cs.allow-jit": True}
    return payload, original, requirements, project_hash, plan


def signer(*, team=b"ABCDEFGHIJ", fail=False):
    calls, entitlements = [], []

    def command(arguments):
        calls.append(arguments)
        path = Path(arguments[-1])
        if "--force" in arguments:
            if fail:
                raise subprocess.CalledProcessError(1, arguments)
            metadata = plistlib.loads(
                Path(arguments[arguments.index("--entitlements") + 1]).read_bytes()
            )
            entitlements.append(metadata)
            target = runtime.bundle_main(path)[0] if path.is_dir() else path
            target.write_bytes(target.read_bytes() + b"FIXTURE_SIGNATURE")
        return SimpleNamespace(stdout=b"", stderr=b"TeamIdentifier=" + team + b"\n")

    return command, calls, entitlements


def prepare(
    inputs, command, *, plan=None, development=False, identity="fixture identity", team="ABCDEFGHIJ"
):
    payload, _, requirements, project_hash, original_plan = inputs
    return runtime.prepare(
        payload,
        requirements,
        "project.whl",
        project_hash,
        identity,
        team,
        original_plan if plan is None else plan,
        command,
        development=development,
    )


def test_signing_rebuilds_record_and_derives_exact_artifact_hashes_without_changing_upstream(
    inputs,
):
    payload, original, requirements, project_hash, plan = inputs
    command, calls, entitlements = signer()
    derived, receipt = prepare(inputs, command)
    assert receipt["notarization_verified"] is receipt["installed_runtime_verified"] is False
    assert receipt["native_files_signed"] == 4 and receipt["bundle_seals_signed"] == 0
    assert receipt["original_requirements_sha256"] == hashlib.sha256(requirements).hexdigest()
    native_hash = runtime.digest(payload / "wheels/native.whl")
    original_hash = runtime.digest(original / "native.whl")
    assert native_hash != original_hash and native_hash.encode() in derived
    assert original_hash.encode() not in derived
    assert (payload / "wheels/pure.whl").read_bytes() == (original / "pure.whl").read_bytes()
    assert runtime.digest(payload / "wheels/project.whl") == project_hash
    assert requirements.endswith((runtime.digest(original / "pure.whl") + "\n").encode())
    assert all(set(value) <= runtime.ENTITLEMENTS for value in entitlements)
    assert entitlements.count({"com.apple.security.cs.allow-jit": True}) == 1
    assert sum("--force" in call for call in calls) == 4
    assert sum("--verify" in call for call in calls) == 4
    assert all("--timestamp" in call for call in calls if "--force" in call)
    with zipfile.ZipFile(payload / "wheels/native.whl") as archive:
        assert not any(name.endswith((".jws", ".p7s")) for name in archive.namelist())
        assert archive.read("package/code.py") == b"# unchanged source\n"
        rows = list(csv.reader(io.StringIO(archive.read("fixture.dist-info/RECORD").decode())))
        assert {row[0] for row in rows} == set(archive.namelist())
        for name, checksum, size in rows:
            if name.endswith(".dist-info/RECORD"):
                assert checksum == size == ""
            else:
                data = archive.read(name)
                expected = (
                    base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
                )
                assert checksum == "sha256=" + expected and int(size) == len(data)
    assert receipt["prepared_requirements_sha256"] == hashlib.sha256(derived).hexdigest()
    assert receipt["source_trees"]["python"] == plan["python_sha256"]
    assert receipt["prepared_trees"]["python"] != plan["python_sha256"]


@pytest.mark.parametrize(
    "fault",
    [
        "tree",
        "resource",
        "path",
        "unused",
        "debug",
        "false",
        "extra",
        "schema",
        "unlocked",
        "project",
    ],
)
def test_changed_sources_or_permission_plan_fail_before_any_signing(inputs, fault):
    payload, _, _, _, original_plan = inputs
    plan = copy.deepcopy(original_plan)
    first = next(iter(plan["executables"]))
    if fault == "tree":
        plan["python_sha256"] = "0" * 64
    elif fault == "resource":
        (payload / "python/new.py").write_text("# changed resource")
    elif fault == "path":
        plan["executables"][first]["paths"] = ["unreviewed/runtime"]
    elif fault == "unused":
        plan["executables"]["0" * 64] = {"paths": [], "entitlements": {}}
    elif fault == "debug":
        plan["executables"][first]["entitlements"] = {"com.apple.security.get-task-allow": True}
    elif fault == "false":
        plan["executables"][first]["entitlements"] = {"com.apple.security.cs.allow-jit": False}
    elif fault == "extra":
        plan["extra"] = "ignored input is forbidden"
    elif fault == "schema":
        plan["schema"] = True
    elif fault == "unlocked":
        with (payload / "wheels/native.whl").open("ab") as stream:
            stream.write(b"changed artifact")
    elif fault == "project":
        (payload / "wheels/project.whl").write_bytes(b"changed project")
    before = runtime.tree_digest(payload)
    command, calls, _ = signer()
    with pytest.raises(ValueError):
        prepare(inputs, command, plan=plan)
    assert calls == [] and runtime.tree_digest(payload) == before


@pytest.mark.parametrize(
    "identity,team,development",
    [
        ("-", "ABCDEFGHIJ", False),
        ("", "ABCDEFGHIJ", False),
        ("certificate", "invalid", False),
        ("certificate", "fixture", True),
    ],
)
def test_development_signing_cannot_be_mixed_with_real_publisher_claims(
    inputs, identity, team, development
):
    command, calls, _ = signer()
    with pytest.raises(ValueError, match="matching_runtime_signing_identity_required"):
        prepare(inputs, command, identity=identity, team=team, development=development)
    assert calls == []


def test_development_receipt_uses_only_ad_hoc_identity_without_secure_timestamp_claim(inputs):
    command, calls, _ = signer(team=b"not set")
    _, receipt = prepare(inputs, command, identity="-", team="fixture", development=True)
    assert receipt["development"] is True
    assert all("--timestamp=none" in call for call in calls if "--force" in call)
    assert receipt["notarization_verified"] is receipt["installed_runtime_verified"] is False


def test_mismatched_signature_or_signer_failure_cannot_produce_a_prepared_wheel(inputs):
    payload, original, _, _, _ = inputs
    command, _, _ = signer(team=b"OTHERTEAM1")
    with pytest.raises(ValueError, match="runtime_signing_publisher_mismatch"):
        prepare(inputs, command)
    assert (payload / "wheels/native.whl").read_bytes() == (original / "native.whl").read_bytes()


def test_native_wheel_requires_a_checksum_record_before_signing(inputs):
    payload, _, requirements, project_hash, _ = inputs
    wheel(payload / "wheels/native.whl", native=True, record=False)
    replacement = runtime.digest(payload / "wheels/native.whl").encode()
    requirements = (
        b"native==1 --hash=sha256:"
        + replacement
        + b"\n"
        + requirements.splitlines(keepends=True)[1]
    )
    with pytest.raises(ValueError, match="runtime_wheel_record_required"):
        runtime.preparation_plan(payload, requirements, "project.whl", project_hash)


def test_bundle_seals_are_signed_after_their_code_and_use_reviewed_main_entitlements(inputs):
    payload, _, requirements, project_hash, _ = inputs
    app = payload / "browsers/Nested.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/MacOS/Helper").write_bytes(thin(2) + b"helper")
    (app / "Contents/Info.plist").write_bytes(
        plistlib.dumps(
            {"CFBundleExecutable": "Helper", "CFBundleIdentifier": "com.example.fixture"}
        )
    )
    plan = runtime.preparation_plan(payload, requirements, "project.whl", project_hash)
    command, calls, _ = signer()
    _, receipt = prepare(inputs, command, plan=plan)
    signed = [call for call in calls if "--force" in call]
    assert signed[-1][-1] == str(app.resolve())
    assert signed[-1][signed[-1].index("--identifier") + 1] == "com.example.fixture"
    assert receipt["bundle_seals_signed"] == 1


def test_build_guard_refuses_an_installed_or_source_runtime_before_modification(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(runtime.sys, "platform", "darwin")
    monkeypatch.setattr(runtime.os, "getuid", lambda: 501)
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 501)
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="private_package_build_copy_required"):
        runtime.build_stage(source)
    assert not list(source.iterdir())


@pytest.mark.parametrize("redirect", ["native_hardlink", "wheel_symlink", "wheelhouse_symlink"])
def test_preparation_cannot_modify_an_external_source_through_a_shared_copy(inputs, redirect):
    payload, original, requirements, project_hash, _ = inputs
    target = payload / "wheels/native.whl"
    if redirect == "native_hardlink":
        external = original / "external-native"
        external.write_bytes((payload / "python/python").read_bytes())
        (payload / "python/python").unlink()
        os.link(external, payload / "python/python")
    elif redirect == "wheel_symlink":
        target.unlink()
        target.symlink_to(original / "native.whl")
    else:
        shutil.rmtree(payload / "wheels")
        (payload / "wheels").symlink_to(original, target_is_directory=True)
    before = {path.name: path.read_bytes() for path in original.iterdir()}
    with pytest.raises(ValueError):
        runtime.preparation_plan(payload, requirements, "project.whl", project_hash)
    assert {path.name: path.read_bytes() for path in original.iterdir()} == before
