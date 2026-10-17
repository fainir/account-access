import copy
import hashlib
import json
import plistlib
from types import SimpleNamespace
import zipfile

import pytest

from scripts import mac_package_smoke as smoke
from scripts import mac_prepared_fixture_plan as review


def plan(paths):
    return {
        "schema": 1,
        "python_sha256": "a" * 64,
        "browsers_sha256": "b" * 64,
        "executables": {"c" * 64: {"paths": paths, "entitlements": {}}},
    }


@pytest.mark.parametrize(
    "path,jit",
    [
        ("python/bin/python3.12", True),
        ("wheels/driver.whl/playwright/driver/node", True),
        ("browsers/chromium/chrome-mac/Browser", True),
        ("browsers/chrome-mac/chrome_crashpad_handler", False),
        ("browsers/ffmpeg/ffmpeg", False),
    ],
)
def test_fixture_exceptions_are_explicit_and_do_not_become_the_original_review(path, jit):
    original = plan([path])
    result = review.fixture_plan(original)
    permissions = result["executables"]["c" * 64]["entitlements"]
    assert permissions.get("com.apple.security.cs.allow-jit", False) is jit
    assert permissions["com.apple.security.cs.disable-library-validation"] is True
    assert set(permissions) <= {
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.disable-library-validation",
    }
    assert original["executables"]["c" * 64]["entitlements"] == {}


@pytest.mark.parametrize("fault", ["schema", "extra", "inherited", "path"])
def test_fixture_plan_rejects_ambiguous_or_prepopulated_permissions(fault):
    value = plan(["python/python"])
    if fault == "schema":
        value["schema"] = True
    elif fault == "extra":
        value["production_profile"] = True
    elif fault == "inherited":
        value["executables"]["c" * 64]["entitlements"] = {"com.apple.security.get-task-allow": True}
    else:
        value["executables"]["c" * 64]["paths"] = ["external/runtime"]
    with pytest.raises(ValueError):
        review.fixture_plan(value)


def test_fixture_plan_command_cannot_run_on_the_owner_mac(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(RuntimeError, match="requires_disposable_mac_ci"):
        review.main([str(tmp_path / "input"), str(tmp_path / "output")])
    assert not list(tmp_path.iterdir())


@pytest.fixture
def installed(tmp_path, monkeypatch):
    base, app = tmp_path / "base", tmp_path / "App.app"
    (base / "wheels").mkdir(parents=True)
    (app / "Contents").mkdir(parents=True)
    original = b"dependency==1 --hash=sha256:" + b"a" * 64 + b"\n"
    derived = original.replace(b"a" * 64, b"b" * 64)
    project = base / "wheels/project.whl"
    with zipfile.ZipFile(project, "w") as archive:
        archive.writestr("account_access/runtime-requirements.txt", original)
    project_hash = smoke.sha256(project)
    (app / "Contents/Info.plist").write_bytes(
        plistlib.dumps({"AccountAccessWheelSHA256": project_hash})
    )
    (base / "package-requirements.txt").write_bytes(
        derived + b"\naccount-access==0.8.0 --hash=sha256:" + project_hash.encode() + b"\n"
    )
    receipt = {
        "schema": 1,
        "development": True,
        "publisher_team": "fixture",
        "transform": "account-access-native-signing-and-wheel-record-v1",
        "notarization_verified": False,
        "installed_runtime_verified": False,
        "project_wheel": {"filename": project.name, "sha256": project_hash},
        "original_requirements_sha256": hashlib.sha256(original).hexdigest(),
        "prepared_requirements_sha256": hashlib.sha256(derived).hexdigest(),
        "native_files_signed": 3,
        "bundle_seals_signed": 1,
        "bundles": ["browsers/Fixture.app"],
        "native_files": [],
    }
    for label, relative, kind in [
        ("python/lib/module.dylib", "python/lib/module.dylib", 6),
        (
            "browsers/Fixture.app/Contents/MacOS/Browser",
            "browsers/Fixture.app/Contents/MacOS/Browser",
            2,
        ),
        (
            "wheels/dependency.whl/package/native.so",
            "runtime/lib/python3.12/site-packages/package/native.so",
            8,
        ),
    ]:
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(("public fixture code: " + label).encode())
        receipt["native_files"].append(
            {
                "path": label,
                "kind": kind,
                "original_sha256": "0" * 64,
                "prepared_sha256": smoke.sha256(target),
            }
        )
    metadata = {"runtime_preparation": receipt}
    (base / "runtime-preparation.json").write_text(json.dumps(receipt))
    calls, protected = [], []

    def command(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(smoke.subprocess, "run", command)
    monkeypatch.setattr(smoke, "root_managed_path", protected.append)
    return base, app, metadata, calls, protected


def test_installed_native_bytes_signatures_seals_and_both_locks_are_checked(installed):
    base, app, metadata, calls, protected = installed
    checks = smoke.prepared_checks(base, app, metadata)
    assert len(checks) == 6 and all(value is True for value in checks.values())
    assert len(calls) == len(protected) == 4
    assert sum("--deep" in call for call in calls) == 1
    assert sum(any(arg.startswith("-R=") for arg in call) for call in calls) == 3


@pytest.mark.parametrize(
    "fault",
    ["receipt", "requirements", "project", "native", "count", "path", "duplicate", "privileged"],
)
def test_installed_payload_cannot_hide_changed_artifacts_or_unsafe_receipt_paths(installed, fault):
    base, app, metadata, _, _ = installed
    metadata = copy.deepcopy(metadata)
    receipt = metadata["runtime_preparation"]
    if fault == "receipt":
        (base / "runtime-preparation.json").write_text("{}")
    elif fault == "requirements":
        (base / "package-requirements.txt").write_text("changed requirements")
    elif fault == "project":
        (base / "wheels/project.whl").write_bytes(b"changed project")
    elif fault == "native":
        (base / "python/lib/module.dylib").write_bytes(b"changed native code")
    elif fault == "count":
        receipt["native_files_signed"] = True
    elif fault == "path":
        receipt["native_files"][0]["path"] = "python/../outside"
    elif fault == "duplicate":
        receipt["native_files"][1] = dict(receipt["native_files"][0])
    elif fault == "privileged":
        (base / "python/lib/module.dylib").chmod(0o4755)
    if fault in {"count", "path", "duplicate"}:
        (base / "runtime-preparation.json").write_text(json.dumps(receipt))
    with pytest.raises((AssertionError, ValueError)):
        smoke.prepared_checks(base, app, metadata)
