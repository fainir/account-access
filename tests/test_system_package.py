from types import SimpleNamespace
import os
import subprocess
import xml.etree.ElementTree as ET
import zipfile

import pytest

from macos import system_package as package


def test_installer_disables_relocation_for_every_nested_app():
    rules = [{"RootRelativeBundlePath": "Applications/Account Access.app", "ChildBundles": [{}]}]
    result = package.bundle_rules(rules)
    for entry in [result[0], result[0]["ChildBundles"][0]]:
        assert entry["BundleIsRelocatable"] is False
        assert entry["BundleHasStrictIdentifier"] is True


@pytest.mark.parametrize("architecture", ["arm64", "x86_64"])
def test_package_is_fixed_to_system_volume_and_supported_mac_version(architecture):
    xml = ET.fromstring(package.distribution("0.8.0", architecture))
    assert xml.find("options").attrib["hostArchitectures"] == architecture
    assert xml.find("domains").attrib == {
        "enable_anywhere": "false",
        "enable_currentUserHome": "false",
        "enable_localSystem": "true",
    }
    assert xml.find("volume-check/allowed-os-versions/os-version").attrib["min"] == "14.0"
    assert xml.find("pkg-ref").text == "payload.pkg"


def test_package_assembly_never_runs_under_root_or_on_another_platform(monkeypatch):
    monkeypatch.setattr(package.os, "getuid", lambda: 0)
    with pytest.raises(ValueError, match="ordinary_mac_build_context_required"):
        package.assemble(SimpleNamespace())


def test_complete_image_may_add_only_its_generated_runtime_and_receipt_to_source_inventory():
    import json

    source = {"roots": {"/" + str(package.BASE): {"python/file": {"sha256": "original"}}}}
    complete = json.loads(json.dumps(source))
    rows = complete["roots"]["/" + str(package.BASE)]
    rows.update({"runtime": {}, "runtime/bin/python": {}, "runtime-image.json": {}})
    package.verify_source_inventory(json.dumps(source), json.dumps(complete))
    rows["python/file"]["sha256"] = "changed"
    with pytest.raises(ValueError, match="runtime_image_source_payload_changed"):
        package.verify_source_inventory(json.dumps(source), json.dumps(complete))


def test_installer_scripts_are_valid_shell_and_refuse_ordinary_user(tmp_path):
    for name, source in [("preinstall", package.PREINSTALL), ("postinstall", package.POSTINSTALL)]:
        path = tmp_path / name
        path.write_text(source)
        assert subprocess.run(["/bin/sh", "-n", str(path)]).returncode == 0
        # Tests use an unprivileged process; no protected path can be touched.
        if package.os.getuid() != 0:
            assert (
                subprocess.run(["/bin/sh", str(path), "package", "destination", "/"]).returncode
                != 0
            )
    assert "-I -B -m account_access.system_provision" in package.POSTINSTALL
    assert "-m pip" not in package.POSTINSTALL and "-m venv" not in package.POSTINSTALL
    assert "chmod" not in package.POSTINSTALL
    assert "runtime" not in package.PREINSTALL  # Reject the entire existing installation first.
    assert '"${3:-}" = /' in package.PREINSTALL
    assert not any(
        word in package.POSTINSTALL for word in ["curl ", "wget ", "http://", "https://"]
    )


def test_protected_owner_app_required_before_signatures_or_payload_copy(tmp_path):
    import plistlib

    app = tmp_path / "Account Access.app"
    (app / "Contents").mkdir(parents=True)
    (app / "Contents/Info.plist").write_bytes(
        plistlib.dumps(
            {
                "CFBundleIdentifier": "com.fainir.accountaccess",
                "CFBundleShortVersionString": "0.8.0",
            }
        )
    )
    with pytest.raises(ValueError, match="protected_owner_app_required"):
        package.inspect_app(app, development=True)
    assert list((app / "Contents").iterdir()) == [app / "Contents/Info.plist"]


@pytest.mark.parametrize("development", [False, True])
@pytest.mark.parametrize("native_python,writable", [(False, False), (True, False), (True, True)])
def test_supplied_python_cannot_run_before_private_payload_inventory(
    tmp_path, monkeypatch, development, native_python, writable
):
    from test_payload_audit import thin

    app, native, python, browsers, wheels = [
        tmp_path / name for name in ["app", "native", "python", "browsers", "wheels"]
    ]
    for path in [app, native, python / "bin", python / "lib/python3.12", browsers, wheels]:
        path.mkdir(parents=True)
    executable = python / "bin/python3.12"
    executable.write_bytes(thin() if native_python else b"#!/bin/sh\nexit 0\n")
    if writable:
        executable.chmod(0o666)
    (python / "lib/python3.12/os.py").write_text("# synthetic fixture")
    (browsers / "browser").write_bytes(thin())
    for name in ["broker", "bootstrap"]:
        (native / ("AccountAccess-" + name)).write_bytes(thin())
    wheel = app / "project.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("account_access/runtime-requirements.txt", "fixture==1")
    with zipfile.ZipFile(wheels / "fixture.whl", "w") as archive:
        archive.writestr("fixture/data", "fixture only")
    calls, inventories = [], []
    monkeypatch.setattr(package.sys, "platform", "darwin")
    # Fake only the assembler's platform context. Patching the shared os module
    # would also change the inventory's ownership checks (and hide Linux UID
    # differences). Deliberately use a different simulated builder identity.
    actual_uid = os.getuid()
    monkeypatch.setattr(package, "os", SimpleNamespace(getuid=lambda: actual_uid + 1))
    assert os.getuid() == actual_uid
    monkeypatch.setattr(
        package, "inspect_app", lambda *a, **k: ("0.8.0", "ABCDEFGHIJ", wheel, b"fixture==1")
    )
    monkeypatch.setattr(package, "signature", lambda *a, **k: {"team": "ABCDEFGHIJ"})

    def command(args):
        calls.append(args)
        assert args[0] == "/bin/chmod", "No supplied interpreter or installer tool may run first"
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(package, "command", command)

    def audit(roots, archives, architecture, command, *, development):
        inventories.append((roots, archives, development))
        assert architecture == "arm64"
        assert all(not str(path).startswith(str(tmp_path)) for path in [*roots, *archives])
        if writable:
            return {}  # The subsequent real inventory must stop unsafe modes.
        raise ValueError("fixture_inventory_stopped_before_execution")

    monkeypatch.setattr(package, "audit_payload", audit)
    expected = (
        "unsafe_install_manifest_object" if writable else "fixture_inventory_stopped_before_execution"
        if native_python
        else "native_python_and_browser_executables_required"
    )
    with pytest.raises(ValueError, match=expected):
        package.assemble(
            SimpleNamespace(
                app=app,
                native=native,
                python=python,
                browsers=browsers,
                wheels=wheels,
                output=tmp_path / "output",
                architecture="arm64",
                development=development,
                installer_identity="fixture never used",
            )
        )
    assert len(calls) == 1 and bool(inventories) is native_python
    if inventories:
        assert inventories[0][2] is development
    assert executable.read_bytes() == (thin() if native_python else b"#!/bin/sh\nexit 0\n")
    if writable:
        assert executable.stat().st_mode & 0o777 == 0o666
    assert not list((tmp_path / "output").iterdir())
