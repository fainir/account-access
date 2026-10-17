from types import SimpleNamespace
import subprocess
import xml.etree.ElementTree as ET

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
    assert "--no-index" in package.POSTINSTALL and "--require-hashes" in package.POSTINSTALL
    assert "-I -B -m" in package.POSTINSTALL and "--symlinks" in package.POSTINSTALL
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
