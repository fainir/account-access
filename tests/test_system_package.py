from types import SimpleNamespace
import os
import plistlib
import platform
import subprocess
import sys
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
    xml = ET.fromstring(package.distribution("0.8.0", architecture, install_bytes=16385))
    assert xml.find("options").attrib["hostArchitectures"] == architecture
    assert xml.find("domains").attrib == {
        "enable_anywhere": "false",
        "enable_currentUserHome": "false",
        "enable_localSystem": "true",
    }
    assert xml.find("volume-check/allowed-os-versions/os-version").attrib["min"] == "14.0"
    assert xml.find("pkg-ref").text == "payload.pkg"
    assert xml.find("pkg-ref").attrib["installKBytes"] == "17"
    assert xml.find("volume-check").attrib["script"] == "accountAccessSpaceCheck()"
    assert "available >= 16385" in xml.find("script").text
    assert "0.1 GB" in xml.find("script").text
    assert "system.run" not in xml.find("script").text
    assert "allow-external-scripts" not in xml.find("options").attrib


@pytest.mark.parametrize("size", [True, False, 0, -1, 4096.0, "4096", None])
def test_distribution_refuses_missing_or_invalid_space_estimate(size):
    with pytest.raises(ValueError, match="invalid_install_space_requirement"):
        package.distribution("0.8.0", "arm64", install_bytes=size)


@pytest.mark.skipif(sys.platform != "darwin", reason="Apple package tools required")
def test_actual_script_only_product_preserves_capacity_check_and_native_byte_units(tmp_path):
    # Assemble and inspect a tiny inert package as an ordinary user. No package
    # is installed, elevated or allowed to execute external programs. The
    # production volume-check runs through native Installer's read-only query.
    # productbuild rewrites installKBytes to zero for --nopayload; this verifies
    # the actual surviving volume-check instead of trusting source XML.
    scripts = tmp_path / "scripts"
    architecture = platform.machine()
    assert architecture in {"arm64", "x86_64"}
    scripts.mkdir()
    (scripts / "public-fixture.txt").write_text("public inert package fixture")
    component = tmp_path / "payload.pkg"
    command = ["/usr/bin/pkgbuild", "--nopayload", "--identifier", package.IDENTIFIER,
               "--version", "0.8.0", "--scripts", str(scripts), str(component)]
    def run(arguments):
        return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL, capture_output=True,
                       timeout=30, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"})
    run(command)
    volume = os.statvfs("/Library/Application Support")
    # Half of actual free bytes is comfortably above its KiB-valued equivalent,
    # on both small local volumes and large CI disks. This discriminates units;
    # a hardcoded small requirement could accidentally pass with either unit.
    available = volume.f_bavail * volume.f_frsize
    assert available >= 1024 * 1024
    for case, required, eligible in [("sufficient", available // 2, True),
                                    ("insufficient", 2**53 - 1, False)]:
        source, product, expanded = [tmp_path / (case + suffix) for suffix in [".xml", ".pkg", "-expanded"]]
        source.write_text(package.distribution("0.8.0", architecture, install_bytes=required))
        run(["/usr/bin/productbuild", "--distribution", str(source),
             "--package-path", str(tmp_path), str(product)])
        run(["/usr/sbin/pkgutil", "--expand", str(product), str(expanded)])
        native = ET.parse(expanded / "Distribution")
        assert native.find("volume-check").attrib["script"] == "accountAccessSpaceCheck()"
        assert f"available >= {required}" in native.find("script").text
        assert "allow-external-scripts" not in native.find("options").attrib
        volumes = plistlib.loads(run(["/usr/sbin/installer", "-volinfo", "-plist", "-pkg", str(product)]).stdout)
        assert type(volumes) is list
        assert any(type(row) is dict and row.get("MountPoint") == "/" for row in volumes) is eligible


def test_package_assembly_never_runs_under_root_or_on_another_platform(monkeypatch):
    monkeypatch.setattr(package.os, "getuid", lambda: 0)
    with pytest.raises(ValueError, match="ordinary_mac_build_context_required"):
        package.assemble(SimpleNamespace())


def test_consumer_package_requires_explicit_pinned_ca_refresh_input_before_provider(tmp_path):
    with pytest.raises(ValueError, match="runtime_ca_pinned_pip_wheel_required"):
        package.stage_runtime_ca(SimpleNamespace(development=False), tmp_path)
    assert list(tmp_path.iterdir()) == []
    assert package.stage_runtime_ca(SimpleNamespace(development=True), tmp_path) is None


def test_explicit_ca_refresh_uses_the_same_path_for_inspection_and_assembly(tmp_path, monkeypatch):
    from macos import runtime_ca

    seen = []
    monkeypatch.setattr(runtime_ca, "refresh", lambda payload, wheel: seen.append((payload, wheel)) or {"fixture": True})
    for inspection in (True, False):
        assert package.stage_runtime_ca(SimpleNamespace(development=False, inspect_runtime=inspection,
                                                       pip_wheel="public-pinned.whl"), tmp_path) == {"fixture": True}
    assert seen == [(tmp_path, "public-pinned.whl"), (tmp_path, "public-pinned.whl")]


@pytest.mark.parametrize("architecture", ["x86_64", "i386", "unknown"])
def test_package_refuses_unavailable_intel_runtime_before_opening_any_supplied_payload(monkeypatch, architecture):
    monkeypatch.setattr(package.sys, "platform", "darwin")
    monkeypatch.setattr(package, "os", SimpleNamespace(getuid=lambda: 501, geteuid=lambda: 501))
    with pytest.raises(ValueError, match="apple_silicon_binary_runtime_required"):
        package.assemble(SimpleNamespace(architecture=architecture))


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
    assert 'exec "$AC_PACKAGE_SCRIPTS/AccountAccess-installerverify" --install' in package.POSTINSTALL
    assert "python" not in package.POSTINSTALL
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
    for name in ["broker", "bootstrap", "installerverify"]:
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
    monkeypatch.setattr(package, "os", SimpleNamespace(getuid=lambda: actual_uid + 1, geteuid=lambda: actual_uid + 1))
    assert os.getuid() == actual_uid
    monkeypatch.setattr(
        package, "inspect_app", lambda *a, **k: ("0.8.0", "ABCDEFGHIJ", wheel, b"fixture==1")
    )
    monkeypatch.setattr(package, "signature", lambda *a, **k: {"team": "ABCDEFGHIJ"})
    # This case isolates the prior native payload inventory; standalone-provider
    # input/source completeness has its own real archive tests.
    monkeypatch.setattr(package, "stage_bitwarden", lambda *a: {"fixture": "separate-provider-input-tests"})
    # Pinned packaging-tool input validation has its own real and synthetic
    # archive checks. This fake image deliberately has no Python packaging tree.
    monkeypatch.setattr(package, "stage_runtime_ca", lambda *a: None)

    def command(args):
        calls.append(args)
        assert args[0] == "/bin/chmod", "No supplied interpreter or installer tool may run first"
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(package, "command", command)

    def audit(roots, archives, architecture, command, *, development):
        inventories.append((roots, archives, development))
        assert architecture == "arm64"
        assert all(not str(path).startswith(str(tmp_path)) for path in [*roots, *archives])
        assert roots[0].as_posix().endswith("/Library/Application Support/Account Access/owner.app")
        public = roots[0].parents[3] / package.OWNER_APP
        assert public.is_symlink() and public.readlink().as_posix() == package.APPLICATION_TARGET
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


@pytest.mark.parametrize("fault", [None, "digest", "count", "schema-bool", "runtime-status", "extra-field", "oversized"])
def test_native_manifest_preflight_uses_bounded_stdin_and_binds_exact_inspection_result(monkeypatch, fault):
    import hashlib
    import json

    encoded = json.dumps({"roots": {"public": {"": {"kind": "directory"}, "code": {"kind": "file"}}}}).encode()
    expected = {"schema": 1, "status": "INSPECTED", "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                "files": 1, "directories": 1, "aliases": 0}
    calls = []
    def inspect(arguments, *, input_data):
        calls.append(arguments)
        assert arguments == ["/synthetic/verifier", "--inspect-manifest"] and input_data == encoded
        value = expected.copy()
        if fault == "digest":
            value["manifest_sha256"] = "0" * 64
        elif fault == "count":
            value["files"] += 1
        elif fault == "schema-bool":
            value["schema"] = True
        elif fault == "runtime-status":
            value["status"] = "VERIFIED"
        elif fault == "extra-field":
            value["unrecognized"] = True
        return SimpleNamespace(stdout=b"x" * 4097 if fault == "oversized" else json.dumps(value).encode())
    monkeypatch.setattr(package, "command", inspect)
    if fault:
        with pytest.raises(ValueError, match="native_manifest_preflight_mismatch"):
            package.native_manifest_preflight("/synthetic/verifier", encoded)
    else:
        package.native_manifest_preflight("/synthetic/verifier", encoded)
    assert len(calls) == 1


@pytest.mark.parametrize("real_uid,effective_uid", [(0, 0), (501, 0), (501, 502)])
def test_package_refuses_privileged_or_mismatched_identity_before_any_payload_path_is_read(monkeypatch, real_uid, effective_uid):
    monkeypatch.setattr(package.sys, "platform", "darwin")
    monkeypatch.setattr(package, "os", SimpleNamespace(getuid=lambda: real_uid, geteuid=lambda: effective_uid))
    with pytest.raises(ValueError, match="ordinary_mac_build_context_required"):
        package.assemble(SimpleNamespace())


@pytest.mark.parametrize("development,installer", [(True, None), (False, "Installer identity"), (True, "Installer identity")])
def test_unsigned_container_refuses_conflicting_modes_before_opening_payload(monkeypatch, development, installer):
    monkeypatch.setattr(package.sys, "platform", "darwin")
    monkeypatch.setattr(package, "os", SimpleNamespace(getuid=lambda: 501, geteuid=lambda: 501))
    with pytest.raises(ValueError, match="unsigned_package_conflicts_with_signing_mode"):
        package.assemble(SimpleNamespace(architecture="arm64", unsigned_package=True,
                                         development=development, installer_identity=installer))


def test_default_production_container_still_requires_installer_identity_before_payload_reads(monkeypatch):
    monkeypatch.setattr(package.sys, "platform", "darwin")
    monkeypatch.setattr(package, "os", SimpleNamespace(getuid=lambda: 501, geteuid=lambda: 501))
    with pytest.raises(ValueError, match="developer_id_installer_identity_required"):
        package.assemble(SimpleNamespace(architecture="arm64", development=False,
                                         installer_identity=None))


@pytest.mark.parametrize("reject", [None, "publisher", "runtime-signing", "audit"])
def test_unsigned_container_keeps_genuine_payload_and_runtime_verification(tmp_path, monkeypatch, reject):
    import hashlib
    import plistlib
    from pathlib import Path

    from macos import runtime_image, runtime_prepare
    from test_payload_audit import thin

    app, native, python, browsers, wheels = [tmp_path / name for name in
                                           ["owner.app", "native", "python", "browsers", "wheels"]]
    for path in [app / "Contents/MacOS", app / "Contents/Resources", native,
                 python / "bin", python / "lib/python3.12", browsers, wheels]:
        path.mkdir(parents=True)
    (app / "Contents/MacOS/AccountAccess").write_bytes(thin())
    (python / "bin/python3.12").write_bytes(thin())
    (python / "lib/python3.12/os.py").write_text("# fictional Python input")
    (browsers / "browser").write_bytes(thin())
    for name in ["broker", "bootstrap", "installerverify"]:
        (native / ("AccountAccess-" + name)).write_bytes(thin())
    wheel = app / "Contents/Resources/account_access.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("account_access/runtime-requirements.txt", "fictional==1")
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "com.fainir.accountaccess", "CFBundleShortVersionString": "0.8.0",
        "AccountAccessSystemInstallationRequired": True,
        "AccountAccessWheelSHA256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
    }))
    with zipfile.ZipFile(wheels / "fictional.whl", "w") as archive:
        archive.writestr("fictional/data", "public fictional data")
    plan = tmp_path / "plan.json"
    plan.write_text('{"reviewed":"fixture"}')
    # Simulate the package entrypoint without changing the host platform used
    # by descriptor/ACL helpers in other modules.
    monkeypatch.setattr(package, "sys", SimpleNamespace(platform="darwin"))
    calls, policies, signatures, advertised = [], [], [], []
    def signature(path, identifier, *, fixture):
        assert fixture is False
        signatures.append(identifier)
        if reject == "publisher":
            raise ValueError("invalid_payload_publisher")
        return {"team": "ABCDEFGHIJ", "identifier": identifier, "hashes": ["a" * 40]}
    monkeypatch.setattr(package, "signature", signature)
    monkeypatch.setattr(package, "stage_bitwarden", lambda *a: {"fixture": "separate-provider-input-tests"})
    # This image is inert fictional data; pinned CA archive checks have their
    # own tests, while this case isolates the genuine unsigned-container gates.
    monkeypatch.setattr(package, "stage_runtime_ca", lambda *a: None)
    def prepare(payload, requirements, project_name, pin, identity, team, selected, command, *, development):
        assert development is False and team == "ABCDEFGHIJ" and identity == "Application publisher"
        assert selected == {"reviewed": "fixture"}
        policies.append("production-runtime-signing")
        if reject == "runtime-signing":
            raise ValueError("matching_runtime_signing_identity_required")
        return requirements, {"fixture": "production-signing-policy-retained"}
    monkeypatch.setattr(runtime_prepare, "prepare", prepare)
    def audit(*args, development):
        assert development is False
        policies.append("production-payload-audit")
        if reject == "audit":
            raise ValueError("payload_publisher_not_verified")
        return {"publisher_signatures_verified": True}
    monkeypatch.setattr(package, "audit_payload", audit)
    monkeypatch.setattr(package, "native_manifest_preflight", lambda *_: policies.append("native-manifest"))
    monkeypatch.setattr(runtime_image, "verify_origins", lambda *_: {})
    def image(payload, *args, **kwargs):
        node = payload / "runtime/lib/python3.12/site-packages/playwright/driver/node"
        node.parent.mkdir(parents=True)
        node.write_bytes(thin())
        return {"fixture": "assembled-without-running-package-code"}
    monkeypatch.setattr(runtime_image, "assemble", image)
    def command(arguments, *, input_data=None):
        calls.append(arguments)
        name = Path(arguments[0]).name
        if name == "pkgbuild":
            scripts = Path(arguments[arguments.index("--scripts") + 1])
            assert arguments[:-1] == ["/usr/bin/pkgbuild", "--nopayload", "--identifier", package.IDENTIFIER,
                "--version", "0.8.0", "--install-location", "/", "--ownership", "recommended", "--scripts", str(scripts)]
            assert {path.name for path in scripts.iterdir()} == {
                "preinstall", "postinstall", "RecoveryManifest.json", "AccountAccess-installerverify", "PublicImage"}
            assert (scripts / "preinstall").read_text() == package.PREINSTALL
            assert (scripts / "postinstall").read_text() == package.POSTINSTALL
            assert (scripts / "PublicImage" / package.CANONICAL_APP).is_dir()
        if name in {"pkgbuild", "productbuild"}:
            assert "--sign" not in arguments
            if name == "productbuild":
                xml = ET.parse(arguments[arguments.index("--distribution") + 1])
                advertised.append(int(xml.find("pkg-ref").attrib["installKBytes"]) * 1024)
            Path(arguments[-1]).write_bytes(b"fictional installer container")
        if name == "python3.12":
            return SimpleNamespace(stdout=b'[[3,12,16],"arm64",true]', stderr=b"")
        assert name in {"chmod", "pkgbuild", "productbuild", "python3.12"}
        return SimpleNamespace(stdout=b"", stderr=b"")
    monkeypatch.setattr(package, "command", command)
    args = SimpleNamespace(app=app, native=native, python=python, browsers=browsers,
        wheels=wheels, output=tmp_path / "output", architecture="arm64", development=False,
        unsigned_package=True, installer_identity=None, runtime_identity="Application publisher",
        runtime_plan=plan, inspect_runtime=False)
    original = {path: path.read_bytes() for path in [wheel, python / "bin/python3.12", browsers / "browser"]}
    if reject:
        with pytest.raises(ValueError, match={"publisher": "invalid_payload_publisher",
                "runtime-signing": "matching_runtime_signing_identity_required",
                "audit": "payload_publisher_not_verified"}[reject]):
            package.assemble(args)
        assert not any(Path(call[0]).name in {"python3.12", "pkgbuild", "productbuild"} for call in calls)
    else:
        result = package.assemble(args)
        assert result["development"] is False and result["unsigned_package"] is True
        assert result["installer_signed"] is False and result["production_ready"] is False
        assert result["notarized"] is False and result["installed"] is False
        assert advertised == [result["required_install_bytes"]]
        assert result["required_install_bytes"] > 256 * 1024 * 1024
        assert (args.output / "Account-Access-arm64-unsigned.pkg").is_file()
        assert policies == ["production-runtime-signing", "production-payload-audit", "native-manifest",
                            "production-payload-audit", "native-manifest"]
        assert set(signatures) == {"com.fainir.accountaccess", "com.fainir.accountaccess.broker",
                                 "com.fainir.accountaccess.bootstrap", "com.fainir.accountaccess.installerverify"}
    assert all(path.read_bytes() == data for path, data in original.items())
