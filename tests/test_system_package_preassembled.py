"""Owned inert image fixtures; every native/package command is replaced, never run."""

import hashlib
import json
from pathlib import Path
import plistlib
from types import SimpleNamespace
import zipfile

import pytest

from account_access.package_manifest import build
from macos import system_package as package
from test_payload_audit import thin


@pytest.mark.parametrize("digest", [
    "d1f74db86890b306f989b65a8c521ce3b0879f261ded122dd409be2ca2fbe317",
    "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da",
    "5a732de4623ba50aefa6d31c54e7b1eae660b2921341f95042c5675d922d808b",
    "630e77605faac2dfdace9faaa5da55e671335c6b18e62114d7f0224a8574f24c",
])
def test_reviewed_images_reach_manifest_validation(tmp_path, digest):
    # Review admits exact image hashes; all manifest, inventory and peer checks remain.
    with pytest.raises(FileNotFoundError):
        package.preassembled_manifest(tmp_path / "missing-manifest", digest)


@pytest.mark.parametrize("digest", [None, True, "f" * 64,
    "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55db",
    "5a732de4623ba50aefa6d31c54e7b1eae660b2921341f95042c5675d922d808a",
    "630e77605faac2dfdace9faaa5da55e671335c6b18e62114d7f0224a8574f24d"])
def test_unreviewed_images_refuse_before_manifest_paths(tmp_path, digest):
    with pytest.raises(ValueError, match="reviewed_preassembled_image_required"):
        package.preassembled_manifest(tmp_path / "missing-manifest", digest)


def fixture_image(tmp_path, monkeypatch):
    root = tmp_path / "PublicImage"
    payload = root / package.BASE
    app = payload / "owner.app"
    for path in [app / "Contents/MacOS", app / "Contents/Resources", payload / "bin",
                 payload / "python/bin", payload / "runtime/bin", payload / "browsers",
                 payload / "runtime/lib/python3.12/site-packages/playwright/driver", payload / "wheels",
                 root / "Applications"]:
        path.mkdir(parents=True, exist_ok=True)
    (root / package.OWNER_APP).symlink_to(package.APPLICATION_TARGET)
    wheel = app / "Contents/Resources/account_access.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("account_access/runtime-requirements.txt", "fictional==1")
    (payload / "wheels/account_access-0.8.0-py3-none-any.whl").write_bytes(wheel.read_bytes())
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "com.fainir.accountaccess", "CFBundleShortVersionString": "0.8.0",
        "AccountAccessSystemInstallationRequired": True,
        "AccountAccessWheelSHA256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
    }))
    executables = [app / "Contents/MacOS/AccountAccess", payload / "python/bin/python3.12",
                   payload / "runtime/bin/python3.12", payload / "browsers/browser",
                   payload / "runtime/lib/python3.12/site-packages/playwright/driver/node"]
    executables += [payload / ("bin/AccountAccess-" + name) for name in ["broker", "bootstrap", "installerverify"]]
    for path in executables:
        path.write_bytes(thin())
        path.chmod(0o755)
    (payload / "runtime/bin/python").symlink_to("python3.12")
    peers = {name: {"team": "ABCDEFGHIJ", "identifier": identifier, "hashes": ["a" * 40]}
             for name, identifier in [("owner", "com.fainir.accountaccess"),
                                      ("broker", "com.fainir.accountaccess.broker"),
                                      ("bootstrap", "com.fainir.accountaccess.bootstrap")]}
    (payload / "package-identity.json").write_text(json.dumps({
        "schema": 1, "managed_by": "account-access-package-identity-v1", "signatures": peers}))
    manifest = tmp_path / "manifest.json"
    args = SimpleNamespace(preassembled_image=root, preassembled_manifest=manifest,
        preassembled_sha256=None, output=tmp_path / "output", architecture="arm64", development=False,
        unsigned_package=True, installer_identity=None)

    def repin():
        raw = build(root, "0.8.0", "arm64")
        manifest.write_bytes(raw)
        args.preassembled_sha256 = hashlib.sha256(raw).hexdigest()
        # The fixed production cohort is never overridden by a command-line flag.
        # Each fictional fixture substitutes only the reviewed digest constant.
        monkeypatch.setattr(package, "PREASSEMBLED_MANIFEST_SHA256", args.preassembled_sha256)
        return raw

    return args, peers, repin


def setup_commands(monkeypatch, args, peers, *, reject=None, on_audit=None):
    calls, checks = [], []
    monkeypatch.setattr(package, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(package, "package_source_provenance", lambda *, require_clean: {
        "source_commit": "d" * 40, "source_tree_clean": True,
    })

    def signature(path, identifier, *, fixture):
        assert fixture is False
        checks.append(identifier)
        if reject == "publisher":
            raise ValueError("fictional_publisher_refusal")
        return {"team": "ABCDEFGHIJ", "identifier": identifier, "hashes": ["a" * 40]}

    def audit(roots, wheels, architecture, command, *, development):
        assert development is False and architecture == "arm64"
        assert len(roots) == 5 and wheels and command is package.command
        assert all(path != args.preassembled_image and not path.is_relative_to(args.preassembled_image)
                   for path in [*roots, *wheels])
        checks.append("audit")
        if reject == "audit":
            raise ValueError("fictional_audit_refusal")
        if on_audit:
            on_audit()
        return {"publisher_signatures_verified": True}

    def preflight(verifier, manifest):
        checks.append("native-preflight")
        assert verifier.name == "AccountAccess-installerverify" and manifest == args.preassembled_manifest.read_bytes()
        if reject == "preflight":
            raise ValueError("fictional_native_preflight_refusal")

    def command(arguments, *, input_data=None):
        calls.append(arguments)
        name = Path(arguments[0]).name
        assert name in {"chmod", "pkgbuild", "productbuild", "pkgutil"}, "No supplied runtime/helper may execute"
        if name == "pkgbuild":
            scripts = Path(arguments[arguments.index("--scripts") + 1])
            assert {path.name for path in scripts.iterdir()} == {
                "preinstall", "postinstall", "RecoveryManifest.json", "AccountAccess-installerverify", "PublicImage"}
            assert (scripts / "preinstall").read_text() == package.PREINSTALL
            assert (scripts / "postinstall").read_text() == package.POSTINSTALL
            assert (scripts / "RecoveryManifest.json").read_bytes() == args.preassembled_manifest.read_bytes()
            assert arguments[1:6] == ["--nopayload", "--identifier", package.IDENTIFIER, "--version", "0.8.0"]
            package.preassembled_inventory(scripts / "PublicImage", args.preassembled_manifest.read_bytes())
        if name in {"pkgbuild", "productbuild"}:
            Path(arguments[-1]).write_bytes(b"fictional package data, never a real build")
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(package, "signature", signature)
    monkeypatch.setattr(package, "audit_payload", audit)
    monkeypatch.setattr(package, "native_manifest_preflight", preflight)
    monkeypatch.setattr(package, "command", command)
    for name in ["stage_runtime_ca", "stage_bitwarden"]:
        monkeypatch.setattr(package, name, lambda *_: pytest.fail("preassembled image was transformed"))
    return calls, checks


@pytest.mark.parametrize("unsigned", [True, False])
def test_preassembled_image_reuses_production_envelope_without_runtime_or_native_execution(tmp_path, monkeypatch, unsigned):
    args, peers, repin = fixture_image(tmp_path, monkeypatch)
    args.unsigned_package = unsigned
    args.installer_identity = None if unsigned else "fictional Installer identity, never used"
    raw = repin()
    calls, checks = setup_commands(monkeypatch, args, peers)
    result = package.assemble_preassembled(args)
    assert [Path(row[0]).name for row in calls] == ["chmod", "pkgbuild", "productbuild"] + ([] if unsigned else ["pkgutil"])
    product = next(row for row in calls if Path(row[0]).name == "productbuild")
    assert ("--sign" in product) is not unsigned
    if not unsigned:
        assert product[-3:-1] == ["--sign", args.installer_identity]
    assert checks[-2:] == ["audit", "native-preflight"]
    assert {"com.fainir.accountaccess", "com.fainir.accountaccess.broker", "com.fainir.accountaccess.bootstrap",
            "com.fainir.accountaccess.installerverify"} <= set(checks)
    assert result["preassembled_source_unchanged"] and result["native_manifest_preflight"]
    assert result["source_commit"] == "d" * 40 and result["source_tree_clean"] is True
    assert result["fresh_install_only"] is True
    assert not any(result[name] for name in ["production_ready", "notarized", "installed", "runtime_transformed"])
    if unsigned:
        assert result["unsigned_package"] and result["installer_signed"] is False
    assert build(args.preassembled_image, "0.8.0", "arm64") == raw
    assert result["payload_manifest_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("option", ["app", "native", "python", "browsers", "wheels", "runtime_identity",
    "runtime_plan", "pip_wheel", "bitwarden_archive", "bitwarden_sources", "bitwarden_source_sha256", "inspect_runtime"])
def test_preassembled_image_refuses_mixed_raw_or_transform_routes_before_inputs(tmp_path, monkeypatch, option):
    args, peers, _ = fixture_image(tmp_path, monkeypatch)
    setup_commands(monkeypatch, args, peers)
    setattr(args, option, True if option == "inspect_runtime" else "fictional-mixed-input")
    with pytest.raises(ValueError, match="preassembled_and_transform_inputs_conflict"):
        package.assemble_preassembled(args)
    assert not args.output.exists()


@pytest.mark.parametrize("fault", ["manifest-pin", "manifest-link", "root-link", "source-data", "extra-envelope"])
def test_preassembled_source_or_manifest_changes_refuse_before_native_commands(tmp_path, monkeypatch, fault):
    args, peers, repin = fixture_image(tmp_path, monkeypatch)
    repin()
    calls, _ = setup_commands(monkeypatch, args, peers)
    if fault == "manifest-pin":
        args.preassembled_sha256 = "f" * 64
    elif fault in {"manifest-link", "root-link"}:
        original = args.preassembled_manifest if fault == "manifest-link" else args.preassembled_image
        alias = tmp_path / "alias"
        alias.symlink_to(original)
        setattr(args, "preassembled_manifest" if fault == "manifest-link" else "preassembled_image", alias)
    elif fault == "source-data":
        (args.preassembled_image / package.BASE / "browsers/browser").write_bytes(b"mutated public input")
    else:
        (args.preassembled_image / "unexpected").write_text("must never enter the package")
    with pytest.raises((ValueError, OSError)):
        package.assemble_preassembled(args)
    assert not calls and not args.output.exists()


@pytest.mark.parametrize("fault", ["copy", "source"])
def test_preassembled_copy_and_late_source_drift_refuse_without_package_tools(tmp_path, monkeypatch, fault):
    args, peers, repin = fixture_image(tmp_path, monkeypatch)
    repin()
    original_copy = package.shutil.copytree

    def copy(source, destination, *positional, **options):
        result = original_copy(source, destination, *positional, **options)
        if Path(source) == args.preassembled_image:
            selected = Path(destination) if fault == "copy" else source
            (selected / package.BASE / "browsers/browser").write_bytes(b"fictional copy-time drift")
        return result

    monkeypatch.setattr(package.shutil, "copytree", copy)
    calls, _ = setup_commands(monkeypatch, args, peers)
    with pytest.raises(ValueError, match="preassembled_image_changed"):
        package.assemble_preassembled(args)
    assert all(Path(row[0]).name == "chmod" for row in calls)


@pytest.mark.parametrize("reject", ["publisher", "audit", "preflight", "peer-identity", "wheel-pin", "native-python"])
def test_preassembled_production_checks_are_not_bypassed_by_unsigned_container(tmp_path, monkeypatch, reject):
    args, peers, repin = fixture_image(tmp_path, monkeypatch)
    payload = args.preassembled_image / package.BASE
    if reject == "peer-identity":
        peers["broker"]["hashes"] = ["b" * 40]
        (payload / "package-identity.json").write_text(json.dumps({
            "schema": 1, "managed_by": "account-access-package-identity-v1", "signatures": peers}))
    if reject == "wheel-pin":
        (payload / "wheels/account_access-0.8.0-py3-none-any.whl").write_bytes(b"different project wheel")
    if reject == "native-python":
        (payload / "runtime/bin/python3.12").write_bytes(b"#!/bin/sh\nexit 0\n")
    repin()
    calls, _ = setup_commands(monkeypatch, args, peers, reject=reject)
    with pytest.raises(ValueError, match={"publisher": "fictional_publisher_refusal", "audit": "fictional_audit_refusal",
        "preflight": "fictional_native_preflight_refusal", "peer-identity": "preassembled_peer_identity_changed",
        "wheel-pin": "wheelhouse_project_mismatch", "native-python": "native_python_and_browser_executables_required"}[reject]):
        package.assemble_preassembled(args)
    assert all(Path(row[0]).name == "chmod" for row in calls)


@pytest.mark.parametrize("real_uid,effective_uid", [(0, 0), (501, 0), (501, 502)])
def test_preassembled_context_guard_precedes_all_paths(monkeypatch, real_uid, effective_uid):
    monkeypatch.setattr(package, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(package, "os", SimpleNamespace(getuid=lambda: real_uid, geteuid=lambda: effective_uid))
    with pytest.raises(ValueError, match="ordinary_mac_build_context_required"):
        package.assemble_preassembled(SimpleNamespace())


def test_preassembled_reviewed_cohort_has_no_development_bypass(monkeypatch):
    monkeypatch.setattr(package, "sys", SimpleNamespace(platform="darwin"))
    with pytest.raises(ValueError, match="preassembled_production_payload_required"):
        package.assemble_preassembled(SimpleNamespace(architecture="arm64", development=True,
                                                      unsigned_package=False, installer_identity=None))
