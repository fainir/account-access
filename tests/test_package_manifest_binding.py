import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from account_access import package_manifest as manifest
from scripts import mac_package_smoke as smoke


@pytest.fixture
def package(tmp_path, monkeypatch):
    root = tmp_path / "input"
    for relative in [manifest.SUPPORT, manifest.CANONICAL_APP]:
        path = root / relative
        path.mkdir(parents=True)
        (path / "public-resource").write_bytes(b"public fixture")
    binary = root / manifest.CANONICAL_APP / "Contents/MacOS/AccountAccess"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"synthetic canonical owner binary")
    public = root / manifest.OWNER_APP
    public.parent.mkdir()
    public.symlink_to(manifest.APPLICATION_TARGET)
    for path in [root, *root.rglob("*")]:
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & 0o777 & ~0o022)
    verifier = root / manifest.SUPPORT / "bin/AccountAccess-installerverify"
    verifier.parent.mkdir()
    verifier.write_bytes(b"synthetic native verifier; never executed")
    verifier.chmod(0o755)
    encoded = manifest.build(root, "0.8.0", "arm64")
    metadata = {"payload_manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                "version": "0.8.0", "architecture": "arm64",
                "installation_strategy": "verified-script-image-v1",
                "installer_verifier_sha256": hashlib.sha256(verifier.read_bytes()).hexdigest()}
    calls = []

    def expand(args, **kwargs):
        calls.append(args)
        assert args[:2] == ["/usr/sbin/pkgutil", "--expand-full"]
        assert kwargs["check"] is True and kwargs["timeout"] <= 120
        component = Path(args[-1]) / "payload.pkg"
        shutil.copytree(root, component / "Scripts/PublicImage", symlinks=True)
        (component / "Scripts/RecoveryManifest.json").write_bytes(encoded)
        shutil.copy2(verifier, component / "Scripts/AccountAccess-installerverify")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(smoke.subprocess, "run", expand)
    return root, metadata, calls, expand


def test_recovery_manifest_is_verified_against_the_entire_expanded_package(package):
    _, metadata, calls, _ = package
    assert smoke.verify_package_manifest(Path("fixture.pkg"), metadata) is True
    assert len(calls) == 1 and "installer" not in " ".join(calls[0])
    assert not Path(calls[0][-1]).exists()


@pytest.mark.parametrize("damage", ["pin", "payload", "manifest", "missing", "alias", "mode",
                                  "verifier-bytes", "verifier-alias", "verifier-missing", "verifier-mode"])
def test_recovery_manifest_cannot_hide_changed_code_metadata_or_paths(package, monkeypatch, damage):
    _, metadata, calls, original = package
    if damage == "pin":
        metadata["payload_manifest_sha256"] = "0" * 64

    def expand(args, **kwargs):
        result = original(args, **kwargs)
        component = Path(args[-1]) / "payload.pkg"
        path = component / "Scripts/RecoveryManifest.json"
        resource = component / "Scripts/PublicImage" / manifest.SUPPORT / "public-resource"
        if damage == "payload":
            resource.write_bytes(b"changed code")
        elif damage == "manifest":
            value = json.loads(path.read_bytes())
            value["version"] = "unrelated"
            encoded = json.dumps(value).encode()
            path.write_bytes(encoded)
            metadata["payload_manifest_sha256"] = hashlib.sha256(encoded).hexdigest()
        elif damage == "missing":
            path.unlink()
        elif damage == "alias":
            path.unlink()
            path.symlink_to(resource)
        elif damage == "mode":
            resource.chmod(0o755)
        elif damage.startswith("verifier-"):
            verifier = component / "Scripts/AccountAccess-installerverify"
            if damage == "verifier-bytes":
                verifier.write_bytes(b"changed executable")
            elif damage == "verifier-mode":
                verifier.chmod(0o644)
            else:
                verifier.unlink()
                if damage == "verifier-alias":
                    verifier.symlink_to(component / "Scripts/PublicImage" / manifest.SUPPORT / "bin/AccountAccess-installerverify")
        return result

    monkeypatch.setattr(smoke.subprocess, "run", expand)
    with pytest.raises((ValueError, OSError)):
        smoke.verify_package_manifest(Path("fixture.pkg"), metadata)
    assert len(calls) == 1 and not Path(calls[0][-1]).exists()


@pytest.mark.parametrize("pin", [None, True, "", "not-a-digest"])
def test_missing_recovery_manifest_pin_stops_before_any_package_tool(package, pin):
    _, metadata, calls, _ = package
    metadata["payload_manifest_sha256"] = pin
    with pytest.raises(ValueError, match="package_recovery_manifest_pin_required"):
        smoke.verify_package_manifest(Path("fixture.pkg"), metadata)
    assert not calls
