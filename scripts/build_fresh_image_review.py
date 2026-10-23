"""Build and statically inspect the pinned fresh Mac installer in hosted CI.

This unprivileged build never invokes Installer or opens an owner application.
It repackages the already signed public image; it cannot sign or publish a release.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

PACKAGING_SOURCE = "56f83bbe89217cbfc9b591a4e8ac8a9525cb80b6"
APP_SOURCE = "d5741bc9912aaf907fe5c52486af18818654dda5"
MANIFEST = "d1f74db86890b306f989b65a8c521ce3b0879f261ded122dd409be2ca2fbe317"
PACKAGE = "ad16754b9acdd71dd1979a2a268b005a96feec681d3392b4af90b0e464590a85"
REQUEST = "artifacts/fresh-image80-build-request.json"
PROFILES = {
    80: (APP_SOURCE, MANIFEST, PACKAGE, REQUEST,
         "artifacts/full-image-installer81-recovery-inputs.json", "full81-source.tar.gz"),
    84: ("d30fda732c589b9ac4dc339a7237ad8ba00d0016",
         "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da",
         "de6769837c00f41e307b5342ab86021c6e2aac27ba7fd99914f670ab2bd99d95",
         "artifacts/fresh-image84-build-request.json", "artifacts/full-image-installer84-inputs.json",
         "full84-source.tar.gz"),
}


def require(value):
    if not value:
        raise ValueError("fresh_image_build_contract_failed")


def guard():
    require(sys.platform == "darwin" and platform.machine() == "arm64"
        and os.getuid() == os.geteuid() != 0
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "fainir/account-access")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=900, **kwargs).stdout


def build_profile(cohort):
    require(type(cohort) is int and cohort in PROFILES)
    return PROFILES[cohort]


def validate_request(value, cohort=80):
    APP_SOURCE, MANIFEST, PACKAGE, _, _, _ = build_profile(cohort)
    require(value == {"schema": 1, "status": "BUILD_ONLY_NO_INSTALL_OR_PUBLICATION",
        "packaging_source": PACKAGING_SOURCE, "app_source": APP_SOURCE,
        "target_manifest_sha256": MANIFEST, "input_package_sha256": PACKAGE,
        "production_ready": False})


def build(repository, bundle, output, cohort=80):
    guard()
    APP_SOURCE, MANIFEST, PACKAGE, REQUEST, contract_path, source_name = build_profile(cohort)
    repository, bundle, output = [path.absolute() for path in (repository, bundle, output)]
    revision = os.environ["GITHUB_SHA"]
    require(command(["git", "rev-parse", "HEAD"], cwd=repository).decode().strip() == revision)
    raw = (repository / REQUEST).read_bytes()
    require(raw == command(["git", "show", revision + ":" + REQUEST], cwd=repository))
    validate_request(json.loads(raw), cohort)
    require(sha(bundle / "full.pkg") == PACKAGE and not output.exists())
    contract_raw = (repository / contract_path).read_bytes()
    require(contract_raw == command(["git", "show", revision + ":" + contract_path], cwd=repository))
    contract = json.loads(contract_raw)
    for name in ("full.pkg", "full-source.tar.gz"):
        row = contract["assets"][name]
        require(sha(bundle / name) == row["sha256"] and (bundle / name).stat().st_size == row["bytes"])
    # Build, source expansion and independent package expansion need ample space.
    require(shutil.disk_usage(output.parent).free > 5 * 1024**3)
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="account-access-fresh-build-") as temporary:
        stage = Path(temporary)
        expanded, source = stage / "input", stage / "source"
        command(["/usr/sbin/pkgutil", "--expand-full", str(bundle / "full.pkg"), str(expanded)])
        image = expanded / "Scripts/TargetImage"
        manifest = expanded / "Scripts/TargetManifest.json"
        require(sha(manifest) == MANIFEST)
        # Import only the exact committed packaging implementation into this build.
        archive = output / "packaging-source.tar.gz"
        archive.write_bytes(command(["git", "archive", "--format=tar.gz", PACKAGING_SOURCE], cwd=repository))
        source.mkdir()
        command(["/usr/bin/tar", "-xzf", str(archive), "-C", str(source)])
        sys.path.insert(0, str(source))
        from macos.system_package import main
        arguments = ["--preassembled-image", str(image), "--preassembled-manifest", str(manifest),
            "--preassembled-sha256", MANIFEST, "--architecture", "arm64", "--unsigned-package",
            "--output", str(stage / "package")]
        original_argv = sys.argv
        try:
            sys.argv = ["macos.system_package", *arguments]
            result = main()
            require(result in (None, 0))
        finally:
            sys.argv = original_argv
        package = stage / "package/Account-Access-arm64-unsigned.pkg"
        report = json.loads((package.parent / "package.json").read_bytes())
        require(report["status"] == "BUILT" and report["preassembled_source_unchanged"] is True
            and report["runtime_transformed"] is False and report["payload_manifest_sha256"] == MANIFEST
            and report["production_ready"] is False and report["sha256"] == sha(package))
        shutil.copy2(package, output / "fresh.pkg")
        shutil.copy2(package.parent / "package.json", output / "package.json")
        shutil.copy2(manifest, output / "fresh-manifest.json")
        candidate = stage / "candidate"
        command(["/usr/sbin/pkgutil", "--expand-full", str(package), str(candidate)])
        # Static checks shared with the separately guarded acceptance controller.
        helper = runpy.run_path(str(repository / "scripts/mac_component_update_installer_probe.py"))
        probe = runpy.run_path(str(repository / "scripts/mac_fresh_image_installer_probe.py"))
        probe["inventory"].__globals__["h"] = SimpleNamespace(**helper)
        inventory = probe["inventory"](candidate)
        scripts = probe["install_script_bodies"]((source / "macos/system_package.py").read_bytes())
        probe["validate_expansion"](candidate, inventory, scripts, manifest_sha=MANIFEST)
        probe["validate_packaged_image"](json.loads(manifest.read_bytes()), inventory)
        inventory_path = output / "fresh-expanded-inventory.json"
        inventory_path.write_text(json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n")
        review = {"schema": 1, "status": "BUILT_NOT_INSTALLED_NOT_INSTALL_QUALIFIED",
            "package_sha256": sha(package), "package_bytes": package.stat().st_size,
            "target_manifest_sha256": MANIFEST, "target_source": APP_SOURCE,
            "packaging_source": PACKAGING_SOURCE, "installer_verifier_sha256": report["installer_verifier_sha256"],
            "expanded_inventory_sha256": sha(inventory_path),
            "actual_Installer_qualified": False, "production_ready": False}
        (output / "fresh-review.json").write_text(json.dumps(review, indent=2) + "\n")
        shutil.copy2(bundle / "full-source.tar.gz", output / source_name)
        print(json.dumps(review))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cohort", type=int, choices=sorted(PROFILES), default=80)
    args = parser.parse_args()
    build(args.repository, args.bundle, args.output, args.cohort)
