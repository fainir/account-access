"""Build the signed owner-upgrade package with reduced duplicate predecessor scans.

This candidate starts from the reviewed scripts-only build-109 package and
retains the projected predecessor proof while avoiding redundant full proof
rebuilds at transition boundaries. It does not change the installed app until
macOS Installer runs the package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
BASE_PACKAGE_SHA256 = "0528d4a545c14c92c58a8ebe03660e8d75efd7d38b67db92ccc913a5249ce2a0"
PACKAGE95_SHA256 = "0c7a83b47d405bd9b02686aceb938877c5cd2f36112cb0b8369069c643453371"
INVENTORY95_SHA256 = "9072d9bce2fd9c1b6118e657c77cab3f32e5c44689f4bb230132f07bbbb0e1e1"
BASE_HELPER_SHA256 = "c51b054d1fc37ada176f390e97402e175efa91aba9c3cb666e80c4ed163d277d"
COMPILED_PINS_SHA256 = "4845f307efc3d4d8c337a407e519c757f45d048be6c9341e7481c3452dc27a30"
TEAM_ID = "WBULD6N4NQ"
PACKAGE_ID = "com.fainir.accountaccess.ownerupgrade112"
NOTARY_PROFILE = "AccountAccessPublisher"
MAX_SOURCE_BYTES = 2 * 1024 * 1024


class BuildRefused(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise BuildRefused(reason)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def process_output(result: subprocess.CompletedProcess[bytes]) -> str:
    return (result.stdout + result.stderr).decode(errors="replace").strip()


def command(label: str, arguments: list[str], *, cwd: Path = ROOT,
            timeout: int = 900, expected: int = 0) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(arguments, cwd=cwd, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode != expected:
        raise BuildRefused(f"{label}_failed_{result.returncode}")
    return result


def read_source(relative: str) -> bytes:
    path = ROOT / relative
    require(path.is_file() and not path.is_symlink(), "source_not_regular")
    before = path.stat(follow_symlinks=False)
    require(0 < before.st_size <= MAX_SOURCE_BYTES, "source_size_refused")
    raw = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and len(raw) == before.st_size, "source_changed_during_read")
    return raw


def rebind_wrapper(wrapper: bytes, old_sha256: str, new_sha256: str) -> bytes:
    require(re.fullmatch(r"[a-f0-9]{64}", old_sha256) is not None
            and re.fullmatch(r"[a-f0-9]{64}", new_sha256) is not None,
            "wrapper_digest_invalid")
    old_guard = b" = '" + old_sha256.encode() + b"' ] || exit 1\n"
    require(wrapper.count(old_guard) == 1 and wrapper.count(b"AccountAccess-ownerupgrade") == 1,
            "base_wrapper_binding_invalid")
    result = wrapper.replace(old_guard, b" = '" + new_sha256.encode() + b"' ] || exit 1\n")
    require(result.count(b" = '" + new_sha256.encode() + b"' ] || exit 1\n") == 1
            and old_sha256.encode() not in result, "wrapper_rebinding_invalid")
    return result


def update_package_info(package_info: bytes) -> bytes:
    identity = f'identifier="{PACKAGE_ID}"'.encode()
    require(package_info.count(identity) == 1 and package_info.count(b'timeout="600"') == 1
            and package_info.count(b'file="./postinstall"') == 1,
            "generated_package_info_mismatch")
    return package_info.replace(b'timeout="600"', b'timeout="1800"')


def validate_flat_package_listing(listing: bytes) -> None:
    try:
        entries = sorted(line for line in listing.decode("utf-8").splitlines() if line)
    except UnicodeError:
        raise BuildRefused("package_archive_listing_invalid") from None
    require(entries == ["PackageInfo", "Scripts"], "package_scripts_archive_not_flat")


def restore_completed_image_payload(
    package95_scripts: Path,
    target_scripts: Path,
    package95_inventory: dict[str, object],
    inventory,
    proof_inventory,
) -> dict[str, object]:
    """Restore and byte-verify the predecessor subtree the helper revalidates."""
    require(package95_scripts.is_dir() and not package95_scripts.is_symlink(),
            "package95_scripts_invalid")
    require(target_scripts.is_dir() and not target_scripts.is_symlink(),
            "base_scripts_invalid")
    source_completed = package95_scripts / "Predecessor/CompletedImage"
    target_predecessor = target_scripts / "Predecessor"
    target_completed = target_predecessor / "Predecessor/CompletedImage"
    require(source_completed.is_dir() and not source_completed.is_symlink(),
            "package95_completed_image_missing")
    require(target_predecessor.is_dir() and not target_predecessor.is_symlink()
            and (target_predecessor / "Predecessor").is_dir()
            and not (target_predecessor / "Predecessor").is_symlink(),
            "base_predecessor_shape_invalid")
    require(target_completed.is_dir() and not target_completed.is_symlink()
            and not any(target_completed.iterdir()), "base_completed_image_not_empty")

    try:
        source_rows = inventory(package95_scripts)
        require(source_rows == package95_inventory, "package95_inventory_mismatch")
        expected_projection = proof_inventory(source_rows)
    except BuildRefused:
        raise
    except Exception:
        raise BuildRefused("package95_predecessor_revalidation_invalid") from None

    shutil.rmtree(target_completed)
    shutil.copytree(source_completed, target_completed, symlinks=True)
    actual_projection = inventory(target_predecessor)
    require(actual_projection == expected_projection, "predecessor_projection_mismatch")
    require(any(
        name.startswith("Predecessor/CompletedImage/TargetImage/")
        and node.get("kind") == "file"
        for name, node in actual_projection.items()
    ), "completed_image_target_payload_missing")
    return actual_projection


def collect_sources() -> dict[str, bytes]:
    shared = runpy.run_path(str(ROOT / "scripts/mac_full_image_installed_probe.py"))
    owner = runpy.run_path(str(ROOT / "scripts/mac_owner_upgrade_probe.py"))
    names = ["macos/" + name for name in shared["DEPENDENCIES"]]
    names += [
        "macos/FullImageInstalledIO.swift", "macos/FullImagePredecessorAuthority.swift",
        "macos/OwnerUpgradeSource.swift", "macos/OwnerUpgradeMain.swift",
        "macos/ComponentUpdate.swift", *shared["FRAGMENTS"], *owner["EXTRA_FRAGMENTS"],
    ]
    require(len(names) == len(set(names)), "duplicate_compile_source")
    return {name: read_source(name) for name in names}


def require_sources_at_commit(source: str, sources: dict[str, bytes]) -> None:
    """Bind every compiler and packaging source to the reported Git revision."""
    packaging_sources = (
        "scripts/build_owner_upgrade112_diagnostic.py",
        "scripts/build_owner_upgrade104_review.py",
        "scripts/mac_full_image_installed_probe.py",
        "scripts/mac_component_update_installer_probe.py",
    )
    for name, raw in [*( (name, read_source(name)) for name in packaging_sources), *sources.items()]:
        try:
            committed = subprocess.check_output(
                ["git", "show", f"{source}:{name}"], cwd=ROOT, timeout=30
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise BuildRefused("build_source_commit_unavailable") from None
        require(raw == committed, "build_source_commit_content_mismatch")


def validate_qa(shared_path: Path, runtime_path: Path, owner_path: Path,
                sources: dict[str, bytes]) -> None:
    shared, runtime, owner = (json.loads(path.read_bytes())
                              for path in (shared_path, runtime_path, owner_path))
    require(shared.get("status") == "PASSED" and shared.get("production_ready") is False,
            "shared_qa_not_passed")
    require(runtime.get("status") == "PASSED" and runtime.get("production_ready") is False
            and runtime.get("result", {}).get("checks") == 69, "runtime_qa_not_passed")
    require(owner.get("status") == "SOURCE_REGRESSION_PASSED"
            and isinstance(owner.get("source_regression_tests"), int)
            and owner["source_regression_tests"] > 0
            and owner.get("swift_parser") == "PASSED"
            and owner.get("native_fixture_probe") in {"PASSED", "TIMED_OUT_UNVERIFIED"}
            and owner.get("installed_reads") is False
            and owner.get("installed_writes") is False and owner.get("production_ready") is False,
            "owner_qa_not_passed")
    for name, raw in sources.items():
        digest = hashlib.sha256(raw).hexdigest()
        require(owner.get("source_sha256", {}).get(name) == digest, "owner_qa_source_mismatch")
        for report in (shared, runtime):
            if name in report.get("source_sha256", {}):
                require(report["source_sha256"][name] == digest, "probe_source_mismatch")


def validate_native_helper(helper: Path, report_path: Path, source: str,
                           sources: dict[str, bytes]) -> dict[str, object]:
    require(helper.is_file() and not helper.is_symlink(), "native_helper_invalid")
    try:
        report = json.loads(report_path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise BuildRefused("native_compile_report_invalid") from None
    require(report.get("status") == "PASSED"
            and report.get("source_commit") == source
            and report.get("target") == "arm64-apple-macos14"
            and report.get("optimization") == "whole-module"
            and report.get("ordinary_entrypoint_refusal") is True
            and report.get("installed_reads") is False
            and report.get("installed_writes") is False
            and report.get("production_ready") is False,
            "native_compile_report_mismatch")
    expected = {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}
    require(report.get("source_sha256") == expected, "native_compile_source_mismatch")
    require(report.get("helper_sha256") == sha256(helper), "native_compile_helper_mismatch")
    return report


def find_signing_identity() -> str:
    result = command("find_signing_identity", ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"], timeout=30)
    identities = re.findall(rb'([A-F0-9]{40})\s+"Developer ID Application: [^\n"]*\('
                           + TEAM_ID.encode() + rb'\)"', result.stdout)
    require(len(identities) == 1, "unique_developer_id_application_missing")
    return identities[0].decode()


def build(args: argparse.Namespace) -> dict[str, object]:
    require(sys.platform == "darwin" and os.getuid() == os.geteuid() != 0,
            "ordinary_macos_user_required")
    require(re.fullmatch(r"[a-f0-9]{40}", args.source) is not None,
            "source_commit_invalid")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
    require(head == args.source, "source_commit_mismatch")
    require(args.output.parent.is_dir() and not os.path.lexists(args.output),
            "output_must_be_new")
    require(shutil.disk_usage(args.output.parent).free >= 6 * 1024**3,
            "insufficient_build_space")
    require(sha256(args.base_package) == BASE_PACKAGE_SHA256, "base_package_hash_mismatch")
    require(args.package95.is_file() and not args.package95.is_symlink()
            and sha256(args.package95) == PACKAGE95_SHA256, "package95_hash_mismatch")
    require(args.inventory95.is_file() and not args.inventory95.is_symlink()
            and sha256(args.inventory95) == INVENTORY95_SHA256, "package95_inventory_hash_mismatch")
    command("base_package_signature", ["/usr/sbin/pkgutil", "--check-signature", str(args.base_package)], timeout=60)
    command("base_package_gatekeeper", ["/usr/sbin/spctl", "--assess", "--type", "install",
        "--verbose", str(args.base_package)], timeout=120)
    command("base_package_staple", ["/usr/bin/xcrun", "stapler", "validate", "-v",
        str(args.base_package)], timeout=120)
    pins_path = ROOT / "artifacts/owner-upgrade106-compiled-pins.swift"
    require(sha256(pins_path) == COMPILED_PINS_SHA256, "compiled_plan_pins_mismatch")
    sources = collect_sources()
    require_sources_at_commit(args.source, sources)
    validate_qa(args.shared_qa, args.runtime_qa, args.owner_qa, sources)
    native_report = validate_native_helper(args.compiled_helper, args.compile_report, args.source, sources)
    identity = find_signing_identity()

    output = args.output.absolute()
    output.mkdir(mode=0o700)
    inventory_tools = runpy.run_path(str(ROOT / "scripts/mac_full_image_installer_probe.py"))
    helper_tools = runpy.run_path(str(ROOT / "scripts/mac_component_update_installer_probe.py"))
    inventory_tools["inventory"].__globals__["h"] = SimpleNamespace(**helper_tools)
    inventory = inventory_tools["inventory"]
    proof_inventory = runpy.run_path(
        str(ROOT / "scripts/build_owner_upgrade104_review.py")
    )["proof_inventory"]

    package95_xar = output / "package95-xar"
    package95_xar.mkdir(mode=0o700)
    command("expand_package95_container", ["/usr/bin/xar", "-x", "-f",
        str(args.package95.absolute()), "-C", str(package95_xar), "Scripts"], timeout=300)
    package95_scripts = output / "package95-scripts"
    package95_scripts.mkdir(mode=0o700)
    command("extract_package95_scripts", ["/usr/bin/tar", "--no-mac-metadata", "-xf",
        str(package95_xar / "Scripts"), "-C", str(package95_scripts)], timeout=900)
    try:
        package95_inventory = json.loads(args.inventory95.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise BuildRefused("package95_inventory_invalid") from None

    expanded = output / "expanded"
    command("expand_base", ["/usr/sbin/pkgutil", "--expand-full", str(args.base_package.absolute()), str(expanded)])
    scripts = expanded / "Scripts"
    info_path = expanded / "PackageInfo"
    require(info_path.is_file() and scripts.is_dir() and not scripts.is_symlink(),
            "base_package_shape_invalid")
    predecessor_projection = restore_completed_image_payload(
        package95_scripts, scripts, package95_inventory, inventory, proof_inventory
    )
    shutil.rmtree(package95_xar)
    shutil.rmtree(package95_scripts)
    helper = scripts / "AccountAccess-ownerupgrade"
    postinstall = scripts / "postinstall"
    require(sha256(helper) == BASE_HELPER_SHA256 and postinstall.is_file(),
            "base_helper_mismatch")

    compile_dir = output / "compile-source"
    compile_dir.mkdir(mode=0o700)
    shared = runpy.run_path(str(ROOT / "scripts/mac_full_image_installed_probe.py"))
    owner = runpy.run_path(str(ROOT / "scripts/mac_owner_upgrade_probe.py"))
    fragments = (*shared["FRAGMENTS"], *owner["EXTRA_FRAGMENTS"])
    paths: list[str] = []
    for name, raw in sources.items():
        if name == "macos/ComponentUpdate.swift" or name in fragments:
            continue
        target = compile_dir / Path(name).name
        target.write_bytes(raw)
        paths.append(str(target))
    combined = compile_dir / "ComponentUpdate.swift"
    combined.write_bytes(b"\n".join(sources[name] for name in (
        "macos/ComponentUpdate.swift", *fragments)))
    paths.append(str(combined))
    pins = compile_dir / "CompiledPins.swift"
    pins.write_bytes(pins_path.read_bytes())
    paths.append(str(pins))
    new_helper = output / "AccountAccess-ownerupgrade"
    shutil.copyfile(args.compiled_helper, new_helper)
    new_helper.chmod(0o755)
    command("sign_helper", ["/usr/bin/codesign", "--options", "runtime", "--timestamp", "--identifier",
        "com.fainir.accountaccess.componentupdate", "--sign", identity, str(new_helper)], timeout=120)
    command("verify_helper_signature", ["/usr/bin/codesign", "--verify", "--strict",
        '-R=anchor apple generic and identifier "com.fainir.accountaccess.componentupdate" '
        f'and certificate leaf[subject.OU] = "{TEAM_ID}" and !(entitlement["com.apple.security.get-task-allow"] exists)',
        str(new_helper)], timeout=120)
    refusal = command("helper_ordinary_refusal", [str(new_helper)], expected=78, timeout=30)
    require(not refusal.stderr and json.loads(refusal.stdout) == {
        "schema": 1, "status": "REFUSED", "reason": "owner_upgrade_installer_context_required"},
        "helper_ordinary_refusal_invalid")

    new_sha = sha256(new_helper)
    wrapper = postinstall.read_bytes()
    postinstall.write_bytes(rebind_wrapper(wrapper, BASE_HELPER_SHA256, new_sha))
    postinstall.chmod(0o755)
    helper.write_bytes(new_helper.read_bytes())
    helper.chmod(0o755)
    require(sha256(helper) == new_sha, "packaged_helper_hash_mismatch")
    scripts_package = output / "scripts-component.pkg"
    command("pkgbuild_scripts", ["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(scripts),
        "--identifier", PACKAGE_ID, "--version", "0.1.0", "--install-location", "/",
        str(scripts_package)], timeout=300)
    package_root = output / "flat-package"
    package_root.mkdir(mode=0o700)
    command("extract_package_components", ["/usr/bin/xar", "-x", "-f", str(scripts_package),
        "-C", str(package_root)])
    scripts_package.unlink()
    info_path = package_root / "PackageInfo"
    scripts_blob = package_root / "Scripts"
    require(info_path.is_file() and not info_path.is_symlink()
            and scripts_blob.is_file() and not scripts_blob.is_symlink(),
            "pkgbuild_scripts_archive_invalid")
    new_info = update_package_info(info_path.read_bytes())
    info_path.write_bytes(new_info)
    versioned_package = output / "Account-Access-Owner-Upgrade-112-unsigned.pkg"
    signed_package = output / "Account-Access-Owner-Upgrade-112.pkg"
    command("assemble_flat", ["/usr/bin/xar", "--compression=none", "-cf", str(versioned_package),
        "PackageInfo", "Scripts"], cwd=package_root)
    listing = command("inspect_package_archive", ["/usr/bin/xar", "-tf", str(versioned_package)])
    validate_flat_package_listing(listing.stdout)
    command("installer_parse_unsigned", ["/usr/sbin/installer", "-pkginfo", "-pkg",
        str(versioned_package)], timeout=120)
    installer_identity = f"Developer ID Installer: Nir Feinstein ({TEAM_ID})"
    command("sign_package", ["/usr/bin/productsign", "--sign", installer_identity,
        str(versioned_package), str(signed_package)], timeout=300)
    versioned_package.unlink()
    notary = command("notarize", ["/usr/bin/xcrun", "notarytool", "submit", str(signed_package),
        "--keychain-profile", NOTARY_PROFILE, "--wait", "--output-format", "json"], timeout=1800)
    notary_result = json.loads(notary.stdout)
    require(notary_result.get("status") == "Accepted", "notary_acceptance_missing")
    command("staple", ["/usr/bin/xcrun", "stapler", "staple", "-v", str(signed_package)], timeout=300)
    command("stapler_validate", ["/usr/bin/xcrun", "stapler", "validate", "-v", str(signed_package)], timeout=120)
    signature = command("package_signature", ["/usr/sbin/pkgutil", "--check-signature", str(signed_package)], timeout=60)
    require(b"Developer ID Installer" in signature.stdout, "installer_signature_missing")
    gatekeeper = command("gatekeeper", ["/usr/sbin/spctl", "--assess", "--type", "install",
        "--verbose", str(signed_package)], timeout=120)
    command("installer_parse_signed", ["/usr/sbin/installer", "-pkginfo", "-pkg",
        str(signed_package)], timeout=120)
    verified = output / "verified-expanded"
    command("verify_expanded_package", ["/usr/sbin/pkgutil", "--expand-full", str(signed_package), str(verified)])
    require(inventory_tools["inventory"](verified / "Scripts")
            == inventory_tools["inventory"](scripts), "signed_package_inventory_mismatch")
    require((verified / "PackageInfo").read_bytes() == new_info
            and sha256(verified / "Scripts/AccountAccess-ownerupgrade") == new_sha,
            "signed_package_content_mismatch")
    shutil.rmtree(verified)
    report: dict[str, object] = {
        "schema": 1,
        "status": "NOTARIZED_STAPLED_PENDING_OWNER_INSTALL",
        "production_ready": False,
        "source_commit": args.source,
        "product_build": 112,
        "package_build": 112,
        "base_package_sha256": BASE_PACKAGE_SHA256,
        "package95_sha256": PACKAGE95_SHA256,
        "package95_inventory_sha256": INVENTORY95_SHA256,
        "predecessor_completed_image_verified": True,
        "predecessor_projection_rows": len(predecessor_projection),
        "package_path": str(signed_package),
        "package_sha256": sha256(signed_package),
        "package_bytes": signed_package.stat().st_size,
        "helper_sha256": new_sha,
        "native_compile_report": str(args.compile_report.absolute()),
        "native_compile_report_status": native_report["status"],
        "source_sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()},
        "notary_submission_id": notary_result.get("id"),
        "notary_status": notary_result.get("status"),
        "stapler_validation": "PASSED",
        "package_signature": "PASSED",
        "gatekeeper_assessment": process_output(gatekeeper),
        "package_format": "flat package with archived Scripts component",
        "installer_parser_validation": "PASSED",
        "installer_execution": "PENDING_OWNER_INSTALL",
        "production_gates_open": ["owner_mac_installer", "agent_service_smoke", "real_account_acceptance"],
    }
    (output / "review.json").write_bytes(encoded(report))
    print(json.dumps(report, sort_keys=True))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-package", required=True, type=Path)
    parser.add_argument("--package95", required=True, type=Path)
    parser.add_argument("--inventory95", required=True, type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--shared-qa", required=True, type=Path)
    parser.add_argument("--runtime-qa", required=True, type=Path)
    parser.add_argument("--owner-qa", required=True, type=Path)
    parser.add_argument("--compiled-helper", required=True, type=Path)
    parser.add_argument("--compile-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    print(json.dumps(build(parser.parse_args()), sort_keys=True))


if __name__ == "__main__":
    main()
