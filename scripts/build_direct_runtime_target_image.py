"""Build a pinned source-current public image for the direct updater.

This is an offline image preparation tool. It copies the reviewed build-118
public image, replaces only signed owner/native code and the Account Access
Python project, recalculates derived metadata and the public manifest, and
never opens Installer or touches an installed Account Access path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

from installer import install
from installer.sources import WheelFile

ROOT = Path(__file__).resolve().parents[1]
BASE_IMAGE_SHA256 = "bb14a99941c7a82938cd0e9b3f91a16ab975e6cdd61a30741d29726a7f7bed38"
BASE_IMAGE_BUILD = 118
TARGET_APP_BUILD = 119
TEAM = "WBULD6N4NQ"
VERSION = "0.8.0"
ARCHITECTURE = "arm64"
SUPPORT_RELATIVE = Path("Library/Application Support/Account Access")
PROJECT = "account_access"
DIST_INFO = "account_access-0.8.0.dist-info"


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def decode_json(path: Path, maximum: int = 2_000_000) -> dict:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "unsafe_json_input")
    value = json.loads(path.read_bytes())
    require(type(value) is dict, "json_object_required")
    return value


def _plain_owned_tree(path: Path) -> None:
    require(path.is_dir() and not path.is_symlink(), "package_tree_required")
    for current, directories, files in os.walk(path, followlinks=False):
        for name in directories + files:
            node = Path(current) / name
            info = node.lstat()
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "package_link_refused")


def replace_project_wheel(runtime: Path, wheel: Path, wheelhouse: Path) -> tuple[str, ...]:
    """Install only the audited pure-Python project wheel without running it."""
    from macos.payload_audit import wheel_entries
    from macos.runtime_image import Destination

    require(runtime.is_dir() and not runtime.is_symlink(), "runtime_tree_required")
    require(wheelhouse.is_dir() and not wheelhouse.is_symlink(), "wheelhouse_required")
    require(wheel.name == f"account_access-{VERSION}-py3-none-any.whl", "project_wheel_identity_mismatch")
    with zipfile.ZipFile(wheel) as archive:
        entries = list(wheel_entries(archive))
        paths = {entry.filename for entry in entries if not entry.is_dir()}
        require(paths and all(path.startswith((PROJECT + "/", DIST_INFO + "/")) for path in paths),
                "project_wheel_contents_refused")
        require(not any(path.lower().endswith((".so", ".dylib", ".bundle")) for path in paths),
                "project_wheel_native_code_refused")

    site = runtime / "lib/python3.12/site-packages"
    scripts = runtime / "bin"
    require(site.is_dir() and scripts.is_dir() and not site.is_symlink() and not scripts.is_symlink(),
            "runtime_python_layout_invalid")
    old_package, old_info = site / PROJECT, site / DIST_INFO
    require(old_package.is_dir() and old_info.is_dir() and not old_package.is_symlink()
            and not old_info.is_symlink(), "existing_project_install_invalid")
    _plain_owned_tree(old_package)
    _plain_owned_tree(old_info)

    project_wheel = wheelhouse / wheel.name
    if os.path.lexists(project_wheel):
        require(project_wheel.is_file() and not project_wheel.is_symlink(), "project_wheelhouse_entry_invalid")
    shutil.copy2(wheel, project_wheel)
    require(sha(project_wheel) == sha(wheel), "project_wheelhouse_copy_mismatch")

    with tempfile.TemporaryDirectory(prefix="account-access-project-wheel-") as temporary:
        stage_runtime = Path(temporary) / "runtime"
        (stage_runtime / "lib/python3.12/site-packages").mkdir(parents=True)
        (stage_runtime / "bin").mkdir()
        with WheelFile.open(wheel) as source:
            source.validate_record(validate_contents=True)
            install(source, Destination(stage_runtime, "account-access"),
                    additional_metadata={"INSTALLER": b"account-access-static-runtime-image 1\n"})
        stage_site = stage_runtime / "lib/python3.12/site-packages"
        new_package, new_info = stage_site / PROJECT, stage_site / DIST_INFO
        new_scripts = sorted(path.name for path in (stage_runtime / "bin").iterdir())
        require(new_package.is_dir() and new_info.is_dir(), "installed_project_wheel_incomplete")
        require(new_scripts and all((stage_runtime / "bin" / name).is_file()
                                   and not (stage_runtime / "bin" / name).is_symlink()
                                   for name in new_scripts), "installed_project_scripts_invalid")
        require(all((scripts / name).is_file() and not (scripts / name).is_symlink()
                    for name in new_scripts), "existing_project_script_missing")
        shutil.rmtree(old_package)
        shutil.rmtree(old_info)
        shutil.copytree(new_package, old_package, symlinks=False)
        shutil.copytree(new_info, old_info, symlinks=False)
        for name in new_scripts:
            shutil.copy2(stage_runtime / "bin" / name, scripts / name)
    return tuple(new_scripts)


def update_derived_metadata(payload: Path, project_sha256: str) -> None:
    from account_access.package_manifest import inventory_digest
    from macos.runtime_prepare import tree_digest

    requirements = payload / "package-requirements.txt"
    raw = requirements.read_bytes()
    old, count = re.subn(rb"(?m)^account-access==0\.8\.0 --hash=sha256:[a-f0-9]{64}$",
                         b"account-access==0.8.0 --hash=sha256:" + project_sha256.encode(), raw)
    require(count == 1, "project_requirement_pin_missing_or_ambiguous")
    requirements.write_bytes(old)

    prep_path = payload / "runtime-preparation.json"
    prep = decode_json(prep_path, 2_000_000)
    project = prep.get("project_wheel")
    require(type(project) is dict and project.get("filename") == f"account_access-{VERSION}-py3-none-any.whl",
            "runtime_project_wheel_receipt_invalid")
    project["sha256"] = project_sha256
    prep_path.write_text(json.dumps(prep, sort_keys=True, indent=2) + "\n")

    runtime = payload / "runtime"
    image_path = payload / "runtime-image.json"
    image = decode_json(image_path, 2_000_000)
    rows = image.get("wheels")
    require(type(rows) is list, "runtime_image_wheel_inventory_invalid")
    matches = [row for row in rows if type(row) is dict and row.get("name") == "account-access"]
    require(len(matches) == 1 and matches[0].get("version") == VERSION, "runtime_project_wheel_inventory_invalid")
    matches[0]["sha256"] = project_sha256
    image["runtime_sha256"] = tree_digest(runtime)
    image["runtime_manifest_sha256"] = inventory_digest(runtime)
    image_path.write_text(json.dumps(image, sort_keys=True, indent=2) + "\n")


def command(argv: list[str]) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"})
    require(result.returncode == 0, "signature_verification_failed")
    return result


def safe_error_reason(exc: BaseException) -> str:
    """Expose only closed, machine-safe reason codes for a failed build step."""
    reason = str(exc)
    return reason if re.fullmatch(r"[a-z0-9_:-]{1,96}", reason) else "direct_runtime_target_image_build_refused"


def build(args) -> dict:
    require(sys.platform == "darwin" and os.getuid() == os.geteuid() != 0, "ordinary_mac_required")
    require(re.fullmatch(r"[a-f0-9]{40}", args.source) is not None, "source_revision_invalid")
    require(re.fullmatch(r"[a-f0-9]{40}", args.target_source) is not None, "target_source_revision_invalid")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=30).decode().strip()
            == args.source, "source_revision_mismatch")
    ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", args.target_source, args.source],
                              cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    require(ancestry.returncode == 0, "target_source_not_in_builder_history")
    require(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                        cwd=ROOT, timeout=30).strip(), "source_tree_not_clean")
    source = args.source_image.absolute()
    manifest_path = args.source_manifest.absolute()
    output = args.output.absolute()
    require(source.is_dir() and not source.is_symlink() and manifest_path.is_file()
            and not manifest_path.is_symlink(), "reviewed_build118_image_required")
    require(output.parent.is_dir() and not os.path.lexists(output)
            and not output.is_relative_to(source) and not source.is_relative_to(output), "new_output_required")

    from account_access.package_manifest import build as make_manifest
    from account_access.system_provision import signature
    from macos.system_package import inspect_app
    from macos.payload_audit import audit_payload

    original_manifest = manifest_path.read_bytes()
    require(hashlib.sha256(original_manifest).hexdigest() == BASE_IMAGE_SHA256, "source_manifest_pin_mismatch")
    require(make_manifest(source, VERSION, ARCHITECTURE) == original_manifest, "source_image_manifest_mismatch")

    app = args.app.absolute()
    native = args.native.absolute()
    wheel = args.wheel.absolute()
    version, team, embedded_wheel, _requirements = inspect_app(app, development=False)
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    require(version == VERSION and team == TEAM and info.get("CFBundleVersion") == str(TARGET_APP_BUILD),
            "current_signed_build119_app_required")
    require(embedded_wheel.read_bytes() == wheel.read_bytes(), "embedded_project_wheel_mismatch")
    rows = {}
    for key, name, identifier in [
        ("owner", "app", "com.fainir.accountaccess"),
        ("broker", "AccountAccess-broker", "com.fainir.accountaccess.broker"),
        ("bootstrap", "AccountAccess-bootstrap", "com.fainir.accountaccess.bootstrap"),
    ]:
        path = app if key == "owner" else native / name
        rows[key] = signature(path, identifier, fixture=False)
        require(rows[key]["team"] == TEAM, "current_payload_team_mismatch")
    installer_verifier = native / "AccountAccess-installerverify"
    require(signature(installer_verifier, "com.fainir.accountaccess.installerverify")["team"] == TEAM,
            "current_installer_verifier_signature_invalid")

    output.mkdir(mode=0o700)
    shutil.copytree(source, output, symlinks=True, dirs_exist_ok=True)
    payload = output / SUPPORT_RELATIVE
    owner_app = payload / "owner.app"
    require(owner_app.is_dir() and not owner_app.is_symlink(), "source_owner_app_invalid")
    shutil.rmtree(owner_app)
    shutil.copytree(app, owner_app, symlinks=True)
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", str(owner_app)])

    bin_dir = payload / "bin"
    for name in ["AccountAccess-broker", "AccountAccess-bootstrap", "AccountAccess-installerverify"]:
        target = bin_dir / name
        require(target.is_file() and not target.is_symlink(), "source_native_helper_invalid")
        shutil.copy2(native / name, target)

    project_wheel = owner_app / "Contents/Resources/account_access.whl"
    project_sha = sha(project_wheel)
    require(project_sha == sha(wheel), "current_wheel_hash_mismatch")
    scripts = replace_project_wheel(payload / "runtime", wheel, payload / "wheels")
    update_derived_metadata(payload, project_sha)

    identity_path = payload / "package-identity.json"
    identity = decode_json(identity_path)
    require(identity.get("schema") == 1 and identity.get("managed_by") == "account-access-package-identity-v1",
            "source_package_identity_invalid")
    identity["signatures"] = rows
    identity_path.write_text(json.dumps(identity, sort_keys=True) + "\n")

    manifest = make_manifest(output, VERSION, ARCHITECTURE)
    # The verifier reads only public manifest bytes; it performs no service or
    # filesystem publication operation in this inspection mode.
    verifier = subprocess.run([str(bin_dir / "AccountAccess-installerverify"), "--inspect-manifest"],
        input=manifest, capture_output=True, timeout=60,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"})
    require(verifier.returncode == 0 and len(verifier.stdout) <= 4096, "target_manifest_native_check_failed")
    summary = json.loads(verifier.stdout)
    from macos.system_package import manifest_counts
    require(summary == {"schema": 1, "status": "INSPECTED", "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                        **manifest_counts(manifest)}, "target_manifest_native_check_mismatch")
    audit = audit_payload([owner_app, payload / "python", payload / "runtime", payload / "browsers", bin_dir],
        sorted((payload / "wheels").glob("*.whl")), ARCHITECTURE, command, development=False)
    require(make_manifest(source, VERSION, ARCHITECTURE) == original_manifest, "source_image_changed")
    require(not os.path.lexists(args.manifest_output), "new_manifest_required")
    args.manifest_output.write_bytes(manifest)
    report = {"schema": 1, "status": "TARGET_IMAGE_QUALIFIED", "builder_commit": args.source,
        "target_source_commit": args.target_source,
        "source_image_build": BASE_IMAGE_BUILD,
        "source_manifest_sha256": BASE_IMAGE_SHA256, "target_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "target_manifest": str(args.manifest_output), "target_manifest_bytes": len(manifest),
        "owner_app_build": TARGET_APP_BUILD, "project_wheel_sha256": project_sha,
        "project_wheel_runtime_scripts": list(scripts), "developer_team": TEAM,
        "native_manifest_preflight": True, "native_payload_audit": audit,
        "source_image_unchanged": True, "installer_executed": False, "installed": False,
        "production_ready": False}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    require(not os.path.lexists(args.report), "new_report_required")
    args.report.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source-image", "source-manifest", "app", "native", "wheel", "output", "report", "manifest-output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target-source", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "REFUSED", "reason": safe_error_reason(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
