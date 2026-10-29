"""Build the exact signed, notarized build-110 to build-116 Mac updater.

This builder reads public package and manifest inputs, compiles the fixed root
helper, and produces a reviewable installer. It never runs Installer or writes
to an installed Account Access path.
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
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET_PACKAGE_SHA256 = "02eaa0c5ace1354208a173cf260b4f1236357ce0cae5671570918b39ea9f3942"
PLAN_SHA256 = "f15129413f71a65e61a53f690b6676306ae905b3b8ba4e5df966c70f423287d5"
BEFORE_SHA256 = "568c79ca3b45ffc357bc5af2b420d481e729630b0120dc6d0058c1a396ad21b1"
AFTER_SHA256 = "78113e53f553cdec0bfb9d0744406a18baaaa3327e1be834af5b45b74c3926aa"
TARGET_SOURCE = "51f9ea5e11434ccdac25e955787de5e27e034eec"
COMPONENT_ID = "com.fainir.accountaccess.directruntimeupgrade117"
HELPER_ID = "com.fainir.accountaccess.componentupdate"
TEAM = "WBULD6N4NQ"
SUPPORT_RELATIVE = "Library/Application Support/Account Access"
RESOURCE_NAMES = {"RuntimeUpgradePlan.json", "BaseManifest.json", "TargetManifest.json", "BaseIdentity.json",
    "TargetIdentity.json", "TargetImage", "AccountAccess-runtimeupgrade", "postinstall"}


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def run(argv, *, timeout=120, cwd=ROOT):
    return subprocess.run(list(map(str, argv)), cwd=cwd, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=timeout, check=False)


def checked(argv, *, timeout=120, cwd=ROOT):
    result = run(argv, timeout=timeout, cwd=cwd)
    require(result.returncode == 0, "command_failed:" + Path(str(argv[0])).name)
    return result.stdout


def cpio_listing(payload: Path) -> set[str]:
    gzip = subprocess.Popen(["/usr/bin/gzip", "-dc", str(payload)], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    assert gzip.stdout is not None
    cpio = subprocess.Popen(["/usr/bin/cpio", "-it"], stdin=gzip.stdout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    gzip.stdout.close()
    listing, cpio_error = cpio.communicate(timeout=600)
    gzip_error = gzip.communicate(timeout=600)[1]
    require(gzip.returncode == 0 and cpio.returncode == 0 and not gzip_error and len(listing) <= 16 * 1024 * 1024,
        "cpio_listing_failed")
    return {name for line in listing.splitlines() if (name := line.decode("utf-8", errors="strict").removeprefix("./")) not in ("", ".")}


def read_json(path: Path, maximum: int):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "unsafe_json_input")
    return json.loads(path.read_bytes())


def git_bytes(*args) -> bytes:
    result = checked(["git", *args], timeout=60)
    return result


def public_payload_inventory(root: Path):
    nodes = {}
    require(root.is_dir() and not root.is_symlink(), "target_support_root_invalid")
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        info = base.lstat()
        require(stat.S_ISDIR(info.st_mode), "target_payload_symlink_refused")
        relative = base.relative_to(root).as_posix()
        if relative == ".":
            relative = ""
        nodes[relative] = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode)}
        for name in list(directories):
            path = base / name
            child = path.lstat()
            if stat.S_ISLNK(child.st_mode):
                nodes[path.relative_to(root).as_posix()] = {"kind": "symlink", "target": os.readlink(path)}
                directories.remove(name)
            else:
                require(stat.S_ISDIR(child.st_mode), "target_payload_node_invalid")
        for name in files:
            path = base / name
            child = path.lstat()
            relative_file = path.relative_to(root).as_posix()
            if stat.S_ISLNK(child.st_mode):
                nodes[relative_file] = {"kind": "symlink", "target": os.readlink(path)}
            else:
                require(stat.S_ISREG(child.st_mode) and child.st_size <= 1024**3, "target_payload_file_invalid")
                nodes[relative_file] = {"kind": "file", "mode": stat.S_IMODE(child.st_mode),
                    "size": child.st_size, "sha256": file_digest(path)}
    return nodes


def expected_sparse_nodes(plan: dict, after: dict):
    image = runpy.run_path(str(ROOT / "macos/full_image_update.py"))
    tree = after["roots"][image["SUPPORT"]]
    included = {""}
    for unit in plan["units"]:
        if unit["kind"] == "public_tree":
            if unit["after"] is not None:
                included.update(unit["after"])
        elif unit["after"] is not None:
            included.add(unit["path"])
    for path in tuple(included):
        parts = path.split("/") if path else []
        for count in range(1, len(parts)):
            included.add("/".join(parts[:count]))
    require(included <= tree.keys(), "sparse_plan_path_absent_from_target")
    return {path: tree[path] for path in included}


def create_sparse_directories(target_image: Path, inventory: dict[str, dict]) -> None:
    support = target_image / SUPPORT_RELATIVE
    for relative, node in sorted(inventory.items(), key=lambda row: (row[0].count("/"), row[0])):
        if node["kind"] != "directory":
            continue
        path = support / relative if relative else support
        if os.path.lexists(path):
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode), "sparse_directory_attachment_refused")
        else:
            path.mkdir(mode=node["mode"], parents=False)
        require(not path.is_symlink(), "sparse_directory_symlink_refused")
        os.chmod(path, node["mode"], follow_symlinks=False)


def sparse_cpio_members(inventory: dict[str, dict]) -> list[str]:
    public_root = "./PublicImage/" + SUPPORT_RELATIVE
    # Selecting directories makes BSD cpio recurse through their contents.
    # Only exact file/symlink archive members belong in the extraction list.
    members = sorted(public_root + "/" + relative for relative, node in inventory.items()
                     if relative and node["kind"] in {"file", "symlink"})
    require(members, "sparse_target_has_no_payload_files")
    return members


def extract_sparse_target(package: Path, expanded: Path, scripts: Path, target_manifest: dict, plan: dict):
    payloads = list(expanded.glob("payload.pkg/Scripts"))
    require(len(payloads) == 1 and stat.S_ISREG(payloads[0].lstat().st_mode), "target_cpio_payload_missing")
    inventory = expected_sparse_nodes(plan, target_manifest)
    # -d creates parent paths, and the manifest below reconstructs the exact
    # sparse directory inventory without selecting recursive directory names.
    patterns = sparse_cpio_members(inventory)
    extracted = scripts.parent / "target-extract"
    extracted.mkdir(mode=0o700)
    gzip = subprocess.Popen(["/usr/bin/gzip", "-dc", str(payloads[0])], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    assert gzip.stdout is not None
    cpio = subprocess.run(["/usr/bin/cpio", "-idm", "--", *patterns], cwd=extracted,
        stdin=gzip.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=False)
    gzip.stdout.close()
    gzip_error = gzip.communicate(timeout=600)[1]
    require(cpio.returncode == 0 and gzip.returncode == 0 and not gzip_error,
        "target_public_delta_extraction_failed")
    public = extracted / "PublicImage"
    target_image = scripts / "TargetImage"
    require(public.is_dir() and not public.is_symlink(), "target_public_image_missing")
    create_sparse_directories(public, inventory)
    shutil.move(str(public), str(target_image))
    support = target_image / SUPPORT_RELATIVE
    actual = public_payload_inventory(support)
    require(actual == inventory, "sparse_target_inventory_mismatch")
    return target_image, support, len(actual), sum(node.get("size", 0) for node in actual.values())


def source_inputs(shared):
    names = ["macos/" + item for item in shared["DEPENDENCIES"]]
    names += ["macos/FullImageInstalledIO.swift", "macos/FullImagePredecessorAuthority.swift",
        "macos/RuntimeUpgradeMain.swift", "macos/ComponentUpdate.swift", *shared["FRAGMENTS"]]
    require(len(names) == len(set(names)), "duplicate_compiler_source")
    return {name: (ROOT / name).read_bytes() for name in names}


def verify_qa(args, sources, plan):
    shared = read_json(args.shared_qa, 16 * 1024 * 1024)
    runtime = read_json(args.runtime_qa, 8 * 1024 * 1024)
    direct = read_json(args.direct_qa, 8 * 1024 * 1024)
    require(shared.get("status") == "PASSED" and shared.get("sources_stable") is True
        and shared.get("guarded_main_refusals") == 6 and shared.get("production_ready") is False,
        "shared_native_qa_not_qualified")
    require(runtime.get("status") == "PASSED" and runtime.get("result", {}).get("checks") == 72
        and runtime.get("installed_reads") is False and runtime.get("production_ready") is False,
        "runtime_native_qa_not_qualified")
    require(direct.get("status") == "PASSED" and direct.get("native", {}).get("units") == 191
        and direct.get("native", {}).get("changed_nodes") == 207 and direct.get("production_ready") is False,
        "direct_native_qa_not_qualified")
    all_hashes = {}
    for report in (shared, runtime, direct):
        for name, value in report.get("source_sha256", {}).items():
            if name in sources:
                require(all_hashes.setdefault(name, value) == value, "qa_source_hashes_disagree")
    for name, raw in sources.items():
        require(all_hashes.get(name) == digest(raw), "qa_does_not_match_build_source")
    require(direct.get("public_inputs_sha256", {}).get("plan.json") == PLAN_SHA256,
        "direct_qa_plan_mismatch")
    require(plan["managed_by"] == "account-access-exact-installed-runtime-delta-v1",
        "direct_plan_marker_mismatch")
    return shared, runtime, direct


def build(args):
    require(sys.platform == "darwin" and os.getuid() == os.geteuid() != 0, "ordinary_mac_required")
    require(re.fullmatch(r"[a-f0-9]{40}", args.source) is not None, "source_revision_invalid")
    require(git_bytes("rev-parse", "HEAD").decode().strip() == args.source, "source_revision_mismatch")
    require(git_bytes("status", "--porcelain").strip() == b"", "source_tree_not_clean")
    output = args.output.absolute()
    require(output.parent.is_dir() and not os.path.lexists(output), "output_must_be_new")
    require(file_digest(args.target_package) == TARGET_PACKAGE_SHA256, "target_package_hash_mismatch")
    require(file_digest(args.plan) == PLAN_SHA256, "plan_hash_mismatch")
    require(re.fullmatch(r"[A-F0-9]{40}", args.application_identity) is not None, "application_identity_invalid")
    shared = runpy.run_path(str(ROOT / "scripts/mac_full_image_installed_probe.py"))
    sources = source_inputs(shared)
    for name, raw in sources.items():
        require(git_bytes("show", args.source + ":" + name) == raw, "source_not_committed")
    shared_qa, runtime_qa, direct_qa = verify_qa(args, sources, json.loads(args.plan.read_bytes()))
    require(file_digest(args.base_manifest) == BEFORE_SHA256, "base_manifest_mismatch")
    require(file_digest(args.base_identity) == "3462087a742f96baab0dbcc5e66e84c1aa408e828f216024529a5d05e7eb7248",
        "base_identity_mismatch")
    before_raw = args.base_manifest.read_bytes()
    old_identity_raw = args.base_identity.read_bytes()
    plan_raw = args.plan.read_bytes()
    import sys as _sys
    _sys.path.insert(0, str(ROOT))
    from macos import direct_runtime_upgrade_plan as direct_planner
    output.mkdir(mode=0o700)
    commands = []
    def command(label, argv, timeout=900, cwd=ROOT):
        result = run(argv, timeout=timeout, cwd=cwd)
        (output / (label + ".stdout")).write_bytes(result.stdout[:4 * 1024 * 1024])
        (output / (label + ".stderr")).write_bytes(result.stderr[:4 * 1024 * 1024])
        commands.append({"name": label, "exit_code": result.returncode})
        (output / "commands.json").write_bytes(encoded(commands))
        require(result.returncode == 0, "build_step_failed:" + label)
        return result.stdout
    command("target-package-signature", ["/usr/sbin/pkgutil", "--check-signature", args.target_package], timeout=60)
    command("target-package-gatekeeper", ["/usr/sbin/spctl", "--assess", "--type", "install", "--verbose", args.target_package], timeout=120)
    expanded = output / "target-expanded"
    command("target-package-expand", ["/usr/sbin/pkgutil", "--expand-full", args.target_package, expanded], timeout=600)
    manifest_candidates = [p for p in expanded.rglob("RecoveryManifest.json") if p.is_file() and not p.is_symlink()]
    require(len(manifest_candidates) == 1 and file_digest(manifest_candidates[0]) == AFTER_SHA256,
        "target_manifest_missing_or_mismatched")
    after_raw = manifest_candidates[0].read_bytes()
    after = json.loads(after_raw)
    identity_candidates = list((expanded / "package-meta" / "PublicImage").rglob("package-identity.json"))
    require(len(identity_candidates) == 1 and not identity_candidates[0].is_symlink(), "target_identity_missing")
    new_identity_raw = identity_candidates[0].read_bytes()
    source_plan = json.loads(plan_raw)
    direct_planner.parse(plan_raw, expected_sha256=PLAN_SHA256, before_manifest=before_raw,
        after_manifest=after_raw, old_identity=old_identity_raw, new_identity=new_identity_raw,
        source_files=source_plan["target_source_files"])
    require(all(digest(git_bytes("show", TARGET_SOURCE + ":" + name)) == file_hash
        for name, file_hash in source_plan["target_source_files"].items()), "target_source_files_mismatch")
    scripts = output / "scripts"
    scripts.mkdir(mode=0o700)
    (scripts / "RuntimeUpgradePlan.json").write_bytes(plan_raw)
    (scripts / "BaseManifest.json").write_bytes(before_raw)
    (scripts / "TargetManifest.json").write_bytes(after_raw)
    (scripts / "BaseIdentity.json").write_bytes(old_identity_raw)
    (scripts / "TargetIdentity.json").write_bytes(new_identity_raw)
    target_image, support, sparse_nodes, sparse_bytes = extract_sparse_target(args.target_package,
        expanded, scripts, after, source_plan)
    require((support / "package-identity.json").read_bytes() == new_identity_raw,
        "target_identity_payload_mismatch")
    shutil.rmtree(expanded)

    code = output / "source"
    code.mkdir(mode=0o700)
    paths = []
    for name, raw in sources.items():
        if name == "macos/ComponentUpdate.swift" or name in shared["FRAGMENTS"]:
            continue
        target = code / Path(name).name
        target.write_bytes(raw)
        paths.append(str(target))
    composed = code / "ComponentUpdate.swift"
    composed.write_bytes(b"\n".join([sources["macos/ComponentUpdate.swift"],
        *(sources[fragment] for fragment in shared["FRAGMENTS"])]))
    paths.append(str(composed))
    source_files = ",".join(json.dumps(key) + ":" + json.dumps(value)
        for key, value in sorted(source_plan["target_source_files"].items()))
    compiled_pins = code / "CompiledPins.swift"
    compiled_pins.write_bytes(shared["DUMMY_COMPILED_PINS"] + (
        "\nenum RuntimeUpgradeCompiledPins { static let value = RuntimeUpgradeSource.Pins("
        f'planSHA256: "{PLAN_SHA256}", beforeSHA256: "{BEFORE_SHA256}", afterSHA256: "{AFTER_SHA256}", '
        f'repairPlan: "{"0" * 64}", repairSource: "{"0" * 40}", targetSource: "{TARGET_SOURCE}", '
        f"sourceFiles: [{source_files}], direct: true) }}\n").encode())
    paths.append(str(compiled_pins))
    helper = scripts / "AccountAccess-runtimeupgrade"
    command("compile-updater", ["/usr/bin/xcrun", "swiftc", "-j", "2", "-O", "-whole-module-optimization",
        "-parse-as-library", "-warnings-as-errors", "-D", "ACCOUNT_ACCESS_RUNTIME_UPGRADE_MAIN",
        "-target", "arm64-apple-macos14", "-module-cache-path", output / "module-cache",
        "-framework", "Foundation", "-framework", "CryptoKit", "-framework", "Security", *paths, "-o", helper], timeout=1800)
    helper.chmod(0o755)
    command("sign-updater", ["/usr/bin/codesign", "--options", "runtime", "--timestamp", "--identifier",
        HELPER_ID, "--sign", args.application_identity, helper], timeout=180)
    command("verify-updater-signature", ["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple generic and identifier "
        f'"{HELPER_ID}" and certificate leaf[subject.OU] = "{TEAM}" and !(entitlement["com.apple.security.get-task-allow"] exists)',
        helper], timeout=120)
    refusal = run([helper], timeout=30)
    (output / "ordinary-refusal.stdout").write_bytes(refusal.stdout)
    (output / "ordinary-refusal.stderr").write_bytes(refusal.stderr)
    require(refusal.returncode == 78 and refusal.stdout == b'{"schema":1,"status":"REFUSED","reason":"runtime_upgrade_installer_context_required"}\n'
        and refusal.stderr == b"", "ordinary_helper_refusal_mismatch")
    postinstall = b'''#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
[ "$(/usr/bin/id -u)" = 0 ] && [ "${3:-}" = / ] || exit 1
AC_PACKAGE_SCRIPTS=$(CDPATH= cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)
exec "$AC_PACKAGE_SCRIPTS/AccountAccess-runtimeupgrade"
'''
    (scripts / "postinstall").write_bytes(postinstall)
    (scripts / "postinstall").chmod(0o755)
    command("postinstall-syntax", ["/bin/sh", "-n", scripts / "postinstall"], timeout=30)
    require({path.name for path in scripts.iterdir()} == RESOURCE_NAMES, "installer_resource_inventory_mismatch")
    raw_pkg = output / "unsigned.pkg"
    command("package-resources", ["/usr/bin/pkgbuild", "--nopayload", "--identifier", COMPONENT_ID,
        "--version", "0.8.0", "--scripts", scripts, raw_pkg], timeout=600)
    container = output / "container"
    container.mkdir(mode=0o700)
    command("expand-raw-package", ["/usr/bin/xar", "-xf", raw_pkg, "-C", container], timeout=300)
    raw_pkg.unlink()
    require({path.name for path in container.iterdir()} == {"PackageInfo", "Scripts"}, "unexpected_package_container")
    info_path = container / "PackageInfo"
    info = info_path.read_bytes()
    require(COMPONENT_ID.encode() in info and info.count(b'timeout="600"') == 1
        and info.count(b'postinstall-action="none"') == 1, "package_info_contract_mismatch")
    info_path.write_bytes(info.replace(b'timeout="600"', b'timeout="1800"').replace(
        b'postinstall-action="none"', b'postinstall-action="restart"'))
    package = output / "Account-Access-Direct-Upgrade-117.pkg"
    command("assemble-package", ["/usr/bin/xar", "--compression=none", "-cf", package,
        "PackageInfo", "Scripts"], cwd=container, timeout=600)
    signed = output / "Account-Access-Direct-Upgrade-117-signed.pkg"
    command("sign-package", ["/usr/bin/productsign", "--sign", args.installer_identity, package, signed], timeout=300)
    package.unlink()
    notary_raw = command("notarize", ["/usr/bin/xcrun", "notarytool", "submit", signed,
        "--keychain-profile", args.notary_profile, "--wait", "--output-format", "json"], timeout=3600)
    notarization = json.loads(notary_raw)
    require(notarization.get("status") == "Accepted", "notary_acceptance_missing")
    command("staple", ["/usr/bin/xcrun", "stapler", "staple", "-v", signed], timeout=300)
    command("staple-verify", ["/usr/bin/xcrun", "stapler", "validate", "-v", signed], timeout=120)
    signature = command("package-signature", ["/usr/sbin/pkgutil", "--check-signature", signed], timeout=60)
    require(b"Developer ID Installer" in signature and b"Notarization: trusted" in signature,
        "signed_package_trust_missing")
    command("gatekeeper", ["/usr/sbin/spctl", "--assess", "--type", "install", "--verbose", signed], timeout=120)
    independent = output / "independent"
    command("independent-expand", ["/usr/sbin/pkgutil", "--expand-full", signed, independent], timeout=600)
    require((independent / "PackageInfo").read_bytes() == info_path.read_bytes(), "signed_package_info_changed")
    independent_scripts = independent / "Scripts"
    require(independent_scripts.is_file() and not independent_scripts.is_symlink(), "signed_scripts_archive_missing")
    resource_names = cpio_listing(independent_scripts)
    require(resource_names == RESOURCE_NAMES, "signed_package_resource_inventory_mismatch")
    report = {"schema": 1, "status": "BUILT_NOT_INSTALLED", "package": str(signed),
        "package_sha256": file_digest(signed), "package_bytes": signed.stat().st_size,
        "notarization": "Accepted", "stapled": True, "gatekeeper": "accepted",
        "helper_sha256": file_digest(helper), "helper_signature": "Developer ID Application verified",
        "installer_signature": "Developer ID Installer verified", "target_package_sha256": TARGET_PACKAGE_SHA256,
        "plan_sha256": PLAN_SHA256, "before_manifest_sha256": BEFORE_SHA256,
        "after_manifest_sha256": AFTER_SHA256, "sparse_nodes": sparse_nodes, "sparse_file_bytes": sparse_bytes,
        "global_operation_count": 195, "package_resource_count": len(RESOURCE_NAMES),
        "ordinary_user_refusal": True, "installer_executed": False, "installed": False,
        "source_revision": args.source, "shared_qa": str(args.shared_qa), "runtime_qa": str(args.runtime_qa),
        "direct_qa": str(args.direct_qa), "notary_status": "Accepted", "notary_id": notarization.get("id"),
        "production_ready": False}
    (output / "review.json").write_bytes(encoded(report))
    print(json.dumps({key: report[key] for key in ["status", "package", "package_sha256", "package_bytes",
        "notarization", "stapled", "gatekeeper", "installed", "production_ready"]}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target-package", required=True, type=Path)
    parser.add_argument("--base-manifest", required=True, type=Path)
    parser.add_argument("--base-identity", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--shared-qa", required=True, type=Path)
    parser.add_argument("--runtime-qa", required=True, type=Path)
    parser.add_argument("--direct-qa", required=True, type=Path)
    parser.add_argument("--application-identity", default="E42D109853911EC536C2A07B769D4FC5B7B96BB9")
    parser.add_argument("--installer-identity", default="Developer ID Installer: Nir Feinstein (WBULD6N4NQ)")
    parser.add_argument("--notary-profile", default="AccountAccessPublisher")
    parser.add_argument("--output", required=True, type=Path)
    build(parser.parse_args())
