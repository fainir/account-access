"""Build the exact signed, notarized build-110 to source-current build-120 updater.

This builder reads a qualified public image and manifest, compiles the fixed
root helper, and produces a reviewable installer. It never runs Installer or
writes to an installed Account Access path.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PLAN_SHA256 = "7949dee76094337190bd9efa31b7e09fc478bf62a3bbdfd44824cc9ba3f3d58b"
BEFORE_SHA256 = "568c79ca3b45ffc357bc5af2b420d481e729630b0120dc6d0058c1a396ad21b1"
AFTER_SHA256 = "6ab5f90fa72dfed84c295d5df4741d3cb9aaf6a0fa89ed155b4cb76400570874"
TARGET_SOURCE = "beda6324d836458a35045ee0d2acd579238d6929"
TARGET_IMAGE_BUILDER_COMMIT = "beda6324d836458a35045ee0d2acd579238d6929"
BASE_IMAGE_SHA256 = "630e77605faac2dfdace9faaa5da55e671335c6b18e62114d7f0224a8574f24c"
COMPONENT_ID = "com.fainir.accountaccess.directruntimeupgrade120recovery"
HELPER_ID = "com.fainir.accountaccess.componentupdate"
TEAM = "WBULD6N4NQ"
SUPPORT_RELATIVE = "Library/Application Support/Account Access"
SUPPORT_RELATIVE_ROOT = "/" + SUPPORT_RELATIVE
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


def publish_package(source: Path, destination: Path, expected_sha256: str) -> Path:
    """Publish a fully qualified package atomically without replacing a prior release."""
    source_info = source.lstat()
    require(stat.S_ISREG(source_info.st_mode) and source_info.st_uid == os.getuid(),
        "publish_source_invalid")
    require(re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is not None,
        "publish_digest_invalid")
    parent = destination.parent.absolute()
    parent_info = parent.lstat()
    require(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.getuid(),
        "publish_destination_parent_invalid")
    destination = parent / destination.name
    require(not os.path.lexists(destination), "publish_destination_exists")

    with source.open("rb") as incoming:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.",
            suffix=".publishing", dir=parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing, length=8 * 1024 * 1024)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            os.chmod(temporary, 0o644, follow_symlinks=False)
            require(file_digest(temporary) == expected_sha256, "publish_copy_digest_mismatch")
            # Hard-link creation is atomic and fails if another file appeared at destination.
            os.link(temporary, destination, follow_symlinks=False)
            os.unlink(temporary)
            directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            require(file_digest(destination) == expected_sha256, "publish_final_digest_mismatch")
            return destination
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def encoded(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def run(argv, *, timeout=120, cwd=ROOT):
    return subprocess.run(list(map(str, argv)), cwd=cwd, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=timeout, check=False)


def checked(argv, *, timeout=120, cwd=ROOT):
    result = run(argv, timeout=timeout, cwd=cwd)
    require(result.returncode == 0, "command_failed:" + Path(str(argv[0])).name)
    return result.stdout


def validate_compile_run(metadata, source):
    require(metadata.get('head_sha') == source and metadata.get('status') == 'completed'
        and metadata.get('conclusion') == 'success'
        and metadata.get('path') == '.github/workflows/mac-release-native-review.yml'
        and metadata.get('repository', {}).get('full_name') == REPOSITORY,
        'compiled_helper_run_not_qualified')


REPOSITORY = 'fainir/account-access'


def reviewed_ci_helper(run_id, source, destination):
    """Accept only our successful exact-commit compiler workflow's artifact."""
    require(type(run_id) is int and run_id > 0, 'compiled_helper_run_invalid')
    base = f'repos/{REPOSITORY}/actions/runs/{run_id}'
    metadata = json.loads(checked(['gh', 'api', base], timeout=60))
    validate_compile_run(metadata, source)
    assets = json.loads(checked(['gh', 'api', base + '/artifacts'], timeout=60))
    candidates = [item for item in assets['artifacts'] if item['name'] == 'release-compiled-updater']
    require(len(candidates) == 1 and candidates[0].get('expired') is False, 'compiled_helper_artifact_missing')
    asset = candidates[0]
    require(type(asset['id']) is int and 0 < asset['size_in_bytes'] <= 16 * 1024 * 1024,
            'compiled_helper_artifact_invalid')
    raw = checked(['gh', 'api', f'repos/{REPOSITORY}/actions/artifacts/{asset["id"]}/zip'], timeout=180)
    require(len(raw) <= 16 * 1024 * 1024 and asset.get('digest') == 'sha256:' + digest(raw),
            'compiled_helper_archive_digest_mismatch')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(archive.namelist() == ['AccountAccess-runtimeupgrade'], 'compiled_helper_archive_inventory_invalid')
        info = archive.infolist()[0]
        require(0 < info.file_size <= 16 * 1024 * 1024, 'compiled_helper_binary_invalid')
        destination.write_bytes(archive.read(info))
    destination.chmod(0o755)


def expanded_script_resource_names(scripts: Path) -> set[str]:
    require(scripts.is_dir() and not scripts.is_symlink(), "signed_scripts_directory_missing")
    entries = list(scripts.iterdir())
    require(len(entries) == len(RESOURCE_NAMES), "signed_script_resource_count_mismatch")
    for path in entries:
        info = path.lstat()
        if path.name == "TargetImage":
            require(stat.S_ISDIR(info.st_mode), "signed_target_image_invalid")
        else:
            require(stat.S_ISREG(info.st_mode), "signed_script_resource_invalid")
    return {path.name for path in entries}


def read_owned_bytes(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and info.st_size <= maximum, "unsafe_public_input")
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(fd, min(1024 * 1024, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        require(len(raw) <= maximum, "public_input_too_large")
        require(len(raw) == info.st_size and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns), "public_input_changed_during_read")
        return bytes(raw)
    finally:
        os.close(fd)


def read_json(path: Path, maximum: int):
    return json.loads(read_owned_bytes(path, maximum))


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


def updater_payload_nodes(plan: dict, after: dict):
    planned = expected_sparse_nodes(plan, after)
    tree = after["roots"][SUPPORT_RELATIVE_ROOT]
    owner_bundle = {path: node for path, node in tree.items()
        if path == "owner.app" or path.startswith("owner.app/")}
    require(owner_bundle.get("owner.app", {}).get("kind") == "directory"
        and owner_bundle.get("owner.app/Contents/_CodeSignature/CodeResources", {}).get("kind") == "file",
        "target_owner_bundle_signature_resources_missing")
    require(all(node["kind"] in {"directory", "file"} for node in owner_bundle.values()),
        "target_owner_bundle_link_refused")
    require(all(path not in planned or planned[path] == node for path, node in owner_bundle.items()),
        "owner_bundle_plan_conflict")
    return planned, planned | owner_bundle


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


def materialize_sparse_target(source_image: Path, target_image: Path,
        inventory: dict[str, dict]) -> tuple[Path, int]:
    """Move only planned public nodes from a verified image into the updater resource."""
    source_support = source_image / SUPPORT_RELATIVE
    target_support = target_image / SUPPORT_RELATIVE
    require(source_image.is_dir() and not source_image.is_symlink(), "target_public_image_invalid")
    require(not os.path.lexists(target_image), "sparse_target_already_exists")

    # The update helper consumes a root-shaped PublicImage. Preserve the two
    # ordinary public parent directories while omitting unrelated app roots.
    target_image.mkdir(mode=0o755)
    for relative in ("Library", "Library/Application Support"):
        source = source_image / relative
        target = target_image / relative
        info = source.lstat()
        require(stat.S_ISDIR(info.st_mode), "target_public_parent_invalid")
        target.mkdir(mode=stat.S_IMODE(info.st_mode))

    create_sparse_directories(target_image, inventory)
    for relative, node in sorted(inventory.items()):
        source = source_support / relative if relative else source_support
        if node["kind"] == "directory":
            require(stat.S_ISDIR(source.lstat().st_mode), "sparse_source_directory_refused")
            continue
        target = target_support / relative
        source_info = source.lstat()
        require(not target.parent.is_symlink(), "sparse_target_parent_symlink_refused")
        if node["kind"] == "file":
            require(stat.S_ISREG(source_info.st_mode), "sparse_source_file_invalid")
            shutil.copy2(source, target, follow_symlinks=False)
        elif node["kind"] == "symlink":
            require(stat.S_ISLNK(source_info.st_mode) and os.readlink(source) == node["target"],
                "sparse_source_symlink_mismatch")
            os.symlink(node["target"], target)
        else:
            raise ValueError("sparse_source_node_invalid")

    actual = public_payload_inventory(target_support)
    require(actual == inventory, "sparse_target_inventory_mismatch")
    return target_support, sum(node.get("size", 0) for node in actual.values())


def extract_sparse_target(public: Path, scripts: Path, target_manifest: dict, plan: dict):
    require(public.is_dir() and not public.is_symlink(), "target_public_image_missing")
    planned_inventory, resource_inventory = updater_payload_nodes(plan, target_manifest)
    require({path.name for path in public.iterdir()} == {"Applications", "Library"},
        "target_public_image_root_mismatch")
    applications = public / "Applications"
    require(stat.S_ISDIR(applications.lstat().st_mode), "target_public_applications_invalid")
    require({path.name for path in applications.iterdir()} == {"Account Access.app"},
        "target_public_applications_inventory_mismatch")
    support = public / SUPPORT_RELATIVE
    for relative in ("Library", "Library/Application Support", SUPPORT_RELATIVE):
        require(stat.S_ISDIR((public / relative).lstat().st_mode), "target_public_support_parent_invalid")
    target_support_manifest = target_manifest["roots"][SUPPORT_RELATIVE_ROOT]
    require(public_payload_inventory(support) == target_support_manifest,
        "target_public_image_manifest_mismatch")
    app_link = public / "Applications" / "Account Access.app"
    app_node = target_manifest["roots"].get("/Applications/Account Access.app", {}).get("")
    require(app_node is not None and app_node.get("kind") == "symlink" and app_link.is_symlink()
        and os.readlink(app_link) == app_node.get("target"), "target_public_app_link_mismatch")
    target_image = scripts / "TargetImage"
    support, _resource_bytes = materialize_sparse_target(public, target_image, resource_inventory)
    plan_bytes = sum(node.get("size", 0) for node in planned_inventory.values())
    return (target_image, support, len(planned_inventory), plan_bytes,
        len(resource_inventory) - len(planned_inventory), resource_inventory)


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
    require(direct.get("status") == "PASSED"
        and direct.get("native", {}).get("units") == len(plan["units"])
        and direct.get("native", {}).get("changed_nodes") == len(plan["changed"])
        and direct.get("production_ready") is False,
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


def prepare_updater_sources(sources, shared, source_plan, code):
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
    return paths


def build(args):
    require(sys.platform == "darwin" and os.getuid() == os.geteuid() != 0, "ordinary_mac_required")
    require(re.fullmatch(r"[a-f0-9]{40}", args.source) is not None, "source_revision_invalid")
    require(git_bytes("rev-parse", "HEAD").decode().strip() == args.source, "source_revision_mismatch")
    require(git_bytes("status", "--porcelain").strip() == b"", "source_tree_not_clean")
    output = args.output.absolute()
    require(output.parent.is_dir() and not os.path.lexists(output), "output_must_be_new")
    plan_raw = read_owned_bytes(args.plan, 34 * 1024 * 1024)
    require(digest(plan_raw) == PLAN_SHA256, "plan_hash_mismatch")
    require(re.fullmatch(r"[A-F0-9]{40}", args.application_identity) is not None, "application_identity_invalid")
    shared = runpy.run_path(str(ROOT / "scripts/mac_full_image_installed_probe.py"))
    sources = source_inputs(shared)
    for name, raw in sources.items():
        require(git_bytes("show", args.source + ":" + name) == raw, "source_not_committed")
    source_plan = json.loads(plan_raw)
    shared_qa, runtime_qa, direct_qa = verify_qa(args, sources, source_plan)
    before_raw = read_owned_bytes(args.base_manifest, 16 * 1024 * 1024)
    old_identity_raw = read_owned_bytes(args.base_identity, 8192)
    require(digest(before_raw) == BEFORE_SHA256, "base_manifest_mismatch")
    require(digest(old_identity_raw) == "3462087a742f96baab0dbcc5e66e84c1aa408e828f216024529a5d05e7eb7248",
        "base_identity_mismatch")
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
    target_image = args.target_image.absolute()
    target_manifest_path = args.target_manifest.absolute()
    target_qualification_raw = read_owned_bytes(args.target_qualification, 2 * 1024 * 1024)
    target_qualification = json.loads(target_qualification_raw)
    require(target_qualification.get("status") == "TARGET_IMAGE_QUALIFIED"
        and target_qualification.get("owner_app_build") == 120
        and target_qualification.get("source_image_build") == 119
        and target_qualification.get("source_manifest_sha256") == BASE_IMAGE_SHA256
        and target_qualification.get("source_image_unchanged") is True
        and target_qualification.get("builder_commit") == TARGET_IMAGE_BUILDER_COMMIT
        and target_qualification.get("target_source_commit") == TARGET_SOURCE
        and target_qualification.get("target_manifest_sha256") == AFTER_SHA256
        and target_qualification.get("project_wheel_sha256") == source_plan["project_wheel_sha256"]
        and target_qualification.get("native_manifest_preflight") is True
        and target_qualification.get("installed") is False
        and target_qualification.get("installer_executed") is False
        and target_qualification.get("native_payload_audit", {}).get("publisher_signatures_verified") is True,
        "target_image_qualification_mismatch")
    require(target_image.is_dir() and not target_image.is_symlink()
        and {path.name for path in target_image.iterdir()} == {"Applications", "Library"},
        "target_public_image_missing")
    after_raw = read_owned_bytes(target_manifest_path, 16 * 1024 * 1024)
    require(digest(after_raw) == AFTER_SHA256, "target_manifest_missing_or_mismatched")
    after = json.loads(after_raw)
    require(all(digest(git_bytes("show", TARGET_SOURCE + ":" + name)) == file_hash
        for name, file_hash in source_plan["target_source_files"].items()), "target_source_files_mismatch")
    scripts = output / "scripts"
    scripts.mkdir(mode=0o700)
    (scripts / "RuntimeUpgradePlan.json").write_bytes(plan_raw)
    (scripts / "BaseManifest.json").write_bytes(before_raw)
    (scripts / "TargetManifest.json").write_bytes(after_raw)
    (scripts / "BaseIdentity.json").write_bytes(old_identity_raw)
    (_, support, sparse_nodes, sparse_bytes, owner_bundle_nodes,
        updater_payload_inventory) = extract_sparse_target(target_image, scripts, after, source_plan)
    command("target-owner-signature", ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2",
        support / "owner.app"], timeout=120)
    new_identity_raw = (support / "package-identity.json").read_bytes()
    direct_planner.parse(plan_raw, expected_sha256=PLAN_SHA256, before_manifest=before_raw,
        after_manifest=after_raw, old_identity=old_identity_raw, new_identity=new_identity_raw,
        source_files=source_plan["target_source_files"])
    (scripts / "TargetIdentity.json").write_bytes(new_identity_raw)
    require((support / "package-identity.json").read_bytes() == new_identity_raw,
        "target_identity_payload_mismatch")
    paths = prepare_updater_sources(sources, shared, source_plan, output / "source")
    helper = scripts / "AccountAccess-runtimeupgrade"
    if getattr(args, 'compiled_run', None) is not None:
        reviewed_ci_helper(args.compiled_run, args.source, helper)
        command('compiled-helper-architecture', ['/usr/bin/lipo', '-verify_arch', 'arm64', helper])
    else:
        command("compile-updater", ["/usr/bin/xcrun", "swiftc", "-j", "2", "-O", "-whole-module-optimization",
            "-parse-as-library", "-warnings-as-errors", "-D", "ACCOUNT_ACCESS_RUNTIME_UPGRADE_MAIN",
            "-target", "arm64-apple-macos14", "-module-cache-path", output / "module-cache",
            "-framework", "Foundation", "-framework", "CryptoKit", "-framework", "Security", *paths, "-o", helper], timeout=1800)
    helper.chmod(0o755)
    command("sign-updater", ["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp", "--identifier",
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
    package = output / "Account-Access-Direct-Upgrade-120-root-recovery.pkg"
    command("assemble-package", ["/usr/bin/xar", "--compression=none", "-cf", package,
        "PackageInfo", "Scripts"], cwd=container, timeout=600)
    signed = output / "Account-Access-Direct-Upgrade-120-root-recovery-signed.pkg"
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
    resource_names = expanded_script_resource_names(independent_scripts)
    require(resource_names == RESOURCE_NAMES, "signed_package_resource_inventory_mismatch")
    packaged_target = independent_scripts / "TargetImage"
    require(packaged_target.is_dir() and not packaged_target.is_symlink(), "signed_target_image_missing")
    packaged_support = packaged_target / SUPPORT_RELATIVE
    require(public_payload_inventory(packaged_support) == updater_payload_inventory,
        "signed_target_image_inventory_mismatch")
    command("independent-owner-signature", ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2",
        packaged_support / "owner.app"], timeout=120)
    published = None
    if args.publish_to is not None:
        published = publish_package(signed, args.publish_to, file_digest(signed))
        published_signature = command("published-package-signature", ["/usr/sbin/pkgutil", "--check-signature",
            published], timeout=60)
        require(b"Developer ID Installer" in published_signature
            and b"Notarization: trusted" in published_signature, "published_package_trust_missing")
        command("published-staple-verify", ["/usr/bin/xcrun", "stapler", "validate", "-v", published], timeout=120)
        command("published-gatekeeper", ["/usr/sbin/spctl", "--assess", "--type", "install", "--verbose",
            published], timeout=120)
    report = {"schema": 1, "status": "BUILT_NOT_INSTALLED", "package": str(signed),
        "package_sha256": file_digest(signed), "package_bytes": signed.stat().st_size,
        "published_package": str(published) if published is not None else None,
        "published_package_sha256": file_digest(published) if published is not None else None,
        "notarization": "Accepted", "stapled": True, "gatekeeper": "accepted",
        "helper_sha256": file_digest(helper), "helper_signature": "Developer ID Application verified",
        "installer_signature": "Developer ID Installer verified",
        "target_image_manifest_sha256": AFTER_SHA256,
        "target_source_commit": TARGET_SOURCE,
        "target_image_builder_commit": TARGET_IMAGE_BUILDER_COMMIT,
        "target_image_qualification": str(args.target_qualification),
        "target_image_qualification_sha256": digest(target_qualification_raw),
        "plan_sha256": PLAN_SHA256, "before_manifest_sha256": BEFORE_SHA256,
        "after_manifest_sha256": AFTER_SHA256, "sparse_nodes": sparse_nodes, "sparse_file_bytes": sparse_bytes,
        "owner_bundle_nodes": owner_bundle_nodes, "owner_bundle_signature": "Developer ID Application verified",
        "packaged_target_image_nodes": len(updater_payload_inventory),
        "plan_unit_count": len(source_plan["units"]),
        "planned_changed_node_count": len(source_plan["changed"]),
        "package_resource_count": len(RESOURCE_NAMES),
        "ordinary_user_refusal": True, "installer_executed": False, "installed": False,
        "source_revision": args.source, "shared_qa": str(args.shared_qa), "runtime_qa": str(args.runtime_qa),
        "direct_qa": str(args.direct_qa), "notary_status": "Accepted", "notary_id": notarization.get("id"),
        "production_ready": False, 'compiled_run': getattr(args, 'compiled_run', None)}
    (output / "review.json").write_bytes(encoded(report))
    print(json.dumps({key: report[key] for key in ["status", "package", "package_sha256", "package_bytes",
        "notarization", "stapled", "gatekeeper", "installed", "production_ready"]}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument('--compiled-run', type=int,
        help='Successful exact-commit release native workflow; signing still occurs only on this Mac')
    parser.add_argument("--target-image", required=True, type=Path)
    parser.add_argument("--target-manifest", required=True, type=Path)
    parser.add_argument("--target-qualification", required=True, type=Path)
    parser.add_argument("--base-manifest", required=True, type=Path)
    parser.add_argument("--base-identity", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--shared-qa", required=True, type=Path)
    parser.add_argument("--runtime-qa", required=True, type=Path)
    parser.add_argument("--direct-qa", required=True, type=Path)
    parser.add_argument("--application-identity", default="E42D109853911EC536C2A07B769D4FC5B7B96BB9")
    parser.add_argument("--installer-identity", default="Developer ID Installer: Nir Feinstein (WBULD6N4NQ)")
    parser.add_argument("--notary-profile", default="AccountAccessPublisher")
    parser.add_argument("--publish-to", type=Path,
        help="Atomically copy the fully qualified package to a persistent path, rechecking signature, notarization and Gatekeeper there")
    parser.add_argument("--output", required=True, type=Path)
    build(parser.parse_args())
