"""Build-only fixed owner104 successor from frozen public inputs; never install."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import struct
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PACKAGE95 = "0c7a83b47d405bd9b02686aceb938877c5cd2f36112cb0b8369069c643453371"
INVENTORY95 = "9072d9bce2fd9c1b6118e657c77cab3f32e5c44689f4bb230132f07bbbb0e1e1"
PINS95 = "c63ff71959f969edf95fe11b02672ea195a0d2b5cb607c7f2afa67e2a7a1a49a"
PLAN = "1647952c58111b78557dee209b5201b43ffab63fb8a689ce73a258a8794d2dd3"
BEFORE = "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
AFTER = "c1b6f40aeafc5243dd2b16a9c4f14448245e389fa45dabcfae4c4f7b913d4afc"
TARGET = "9c375d1655f8fb27aa4389b11f546193e05b05f5"
IDENTIFIER = "com.fainir.accountaccess.ownerupgrade104"
BUILD_TOOLS = (
    "/usr/bin/xcrun",
    "/usr/bin/codesign",
    "/usr/bin/pkgbuild",
    "/usr/sbin/pkgutil",
    "/usr/bin/xar",
    "/usr/bin/tar",
    "/bin/sh",
)


def require(value):
    if not value:
        raise ValueError("owner_upgrade_build_refused")


def verify_build_tools():
    require(all(Path(name).is_file() and os.access(name, os.X_OK) for name in BUILD_TOOLS))


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def verify_wrapper_binding(wrapper, helper_sha256, *, helper_name="AccountAccess-ownerupgrade"):
    """Bind the actual shell entrypoint to the signed helper before packaging."""
    require(type(wrapper) is bytes and len(wrapper) <= 8192
            and type(helper_sha256) is str and re.fullmatch(r"[a-f0-9]{64}", helper_sha256)
            and helper_name in {"AccountAccess-ownerupgrade", "AccountAccess-runtimeupgrade"})
    guard = (b'[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum -a 256 '
             b'"$AC_COMPONENT_HELPER" | /usr/bin/awk \'{print $1}\')" = \''
             + helper_sha256.encode() + b"' ] || exit 1\n")
    require(wrapper.splitlines(keepends=True).count(guard) == 1
            and re.findall(rb"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])", wrapper) == [helper_sha256.encode()]
            and wrapper.count(b'AC_COMPONENT_HELPER="$AC_COMPONENT_SCRIPTS/' + helper_name.encode() + b'"\n') == 1
            and wrapper.count(helper_name.encode()) == 1
            and wrapper.endswith(b'exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C "$AC_COMPONENT_HELPER"\n'))


def owner_wrapper(predecessor, runtime_sha256, owner_sha256):
    require(type(owner_sha256) is str and re.fullmatch(r"[a-f0-9]{64}", owner_sha256))
    verify_wrapper_binding(predecessor, runtime_sha256, helper_name="AccountAccess-runtimeupgrade")
    result = predecessor.replace(runtime_sha256.encode(), owner_sha256.encode()).replace(
        b"AccountAccess-runtimeupgrade", b"AccountAccess-ownerupgrade")
    verify_wrapper_binding(result, owner_sha256)
    return result


def helper_target(raw):
    """Inspect the thin ARM64 executable, independently of compiler arguments."""
    require(type(raw) is bytes and 32 <= len(raw) <= 16 * 1024**2)
    header = struct.unpack_from("<8I", raw)
    require(header[0] == 0xFEEDFACF and header[1] == 0x100000C and header[2] == 0 and header[3] == 2
            and 1 <= header[4] <= 256 and 8 <= header[5] <= 65536 and 32 + header[5] <= len(raw))
    end, offset, versions = 32 + header[5], 32, []
    for _ in range(header[4]):
        require(offset + 8 <= end)
        kind, size = struct.unpack_from("<II", raw, offset)
        require(size >= 8 and size % 8 == 0 and offset + size <= end)
        if kind == 0x32:  # LC_BUILD_VERSION
            require(size >= 24)
            platform, minimum, sdk, tools = struct.unpack_from("<4I", raw, offset + 8)
            require(tools <= 8 and size == 24 + tools * 8)
            versions.append((platform, minimum, sdk))
        offset += size
    require(offset == end and len(versions) == 1)
    platform, minimum, sdk = versions[0]
    require(platform == 1 and minimum == 14 << 16 and minimum <= sdk <= 99 << 16)

    def version(value):
        parts = [str(value >> 16), str((value >> 8) & 255)]
        if value & 255:
            parts.append(str(value & 255))
        return ".".join(parts)

    return {"architecture": "arm64", "platform": "macos", "minimum_macos": version(minimum), "sdk": version(sdk)}


def validate_qa(shared, runtime, owner, sources):
    require(
        shared.get("status") == "PASSED"
        and shared.get("sources_stable") is True
        and shared.get("guarded_main_refusals") == 6
        and runtime.get("status") == "PASSED"
        and runtime.get("entrypoint_ordinary_refusal") is True
        and runtime.get("result", {}).get("status") == "PASSED"
        and runtime.get("result", {}).get("checks") == 69
        and runtime.get("installed_reads") is False
        and owner.get("status") == "PASSED"
        and owner.get("ordinary_entrypoint_refusal") is True
        and owner.get("installed_reads") is False
        and owner.get("installed_writes") is False
        and owner.get("production_ready") is False
    )
    rows = owner.get("results", [])
    require(
        len(rows) == 4
        and all(r.get("status") == "PASSED" for r in rows)
        and rows[0].get("checks") == 68
        and rows[1].get("ordinary_context_refusals") == 2
        and rows[1].get("namespace_checks") == 26
        and rows[1].get("preparation_checks") == 21
        and rows[2].get("checks") == 477
        and rows[2].get("root_execution") is False
        and rows[3].get("checks") == 324
        and rows[3].get("owned_temp_fake_barrier_only") is True
    )
    for name, raw in sources.items():
        digest = hashlib.sha256(raw).hexdigest()
        require(owner.get("source_sha256", {}).get(name) == digest)
        for report in (shared, runtime):
            if name in report.get("source_sha256", {}):
                require(report["source_sha256"][name] == digest)


def public_image(rows, manifest):
    """Project a closed build inventory into its two declared public roots."""
    prefixes = {
        "/Applications/Account Access.app": "Applications/Account Access.app",
        "/Library/Application Support/Account Access": "Library/Application Support/Account Access",
    }
    allowed = {"", "Applications", "Library", "Library/Application Support"}
    result = {}
    for root, prefix in prefixes.items():
        result[root] = {}
        for path, item in rows.items():
            if path != prefix and not path.startswith(prefix + "/"):
                continue
            allowed.add(path)
            relative = path[len(prefix) :].lstrip("/")
            if item["kind"] == "file":
                node = {
                    "kind": "file",
                    "mode": item["mode"],
                    "size": item["bytes"],
                    "sha256": item["sha256"],
                }
            elif item["kind"] == "directory":
                node = {"kind": "directory", "mode": item["mode"]}
            else:
                node = {"kind": "symlink", "target": item["target"]}
            result[root][relative] = node
    require(set(rows) == allowed and result == manifest["roots"])


def proof_inventory(rows):
    """The completed-state verifier consumes records, not ancestor payloads."""
    omitted = ("TargetImage", "Predecessor/CompletedImage")
    require(rows.get("") == {"kind": "directory", "mode": 0o700, "acl": "empty"})
    require(
        all(
            rows.get(name, {}).get("kind") == "directory" and rows[name]["mode"] == 0o755
            for name in omitted
        )
    )
    result = {
        name: node
        for name, node in rows.items()
        if not any(name.startswith(prefix + "/") for prefix in omitted)
    }
    # pkgutil's original Scripts container is private. Once embedded, it is a
    # fixed public resource directory: fullResourceDirectory requires 0755.
    # Only this fresh build container changes; every verifier record is exact.
    result[""] = {**rows[""], "mode": 0o755}
    return result


def proof_extract_command(archive, output):
    return [
        "/usr/bin/tar",
        "--no-mac-metadata",
        "-xf",
        str(archive),
        "-C",
        str(output),
        "--exclude=TargetImage/*",
        "--exclude=./TargetImage/*",
        "--exclude=Predecessor/CompletedImage/*",
        "--exclude=./Predecessor/CompletedImage/*",
        "--exclude=._TargetImage",
        "--exclude=./._TargetImage",
        "--exclude=Predecessor/._CompletedImage",
        "--exclude=./Predecessor/._CompletedImage",
    ]


def build(args):
    require(
        sys.platform == "darwin"
        and os.getuid() == os.geteuid() != 0
        and re.fullmatch("[a-f0-9]{40}", args.source)
        and re.fullmatch("[A-F0-9]{40}", args.signing_identity)
    )
    verify_build_tools()
    output = args.output.absolute()
    require(output.parent.is_dir() and not os.path.lexists(output))
    space = os.statvfs(output.parent)
    require(space.f_bavail * space.f_frsize >= 2 * 1024**3)

    def git(*values):
        return subprocess.check_output(["git", *values], cwd=ROOT, timeout=30)

    require(git("rev-parse", "HEAD").decode().strip() == args.source)
    require(
        sha(args.package95) == PACKAGE95
        and sha(args.inventory95) == INVENTORY95
        and sha(args.pins95) == PINS95
        and sha(args.plan) == PLAN
        and sha(args.target_manifest) == AFTER
    )
    recipe_files = (
        "scripts/build_owner_upgrade104_review.py",
        "macos/owner_upgrade104_plan.py",
    )
    require(
        all((ROOT / name).read_bytes() == git("show", args.source + ":" + name) for name in recipe_files)
    )
    probe = runpy.run_path(str(ROOT / "scripts/mac_full_image_installed_probe.py"))
    owner_probe = runpy.run_path(str(ROOT / "scripts/mac_owner_upgrade_probe.py"))
    names = ["macos/" + n for n in probe["DEPENDENCIES"]]
    names += [
        "macos/FullImageInstalledIO.swift",
        "macos/FullImagePredecessorAuthority.swift",
        "macos/OwnerUpgradeSource.swift",
        "macos/OwnerUpgradeMain.swift",
        "macos/ComponentUpdate.swift",
        *probe["FRAGMENTS"],
        *owner_probe["EXTRA_FRAGMENTS"],
    ]
    require(len(names) == len(set(names)))
    sources = {n: (ROOT / n).read_bytes() for n in names}
    require(all(raw == git("show", args.source + ":" + n) for n, raw in sources.items()))
    reports = [json.loads(p.read_bytes()) for p in (args.shared_qa, args.runtime_qa, args.owner_qa)]
    validate_qa(*reports, sources)
    plan_raw, after_raw = args.plan.read_bytes(), args.target_manifest.read_bytes()
    plan = json.loads(plan_raw)
    require(
        plan["target_source"] == TARGET
        and plan["before_manifest_sha256"] == BEFORE
        and plan["after_manifest_sha256"] == AFTER
    )
    require(
        all(
            hashlib.sha256(git("show", TARGET + ":" + name)).hexdigest() == digest
            for name, digest in plan["target_native_source_files"].items()
        )
    )
    output.mkdir(mode=0o700)
    commands = []

    def command(label, arguments, *, cwd=ROOT, expected=0, timeout=900):
        response = subprocess.run(
            arguments,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        (output / (label + ".stdout")).write_bytes(response.stdout)
        (output / (label + ".stderr")).write_bytes(response.stderr)
        commands.append(
            {
                "name": label,
                "exit_code": response.returncode,
                "stdout_sha256": hashlib.sha256(response.stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(response.stderr).hexdigest(),
            }
        )
        (output / "commands.json").write_bytes(encoded(commands))
        require(response.returncode == expected)
        return response

    inspect = runpy.run_path(str(ROOT / "scripts/mac_full_image_installer_probe.py"))
    helper = runpy.run_path(str(ROOT / "scripts/mac_component_update_installer_probe.py"))
    inspect["inventory"].__globals__["h"] = SimpleNamespace(**helper)
    inventory = inspect["inventory"]
    expected_original = json.loads(args.inventory95.read_bytes())
    expected_proof = proof_inventory(expected_original)
    # PACKAGE95 and INVENTORY95 are independently frozen before extraction.
    # Avoid writing unchanged ancestor payloads only to discard them again.
    # Every retained resource, including the original broker, must still match
    # the exact frozen inventory. The final package is expanded independently.
    archive = output / "previous-archive"
    archive.mkdir(mode=0o700)
    command(
        "extract-previous-container",
        ["/usr/bin/xar", "-xf", str(args.package95.absolute()), "-C", str(archive), "Scripts"],
    )
    require(
        {p.name for p in archive.iterdir()} == {"Scripts"}
        and (archive / "Scripts").is_file()
        and not (archive / "Scripts").is_symlink()
    )
    expanded = output / "previous"
    expanded.mkdir(mode=0o700)
    previous_scripts = expanded / "Scripts"
    previous_scripts.mkdir(mode=expected_proof[""]["mode"])
    command("extract-previous-proof", proof_extract_command(archive / "Scripts", previous_scripts))
    for relative in ("TargetImage", "Predecessor/CompletedImage"):
        path = previous_scripts / relative
        if not os.path.lexists(path):
            path.mkdir(mode=0o755)
        require(path.is_dir() and not path.is_symlink())
    require(inventory(previous_scripts) == expected_proof)
    require(sha(previous_scripts / "TargetManifest.json") == BEFORE)
    shutil.rmtree(archive)
    scripts = output / "scripts"
    scripts.mkdir(mode=0o755)
    os.rename(expanded / "Scripts", scripts / "Predecessor")
    require(inventory(scripts / "Predecessor") == expected_proof)
    image = scripts / "TargetImage"
    image.mkdir(mode=0o755)
    for relative in (
        "Applications",
        "Library",
        "Library/Application Support",
        "Library/Application Support/Account Access",
    ):
        directory = image / relative
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
    alias = image / "Applications/Account Access.app"
    alias.symlink_to("../Library/Application Support/Account Access/owner.app")
    os.lchmod(alias, 0o755)
    support = scripts / "TargetImage/Library/Application Support/Account Access"
    current_app = support / "owner.app"
    require(args.owner_app.is_dir() and not args.owner_app.is_symlink())
    shutil.copytree(args.owner_app, current_app, symlinks=True)
    (support / "package-identity.json").write_bytes(args.target_identity.read_bytes())
    (support / "package-identity.json").chmod(0o644)
    files = {
        "OwnerUpgradePlan.json": plan_raw,
        "BaseManifest.json": (scripts / "Predecessor/TargetManifest.json").read_bytes(),
        "TargetManifest.json": after_raw,
        "BaseIdentity.json": (scripts / "Predecessor/TargetIdentity.json").read_bytes(),
        "TargetIdentity.json": args.target_identity.read_bytes(),
    }
    sys.path.insert(0, str(ROOT))
    from macos import owner_upgrade104_plan as planner

    planner.parse(
        plan_raw,
        expected_sha256=PLAN,
        before_manifest=files["BaseManifest.json"],
        after_manifest=after_raw,
        old_identity=files["BaseIdentity.json"],
        new_identity=files["TargetIdentity.json"],
        source_files=plan["target_native_source_files"],
    )
    payload_raw = planner.payload_manifest(after_raw)
    public_image(inventory(scripts / "TargetImage"), json.loads(payload_raw))
    (output / "PayloadManifest.json").write_bytes(payload_raw)
    for name, data in files.items():
        (scripts / name).write_bytes(data)
        (scripts / name).chmod(0o644)
    shutil.rmtree(expanded)
    code = output / "source"
    code.mkdir(mode=0o700)
    paths = []
    for name, data in sources.items():
        if name == "macos/ComponentUpdate.swift" or name in (
            *probe["FRAGMENTS"],
            *owner_probe["EXTRA_FRAGMENTS"],
        ):
            continue
        target = code / Path(name).name
        target.write_bytes(data)
        paths.append(str(target))
    combined = code / "ComponentUpdate.swift"
    combined.write_bytes(
        b"\n".join(
            sources[n]
            for n in (
                "macos/ComponentUpdate.swift",
                *probe["FRAGMENTS"],
                *owner_probe["EXTRA_FRAGMENTS"],
            )
        )
    )
    paths.append(str(combined))
    compiled = code / "CompiledPins.swift"
    source_files = ",".join(
        json.dumps(k) + ":" + json.dumps(v)
        for k, v in sorted(plan["target_native_source_files"].items())
    )
    compiled.write_bytes(
        args.pins95.read_bytes()
        + (
            "\nenum OwnerUpgradeCompiledPins { static let value = OwnerUpgradeSource.Pins("
            f'planSHA256: "{PLAN}", beforeSHA256: "{BEFORE}", afterSHA256: "{AFTER}", '
            f'predecessorRuntimePlan: "{plan["predecessor_runtime_plan_sha256"]}", '
            f'targetSource: "{TARGET}", sourceFiles: [{source_files}]) }}\n'
        ).encode()
    )
    paths.append(str(compiled))
    binary = scripts / "AccountAccess-ownerupgrade"
    command(
        "compile",
        [
            "/usr/bin/xcrun",
            "swiftc",
            "-j",
            "2",
            "-O",
            "-whole-module-optimization",
            "-parse-as-library",
            "-warnings-as-errors",
            "-D",
            "ACCOUNT_ACCESS_OWNER_UPGRADE_MAIN",
            "-target",
            "arm64-apple-macos14",
            "-module-cache-path",
            str(output / "module-cache"),
            "-framework",
            "Foundation",
            "-framework",
            "CryptoKit",
            "-framework",
            "Security",
            *paths,
            "-o",
            str(binary),
        ],
        timeout=1800,
    )
    binary.chmod(0o755)
    target = helper_target(binary.read_bytes())
    command(
        "sign",
        [
            "/usr/bin/codesign",
            "--options",
            "runtime",
            "--timestamp",
            "--identifier",
            "com.fainir.accountaccess.componentupdate",
            "--sign",
            args.signing_identity,
            str(binary),
        ],
        timeout=120,
    )
    command(
        "signature",
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict",
            "-R=anchor apple generic and identifier "
            '"com.fainir.accountaccess.componentupdate" and certificate leaf[subject.OU] = "WBULD6N4NQ" '
            'and !(entitlement["com.apple.security.get-task-allow"] exists)',
            str(binary),
        ],
        timeout=120,
    )
    refused = command("ordinary-refusal", [str(binary)], expected=78, timeout=30)
    require(
        not refused.stderr
        and json.loads(refused.stdout)
        == {"schema": 1, "status": "REFUSED", "reason": "owner_upgrade_installer_context_required"}
    )
    wrapper = owner_wrapper((scripts / "Predecessor/postinstall").read_bytes(),
                            sha(scripts / "Predecessor/AccountAccess-runtimeupgrade"), sha(binary))
    (scripts / "postinstall").write_bytes(wrapper)
    (scripts / "postinstall").chmod(0o755)
    command("wrapper", ["/bin/sh", "-n", str(scripts / "postinstall")], timeout=30)
    verify_wrapper_binding((scripts / "postinstall").read_bytes(), sha(binary))
    final_inventory = inventory(scripts)
    package = output / "Account-Access-Owner-Upgrade-104-local-unsigned-1800.pkg"
    raw_package = output / "raw.pkg"
    command(
        "package",
        [
            "/usr/bin/pkgbuild",
            "--nopayload",
            "--identifier",
            IDENTIFIER,
            "--version",
            "0.1.0",
            "--scripts",
            str(scripts),
            str(raw_package),
        ],
    )
    container = output / "container"
    container.mkdir(mode=0o700)
    command("extract-container", ["/usr/bin/xar", "-xf", str(raw_package), "-C", str(container)])
    require({p.name for p in container.iterdir()} == {"PackageInfo", "Scripts"})
    raw_package.unlink()
    info = (container / "PackageInfo").read_bytes()
    require(
        info.count(b'timeout="600"') == 1
        and IDENTIFIER.encode() in info
        and info.count(b'postinstall-action="none"') == 1
    )
    (container / "PackageInfo").write_bytes(info.replace(b'timeout="600"', b'timeout="1800"'))
    command(
        "repack",
        ["/usr/bin/xar", "--compression=none", "-cf", str(package), "PackageInfo", "Scripts"],
        cwd=container,
    )
    independent = output / "independent"
    command("expand-final", ["/usr/sbin/pkgutil", "--expand-full", str(package), str(independent)])
    require(
        inventory(independent / "Scripts") == final_inventory
        and (independent / "PackageInfo").read_bytes() == (container / "PackageInfo").read_bytes()
    )
    verify_wrapper_binding((independent / "Scripts/postinstall").read_bytes(),
                           sha(independent / "Scripts/AccountAccess-ownerupgrade"))
    require(helper_target((independent / "Scripts/AccountAccess-ownerupgrade").read_bytes()) == target)
    shutil.rmtree(independent)
    shutil.rmtree(container)
    (output / "scripts-inventory.json").write_bytes(encoded(final_inventory))
    report = {
        "schema": 1,
        "status": "BUILT_PENDING_INSTALLER_QA",
        "controller_source": args.source,
        "application_source": TARGET,
        "plan_sha256": PLAN,
        "before_manifest_sha256": BEFORE,
        "after_manifest_sha256": AFTER,
        "package_sha256": sha(package),
        "package_bytes": package.stat().st_size,
        "helper_sha256": sha(binary),
        "helper_target": target,
        "scripts_inventory_sha256": sha(output / "scripts-inventory.json"),
        "compiled_pins_sha256": sha(compiled),
        "payload_manifest_sha256": hashlib.sha256(payload_raw).hexdigest(),
        "predecessor_proof_inventory_sha256": hashlib.sha256(encoded(expected_proof)).hexdigest(),
        "predecessor_payloads_omitted": ["TargetImage/*", "Predecessor/CompletedImage/*"],
        "predecessor_container_sha256": PACKAGE95,
        "predecessor_full_inventory_sha256": INVENTORY95,
        "predecessor_extraction": "fixed_sparse_archive_projection",
        "source_sha256": {n: hashlib.sha256(data).hexdigest() for n, data in sources.items()},
        "shared_qa_sha256": sha(args.shared_qa),
        "runtime_qa_sha256": sha(args.runtime_qa),
        "owner_qa_sha256": sha(args.owner_qa),
        "postinstall_timeout": 1800,
        "postinstall_action": "none",
        "postinstall_helper_binding_verified": True,
        "installed": False,
        "production_ready": False,
    }
    (output / "review.json").write_bytes(encoded(report))
    print(
        json.dumps(
            {
                k: report[k]
                for k in ("status", "controller_source", "package_sha256", "package_bytes")
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "package95",
        "inventory95",
        "pins95",
        "owner-app",
        "target-manifest",
        "target-identity",
        "plan",
        "shared-qa",
        "runtime-qa",
        "owner-qa",
        "output",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--signing-identity", required=True)
    build(parser.parse_args())
