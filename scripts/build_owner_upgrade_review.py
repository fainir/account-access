"""Build-only fixed owner97 successor from frozen public inputs; never install."""

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
PACKAGE95 = "0c7a83b47d405bd9b02686aceb938877c5cd2f36112cb0b8369069c643453371"
INVENTORY95 = "9072d9bce2fd9c1b6118e657c77cab3f32e5c44689f4bb230132f07bbbb0e1e1"
PINS95 = "c63ff71959f969edf95fe11b02672ea195a0d2b5cb607c7f2afa67e2a7a1a49a"
PLAN = "1b5812e7e6618ce92a242f6acc5683daccd4485c7e2e57859597c029960ee42c"
BEFORE = "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
AFTER = "c80f0430c7529acb8479661554aadd7e6b1cfb98303df1e2bda1e5024a75356c"
TARGET = "6736a20f8ed20d9188380b83b808ec9e380df501"
IDENTIFIER = "com.fainir.accountaccess.ownerupgrade97"


def require(value):
    if not value:
        raise ValueError("owner_upgrade_build_refused")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate_qa(shared, runtime, owner, sources):
    require(
        shared.get("status") == "PASSED"
        and shared.get("sources_stable") is True
        and shared.get("guarded_main_refusals") == 6
        and runtime.get("status") == "PASSED"
        and runtime.get("entrypoint_ordinary_refusal") is True
        and runtime.get("result", {}).get("status") == "PASSED"
        and runtime.get("result", {}).get("checks") == 68
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
        and rows[0].get("checks") == 29
        and rows[1].get("ordinary_context_refusals") == 2
        and rows[1].get("namespace_checks") == 26
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


def build(args):
    require(
        sys.platform == "darwin"
        and os.getuid() == os.geteuid() != 0
        and re.fullmatch("[a-f0-9]{40}", args.source)
        and re.fullmatch("[A-F0-9]{40}", args.signing_identity)
    )
    output = args.output.absolute()
    require(output.parent.is_dir() and not os.path.lexists(output))

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
    require(
        (ROOT / "scripts/build_owner_upgrade_review.py").read_bytes()
        == git("show", args.source + ":scripts/build_owner_upgrade_review.py")
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
    plan, after = json.loads(plan_raw), json.loads(after_raw)
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
    expanded = output / "previous"
    command(
        "expand-previous",
        ["/usr/sbin/pkgutil", "--expand-full", str(args.package95.absolute()), str(expanded)],
    )
    require(inventory(expanded / "Scripts") == json.loads(args.inventory95.read_bytes()))
    require(sha(expanded / "Scripts/TargetManifest.json") == BEFORE)
    scripts = output / "scripts"
    scripts.mkdir(mode=0o755)
    shutil.copytree(expanded / "Scripts", scripts / "Predecessor", symlinks=True)
    require(inventory(scripts / "Predecessor") == json.loads(args.inventory95.read_bytes()))
    shutil.copytree(scripts / "Predecessor/TargetImage", scripts / "TargetImage", symlinks=True)
    support = scripts / "TargetImage/Library/Application Support/Account Access"
    current_app = support / "owner.app"
    # Only the new exclusive build copy is removed. The source and installation
    # are never selected as destinations by this builder.
    require(current_app.parent == support and current_app.is_dir() and not current_app.is_symlink())
    shutil.rmtree(current_app)
    require(args.owner_app.is_dir() and not args.owner_app.is_symlink())
    shutil.copytree(args.owner_app, current_app, symlinks=True)
    (support / "package-identity.json").write_bytes(args.target_identity.read_bytes())
    files = {
        "OwnerUpgradePlan.json": plan_raw,
        "BaseManifest.json": (scripts / "Predecessor/TargetManifest.json").read_bytes(),
        "TargetManifest.json": after_raw,
        "BaseIdentity.json": (scripts / "Predecessor/TargetIdentity.json").read_bytes(),
        "TargetIdentity.json": args.target_identity.read_bytes(),
    }
    sys.path.insert(0, str(ROOT))
    from macos import owner_upgrade_plan as planner

    planner.parse(
        plan_raw,
        expected_sha256=PLAN,
        before_manifest=files["BaseManifest.json"],
        after_manifest=after_raw,
        old_identity=files["BaseIdentity.json"],
        new_identity=files["TargetIdentity.json"],
        source_files=plan["target_native_source_files"],
    )
    public_image(inventory(scripts / "TargetImage"), after)
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
    wrapper = (scripts / "Predecessor/postinstall").read_bytes()
    old_digest = sha(scripts / "Predecessor/AccountAccess-runtimeupgrade").encode()
    require(wrapper.count(old_digest) == 1 and wrapper.count(b"AccountAccess-runtimeupgrade") == 1)
    wrapper = wrapper.replace(old_digest, sha(binary).encode()).replace(
        b"AccountAccess-runtimeupgrade", b"AccountAccess-ownerupgrade"
    )
    (scripts / "postinstall").write_bytes(wrapper)
    (scripts / "postinstall").chmod(0o755)
    command("wrapper", ["/bin/sh", "-n", str(scripts / "postinstall")], timeout=30)
    final_inventory = inventory(scripts)
    package = output / "Account-Access-Owner-Upgrade-97-local-unsigned-1800.pkg"
    raw_package = output / "raw.pkg"
    command(
        "package",
        [
            "/usr/sbin/pkgbuild",
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
        "scripts_inventory_sha256": sha(output / "scripts-inventory.json"),
        "compiled_pins_sha256": sha(compiled),
        "source_sha256": {n: hashlib.sha256(data).hexdigest() for n, data in sources.items()},
        "shared_qa_sha256": sha(args.shared_qa),
        "runtime_qa_sha256": sha(args.runtime_qa),
        "owner_qa_sha256": sha(args.owner_qa),
        "postinstall_timeout": 1800,
        "postinstall_action": "none",
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
