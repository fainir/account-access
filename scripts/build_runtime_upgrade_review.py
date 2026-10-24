"""Build-only fixed package91 -> runtime92 upgrade; never run Installer.

Requires committed controller sources matching both ordinary native QA reports.
Only public package inputs and a new output directory are read or written.
"""
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
REPAIR_PACKAGE = "ed747b1ce30364f42c9d1b4f702d098722cec10eee7a97a3618f7cae2ba12d80"
REPAIR_INVENTORY = "c1ffb9577ded666a452edc719affe0d2e84f636a7714bf3e87f6f48e6413037c"
FRESH_PACKAGE = "2a4244ca550511553695063ac31217379f3bc9bf31199aa3426eecf5d3309445"
PLAN = "671c32eb5daacb79a1ec5f63d97cc29d2b6f34b5c75a773a1b477aca981ce6df"
BEFORE = "5a732de4623ba50aefa6d31c54e7b1eae660b2921341f95042c5675d922d808b"
AFTER = "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
TARGET = "7051ef225ff2f35d67576d0ddbbc3e0b107e00bf"
FULL_PINS = "dab62cbad1c11821681be4ab480d8153457da7b16a6ec2e012a5d341555c0ba4"
IDENTIFIER = "com.fainir.accountaccess.runtimeupgrade94"


def require(value):
    if not value:
        raise ValueError("runtime_upgrade_build_refused")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def native_qa(shared, runtime, sources):
    require(shared.get("status") == "PASSED" and shared.get("sources_stable") is True
            and shared.get("guarded_main_refusals") == 6 and runtime.get("status") == "PASSED"
            and runtime.get("entrypoint_ordinary_refusal") is True
            and type(runtime.get("result", {}).get("checks")) is int and runtime["result"]["checks"] == 68
            and runtime["result"].get("status") == "PASSED"
            and runtime.get("installed_reads") is False and runtime.get("production_ready") is False
            and bool(sources))
    for name, raw in sources.items():
        digest = hashlib.sha256(raw).hexdigest()
        require(runtime.get("source_sha256", {}).get(name) == digest)
        if name != "macos/RuntimeUpgradeMain.swift":
            require(shared.get("source_sha256", {}).get(name) == digest)


def build(args):
    require(sys.platform == "darwin" and os.getuid() == os.geteuid() != 0
            and re.fullmatch("[a-f0-9]{40}", args.source)
            and re.fullmatch("[A-F0-9]{40}", args.signing_identity))
    output = args.output.absolute()
    require(output.parent.is_dir() and not os.path.lexists(output))
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=ROOT, timeout=30)
    require(git("rev-parse", "HEAD").decode().strip() == args.source)
    require(sha(args.package91) == REPAIR_PACKAGE and sha(args.inventory91) == REPAIR_INVENTORY
            and sha(args.runtime92) == FRESH_PACKAGE and sha(args.plan) == PLAN)
    full_pins = ROOT / "artifacts/repair91-full-image-pins.swift"
    require(sha(full_pins) == FULL_PINS)
    probe = runpy.run_path(str(ROOT / "scripts/mac_full_image_installed_probe.py"))
    names = ["macos/" + n for n in probe["DEPENDENCIES"]]
    names += ["macos/FullImageInstalledIO.swift", "macos/FullImagePredecessorAuthority.swift", "macos/RuntimeUpgradeMain.swift",
              "macos/ComponentUpdate.swift", *probe["FRAGMENTS"]]
    require(len(set(names)) == len(names))
    sources = {n: (ROOT / n).read_bytes() for n in names}
    require(all(raw == git("show", args.source + ":" + n) for n, raw in sources.items()))
    shared = json.loads(args.shared_qa.read_bytes())
    runtime = json.loads(args.runtime_qa.read_bytes())
    native_qa(shared, runtime, sources)
    plan_raw = args.plan.read_bytes()
    plan = json.loads(plan_raw)
    require(plan["before_manifest_sha256"] == BEFORE and plan["after_manifest_sha256"] == AFTER
            and plan["target_source"] == TARGET)
    require(all(hashlib.sha256(git("show", TARGET + ":" + n)).hexdigest() == digest
                for n, digest in plan["target_source_files"].items()))
    output.mkdir(mode=0o700)
    commands = []
    def command(label, argv, *, cwd=ROOT, expected=0, timeout=900):
        result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        (output / (label + ".stdout")).write_bytes(result.stdout)
        (output / (label + ".stderr")).write_bytes(result.stderr)
        commands.append({"name": label, "command": list(map(str, argv)), "exit_code": result.returncode})
        (output / "commands.json").write_bytes(encoded(commands))
        require(result.returncode == expected)
        return result
    old = output / "repair91"
    fresh = output / "runtime92"
    command("expand-predecessor", ["/usr/sbin/pkgutil", "--expand-full", str(args.package91.absolute()), str(old)])
    command("expand-target", ["/usr/sbin/pkgutil", "--expand-full", str(args.runtime92.absolute()), str(fresh)])
    helper = runpy.run_path(str(ROOT / "scripts/mac_component_update_installer_probe.py"))
    inspect = runpy.run_path(str(ROOT / "scripts/mac_full_image_installer_probe.py"))
    inspect["inventory"].__globals__["h"] = SimpleNamespace(**helper)
    inventory = inspect["inventory"]
    require(inventory(old / "Scripts") == json.loads(args.inventory91.read_bytes()))
    candidates = list(fresh.rglob("RecoveryManifest.json"))
    require(len(candidates) == 1 and sha(candidates[0]) == AFTER)
    fresh_scripts = candidates[0].parent
    require(sha(old / "Scripts/TargetManifest.json") == BEFORE)
    scripts = output / "scripts"
    scripts.mkdir(mode=0o700)
    shutil.copytree(old / "Scripts", scripts / "Predecessor", symlinks=True)
    shutil.copytree(fresh_scripts / "PublicImage", scripts / "TargetImage", symlinks=True)
    require(inventory(scripts / "Predecessor") == inventory(old / "Scripts"))
    require(inventory(scripts / "TargetImage") == inventory(fresh_scripts / "PublicImage"))
    support = scripts / "TargetImage/Library/Application Support/Account Access"
    files = {"RuntimeUpgradePlan.json": plan_raw, "BaseManifest.json": (old / "Scripts/TargetManifest.json").read_bytes(),
        "TargetManifest.json": candidates[0].read_bytes(), "BaseIdentity.json": (old / "Scripts/TargetIdentity.json").read_bytes(),
        "TargetIdentity.json": (support / "package-identity.json").read_bytes()}
    sys.path.insert(0, str(ROOT))
    from macos import runtime_upgrade_plan as planner
    planner.parse(plan_raw, expected_sha256=PLAN, before_manifest=files["BaseManifest.json"],
        after_manifest=files["TargetManifest.json"], old_identity=files["BaseIdentity.json"],
        new_identity=files["TargetIdentity.json"], source_files=plan["target_source_files"])
    for name, raw in files.items():
        (scripts / name).write_bytes(raw)
        (scripts / name).chmod(0o644)
    code = output / "source"
    code.mkdir(mode=0o700)
    paths = []
    for name, raw in sources.items():
        if name == "macos/ComponentUpdate.swift" or name in probe["FRAGMENTS"]:
            continue
        target = code / Path(name).name
        target.write_bytes(raw)
        paths.append(str(target))
    combined = code / "ComponentUpdate.swift"
    combined.write_bytes(b"\n".join(sources[n] for n in ["macos/ComponentUpdate.swift", *probe["FRAGMENTS"]]))
    paths.append(str(combined))
    compiled = code / "CompiledPins.swift"
    source_files = ",".join(json.dumps(k) + ":" + json.dumps(v) for k, v in sorted(plan["target_source_files"].items()))
    compiled.write_bytes(full_pins.read_bytes() + (
        '\nenum BrokerRepairCompiledPins { static let value = BrokerRepairSource.Pins('
        f'planSHA256: "{plan["predecessor_repair_plan_sha256"]}", '
        'predecessorPlanSHA256: "9dbd37cf8282fe605de7d73a828b6e4d6379e021177cc089a0b21f522f8edd85", '
        'beforeManifestSHA256: "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da", '
        f'afterManifestSHA256: "{BEFORE}", sourceCommit: "{plan["predecessor_repair_source"]}") }}\n'
        'enum RuntimeUpgradeCompiledPins { static let value = RuntimeUpgradeSource.Pins('
        f'planSHA256: "{PLAN}", beforeSHA256: "{BEFORE}", afterSHA256: "{AFTER}", '
        f'repairPlan: "{plan["predecessor_repair_plan_sha256"]}", repairSource: "{plan["predecessor_repair_source"]}", '
        f'targetSource: "{TARGET}", sourceFiles: [{source_files}]) }}\n').encode())
    paths.append(str(compiled))
    binary = scripts / "AccountAccess-runtimeupgrade"
    command("compile", ["/usr/bin/xcrun", "swiftc", "-j", "2", "-O", "-whole-module-optimization",
        "-parse-as-library", "-warnings-as-errors", "-D", "ACCOUNT_ACCESS_RUNTIME_UPGRADE_MAIN",
        "-target", "arm64-apple-macos14", "-module-cache-path", str(output / "module-cache"),
        "-framework", "Foundation", "-framework", "CryptoKit", "-framework", "Security", *paths, "-o", str(binary)], timeout=1800)
    binary.chmod(0o755)
    command("sign", ["/usr/bin/codesign", "--options", "runtime", "--timestamp", "--identifier",
        "com.fainir.accountaccess.componentupdate", "--sign", args.signing_identity, str(binary)], timeout=120)
    command("verify-signature", ["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple generic and identifier "
        '\"com.fainir.accountaccess.componentupdate\" and certificate leaf[subject.OU] = \"WBULD6N4NQ\" '
        'and !(entitlement[\"com.apple.security.get-task-allow\"] exists)', str(binary)], timeout=120)
    refusal = command("ordinary-refusal", [str(binary)], expected=78, timeout=30)
    require(refusal.stdout == b'{"schema":1,"status":"REFUSED","reason":"runtime_upgrade_installer_context_required"}\n'
            and not refusal.stderr)
    wrapper = (old / "Scripts/postinstall").read_bytes()
    old_sha = sha(old / "Scripts/AccountAccess-brokerrepair").encode()
    require(wrapper.count(old_sha) == 1 and wrapper.count(b"AccountAccess-brokerrepair") == 1)
    wrapper = wrapper.replace(old_sha, sha(binary).encode()).replace(b"AccountAccess-brokerrepair", b"AccountAccess-runtimeupgrade")
    (scripts / "postinstall").write_bytes(wrapper)
    (scripts / "postinstall").chmod(0o755)
    command("wrapper-syntax", ["/bin/sh", "-n", str(scripts / "postinstall")], timeout=30)
    final_inventory = inventory(scripts)
    raw = output / "raw.pkg"
    command("package", ["/usr/bin/pkgbuild", "--nopayload", "--identifier", IDENTIFIER,
        "--version", "0.1.0", "--scripts", str(scripts), str(raw)])
    container = output / "container"
    container.mkdir(mode=0o700)
    command("extract-container", ["/usr/bin/xar", "-xf", str(raw), "-C", str(container)])
    require({p.name for p in container.iterdir()} == {"PackageInfo", "Scripts"})
    info = (container / "PackageInfo").read_bytes()
    require(info.count(b'timeout="600"') == 1 and IDENTIFIER.encode() in info)
    (container / "PackageInfo").write_bytes(info.replace(b'timeout="600"', b'timeout="1800"'))
    package = output / "Account-Access-Runtime-Upgrade-94-local-unsigned-1800.pkg"
    command("repack", ["/usr/bin/xar", "--compression=none", "-cf", str(package), "PackageInfo", "Scripts"], cwd=container)
    independent = output / "independent"
    command("expand-final", ["/usr/sbin/pkgutil", "--expand-full", str(package), str(independent)])
    require(inventory(independent / "Scripts") == final_inventory
            and (independent / "PackageInfo").read_bytes() == (container / "PackageInfo").read_bytes())
    (output / "scripts-inventory.json").write_bytes(encoded(final_inventory))
    report = {"schema": 1, "status": "BUILT_PENDING_INSTALLER_QA", "controller_source": args.source,
        "application_source": TARGET, "plan_sha256": PLAN, "before_manifest_sha256": BEFORE, "after_manifest_sha256": AFTER,
        "package_sha256": sha(package), "package_bytes": package.stat().st_size, "helper_sha256": sha(binary),
        "scripts_inventory_sha256": sha(output / "scripts-inventory.json"), "compiled_pins_sha256": sha(compiled),
        "source_sha256": {n: hashlib.sha256(raw).hexdigest() for n, raw in sources.items()},
        "shared_qa_sha256": sha(args.shared_qa), "runtime_qa_sha256": sha(args.runtime_qa),
        "postinstall_timeout": 1800, "installed": False, "production_ready": False}
    (output / "review.json").write_bytes(encoded(report))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package91", "inventory91", "runtime92", "plan", "shared-qa", "runtime-qa", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--signing-identity", required=True)
    build(parser.parse_args())
