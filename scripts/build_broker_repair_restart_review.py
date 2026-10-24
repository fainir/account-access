"""Build-only controller replacement for the frozen repair-87 public image.

No installed path, account store, owner command or Installer is accessed. The
new helper must come from committed source matching the native QA report. Its
two changed resources are independently checked against the frozen inventory.
The existing application's old runtime still requires a separate update.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
from types import SimpleNamespace

PAYLOAD_SOURCE = "c4cf1b0918c1a51cbd4a38880364fcb71fa5980e"
PACKAGE_SHA = "27ee29eea45992461d0d8e5d2f36878a784b15f52713066f9710647715420994"
INVENTORY_SHA = "85e47bfad45e06188484ce002e1df0a24fd7048c1b5abc5ae2baea4025314cca"
REVIEW_SHA = "3e034cc68a2bc407603d43f61df61cb9665a698d7053e51f9431ca08e2597a09"
FULL_PINS_SHA = "dab62cbad1c11821681be4ab480d8153457da7b16a6ec2e012a5d341555c0ba4"
PLAN = "3741aae23c6c23c9da33ae233d0657800454514042d59cba951e7bbf7d1d8ec1"
PREDECESSOR = "9dbd37cf8282fe605de7d73a828b6e4d6379e021177cc089a0b21f522f8edd85"
BEFORE = "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da"
AFTER = "5a732de4623ba50aefa6d31c54e7b1eae660b2921341f95042c5675d922d808b"


def require(condition):
    if not condition:
        raise ValueError("broker_repair_restart_build_refused")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def package_profile(cohort):
    require(type(cohort) is int and cohort in {88, 90})
    return (f"com.fainir.accountaccess.brokerrepair{cohort}",
            f"Account-Access-Broker-Repair-{cohort}-local-unsigned-1800.pkg")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def unchanged_resources(before, after, helper, wrapper):
    require(type(before) is dict and type(after) is dict and before.keys() == after.keys())
    changed = {name for name in before if before[name] != after[name]}
    require(changed == {"AccountAccess-brokerrepair", "postinstall"})
    for name, raw in (("AccountAccess-brokerrepair", helper), ("postinstall", wrapper)):
        require(after[name] == {"kind": "file", "mode": 0o755, "acl": "empty",
                               "bytes": len(raw), "sha256": digest(raw)})


def native_qa(report, sources):
    require(report.get("status") == "PASSED" and report.get("sources_stable") is True
            and report.get("guarded_main_refusals") == 6
            and report.get("entrypoint_ordinary_refusal", {}).get("exit_code") == 78
            and report.get("repair_entrypoint_ordinary_refusal", {}).get("exit_code") == 78
            and all(report.get("source_sha256", {}).get(name) == digest(raw) for name, raw in sources.items()))


def build(args):
    require(sys.platform == "darwin" and os.getuid() == os.geteuid() != 0
            and re.fullmatch("[a-f0-9]{40}", args.source)
            and re.fullmatch("[A-F0-9]{40}", args.signing_identity))
    identifier, package_name = package_profile(getattr(args, "cohort", 88))
    root, output = args.repository.resolve(strict=True), args.output.absolute()
    require(output.parent.is_dir() and not output.exists() and not output.is_symlink())
    require(sha(args.package87) == PACKAGE_SHA and sha(args.inventory87) == INVENTORY_SHA
            and sha(args.review87) == REVIEW_SHA and sha(args.full_pins) == FULL_PINS_SHA)
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root, timeout=30)
    require(git("rev-parse", "HEAD").decode().strip() == args.source)
    probe = runpy.run_path(str(root / "scripts/mac_full_image_installed_probe.py"))
    names = ["macos/" + name for name in probe["DEPENDENCIES"]]
    names += ["macos/FullImageInstalledIO.swift", "macos/FullImagePredecessorAuthority.swift",
              "macos/BrokerRepairMain.swift", "macos/ComponentUpdate.swift", *probe["FRAGMENTS"]]
    require(len(names) == len(set(names)))
    sources = {name: (root / name).read_bytes() for name in names}
    require(all(raw == git("show", args.source + ":" + name) for name, raw in sources.items()))
    qa = json.loads(args.qa_report.read_bytes())
    native_qa(qa, sources)
    previous = json.loads(args.review87.read_bytes())
    require(previous["source_commit"] == PAYLOAD_SOURCE and previous["plan_sha256"] == PLAN
            and previous["before_manifest_sha256"] == BEFORE and previous["after_manifest_sha256"] == AFTER)
    for name, expected in previous["native_sources"].items():
        require(re.fullmatch(r"macos/[A-Za-z0-9_.-]+\.(?:swift|h|c)", name)
                and digest(git("show", PAYLOAD_SOURCE + ":" + name)) == expected)
    output.mkdir(mode=0o700)
    commands = []
    def command(label, argv, *, cwd=root, expected=0, timeout=900):
        result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        (output / (label + ".stdout")).write_bytes(result.stdout)
        (output / (label + ".stderr")).write_bytes(result.stderr)
        commands.append({"name": label, "command": list(map(str, argv)), "exit_code": result.returncode})
        (output / "commands.json").write_bytes(encoded(commands))
        require(result.returncode == expected)
        return result
    expanded = output / "input"
    command("expand-input", ["/usr/sbin/pkgutil", "--expand-full", str(args.package87.absolute()), str(expanded)])
    helper = runpy.run_path(str(root / "scripts/mac_component_update_installer_probe.py"))
    inspect = runpy.run_path(str(root / "scripts/mac_full_image_installer_probe.py"))
    inspect["inventory"].__globals__["h"] = SimpleNamespace(**helper)
    scripts = expanded / "Scripts"
    original = json.loads(args.inventory87.read_bytes())
    require(inspect["inventory"](scripts) == original)
    require(sha(scripts / "BrokerRepairPlan.json") == PLAN
            and sha(scripts / "CompletedImage/FullImagePlan.json") == PREDECESSOR
            and sha(scripts / "BaseManifest.json") == BEFORE and sha(scripts / "TargetManifest.json") == AFTER)
    code = output / "source"
    code.mkdir(mode=0o700)
    paths = []
    for name in names:
        if name == "macos/ComponentUpdate.swift" or name in probe["FRAGMENTS"]:
            continue
        path = code / Path(name).name
        path.write_bytes(sources[name])
        paths.append(str(path))
    composed = code / "ComponentUpdate.swift"
    composed.write_bytes(b"\n".join(sources[name] for name in ["macos/ComponentUpdate.swift", *probe["FRAGMENTS"]]))
    paths.append(str(composed))
    full = code / "FullImageUpdateCompiledPins.swift"
    full.write_bytes(args.full_pins.read_bytes())
    paths.append(str(full))
    repair = code / "BrokerRepairCompiledPins.swift"
    repair.write_text('enum BrokerRepairCompiledPins { static let value = BrokerRepairSource.Pins('
        f'planSHA256: "{PLAN}", predecessorPlanSHA256: "{PREDECESSOR}", beforeManifestSHA256: "{BEFORE}", '
        f'afterManifestSHA256: "{AFTER}", sourceCommit: "{PAYLOAD_SOURCE}") }}\n')
    paths.append(str(repair))
    binary = scripts / "AccountAccess-brokerrepair"
    old_helper_sha = sha(binary)
    wrapper = (scripts / "postinstall").read_bytes()
    require(wrapper.count(old_helper_sha.encode()) == 1)
    binary.unlink()
    command("compile", ["/usr/bin/xcrun", "swiftc", "-j", "2", "-O", "-whole-module-optimization",
        "-parse-as-library", "-warnings-as-errors", "-D", "ACCOUNT_ACCESS_BROKER_REPAIR_MAIN",
        "-target", "arm64-apple-macos14", "-module-cache-path", str(output / "module-cache"),
        "-framework", "Foundation", "-framework", "CryptoKit", "-framework", "Security",
        *paths, "-o", str(binary)], timeout=1800)
    binary.chmod(0o755)
    command("sign", ["/usr/bin/codesign", "--options", "runtime", "--timestamp", "--identifier",
        "com.fainir.accountaccess.componentupdate", "--sign", args.signing_identity, str(binary)], timeout=120)
    command("verify-signature", ["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple generic and identifier "
        '\"com.fainir.accountaccess.componentupdate\" and certificate leaf[subject.OU] = \"WBULD6N4NQ\" '
        'and !(entitlement[\"com.apple.security.get-task-allow\"] exists)', str(binary)], timeout=120)
    refusal = command("ordinary-refusal", [str(binary)], expected=78, timeout=30)
    require(refusal.stdout == b'{"schema":1,"status":"REFUSED","reason":"broker_repair_installer_context_required"}\n'
            and refusal.stderr == b"")
    wrapper = wrapper.replace(old_helper_sha.encode(), sha(binary).encode())
    (scripts / "postinstall").write_bytes(wrapper)
    command("wrapper-syntax", ["/bin/sh", "-n", str(scripts / "postinstall")], timeout=30)
    inventory = inspect["inventory"](scripts)
    unchanged_resources(original, inventory, binary.read_bytes(), wrapper)
    raw_package = output / "raw.pkg"
    command("package", ["/usr/bin/pkgbuild", "--nopayload", "--identifier", identifier,
        "--version", "0.1.0", "--scripts", str(scripts), str(raw_package)])
    container = output / "container"
    container.mkdir(mode=0o700)
    command("extract-container", ["/usr/bin/xar", "-xf", str(raw_package), "-C", str(container)])
    require({p.name for p in container.iterdir()} == {"PackageInfo", "Scripts"})
    info = (container / "PackageInfo").read_bytes()
    require(info.count(b'timeout="600"') == 1 and identifier.encode() in info)
    (container / "PackageInfo").write_bytes(info.replace(b'timeout="600"', b'timeout="1800"'))
    package = output / package_name
    command("repack", ["/usr/bin/xar", "--compression=none", "-cf", str(package), "PackageInfo", "Scripts"], cwd=container)
    independent = output / "independent"
    command("expand-final", ["/usr/sbin/pkgutil", "--expand-full", str(package), str(independent)])
    require(inspect["inventory"](independent / "Scripts") == inventory
            and (independent / "PackageInfo").read_bytes() == (container / "PackageInfo").read_bytes())
    (output / "scripts-inventory.json").write_bytes(encoded(inventory))
    report = {"schema": 1, "status": "BUILT_PENDING_INSTALLER_QA", "source_commit": PAYLOAD_SOURCE,
        "controller_source_commit": args.source, "plan_sha256": PLAN, "before_manifest_sha256": BEFORE,
        "after_manifest_sha256": AFTER, "broker_sha256": previous["broker_sha256"], "helper_sha256": sha(binary),
        "package_sha256": sha(package), "package_bytes": package.stat().st_size, "postinstall_timeout": 1800,
        "native_sources": previous["native_sources"], "controller_sources": {n: digest(r) for n, r in sources.items()},
        "compiled_pins": {p.name: sha(p) for p in (full, repair)}, "qa_report_sha256": sha(args.qa_report),
        "scripts_inventory_sha256": sha(output / "scripts-inventory.json"), "expanded_nodes": len(inventory),
        "changed_resources": ["AccountAccess-brokerrepair", "postinstall"], "independent_expansion_passed": True,
        "installer_signed": False, "installed": False, "runtime_update_required": True, "production_ready": False}
    (output / "review.json").write_bytes(encoded(report))
    print(json.dumps({k: report[k] for k in ("status", "package_sha256", "package_bytes", "installed", "production_ready")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "package87", "inventory87", "review87", "full-pins", "qa-report", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--signing-identity", required=True)
    parser.add_argument("--cohort", type=int, choices=[88, 90], default=88)
    build(parser.parse_args())
