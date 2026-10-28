"""Ordinary, temp-only native owner-upgrade checks; never install an update."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXTRA_FRAGMENTS = (
    "macos/source-fragments/CompletedRuntimeUpgrade.swift.inc",
    "macos/source-fragments/OwnerUpgradeInstalledAdapter.swift.inc",
)
DUMMY = b"""
enum RuntimeUpgradeCompiledPins {
    static let value = RuntimeUpgradeSource.Pins(planSHA256: String(repeating: "0", count: 64),
        beforeSHA256: String(repeating: "0", count: 64), afterSHA256: String(repeating: "0", count: 64),
        repairPlan: String(repeating: "0", count: 64), repairSource: String(repeating: "0", count: 40),
        targetSource: String(repeating: "0", count: 40), sourceFiles: [:])
}
enum OwnerUpgradeCompiledPins {
    static let value = OwnerUpgradeSource.Pins(planSHA256: String(repeating: "0", count: 64),
        beforeSHA256: String(repeating: "0", count: 64), afterSHA256: String(repeating: "0", count: 64),
        predecessorRuntimePlan: String(repeating: "0", count: 64), targetSource: String(repeating: "0", count: 40),
        sourceFiles: [:])
}
"""
DISPATCHER = b"""
import Foundation
import Darwin
@main struct OwnerUpgradeProbe {
    static func main() throws {
        guard getuid() != 0, getuid() == geteuid(), CommandLine.arguments.count == 2 else { exit(78) }
        var contexts = 0
        func context(_ body: () throws -> Void) throws {
            do { try body() } catch ComponentUpdateFailure.context { contexts += 1; return }
            throw FullImageFailure.unavailable
        }
        try context { _ = try ComponentController.completedRuntimeUpgrade(resources: -1,
            pins: RuntimeUpgradeCompiledPins.value, repairPins: BrokerRepairCompiledPins.value,
            predecessorPins: FullImageUpdateCompiledPins.value) }
        try context { _ = try ComponentController.runOwnerUpgrade(resources: -1,
            pins: OwnerUpgradeCompiledPins.value, runtimePins: RuntimeUpgradeCompiledPins.value,
            repairPins: BrokerRepairCompiledPins.value, predecessorPins: FullImageUpdateCompiledPins.value) }
        let namespaces = try RuntimeUpgradeNamespaceChecks.run() + OwnerUpgradeNamespaceChecks.run()
        let preparation = try OwnerUpgradePreparationChecks.run()
        try OwnerUpgradeSourceChecks.main()
        print("{\\"schema\\":1,\\"status\\":\\"PASSED\\",\\"ordinary_context_refusals\\":" + String(contexts)
            + ",\\"namespace_checks\\":" + String(namespaces) + ",\\"preparation_checks\\":" + String(preparation)
            + ",\\"installed_reads\\":false,\\"production_ready\\":false}")
    }
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError("ordinary_mac_required")
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    sources = output / "sources"
    sources.mkdir(mode=0o700)
    shared = runpy.run_path(str(ROOT / "scripts/mac_full_image_installed_probe.py"))
    fragments = (*shared["FRAGMENTS"], *EXTRA_FRAGMENTS)
    core = ["macos/" + n for n in shared["DEPENDENCIES"]]
    core += [
        "macos/FullImageInstalledIO.swift",
        "macos/FullImagePredecessorAuthority.swift",
        "macos/OwnerUpgradeSource.swift",
    ]
    names = [
        *core,
        "macos/ComponentUpdate.swift",
        *fragments,
        "macos/OwnerUpgradeMain.swift",
        "macos/Tests/OwnerUpgradeSourceChecks.swift",
        "macos/Tests/OwnerUpgradeNamespaceChecks.swift",
        "macos/Tests/OwnerUpgradePreparationChecks.swift",
        "macos/Tests/RuntimeUpgradeNamespaceChecks.swift",
        "macos/Tests/FullImageTransitionStorageChecks.swift",
        "macos/Tests/FullImageTreeStorageChecks.swift",
    ]
    raw = {name: (ROOT / name).read_bytes() for name in names}
    pins = {name: hashlib.sha256(data).hexdigest() for name, data in raw.items()}
    completed_runtime = raw["macos/source-fragments/CompletedRuntimeUpgrade.swift.inc"].decode("utf-8")
    historical_steps = (
        "historicalObservation: true",
        "let proof = try completedBrokerRepairLocked(",
        "repairComponentDevice(resources: previous, pins: predecessorPins",
        "createIfMissing: false, observationDevice: observationDevice",
    )
    positions = [completed_runtime.index(step) for step in historical_steps]
    assert positions == sorted(positions), "completed_runtime_historical_binding_order"
    assert "observationDevice: observationDevice,\n                completedProjection: current" in completed_runtime
    assert "createIfMissing: false, observationDevice: observationDevice, completedProjection: projected" in completed_runtime
    for name in core:
        (sources / Path(name).name).write_bytes(raw[name])
    (sources / "OwnerUpgradeMain.swift").write_bytes(raw["macos/OwnerUpgradeMain.swift"])
    composed = sources / "ComponentUpdate.swift"
    composed.write_bytes(b"\n".join(raw[n] for n in ("macos/ComponentUpdate.swift", *fragments)))
    dummy = sources / "DummyPins.swift"
    dummy.write_bytes(shared["DUMMY_COMPILED_PINS"] + DUMMY)
    dispatch = sources / "Probe.swift"
    dispatch.write_bytes(DISPATCHER)
    flags = [
        "/usr/bin/xcrun",
        "swiftc",
        "-j",
        "2",
        "-O",
        "-parse-as-library",
        "-warnings-as-errors",
        "-module-cache-path",
        str(output / "module-cache"),
        "-framework",
        "Foundation",
        "-framework",
        "CryptoKit",
        "-framework",
        "Security",
    ]

    def command(label, arguments, timeout=900):
        result = subprocess.run(
            arguments,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        (output / (label + ".stdout")).write_bytes(result.stdout)
        (output / (label + ".stderr")).write_bytes(result.stderr)
        if result.returncode != 0 or result.stderr:
            print(
                json.dumps(
                    {
                        "status": "REFUSED",
                        "step": label,
                        "exit_code": result.returncode,
                        "diagnostic": result.stderr.decode(errors="replace")[:8000],
                    }
                )
            )
            raise ValueError("owner_upgrade_probe_failed")
        return result.stdout

    command(
        "inputs",
        [
            sys.executable,
            str(ROOT / "scripts/mac_owner_upgrade_plan_fixture.py"),
            "--output",
            str(output / "inputs"),
        ],
        30,
    )
    core_paths = [str(sources / Path(name).name) for name in core] + [str(composed),
        str(sources / "OwnerUpgradeMain.swift")]
    fixture_names = [
        "OwnerUpgradeSourceChecks",
        "OwnerUpgradeNamespaceChecks",
        "OwnerUpgradePreparationChecks",
        "RuntimeUpgradeNamespaceChecks",
    ]
    for name in fixture_names:
        (sources / (name + ".swift")).write_bytes(raw["macos/Tests/" + name + ".swift"])
    checks = output / "owner-checks"
    command(
        "compile",
        [
            *flags,
            "-D",
            "ACCOUNT_ACCESS_FULL_IMAGE_INSTALLED_CHECKS",
            "-D",
            "ACCOUNT_ACCESS_OWNER_UPGRADE_PROBE",
            *core_paths,
            *[str(sources / (n + ".swift")) for n in fixture_names],
            str(dummy),
            str(dispatch),
            "-o",
            str(checks),
        ],
    )
    lines = command("checks", [str(checks), str(output / "inputs")], 120).splitlines()
    results = [json.loads(line) for line in lines]
    assert len(results) == 2 and all(r["status"] == "PASSED" for r in results)
    entry = sources / "OwnerUpgradeMain.swift"
    entry.write_bytes(raw["macos/OwnerUpgradeMain.swift"])
    entry_core_paths = [path for path in core_paths if Path(path).name != "OwnerUpgradeMain.swift"]
    binary = output / "AccountAccess-ownerupgrade"
    command(
        "entry-compile",
        [
            *flags,
            "-D",
            "ACCOUNT_ACCESS_OWNER_UPGRADE_MAIN",
            *entry_core_paths,
            str(dummy),
            str(entry),
            "-o",
            str(binary),
        ],
    )
    refused = subprocess.run([str(binary)], capture_output=True, timeout=30, check=False)
    (output / "entry-refusal.stdout").write_bytes(refused.stdout)
    (output / "entry-refusal.stderr").write_bytes(refused.stderr)
    assert (
        refused.returncode == 78
        and not refused.stderr
        and json.loads(refused.stdout)
        == {"schema": 1, "status": "REFUSED", "reason": "owner_upgrade_installer_context_required"}
    )
    for name, label, dependencies in [
        (
            "FullImageTreeStorageChecks",
            "trees",
            ["InstallerPayload", "FullImageTreeAttachment", "FullImageTreeStorage"],
        ),
        ("FullImageTransitionStorageChecks", "mixed", None),
    ]:
        test = sources / (name + ".swift")
        test.write_bytes(raw["macos/Tests/" + name + ".swift"])
        selected = (
            core_paths
            if dependencies is None
            else [str(sources / (n + ".swift")) for n in dependencies]
        )
        executable = output / label
        command(label + "-compile", [*flags, *selected, str(test), "-o", str(executable)])
        results.append(json.loads(command(label, [str(executable)], 180)))
    changed_sources = [
        name for name, digest in pins.items()
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest
    ]
    if changed_sources:
        raise ValueError("owner_upgrade_source_changed_during_probe:" + ",".join(sorted(changed_sources)))
    report = {
        "schema": 1,
        "status": "PASSED",
        "results": results,
        "ordinary_entrypoint_refusal": True,
        "source_sha256": pins,
        "installed_reads": False,
        "installed_writes": False,
        "production_ready": False,
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "PASSED", "results": results, "ordinary_entrypoint_refusal": True}))


if __name__ == "__main__":
    main()
