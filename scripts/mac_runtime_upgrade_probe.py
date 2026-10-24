"""Compile and exercise the runtime planner with public fictional inputs only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() != os.getuid():
        raise ValueError("ordinary_mac_required")
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    sources = output / "sources"
    sources.mkdir(mode=0o700)
    shared = runpy.run_path(str(ROOT / "scripts/mac_full_image_installed_probe.py"))
    dependencies = shared["DEPENDENCIES"]
    names = ["macos/" + name for name in dependencies]
    names += ["macos/ComponentUpdate.swift", "macos/FullImageInstalledIO.swift", "macos/FullImagePredecessorAuthority.swift",
              "macos/Tests/RuntimeUpgradeSourceChecks.swift", "macos/Tests/RuntimeUpgradeNamespaceChecks.swift",
              "macos/Tests/RuntimeUpgradeMetadataChecks.swift"]
    pins = {}
    paths = []
    for name in names:
        raw = (ROOT / name).read_bytes()
        if name == "macos/ComponentUpdate.swift":
            pieces = [raw]
            for fragment in shared["FRAGMENTS"]:
                item = (ROOT / fragment).read_bytes()
                pins[fragment] = hashlib.sha256(item).hexdigest()
                pieces.append(item)
            raw = b"\n".join(pieces)
        assert len(raw) < 2 * 1024**2
        pins[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        destination = sources / Path(name).name
        with destination.open("xb") as stream:
            stream.write(raw)
        paths.append(str(destination))
    def command(argv, name, timeout):
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout, check=False)
        (output / (name + ".stdout")).write_bytes(result.stdout)
        (output / (name + ".stderr")).write_bytes(result.stderr)
        assert result.returncode == 0 and not result.stderr, name
        return result.stdout
    command([sys.executable, str(ROOT / "scripts/mac_runtime_upgrade_plan_fixture.py"),
             "--output", str(output / "inputs")], "prepare", 30)
    binary = output / "runtime-source-check"
    command(["/usr/bin/xcrun", "swiftc", "-j", "2", "-O", "-parse-as-library", "-warnings-as-errors",
             "-D", "ACCOUNT_ACCESS_FULL_IMAGE_INSTALLED_CHECKS",
             "-framework", "Foundation", "-framework", "CryptoKit", "-framework", "Security",
             *paths, "-o", str(binary)], "compile", 900)
    result = json.loads(command([str(binary), str(output / "inputs")], "runtime", 120))
    assert result["status"] == "PASSED" and result["checks"] == 68 and result["installed_reads"] is False
    entry_name = "macos/RuntimeUpgradeMain.swift"
    entry_raw = (ROOT / entry_name).read_bytes()
    pins[entry_name] = hashlib.sha256(entry_raw).hexdigest()
    entry_source = sources / Path(entry_name).name
    entry_source.write_bytes(entry_raw)
    dummy = sources / "OrdinaryRefusalPins.swift"
    dummy.write_bytes(shared["DUMMY_COMPILED_PINS"] + b'''\n// Ordinary refusal only; invalid empty pins cannot authorize an update.
enum RuntimeUpgradeCompiledPins {
    static let value = RuntimeUpgradeSource.Pins(planSHA256: String(repeating: "0", count: 64),
        beforeSHA256: String(repeating: "0", count: 64), afterSHA256: String(repeating: "0", count: 64),
        repairPlan: String(repeating: "0", count: 64), repairSource: String(repeating: "0", count: 40),
        targetSource: String(repeating: "0", count: 40), sourceFiles: [:])
}
''')
    entry_binary = output / "AccountAccess-runtimeupgrade"
    entry_paths = [p for p in paths if not Path(p).name.startswith("RuntimeUpgrade") or Path(p).name == "RuntimeUpgradeSource.swift"]
    command(["/usr/bin/xcrun", "swiftc", "-j", "2", "-O", "-parse-as-library", "-warnings-as-errors",
             "-D", "ACCOUNT_ACCESS_RUNTIME_UPGRADE_MAIN",
             "-framework", "Foundation", "-framework", "CryptoKit", "-framework", "Security",
             *entry_paths, str(entry_source), str(dummy), "-o", str(entry_binary)], "entry-compile", 900)
    refusal = subprocess.run([str(entry_binary)], capture_output=True, timeout=30, check=False)
    (output / "entry-refusal.stdout").write_bytes(refusal.stdout)
    (output / "entry-refusal.stderr").write_bytes(refusal.stderr)
    assert refusal.returncode == 78 and not refusal.stderr
    assert json.loads(refusal.stdout) == {"schema": 1, "status": "REFUSED", "reason": "runtime_upgrade_installer_context_required"}
    assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest for name, digest in pins.items())
    report = {"schema": 1, "status": "PASSED", "result": result, "source_sha256": pins,
              "entrypoint_ordinary_refusal": True, "installed_reads": False, "production_ready": False}
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "PASSED", "checks": result["checks"], "installed_reads": False,
                      "production_ready": False}, sort_keys=True))


if __name__ == "__main__":
    main()
