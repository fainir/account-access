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
    parser.add_argument("--resume", action="store_true",
                        help="reuse an exact-source 72-check compile from this output directory")
    args = parser.parse_args()
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() != os.getuid():
        raise ValueError("ordinary_mac_required")
    output = args.output.absolute()
    if args.resume:
        info = output.lstat()
        if not output.is_dir() or output.is_symlink() or info.st_uid != os.getuid():
            raise ValueError("unsafe_resume_output")
    else:
        output.mkdir(mode=0o700)
    sources = output / "sources"
    if args.resume:
        if not sources.is_dir() or sources.is_symlink():
            raise ValueError("resume_sources_missing")
    else:
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
        if args.resume:
            if not destination.is_file() or destination.is_symlink() or destination.read_bytes() != raw:
                raise ValueError("resume_source_mismatch:" + Path(name).name)
        else:
            with destination.open("xb") as stream:
                stream.write(raw)
        paths.append(str(destination))
    def command(argv, name, timeout):
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout, check=False)
        (output / (name + ".stdout")).write_bytes(result.stdout)
        (output / (name + ".stderr")).write_bytes(result.stderr)
        assert result.returncode == 0 and not result.stderr, name
        return result.stdout
    binary = output / "runtime-source-check"
    if args.resume:
        compile_stderr = (output / "compile.stderr").read_bytes()
        runtime_stderr = (output / "runtime.stderr").read_bytes()
        if compile_stderr or runtime_stderr or not binary.is_file() or not (output / "inputs").is_dir():
            raise ValueError("resume_native_check_incomplete")
        result = json.loads((output / "runtime.stdout").read_bytes())
    else:
        command([sys.executable, str(ROOT / "scripts/mac_runtime_upgrade_plan_fixture.py"),
                 "--output", str(output / "inputs")], "prepare", 30)
        command(["/usr/bin/xcrun", "swiftc", "-j", "2", "-O", "-parse-as-library", "-warnings-as-errors",
                 "-D", "ACCOUNT_ACCESS_FULL_IMAGE_INSTALLED_CHECKS",
                 "-framework", "Foundation", "-framework", "CryptoKit", "-framework", "Security",
                 *paths, "-o", str(binary)], "compile", 900)
        result = json.loads(command([str(binary), str(output / "inputs")], "runtime", 120))
    assert result["status"] == "PASSED" and result["checks"] == 72 and result["installed_reads"] is False
    entry_name = "macos/RuntimeUpgradeMain.swift"
    entry_raw = (ROOT / entry_name).read_bytes()
    pins[entry_name] = hashlib.sha256(entry_raw).hexdigest()
    entry_source = sources / Path(entry_name).name
    if args.resume:
        if not entry_source.is_file() or entry_source.is_symlink() or entry_source.read_bytes() != entry_raw:
            raise ValueError("resume_entry_source_mismatch")
    else:
        entry_source.write_bytes(entry_raw)
    dummy = sources / "OrdinaryRefusalPins.swift"
    dummy_data = shared["DUMMY_COMPILED_PINS"] + b'''\n// Ordinary refusal only; invalid empty pins cannot authorize an update.
enum RuntimeUpgradeCompiledPins {
    static let value = RuntimeUpgradeSource.Pins(planSHA256: String(repeating: "0", count: 64),
        beforeSHA256: String(repeating: "0", count: 64), afterSHA256: String(repeating: "0", count: 64),
        repairPlan: String(repeating: "0", count: 64), repairSource: String(repeating: "0", count: 40),
        targetSource: String(repeating: "0", count: 40), sourceFiles: [:])
}
'''
    if args.resume:
        if not dummy.is_file() or dummy.is_symlink() or dummy.read_bytes() != dummy_data:
            raise ValueError("resume_dummy_pins_mismatch")
    else:
        dummy.write_bytes(dummy_data)
    entry_binary = output / "AccountAccess-runtimeupgrade"
    entry_paths = [p for p in paths if not Path(p).name.startswith("RuntimeUpgrade") or Path(p).name == "RuntimeUpgradeSource.swift"]
    # The production module and source fixture above are optimized. This tiny
    # entrypoint check covers only the ordinary-user refusal path; keeping it
    # unoptimized avoids multi-minute optimizer work on the same module graph.
    command(["/usr/bin/xcrun", "swiftc", "-j", "2", "-Onone", "-parse-as-library", "-warnings-as-errors",
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
