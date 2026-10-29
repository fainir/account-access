"""Compile and validate the exact direct-upgrade contract using public inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ("plan.json", "before.json", "after.json", "old-identity.json", "new-identity.json")
LIMITS = {"plan.json": 34 * 1024 * 1024, "before.json": 16 * 1024 * 1024,
          "after.json": 16 * 1024 * 1024, "old-identity.json": 8192, "new-identity.json": 8192}


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_public_input(root: Path, name: str) -> bytes:
    path = root / name
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= LIMITS[name], "unsafe_public_input")
        result = bytearray()
        while len(result) <= LIMITS[name]:
            part = os.read(fd, min(1024 * 1024, LIMITS[name] + 1 - len(result)))
            if not part:
                break
            result.extend(part)
        require(len(result) <= LIMITS[name], "public_input_too_large")
        return bytes(result)
    finally:
        os.close(fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(sys.platform == "darwin" and os.getuid() > 0 and os.geteuid() == os.getuid(), "ordinary_mac_required")
    inputs = args.inputs.absolute()
    info = os.stat(inputs, follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "unsafe_input_directory")
    raws = {name: read_public_input(inputs, name) for name in INPUTS}
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    shared = runpy.run_path(str(ROOT / "scripts/mac_full_image_installed_probe.py"))
    names = ["macos/" + name for name in shared["DEPENDENCIES"]]
    names += ["macos/ComponentUpdate.swift", *shared["FRAGMENTS"], "macos/FullImageInstalledIO.swift",
              "macos/FullImagePredecessorAuthority.swift",
              "macos/Tests/DirectRuntimeUpgradeSourceChecks.swift"]
    require(len(names) == len(set(names)), "duplicate_native_source")
    sources = output / "sources"
    sources.mkdir(mode=0o700)
    pins: dict[str, str] = {}
    paths: list[str] = []
    for name in names:
        raw = (ROOT / name).read_bytes()
        if name == "macos/ComponentUpdate.swift":
            fragments = [(ROOT / fragment).read_bytes() for fragment in shared["FRAGMENTS"]]
            raw = b"\n".join([raw, *fragments])
        if name in shared["FRAGMENTS"]:
            continue
        destination = sources / Path(name).name
        require(not destination.exists(), "duplicate_compiler_basename")
        destination.write_bytes(raw)
        pins[name] = digest((ROOT / name).read_bytes())
        if name == "macos/ComponentUpdate.swift":
            for fragment in shared["FRAGMENTS"]:
                pins[fragment] = digest((ROOT / fragment).read_bytes())
        paths.append(str(destination))
    data = output / "inputs"
    data.mkdir(mode=0o700)
    for name, raw in raws.items():
        (data / name).write_bytes(raw)
    binary = output / "direct-source-check"
    command = ["/usr/bin/xcrun", "swiftc", "-j", "2", "-parse-as-library", "-warnings-as-errors",
        "-framework", "Foundation", "-framework", "CryptoKit", "-framework", "Security", *paths, "-o", str(binary)]
    result = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=900)
    (output / "compile.stdout").write_bytes(result.stdout)
    (output / "compile.stderr").write_bytes(result.stderr)
    require(result.returncode == 0 and not result.stderr, "native_direct_probe_compile_failed")
    executed = subprocess.run([str(binary), str(data)], cwd=ROOT, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=120)
    (output / "run.stdout").write_bytes(executed.stdout)
    (output / "run.stderr").write_bytes(executed.stderr)
    require(executed.returncode == 0 and not executed.stderr, "native_direct_probe_failed")
    report = json.loads(executed.stdout)
    plan = json.loads(raws["plan.json"])
    direct_units = [unit for unit in plan["units"] if unit.get("kind") == "direct_file"]
    require(report == {"status": "PASSED", "changed_nodes": len(plan["changed"]), "units": len(plan["units"]),
        "direct_files_added": sum(unit.get("before") is None for unit in direct_units),
        "direct_files_removed": sum(unit.get("after") is None for unit in direct_units),
        "projection_checks": 2, "refusal_checks": 4,
        "installed_reads": False, "service_actions": False, "production_ready": False}, "native_report_mismatch")
    require(all(digest((ROOT / name).read_bytes()) == value for name, value in pins.items()), "source_changed_during_compile")
    summary = {"status": "PASSED", "native": report, "source_sha256": pins,
        "public_inputs_sha256": {name: digest(raw) for name, raw in raws.items()},
        "installed_reads": False, "service_actions": False, "production_ready": False}
    (output / "result.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": "PASSED", "changed_nodes": len(plan["changed"]), "units": len(plan["units"]),
        "installed_reads": False, "production_ready": False}, sort_keys=True))


if __name__ == "__main__":
    main()
