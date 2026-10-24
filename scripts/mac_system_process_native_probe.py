"""Compile the read-only system-code attestation probe on a disposable Mac."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (sys.platform != "darwin" or os.getuid() != os.geteuid() or os.getuid() == 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "fainir/account-access"):
        parser.error("disposable_hosted_mac_required")
    root = Path(__file__).resolve().parents[1]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    assert revision == os.environ["GITHUB_SHA"]
    shared = runpy.run_path(str(root / "scripts/mac_component_update_native_probe.py"))
    names = [*shared["COMPILE_SOURCES"], "macos/Tests/ComponentSystemProcessNativeChecks.swift"]
    hashes = {}
    for name in names:
        raw = (root / name).read_bytes()
        assert raw == subprocess.check_output(["git", "show", revision + ":" + name], cwd=root)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    args.output.mkdir(mode=0o700)
    command = ["/usr/bin/xcrun", "swiftc", "-j", "2", "-O", "-parse-as-library", "-warnings-as-errors",
               "-framework", "Foundation", "-framework", "Security", "-framework", "CryptoKit",
               *[str(root / n) for n in names], "-o", str(args.output / "system-process-checks")]
    compiled = subprocess.run(command, capture_output=True, timeout=600, check=False)
    (args.output / "compile.stdout").write_bytes(compiled.stdout)
    (args.output / "compile.stderr").write_bytes(compiled.stderr)
    assert compiled.returncode == 0 and not compiled.stderr
    (args.output / "sources.json").write_text(json.dumps({"source_revision": revision, "source_sha256": hashes}, indent=2) + "\n")


if __name__ == "__main__":
    main()
