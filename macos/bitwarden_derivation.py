"""Data-only CLI-specific removal of an unused external dependency.

The original Bitwarden source and upstream package/version remain unchanged.
This derivative does not patch a cryptographic implementation. It refuses every
input except the reviewed original JavaScript assets and package metadata.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

DERIVATION_ID = "remove-unused-node-forge-v1"
MODIFICATION_DATE = "2026-10-20"
ASSETS = ("build/344.js", "build/685.js", "build/bw.js")
REMOVED_PATH = "node_modules/node-forge"
IMPORT = (b';// external "node-forge"\n'
          b'const external_node_forge_namespaceObject = require("node-forge");')
NOTICE = b";// Account Access modification (2026-10-20): removed an unused external import."
EMBEDDED_DEPENDENCY = b'"node-forge":"1.4.0",'


def checksum(raw):
    return hashlib.sha256(raw).hexdigest()


def derive_cli(files, ledger):
    """Return a new file mapping only after all input/output bindings agree."""
    try:
        spec = ledger["cli_derivation"]
        review = ledger["residual_advisories"][0]["applicability"]
        assets = review["javascript_assets_sha256"]
        if (spec["id"] != DERIVATION_ID or spec["modified_on"] != MODIFICATION_DATE
                or spec["upstream_patched"] is not False
                or spec["omitted_runtime_paths"] != [REMOVED_PATH]
                or spec["source_sha256"] != checksum(Path(__file__).read_bytes())
                or set(assets) != set(ASSETS)
                or {name: checksum(raw) for name, raw in files.items()
                    if name.endswith((".js", ".cjs", ".mjs"))} != assets):
            raise ValueError()
        entry = files["build/bw.js"]
        metadata_raw = files["package.json"]
        if (checksum(entry) != spec["official_entrypoint_sha256"]
                or checksum(entry) != review["official_entrypoint_sha256"]
                or checksum(metadata_raw) != spec["official_metadata_sha256"]
                or entry.count(IMPORT) != 1 or entry.count(EMBEDDED_DEPENDENCY) != 1
                or entry.count(b"external_node_forge_namespaceObject") != 1
                or entry.count(b'require("node-forge")') != 1):
            raise ValueError()
        remaining = entry.replace(IMPORT, b"", 1).replace(EMBEDDED_DEPENDENCY, b"", 1)
        if (b"node-forge" in remaining
                or any(b"node-forge" in files[name] or b"external_node_forge_namespaceObject" in files[name]
                       for name in ASSETS if name != "build/bw.js")):
            raise ValueError()
        metadata = json.loads(metadata_raw)
        if (metadata["name"] != "@bitwarden/cli" or metadata["version"] != ledger["official_cli_version"]
                or metadata["dependencies"].pop("node-forge") != "1.4.0"
                or any("node-forge" in metadata.get(kind, {})
                       for kind in ("optionalDependencies", "peerDependencies"))):
            raise ValueError()
        metadata["accountAccessModification"] = (
            "Unused external dependency removed on 2026-10-20; upstream version unchanged.")
        modified_entry = entry.replace(IMPORT, NOTICE, 1).replace(EMBEDDED_DEPENDENCY, b"", 1)
        modified_metadata = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode()
        if (checksum(modified_entry) != spec["derived_entrypoint_sha256"]
                or checksum(modified_metadata) != spec["derived_metadata_sha256"]
                or b"node-forge" in modified_entry or b"external_node_forge_namespaceObject" in modified_entry):
            raise ValueError()
        derived = dict(files)
        derived.update({"build/bw.js": modified_entry, "package.json": modified_metadata})
        return derived
    except (KeyError, TypeError, ValueError, IndexError, OSError):
        raise ValueError("bitwarden_cli_derivation_changed") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New directory for the two modified file overlays")
    parser.add_argument("--ledger", type=Path, default=Path(__file__).with_name("dependency-overrides.json"))
    args = parser.parse_args(argv)
    try:
        if os.getuid() == 0 or os.getuid() != os.geteuid() or args.output.exists() or args.output.is_symlink():
            raise ValueError()
        javascript = set()
        for count, path in enumerate(args.cli_directory.rglob("*"), 1):
            if count > 20_000 or path.is_symlink():
                raise ValueError()
            if path.is_file() and path.suffix in {".js", ".cjs", ".mjs"}:
                javascript.add(path.relative_to(args.cli_directory).as_posix())
        if args.cli_directory.is_symlink() or javascript != set(ASSETS):
            raise ValueError()
        ledger_info = args.ledger.lstat()
        if (not stat.S_ISREG(ledger_info.st_mode) or ledger_info.st_nlink != 1
                or not 0 < ledger_info.st_size <= 128 * 1024):
            raise ValueError()
        with args.ledger.open("rb") as stream:
            ledger_raw = stream.read(128 * 1024 + 1)
        if len(ledger_raw) != ledger_info.st_size:
            raise ValueError()
        files = {}
        for name in (*ASSETS, "package.json"):
            path = args.cli_directory / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 20 * 1024 * 1024:
                raise ValueError()
            with path.open("rb") as stream:
                files[name] = stream.read(20 * 1024 * 1024 + 1)
            if len(files[name]) != info.st_size:
                raise ValueError()
        derived = derive_cli(files, json.loads(ledger_raw))
        args.output.mkdir(mode=0o700)
        for name in ("build/bw.js", "package.json"):
            output = args.output / name
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with output.open("xb") as stream:
                stream.write(derived[name])
            output.chmod(0o644)
        print(json.dumps({"status": "DERIVED", "derivation": DERIVATION_ID,
                          "entrypoint_sha256": checksum(derived["build/bw.js"]),
                          "upstream_patched": False}))
        return 0
    except (OSError, ValueError):
        print('{"status":"REFUSED","reason":"reviewed_cli_inputs_and_fresh_output_required"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
