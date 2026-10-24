"""GET-only transfer of exact reviewed fresh runtime draft assets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess

REPOSITORY = "fainir/account-access"
SOURCE = "57663aae54f438e65f59baf40721f5ffcb8ff524"
CONTRACT = "artifacts/fresh-image89-installer-inputs.json"
MANIFEST = "c2c6c1fd525a2a43d55fb17ed750b64a1432f1aa8bcbc63a4b73ae476596d3fc"
VERIFIER = "cce66e7499a755a4bd5dba098059012860d5e0fcf54ae8e461708b4ac4ef8534"
# Exact contract reviewed after expansion and draft asset verification.
CONTRACT_SHA256 = "514310bb4446c1d96d4e01ea3e68bc0c3a6c210159e135bd4b4d16477ed51be0"
FILES = frozenset({"fresh.pkg", "fresh-review.json", "fresh-expanded-inventory.json",
    "fresh-manifest.json", "project-source.tar.gz", "bitwarden-source.tar.gz", "BUILD.md"})
TRANSFER_SOURCE = "scripts/download_full_image_installer_inputs.py"
TRANSFER_SHA = "573783db0627f0768606b75d847f03cff92783b96c683ac2dc2869f93798a14b"
PROBES = ("scripts/mac_fresh_image_installer_probe.py", "scripts/download_fresh_runtime_inputs.py",
    "scripts/mac_component_update_installer_probe.py", TRANSFER_SOURCE)
RUNTIME92_SOURCE = "7051ef225ff2f35d67576d0ddbbc3e0b107e00bf"
RUNTIME92_MANIFEST = "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
RUNTIME92_CONTRACT = "artifacts/fresh-image92-installer-inputs.json"
RUNTIME92_CONTRACT_SHA256 = "58a73486685c0b82e39aa3eab3e1bc6f98e98bbd9f58d7700c080331addbba0c"


def require(value):
    if not value:
        raise ValueError("fresh_runtime_input_contract_refused")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def hex_value(value, length=64):
    return isinstance(value, str) and re.fullmatch("[a-f0-9]{" + str(length) + "}", value) is not None


def profile(cohort):
    require(type(cohort) is int and cohort in {89, 92})
    if cohort == 89:
        return SOURCE, MANIFEST, CONTRACT, CONTRACT_SHA256
    return RUNTIME92_SOURCE, RUNTIME92_MANIFEST, RUNTIME92_CONTRACT, RUNTIME92_CONTRACT_SHA256


def validate(value, cohort=89):
    source, manifest, _, contract_sha = profile(cohort)
    require(hex_value(contract_sha))
    require(type(value) is dict and set(value) == {"schema", "status", "repository", "target_source",
        "packaging_source", "target_manifest_sha256", "installer_verifier_sha256", "assets"}
        and type(value["schema"]) is int and value["schema"] == 1
        and value["status"] == "FROZEN_REVIEWED_ASSETS" and value["repository"] == REPOSITORY
        and value["target_source"] == value["packaging_source"] == source
        and value["target_manifest_sha256"] == manifest and value["installer_verifier_sha256"] == VERIFIER
        and type(value["assets"]) is dict and set(value["assets"]) == FILES)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    require(digest(raw) == contract_sha)
    return value


def context():
    require(os.getuid() != 0 and os.geteuid() == os.getuid()
        and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_ACTIONS") == "true" and hex_value(os.environ.get("GITHUB_SHA"), 40))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cohort", type=int, choices=[89, 92], default=89)
    args = parser.parse_args()
    context()  # Before consulting a path, loading source, or invoking Git/gh.
    cohort = getattr(args, "cohort", 89)
    _, _, contract_path, _ = profile(cohort)
    revision = os.environ["GITHUB_SHA"]
    raw = args.contract.read_bytes()
    require(len(raw) < 64 * 1024 and subprocess.check_output(
        ["git", "show", revision + ":" + contract_path], timeout=5) == raw)
    contract = validate(decode(raw), cohort)  # Missing/pending contract cannot reach the network.
    transfer_raw = Path(TRANSFER_SOURCE).read_bytes()
    require(TRANSFER_SHA and digest(transfer_raw) == TRANSFER_SHA and subprocess.check_output(
        ["git", "show", revision + ":" + TRANSFER_SOURCE], timeout=5) == transfer_raw)
    transfer = runpy.run_path(TRANSFER_SOURCE)  # Definitions only; its main is never run.
    args.output.mkdir(mode=0o700)  # Never adopt a partial transfer directory.
    releases = {}
    for name, row in sorted(contract["assets"].items()):
        identifier = row["release"]["id"]
        if identifier not in releases:
            releases[identifier] = transfer["api"](f"repos/{REPOSITORY}/releases/{identifier}")
        release = releases[identifier]
        require(release.get("id") == identifier and release.get("draft") is True
            and release.get("tag_name") == row["release"]["tag"]
            and release.get("target_commitish") == row["release"]["source"])
        found = [item for item in release["assets"] if item.get("id") == row["id"]]
        require(len(found) == 1 and found[0].get("state") == "uploaded" and found[0].get("size") == row["bytes"]
            and found[0].get("digest") == "sha256:" + row["sha256"])
        transfer["download"](row, args.output / name)
    source_pins = {}
    for name in PROBES:
        body = Path(name).read_bytes()
        require(subprocess.check_output(["git", "show", revision + ":" + name], timeout=5) == body)
        source_pins[name] = digest(body)
    (args.output / "asset-contract.json").write_bytes(raw)
    (args.output / "controller.json").write_text(json.dumps({"schema": 1, "controller_revision": revision,
        "contract_sha256": digest(raw), "probe_sources": source_pins,
        "files": {name: row["sha256"] for name, row in contract["assets"].items()}}, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
