"""Download only the committed fresh-image QA contract; never install anything."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess

REPOSITORY = "fainir/account-access"
CONTRACT = "artifacts/fresh-image80-installer-inputs.json"
MANIFEST = "d1f74db86890b306f989b65a8c521ce3b0879f261ded122dd409be2ca2fbe317"
APP_SOURCE = "d5741bc9912aaf907fe5c52486af18818654dda5"
PACKAGING_SOURCE = "56f83bbe89217cbfc9b591a4e8ac8a9525cb80b6"
VERIFIER = "cce66e7499a755a4bd5dba098059012860d5e0fcf54ae8e461708b4ac4ef8534"
FILES = frozenset({"fresh.pkg", "fresh-review.json", "fresh-expanded-inventory.json",
                   "fresh-manifest.json", "full81-source.tar.gz", "packaging-source.tar.gz"})
FULL81_SOURCE = {"id": 663422302, "bytes": 232976220,
    "sha256": "5872d18b2779dd11418fed2193a1f9fb18019f8b8c9bcf8e8a60c1b0760559e8",
    "release": {"id": 419902915, "tag": "qa-740fe3c-full-image81",
                "source": "740fe3c479a763950e98340584ea173e04522072"}}
TRANSFER_SOURCE = "scripts/download_full_image_installer_inputs.py"
TRANSFER_SHA = "e3f995727d5a5e3b9780df25d232bf856c4f9ae2c0a0c7fac881fa4208f60057"
PROBES = ("scripts/mac_fresh_image_installer_probe.py", "scripts/download_fresh_image_installer_inputs.py",
          "scripts/mac_component_update_installer_probe.py", TRANSFER_SOURCE)


def require(value):
    if not value:
        raise ValueError("fresh_image_installer_input_contract_failed")


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


def validate(value):
    require(type(value) is dict and set(value) == {"schema", "status", "repository", "target_source",
        "packaging_source", "target_manifest_sha256", "installer_verifier_sha256", "assets"}
        and type(value["schema"]) is int and value["schema"] == 1
        and value["status"] == "FROZEN_REVIEWED_ASSETS" and value["repository"] == REPOSITORY
        and value["target_source"] == APP_SOURCE and value["target_manifest_sha256"] == MANIFEST
        and value["installer_verifier_sha256"] == VERIFIER and value["packaging_source"] == PACKAGING_SOURCE
        and type(value["assets"]) is dict and set(value["assets"]) == FILES)
    identifiers, releases = set(), []
    for name, row in value["assets"].items():
        require(type(row) is dict and set(row) == {"release", "id", "sha256", "bytes"}
            and type(row["id"]) is int and 0 < row["id"] < 10**20 and row["id"] not in identifiers
            and type(row["bytes"]) is int and 0 < row["bytes"] <= 1024**3 and hex_value(row["sha256"]))
        release = row["release"]
        require(type(release) is dict and set(release) == {"id", "tag", "source"}
            and type(release["id"]) is int and 0 < release["id"] < 10**20
            and isinstance(release["tag"], str) and re.fullmatch("qa-[a-zA-Z0-9.-]{1,100}", release["tag"])
            and hex_value(release["source"], 40))
        identifiers.add(row["id"])
        if name == "full81-source.tar.gz":
            require(row == FULL81_SOURCE)
        else:
            require(release["source"] == value["packaging_source"])
            releases.append(release)
        if name == "fresh-manifest.json":
            require(row["sha256"] == MANIFEST)
    require(all(release == releases[0] for release in releases))
    return value


def context():
    require(os.getuid() != 0 and os.geteuid() == os.getuid()
        and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_ACTIONS") == "true" and hex_value(os.environ.get("GITHUB_SHA"), 40))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    context()  # Before consulting a path, loading source, or invoking Git/gh.
    revision = os.environ["GITHUB_SHA"]
    raw = args.contract.read_bytes()
    require(len(raw) < 64 * 1024 and subprocess.check_output(
        ["git", "show", revision + ":" + CONTRACT], timeout=5) == raw)
    contract = validate(decode(raw))  # Missing/pending contract cannot reach the network.
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
