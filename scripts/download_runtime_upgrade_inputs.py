"""GET-only hosted download of the exact runtime-upgrade-94 draft asset contract."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess

REPOSITORY = "fainir/account-access"
SOURCE = "cbf06067e7dc5a53dc6f2d1e87f0284503474e6d"
CONTRACT = "artifacts/runtime-upgrade95-installer-inputs.json"
# Canonical identity of the reviewed package and exact uploaded draft assets.
CONTRACT_SHA256 = "675c45a538ca00276933b1e8f0f76f525ff4a9f5bf67f7cdc387ddcdf91ed510"
FILES = {"runtime-upgrade.pkg", "upgrade-review.json", "upgrade-scripts-inventory.json"}


def require(condition):
    if not condition:
        raise ValueError("runtime_upgrade_inputs_refused")


def validate(value):
    require(isinstance(CONTRACT_SHA256, str) and re.fullmatch("[a-f0-9]{64}", CONTRACT_SHA256))
    require(type(value) is dict and set(value) == {"schema", "status", "repository", "source_commit", "assets"}
            and type(value["schema"]) is int and value["schema"] == 1
            and value["status"] == "FROZEN_REVIEWED_ASSETS" and value["repository"] == REPOSITORY
            and value["source_commit"] == SOURCE and type(value["assets"]) is dict
            and set(value["assets"]) == FILES)
    # Pins every identity, byte count, hash and release independently of live
    # release metadata. No environment or CLI argument selects another cohort.
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    require(hashlib.sha256(canonical).hexdigest() == CONTRACT_SHA256)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() != 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and re.fullmatch("[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")))
    revision = os.environ["GITHUB_SHA"]
    raw = Path(CONTRACT).read_bytes()
    require(len(raw) <= 65536 and subprocess.check_output(["git", "show", revision + ":" + CONTRACT], timeout=10) == raw)
    shared = runpy.run_path("scripts/download_full_image_installer_inputs.py")
    contract = validate(shared["decode"](raw))
    args.output.mkdir(mode=0o700)
    releases = {}
    for name, row in sorted(contract["assets"].items()):
        rid = row["release"]["id"]
        if rid not in releases:
            releases[rid] = shared["api"](f"repos/{REPOSITORY}/releases/{rid}")
        release = releases[rid]
        require(release.get("id") == rid and release.get("draft") is True
                and release.get("tag_name") == row["release"]["tag"]
                and release.get("target_commitish") == row["release"]["source"])
        matches = [a for a in release["assets"] if a.get("id") == row["id"]]
        require(len(matches) == 1 and matches[0].get("size") == row["bytes"]
                and matches[0].get("state") == "uploaded" and matches[0].get("digest") == "sha256:" + row["sha256"])
        shared["download"](row, args.output / name)
    (args.output / "asset-contract.json").write_bytes(raw)
    (args.output / "controller.json").write_text(json.dumps({"schema": 1, "controller_revision": revision,
        "contract_sha256": hashlib.sha256(raw).hexdigest()}, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
