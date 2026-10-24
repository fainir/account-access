"""Download the committed, draft-only broker repair assets for hosted Mac QA."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess

REPOSITORY = "fainir/account-access"
SOURCE = "c4cf1b0918c1a51cbd4a38880364fcb71fa5980e"
PACKAGE = "27ee29eea45992461d0d8e5d2f36878a784b15f52713066f9710647715420994"
ROOT_PACKAGE = "97c5109627a6f218fa935196f668739ca1bdfe45005fab2ae72cb4e159677d3d"
CONTRACT = "artifacts/broker-repair-installer87-inputs.json"
FILES = {"repair.pkg", "repair-review.json", "repair-scripts-inventory.json",
         "root-revalidation.pkg", "root-revalidation-review.json"}


def require(value):
    if not value:
        raise ValueError("broker_repair_inputs_refused")


def validate(value):
    require(isinstance(value, dict) and set(value) == {"schema", "status", "repository", "source_commit", "assets"}
            and type(value["schema"]) is int and value["schema"] == 1
            and value["status"] == "FROZEN_REVIEWED_ASSETS" and value["repository"] == REPOSITORY
            and value["source_commit"] == SOURCE and isinstance(value["assets"], dict)
            and set(value["assets"]) == FILES)
    identities = set()
    releases = set()
    for name, row in value["assets"].items():
        require(isinstance(row, dict) and set(row) == {"release", "id", "bytes", "sha256"}
                and type(row["id"]) is int and 0 < row["id"] < 10**20 and row["id"] not in identities
                and type(row["bytes"]) is int and 0 < row["bytes"] <= 512 * 1024**2
                and isinstance(row["sha256"], str) and re.fullmatch("[a-f0-9]{64}", row["sha256"]))
        identities.add(row["id"])
        release = row["release"]
        require(isinstance(release, dict) and set(release) == {"id", "tag", "source"}
                and type(release["id"]) is int and release["id"] > 0
                and release["source"] == SOURCE and release["tag"] == "qa-c4cf1b0-broker-repair87")
        releases.add(release["id"])
    require(len(releases) == 1 and value["assets"]["repair.pkg"]["sha256"] == PACKAGE
            and value["assets"]["repair.pkg"]["bytes"] == 299586792
            and value["assets"]["root-revalidation.pkg"]["sha256"] == ROOT_PACKAGE
            and value["assets"]["root-revalidation.pkg"]["bytes"] == 3459002)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.getuid() != 0 and os.environ.get("GITHUB_ACTIONS") == "true"
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
                and release.get("tag_name") == row["release"]["tag"] and release.get("target_commitish") == SOURCE)
        matches = [a for a in release["assets"] if a.get("id") == row["id"]]
        require(len(matches) == 1 and matches[0].get("size") == row["bytes"]
                and matches[0].get("state") == "uploaded" and matches[0].get("digest") == "sha256:" + row["sha256"])
        shared["download"](row, args.output / name)
    (args.output / "asset-contract.json").write_bytes(raw)
    (args.output / "controller.json").write_text(json.dumps({"schema": 1, "controller_revision": revision,
        "contract_sha256": hashlib.sha256(raw).hexdigest()}, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
