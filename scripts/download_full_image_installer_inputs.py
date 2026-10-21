"""Source proposal: fixed public release GETs for disposable-Mac acceptance.

Run only after the adjacent asset contract is frozen and committed. No root,
Installer, account, local signing identity or user settings are accessed here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

REPOSITORY = "fainir/account-access"
FILES = {"base.pkg", "base-manifest.json", "base-source.tar.gz", "component.pkg",
         "component-review.json", "component-source.tar.gz", "full.pkg",
         "full-review.json", "full-scripts-inventory.json", "full-source.tar.gz"}
BASE = {
    "base.pkg": (659061910, "e525233e74ee942a53c389babac57eee6cad25b79ea178ff9a6384b0a5c5567c", 289451807),
    "base-manifest.json": (659061912, "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8", 4989248),
    "base-source.tar.gz": (659061965, "4b239336a11d702932c376fb7448f9dda6a1eda87c4fe678cadbf537ba137a37", 219113811),
}
BASE_RELEASE = {"id": 418292574, "tag": "qa-fbd2a73-build76-component-base",
                "source": "fbd2a733b60acde68e82fe796cb7abd971d5d625"}
COMPONENT = "674c5df7866477e48811d002128370aaec6385aeb0565137036880de4c626bef"
COMPONENT_SOURCE = "213509c6bd9ff40131bd71dcb1a2967e96cd76a3"
PROBES = ("scripts/mac_full_image_installer_probe.py", "scripts/mac_component_update_installer_probe.py")


def require(value):
    if not value:
        raise ValueError("full_image_installer_input_contract_failed")


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
    require(set(value) == {"schema", "status", "repository", "component_source", "target_source", "plan_sha256", "assets"}
            and type(value["schema"]) is int and value["schema"] == 1
            and value["status"] == "FROZEN_REVIEWED_ASSETS" and value["repository"] == REPOSITORY
            and value["component_source"] == COMPONENT_SOURCE
            and value["target_source"] == "d5741bc9912aaf907fe5c52486af18818654dda5"
            and value["plan_sha256"] == "7c80a671d8b87815db127c6e7d7e8dd9db8c023d70e891185258391b2b3f14a3"
            and isinstance(value["assets"], dict) and set(value["assets"]) == FILES)
    identities = set()
    for name, row in value["assets"].items():
        require(isinstance(row, dict) and set(row) == {"release", "id", "sha256", "bytes"}
                and type(row["id"]) is int and 0 < row["id"] < 10**20
                and type(row["bytes"]) is int and 0 < row["bytes"] <= 1024**3 and hex_value(row["sha256"]))
        release = row["release"]
        require(isinstance(release, dict) and set(release) == {"id", "tag", "source"}
                and type(release["id"]) is int and 0 < release["id"] < 10**20
                and isinstance(release["tag"], str) and re.fullmatch("qa-[a-zA-Z0-9.-]{1,100}", release["tag"])
                and hex_value(release["source"], 40) and row["id"] not in identities)
        identities.add(row["id"])
        if name in BASE:
            require(release == BASE_RELEASE and (row["id"], row["sha256"], row["bytes"]) == BASE[name])
        elif name.startswith("component"):
            require(release["source"] == COMPONENT_SOURCE)
        if name == "component.pkg":
            require(row["sha256"] == COMPONENT and row["bytes"] == 3457184)
    # A full image may be assembled with newer controller source than its GUI.
    require(len({value["assets"][name]["release"]["id"] for name in FILES if name.startswith("full")}) == 1)
    return value


def api(endpoint):
    child = subprocess.run(["gh", "api", "--hostname", "github.com", endpoint],
                           stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
    require(len(child.stdout) <= 2 * 1024**2)
    return decode(child.stdout)


def download(row, destination):
    child = subprocess.Popen(["gh", "api", "--hostname", "github.com",
        f"repos/{REPOSITORY}/releases/assets/{row['id']}", "-H", "Accept: application/octet-stream"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    until, count, checksum = time.monotonic() + 360, 0, hashlib.sha256()
    try:
        os.set_blocking(child.stdout.fileno(), False)
        with destination.open("xb") as output, selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            while ready.get_map():
                require(time.monotonic() < until)
                for key, _ in ready.select(0.1):
                    try:
                        block = os.read(key.fd, 1024**2)
                    except BlockingIOError:
                        continue
                    if not block:
                        ready.unregister(key.fileobj)
                    else:
                        count += len(block)
                        require(count <= row["bytes"])
                        checksum.update(block)
                        output.write(block)
        require(child.wait(timeout=5) == 0 and count == row["bytes"] and checksum.hexdigest() == row["sha256"])
    finally:
        import signal
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        child.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.getuid() != 0 and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_ACTIONS") == "true" and hex_value(os.environ.get("GITHUB_SHA"), 40))
    revision = os.environ["GITHUB_SHA"]
    raw = args.contract.read_bytes()
    require(len(raw) < 64 * 1024 and subprocess.check_output(
        ["git", "show", revision + ":artifacts/full-image-installer81-recovery-inputs.json"], timeout=5) == raw)
    contract = validate(decode(raw))
    args.output.mkdir(mode=0o700)  # Never reuse a partial transfer directory.
    releases = {}
    for name, row in sorted(contract["assets"].items()):
        identifier = row["release"]["id"]
        if identifier not in releases:
            release = api(f"repos/{REPOSITORY}/releases/{identifier}")
            require(release.get("id") == identifier and release.get("draft") is True
                    and release.get("tag_name") == row["release"]["tag"]
                    and release.get("target_commitish") == row["release"]["source"])
            releases[identifier] = release
        release = releases[identifier]
        require(release.get("tag_name") == row["release"]["tag"]
                and release.get("target_commitish") == row["release"]["source"])
        found = [item for item in release["assets"] if item.get("id") == row["id"]]
        require(len(found) == 1 and found[0].get("state") == "uploaded"
                and found[0].get("size") == row["bytes"] and found[0].get("digest") == "sha256:" + row["sha256"])
        download(row, args.output / name)
    source_pins = {}
    for name in PROBES:
        body = Path(name).read_bytes()
        require(subprocess.check_output(["git", "show", revision + ":" + name], timeout=5) == body)
        source_pins[name] = digest(body)
    (args.output / "asset-contract.json").write_bytes(raw)
    controller = {"schema": 1, "controller_revision": revision,
                  "contract_sha256": digest(raw), "probe_sources": source_pins,
                  "files": {name: row["sha256"] for name, row in contract["assets"].items()}}
    (args.output / "controller.json").write_text(json.dumps(controller, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
