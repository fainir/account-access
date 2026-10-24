"""Build-only hosted review of the exact repaired public image for new Mac installs.

The repair package contains the completed predecessor and three replacements,
not an already assembled successor. Compose them only in a new private build
directory and require the complete successor manifest before packaging. This
controller never installs, signs, publishes, or opens an account store.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace

REPOSITORY = "fainir/account-access"
PACKAGING_SOURCE = "39b3bfbfe6b5ceb3fccb0f635b806220ae11007b"
SOURCE = "c4cf1b0918c1a51cbd4a38880364fcb71fa5980e"
APP_SOURCE = "d30fda732c589b9ac4dc339a7237ad8ba00d0016"
BROKER_SOURCE = "5f4926a33883d6234f2538a5d0969e3b70c883b0"
BEFORE = "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da"
AFTER = "5a732de4623ba50aefa6d31c54e7b1eae660b2921341f95042c5675d922d808b"
PACKAGE = "27ee29eea45992461d0d8e5d2f36878a784b15f52713066f9710647715420994"
REQUEST = "artifacts/fresh-image87-build-request.json"
REPAIR_CONTRACT = "artifacts/broker-repair-installer87-inputs.json"
APP_CONTRACT = "artifacts/full-image-installer84-inputs.json"
BASE = Path("Library/Application Support/Account Access")
REPLACEMENTS = {"bin/AccountAccess-broker": "AccountAccess-broker",
                "package-identity.json": "TargetIdentity.json",
                "broker-repair-identity.json": "BrokerRepairIdentity.json"}
REPAIR_FILES = {"repair.pkg", "repair-review.json", "repair-scripts-inventory.json"}


def require(value):
    if not value:
        raise ValueError("fresh_repair_image_build_refused")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def command(arguments, **kwargs):
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                          check=True, timeout=900, **kwargs).stdout


def guard(*, build):
    require(os.getuid() == os.geteuid() != 0
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and re.fullmatch("[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")))
    if build:
        require(sys.platform == "darwin" and platform.machine() == "arm64")


def validate_request(value):
    require(type(value) is dict and type(value.get("schema")) is int
        and value.get("production_ready") is False
        and value == {"schema": 1, "status": "BUILD_ONLY_NO_INSTALL_OR_PUBLICATION",
        "packaging_source": PACKAGING_SOURCE, "repair_source": SOURCE,
        "app_source": APP_SOURCE, "broker_compilation_source": BROKER_SOURCE,
        "before_manifest_sha256": BEFORE, "target_manifest_sha256": AFTER,
        "input_package_sha256": PACKAGE, "production_ready": False})


def committed(repository, relative):
    raw = (repository / relative).read_bytes()
    require(raw == command(["git", "show", os.environ["GITHUB_SHA"] + ":" + relative], cwd=repository))
    return raw


def inputs(repository):
    require(command(["git", "rev-parse", "HEAD"], cwd=repository).decode().strip()
            == os.environ["GITHUB_SHA"])
    shared = runpy.run_path(str(repository / "scripts/download_full_image_installer_inputs.py"))
    repair = runpy.run_path(str(repository / "scripts/download_broker_repair_installer_inputs.py"))
    validate_request(shared["decode"](committed(repository, REQUEST)))
    contract = repair["validate"](shared["decode"](committed(repository, REPAIR_CONTRACT)))
    app = shared["validate"](shared["decode"](committed(repository, APP_CONTRACT)), 84)
    source = app["assets"]["full-source.tar.gz"]
    require(source["sha256"] == "5f262e8a9b9016dded2a0ac5a68966bca3332948c403363799dbdf4dddeba2d5"
            and source["bytes"] == 252473415)
    return {**{name: contract["assets"][name] for name in REPAIR_FILES},
            "full84-source.tar.gz": source}, shared


def download(repository, output):
    guard(build=False)
    rows, shared = inputs(repository)
    output.mkdir(mode=0o700)
    releases = {}
    for name, row in sorted(rows.items()):
        rid = row["release"]["id"]
        if rid not in releases:
            releases[rid] = shared["api"](f"repos/{REPOSITORY}/releases/{rid}")
        release = releases[rid]
        require(release.get("id") == rid and release.get("draft") is True
                and release.get("tag_name") == row["release"]["tag"]
                and release.get("target_commitish") == row["release"]["source"])
        matches = [item for item in release["assets"] if item.get("id") == row["id"]]
        require(len(matches) == 1 and matches[0].get("state") == "uploaded"
                and matches[0].get("size") == row["bytes"]
                and matches[0].get("digest") == "sha256:" + row["sha256"])
        shared["download"](row, output / name)


def materialize(scripts, target, inventory):
    """Data-only composition. Both full image inventories and all three bytes bind it."""
    before, after = [(scripts / name).read_bytes() for name in ("BaseManifest.json", "TargetManifest.json")]
    require(digest(before) == BEFORE and digest(after) == AFTER)
    source = scripts / "CompletedImage/TargetImage"
    require(not target.exists() and not target.is_symlink()
            and not target.absolute().is_relative_to(scripts.absolute()))
    inventory(source, before)
    old, new = json.loads(before), json.loads(after)
    root = "/" + BASE.as_posix()
    require(old.keys() == new.keys() and old["roots"].keys() == new["roots"].keys())
    require(all(old[k] == new[k] for k in old if k != "roots")
            and all(old["roots"][k] == new["roots"][k] for k in old["roots"] if k != root))
    a, b = old["roots"][root], new["roots"][root]
    require({key for key in a.keys() | b.keys() if a.get(key) != b.get(key)} == set(REPLACEMENTS))
    require("broker-repair-identity.json" not in a)
    replacements = {}
    for relative, name in REPLACEMENTS.items():
        node, path = b[relative], scripts / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and node["kind"] == "file" and node["mode"] == (0o755 if relative.startswith("bin/") else 0o644)
                and 0 < info.st_size == node["size"] <= 16 * 1024**2)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            raw = stream.read(node["size"] + 1)
        require(len(raw) == node["size"] and digest(raw) == node["sha256"])
        replacements[relative] = (raw, node["mode"])
    shutil.copytree(source, target, symlinks=True)
    inventory(target, before)
    for relative, (raw, mode) in replacements.items():
        path = target / BASE / relative
        if path.exists():
            path.unlink()  # Only the new private copy; never source or installed paths.
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(mode)
    inventory(target, after)
    inventory(source, before)
    require((scripts / "BaseManifest.json").read_bytes() == before
            and (scripts / "TargetManifest.json").read_bytes() == after)
    return after


def build(repository, bundle, output):
    guard(build=True)
    rows, _ = inputs(repository)
    require(not output.exists() and not output.is_symlink()
            and {p.name for p in bundle.iterdir()} == set(rows)
            and shutil.disk_usage(output.parent).free > 6 * 1024**3)
    for name, row in rows.items():
        require((bundle / name).stat().st_size == row["bytes"] and sha(bundle / name) == row["sha256"])
    output.mkdir(mode=0o700)
    review = json.loads((bundle / "repair-review.json").read_bytes())
    require(review["source_commit"] == SOURCE and review["before_manifest_sha256"] == BEFORE
            and review["after_manifest_sha256"] == AFTER and review["package_sha256"] == PACKAGE)
    for key in ("native_sources", "controller_sources"):
        require(type(review[key]) is dict and 1 <= len(review[key]) <= 128)
        for path, expected in review[key].items():
            require(re.fullmatch(r"macos/(?:source-fragments/)?[A-Za-z0-9_.-]+\.(?:swift|h|c|inc)", path)
                    and digest(command(["git", "show", SOURCE + ":" + path], cwd=repository)) == expected)
            if key == "native_sources":
                require(digest(command(["git", "show", BROKER_SOURCE + ":" + path], cwd=repository)) == expected)
    with tempfile.TemporaryDirectory(prefix="account-access-fresh87-build-") as temporary:
        stage = Path(temporary)
        expanded, packaging = stage / "repair", stage / "packaging"
        command(["/usr/sbin/pkgutil", "--expand-full", str(bundle / "repair.pkg"), str(expanded)])
        helper = runpy.run_path(str(repository / "scripts/mac_component_update_installer_probe.py"))
        probe = runpy.run_path(str(repository / "scripts/mac_fresh_image_installer_probe.py"))
        probe["inventory"].__globals__["h"] = SimpleNamespace(**helper)
        require(probe["inventory"](expanded / "Scripts") == json.loads((bundle / "repair-scripts-inventory.json").read_bytes()))
        archive = output / "packaging-source.tar.gz"
        archive.write_bytes(command(["git", "archive", "--format=tar.gz", PACKAGING_SOURCE], cwd=repository))
        packaging.mkdir()
        command(["/usr/bin/tar", "-xzf", str(archive), "-C", str(packaging)])
        sys.path.insert(0, str(packaging))
        from macos.system_package import assemble_preassembled, preassembled_inventory
        image, manifest = stage / "target", stage / "target-manifest.json"
        manifest.write_bytes(materialize(expanded / "Scripts", image, preassembled_inventory))
        args = SimpleNamespace(preassembled_image=image, preassembled_manifest=manifest,
            preassembled_sha256=AFTER, architecture="arm64", development=False,
            unsigned_package=True, installer_identity=None, output=stage / "package")
        result = assemble_preassembled(args)
        package = args.output / "Account-Access-arm64-unsigned.pkg"
        require(result["status"] == "BUILT" and result["preassembled_source_unchanged"] is True
                and result["runtime_transformed"] is False and result["payload_manifest_sha256"] == AFTER
                and result["sha256"] == sha(package) and result["production_ready"] is False)
        candidate = stage / "candidate"
        command(["/usr/sbin/pkgutil", "--expand-full", str(package), str(candidate)])
        inventory = probe["inventory"](candidate)
        scripts = probe["install_script_bodies"]((packaging / "macos/system_package.py").read_bytes())
        probe["validate_expansion"](candidate, inventory, scripts, manifest_sha=AFTER)
        probe["validate_packaged_image"](json.loads(manifest.read_bytes()), inventory)
        shutil.copy2(package, output / "fresh.pkg")
        shutil.copy2(args.output / "package.json", output / "package.json")
        shutil.copy2(manifest, output / "fresh-manifest.json")
        inventory_path = output / "fresh-expanded-inventory.json"
        inventory_path.write_text(json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n")
        shutil.copy2(bundle / "full84-source.tar.gz", output / "full84-source.tar.gz")
        for name, revision in (("repair-source.tar.gz", SOURCE), ("broker-source.tar.gz", BROKER_SOURCE)):
            (output / name).write_bytes(command(["git", "archive", "--format=tar.gz", revision], cwd=repository))
        report = {"schema": 1, "status": "BUILT_NOT_INSTALLED_NOT_INSTALL_QUALIFIED",
            "package_sha256": sha(package), "package_bytes": package.stat().st_size,
            "target_manifest_sha256": AFTER, "target_source": SOURCE,
            "app_source": APP_SOURCE, "broker_compilation_source": BROKER_SOURCE,
            "packaging_source": PACKAGING_SOURCE, "installer_verifier_sha256": result["installer_verifier_sha256"],
            "expanded_inventory_sha256": sha(inventory_path),
            "corresponding_sources": {p.name: sha(p) for p in output.glob("*-source.tar.gz")},
            "actual_Installer_qualified": False, "production_ready": False}
        (output / "fresh-review.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["download", "build"])
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "download":
        download(args.repository.absolute(), args.output.absolute())
    else:
        require(args.bundle is not None)
        build(args.repository.absolute(), args.bundle.absolute(), args.output.absolute())
