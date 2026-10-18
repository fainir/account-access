"""Prepare corresponding-source release materials before any consumer build.

This ordinary maintainer tool downloads public immutable source inputs only.
It never runs npm, cargo, bw, upstream scripts, or a privileged operation.
"""

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import tomllib
from urllib.parse import urlsplit
import urllib.request

from .bitwarden_runtime import MAX_MATERIAL_BYTES, MAX_SOURCE_BYTES, NOTICES, OVERRIDES, digest, locked, ordinary_input, source_materials
from .bitwarden_notices import supplemental_notice

HOSTS = {"raw.githubusercontent.com", "codeload.github.com", "registry.npmjs.org", "static.crates.io", "nodejs.org"}


def reviewed_url(url):
    parsed = urlsplit(url)
    return (parsed.scheme == "https" and parsed.netloc in HOSTS
            and not parsed.username and not parsed.password and not parsed.fragment)


class ReviewedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, request, response, code, message, headers, newurl):
        if not reviewed_url(newurl):
            raise ValueError("bitwarden_source_redirect_not_reviewed")
        return super().redirect_request(request, response, code, message, headers, newurl)


def download(url, path, expected=None):
    if not reviewed_url(url):
        raise ValueError("bitwarden_source_url_not_reviewed")
    temporary = path.with_name(path.name + ".pending")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        opener = urllib.request.build_opener(ReviewedRedirect())
        with opener.open(url, timeout=45) as response, temporary.open("xb") as output:
            if not reviewed_url(response.url):
                raise ValueError("bitwarden_source_redirect_not_reviewed")
            size = 0
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > MAX_MATERIAL_BYTES:
                    raise ValueError("bitwarden_source_download_limit")
                if shutil.disk_usage(path.parent).free < 256 * 1024 * 1024:
                    raise ValueError("insufficient_corresponding_source_scratch_space")
                output.write(block)
        if expected and digest(temporary) != expected:
            raise ValueError("bitwarden_source_download_changed")
        temporary.rename(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def filtered_source(path):
    """Exclude upstream's non-OSS directories; preserve the other source bytes."""
    target = path.with_name(path.name + ".oss")
    with path.open("rb") as source, target.open("xb") as output:
        with tarfile.open(fileobj=source, mode="r|gz") as incoming:
            with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|") as outgoing:
                    count = total = 0
                    for member in incoming:
                        count += 1
                        total += member.size
                        if count > 100_000 or member.size > MAX_MATERIAL_BYTES or total > 1024 * 1024 * 1024:
                            raise ValueError("bitwarden_upstream_source_limit")
                        parts = PurePosixPath(member.name).parts
                        if "bitwarden_license" in parts:
                            continue
                        if member.name.startswith("/") or ".." in parts:
                            raise ValueError("bitwarden_upstream_source_path_changed")
                        if not (member.isfile() or member.isdir() or member.issym()):
                            raise ValueError("bitwarden_upstream_source_type_changed")
                        if member.issym():
                            destination = list(parts[:-1])
                            if member.linkname.startswith("/"):
                                raise ValueError("bitwarden_upstream_source_link_changed")
                            for part in PurePosixPath(member.linkname).parts:
                                if part == "..":
                                    if len(destination) <= 1:
                                        raise ValueError("bitwarden_upstream_source_link_changed")
                                    destination.pop()
                                elif part != ".":
                                    destination.append(part)
                            if "bitwarden_license" in destination:
                                continue
                        outgoing.addfile(member, incoming.extractfile(member) if member.isfile() else None)
    path.unlink()  # Only this tool's freshly downloaded public scratch object.
    target.rename(path)


def notice_text(path, name):
    """Retain upstream copyright/license files from each source distribution."""
    pieces = []
    total = count = expanded = 0
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            count += 1
            expanded += member.size
            if (count > 100_000 or member.size < 0 or member.size > MAX_MATERIAL_BYTES
                    or expanded > MAX_SOURCE_BYTES):
                raise ValueError("bitwarden_dependency_notice_limit")
            lower = PurePosixPath(member.name).name.lower()
            if (member.isfile() and any(word in lower for word in ["license", "licence", "copying", "notice", "copyright"])
                    and member.size <= 256 * 1024):
                with archive.extractfile(member) as stream:
                    raw = stream.read(256 * 1024 + 1)
                if b"\0" not in raw:
                    total += len(raw)
                    if total > 4 * 1024 * 1024:
                        raise ValueError("bitwarden_dependency_notice_limit")
                    pieces.append("\n--- " + name + " :: " + member.name + " ---\n" + raw.decode("utf-8", errors="replace"))
    return "\n".join(pieces)


def reuse_materials(archive_path, expected_sha256, materials, root):
    """Reuse identical public archives while preserving the reviewed old asset."""
    path = ordinary_input(archive_path, maximum=MAX_SOURCE_BYTES)
    if digest(path) != expected_sha256:
        raise ValueError("bitwarden_source_bundle_changed")
    copied = {}
    with tarfile.open(path, "r|gz") as archive:
        index = None
        count = total = 0
        for member in archive:
            count += 1
            total += member.size
            if (count > 3000 or not member.isfile() or not 0 < member.size <= MAX_MATERIAL_BYTES
                    or total > MAX_SOURCE_BYTES):
                raise ValueError("bitwarden_source_bundle_invalid")
            if member.name == "source-index.json":
                if index is not None or member.size > 2 * 1024 * 1024:
                    raise ValueError("bitwarden_source_bundle_invalid")
                index = json.load(archive.extractfile(member))
            if member.name not in materials:
                continue
            if index is None or member.name in copied:
                raise ValueError("bitwarden_source_bundle_invalid")
            row = index["materials"][member.name]
            origin = materials[member.name]
            if row["url"] != origin["url"]:
                continue  # A newer interpreter source must be downloaded.
            target = root / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                shutil.copyfileobj(archive.extractfile(member), output, 1024 * 1024)
            if (target.stat().st_size != row["bytes"] or digest(target) != row["sha256"]
                    or origin.get("sha256", row["sha256"]) != row["sha256"]):
                raise ValueError("bitwarden_source_material_changed")
            copied[member.name] = row
    return copied


def prepare(output, *, reuse_archive=None, reuse_sha256=None):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError("fresh_ordinary_source_build_required")
    if shutil.disk_usage(output.parent).free < 3_000_000_000:
        raise ValueError("insufficient_corresponding_source_scratch_space")
    lock = locked()
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="bitwarden-source-inputs-", dir=output) as temporary:
        root = Path(temporary)
        package = download("https://raw.githubusercontent.com/bitwarden/clients/" + lock["clients_commit"] + "/package-lock.json",
                           root / "package-lock.json", lock["package_lock_sha256"])
        cargo = download("https://raw.githubusercontent.com/bitwarden/sdk-internal/" + lock["sdk_commit"] + "/Cargo.lock",
                         root / "Cargo.lock", lock["cargo_lock_sha256"])
        materials = source_materials(json.loads(package.read_bytes()), tomllib.loads(cargo.read_text()), lock)
        index = {"schema": 1, "managed_by": "account-access-bitwarden-source-v1",
                 "binary_archive_sha256": lock["archive_sha256"], "clients_commit": lock["clients_commit"],
                 "sdk_commit": lock["sdk_commit"], "materials": {}}
        reused = reuse_materials(reuse_archive, reuse_sha256, materials, root) if reuse_archive else {}

        def fetch(item):
            name, origin = item
            target = root / name
            if name not in reused:
                target = download(origin["url"], target, origin.get("sha256"))
            original = digest(target)
            if "integrity" in origin:
                import base64
                with target.open("rb") as stream:
                    actual = "sha512-" + base64.b64encode(hashlib.file_digest(stream, "sha512").digest()).decode()
                if actual != origin["integrity"]:
                    raise ValueError("bitwarden_source_download_changed")
            if origin.get("filter_commercial") and name not in reused:
                filtered_source(target)
            return name, {"url": origin["url"], "sha256": digest(target), "bytes": target.stat().st_size,
                          "upstream_archive_sha256": reused.get(name, {}).get("upstream_archive_sha256", original),
                          "commercial_directories_excluded": bool(origin.get("filter_commercial"))}

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            for name, row in executor.map(fetch, materials.items()):
                index["materials"][name] = row
        if sum(row["bytes"] for row in index["materials"].values()) > 960 * 1024 * 1024:
            raise ValueError("bitwarden_source_material_limit")
        notices, missing = [], []
        for name in materials:
            text = notice_text(root / name, name)
            if not text:
                text = supplemental_notice(name, materials[name], root / name)
            if not text:
                missing.append(name)
            notices.append(text)
        # An unknown attribution remains a publication blocker. Reviewed
        # supplements retain exact upstream files/declarations and provenance.
        index["notice_files_missing"] = missing
        notice = "Bitwarden OSS CLI corresponding-source dependency notices\n" + "\n".join(notices)
        if len(notice.encode()) > 16 * 1024 * 1024:
            raise ValueError("bitwarden_dependency_notice_limit")
        (root / "THIRD_PARTY_NOTICES.txt").write_text(notice)
        shutil.copyfile(OVERRIDES, root / "dependency-overrides.json")
        for name in ["BUILD.md", "GPL-3.0.txt"]:
            shutil.copyfile(NOTICES / name, root / name)
        (root / "source-index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
        archive = output / lock["source_asset"]
        names = ["source-index.json", "package-lock.json", "Cargo.lock", "dependency-overrides.json",
                 "BUILD.md", "GPL-3.0.txt", "THIRD_PARTY_NOTICES.txt", *materials]
        with archive.open("xb") as file:
            with gzip.GzipFile(fileobj=file, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|") as result:
                    for name in names:
                        path = root / name
                        info = tarfile.TarInfo(name)
                        info.mode, info.size = 0o644, path.stat().st_size
                        with path.open("rb") as stream:
                            result.addfile(info, stream)
        summary = {"source_asset": archive.name, "sha256": digest(archive), "bytes": archive.stat().st_size,
                   "materials": len(materials), "notice_files_missing": missing,
                   "dependency_notice_inventory_complete": not missing,
                   "binary_redistribution_ready": False,
                   "private_accounts": 0, "upstream_code_executed": False}
        (output / "source-review.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--reuse-sources", help="Prior reviewed public source asset; original is preserved")
    parser.add_argument("--reuse-sha256", help="Explicit SHA-256 of the prior public source asset")
    args = parser.parse_args()
    report = prepare(args.output, reuse_archive=args.reuse_sources, reuse_sha256=args.reuse_sha256)
    print(json.dumps({key: value for key, value in report.items() if key != "notice_files_missing"}
                     | {"notice_files_missing_count": len(report["notice_files_missing"])}))


if __name__ == "__main__":
    main()
