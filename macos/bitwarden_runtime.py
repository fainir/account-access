"""Stage pinned OSS CLI JavaScript/WASM and reviewed source release materials.

Ordinary maintainer build only. No executable is run, downloaded, or discovered
through PATH here. The existing signed Playwright Node is reused; no standalone
CLI executable or embedded interpreter is added to the protected runtime.
"""

import base64
import copy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import tarfile
import tomllib
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).parent
LOCK = ROOT / "bitwarden-cli.lock.json"
OVERRIDES = ROOT / "bitwarden-overrides.lock.json"
NOTICES = ROOT / "notices/bitwarden"
PROVIDER_WORKER = ROOT.parent / "account_access/bitwarden_source.py"
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_MATERIAL_BYTES = 192 * 1024 * 1024


def locked():
    return json.loads(LOCK.read_bytes())


def _reviewed_ledger(lock):
    value = json.loads(OVERRIDES.read_bytes())
    if (value.get("schema") != 1 or type(value.get("schema")) is not int
            or value.get("official_cli_version") != lock["version"]
            or value.get("official_archive_sha256") != lock["archive_sha256"]
            or value.get("upstream_package_lock_sha256") != lock["package_lock_sha256"]):
        raise ValueError("bitwarden_dependency_overrides_changed")
    return value


def reviewed_overrides(lock):
    return _reviewed_ledger(lock)["overrides"]


def review_residual_advisories(lock, *, cli=None, dependencies=None):
    """Refuse stale forge review assumptions; this does not clear the advisory.

    This guard binds the bounded review to the worker, complete official JS
    asset set and resolved dependency graph. Updating an upstream archive pin
    alone cannot silently reuse a review of a different program.
    """
    try:
        rows = _reviewed_ledger(lock)["residual_advisories"]
        if not isinstance(rows, list) or len(rows) != 1:
            raise ValueError()
        row = rows[0]
        if not isinstance(row, dict):
            raise ValueError()
        review = row["applicability"]
        if not isinstance(review, dict) or not isinstance(row.get("version"), str):
            raise ValueError()
        counts = ["bound_namespace_occurrences", "forge_runtime_imports", "chunk_forge_references",
                  "transitive_forge_consumers", "rsa_signature_verification_calls_identified"]
        if any(type(review.get(key)) is not int for key in counts):
            raise ValueError()
        if (row["package"] != "node-forge" or row["version"] != lock["npm_dependencies"]["node-forge"]
                or row["url"] != "https://github.com/advisories/GHSA-86w9-cpqp-85rv"
                or row["analysis_state"] != "under_investigation"
                or review["allowed_commands"] != ["--version", "status", "config server", "login --apikey",
                                                  "unlock", "sync --force", "get item EXACT_UUID"]
                or review["official_entrypoint_sha256"] != lock["entrypoint_sha256"]
                or review["worker_source_sha256"] != digest(PROVIDER_WORKER)
                or review["bound_namespace_occurrences"] != 1
                or review["bound_namespace_used"] is not False
                or review["forge_runtime_imports"] != 1
                or review["chunk_forge_references"] != 0
                or review["transitive_forge_consumers"] != 0
                or review["rsa_signature_verification_calls_identified"] != 0):
            raise ValueError()
        assets = review["javascript_assets_sha256"]
        if (not isinstance(assets, dict) or not assets or lock["entrypoint"] not in assets
                or assets[lock["entrypoint"]] != lock["entrypoint_sha256"]
                or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
                       for value in assets.values())):
            raise ValueError()
        if cli is not None:
            actual = {name: hashlib.sha256(raw).hexdigest() for name, raw in cli.items()
                      if name.endswith((".js", ".cjs", ".mjs"))}
            entry = cli[lock["entrypoint"]]
            binding = b'const external_node_forge_namespaceObject = require("node-forge");'
            # Apart from the unused binding, the reviewed bundle mentions the
            # package only in its external-module label and embedded metadata.
            remaining = entry.replace(binding, b"", 1).replace(b';// external "node-forge"', b"", 1)
            remaining = remaining.replace(b'"node-forge":"' + row["version"].encode() + b'"', b"", 1)
            if (actual != assets
                    or entry.count(b"external_node_forge_namespaceObject") != 1
                    or entry.count(binding) != 1
                    or entry.count(b'require("node-forge")') != 1
                    or b"node-forge" in remaining
                    or any(b"node-forge" in cli[name] or b"external_node_forge_namespaceObject" in cli[name]
                           for name in actual if name != lock["entrypoint"])):
                raise ValueError()
        if dependencies is not None:
            forge_paths = [path for path in dependencies if path.endswith("/node_modules/node-forge")
                           or path == "node_modules/node-forge"]
            if (forge_paths != ["node_modules/node-forge"]
                    or dependencies[forge_paths[0]]["version"] != row["version"]
                    or any("node-forge" in dependency.get(kind, {})
                           for dependency in dependencies.values()
                           for kind in ["dependencies", "optionalDependencies", "peerDependencies"])):
                raise ValueError()
    except (KeyError, TypeError, ValueError, OSError):
        raise ValueError("bitwarden_residual_advisory_review_changed") from None


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def ordinary_input(path, *, maximum):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or not 0 < info.st_size <= maximum or info.st_mode & 0o022):
        raise ValueError("bitwarden_build_input_needs_review")
    return path


def runtime_dependencies(package_lock, lock=None):
    """Resolve only the official CLI's locked external JavaScript dependency tree."""
    lock = lock or locked()
    packages = copy.deepcopy(package_lock["packages"])
    for name, version in lock["npm_dependencies"].items():
        if packages.get("node_modules/" + name, {}).get("version") != version:
            raise ValueError("bitwarden_runtime_dependency_changed")
    replacements = reviewed_overrides(lock)
    for path, change in replacements.items():
        if packages.get(path, {}).get("version") != change["from_version"]:
            raise ValueError("bitwarden_dependency_overrides_changed")
        packages[path] = change["package"]
    result = {}

    def locate(parent, name):
        while True:
            candidate = posixpath.join(parent, "node_modules", name)
            if candidate in packages:
                return candidate
            if not parent:
                raise ValueError("bitwarden_runtime_dependency_missing")
            parent = posixpath.dirname(parent)
            if posixpath.basename(parent) == "node_modules":
                parent = posixpath.dirname(parent)

    def visit(parent, name, optional=False):
        if not re.fullmatch(r"(?:@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+", name):
            raise ValueError("bitwarden_runtime_dependency_changed")
        try:
            path = locate(parent, name)
        except ValueError:
            if optional:
                return
            raise
        if path in result:
            return
        row = packages[path]
        if row.get("dev") or row.get("link") or len(result) >= 1000:
            raise ValueError("bitwarden_runtime_dependency_changed")
        result[path] = row
        for key in ["dependencies", "optionalDependencies", "peerDependencies"]:
            for child in row.get(key, {}):
                is_optional = key == "optionalDependencies" or (key == "peerDependencies"
                    and row.get("peerDependenciesMeta", {}).get(child, {}).get("optional"))
                if not is_optional or key != "peerDependencies":
                    visit(path, child, is_optional)

    # These three external requires are emitted by the reviewed official bundle
    # and supplied transitively by its published package dependencies.
    for name in sorted(set(lock["npm_dependencies"]) | {"buffer", "debug", "proxy-agent-negotiate"}):
        visit("", name)
    if not set(replacements).issubset(result):
        raise ValueError("bitwarden_dependency_overrides_changed")
    review_residual_advisories(lock, dependencies=result)
    return result


def source_materials(package_lock, cargo_lock, lock=None):
    """Complete conservative OSS runtime dependency inventory, without npm/cargo.

    General purpose build tools remain selected by the upstream lockfiles.
    The matching unmodified Node source and SDK Rust sources are included.
    JavaScript packages are limited to the official npm CLI's actual closure.
    """
    lock = lock or locked()
    clients, sdk = lock["clients_commit"], lock["sdk_commit"]
    result = {
        "clients-source.tar.gz": {"url": f"https://codeload.github.com/bitwarden/clients/tar.gz/{clients}", "filter_commercial": True},
        "sdk-source.tar.gz": {"url": f"https://codeload.github.com/bitwarden/sdk-internal/tar.gz/{sdk}", "filter_commercial": True},
        "passkey-source.tar.gz": {"url": "https://codeload.github.com/bitwarden/passkey-rs/tar.gz/" + lock["passkey_commit"]},
        "node-source.tar.xz": {"url": "https://nodejs.org/dist/v" + lock["node_version"] + "/node-v" + lock["node_version"] + ".tar.xz",
                               "sha256": lock["node_source_sha256"]},
    }
    for name, row in runtime_dependencies(package_lock, lock).items():
        url = row.get("resolved", "")
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.netloc != "registry.npmjs.org"
                or parsed.query or parsed.fragment or not isinstance(row.get("integrity"), str)
                or not row["integrity"].startswith("sha512-")):
            raise ValueError("bitwarden_source_dependency_needs_review")
        base64.b64decode(row["integrity"][7:], validate=True)
        result["npm/" + hashlib.sha256(url.encode()).hexdigest() + ".tgz"] = {
            "url": url, "integrity": row["integrity"], "name": name, "version": row["version"]}
    for row in cargo_lock["package"]:
        source = row.get("source", "")
        if source.startswith("git+"):
            expected = "git+https://github.com/bitwarden/passkey-rs?rev=" + lock["passkey_commit"] + "#" + lock["passkey_commit"]
            if source != expected:
                raise ValueError("bitwarden_source_dependency_needs_review")
        elif source:
            if source != "registry+https://github.com/rust-lang/crates.io-index":
                raise ValueError("bitwarden_source_dependency_needs_review")
            name, version, checksum = row["name"], row["version"], row["checksum"]
            if (not re.fullmatch(r"[A-Za-z0-9_-]+", name)
                    or not re.fullmatch(r"[A-Za-z0-9.+_-]+", version)
                    or not re.fullmatch(r"[a-f0-9]{64}", checksum)):
                raise ValueError("bitwarden_source_dependency_needs_review")
            result[f"cargo/{name}-{version}.crate"] = {
                "url": f"https://static.crates.io/crates/{name}/{name}-{version}.crate", "sha256": checksum}
    return result


def _read_member(archive, member, maximum):
    if not member.isfile() or not 0 < member.size <= maximum:
        raise ValueError("bitwarden_source_bundle_invalid")
    with archive.extractfile(member) as stream:
        value = stream.read(maximum + 1)
    if len(value) != member.size:
        raise ValueError("bitwarden_source_bundle_invalid")
    return value


def source_bundle(path, expected_sha256):
    lock = locked()
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("reviewed_bitwarden_source_digest_required")
    path = ordinary_input(path, maximum=MAX_SOURCE_BYTES)
    if digest(path) != expected_sha256:
        raise ValueError("bitwarden_source_bundle_changed")
    with tarfile.open(path, "r:gz") as archive:
        selected = {}
        total = 0
        for row in archive:
            parts = PurePosixPath(row.name).parts
            if (not row.isfile() or row.name.startswith("/") or ".." in parts
                    or "\\" in row.name or not 0 < row.size <= MAX_MATERIAL_BYTES
                    or row.name in selected or len(selected) >= 3000):
                raise ValueError("bitwarden_source_bundle_invalid")
            total += row.size
            if total > MAX_SOURCE_BYTES:
                raise ValueError("bitwarden_source_bundle_invalid")
            selected[row.name] = row
        index = json.loads(_read_member(archive, selected["source-index.json"], 2 * 1024 * 1024))
        if (index.get("schema") != 1 or type(index.get("schema")) is not int
                or index.get("managed_by") != "account-access-bitwarden-source-v1"
                or index.get("binary_archive_sha256") != lock["archive_sha256"]
                or index.get("clients_commit") != lock["clients_commit"]
                or index.get("sdk_commit") != lock["sdk_commit"]):
            raise ValueError("bitwarden_source_bundle_invalid")
        if index.get("notice_files_missing") != []:
            raise ValueError("bitwarden_dependency_notices_need_review")
        package = _read_member(archive, selected["package-lock.json"], 3 * 1024 * 1024)
        cargo = _read_member(archive, selected["Cargo.lock"], 1024 * 1024)
        if (hashlib.sha256(package).hexdigest() != lock["package_lock_sha256"]
                or hashlib.sha256(cargo).hexdigest() != lock["cargo_lock_sha256"]):
            raise ValueError("bitwarden_source_lock_changed")
        expected = source_materials(json.loads(package), tomllib.loads(cargo.decode()), lock)
        required = {"source-index.json", "package-lock.json", "Cargo.lock", "dependency-overrides.json",
                    "BUILD.md", "GPL-3.0.txt", "THIRD_PARTY_NOTICES.txt", *expected}
        if set(selected) != required or set(index.get("materials", {})) != set(expected):
            raise ValueError("bitwarden_corresponding_source_incomplete")
        notices = _read_member(archive, selected["THIRD_PARTY_NOTICES.txt"], 16 * 1024 * 1024)
        if _read_member(archive, selected["dependency-overrides.json"], 128 * 1024) != OVERRIDES.read_bytes():
            raise ValueError("bitwarden_dependency_overrides_changed")
        for name in ["BUILD.md", "GPL-3.0.txt"]:
            if _read_member(archive, selected[name], 128 * 1024) != (NOTICES / name).read_bytes():
                raise ValueError("bitwarden_source_notices_changed")
        for name, origin in expected.items():
            row = index["materials"][name]
            if row.get("url") != origin["url"] or type(row.get("bytes")) is not int or row["bytes"] != selected[name].size:
                raise ValueError("bitwarden_source_bundle_invalid")
            with archive.extractfile(selected[name]) as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            if checksum != row.get("sha256") or origin.get("sha256", checksum) != checksum:
                raise ValueError("bitwarden_source_material_changed")
            if "integrity" in origin:
                with archive.extractfile(selected[name]) as stream:
                    actual = base64.b64encode(hashlib.file_digest(stream, "sha512").digest()).decode()
                if "sha512-" + actual != origin["integrity"]:
                    raise ValueError("bitwarden_source_material_changed")
    return {"source_asset": lock["source_asset"], "source_bundle_sha256": expected_sha256,
            "source_materials": len(expected), "source_distribution_required": True,
            "clients_commit": lock["clients_commit"], "sdk_commit": lock["sdk_commit"]}, notices


def _npm_files(raw):
    """Validate npm's data-only tar layout; never execute install scripts."""
    files, prefix, total, count = {}, None, 0, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            count += 1
            parts = PurePosixPath(member.name).parts
            if (not parts or member.name.startswith("/") or ".." in parts or "\\" in member.name
                    or count > 20_000 or member.size < 0 or member.size > 20 * 1024 * 1024):
                raise ValueError("bitwarden_cli_archive_invalid")
            if prefix is None:
                prefix = parts[0]
            if prefix != parts[0]:
                raise ValueError("bitwarden_cli_archive_invalid")
            if member.isdir():
                continue
            if not member.isfile() or len(parts) < 2:
                raise ValueError("bitwarden_cli_archive_invalid")
            name = str(PurePosixPath(*parts[1:]))
            total += member.size
            if total > 96 * 1024 * 1024:
                raise ValueError("bitwarden_cli_archive_invalid")
            with archive.extractfile(member) as stream:
                raw_file = stream.read(20 * 1024 * 1024 + 1)
            # The upstream agent-base tar repeats identical generated files.
            # Conflicting duplicate entries and every link remain forbidden.
            if name in files and files[name] != raw_file:
                raise ValueError("bitwarden_cli_archive_invalid")
            if (len(raw_file) != member.size or name.endswith(".node")
                    or raw_file[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                                        b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                                        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca", b"\x7fELF"}):
                raise ValueError("bitwarden_cli_native_addon_not_permitted")
            files[name] = raw_file
    return files


def _write_npm(files, target):
    for name, raw in files.items():
        output = target / name
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        with output.open("xb") as stream:
            stream.write(raw)
        output.chmod(0o644)


def stage(payload, archive, sources, source_sha256):
    """Stage exact npm JS/WASM using the already protected Playwright Node."""
    lock = locked()
    archive = ordinary_input(archive, maximum=lock["archive_bytes"])
    if archive.stat().st_size != lock["archive_bytes"] or digest(archive) != lock["archive_sha256"]:
        raise ValueError("bitwarden_cli_archive_changed")
    provenance, notices = source_bundle(sources, source_sha256)
    node_wheel = ordinary_input(Path(payload) / "wheels" / lock["node_wheel_filename"], maximum=96 * 1024 * 1024)
    if digest(node_wheel) != lock["node_wheel_sha256"]:
        raise ValueError("bitwarden_node_runtime_changed")
    with zipfile.ZipFile(node_wheel) as wheel:
        with wheel.open("playwright/driver/node") as node:
            if hashlib.file_digest(node, "sha256").hexdigest() != lock["node_upstream_sha256"]:
                raise ValueError("bitwarden_node_runtime_changed")
    raw = archive.read_bytes()
    if "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode() != lock["npm_integrity"]:
        raise ValueError("bitwarden_cli_archive_changed")
    cli = _npm_files(raw)
    metadata = json.loads(cli["package.json"])
    if (metadata.get("name") != "@bitwarden/cli" or metadata.get("version") != lock["version"]
            or metadata.get("dependencies") != lock["npm_dependencies"]
            or metadata.get("bin") != {"bw": lock["entrypoint"]}
            or hashlib.sha256(cli[lock["entrypoint"]]).hexdigest() != lock["entrypoint_sha256"]):
        raise ValueError("bitwarden_cli_archive_changed")
    review_residual_advisories(lock, cli=cli)
    target = Path(payload) / "python/libexec/bitwarden"
    if target.parent.exists() or target.parent.is_symlink():
        raise ValueError("bitwarden_runtime_destination_must_be_new")
    target.mkdir(parents=True, mode=0o755)
    _write_npm(cli, target)
    with tarfile.open(sources, "r|gz") as source:
        package = None
        dependencies = {}
        for member in source:
            if member.name == "package-lock.json":
                package = json.load(source.extractfile(member))
                for path, row in runtime_dependencies(package, lock).items():
                    name = "npm/" + hashlib.sha256(row["resolved"].encode()).hexdigest() + ".tgz"
                    dependencies.setdefault(name, []).append(path)
            elif member.name in dependencies:
                body = source.extractfile(member).read()
                files = _npm_files(body)
                for path in dependencies.pop(member.name):
                    _write_npm(files, target / path)
        if package is None or dependencies:
            raise ValueError("bitwarden_corresponding_source_incomplete")
    shutil.copyfile(NOTICES / "GPL-3.0.txt", target / "GPL-3.0.txt")
    shutil.copyfile(NOTICES / "NOTICE.md", target / "NOTICE.md")
    (target / "THIRD_PARTY_NOTICES.txt").write_bytes(notices)
    result = {"schema": 1, "version": lock["version"], "architecture": lock["architecture"],
              "entrypoint": lock["entrypoint"], "node_relative": lock["node_relative"],
              "node_version": lock["node_version"], "native_addons": False,
              "node_upstream_sha256": lock["node_upstream_sha256"], "node_wheel_sha256": lock["node_wheel_sha256"],
              "license": "GPL-3.0-only", "upstream_archive_sha256": lock["archive_sha256"],
              "entrypoint_sha256": lock["entrypoint_sha256"], **provenance}
    result["dependency_overrides_sha256"] = digest(OVERRIDES)
    shutil.copyfile(OVERRIDES, target / "dependency-overrides.json")
    (target / "runtime-manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result
