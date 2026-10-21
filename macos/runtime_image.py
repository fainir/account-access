"""Build a complete private runtime from approved wheels without importing them.

The supplied interpreter is not executed here. This is maintainer assembly,
never an installed-service repair or a credential migration operation.
"""

from collections import deque
from email.parser import Parser
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tomllib
from urllib.parse import unquote, urlsplit
import zipfile

from installer import install
from installer.destinations import SchemeDictionaryDestination
from installer.sources import WheelFile
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.tags import compatible_tags, cpython_tags, mac_platforms, parse_tag
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

from .payload_audit import MAX_WHEEL, tree_files, wheel_entries
from .runtime_prepare import build_stage, digest, tree_digest

INTERPRETER = "/Library/Application Support/Account Access/runtime/bin/python"
MAX_DISTRIBUTIONS = 256
MAX_METADATA = 2 * 1024 * 1024
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
TRUSTED_LOCK = Path(__file__).resolve().parents[1] / "uv.lock"


def verify_origins(wheels, original_requirements, project_name, project_hash, preparation=None):
    """Bind original filenames to hashes from the maintainer's locked artifacts.

    The app's pinned requirements must approve each original hash as well. A
    preparation receipt is accepted only from this build's signing step.
    """
    approved = set(re.findall(rb"--hash=sha256:([a-f0-9]{64})", original_requirements))
    if TRUSTED_LOCK.stat().st_size > 4 * MAX_METADATA:
        raise ValueError("runtime_image_artifact_lock_limit")
    upstream = tomllib.loads(TRUSTED_LOCK.read_text())
    pairs = set()
    for package in upstream["package"]:
        for wheel in package.get("wheels", []):
            filename = unquote(urlsplit(wheel["url"]).path.rsplit("/", 1)[-1])
            checksum = wheel["hash"].removeprefix("sha256:")
            if checksum.encode() in approved:
                pairs.add((filename, checksum))
    transformed = {}
    if preparation is not None:
        if preparation.get("transform") != "account-access-native-signing-and-wheel-record-v1":
            raise ValueError("runtime_image_preparation_receipt_required")
        for row in preparation["wheels"]:
            if row["filename"] in transformed:
                raise ValueError("runtime_image_preparation_receipt_ambiguous")
            transformed[row["filename"]] = row
    result = {}
    for path in sorted(Path(wheels).iterdir()):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_WHEEL:
            raise ValueError("runtime_image_binary_wheelhouse_required")
        current = digest(path)
        if path.name == project_name:
            if current != project_hash:
                raise ValueError("runtime_image_project_pin_required")
            original = current
        else:
            row = transformed.get(path.name)
            original = current if row is None else row["original_sha256"]
            if row is not None and row["prepared_sha256"] != current:
                raise ValueError("runtime_image_prepared_artifact_changed")
            if (path.name, original) not in pairs:
                raise ValueError("runtime_image_original_filename_hash_mismatch")
        result[path.name] = {"original_sha256": original, "sha256": current}
    if preparation is not None and set(transformed) != set(result) - {project_name}:
        raise ValueError("runtime_image_preparation_receipt_ambiguous")
    return result


def target(architecture, python_version):
    version = Version(python_version)
    if (architecture not in {"arm64", "x86_64"} or version.release[:2] != (3, 12)
            or len(version.release) != 3 or version.is_prerelease or version.is_devrelease
            or version.epoch or version.local or version.is_postrelease):
        raise ValueError("runtime_image_target_unsupported")
    environment = default_environment()
    environment.update(
        implementation_name="cpython", implementation_version=str(version),
        os_name="posix", platform_machine=architecture, platform_python_implementation="CPython",
        platform_system="Darwin", platform_release="", platform_version="",
        python_full_version=str(version), python_version="3.12", sys_platform="darwin", extra="",
    )
    platforms = list(mac_platforms(version=(14, 0), arch=architecture))
    tags = set(cpython_tags((3, 12), abis=["cp312"], platforms=platforms))
    tags.update(compatible_tags((3, 12), interpreter="cp312", platforms=platforms))
    return environment, tags


def applies(marker, environment, extras=()):
    if marker is None:
        return True
    # One image supports all macOS 14+ systems. A host-kernel-dependent marker
    # cannot safely be decided using the maintainer's current OS version.
    if re.search(r"\bplatform_(?:release|version)\b", str(marker)):
        raise ValueError("runtime_image_os_version_marker_unsupported")
    return any(marker.evaluate({**environment, "extra": extra}) for extra in {"", *extras})


def locked(requirements, environment):
    if not requirements or len(requirements) > MAX_METADATA:
        raise ValueError("runtime_image_lock_required")
    result = {}
    text = requirements.decode("utf-8").replace("\\\r\n", " ").replace("\\\n", " ")
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        hashes = set(re.findall(r"--hash=sha256:([a-f0-9]{64})(?=\s|$)", line))
        clean = re.sub(r"\s+--hash=sha256:[a-f0-9]{64}(?=\s|$)", "", line).strip()
        requirement = Requirement(clean)
        pins = list(requirement.specifier)
        if (not hashes or requirement.url or requirement.extras or len(pins) != 1
                or pins[0].operator != "==" or "*" in pins[0].version):
            raise ValueError("runtime_image_exact_hashed_lock_required")
        if not applies(requirement.marker, environment):
            continue
        name = canonicalize_name(requirement.name)
        if name in result or len(result) >= MAX_DISTRIBUTIONS:
            raise ValueError("runtime_image_lock_ambiguous")
        result[name] = (Version(pins[0].version), hashes)
    return result


def metadata(source, name, version, python_version):
    text = source.read_dist_info("METADATA")
    if len(text.encode()) > MAX_METADATA:
        raise ValueError("runtime_image_metadata_limit")
    value = Parser().parsestr(text)
    if (len(value.get_all("Name", [])) != 1 or len(value.get_all("Version", [])) != 1
            or canonicalize_name(value["Name"]) != name or Version(value["Version"]) != version
            or len(value.get_all("Requires-Python", [])) > 1):
        raise ValueError("runtime_image_wheel_identity_mismatch")
    if value.get("Requires-Python"):
        from packaging.specifiers import SpecifierSet

        if not SpecifierSet(value["Requires-Python"]).contains(python_version):
            raise ValueError("runtime_image_python_requirement_mismatch")
    dependencies = value.get_all("Requires-Dist", [])
    if len(dependencies) > 4096:
        raise ValueError("runtime_image_metadata_limit")
    return {
        "dependencies": [Requirement(item) for item in dependencies],
        "extras": {canonicalize_name(item) for item in value.get_all("Provides-Extra", [])},
    }


def select(wheels, requirements, project_name, project_hash, architecture, python_version, *, origins=None):
    environment, tags = target(architecture, python_version)
    expected = locked(requirements, environment)
    project, version, _, _ = parse_wheel_filename(project_name)
    if project != "account-access" or version != Version("0.8.0") or project in expected:
        raise ValueError("runtime_image_project_pin_required")
    if re.fullmatch(r"[a-f0-9]{64}", project_hash) is None:
        raise ValueError("runtime_image_project_pin_required")
    expected[project] = (version, {project_hash})
    chosen = {}
    for path in sorted(Path(wheels).iterdir()):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > MAX_WHEEL or path.suffix != ".whl"):
            raise ValueError("runtime_image_binary_wheelhouse_required")
        name, version, _, wheel_tags = parse_wheel_filename(path.name)
        if name not in expected or version != expected[name][0] or not wheel_tags & tags:
            raise ValueError("runtime_image_wheel_target_or_version_mismatch")
        checksum = digest(path)
        if checksum not in expected[name][1] or name in chosen:
            raise ValueError("runtime_image_wheel_pin_or_uniqueness_mismatch")
        if origins is not None:
            origin = origins.get(path.name)
            if type(origin) is not dict or origin.get("sha256") != checksum:
                raise ValueError("runtime_image_artifact_origin_mismatch")
        with zipfile.ZipFile(path) as archive:
            entries = list(wheel_entries(archive))
            if any(Path(entry.filename).name in {"METADATA", "WHEEL", "RECORD", "entry_points.txt"}
                   and entry.file_size > MAX_METADATA for entry in entries):
                raise ValueError("runtime_image_metadata_limit")
            if any(part.lower().endswith(".pth")
                   or part.lower().split(".", 1)[0] in {"sitecustomize", "usercustomize"}
                   or part.lower() in {"pyvenv.cfg", "python._pth", "python3.12._pth"}
                   for entry in entries for part in Path(entry.filename).parts):
                raise ValueError("runtime_image_wheel_startup_hook_refused")
        with WheelFile.open(path) as source:
            source.validate_record(validate_contents=True)
            wheel_metadata = Parser().parsestr(source.read_dist_info("WHEEL"))
            declared_tags = set()
            for declaration in wheel_metadata.get_all("Tag", []):
                declared_tags.update(parse_tag(declaration))
            covered = all(any(tag == declared or (
                declared.platform == "any" and tag.interpreter == declared.interpreter
                and tag.abi == declared.abi) for declared in declared_tags) for tag in wheel_tags)
            # Some published wheels narrow a generic WHEEL platform in their
            # filename. Accept that only with verified original filename/hash
            # provenance; never let a rename broaden an incompatible wheel.
            if not covered or (declared_tags != wheel_tags and origins is None):
                raise ValueError("runtime_image_wheel_tag_identity_mismatch")
            details = metadata(source, name, version, environment["python_full_version"])
        chosen[name] = {"path": path, "version": version, "sha256": checksum, **details}
    if set(chosen) != set(expected):
        raise ValueError("runtime_image_locked_distribution_missing")
    # Validate the already-resolved lock, rather than running a resolver or
    # downloading an alternative. Extras propagate through this finite graph.
    extras, visited, pending = {project: set()}, {}, deque([project])
    while pending:
        name = pending.popleft()
        active = extras[name]
        if visited.get(name) == active:
            continue
        visited[name] = set(active)
        if not active <= chosen[name]["extras"]:
            raise ValueError("runtime_image_requested_extra_missing")
        for requirement in chosen[name]["dependencies"]:
            if not applies(requirement.marker, environment, active):
                continue
            dependency = canonicalize_name(requirement.name)
            if (requirement.url or dependency not in chosen
                    or not requirement.specifier.contains(chosen[dependency]["version"], prereleases=True)):
                raise ValueError("runtime_image_dependency_lock_mismatch")
            requested = {canonicalize_name(item) for item in requirement.extras}
            previous = extras.get(dependency)
            extras.setdefault(dependency, set()).update(requested)
            if previous is None or visited.get(dependency) != extras[dependency]:
                pending.append(dependency)
    if set(visited) != set(expected):
        raise ValueError("runtime_image_unreachable_locked_distribution")
    return chosen


class Destination(SchemeDictionaryDestination):
    def __init__(self, runtime, name):
        self.runtime = Path(runtime).resolve(strict=True)
        library = str(self.runtime / "lib/python3.12/site-packages")
        super().__init__(
            {"purelib": library, "platlib": library, "scripts": str(self.runtime / "bin"),
             "headers": str(self.runtime / "include/python3.12" / name), "data": str(self.runtime)},
            interpreter=INTERPRETER, script_kind="posix", bytecode_optimization_levels=(),
            overwrite_existing=False,
        )

    def write_to_fs(self, scheme, path, stream, is_executable):
        relative = Path(path)
        if (scheme not in self.scheme_dict or relative.is_absolute() or ".." in relative.parts
                or "\\" in path or "\0" in path):
            raise ValueError("runtime_image_destination_refused")
        target = Path(self.scheme_dict[scheme]) / relative
        if not target.resolve(strict=False).is_relative_to(self.runtime) or target.is_symlink():
            raise ValueError("runtime_image_destination_refused")
        return super().write_to_fs(scheme, path, stream, is_executable)

    def write_script(self, name, module, attr, section):
        if (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) is None
                or IDENTIFIER.fullmatch(module) is None or IDENTIFIER.fullmatch(attr) is None):
            raise ValueError("runtime_image_entrypoint_refused")
        return super().write_script(name, module, attr, section)


def assemble(payload, requirements, project_name, project_hash, architecture, python_version, *, origins=None):
    payload = build_stage(payload)
    source, runtime = payload / "python", payload / "runtime"
    if runtime.exists() or runtime.is_symlink():
        raise ValueError("runtime_image_destination_must_be_new")
    original = tree_digest(source)
    selected = select(payload / "wheels", requirements, project_name, project_hash,
                      architecture, python_version, origins=origins)
    shutil.copytree(source, runtime, symlinks=True)
    executable = runtime / "bin/python3.12"
    if not executable.is_file() or not executable.resolve(strict=True).is_relative_to(runtime):
        raise ValueError("runtime_image_python_required")
    alias = runtime / "bin/python"
    if not alias.exists() and not alias.is_symlink():
        alias.symlink_to("python3.12")
    if alias.resolve(strict=True) != executable.resolve(strict=True):
        raise ValueError("runtime_image_python_alias_mismatch")
    for name, wheel in selected.items():
        with WheelFile.open(wheel["path"]) as source_wheel:
            install(source_wheel, Destination(runtime, name),
                    additional_metadata={"INSTALLER": b"account-access-static-runtime-image 1\n"})
    # Only newly copied/generated public code changes mode. Source signing
    # receipts remain exact and no installed/private account directory is used.
    for directory, _, _ in os.walk(runtime, followlinks=False):
        Path(directory).chmod(0o755)
    for path in tree_files(runtime):
        if not path.is_symlink():
            path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    if tree_digest(source) != original:
        raise ValueError("runtime_image_source_changed")
    from account_access.package_manifest import inventory_digest

    runtime_manifest = inventory_digest(runtime)
    return {
        "schema": 1, "transform": "account-access-static-runtime-image-v1",
        "architecture": architecture, "python_version": python_version,
        "source_python_sha256": original, "runtime_sha256": tree_digest(runtime),
        "runtime_manifest_sha256": runtime_manifest,
        "requirements_sha256": hashlib.sha256(requirements).hexdigest(),
        "interpreter": INTERPRETER, "bytecode_compiled": False,
        "wheel_installation_executes_package_code": False,
        "wheels": [{"name": name, "version": str(wheel["version"]), "sha256": wheel["sha256"]}
                   for name, wheel in selected.items()],
    }
