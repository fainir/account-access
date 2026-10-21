import base64
import csv
import hashlib
import io
from pathlib import Path
import zipfile

import pytest

from macos import runtime_image as image


PROJECT = "account_access-0.8.0-py3-none-any.whl"


def wheel(root, name, version="1.0", *, requires=(), extras=(), files=None, entrypoint=False,
          tag="py3-none-any", declared_tag=None, python=">=3.11", corrupt=False):
    normalized = name.replace("-", "_")
    filename = f"{normalized}-{version}-{tag}.whl"
    directory = f"{normalized}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\nRequires-Python: {python}\n"
    metadata += "".join("Requires-Dist: " + item + "\n" for item in requires)
    metadata += "".join("Provides-Extra: " + item + "\n" for item in extras)
    contents = {f"{normalized}/__init__.py": b"raise RuntimeError('package code must not execute')\n",
                f"{directory}/METADATA": metadata.encode(),
                f"{directory}/WHEEL": (f"Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: {declared_tag or tag}\n").encode(),
                **(files or {})}
    if entrypoint:
        contents[f"{directory}/entry_points.txt"] = f"[console_scripts]\n{name}-tool = {normalized}:main\n".encode()
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for path, data in sorted(contents.items()):
        checksum = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        writer.writerow([path, "sha256=" + checksum, len(data)])
    writer.writerow([f"{directory}/RECORD", "", ""])
    contents[f"{directory}/RECORD"] = record.getvalue().encode()
    if corrupt:
        contents[f"{normalized}/__init__.py"] = b"changed after RECORD"
    path = root / filename
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in contents.items():
            archive.writestr(member, data)
    return path


def lock(*paths):
    return b"".join(
        (f"{path.name.split('-')[0]}=={path.name.split('-')[1]} \\\n"
         f"    --hash=sha256:{image.digest(path)}\n").encode()
        for path in paths
    )


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    payload = tmp_path / "private-copy"
    wheels = payload / "wheels"
    wheels.mkdir(parents=True)
    source = payload / "python"
    (source / "bin").mkdir(parents=True)
    (source / "lib/python3.12/site-packages").mkdir(parents=True)
    (source / "bin/python3.12").write_bytes(b"This synthetic interpreter must never execute\n")
    (source / "bin/python3.12").chmod(0o755)
    dependency = wheel(wheels, "fixture", entrypoint=True)
    project = wheel(wheels, "account-access", "0.8.0", requires=["fixture>=1"])
    # Only synthetic private trees are assembled locally. The real OS/private
    # build-copy guard is checked separately; no supplied code executes.
    monkeypatch.setattr(image, "build_stage", lambda value: Path(value).resolve(strict=True))
    return payload, dependency, project


def selected(inputs, *, requirements=None, architecture="arm64", python_version="3.12.13"):
    payload, dependency, project = inputs
    return image.select(payload / "wheels", lock(dependency) if requirements is None else requirements,
                        project.name, image.digest(project), architecture, python_version)


def origin_lock(tmp_path, monkeypatch, *paths):
    artifact_lock = tmp_path / "maintainer-uv.lock"
    artifact_lock.write_text("".join(
        '[[package]]\nname = "fixture"\nwheels = [{url = "https://example.invalid/'
        + path.name + '", hash = "sha256:' + image.digest(path) + '"}]\n'
        for path in paths))
    monkeypatch.setattr(image, "TRUSTED_LOCK", artifact_lock)


def test_original_platform_filename_can_narrow_generic_wheel_metadata_only_with_verified_origin(inputs, tmp_path, monkeypatch):
    payload, dependency, project = inputs
    dependency.unlink()
    dependency = wheel(payload / "wheels", "fixture", tag="py3-none-macosx_11_0_arm64",
                       declared_tag="py3-none-any")
    origin_lock(tmp_path, monkeypatch, dependency)
    with pytest.raises(ValueError, match="wheel_tag_identity_mismatch"):
        selected((payload, dependency, project))
    origins = image.verify_origins(payload / "wheels", lock(dependency), PROJECT, image.digest(project))
    result = image.select(payload / "wheels", lock(dependency), PROJECT, image.digest(project),
                          "arm64", "3.12.13", origins=origins)
    assert set(result) == {"account-access", "fixture"}
    assert origins[dependency.name] == {"original_sha256": image.digest(dependency),
                                        "sha256": image.digest(dependency)}


def test_renaming_hashed_generic_body_linux_artifact_to_mac_is_not_a_verified_origin(inputs, tmp_path, monkeypatch):
    payload, dependency, project = inputs
    dependency.unlink()
    original = wheel(payload / "wheels", "fixture", tag="py3-none-manylinux_2_17_aarch64",
                     declared_tag="py3-none-any")
    origin_lock(tmp_path, monkeypatch, original)
    requirements = lock(original)
    original.rename(payload / "wheels/fixture-1.0-py3-none-macosx_11_0_arm64.whl")
    with pytest.raises(ValueError, match="original_filename_hash_mismatch"):
        image.verify_origins(payload / "wheels", requirements, PROJECT, image.digest(project))


def test_wheel_origin_also_requires_the_apps_original_hash_pin(inputs, tmp_path, monkeypatch):
    payload, dependency, project = inputs
    origin_lock(tmp_path, monkeypatch, dependency)
    with pytest.raises(ValueError, match="original_filename_hash_mismatch"):
        image.verify_origins(payload / "wheels", lock(dependency).replace(image.digest(dependency).encode(), b"0" * 64),
                             PROJECT, image.digest(project))


@pytest.mark.parametrize("fault", [None, "wrong-transform", "wrong-original", "changed-prepared",
                                 "missing-row", "duplicate-row", "extra-row"])
def test_prepared_origin_is_bound_to_original_filename_hash_and_current_signing_receipt(inputs, tmp_path, monkeypatch, fault):
    payload, dependency, project = inputs
    origin_lock(tmp_path, monkeypatch, dependency)
    requirements = lock(dependency)
    original = image.digest(dependency)
    dependency = wheel(payload / "wheels", "fixture", files={"fixture/signed-native": b"prepared bytes"})
    prepared = image.digest(dependency)
    row = {"filename": dependency.name, "original_sha256": original, "prepared_sha256": prepared}
    receipt = {"transform": "account-access-native-signing-and-wheel-record-v1", "wheels": [row]}
    if fault == "wrong-transform":
        receipt["transform"] = "unrecognized"
    elif fault == "wrong-original":
        row["original_sha256"] = "0" * 64
    elif fault == "changed-prepared":
        row["prepared_sha256"] = "0" * 64
    elif fault == "missing-row":
        receipt["wheels"] = []
    elif fault in {"duplicate-row", "extra-row"}:
        receipt["wheels"].append({**row, "filename": row["filename"] if fault == "duplicate-row" else "extra.whl"})
    if fault:
        with pytest.raises(ValueError, match="runtime_image_"):
            image.verify_origins(payload / "wheels", requirements, PROJECT, image.digest(project), receipt)
    else:
        origins = image.verify_origins(payload / "wheels", requirements, PROJECT, image.digest(project), receipt)
        assert origins[dependency.name] == {"original_sha256": original, "sha256": prepared}
        result = image.select(payload / "wheels", lock(dependency), PROJECT, image.digest(project),
                              "arm64", "3.12.13", origins=origins)
        assert result["fixture"]["sha256"] == prepared


def test_verified_origin_cannot_be_reused_for_changed_wheel_bytes(inputs, tmp_path, monkeypatch):
    payload, dependency, project = inputs
    origin_lock(tmp_path, monkeypatch, dependency)
    origins = image.verify_origins(payload / "wheels", lock(dependency), PROJECT, image.digest(project))
    wheel(payload / "wheels", "fixture", files={"fixture/changed": b"unapproved replacement"})
    with pytest.raises(ValueError, match="artifact_origin_mismatch"):
        image.select(payload / "wheels", lock(dependency), PROJECT, image.digest(project),
                     "arm64", "3.12.13", origins=origins)


def test_exact_locked_wheels_are_materialized_without_import_or_interpreter_execution(inputs):
    payload, dependency, project = inputs
    original = image.tree_digest(payload / "python")
    receipt = image.assemble(payload, lock(dependency), project.name, image.digest(project),
                             "arm64", "3.12.13")
    runtime = payload / "runtime"
    assert (runtime / "bin/python").is_symlink()
    assert (runtime / "bin/python").readlink() == Path("python3.12")
    assert image.tree_digest(payload / "python") == original == receipt["source_python_sha256"]
    assert image.tree_digest(runtime) == receipt["runtime_sha256"]
    assert receipt["bytecode_compiled"] is False
    assert receipt["wheel_installation_executes_package_code"] is False
    assert len(receipt["wheels"]) == 2
    assert not list(runtime.rglob("*.pyc"))
    library = runtime / "lib/python3.12/site-packages"
    assert (library / "fixture/__init__.py").read_bytes().startswith(b"raise RuntimeError")
    script = (runtime / "bin/fixture-tool").read_text()
    assert image.INTERPRETER in script and str(payload) not in script
    with (library / "fixture-1.0.dist-info/RECORD").open() as stream:
        rows = list(csv.reader(stream))
    assert any(row[0] == "../../../bin/fixture-tool" for row in rows)
    assert not (payload / "python/bin/fixture-tool").exists()


def test_runtime_destination_cannot_adopt_or_replace_existing_data(inputs):
    payload, dependency, project = inputs
    runtime = payload / "runtime"
    runtime.mkdir()
    marker = runtime / "keep"
    marker.write_text("unrelated fixture")
    with pytest.raises(ValueError, match="runtime_image_destination_must_be_new"):
        image.assemble(payload, lock(dependency), project.name, image.digest(project), "arm64", "3.12.13")
    assert marker.read_text() == "unrelated fixture"


@pytest.mark.parametrize("version,architecture", [("3.13.1", "arm64"), ("3.12.0rc1", "arm64"),
                                                  ("3.12", "arm64"), ("3.12.13", "i386"),
                                                  ("1!3.12.13", "arm64"), ("3.12.13+local", "arm64")])
def test_runtime_target_must_be_stable_cpython_312_with_supported_mac_architecture(version, architecture):
    with pytest.raises(ValueError, match="runtime_image_target_unsupported"):
        image.target(architecture, version)


@pytest.mark.parametrize("change,reason", [
    ("hash", "pin_or_uniqueness"), ("missing", "distribution_missing"),
    ("duplicate", "pin_or_uniqueness"), ("linux", "target_or_version"),
    ("newer-mac", "target_or_version"), ("wrong-abi", "target_or_version"),
    ("python", "python_requirement"), ("record", None),
])
def test_unapproved_missing_incompatible_or_corrupt_wheels_stop_before_image_creation(inputs, change, reason):
    payload, dependency, project = inputs
    requirements = lock(dependency)
    if change == "hash":
        requirements = requirements.replace(image.digest(dependency).encode(), b"0" * 64)
    elif change == "missing":
        dependency.unlink()
    elif change == "duplicate":
        second = wheel(payload / "wheels", "fixture", tag="py2.py3-none-any")
        requirements = requirements.rstrip() + b" \\\n    --hash=sha256:" + image.digest(second).encode() + b"\n"
    else:
        dependency.unlink()
        tag = {"linux": "cp312-cp312-manylinux_2_17_aarch64",
               "newer-mac": "cp312-cp312-macosx_15_0_arm64",
               "wrong-abi": "cp313-cp313-macosx_11_0_arm64"}.get(change, "py3-none-any")
        replacement = wheel(payload / "wheels", "fixture", tag=tag, python=">=3.13" if change == "python" else ">=3.11",
                            corrupt=change == "record")
        requirements = lock(replacement)
    with pytest.raises(ValueError, match=reason):
        image.assemble(payload, requirements, project.name, image.digest(project), "arm64", "3.12.13")
    assert not (payload / "runtime").exists()


@pytest.mark.parametrize("line", ["fixture>=1", "fixture==1.0", "fixture==1.* --hash=sha256:" + "a" * 64,
                                 "fixture @ https://example.invalid/fixture.whl --hash=sha256:" + "a" * 64])
def test_runtime_lock_requires_one_exact_hash_pinned_version(line):
    environment, _ = image.target("arm64", "3.12.13")
    with pytest.raises(ValueError):
        image.locked(line.encode(), environment)


def test_target_markers_do_not_use_the_maintainers_platform(inputs):
    _, dependency, _ = inputs
    requirements = lock(dependency) + b"windows-only==1; sys_platform == 'win32' \\\n    --hash=sha256:" + b"0" * 64 + b"\n"
    assert set(selected(inputs, requirements=requirements)) == {"account-access", "fixture"}


def test_renaming_an_approved_linux_wheel_cannot_forge_mac_compatibility(inputs):
    payload, dependency, _ = inputs
    dependency.unlink()
    original = wheel(payload / "wheels", "fixture", tag="cp312-cp312-manylinux_2_17_aarch64")
    renamed = payload / "wheels/fixture-1.0-py3-none-any.whl"
    original.rename(renamed)
    with pytest.raises(ValueError, match="wheel_tag_identity_mismatch"):
        selected(inputs, requirements=lock(renamed))


def test_os_kernel_version_dependent_locks_are_not_guessed(inputs):
    _, dependency, _ = inputs
    requirements = lock(dependency).replace(b" \\\n", b"; platform_release >= '23' \\\n", 1)
    with pytest.raises(ValueError, match="os_version_marker_unsupported"):
        selected(inputs, requirements=requirements)


@pytest.mark.parametrize("fault", ["missing-dependency", "wrong-version", "unused", "missing-extra"])
def test_installed_metadata_must_match_the_complete_locked_dependency_graph(inputs, fault):
    payload, dependency, _ = inputs
    requires = {"missing-dependency": ["missing>=1"], "wrong-version": ["fixture>=2"],
                "unused": [], "missing-extra": ["fixture[feature]>=1"]}[fault]
    project = wheel(payload / "wheels", "account-access", "0.8.0", requires=requires)
    with pytest.raises(ValueError, match="(?:dependency_lock_mismatch|unreachable_locked|requested_extra_missing)"):
        image.select(payload / "wheels", lock(dependency), PROJECT, image.digest(project), "arm64", "3.12.13")


def test_selected_extras_propagate_through_the_pinned_graph(inputs):
    payload, dependency, _ = inputs
    dependency = wheel(payload / "wheels", "fixture", requires=["optional>=1; extra == 'feature'"], extras=["feature"])
    optional = wheel(payload / "wheels", "optional")
    project = wheel(payload / "wheels", "account-access", "0.8.0", requires=["fixture[feature]>=1"])
    result = image.select(payload / "wheels", lock(dependency, optional), PROJECT, image.digest(project), "arm64", "3.12.13")
    assert set(result) == {"account-access", "fixture", "optional"}


@pytest.mark.parametrize("hook", ["startup.pth", "sitecustomize.py", "usercustomize.py",
                                  "sitecustomize.pyc", "sitecustomize/__init__.py",
                                  "fixture.data/data/pyvenv.cfg"])
def test_wheel_startup_hooks_are_not_silently_added_to_privileged_runtime(inputs, hook):
    payload, _, project = inputs
    dependency = wheel(payload / "wheels", "fixture", files={hook: b"import unrelated"})
    with pytest.raises(ValueError, match="startup_hook_refused"):
        image.assemble(payload, lock(dependency), PROJECT, image.digest(project), "arm64", "3.12.13")


@pytest.mark.parametrize("name,module,attr", [("../escape", "fixture", "main"),
                                           ("safe", "fixture;unsafe", "main"),
                                           ("safe", "fixture", "main()")])
def test_generated_entrypoints_cannot_escape_the_runtime_or_inject_python(inputs, name, module, attr):
    payload, _, _ = inputs
    directory = payload / "destination"
    directory.mkdir()
    destination = image.Destination(directory, "fixture")
    with pytest.raises(ValueError, match="entrypoint_refused"):
        destination.write_script(name, module, attr, "console")
    assert not list(directory.iterdir())


def test_direct_destination_write_refuses_aliases_and_parent_traversal(inputs, tmp_path):
    payload, _, _ = inputs
    runtime = payload / "destination"
    runtime.mkdir()
    destination = image.Destination(runtime, "fixture")
    with pytest.raises(ValueError, match="destination_refused"):
        destination.write_to_fs("data", "../outside", io.BytesIO(b"fixture"), False)
    (runtime / "alias").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="destination_refused"):
        destination.write_to_fs("data", "alias/outside", io.BytesIO(b"fixture"), False)
    assert not (tmp_path / "outside").exists()


def test_production_runtime_assembly_requires_the_private_mac_build_context(tmp_path):
    with pytest.raises(ValueError, match="(?:ordinary_mac_runtime_preparation_required|private_package_build_copy_required)"):
        # Call the actual guard, which the synthetic fixtures replace only for
        # their own unit tests. It cannot touch an installed runtime or vault.
        from macos.runtime_prepare import build_stage

        build_stage(tmp_path)
    assert not list(tmp_path.iterdir())
