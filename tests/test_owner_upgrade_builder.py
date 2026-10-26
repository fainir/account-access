"""Build contract checks with fictional reports and inventories only."""

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import struct
import sys
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "owner_builder", Path(__file__).resolve().parents[1] / "scripts/build_owner_upgrade_review.py"
)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
REJECTED_WRAPPER = (Path(__file__).parents[1] / "artifacts/owner99-rejected-postinstall-20261025.sh.txt").read_bytes()
OLD_HELPER = "71adcbfa469f9b6dcb6705cefc55015dea23807cf7d08c7e9ba369658c7f4daa"
NEW_HELPER = "f45ec93061242a71c7bcf25539ad70fd922a50a4e5c2a46e0efd2dc65f70bedf"


def target_fixture(command=None, *, cpu=0x100000C, filetype=2, ncmds=1, minimum=14 << 16, sdk=27 << 16, platform=1):
    command = struct.pack("<6I", 0x32, 24, platform, minimum, sdk, 0) if command is None else command
    return struct.pack("<8I", 0xFEEDFACF, cpu, 0, filetype, ncmds, len(command), 0, 0) + command


def test_macho_target_is_read_from_the_executable_not_assumed_from_arguments():
    assert builder.helper_target(target_fixture()) == {
        "architecture": "arm64", "platform": "macos", "minimum_macos": "14.0", "sdk": "27.0"}


def test_actual_package100_build_version_record_is_refused():
    import json
    evidence = json.loads((Path(__file__).parents[1] / "artifacts/owner-upgrade100-installer-refusal-20261025.json").read_bytes())
    command = bytes.fromhex(evidence["helper_build_version"]["load_command_hex"])
    with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
        builder.helper_target(target_fixture(command))


@pytest.mark.parametrize("raw", [
    b"", target_fixture()[:31], target_fixture()[:-1],
    target_fixture(cpu=0x1000007), target_fixture(filetype=6),
    target_fixture(minimum=27 << 16), target_fixture(minimum=15 << 16),
    target_fixture(sdk=13 << 16), target_fixture(platform=2),
    target_fixture(ncmds=0), target_fixture(ncmds=2),
    target_fixture(struct.pack("<2I", 0x32, 0)),
    target_fixture(struct.pack("<6I", 0x32, 24, 1, 14 << 16, 27 << 16, 1)),
    target_fixture(struct.pack("<6I", 0x32, 24, 1, 14 << 16, 27 << 16, 0) * 2, ncmds=2),
])
def test_wrong_platform_architecture_deployment_or_malformed_load_commands_refused(raw):
    with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
        builder.helper_target(raw)


def test_actual_rejected_package99_wrapper_cannot_bind_its_rebuilt_helper():
    builder.verify_wrapper_binding(REJECTED_WRAPPER, OLD_HELPER)
    with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
        builder.verify_wrapper_binding(REJECTED_WRAPPER, NEW_HELPER)


def test_owner_wrapper_is_derived_from_the_exact_runtime_wrapper_and_new_helper():
    runtime = REJECTED_WRAPPER.replace(b"AccountAccess-ownerupgrade", b"AccountAccess-runtimeupgrade")
    corrected = builder.owner_wrapper(runtime, OLD_HELPER, NEW_HELPER)
    assert corrected == REJECTED_WRAPPER.replace(OLD_HELPER.encode(), NEW_HELPER.encode())
    builder.verify_wrapper_binding(corrected, NEW_HELPER)


@pytest.mark.parametrize("fault", ["old_pin", "duplicate_pin", "commented_guard", "different_hash_command", "different_helper", "extra_tail"])
def test_binding_refuses_stale_or_modified_shell_entrypoints(fault):
    corrected = REJECTED_WRAPPER.replace(OLD_HELPER.encode(), NEW_HELPER.encode())
    if fault == "old_pin":
        corrected = REJECTED_WRAPPER
    elif fault == "duplicate_pin":
        corrected = b"# " + NEW_HELPER.encode() + b"\n" + corrected
    elif fault == "commented_guard":
        corrected = corrected.replace(b'[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum',
                                      b'#[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum')
    elif fault == "different_hash_command":
        corrected = corrected.replace(b"shasum -a 256", b"shasum -a 512")
    elif fault == "different_helper":
        corrected = corrected.replace(b"AccountAccess-ownerupgrade", b"AccountAccess-unreviewed")
    else:
        corrected += b"echo unexpected\n"
    with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
        builder.verify_wrapper_binding(corrected, NEW_HELPER)


@pytest.mark.skipif(not Path("/usr/bin/shasum").is_file(), reason="actual fixed hash command")
def test_exact_shell_hash_guard_accepts_only_its_owned_fixture_bytes(tmp_path):
    binary = tmp_path / "fictional-helper-not-executed"
    binary.write_bytes(b"fictional helper bytes")
    checksum = hashlib.sha256(binary.read_bytes()).hexdigest()
    wrapper = REJECTED_WRAPPER.replace(OLD_HELPER.encode(), checksum.encode())
    builder.verify_wrapper_binding(wrapper, checksum)
    guard = next(line for line in wrapper.splitlines() if b"/usr/bin/shasum -a 256" in line)
    script = b'AC_COMPONENT_HELPER="$1"\n' + guard + b"\n"
    def run():
        return subprocess.run(["/bin/sh", "-c", script.decode(), "fixture", str(binary)], capture_output=True)
    assert run().returncode == 0
    binary.write_bytes(b"changed fictional helper bytes")
    assert run().returncode == 1


@pytest.mark.skipif(sys.platform != "darwin", reason="Apple build tools")
def test_apple_build_tools_exist_before_expensive_compilation():
    builder.verify_build_tools()


def test_missing_build_tool_refused(monkeypatch):
    monkeypatch.setattr(builder, "BUILD_TOOLS", ("/nonexistent-account-access-builder-tool",))
    with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
        builder.verify_build_tools()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS package archive extractor")
@pytest.mark.parametrize("leading_dot", [False, True])
def test_sparse_cpio_extraction_keeps_verifier_and_omits_only_payloads(tmp_path, leading_dot):
    source, output = tmp_path / "input", tmp_path / "output"
    source.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    rows = {
        "TargetImage/large-payload": b"omit unchanged image",
        "Predecessor/CompletedImage/large-payload": b"omit unchanged ancestor",
        "TargetImageExtra/keep": b"different component",
        "._TargetImage": b"omit directory AppleDouble metadata",
        "Predecessor/._CompletedImage": b"omit ancestor AppleDouble metadata",
        "._TargetImageExtra": b"retain unrelated metadata-looking name",
        "Predecessor/AccountAccess-broker": b"retain exact native verifier",
        "Predecessor/Plan.json": b"retain original source record",
        "TargetManifest.json": b"retain full target manifest",
    }
    for name, raw in rows.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    archive = tmp_path / "Scripts"
    members = ["."] if leading_dot else sorted(p.name for p in source.iterdir())
    subprocess.run(
        [
            "/usr/bin/tar",
            "--no-mac-metadata",
            "--format=newc",
            "-czf",
            str(archive),
            "-C",
            str(source),
            *members,
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(builder.proof_extract_command(archive, output), check=True, capture_output=True)
    assert output.stat().st_mode & 0o777 == 0o700
    actual = {str(p.relative_to(output)): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    assert actual == {
        name: raw
        for name, raw in rows.items()
        if not name.startswith(("TargetImage/", "Predecessor/CompletedImage/"))
        and name not in {"._TargetImage", "Predecessor/._CompletedImage"}
    }


def reports():
    source = {"macos/fictional.swift": b"fictional source"}
    pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in source.items()}
    shared = {
        "status": "PASSED",
        "sources_stable": True,
        "guarded_main_refusals": 6,
        "source_sha256": pins,
    }
    runtime = {
        "status": "PASSED",
        "entrypoint_ordinary_refusal": True,
        "installed_reads": False,
        "result": {"status": "PASSED", "checks": 68},
        "source_sha256": pins,
    }
    owner = {
        "status": "PASSED",
        "ordinary_entrypoint_refusal": True,
        "installed_reads": False,
        "installed_writes": False,
        "production_ready": False,
        "source_sha256": pins,
        "results": [
            {"status": "PASSED", "checks": 32},
            {"status": "PASSED", "ordinary_context_refusals": 2, "namespace_checks": 26, "preparation_checks": 21},
            {"status": "PASSED", "checks": 477, "root_execution": False},
            {"status": "PASSED", "checks": 324, "owned_temp_fake_barrier_only": True},
        ],
    }
    return shared, runtime, owner, source


def test_exact_ordinary_qa_and_source_bindings_are_required():
    builder.validate_qa(*reports())


@pytest.mark.parametrize(
    "fault",
    [
        "shared_status",
        "shared_stability",
        "shared_refusals",
        "runtime_status",
        "runtime_entry",
        "runtime_result",
        "runtime_reads",
        "owner_status",
        "owner_entry",
        "owner_reads",
        "owner_writes",
        "owner_production",
        "missing_result",
        "failed_result",
        "source_changed",
        "shared_source_changed",
        "namespace_count",
        "preparation_count",
        "root_execution",
        "real_barrier",
    ],
)
def test_unqualified_or_mismatched_reports_refused(fault):
    shared, runtime, owner, sources = deepcopy(reports())
    if fault == "shared_status":
        shared["status"] = "REFUSED"
    elif fault == "shared_stability":
        shared["sources_stable"] = False
    elif fault == "shared_refusals":
        shared["guarded_main_refusals"] = 5
    elif fault == "runtime_status":
        runtime["status"] = "REFUSED"
    elif fault == "runtime_entry":
        runtime["entrypoint_ordinary_refusal"] = False
    elif fault == "runtime_result":
        runtime["result"]["status"] = "REFUSED"
    elif fault == "runtime_reads":
        runtime["installed_reads"] = True
    elif fault == "owner_status":
        owner["status"] = "REFUSED"
    elif fault == "owner_entry":
        owner["ordinary_entrypoint_refusal"] = False
    elif fault == "owner_reads":
        owner["installed_reads"] = True
    elif fault == "owner_writes":
        owner["installed_writes"] = True
    elif fault == "owner_production":
        owner["production_ready"] = True
    elif fault == "missing_result":
        owner["results"].pop()
    elif fault == "failed_result":
        owner["results"][0]["status"] = "REFUSED"
    elif fault == "source_changed":
        sources["macos/fictional.swift"] = b"different source"
    elif fault == "shared_source_changed":
        shared["source_sha256"] = {"macos/fictional.swift": "0" * 64}
    elif fault == "namespace_count":
        owner["results"][1]["namespace_checks"] = 25
    elif fault == "preparation_count":
        owner["results"][1]["preparation_checks"] = 20
    elif fault == "root_execution":
        owner["results"][2]["root_execution"] = True
    elif fault == "real_barrier":
        owner["results"][3]["owned_temp_fake_barrier_only"] = False
    with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
        builder.validate_qa(shared, runtime, owner, sources)


@pytest.mark.parametrize(
    "platform,uid,euid", [("linux", 501, 501), ("darwin", 0, 0), ("darwin", 501, 0)]
)
def test_context_refusal_precedes_any_path_read(monkeypatch, platform, uid, euid):
    monkeypatch.setattr(builder.sys, "platform", platform)
    monkeypatch.setattr(builder.os, "getuid", lambda: uid)
    monkeypatch.setattr(builder.os, "geteuid", lambda: euid)
    with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
        builder.build(SimpleNamespace())


@pytest.mark.parametrize(
    "fault", [None, "extra_root", "changed_byte", "missing_alias", "wrong_mode"]
)
def test_whole_build_tree_matches_the_two_public_roots(fault):
    directory = {"kind": "directory", "mode": 0o755, "acl": "empty"}
    alias = {
        "kind": "symlink",
        "mode": 0o755,
        "target": "../Library/Application Support/Account Access/owner.app",
        "acl": "empty",
    }
    file = {"kind": "file", "mode": 0o644, "bytes": 3, "sha256": "a" * 64, "acl": "empty"}
    rows = {
        name: dict(directory)
        for name in (
            "",
            "Applications",
            "Library",
            "Library/Application Support",
            "Library/Application Support/Account Access",
        )
    }
    rows["Applications/Account Access.app"] = dict(alias)
    rows["Library/Application Support/Account Access/example"] = dict(file)
    manifest = {
        "roots": {
            "/Applications/Account Access.app": {
                "": {"kind": "symlink", "target": alias["target"]}
            },
            "/Library/Application Support/Account Access": {
                "": {"kind": "directory", "mode": 0o755},
                "example": {"kind": "file", "mode": 0o644, "size": 3, "sha256": "a" * 64},
            },
        }
    }
    if fault == "extra_root":
        rows["unreviewed"] = directory
    elif fault == "changed_byte":
        rows["Library/Application Support/Account Access/example"]["sha256"] = "b" * 64
    elif fault == "missing_alias":
        del rows["Applications/Account Access.app"]
    elif fault == "wrong_mode":
        rows["Library/Application Support/Account Access/example"]["mode"] = 0o600
    if fault is None:
        builder.public_image(rows, manifest)
    else:
        with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
            builder.public_image(rows, manifest)


def test_predecessor_projection_keeps_exact_records_and_native_broker():
    directory = {"kind": "directory", "mode": 0o755}
    file = {"kind": "file", "mode": 0o644, "sha256": "a" * 64, "bytes": 3}
    rows = {
        "": {"kind": "directory", "mode": 0o700, "acl": "empty"},
        "TargetImage": directory,
        "TargetImage/large-runtime": file,
        "Predecessor": directory,
        "Predecessor/CompletedImage": directory,
        "Predecessor/CompletedImage/large-runtime": file,
        "RuntimeUpgradePlan.json": file,
        "Predecessor/AccountAccess-broker": file,
    }
    projected = builder.proof_inventory(rows)
    assert set(projected) == set(rows) - {
        "TargetImage/large-runtime",
        "Predecessor/CompletedImage/large-runtime",
    }
    assert projected[""] == {"kind": "directory", "mode": 0o755, "acl": "empty"}
    assert rows[""]["mode"] == 0o700
    assert all(projected[name] == rows[name] for name in projected if name)


@pytest.mark.parametrize("fault", ["missing", "file", "wrong_mode"])
def test_predecessor_projection_refuses_unexpected_roots(fault):
    rows = {
        name: {"kind": "directory", "mode": 0o755}
        for name in ("TargetImage", "Predecessor/CompletedImage")
    }
    rows[""] = {"kind": "directory", "mode": 0o700, "acl": "empty"}
    if fault == "missing":
        del rows["TargetImage"]
    elif fault == "file":
        rows["TargetImage"]["kind"] = "file"
    else:
        rows["TargetImage"]["mode"] = 0o700
    with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
        builder.proof_inventory(rows)


@pytest.mark.parametrize(
    "root",
    [
        None,
        {"kind": "file", "mode": 0o700, "acl": "empty"},
        {"kind": "directory", "mode": 0o755, "acl": "empty"},
        {"kind": "directory", "mode": 0o700, "acl": "nonempty"},
    ],
)
def test_predecessor_projection_refuses_an_unqualified_original_container(root):
    rows = {
        name: {"kind": "directory", "mode": 0o755}
        for name in ("TargetImage", "Predecessor/CompletedImage")
    }
    if root is not None:
        rows[""] = root
    with pytest.raises(ValueError, match="owner_upgrade_build_refused"):
        builder.proof_inventory(rows)
