from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_owner_upgrade112_diagnostic",
    ROOT / "scripts/build_owner_upgrade112_diagnostic.py",
)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def test_candidate_is_bound_to_reviewed_inputs_and_new_package_identity() -> None:
    assert BUILDER.BASE_PACKAGE_SHA256 == "0528d4a545c14c92c58a8ebe03660e8d75efd7d38b67db92ccc913a5249ce2a0"
    assert BUILDER.PACKAGE95_SHA256 == "0c7a83b47d405bd9b02686aceb938877c5cd2f36112cb0b8369069c643453371"
    assert BUILDER.INVENTORY95_SHA256 == "9072d9bce2fd9c1b6118e657c77cab3f32e5c44689f4bb230132f07bbbb0e1e1"
    assert BUILDER.PACKAGE_ID == "com.fainir.accountaccess.ownerupgrade112"


def test_package_info_binds_build112_identity_and_extends_postinstall_timeout() -> None:
    package_info = (
        b'<pkg-info identifier="com.fainir.accountaccess.ownerupgrade112" install-location="/">'
        b'<postinstall file="./postinstall" timeout="600"/>'
    )

    updated = BUILDER.update_package_info(package_info)

    assert b'identifier="com.fainir.accountaccess.ownerupgrade112"' in updated
    assert b'timeout="1800"' in updated
    for mismatch in (
        package_info.replace(b"ownerupgrade112", b"ownerupgrade110"),
        package_info.replace(b'timeout="600"', b'timeout="300"'),
    ):
        with pytest.raises(BUILDER.BuildRefused, match="generated_package_info_mismatch"):
            BUILDER.update_package_info(mismatch)


def test_builder_pins_its_own_source_for_reproducible_builds() -> None:
    source = (ROOT / "scripts/build_owner_upgrade112_diagnostic.py").read_text()
    assert '"scripts/build_owner_upgrade112_diagnostic.py"' in source
    assert "scripts/build_owner_upgrade110_diagnostic.py" not in source


def test_precompiled_helper_must_match_source_and_compile_report(tmp_path: Path) -> None:
    helper = tmp_path / "AccountAccess-ownerupgrade"
    helper.write_bytes(b"compiled helper")
    sources = BUILDER.collect_sources()
    source_hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}
    report = {
        "status": "PASSED",
        "source_commit": "a" * 40,
        "target": "arm64-apple-macos14",
        "optimization": "whole-module",
        "ordinary_entrypoint_refusal": True,
        "installed_reads": False,
        "installed_writes": False,
        "production_ready": False,
        "source_sha256": dict(source_hashes),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
    }
    report_path = tmp_path / "compile-report.json"
    report_path.write_text(json.dumps(report))

    assert BUILDER.validate_native_helper(helper, report_path, "a" * 40, sources) == report

    report["source_sha256"]["macos/OwnerUpgradeMain.swift"] = "0" * 64
    report_path.write_text(json.dumps(report))
    with pytest.raises(BUILDER.BuildRefused, match="native_compile_source_mismatch"):
        BUILDER.validate_native_helper(helper, report_path, "a" * 40, sources)

    report["source_sha256"] = dict(source_hashes)
    report["helper_sha256"] = "0" * 64
    report_path.write_text(json.dumps(report))
    with pytest.raises(BUILDER.BuildRefused, match="native_compile_helper_mismatch"):
        BUILDER.validate_native_helper(helper, report_path, "a" * 40, sources)


def test_source_qa_keeps_native_fixture_timeout_explicit(tmp_path: Path) -> None:
    sources = BUILDER.collect_sources()
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}
    shared = {"status": "PASSED", "production_ready": False, "source_sha256": {}}
    runtime = {"status": "PASSED", "production_ready": False,
               "result": {"checks": 69}, "source_sha256": {}}
    owner = {
        "status": "SOURCE_REGRESSION_PASSED",
        "source_regression_tests": 83,
        "swift_parser": "PASSED",
        "native_fixture_probe": "TIMED_OUT_UNVERIFIED",
        "installed_reads": False,
        "installed_writes": False,
        "production_ready": False,
        "source_sha256": hashes,
    }
    paths = []
    for name, report in (("shared", shared), ("runtime", runtime), ("owner", owner)):
        path = tmp_path / (name + ".json")
        path.write_text(json.dumps(report))
        paths.append(path)

    BUILDER.validate_qa(*paths, sources)

    owner["native_fixture_probe"] = "UNKNOWN"
    paths[2].write_text(json.dumps(owner))
    with pytest.raises(BUILDER.BuildRefused, match="owner_qa_not_passed"):
        BUILDER.validate_qa(*paths, sources)
