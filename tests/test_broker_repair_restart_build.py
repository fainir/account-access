"""Inert resource maps and source reports; never build, sign or install."""
from copy import deepcopy
import hashlib
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def controller():
    return runpy.run_path(str(ROOT / "scripts/build_broker_repair_restart_review.py"))


def test_package_profile_is_closed_and_preserves_previous_name():
    select = controller()["package_profile"]
    for cohort in [88, 90]:
        assert select(cohort) == (f"com.fainir.accountaccess.brokerrepair{cohort}",
                                 f"Account-Access-Broker-Repair-{cohort}-local-unsigned-1800.pkg")
    for invalid in [True, "90", 89, 91, None, {}]:
        with pytest.raises(ValueError):
            select(invalid)


def resources():
    def file(raw):
        return {"kind": "file", "mode": 0o755, "acl": "empty", "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}
    before = {"": {"kind": "directory", "mode": 0o755, "acl": "empty"},
              "AccountAccess-brokerrepair": file(b"old helper"), "postinstall": file(b"old wrapper"),
              "CompletedImage/pinned": file(b"immutable predecessor")}
    after = {**before, "AccountAccess-brokerrepair": file(b"new helper"), "postinstall": file(b"new wrapper")}
    return before, after


def test_only_exact_helper_and_wrapper_change():
    before, after = resources()
    controller()["unchanged_resources"](before, after, b"new helper", b"new wrapper")


@pytest.mark.parametrize("fault", ["removed", "added", "predecessor", "mode", "acl", "hash", "size", "kind", "unchanged-helper"])
def test_resource_diff_refuses_unrelated_changes_and_wrong_helper(fault):
    before, after = map(deepcopy, resources())
    if fault == "removed":
        del after["CompletedImage/pinned"]
    elif fault == "added":
        after["unexpected"] = after["postinstall"]
    elif fault == "predecessor":
        after["CompletedImage/pinned"]["sha256"] = "a" * 64
    elif fault == "unchanged-helper":
        after["AccountAccess-brokerrepair"] = before["AccountAccess-brokerrepair"]
    else:
        key = {"hash": "sha256", "size": "bytes"}.get(fault, fault)
        after["AccountAccess-brokerrepair"][key] = "altered"
    with pytest.raises(ValueError):
        controller()["unchanged_resources"](before, after, b"new helper", b"new wrapper")


def qa():
    sources = {"macos/fixture.swift": b"fictional nonexecuted source"}
    report = {"status": "PASSED", "sources_stable": True, "guarded_main_refusals": 6,
              "entrypoint_ordinary_refusal": {"exit_code": 78},
              "repair_entrypoint_ordinary_refusal": {"exit_code": 78},
              "source_sha256": {k: hashlib.sha256(v).hexdigest() for k, v in sources.items()}}
    return report, sources


def test_native_source_report_matches_every_compilation_input():
    report, sources = qa()
    controller()["native_qa"](report, sources)
    sources["macos/second.swift"] = b"another input"
    with pytest.raises(ValueError):
        controller()["native_qa"](report, sources)


@pytest.mark.parametrize("field", ["status", "sources_stable", "guarded_main_refusals", "entrypoint_ordinary_refusal", "repair_entrypoint_ordinary_refusal", "source_sha256"])
def test_missing_native_qa_evidence_refused(field):
    report, sources = qa()
    del report[field]
    with pytest.raises(ValueError):
        controller()["native_qa"](report, sources)


@pytest.mark.parametrize("fault", ["root", "other-platform", "source", "identity"])
def test_build_context_refuses_before_reading_any_input(monkeypatch, fault):
    module = controller()
    monkeypatch.setattr(module["sys"], "platform", "linux" if fault == "other-platform" else "darwin")
    monkeypatch.setattr(module["os"], "getuid", lambda: 0 if fault == "root" else 501)
    monkeypatch.setattr(module["os"], "geteuid", module["os"].getuid)
    args = SimpleNamespace(source="wrong" if fault == "source" else "a" * 40,
                           signing_identity="wrong" if fault == "identity" else "A" * 40)
    with pytest.raises(ValueError):
        module["build"](args)
