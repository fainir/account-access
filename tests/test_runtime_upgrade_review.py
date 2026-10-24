"""Builder evidence checks only: never compile, sign, install or read accounts."""
from copy import deepcopy
import hashlib
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

review = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/build_runtime_upgrade_review.py"))


def reports():
    sources = {"macos/RuntimeUpgradeMain.swift": b"fictional-entry", "macos/RuntimeUpgradeSource.swift": b"fictional-source"}
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}
    shared = {"status": "PASSED", "sources_stable": True, "guarded_main_refusals": 6, "source_sha256": hashes.copy()}
    runtime = {"status": "PASSED", "entrypoint_ordinary_refusal": True, "result": {"status": "PASSED", "checks": 68},
               "source_sha256": hashes.copy(), "installed_reads": False, "production_ready": False}
    return shared, runtime, sources


def test_both_native_reports_must_bind_every_controller_source():
    shared, runtime, sources = reports()
    review["native_qa"](shared, runtime, sources)
    for name in sources:
        changed = dict(sources, **{name: b"changed-controller"})
        with pytest.raises(ValueError):
            review["native_qa"](shared, runtime, changed)
    for report in (shared, runtime):
        report["source_sha256"].pop("macos/RuntimeUpgradeSource.swift")
        with pytest.raises(ValueError):
            review["native_qa"](shared, runtime, sources)


@pytest.mark.parametrize("target,key,value", [
    ("shared", "sources_stable", 1), ("shared", "guarded_main_refusals", 5),
    ("runtime", "entrypoint_ordinary_refusal", 1), ("runtime", "installed_reads", 0),
    ("runtime", "production_ready", True), ("runtime", "status", "RUNNING"),
    ("result", "checks", 68.0), ("result", "checks", 67), ("result", "status", "SKIPPED"),
])
def test_optimistic_or_incomplete_evidence_refused(target, key, value):
    shared, runtime, sources = deepcopy(reports())
    {"shared": shared, "runtime": runtime, "result": runtime["result"]}[target][key] = value
    with pytest.raises(ValueError):
        review["native_qa"](shared, runtime, sources)


def test_root_builder_refuses_before_consulting_arguments(monkeypatch):
    monkeypatch.setattr(review["os"], "getuid", lambda: 0)
    monkeypatch.setattr(review["os"], "geteuid", lambda: 0)
    monkeypatch.setattr(review["sys"], "platform", "darwin")
    with pytest.raises(ValueError):
        review["build"](SimpleNamespace())
