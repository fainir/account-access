"""Closed draft asset identities only; no network, signing or installation."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=[88, 90])
def cohort(request):
    return request.param


def downloader(cohort=88):
    name = "restart" if cohort == 88 else "progress"
    return runpy.run_path(str(ROOT / f"scripts/download_broker_repair_{name}_inputs.py"))


def test_committed_reviewed_restart_contract(cohort):
    module = downloader(cohort)
    contract = json.loads((ROOT / module["CONTRACT"]).read_bytes())
    assert module["validate"](contract) == contract
    assert contract["source_commit"] == module["SOURCE"]
    prior = json.loads((ROOT / "artifacts/broker-repair-installer87-inputs.json").read_bytes())
    for name in ("root-revalidation.pkg", "root-revalidation-review.json"):
        assert contract["assets"][name] == prior["assets"][name]


def fixture(monkeypatch, cohort):
    module = downloader(cohort)
    value = {"schema": 1, "status": "FROZEN_REVIEWED_ASSETS", "repository": module["REPOSITORY"],
             "source_commit": module["SOURCE"], "assets": {}}
    for index, name in enumerate(sorted(module["FILES"]), 1):
        value["assets"][name] = {"id": index, "bytes": index + 100, "sha256": str(index) * 64,
            "release": {"id": 100, "source": module["SOURCE"], "tag": "fictional-draft"}}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    monkeypatch.setitem(module["validate"].__globals__, "CONTRACT_SHA256", hashlib.sha256(raw).hexdigest())
    return module, value


def test_exact_fixture_and_every_nested_identity_are_bound(monkeypatch, cohort):
    module, value = fixture(monkeypatch, cohort)
    assert module["validate"](value) == value
    for name, row in value["assets"].items():
        for key in row:
            altered = deepcopy(value)
            altered["assets"][name][key] = "foreign"
            with pytest.raises(ValueError):
                module["validate"](altered)
        for key in row["release"]:
            altered = deepcopy(value)
            altered["assets"][name]["release"][key] = "foreign"
            with pytest.raises(ValueError):
                module["validate"](altered)
    for key in value:
        altered = deepcopy(value)
        del altered[key]
        with pytest.raises(ValueError):
            module["validate"](altered)
    with pytest.raises(ValueError):
        module["validate"]({**value, "schema": True})


@pytest.mark.parametrize("pin", [None, "", "0" * 64, True, "Z" * 64])
def test_unqualified_or_different_contract_cannot_download(monkeypatch, pin, cohort):
    module, value = fixture(monkeypatch, cohort)
    monkeypatch.setitem(module["validate"].__globals__, "CONTRACT_SHA256", pin)
    with pytest.raises(ValueError):
        module["validate"](value)


def test_ordinary_context_refuses_before_any_file_read(monkeypatch, tmp_path, cohort):
    module = downloader(cohort)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(module["os"], "getuid", lambda: 501)
    monkeypatch.setattr(module["os"], "geteuid", lambda: 501)
    monkeypatch.setattr("sys.argv", ["download", "--output", str(tmp_path / "unused")])
    monkeypatch.setattr(Path, "read_bytes", lambda *_: pytest.fail("Unexpected filesystem read"))
    with pytest.raises(ValueError):
        module["main"]()


def test_restart_workflow_is_guarded_and_tests_all_three_scenarios(cohort):
    import yaml
    value = yaml.safe_load((ROOT / f".github/workflows/mac-broker-repair{cohort}-installer-review.yml").read_text())
    job = value["jobs"]["actual-installer"]
    assert job["permissions"] == {"contents": "read"}
    assert job["strategy"]["fail-fast"] is False
    assert set(job["strategy"]["matrix"]["scenario"]) == {"install-reapply", "interrupt-broker", "foreign-binding"}
    assert "GH_TOKEN" not in json.dumps(job)
    assert f"--cohort {cohort}" in json.dumps(job)
    assert all(step.get("with", {}).get("persist-credentials") is False
               for step in job["steps"] if "checkout@" in step.get("uses", ""))


def test_successor_workflow_preserves_reviewed_action_versions():
    import yaml
    def actions(cohort):
        value = yaml.safe_load((ROOT / f".github/workflows/mac-broker-repair{cohort}-installer-review.yml").read_text())
        return [(name, step["uses"]) for name, job in value["jobs"].items()
                for step in job["steps"] if "uses" in step]
    assert actions(90) == actions(88)
