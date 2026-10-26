import json
import runpy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("cohort", [80, 84])
def test_build_request_pins_unchanged_public_image_and_packaging_source(cohort):
    module = runpy.run_path(str(ROOT / "scripts/build_fresh_image_review.py"))
    profile = module["build_profile"](cohort)
    request = json.loads((ROOT / profile[3]).read_bytes())
    module["validate_request"](request, cohort)
    for key in ("packaging_source", "app_source", "target_manifest_sha256", "input_package_sha256"):
        with pytest.raises(ValueError, match="fresh_image_build_contract_failed"):
            module["validate_request"]({**request, key: "0" * len(request[key])}, cohort)
    for key in ("production_ready", "status"):
        with pytest.raises(ValueError, match="fresh_image_build_contract_failed"):
            module["validate_request"]({**request, key: True}, cohort)
    with pytest.raises(ValueError):
        module["validate_request"](request, 80 if cohort == 84 else 84)


@pytest.mark.parametrize("cohort", [None, True, 80.0, "84", 83, 85])
def test_unreviewed_or_ambiguous_build_cohort_refused(cohort):
    module = runpy.run_path(str(ROOT / "scripts/build_fresh_image_review.py"))
    with pytest.raises(ValueError):
        module["build_profile"](cohort)


@pytest.mark.parametrize("changed", ["root", "personal-mac", "linux", "intel", "repository"])
@pytest.mark.parametrize("cohort", [80, 84])
def test_build_refuses_wrong_execution_context_before_paths_or_processes(monkeypatch, changed, cohort):
    module = runpy.run_path(str(ROOT / "scripts/build_fresh_image_review.py"))
    monkeypatch.setattr(module["sys"], "platform", "linux" if changed == "linux" else "darwin")
    monkeypatch.setattr(module["platform"], "machine", lambda: "x86_64" if changed == "intel" else "arm64")
    monkeypatch.setattr(module["os"], "getuid", lambda: 0 if changed == "root" else 501)
    monkeypatch.setattr(module["os"], "geteuid", module["os"].getuid)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted" if changed == "personal-mac" else "github-hosted")
    monkeypatch.setenv("GITHUB_REPOSITORY", "other/repo" if changed == "repository" else "fainir/account-access")
    with pytest.raises(ValueError, match="fresh_image_build_contract_failed"):
        module["build"](None, None, None, cohort)


def test_fresh84_workflow_downloads_and_builds_only_its_reviewed_cohort():
    import yaml
    workflow = yaml.safe_load((ROOT / ".github/workflows/mac-fresh-image84-build-review.yml").read_text())
    assert workflow.get("on", workflow.get(True))["push"]["paths"] == ["artifacts/fresh-image84-build-request.json"]
    for job in workflow["jobs"].values():
        actions = [step["uses"] for step in job["steps"] if "uses" in step]
        assert actions[0] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        assert "--cohort 84" in commands and "sudo" not in commands
