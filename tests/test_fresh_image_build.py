import json
import runpy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_build_request_pins_unchanged_public_image_and_packaging_source():
    module = runpy.run_path(str(ROOT / "scripts/build_fresh_image_review.py"))
    request = json.loads((ROOT / module["REQUEST"]).read_bytes())
    module["validate_request"](request)
    for key in ("packaging_source", "app_source", "target_manifest_sha256", "input_package_sha256"):
        with pytest.raises(ValueError, match="fresh_image_build_contract_failed"):
            module["validate_request"]({**request, key: "0" * len(request[key])})
    for key in ("production_ready", "status"):
        with pytest.raises(ValueError, match="fresh_image_build_contract_failed"):
            module["validate_request"]({**request, key: True})


@pytest.mark.parametrize("changed", ["root", "personal-mac", "linux", "intel", "repository"])
def test_build_refuses_wrong_execution_context_before_paths_or_processes(monkeypatch, changed):
    module = runpy.run_path(str(ROOT / "scripts/build_fresh_image_review.py"))
    monkeypatch.setattr(module["sys"], "platform", "linux" if changed == "linux" else "darwin")
    monkeypatch.setattr(module["platform"], "machine", lambda: "x86_64" if changed == "intel" else "arm64")
    monkeypatch.setattr(module["os"], "getuid", lambda: 0 if changed == "root" else 501)
    monkeypatch.setattr(module["os"], "geteuid", module["os"].getuid)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted" if changed == "personal-mac" else "github-hosted")
    monkeypatch.setenv("GITHUB_REPOSITORY", "other/repo" if changed == "repository" else "fainir/account-access")
    with pytest.raises(ValueError, match="fresh_image_build_contract_failed"):
        module["build"](None, None, None)
