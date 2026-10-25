"""The hosted compatibility check cannot become an owner-machine entrypoint."""

from pathlib import Path
import runpy

import pytest

PROBE = runpy.run_path(str(Path(__file__).parents[1] / "scripts/mac_owner_upgrade_compatibility_probe.py"))


@pytest.mark.parametrize("fault", ["not_hosted", "root", "wrong_repository", "wrong_temp"])
def test_context_refusal_precedes_paths_and_commands(monkeypatch, fault):
    values = PROBE["main"].__globals__
    monkeypatch.setattr(values["sys"], "platform", "darwin")
    monkeypatch.setattr(values["platform"], "machine", lambda: "arm64")
    monkeypatch.setattr(values["os"], "getuid", lambda: 501)
    monkeypatch.setattr(values["os"], "geteuid", lambda: 501)
    for name, value in {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                        "GITHUB_REPOSITORY": "fainir/account-access", "RUNNER_TEMP": "/Users/runner/work/_temp",
                        "GITHUB_SHA": "a" * 40}.items():
        monkeypatch.setenv(name, value)
    if fault == "not_hosted":
        monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    elif fault == "root":
        monkeypatch.setattr(values["os"], "getuid", lambda: 0)
        monkeypatch.setattr(values["os"], "geteuid", lambda: 0)
    elif fault == "wrong_repository":
        monkeypatch.setenv("GITHUB_REPOSITORY", "unrelated/project")
    else:
        monkeypatch.setenv("RUNNER_TEMP", "/tmp/owner")

    def forbidden(*args, **kwargs):
        pytest.fail("refused context reached a path or command")

    monkeypatch.setattr(values["subprocess"], "run", forbidden)
    monkeypatch.setattr(values["Path"], "is_dir", forbidden)
    with pytest.raises(ValueError, match="owner_compatibility_refused"):
        PROBE["main"]()
