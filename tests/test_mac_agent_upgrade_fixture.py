"""The mutating legacy fixture must refuse before inspecting any local path."""

from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest


PROBE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/mac_agent_setup_probe.py"))


@pytest.mark.parametrize("platform,uid,euid,hosted,prefix", [
    ("linux", 501, 501, "true", "/Library/PrivilegedHelperTools/account-access-worker-qa-aB12cd34"),
    ("darwin", 0, 0, "true", "/Library/PrivilegedHelperTools/account-access-worker-qa-aB12cd34"),
    ("darwin", 501, 502, "true", "/Library/PrivilegedHelperTools/account-access-worker-qa-aB12cd34"),
    ("darwin", 501, 501, "false", "/Library/PrivilegedHelperTools/account-access-worker-qa-aB12cd34"),
    ("darwin", 501, 501, "true", "/Library/Application Support/Account Access"),
    ("darwin", 501, 501, "true", "/Library/PrivilegedHelperTools/account-access-worker-qa-unreviewed"),
    ("darwin", 501, 501, "true", "/Library/PrivilegedHelperTools/account-access-worker-qa-aB12cd34/../../outside"),
])
def test_upgrade_fixture_refuses_unqualified_context_before_path_access(monkeypatch, platform, uid, euid, hosted, prefix):
    globals_ = PROBE["main"].__globals__
    monkeypatch.setitem(globals_, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setitem(globals_, "os", SimpleNamespace(getuid=lambda: uid, geteuid=lambda: euid,
                                                      environ={"GITHUB_ACTIONS": hosted}))

    def forbidden(*args, **kwargs):
        raise AssertionError("fixture path inspected")

    monkeypatch.setitem(globals_, "root_managed_path", forbidden)
    with pytest.raises(RuntimeError, match="disposable_agent_setup_required"):
        PROBE["main"](["--prefix", prefix, "--socket", str(Path(prefix) / "public/first-enrollment-agent.sock"), "upgrade"])
