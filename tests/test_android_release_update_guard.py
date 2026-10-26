"""The update harness must never install or remove apps on an owner's phone."""

from pathlib import Path
import runpy

import pytest

FIXTURE = runpy.run_path(str(Path(__file__).parents[1] / "scripts/android_release_update_journey.py"))


def test_missing_hosted_environment_refuses_before_paths_or_commands(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    def forbidden(*args, **kwargs):
        pytest.fail("ordinary environment reached a command")

    monkeypatch.setattr(FIXTURE["main"].__globals__["subprocess"], "check_output", forbidden)
    monkeypatch.setattr(FIXTURE["main"].__globals__["subprocess"], "run", forbidden)
    with pytest.raises(ValueError, match="android_update_fixture_refused"):
        FIXTURE["main"]()


@pytest.mark.parametrize("devices", [
    "List of devices attached\nphysical-phone\tdevice\n",
    "List of devices attached\nemulator-5554\toffline\n",
    "List of devices attached\nemulator-5554\tdevice\nphysical-phone\tdevice\n",
    "List of devices attached\nemulator-5554\tdevice\nemulator-5556\tdevice\n",
    "List of devices attached\n",
])
def test_ambiguous_or_physical_adb_target_is_refused(devices):
    with pytest.raises(ValueError, match="android_update_fixture_refused"):
        FIXTURE["emulator_serial"](devices)


def test_one_hosted_emulator_is_selected_by_its_exact_serial():
    assert FIXTURE["emulator_serial"]("List of devices attached\nemulator-5554 device product:sdk_gphone model:emulator transport_id:1\n") == "emulator-5554"
