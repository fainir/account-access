"""Only early build-script refusal paths; no compiler/signing/app is run."""

from pathlib import Path
import subprocess

import pytest


@pytest.mark.parametrize("number", [None, "", "0", "76", "075", "077", "-1", "77.0", "77x", "1000000000"])
def test_changed_gui_cannot_be_assembled_under_missing_or_historical_build_number(tmp_path, number):
    script = tmp_path / "source with spaces/macos/build.sh"
    script.parent.mkdir(parents=True)
    source = Path(__file__).resolve().parents[1] / "macos/build.sh"
    script.write_bytes(source.read_bytes())
    output = tmp_path / "output-must-not-exist"
    environment = {"PATH": "/usr/bin:/bin", "ACCOUNT_ACCESS_MAC_OUTPUT": str(output)}
    if number is not None:
        environment["ACCOUNT_ACCESS_MAC_BUILD"] = number
    result = subprocess.run(["/bin/sh", str(script)], env=environment,
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"Set ACCOUNT_ACCESS_MAC_BUILD to a decimal build number greater than 76.\n"
    assert not output.exists()


@pytest.mark.parametrize("number", ["77", "123456789", "999999999"])
def test_distinct_build_number_reaches_missing_wheel_gate_without_output_or_compiler(tmp_path, number):
    script = tmp_path / "macos/build.sh"
    script.parent.mkdir()
    script.write_bytes((Path(__file__).resolve().parents[1] / "macos/build.sh").read_bytes())
    output = tmp_path / "output-must-not-exist"
    result = subprocess.run(["/bin/sh", str(script)],
                            env={"PATH": "/usr/bin:/bin", "ACCOUNT_ACCESS_MAC_BUILD": number,
                                 "ACCOUNT_ACCESS_MAC_OUTPUT": str(output)},
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
    assert result.returncode == 1
    assert result.stderr == b"Build the 0.8.0 wheel with uv build before building the Mac installer.\n"
    assert not output.exists()
