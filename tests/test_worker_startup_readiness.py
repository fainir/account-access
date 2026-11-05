"""Compile the production readiness loop without any root/process capabilities."""
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "darwin", reason="native Swift readiness checks require macOS")
def test_cold_start_deadline_child_ownership_and_bounded_health(tmp_path):
    root = Path(__file__).resolve().parents[1]
    raw = (root / "macos/RootWorkerProcess.swift").read_text()
    # The prefix contains the exact enums/loop, excluding the root worker class.
    prefix, separator, _ = raw.partition("final class RootWorkerProcess {")
    assert separator
    source = tmp_path / "Readiness.swift"
    source.write_text(prefix)
    binary = tmp_path / "readiness-checks"
    subprocess.run(["xcrun", "swiftc", "-O", "-parse-as-library", "-warnings-as-errors",
                    "-framework", "Foundation", "-framework", "Security", str(source),
                    str(root / "macos/Tests/WorkerStartupReadinessChecks.swift"), "-o", str(binary)],
                   capture_output=True, check=True, timeout=120)
    result = subprocess.run([str(binary)], capture_output=True, text=True, check=True, timeout=10)
    assert not result.stderr
    assert result.stdout.splitlines() == [
        "PASS cold_live_worker_ready_after_45_seconds",
        "PASS unready_worker_stops_at_fixed_deadline",
        "PASS child_exit_refuses_before_health_probe",
        "PASS ownership_failure_is_preserved",
        "PASS temporary_health_transport_failure_can_recover",
        "PASS health_reply_cannot_outlive_deadline",
    ]
