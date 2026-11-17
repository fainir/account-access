"""Compile the production retry orchestration without root or worker capabilities."""
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "darwin", reason="native Swift startup checks require macOS")
def test_initial_worker_timeout_recovery_cleanup_authority_pause_and_budget(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sources = []
    for name, boundary in [("RootWorkerProcess", "final class RootWorkerProcess {"),
                           ("RootWorkerSupervisor", "final class RootWorkerSupervisor:")]:
        raw = (root / f"macos/{name}.swift").read_text()
        prefix, separator, _ = raw.partition(boundary)
        assert separator
        target = tmp_path / f"{name}.swift"
        target.write_text(prefix)
        sources.append(str(target))
    binary = tmp_path / "startup-recovery-checks"
    subprocess.run(["xcrun", "swiftc", "-O", "-parse-as-library", "-warnings-as-errors",
                    "-framework", "Foundation", "-framework", "Security", *sources,
                    str(root / "macos/Tests/InitialWorkerStartupRecoveryChecks.swift"), "-o", str(binary)],
                   capture_output=True, check=True, timeout=120)
    result = subprocess.run([str(binary)], capture_output=True, text=True, check=True, timeout=10)
    assert not result.stderr
    assert result.stdout.splitlines() == [
        "PASS initial_timeout_retries_only_after_owned_cleanup_and_fresh_authority",
        "PASS two_retry_budget_exhaustion_preserves_exact_timeout",
        "PASS later_success_uses_finite_separate_startup_backoff",
        "PASS identity_socket_code_pause_and_exit_failures_never_retry",
        "PASS key_authorization_and_publication_failures_never_retry",
        "PASS cleanup_failure_replaces_timeout_without_retry",
        "PASS default_caller_retains_one_attempt_without_enrollment_callback",
        "PASS pause_before_backoff_returns_interrupted_without_repair_error",
        "PASS pause_during_backoff_stops_before_another_child",
        "PASS final_backoff_slice_rechecks_pause_before_launch",
        "PASS changed_durable_authority_is_terminal_after_cleanup",
        "PASS later_security_failure_does_not_consume_another_retry",
        "PASS paused_launch_without_worker_never_reports_readiness",
    ]
