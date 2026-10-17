"""Require native owned-worker supervision, with explicit fixture limitations."""
import json
from pathlib import Path
import sys


CHECKS = {"existing_store_started", "synthetic_owner_session_active_before_crash", "owned_crash_enters_backoff",
          "old_owner_session_retired", "writes_during_backoff_not_replayed", "backoff_deadline_enforced",
          "crashed_store_reopens_automatically", "new_session_requires_own_setup_approval",
          "successive_backoff_deadlines_enforced", "restart_budget_exhaustion_stops_loop",
          "failed_state_does_not_restart_on_tick", "supervisor_shutdown_cleans_listeners",
          "pause_stops_running_worker", "pause_survives_future_ticks", "paused_start_never_launches_worker",
          "paused_native_health_remains_available", "paused_owner_reads_do_not_start_worker",
          "missing_key_is_terminal_without_enrollment", "missing_key_not_recreated"}


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED" and value.get("platform") == "macos"
            and value.get("environment") == "controlled-demo" and value.get("production_ready") is False
            and type(value.get("private_signins")) is int and value["private_signins"] == 0
            and value.get("system_key_used") is True and value.get("actual_worker_used") is True
            and value.get("consumer_deployment_verified") is False
            and value.get("parent_daemon_recovery_verified") is False
            and value.get("genuine_owner_approval_verified") is False
            and value.get("owner_session_checks") == "synthetic-in-process"
            and value.get("controlled_monotonic_clock") is True and value.get("fixture_key_removed") is True
            and isinstance(value.get("checks"), dict) and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Root worker supervision evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated native root worker supervision evidence: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
