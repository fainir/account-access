"""Require actual system-host/key custody composition without private QA claims."""

import json
from pathlib import Path
import sys

CHECKS = {
    "cli_completed_native_sms_browser_reads",
    "only_approved_result_fields_returned",
    "no_six_digit_code_in_cli_results",
    "agent_still_cannot_read_worker_store",
    "agent_cannot_fetch_native_collector_requests",
    "system_key_initialized_private_worker_store",
    "production_composed_host_started",
    "kernel_worker_parent_group_identity_verified",
    "launchd_socket_activation_one_shot",
    "two_fresh_password_sms_logins_completed",
    "two_reviewed_identity_steps_completed",
    "saved_sessions_reused_after_each_login",
    "cold_host_reopened_same_store",
    "both_hosts_stopped_owned_workers",
    "temporary_jobs_removed",
    "fixture_setup_policy_removed",
    "fixture_system_key_removed",
    "durable_task_retries_cooldown_without_owner",
}


def validate(value):
    return (
        type(value) is dict
        and value.get("status") == "PASSED"
        and value.get("platform") == "macos"
        and value.get("environment") == "controlled-demo"
        and value.get("production_ready") is False
        and type(value.get("private_signins")) is int
        and value["private_signins"] == 0
        and all(
            value.get(k) is True
            for k in [
                "system_key_used",
                "production_composed_host_used",
                "actual_native_collector_used",
                "actual_distinct_uids",
                "full_worker_browser_sms_journey_verified",
            ]
        )
        and all(
            value.get(k) is False
            for k in [
                "real_messages_database_used",
                "physical_sms_delivery_verified",
                "genuine_owner_approval_verified",
                "genuine_full_disk_access_verified",
                "consumer_deployment_verified",
                "publisher_signed_peers",
            ]
        )
        and type(value.get("checks")) is dict
        and set(value["checks"]) == CHECKS
        and all(v is True for v in value["checks"].values())
    )


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("System-host native SMS evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated production host, System key and native/browser composition")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
