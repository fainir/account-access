"""Require the composed native/isolated/browser journey; never claim a real phone."""

import json
from pathlib import Path
import sys

CHECKS = {
    "cli_completed_native_sms_browser_reads",
    "only_approved_result_fields_returned",
    "no_six_digit_code_in_cli_results",
    "agent_still_cannot_read_worker_store",
    "agent_cannot_fetch_native_collector_requests",
    "provider_verified_password_and_fresh_sms",
    "session_reuse_avoids_second_password_and_sms",
    "real_distinct_reader_and_worker_uids",
    "root_collector_stops_cleanly",
    "temporary_collector_job_removed",
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
            value.get(key) is True
            for key in [
                "full_worker_browser_sms_journey_verified",
                "actual_native_collector_used",
                "actual_distinct_uids",
            ]
        )
        and all(
            value.get(key) is False
            for key in [
                "real_messages_database_used",
                "physical_sms_delivery_verified",
                "genuine_full_disk_access_verified",
                "system_key_used",
            ]
        )
        and type(value.get("checks")) is dict
        and set(value["checks"]) == CHECKS
        and all(item is True for item in value["checks"].values())
    )


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Composed native SMS browser evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated composed native reader, isolated worker and browser journey")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
