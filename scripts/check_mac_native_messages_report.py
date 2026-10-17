"""Validate native SMS process evidence without claiming physical delivery."""

import json
from pathlib import Path
import sys

CHECKS = {
    "root_launches_reader_as_separate_owner_uid",
    "private_socket_returns_matching_fresh_fixture_code",
    "already_used_message_excluded",
    "pre_request_baseline_excludes_old_messages",
    "expired_native_request_refused",
    "wrong_root_parent_signature_refused",
    "boolean_baseline_refused",
    "ambiguous_matching_texts_refused",
    "wrong_reader_code_refused_before_launch",
    "forged_reader_pid_refused_before_request",
    "untrusted_invoker_cannot_read_codes",
    "future_dated_message_excluded",
    "truncated_result_set_cannot_supply_code",
}


def validate(value):
    return (
        type(value) is dict
        and value.get("status") == "PASSED"
        and value.get("environment") == "controlled-demo"
        and value.get("production_ready") is False
        and type(value.get("private_signins")) is int
        and value["private_signins"] == 0
        and value.get("actual_separate_owner_uid_reader") is True
        and all(
            value.get(name) is False
            for name in [
                "real_messages_database_used",
                "physical_sms_delivery_verified",
                "full_worker_browser_sms_journey_verified",
                "genuine_full_disk_access_verified",
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
    except (ValueError, OSError):
        print("Native Messages evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated native Messages identity and private-socket evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
