"""Require composed native framing/XPC/worker evidence without Chrome claims."""

import json
from pathlib import Path
import sys

CHECKS = {
    "framed_desktop_xpc_reaches_enrolled_worker",
    "unsupported_cookie_import_refused",
    "new_connection_requires_genuine_setup_proof",
    "routine_poll_reconnects_after_denied_setup",
    "baseline_armed_before_password_submission",
    "wrong_window_delivery_refused",
    "unrelated_source_delivery_refused",
    "stale_message_delivery_refused",
    "delivery_ack_contains_no_code",
    "fresh_password_identity_sms_login_completed",
    "saved_session_reused_for_second_cli_read",
    "cli_returns_only_approved_data_without_code",
    "consumed_window_rejects_replayed_delivery",
    "completed_window_no_longer_pending",
    "native_frame_process_exits_cleanly",
    "fixture_system_key_removed",
    "fixture_setup_policy_removed",
    "temporary_jobs_removed",
}
VERIFIED = {
    "actual_native_framing_used", "actual_desktop_connection_used", "actual_native_xpc_used",
    "production_composed_host_used", "system_key_used", "actual_distinct_uids",
    "password_sms_browser_login_verified",
}
UNVERIFIED = {
    "signed_chrome_parent_verified", "actual_chrome_extension_used", "google_messages_dom_used",
    "physical_sms_delivery_verified", "genuine_owner_approval_verified", "publisher_signed_peers",
    "consumer_deployment_verified",
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
        and all(value.get(key) is True for key in VERIFIED)
        and all(value.get(key) is False for key in UNVERIFIED)
        and type(value.get("checks")) is dict
        and set(value["checks"]) == CHECKS
        and all(result is True for result in value["checks"].values())
    )


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Protected browser composition evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated native framing, desktop XPC and isolated password/SMS composition")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
