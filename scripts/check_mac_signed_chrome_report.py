"""Require real stable-Chrome native/XPC evidence with narrowly bounded claims."""

import json
from pathlib import Path
import re
import sys

EXTENSION_ID = "nidjfmpcbbneapibefbhniaiijgigofo"
RESOURCES = {"manifest.json", "background.js", "reader.js", "popup.js", "popup.html", "popup.css"}
CHILD_CHECKS = {
    "fresh_profile_has_no_existing_user_data",
    "isolated_native_manifest_points_to_pinned_binary",
    "stable_chrome_matches_production_signature_requirement",
    "shell_parent_cannot_launch_native_bridge",
    "actual_packaged_extension_id_loaded",
    "extension_native_pending_reaches_enrolled_worker",
    "second_roundtrip_reuses_native_port",
    "unsupported_cookie_import_refused",
    "extension_reload_reconnects_same_enrolled_worker",
    "optional_host_and_cookie_permissions_stay_ungranted",
    "no_external_website_opened",
    "packaged_extension_resources_unchanged",
    "fresh_chrome_context_closed",
}
CHECKS = CHILD_CHECKS | {
    "temporary_chrome_profile_removed", "fixture_system_key_removed",
    "fixture_setup_policy_removed", "temporary_jobs_removed",
}
VERIFIED = {
    "actual_stable_chrome_used", "signed_chrome_parent_verified", "actual_chrome_extension_used",
    "actual_native_framing_used", "actual_desktop_connection_used", "actual_native_xpc_used",
    "production_composed_host_used", "system_key_used", "actual_distinct_uids",
    "native_pending_roundtrip_verified",
}
UNVERIFIED = {
    "production_entrypoint_run_verified", "production_manifest_google_messages_dom_used", "physical_sms_delivery_verified",
    "genuine_owner_approval_verified", "publisher_signed_peers", "consumer_deployment_verified",
    "production_manifest_password_sms_browser_login_verified", "extension_marketplace_install_verified",
}
SMS_CHILD_CHECKS = {
    "separate_empty_fixture_profile_used",
    "only_messages_host_permission_moved_from_optional_to_required",
    "all_five_packaged_script_html_css_resources_unchanged",
    "same_extension_key_and_id_loaded",
    "https_messages_document_fulfilled_in_memory",
    "production_reader_registered_and_injected_by_public_chrome_api",
    "only_messages_origin_granted_without_cookie_or_github_access",
    "single_fresh_synthetic_text_inserted_into_dom",
    "unchanged_background_polling_completed_fresh_password_sms_login",
    "second_cli_read_reused_saved_session",
    "cli_returns_only_reviewed_data_without_login_codes",
    "completed_window_no_longer_pending",
    "fixture_resources_unchanged_after_login",
    "fixture_chrome_context_and_cli_children_closed",
}
SMS_CHECKS = SMS_CHILD_CHECKS | {
    "provider_recorded_one_fresh_password_sms_and_identity_submission",
    "fixture_profile_and_pre_enrollment_manifest_removed",
}
SMS_VERIFIED = {
    "synthetic_manifest_pre_enrollment_used", "synthetic_google_messages_dom_used",
    "actual_content_script_and_background_polling_used", "password_sms_browser_login_verified",
}
SMS_UNVERIFIED = {
    "production_extension_manifest_used", "genuine_browser_permission_approval_verified",
    "physical_sms_delivery_verified", "production_entrypoint_run_verified",
}
CHILD_FIELDS = {"status", "chrome_version", "extension_id", "extension_resources_sha256", "checks", "sms_journey"}


def sms_journey(value, hashes, *, child):
    expected_checks = SMS_CHILD_CHECKS if child else SMS_CHECKS
    if (
        type(value) is not dict or set(value) != SMS_VERIFIED | SMS_UNVERIFIED | {
            "status", "checks", "script_resources_sha256", "synthetic_manifest_sha256",
        }
        or value.get("status") != "PASSED"
        or type(value.get("checks")) is not dict or set(value["checks"]) != expected_checks
        or not all(item is True for item in value["checks"].values())
        or not all(value.get(key) is True for key in SMS_VERIFIED)
        or not all(value.get(key) is False for key in SMS_UNVERIFIED)
        or value.get("script_resources_sha256") != {key: item for key, item in hashes.items() if key != "manifest.json"}
        or type(value.get("synthetic_manifest_sha256")) is not str
        or re.fullmatch(r"[a-f0-9]{64}", value["synthetic_manifest_sha256"]) is None
        or value["synthetic_manifest_sha256"] == hashes.get("manifest.json")
    ):
        return False
    return True


def metadata(value):
    hashes = value.get("extension_resources_sha256")
    return (
        value.get("status") == "PASSED"
        and type(value.get("chrome_version")) is str
        and re.fullmatch(r"(?:Headless)?Chrome/\d+\.\d+\.\d+\.\d+", value["chrome_version"]) is not None
        and value.get("extension_id") == EXTENSION_ID
        and type(hashes) is dict
        and set(hashes) == RESOURCES
        and all(type(item) is str and re.fullmatch(r"[a-f0-9]{64}", item) for item in hashes.values())
    )


def validate_child(value):
    return (
        type(value) is dict and set(value) == CHILD_FIELDS and metadata(value)
        and type(value.get("checks")) is dict and set(value["checks"]) == CHILD_CHECKS
        and all(item is True for item in value["checks"].values())
        and sms_journey(value.get("sms_journey"), value["extension_resources_sha256"], child=True)
    )


def validate(value):
    return (
        type(value) is dict
        and set(value) == CHILD_FIELDS | VERIFIED | UNVERIFIED | {
            "platform", "environment", "production_ready", "private_signins",
        }
        and metadata(value)
        and value.get("platform") == "macos"
        and value.get("environment") == "controlled-demo"
        and value.get("production_ready") is False
        and type(value.get("private_signins")) is int and value["private_signins"] == 0
        and all(value.get(key) is True for key in VERIFIED)
        and all(value.get(key) is False for key in UNVERIFIED)
        and type(value.get("checks")) is dict and set(value["checks"]) == CHECKS
        and all(item is True for item in value["checks"].values())
        and sms_journey(value.get("sms_journey"), value["extension_resources_sha256"], child=False)
    )


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Signed stable-Chrome native evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated signed-Chrome transport and synthetic manifest/DOM password-SMS runtime join")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
