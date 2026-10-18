"""Require publisher-authenticated production entrypoint evidence, never approval."""

import json
from pathlib import Path
import re
import sys

CHECKS = {
    "hosted_arm64_mac_guard_passed", "immutable_review_archive_verified",
    "archive_matches_exact_public_image", "application_wheel_and_runtime_match_source",
    "genuine_publisher_components_verified", "fresh_production_paths_only",
    "canonical_owner_bundle_protected", "public_app_alias_is_navigation_only", "shared_applications_parent_unchanged",
    "production_prepare_and_activate_used", "root_profile_pins_actual_publisher_hashes",
    "genuine_broker_registered_its_own_exact_rule", "production_owner_browser_setup_used",
    "signed_stable_chrome_used", "unchanged_packaged_extension_used",
    "shell_parent_rejected_by_production_entrypoint", "native_pending_reached_initial_enrollment",
    "second_pending_reached_initial_enrollment", "optional_permissions_stay_ungranted",
    "no_external_website_opened", "chrome_and_native_children_stopped",
    "empty_vault_and_no_enrollment_journal", "created_system_job_removed",
    "created_authorization_rule_removed", "created_service_identity_removed",
    "temporary_owner_identity_and_domain_removed", "fresh_public_image_removed",
}
TRUE_FLAGS = {"publisher_signed_peers", "genuine_dynamic_xpc_verified",
              "production_browser_entrypoint_verified", "production_desktop_profile_verified",
              "actual_stable_chrome_used", "actual_native_framing_used"}
FALSE_FLAGS = {"genuine_owner_approval_verified", "positive_enrollment_verified",
               "website_login_verified", "physical_sms_delivery_verified",
               "consumer_deployment_verified", "notarization_verified", "production_ready"}
FIELDS = {"schema", "status", "platform", "architecture", "environment", "source_revision",
          "controller_revision", "review_archive_sha256", "publisher_team", "chrome_version",
          "component_hashes", "extension_resources_sha256", "checks", "private_signins",
          "limits"} | TRUE_FLAGS | FALSE_FLAGS


def validate(value):
    hashes = value.get("component_hashes") if isinstance(value, dict) else None
    resources = value.get("extension_resources_sha256") if isinstance(value, dict) else None
    return (type(value) is dict and set(value) == FIELDS and value.get("schema") == 1
            and type(value["schema"]) is int and value.get("status") == "PASSED"
            and value.get("platform") == "macos" and value.get("architecture") == "arm64"
            and value.get("environment") == "disposable-hosted-ci-public-review"
            and value.get("publisher_team") == "WBULD6N4NQ"
            and all(type(value.get(key)) is str and re.fullmatch(r"[a-f0-9]{40}", value[key])
                    for key in ["source_revision", "controller_revision"])
            and type(value.get("review_archive_sha256")) is str
            and re.fullmatch(r"[a-f0-9]{64}", value["review_archive_sha256"])
            and type(value.get("chrome_version")) is str
            and re.fullmatch(r"(?:Headless)?Chrome/\d+\.\d+\.\d+\.\d+", value["chrome_version"])
            and type(hashes) is dict and set(hashes) == {"owner", "broker", "bootstrap"}
            and all(type(items) is list and 1 <= len(items) <= 8
                    and all(type(item) is str and re.fullmatch(r"[a-f0-9]{40}", item) for item in items)
                    for items in hashes.values())
            and type(resources) is dict and set(resources) == {
                "manifest.json", "background.js", "reader.js", "popup.js", "popup.html", "popup.css"}
            and all(type(item) is str and re.fullmatch(r"[a-f0-9]{64}", item) for item in resources.values())
            and type(value.get("checks")) is dict and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values())
            and all(value.get(key) is True for key in TRUE_FLAGS)
            and all(value.get(key) is False for key in FALSE_FLAGS)
            and type(value.get("private_signins")) is int and value["private_signins"] == 0
            and value.get("limits") == "Public signed transport before owner enrollment; no key, website login, personal account, phone, approval or consumer installation was validated.")


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError, TypeError):
        print("Publisher production transport evidence missing or incomplete", file=sys.stderr)
        return 1
    print("Verified genuine publisher production transport; owner enrollment remains unverified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
