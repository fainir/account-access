"""Require real native initializer/key-proof checks without claiming setup UX."""
import json
from pathlib import Path
import sys


CHECKS = {"wrong_bootstrap_code_refused", "staging_and_destination_initially_empty", "native_initializer_completed",
          "kernel_permanent_identity_parent_and_group_verified", "secret_bound_receipt_verified", "initializer_exit_confirmed",
          "destination_not_published_or_modified", "staged_files_private_and_owned_by_broker", "second_initialization_refused",
          "second_initialization_preserves_stage_files", "ordinary_worker_authenticates_initialized_store",
          "initialized_store_worker_stops_cleanly", "wrong_existing_key_never_reports_ready", "wrong_key_fixture_removed",
          "correct_key_reopens_stage_after_wrong_key_refusal", "destination_remains_unpublished"}


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED" and value.get("platform") == "macos"
            and value.get("environment") == "controlled-demo" and value.get("production_ready") is False
            and type(value.get("private_signins")) is int and value["private_signins"] == 0
            and value.get("system_key_used") is True and value.get("actual_initializer_used") is True
            and value.get("consumer_deployment_verified") is False and value.get("genuine_owner_approval_verified") is False
            and value.get("stage_published") is False and value.get("key_enrollment_authorization_verified") is False
            and value.get("fixture_key_removed") is True and value.get("publisher_signed_peers") is False
            and isinstance(value.get("checks"), dict) and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Staged initialization evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated native staged initialization evidence: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
