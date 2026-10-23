"""Require first-store native orchestration without claiming genuine approval."""
import json
from pathlib import Path
import sys


CHECKS = {
    "unapproved_native_client_enrollment_refused", "approved_owner_client_enrollment_reaches_worker",
    "owner_client_enrollment_is_idempotent", "client_enrollment_reply_omits_capability",
    "different_client_cannot_replace_existing_enrollment", "owner_client_installation_receipt_accepted",
    "enrolled_client_survives_worker_reopening", "portable_launcher_discovers_empty_approved_account_set",
    "portable_launcher_omits_client_capability", "claude_launcher_discovers_empty_approved_account_set",
    "claude_launcher_omits_client_capability", "both_host_session_instructions_preserved",
    "owner_user_client_install_has_no_broker_store_access",
    "initialized_pause_keeps_owner_state_available", "initialized_resume_requires_owner_approval",
    "immediate_initialized_resume_preserves_worker",
    "fresh_start_waits_for_owner_without_worker", "fresh_start_does_not_create_system_key",
    "unenrolled_owner_state_available", "unenrolled_health_available", "ordinary_route_cannot_enroll",
    "unapproved_session_cannot_enroll", "real_setup_verifier_rejects_invalid_owner_proof",
    "failed_owner_proof_does_not_create_key", "pause_before_approval_does_not_create_key",
    "initial_setup_pause_survives_reopening", "paused_start_keeps_system_key_absent",
    "approved_native_enrollment_starts_asynchronously", "pause_during_initialization_stops_progress",
    "paused_enrollment_cannot_resume_without_approval", "approved_inflight_resume_does_not_duplicate_pipeline",
    "owner_approved_pipeline_reaches_actual_worker", "new_vault_key_confirmed_in_system_keychain",
    "enrolled_owner_state_reaches_published_store", "completed_enrollment_is_idempotent",
    "authorized_published_setup_reopens_without_new_approval", "missing_key_after_publication_requires_repair",
    "published_vault_key_never_recreated", "repair_state_keeps_native_owner_reads_available", "new_fixture_key_removed",
    "changed_publication_device_remains_refused_before_worker",
    "changed_publication_device_has_closed_diagnostic", "missing_key_has_closed_diagnostic_without_replacement",
    "persistent_volume_binding_reopens_simulated_device_change",
    "persistent_volume_reopen_preserves_original_registration",
    "different_persistent_volume_refused_before_worker",
}


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED" and value.get("platform") == "macos"
            and value.get("environment") == "controlled-demo" and value.get("production_ready") is False
            and type(value.get("private_signins")) is int and value["private_signins"] == 0
            and value.get("system_key_used") is True and value.get("actual_initial_setup_used") is True
            and value.get("consumer_deployment_verified") is False and value.get("genuine_owner_approval_verified") is False
            and value.get("synthetic_setup_approval_used") is True and value.get("controlled_initializer_gate") is True
            and value.get("authorization_database_changed") is False and value.get("fixture_key_removed") is True
            and value.get("publisher_signed_peers") is False and isinstance(value.get("checks"), dict)
            and set(value["checks"]) == CHECKS and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Initial setup evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated native first-store setup evidence: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
