"""Validate generated-installation acceptance without claiming a consumer package."""

import json
from pathlib import Path
import sys


CHECKS = {
    "prepared_installation_is_idempotent",
    "dedicated_nonlogin_identity_created",
    "broker_and_owner_identities_differ",
    "broker_home_is_private",
    "new_store_and_stage_are_empty",
    "nonlogin_user_bootstrap_domain_ready",
    "public_profile_binds_owner_and_server",
    "published_policies_preserve_empty_fixed_enrollment",
    "generated_installation_starts_actual_system_entrypoint",
    "exact_prepared_job_is_persisted_and_registered",
    "fresh_install_waits_without_key_or_worker",
    "system_entrypoint_recreates_nonlogin_user_domain",
    "first_enrollment_root_peer_prepared",
    "first_enrollment_state_available_without_vault",
    "first_enrollment_health_available",
    "first_enrollment_without_approval_refused",
    "first_enrollment_invalid_os_proof_refused",
    "first_enrollment_invalid_proof_cannot_create_key",
    "first_enrollment_caller_configuration_refused",
    "desktop_profile_reads_protected_root_registration",
    "desktop_native_read_needs_no_os_approval",
    "desktop_native_invalid_os_proof_blocks_enrollment",
    "rejected_setup_keeps_new_key_absent",
    "fixture_setup_policy_removed",
    "created_service_identity_and_domain_removed",
    "temporary_system_jobs_removed",
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
        and value.get("actual_provisioner_used") is True
        and value.get("actual_system_entrypoint_used") is True
        and value.get("actual_native_xpc_used") is True
        and value.get("consumer_package_verified") is False
        and value.get("genuine_owner_approval_verified") is False
        and value.get("publisher_signed_peers") is False
        and value.get("fixture_identity_removed") is True
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
        print("System provisioning evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated generated system-installation evidence: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
