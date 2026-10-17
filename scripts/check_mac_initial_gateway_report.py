"""Validate the shipping host's pre-enrollment XPC boundary, not approval."""
import json
from pathlib import Path
import sys


CHECKS = {
    "system_entrypoint_hosts_initial_owner_gateway", "no_initial_worker_or_key_created",
    "first_enrollment_root_peer_prepared", "first_enrollment_state_available_without_vault",
    "first_enrollment_health_available", "first_enrollment_without_approval_refused",
    "first_enrollment_invalid_os_proof_refused", "first_enrollment_invalid_proof_cannot_create_key",
    "first_enrollment_caller_configuration_refused", "unapproved_initial_owner_code_refused",
    "wrong_initial_owner_uid_refused", "wrong_initial_server_code_refused", "rejected_setup_never_creates_a_key",
    "entrypoint_fixture_setup_policy_removed", "entrypoint_system_jobs_removed",
}


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED" and value.get("platform") == "macos"
            and value.get("environment") == "controlled-demo" and value.get("production_ready") is False
            and type(value.get("private_signins")) is int and value["private_signins"] == 0
            and value.get("actual_system_entrypoint_used") is True and value.get("actual_native_xpc_used") is True
            and value.get("consumer_deployment_verified") is False and value.get("genuine_owner_approval_verified") is False
            and value.get("positive_enrollment_verified") is False and value.get("authorization_database_changed") is True
            and value.get("fixture_policy_removed") is True and value.get("publisher_signed_peers") is False
            and isinstance(value.get("checks"), dict) and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Initial owner gateway evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated system entrypoint initial owner gateway: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
