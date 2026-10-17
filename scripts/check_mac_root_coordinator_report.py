"""Accept only a real system-host crash/restart journey with fixture limits."""
import json
from pathlib import Path
import sys


CLIENT_CHECKS = {"coordinator_privileged_peer_prepared", "coordinator_encrypted_fixture_store_reached",
                 "coordinator_ungranted_setup_refused", "coordinator_unauthorized_write_refused"}
CHECKS = {phase + "_" + name for phase in ["initial", "recovered", "cold"] for name in CLIENT_CHECKS} | {
    "composed_system_host_started", "worker_kernel_identity_and_job_group_verified",
    "socket_activation_cannot_replay", "unapproved_client_code_refused", "wrong_owner_uid_refused", "wrong_server_signature_refused",
    "system_manager_restarted_crashed_parent", "old_worker_exited_without_pid_adoption",
    "replacement_worker_has_new_process_identity", "activated_socket_identity_survives_parent_crash",
    "crashed_parent_owner_channel_retired", "old_parent_exits_on_service_removal", "old_worker_exits_on_service_removal",
    "cold_service_reopens_system_key_store", "pause_stops_owned_worker_before_parent_crash",
    "pause_survives_parent_restart", "paused_parent_keeps_native_gateway_alive", "fixture_setup_policy_removed", "system_job_removed"}


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED" and value.get("platform") == "macos"
            and value.get("environment") == "controlled-demo" and value.get("production_ready") is False
            and type(value.get("private_signins")) is int and value["private_signins"] == 0
            and value.get("system_key_used") is True and value.get("actual_worker_used") is True
            and value.get("actual_root_composition_verified") is True
            and value.get("parent_daemon_recovery_verified") is True
            and value.get("machine_reboot_verified") is False and value.get("consumer_deployment_verified") is False
            and value.get("genuine_owner_approval_verified") is False and value.get("publisher_signed_peers") is False
            and value.get("authorization_database_changed") is True and value.get("fixture_policy_removed") is True
            and value.get("fixture_key_removed") is True
            and isinstance(value.get("checks"), dict) and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Root coordinator crash/restart evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated composed root coordinator crash/restart evidence: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
