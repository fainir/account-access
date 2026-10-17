"""Fail CI if the cross-user acceptance report is missing or incomplete."""

import json
from pathlib import Path
import sys


CHECKS = {
    "different_nonroot_uid", "approved_api_password_totp_reads", "ungranted_operation_denied",
    "vault_database_read_denied", "vault_database_write_denied", "owner_configuration_read_denied",
    "runtime_write_denied", "runtime_replacement_denied", "policy_write_denied",
    "worker_memory_read_denied", "worker_environment_read_denied", "worker_descriptors_denied",
    "worker_signal_denied", "private_owner_channel_denied", "agent_api_has_no_owner_routes",
    "agent_has_no_passwordless_sudo", "provider_confirmed_two_passwords_one_totp",
    "revoked_operation_denied", "worker_still_alive_after_denied_attacks", "graceful_worker_exit",
    "worker_output_has_no_credentials",
}


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED"
            and value.get("environment") == "controlled-demo" and value.get("platform") == "linux"
            and value.get("production_ready") is False and type(value.get("private_signins")) is int
            and value["private_signins"] == 0 and value.get("real_distinct_uids") is True
            and isinstance(value.get("checks"), dict) and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Worker acceptance report missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated cross-user acceptance report: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
