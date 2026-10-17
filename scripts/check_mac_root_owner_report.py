"""Require complete evidence for the disposable root owner-service journey."""

import json
from pathlib import Path
import sys


CHECKS = {"root_only_capability_handoff", "daemon_root_uid_verified", "privileged_root_peer_prepared",
          "root_backend_reached_isolated_worker", "unconfigured_os_setup_refused",
          "unauthorized_credential_write_refused", "unauthorized_grant_refused",
          "signed_owner_revocation_reached_worker", "stopped_service_channel_refused",
          "launchd_service_removed", "daemon_process_exited", "gateway_stop_keeps_worker_alive",
          "capability_absent_from_client_output", "worker_operates_after_owner_gateway_stop", "revocation_confirmed_by_agent"}
for prefix in ("wrong_client", "wrong_user", "wrong_server"):
    CHECKS.update(prefix + "_" + suffix for suffix in ("refused", "setup_refused", "credential_input_refused"))


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED"
            and value.get("environment") == "controlled-demo" and value.get("platform") == "macos"
            and value.get("production_ready") is False and type(value.get("private_signins")) is int
            and value["private_signins"] == 0 and value.get("root_service_installed") is True
            and value.get("consumer_deployment_verified") is False and value.get("real_owner_auth_approval_tested") is False
            and value.get("authorization_database_changed") is False and value.get("publisher_signed_peers") is False
            and isinstance(value.get("checks"), dict) and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Root owner-service evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated root owner-service evidence: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
