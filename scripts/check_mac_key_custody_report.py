"""Require real system-context persistence and unprivileged-read evidence."""

import json
from pathlib import Path
import sys


CHECKS = {"create_system_daemon_context_verified", "create_missing_key_read_did_not_enroll",
          "create_invalid_vault_identity_rejected", "create_key_description_redacted",
          "create_fresh_key_stored_and_canary_encrypted", "create_duplicate_enrollment_cannot_replace_key",
          "reopen_system_daemon_context_verified", "reopen_persisted_key_recovered_after_process_restart",
          "unprivileged_provider_refused", "unprivileged_direct_system_item_read_denied",
          "remove_system_daemon_context_verified", "remove_fixture_key_removed_and_not_recreated",
          "separate_daemon_processes_used", "unprivileged_probe_has_different_code_signature",
          "create_provider_disabled_core_dumps", "reopen_provider_disabled_core_dumps", "remove_provider_disabled_core_dumps",
          "create_other_vault_cannot_read_enrolled_key", "create_key_confirmed_in_system_keychain",
          "reopen_key_confirmed_in_system_keychain"}


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED"
            and value.get("platform") == "macos" and value.get("environment") == "controlled-demo"
            and value.get("production_ready") is False and type(value.get("private_signins")) is int
            and value["private_signins"] == 0 and value.get("personal_keychain_used") is False
            and value.get("consumer_deployment_verified") is False and value.get("fixture_namespace") is True
            and value.get("fixture_key_removed") is True and type(value.get("direct_read_status")) is int
            and value["direct_read_status"] in {-25293, -25308}
            and isinstance(value.get("checks"), dict) and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("System key-custody evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated system key-custody evidence: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
