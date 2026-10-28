"""Validate fixture-only system authorization policy provisioning evidence."""
import json
from pathlib import Path
import sys


CHECKS = {"system_daemon_context_verified", "namespace_initially_absent", "strict_rule_created",
          "strict_rule_readback_verified", "matching_rule_preserved", "root_shortcut_refused",
          "changed_policy_detected", "changed_policy_refused", "changed_policy_preserved",
          "changed_policy_granted_proof_refused", "strict_rule_restored", "fixture_rule_removed",
          "unprivileged_policy_install_refused", "registrar_identity_verified",
          "foreign_registrar_identifier_refused", "foreign_registrar_requirement_refused"}


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED" and value.get("platform") == "macos"
            and value.get("environment") == "controlled-demo" and value.get("production_ready") is False
            and type(value.get("private_signins")) is int and value["private_signins"] == 0
            and value.get("authorization_database_changed") is True and value.get("fixture_namespace") is True
            and value.get("fixture_right_removed") is True and value.get("synthetic_permissive_rule_used") is True
            and value.get("real_owner_auth_approval_tested") is False and value.get("consumer_deployment_verified") is False
            and isinstance(value.get("checks"), dict) and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("Owner policy evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated owner policy evidence: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
