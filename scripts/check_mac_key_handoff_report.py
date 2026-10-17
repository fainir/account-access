"""Require real System-key/native-drop/production-reader handoff evidence."""
import json
from pathlib import Path
import sys


CHECKS = {"system_key_decrypted_by_python_reader", "owner_entropy_receipt_verified", "kernel_dedicated_identity_verified",
          "descriptor_allowlist_verified", "exact_envelope_and_eof_verified", "channel_description_redacted",
          "successful_channel_cannot_replay", "missing_reader_fails_without_signal_or_fallback",
          "failed_channel_cannot_replay", "cancelled_channel_refuses_owner_material"}


def validate(value):
    return (isinstance(value, dict) and value.get("status") == "PASSED" and value.get("platform") == "macos"
            and value.get("environment") == "controlled-demo" and value.get("production_ready") is False
            and type(value.get("private_signins")) is int and value["private_signins"] == 0
            and value.get("system_key_used") is True and value.get("production_python_reader_used") is True
            and value.get("consumer_deployment_verified") is False and value.get("production_supervision_verified") is False
            and value.get("actual_worker_store_handoff_verified") is False and value.get("fixture_key_removed") is True
            and isinstance(value.get("checks"), dict) and set(value["checks"]) == CHECKS
            and all(item is True for item in value["checks"].values()))


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 1 or not validate(json.loads(Path(args[0]).read_bytes())):
            raise ValueError()
    except (OSError, ValueError):
        print("System key handoff evidence missing, failed or incomplete", file=sys.stderr)
        return 1
    print("Validated System key handoff evidence: all required checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
