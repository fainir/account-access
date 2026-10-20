"""Ordinary disposable-Mac CI checks for the explicit component updater.

Compiles synthetic public-file/policy fixtures and checks the production entry
point's ordinary-user refusal. Never runs a root updater or installed service.
Only bounded logs and JSON reports are retained, not executable artifacts.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
COMPILE_SOURCES = (
    "macos/ComponentUpdate.swift", "macos/InstallerPayload.swift",
    "macos/ComponentUpdatePolicies.swift", "macos/ComponentUpdateIdentity.swift",
    "macos/InstallationRootBinding.swift",
)
REVALIDATION_SOURCE = "macos/InstallationRootRevalidation.swift"
ROOT_FIXTURE_SOURCE = "macos/InstallationRootBindingTests.swift"
SOURCE_PATHS = (
    *COMPILE_SOURCES, "macos/Tests/ComponentUpdateChecks.swift", "macos/Tests/ComponentUpdateIdentityChecks.swift",
    "macos/Tests/ComponentUpdatePolicyChecks.swift", REVALIDATION_SOURCE, ROOT_FIXTURE_SOURCE,
    "scripts/mac_component_update_native_probe.py",
    ".github/workflows/mac-worker.yml",
)
CORE_CHECKS = frozenset({
    "domain_durable_intent_and_local_barrier_order",
    "failed_domain_intent_has_no_lifecycle_effect",
    "domain_success_never_bypasses_all_process_checks",
    "domain_bootstrap_failure_requires_fresh_removal",
    "recreated_domain_is_removed_before_retry_or_rollback",
    "domain_event_failures_preserve_safe_local_state",
    "only_measured_domain_teardown_responses_retry",
    "unknown_domain_results_never_authorize_quiescence",
    "domain_teardown_retry_has_deadline_attempt_and_child_bounds",
    "initial_owner_disabled_refused", "fresh_attempt_rollback_owned", "failed_disable_intent_not_owned",
    "missing_service_response_exact", "generic_nonzero_not_absence", "foreign_service_not_absence",
    "extra_output_not_absence", "coherent_group_before_enable", "head_after_full_verification",
    "partial_swap_recovery_finishes_coherent_group", "post_swap_failure_rolls_back", "concurrent_replacement_preserved_disabled",
    "fixed_job_parser_accepts_only_closed_states", "foreign_or_malformed_job_print_rejected",
    "saved_process_identity_bound_to_birth_and_boot", "process_group_error_not_empty",
    "disabled_override_requires_closed_output", "interrupted_preparation_retained_next_publishes",
    "unknown_preparation_child_refused",
    "disk_capacity_checked_on_target_volume",
    "native_disabled_enabled_tokens_and_ambiguity_checked",
    "legacy_receipts_bound_to_original_bytes_owner_and_roots",
    "legacy_shape_digest_owner_status_and_record_set_fail_closed",
    "legacy_fixed_roots_require_bounded_nonboolean_integer_pairs",
    "legacy_bounded_json_and_plain_escaped_nested_duplicates_rejected",
    "device_only_migration_never_accepts_inode_or_root_set_changes",
    "supplement_binds_uuid_and_both_original_inodes_across_device_renumbering",
    "supplement_requires_supported_canonical_nonzero_volume_uuid",
    "supplement_owner_publisher_schema_plan_source_policy_provenance_fail_closed",
    "supplement_fixed_root_schema_uuid_and_inode_cannot_be_substituted",
    "supplement_rejects_any_changed_original_receipt_bytes_or_digest",
    "supplement_bounded_json_and_duplicate_members_rejected",
    "owned_directory_volume_uuid_abi_is_canonical_and_nonzero",
})
POLICY_CHECKS = frozenset({
    "exact_install_record_preserved_except_fingerprint", "exact_host_policy_preserved_except_bootstrap_hashes",
    "exact_owner_profile_preserved_except_broker_hashes", "owner_and_broker_uids_preserved",
    "invalid_records_paths_signatures_rejected", "foreign_root_or_broker_console_rejected",
    "invalid_fingerprint_rejected", "duplicate_plain_or_escaped_key_rejected",
})
PIN_SOURCE = 'enum ComponentUpdateCompiledPins { static let planSHA256 = "' + "0" * 64 + '" }\n'
MAIN_REFUSAL = {"schema": 1, "status": "REFUSED", "reason": "component_update_context_required"}
REVALIDATION_REFUSAL = {"schema": 1, "status": "REFUSED", "reason": "installation_revalidation_context_required",
                        "production_ready": False}
ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}
MAX_LOG = 128 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture_result(raw, *, kind):
    """A count or optimistic summary alone cannot satisfy native acceptance."""
    value = json.loads(raw)
    expected = CORE_CHECKS if kind == "core" else POLICY_CHECKS
    count_key, count = ("ordinary_fixture_assertions", 236) if kind == "core" else ("count", 41)
    if (not isinstance(value, dict)
            or set(value) != {"schema", "status", "checks", count_key, "installed_reads", "service_actions"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["status"] != "PASSED" or value["installed_reads"] is not False
            or value["service_actions"] is not False or type(value[count_key]) is not int or value[count_key] != count
            or not isinstance(value["checks"], dict) or set(value["checks"]) != expected
            or any(item is not True for item in value["checks"].values())):
        raise ValueError("native_fixture_contract_failed")
    return value


def main_result(returncode, raw):
    value = json.loads(raw)
    if returncode != 78 or value != MAIN_REFUSAL or type(value.get("schema")) is not int:
        raise ValueError("native_main_refusal_failed")
    return {"returncode": returncode, "result": value}


def revalidation_result(returncode, raw):
    value = json.loads(raw)
    if (returncode != 78 or value != REVALIDATION_REFUSAL or type(value.get("schema")) is not int
            or type(value.get("production_ready")) is not bool):
        raise ValueError("native_revalidation_refusal_failed")
    return {"returncode": returncode, "result": value}


def run(arguments, *, output, log_name, report, timeout):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=timeout, env=ENVIRONMENT, check=False)
    except subprocess.TimeoutExpired as error:
        partial = json.dumps({"returncode": None, "timed_out": True,
                              "stdout": (error.stdout or b"").decode("utf-8", errors="replace"),
                              "stderr": (error.stderr or b"").decode("utf-8", errors="replace")}, sort_keys=True).encode() + b"\n"
        if len(partial) <= MAX_LOG:
            (output / log_name).write_bytes(partial)
            report["logs"][log_name] = digest(partial)
        raise
    # Keep both streams exact inside one bounded, machine-readable log.
    raw = json.dumps({"returncode": result.returncode,
                      "stdout": result.stdout.decode("utf-8", errors="replace"),
                      "stderr": result.stderr.decode("utf-8", errors="replace")}, sort_keys=True).encode() + b"\n"
    if len(raw) > MAX_LOG:
        raise ValueError("native_probe_log_limit")
    (output / log_name).write_bytes(raw)
    report["logs"][log_name] = digest(raw)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "macOS"
            or re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", "")) is None
            or re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ATTEMPT", "")) is None):
        parser.error("Requires an ordinary GitHub runner in a disposable Mac CI VM")
    revision = os.environ.get("GITHUB_SHA", "")
    current = subprocess.check_output(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                      timeout=5, env=ENVIRONMENT, text=True).strip()
    if re.fullmatch(r"[a-f0-9]{40}", revision) is None or current != revision:
        parser.error("Requires the exact checked-out GitHub source commit")
    hashes = {}
    for name in SOURCE_PATHS:
        raw = (ROOT / name).read_bytes()
        committed = subprocess.check_output(["/usr/bin/git", "-C", str(ROOT), "show", revision + ":" + name],
                                            timeout=5, env=ENVIRONMENT)
        if raw != committed:
            parser.error("Compile inputs must match the exact CI commit")
        hashes[name] = digest(raw)
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("Requires a new evidence directory")
    output.mkdir(mode=0o700)
    report = {"schema": 1, "status": "FAILED", "environment": "ordinary-disposable-mac-ci",
              "source_revision": revision, "source_sha256": hashes,
              "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "checks": {"core_fixture": False, "policy_fixture": False, "ordinary_main_refusal": False,
                         "ordinary_revalidation_refusal": False},
              "logs": {}, "generated_pin_source": PIN_SOURCE, "generated_pin_source_sha256": digest(PIN_SOURCE.encode()),
              "installed_reads": False, "service_actions": False, "root_execution": False,
              "production_ready": False}
    try:
        with tempfile.TemporaryDirectory(prefix="account-access-component-native-") as folder:
            scratch = Path(folder)
            base = ["/usr/bin/xcrun", "swiftc", "-O", "-parse-as-library", "-warnings-as-errors",
                    "-module-cache-path", str(scratch / "module-cache"),
                    "-framework", "Foundation", "-framework", "Security", "-framework", "CryptoKit"]
            sources = [str(ROOT / name) for name in COMPILE_SOURCES]
            for kind, fixtures, compile_sources in (
                ("core", "macos/Tests/ComponentUpdateChecks.swift", sources),
                ("policy", "macos/Tests/ComponentUpdatePolicyChecks.swift", [str(ROOT / "macos/ComponentUpdatePolicies.swift")]),
            ):
                executable = scratch / (kind + "-checks")
                extra = [str(ROOT / "macos/Tests/ComponentUpdateIdentityChecks.swift"),
                         str(ROOT / ROOT_FIXTURE_SOURCE)] if kind == "core" else []
                compiled = run([*base, *compile_sources, *extra, str(ROOT / fixtures), "-o", str(executable)],
                               output=output, log_name="compile-" + kind + ".log", report=report, timeout=120)
                if compiled.returncode != 0:
                    raise ValueError("native_fixture_compile_failed")
                executed = run([str(executable)], output=output, log_name="run-" + kind + ".log", report=report, timeout=15)
                if executed.returncode != 0:
                    raise ValueError("native_fixture_execution_failed")
                value = fixture_result(executed.stdout, kind=kind)
                report[kind + "_fixture_json"] = value
                (output / (kind + "-fixture.json")).write_text(json.dumps(value, sort_keys=True) + "\n")
                report["checks"][kind + "_fixture"] = True
            pin = scratch / "ComponentPlanPin.swift"
            pin.write_text(PIN_SOURCE)
            executable = scratch / "ordinary-main"
            compiled = run([*base, "-D", "ACCOUNT_ACCESS_COMPONENT_UPDATE_MAIN", *sources, str(pin), "-o", str(executable)],
                           output=output, log_name="compile-main.log", report=report, timeout=120)
            if compiled.returncode != 0:
                raise ValueError("native_main_compile_failed")
            executed = run([str(executable)], output=output, log_name="run-main.log", report=report, timeout=10)
            report["ordinary_main"] = main_result(executed.returncode, executed.stdout)
            (output / "ordinary-main.json").write_text(json.dumps(report["ordinary_main"], sort_keys=True) + "\n")
            report["checks"]["ordinary_main_refusal"] = True
            executable = scratch / "ordinary-revalidation"
            compiled = run([*base, "-D", "ACCOUNT_ACCESS_INSTALLATION_ROOT_REVALIDATION_MAIN", *sources,
                            str(ROOT / REVALIDATION_SOURCE), str(pin), "-o", str(executable)],
                           output=output, log_name="compile-revalidation.log", report=report, timeout=120)
            if compiled.returncode != 0:
                raise ValueError("native_revalidation_compile_failed")
            executed = run([str(executable)], output=output, log_name="run-revalidation.log", report=report, timeout=10)
            report["ordinary_revalidation"] = revalidation_result(executed.returncode, executed.stdout)
            (output / "ordinary-revalidation.json").write_text(json.dumps(report["ordinary_revalidation"], sort_keys=True) + "\n")
            report["checks"]["ordinary_revalidation_refusal"] = True
        if hashes != {name: digest((ROOT / name).read_bytes()) for name in SOURCE_PATHS}:
            raise ValueError("native_probe_source_changed")
        report["status"] = "PASSED"
    except Exception:
        report["failure_reason"] = "native_component_probe_failed"
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
