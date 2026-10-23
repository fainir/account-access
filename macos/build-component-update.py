"""Build-only explicit worker-v2 component package; never install or run root.

The signed base76 GUI is retained. This builder compiles a new native ABI group
and one-shot updater from exact committed source, not a new GUI/full runtime.
"""

import argparse
import ast
import io
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile

from account_access.system_provision import signature
from macos import component_update as component

ROOT = Path(__file__).resolve().parent.parent
BASE = Path(component.SUPPORT)
MANIFEST = ROOT / "dist/release-080-review-build76/actual-package-manifest.json"
IDENTIFIER = "com.fainir.accountaccess.componentupdate76v2"
PACKAGE_NAME = "Account-Access-Worker-v2-Component-Update-local-unsigned.pkg"
REVALIDATION_IDENTIFIER = "com.fainir.accountaccess.installationrootrevalidation"
REVALIDATION_PACKAGE_NAME = "Account-Access-Installation-Root-Revalidation-local-unsigned.pkg"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}
REPOSITORY = "fainir/account-access"
WORKFLOWS = ("check.yml", "android.yml", "worker-boundary.yml", "mac-worker.yml")
REVIEW_WORKFLOW = "mac-component-update-review.yml"
REQUIRED_JOBS = {
    "check.yml": {"native-owner-gateway", "native-owner-ui", "test"},
    "android.yml": {"android"}, "worker-boundary.yml": {"cross-user"},
    "mac-worker.yml": {"mac-installer-context", "mac-cross-user"},
    REVIEW_WORKFLOW: {"ordinary-contracts"},
}
NATIVE_CI_SOURCES = (
    "macos/ComponentUpdate.swift", "macos/InstallerPayload.swift", "macos/ComponentUpdatePolicies.swift",
    "macos/ComponentUpdateIdentity.swift",
    "macos/InstallationRootBinding.swift", "macos/InstallationRootRevalidation.swift",
    "macos/InstallationRootBindingTests.swift",
    "macos/Tests/ComponentUpdateChecks.swift", "macos/Tests/ComponentUpdatePolicyChecks.swift",
    "macos/Tests/ComponentUpdateIdentityChecks.swift",
    "scripts/mac_component_update_native_probe.py", ".github/workflows/mac-worker.yml",
)
POLICY_CHECKS = frozenset({
    "exact_install_record_preserved_except_fingerprint", "exact_host_policy_preserved_except_bootstrap_hashes",
    "exact_owner_profile_preserved_except_broker_hashes", "owner_and_broker_uids_preserved",
    "invalid_records_paths_signatures_rejected", "foreign_root_or_broker_console_rejected",
    "invalid_fingerprint_rejected", "duplicate_plain_or_escaped_key_rejected",
})
# These are assertion groups in the actual native fixture, not caller flags.
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
    "root_revalidation_attests_each_current_lifecycle_independently",
    "root_revalidation_command_failure_never_reuses_prior_authority",
    "root_revalidation_malformed_or_forged_observation_refused",
    "root_revalidation_live_attestation_failure_propagates",
    "disabled_override_requires_closed_output",
    "interrupted_preparation_retained_next_publishes",
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
ZERO_PIN = ('enum ComponentUpdateCompiledPins { static let planSHA256 = "' + "0" * 64 + '" }\n')
MAX_ARCHIVE = 4 * 1024 * 1024
NATIVE_SOURCES = (
    "RootVaultKeyStore RootWorkerChannel WorkerBootstrap WorkerListenerBindings OwnerGateway OwnerGatewayHost "
    "OwnerAuthorizationPolicy RootActivatedListeners RootWorkerProcess RootWorkerSupervisor RootMessagesCollector "
    "RootBrokerHost RootStoreInitializer RootStoreVolumeBinding RootStoreVolumePublication RootStorePublication RootInitialEnrollment SystemBroker"
).split()


def command(arguments, *, env=None, timeout=120):
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                          check=True, timeout=timeout, env=env or ENV)


def source_paths():
    paths = [Path(__file__).resolve(), ROOT / "macos/component_update.py", ROOT / "macos/ComponentUpdate.swift",
            ROOT / "macos/ComponentUpdatePolicies.swift", ROOT / "account_access/system_provision.py",
            ROOT / "macos/InstallerPayload.swift", ROOT / "macos/build-broker.sh",
            *(ROOT / "macos" / (name + ".swift") for name in NATIVE_SOURCES),
            *(ROOT / name for name in ("macos/KeychainInteraction.c", "macos/KeychainInteraction.h",
                                      "macos/NativeBroker.c", "macos/NativeBroker.h")),
            *(ROOT / name for name in NATIVE_CI_SOURCES),
            *(ROOT / ".github/workflows" / name for name in WORKFLOWS),
            ROOT / ".github/workflows" / REVIEW_WORKFLOW,
            ROOT / "scripts/mac_launchctl_disable_probe.py",
            ROOT / "scripts/mac_component_update_installer_probe.py",
            *(ROOT / name for name in component.PYTHON_FILES)]
    return sorted(set(paths))


def github_bytes(endpoint, *, maximum=MAX_ARCHIVE):
    """Authenticated, fixed-host REST reads with bounded bytes/time; no artifact execution."""
    gh = shutil.which("gh")
    if gh is None or not 0 < maximum <= MAX_ARCHIVE:
        raise ValueError("component_authenticated_github_required")
    # Keep only the caller's existing authentication/config locations. Tokens
    # remain environment-only and are never included in evidence or commands.
    github_environment = {**ENV, **{name: os.environ[name] for name in (
        "HOME", "XDG_CONFIG_HOME", "GH_TOKEN", "GITHUB_TOKEN") if name in os.environ}}
    child = subprocess.Popen([gh, "api", "--hostname", "github.com", endpoint],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=github_environment)
    output, error = bytearray(), bytearray()
    deadline = time.monotonic() + 30
    try:
        with selectors.DefaultSelector() as ready:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                ready.register(stream, selectors.EVENT_READ)
            while ready.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("component_github_deadline")
                for key, _ in ready.select(min(remaining, 0.1)):
                    try:
                        block = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        ready.unregister(key.fileobj)
                        continue
                    target = output if key.fileobj is child.stdout else error
                    target.extend(block)
                    if len(output) > maximum or len(error) > 65536:
                        raise ValueError("component_github_output_bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0 or child.wait(timeout=remaining) != 0:
            raise ValueError("component_github_read_failed")
        return bytes(output)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        child.stdout.close()
        child.stderr.close()


def github_json(endpoint):
    return strict_json(github_bytes(endpoint))


def strict_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("component_ci_duplicate_json_key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def archive_members(raw):
    """Read bounded regular ZIP members in memory; never extract or execute them."""
    if not 0 < len(raw) <= MAX_ARCHIVE:
        raise ValueError("component_ci_archive_bound")
    result, total = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if not 1 <= len(entries) <= 16:
                raise ValueError("component_ci_archive_members")
            for item in entries:
                mode = item.external_attr >> 16
                if (not re.fullmatch(r"[a-z][a-z0-9-]{0,63}\.(?:json|log|py|txt)", item.filename)
                        or item.filename in result or item.is_dir() or item.flag_bits & 1
                        or (stat.S_IFMT(mode) not in (0, stat.S_IFREG))
                        or not 0 <= item.file_size <= 128 * 1024):
                    raise ValueError("component_ci_archive_members")
                total += item.file_size
                if total > 1024 * 1024:
                    raise ValueError("component_ci_archive_bound")
                data = archive.read(item)
                if len(data) != item.file_size:
                    raise ValueError("component_ci_archive_bound")
                result[item.filename] = data
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        raise ValueError("component_ci_archive_invalid") from None
    return result


def _true_checks(value, expected):
    return isinstance(value, dict) and set(value) == expected and all(item is True for item in value.values())


def publisher_requirement(identifier, team):
    if identifier not in {"com.fainir.accountaccess." + kind for kind in ("broker", "bootstrap", "componentupdate")} or re.fullmatch(r"[A-Z0-9]{10}", team) is None:
        raise ValueError("component_publisher_requirement_invalid")
    return ('anchor apple generic and identifier "' + identifier + '" '
            'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
            'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
            'and certificate leaf[subject.OU] = "' + team + '" '
            'and !(entitlement["com.apple.security.get-task-allow"] exists)')


def validate_native_report(files, *, source, sources, run_id, run_attempt=1):
    report = strict_json(files["report.json"])
    if (type(report.get("schema")) is not int or report["schema"] != 1 or report.get("status") != "PASSED"
            or report.get("environment") != "ordinary-disposable-mac-ci"
            or any(report.get(key) is not False for key in ("installed_reads", "service_actions", "root_execution", "production_ready"))
            or report.get("source_revision") != source
            or report.get("source_sha256") != {name: sources[name] for name in NATIVE_CI_SOURCES}
            or type(run_attempt) is not int or run_attempt not in {1, 2}
            or str(report.get("run_id")) != str(run_id) or str(report.get("run_attempt")) != str(run_attempt)
            or not _true_checks(report.get("checks"), {"core_fixture", "policy_fixture", "ordinary_main_refusal", "ordinary_revalidation_refusal"})
            or report.get("ordinary_main") != {"returncode": 78, "result": {
                "schema": 1, "status": "REFUSED", "reason": "component_update_context_required"}}
            or type(report["ordinary_main"]["result"]["schema"]) is not int
            or report.get("ordinary_revalidation") != {"returncode": 78, "result": {
                "schema": 1, "status": "REFUSED", "reason": "installation_revalidation_context_required", "production_ready": False}}
            or type(report["ordinary_revalidation"]["result"]["schema"]) is not int
            or report.get("generated_pin_source") != ZERO_PIN
            or report.get("generated_pin_source_sha256") != component.digest(ZERO_PIN.encode())):
        raise ValueError("component_native_ci_binding_changed")
    core, policy = report.get("core_fixture_json", {}), report.get("policy_fixture_json", {})
    if (set(core) != {"schema", "status", "checks", "ordinary_fixture_assertions", "installed_reads", "service_actions"}
            or type(core.get("schema")) is not int or core["schema"] != 1 or core.get("status") != "PASSED"
            or type(core.get("ordinary_fixture_assertions")) is not int or core["ordinary_fixture_assertions"] != 331
            or not _true_checks(core.get("checks"), CORE_CHECKS)
            or set(policy) != {"schema", "status", "checks", "count", "installed_reads", "service_actions"}
            or type(policy.get("schema")) is not int or policy["schema"] != 1 or policy.get("status") != "PASSED"
            or type(policy.get("count")) is not int or policy["count"] != 41 or not _true_checks(policy.get("checks"), POLICY_CHECKS)
            or any(item.get("installed_reads") is not False or item.get("service_actions") is not False
                   for item in (core, policy))):
        raise ValueError("component_native_ci_assertions_changed")
    logs = report.get("logs", {})
    required = {f"{action}-{kind}.log" for action in ("compile", "run") for kind in ("core", "policy", "main", "revalidation")}
    if (not isinstance(logs, dict) or set(logs) != required
            or any(re.fullmatch(r"(?:compile|run)-(?:core|policy|main|revalidation)\.log", name) is None
                   or name not in files or component.digest(files[name]) != checksum
                   for name, checksum in logs.items())):
        raise ValueError("component_native_ci_logs_changed")
    allowed = {"report.json", *logs}
    for name, value in (("core-fixture.json", core), ("policy-fixture.json", policy),
                        ("ordinary-main.json", report["ordinary_main"]), ("ordinary-revalidation.json", report["ordinary_revalidation"])):
        if name not in files or strict_json(files[name]) != value:
            raise ValueError("component_native_ci_raw_result_changed")
        allowed.add(name)
    for name in required:
        log = strict_json(files[name])
        expected_code = 78 if name in {"run-main.log", "run-revalidation.log"} else 0
        if (set(log) != {"returncode", "stdout", "stderr"} or type(log["returncode"]) is not int
                or log["returncode"] != expected_code or not isinstance(log["stdout"], str)
                or not isinstance(log["stderr"], str)):
            raise ValueError("component_native_ci_log_outcome_changed")
        if name.startswith("run-"):
            expected_value = {"run-core.log": core, "run-policy.log": policy,
                              "run-main.log": report["ordinary_main"]["result"],
                              "run-revalidation.log": report["ordinary_revalidation"]["result"]}[name]
            if strict_json(log["stdout"]) != expected_value:
                raise ValueError("component_native_ci_log_outcome_changed")
    if set(files) != allowed:
        raise ValueError("component_native_ci_members_changed")
    return report


def _probe_command(value, *, code=None, nonzero=False):
    return (isinstance(value, dict) and type(value.get("returncode")) is int
            and (code is None or value["returncode"] == code)
            and (not nonzero or value["returncode"] != 0)
            and value.get("client_reaped") is True
            and all(value.get(key) is False for key in ("timed_out", "output_limited", "invocation_failed")))


def _override_evidence(command_result, label, expected):
    """Bind the retained public fixture row to its measured closed state."""
    value = command_result.get("override_evidence")
    if (not isinstance(value, dict) or set(value) != {"target_line", "token", "normalized"}
            or value.get("normalized") != expected
            or type(command_result.get("output_bytes")) is not int
            or not 0 < command_result["output_bytes"] <= 128 * 1024
            or not isinstance(command_result.get("output_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}", command_result["output_sha256"]) is None):
        return False
    if expected == "absent":
        return value["target_line"] is None and value["token"] is None
    line = value["target_line"]
    if not isinstance(line, str) or len(line) > 512:
        return False
    row = re.fullmatch(r'[ \t]*"' + re.escape(label) + r'"[ \t]+=>[ \t]+(disabled|enabled|true|false)[ \t]*', line)
    return (row is not None and value["token"] == row[1]
            and {"disabled": "true", "true": "true", "enabled": "false", "false": "false"}[row[1]] == expected
            and len(line.encode("utf-8")) <= command_result["output_bytes"])


def validate_disable_report(files, *, source, sources, run_id, run_attempt=1):
    allowed = {"report.json", "installer-context.json", "root-probe.py", "installer-stdout.txt", "installer-stderr.txt"}
    if not {"report.json", "installer-context.json", "root-probe.py"} <= set(files) or not set(files) <= allowed:
        raise ValueError("component_disable_ci_members_changed")
    report = strict_json(files["report.json"])
    binding = report.get("source_binding", {})
    scope = "unique_system_job_registration_exclusion_while_disabled_no_reboot"
    if (type(report.get("schema")) is not int or report["schema"] != 1 or report.get("status") != "PASSED"
            or report.get("environment") != "disposable-mac-ci-installer" or report.get("status_scope") != scope
            or type(run_attempt) is not int or run_attempt not in {1, 2}
            or str(report.get("run_id")) != str(run_id) or str(report.get("run_attempt")) != str(run_attempt)
            or report.get("actual_installer_used") is not True or type(report.get("installer_exit_code")) is not int
            or report["installer_exit_code"] != 0
            or report.get("installer_timed_out", False) is not False
            or binding != {"git_head": source, "github_sha": source,
                "probe_script_sha256": sources["scripts/mac_launchctl_disable_probe.py"],
                "workflow_sha256": sources[".github/workflows/mac-worker.yml"],
                "root_probe_sha256": component.digest(files["root-probe.py"])}):
        raise ValueError("component_disable_ci_binding_changed")
    probe = report.get("probe", {})
    if (probe != strict_json(files["installer-context.json"]) or type(probe.get("schema")) is not int or probe["schema"] != 1
            or probe.get("status") != "PASSED" or probe.get("status_scope") != scope
            or probe.get("root_probe_sha256") != binding["root_probe_sha256"]
            or probe.get("actual_installer_script") is not True
            or probe.get("failure_stage") is not None or probe.get("measurement_failure_stage") is not None
            or any(value.get(key) is not False for value in (probe, report)
                   for key in ("private_data_accessed", "production_namespace_accessed", "production_ready", "reboot_tested"))):
        raise ValueError("component_disable_ci_scope_changed")
    truths = ("preflight_definitively_absent", "initial_enabled_marker_created", "after_bootout_definitively_absent",
              "disabled_definitively_absent", "disabled_marker_absent_for_2000ms", "already_absent_state_confirmed",
              "reenabled_marker_created", "fixture_removed", "service_removed", "effective_enabled_restored",
              "unique_false_override_retained_until_vm_teardown")
    if (any(probe.get(key) is not True for key in truths)
            or probe.get("zero_override_state_claimed") is not False
            or probe.get("initial_disabled_override") != "absent" or probe.get("disabled_override") != "true"
            or probe.get("disabled_override_after_attempt") != "true" or probe.get("enabled_override") != "false"
            or probe.get("service_health_verified") is not False):
        raise ValueError("component_disable_ci_observation_changed")
    zero = ("initial_disabled_query", "initial_bootstrap", "disable", "disabled_query", "bootout",
            "disabled_query_after_attempt", "enable", "enabled_query", "reenabled_bootstrap",
            "cleanup_enable", "cleanup_disabled_query")
    absent = ("preflight_lookup", "after_bootout_lookup", "disabled_lookup", "lookup_after_absent_bootout", "cleanup_lookup")
    if (any(not _probe_command(probe.get(key), code=0) for key in zero)
            or any(not _probe_command(probe.get(key), code=113) for key in absent)
            or not _probe_command(probe.get("disabled_bootstrap"), nonzero=True)
            or any(not _probe_command(probe.get(key)) for key in ("bootout_already_absent", "cleanup_bootout"))):
        raise ValueError("component_disable_ci_command_changed")
    # Bind the generated root script to the frozen template without importing
    # or executing either the archive's Python source or its root entry point.
    template_path = ROOT / "scripts/mac_launchctl_disable_probe.py"
    template_raw = template_path.read_bytes()
    if component.digest(template_raw) != sources["scripts/mac_launchctl_disable_probe.py"]:
        raise ValueError("component_disable_ci_template_changed")
    template = next((item.value.value for item in ast.parse(template_raw).body
                     if isinstance(item, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "ROOT_PROBE"
                                                            for target in item.targets)
                     and isinstance(item.value, ast.Constant) and isinstance(item.value.value, str)), None)
    generated = files["root-probe.py"].decode("utf-8")
    token = next((item.value.value for item in ast.parse(generated).body
                  if isinstance(item, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "TOKEN"
                                                         for target in item.targets)
                  and isinstance(item.value, ast.Constant) and isinstance(item.value.value, str)), None)
    if template is None or not isinstance(token, str) or re.fullmatch(r"[a-f0-9]{32}", token) is None or template.replace("__TOKEN__", token) != generated:
        raise ValueError("component_disable_ci_generated_source_changed")
    label = "local.account-access-disable-probe." + token
    for key, expected in (("initial_disabled_query", "absent"), ("disabled_query", "true"),
                          ("disabled_query_after_attempt", "true"), ("enabled_query", "false"),
                          ("cleanup_disabled_query", "false")):
        if not _override_evidence(probe[key], label, expected):
            raise ValueError("component_disable_ci_override_evidence_changed")
    absent_bytes = ('Bad request.\nCould not find service "local.account-access-disable-probe.' + token
                    + '" in domain for system\n').encode()
    if any(probe[key].get("output_sha256") != component.digest(absent_bytes)
           or probe[key].get("output_bytes") != len(absent_bytes) for key in absent):
        raise ValueError("component_disable_ci_absence_evidence_changed")
    return report


HOSTED_UNACQUIRED = "The job was not acquired by Runner of type hosted even after multiple attempts"
MAC_CAPACITY = "Due to capacity constraints, jobs targeting macOS arm64 runners may experience longer queue times."


def _retry_jobs(run, source, archives):
    """One failed-jobs-only retry of a proven unacquired Mac runner; never rerun code failures."""
    if (run.get("path") not in {".github/workflows/check.yml", ".github/workflows/mac-worker.yml"}
            or type(run.get("workflow_id")) is not int or run["workflow_id"] <= 0):
        raise ValueError("component_ci_retry_workflow_not_eligible")
    responses = []

    def read(suffix, name):
        endpoint = f"repos/{REPOSITORY}/" + suffix
        raw = github_bytes(endpoint)
        value = strict_json(raw)
        filename = f"infra-{run['id']}-{name}.json"
        archives[filename] = raw
        responses.append({"file": filename, "endpoint": endpoint, "sha256": component.digest(raw)})
        return value

    def jobs(attempt):
        value = read(f"actions/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100", f"jobs-{attempt}")
        rows = value.get("jobs", [])
        if (not isinstance(rows, list) or any(not isinstance(item, dict) for item in rows)
                or type(value.get("total_count")) is not int or value["total_count"] != len(rows)
                or not 1 <= len(rows) <= 16 or len({item.get("name") for item in rows}) != len(rows)
                or len({item.get("id") for item in rows}) != len(rows)
                or any(type(item.get("id")) is not int or item["id"] <= 0
                       or type(item.get("run_id")) is not int or item["run_id"] != run["id"]
                       or item.get("run_url") != f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run['id']}"
                       or item.get("head_sha") != source or item.get("status") != "completed" for item in rows)):
            raise ValueError("component_ci_retry_jobs_incomplete")
        return rows

    def unassigned(job):
        return (job.get("labels") == ["macos-15"] and job.get("steps") == []
                and all(type(job.get(key)) is int and job[key] == 0 for key in ("runner_id", "runner_group_id"))
                and all(job.get(key) == "" for key in ("runner_name", "runner_group_name")))

    def succeeded(job):
        steps = job.get("steps")
        return (job.get("conclusion") == "success" and type(job.get("runner_id")) is int and job["runner_id"] > 0
                and isinstance(job.get("runner_name"), str) and bool(job["runner_name"])
                and isinstance(steps, list) and 1 <= len(steps) <= 64
                and all(isinstance(step, dict) and step.get("status") == "completed" and step.get("conclusion") in {"success", "skipped"}
                        for step in steps))

    def checked(job, cancelled):
        endpoint = f"check-runs/{job['id']}"
        url = f"https://api.github.com/repos/{REPOSITORY}/" + endpoint
        if job.get("check_run_url") != url:
            raise ValueError("component_ci_retry_check_identity_changed")
        check = read(endpoint, f"check-{job['id']}")
        output = check.get("output", {})
        annotations = read(endpoint + "/annotations?per_page=100", f"annotations-{job['id']}")
        if (type(check.get("id")) is not int or check["id"] != job["id"]
                or check.get("name") != job["name"] or check.get("head_sha") != source
                or check.get("app", {}).get("slug") != "github-actions" or check.get("status") != "completed"
                or check.get("conclusion") != job["conclusion"] or output.get("annotations_url") != url + "/annotations"
                or type(output.get("annotations_count")) is not int or not isinstance(annotations, list)
                or output["annotations_count"] != len(annotations) or len(annotations) > 9):
            raise ValueError("component_ci_retry_check_identity_changed")
        if not cancelled:
            if annotations:
                raise ValueError("component_ci_retry_dependency_annotation_changed")
            return
        messages = []
        for annotation in annotations:
            if (not isinstance(annotation, dict) or set(annotation) != {"annotation_level", "blob_href", "end_column", "end_line", "message", "path",
                                    "raw_details", "start_column", "start_line", "title"}
                    or annotation["path"] != ".github" or annotation["raw_details"] != "" or annotation["title"] != ""
                    or annotation["start_column"] is not None or annotation["end_column"] is not None
                    or type(annotation["start_line"]) is not int or annotation["start_line"] != 1
                    or type(annotation["end_line"]) is not int or annotation["end_line"] != 1
                    or annotation["blob_href"] != f"https://github.com/{REPOSITORY}/blob/{source}/.github"):
                raise ValueError("component_ci_retry_annotation_changed")
            messages.append((annotation["annotation_level"], annotation["message"]))
        if (messages.count(("failure", HOSTED_UNACQUIRED)) != 1
                or not 1 <= messages.count(("notice", MAC_CAPACITY)) <= 8
                or any(item not in {("failure", HOSTED_UNACQUIRED), ("notice", MAC_CAPACITY)} for item in messages)):
            raise ValueError("component_ci_retry_not_hosted_capacity")

    first = read(f"actions/runs/{run['id']}/attempts/1", "run-1")
    if (first.get("run_attempt") != 1 or type(first.get("run_attempt")) is not int
            or first.get("status") != "completed" or first.get("conclusion") not in {"cancelled", "failure"}
            or any(first.get(key) != run.get(key) for key in ("id", "head_sha", "path", "event", "workflow_id"))
            or type(first.get("workflow_id")) is not int or first["workflow_id"] <= 0
            or any(first.get(key, {}).get("full_name") != REPOSITORY for key in ("repository", "head_repository"))):
        raise ValueError("component_ci_retry_original_not_eligible")
    second_run = read(f"actions/runs/{run['id']}/attempts/2", "run-2")
    if (second_run.get("run_attempt") != 2 or type(second_run.get("run_attempt")) is not int
            or second_run.get("status") != "completed" or second_run.get("conclusion") != "success"
            or any(second_run.get(key) != run.get(key) for key in ("id", "head_sha", "path", "event", "workflow_id"))
            or any(second_run.get(key, {}).get("full_name") != REPOSITORY for key in ("repository", "head_repository"))):
        raise ValueError("component_ci_retry_second_attempt_changed")
    original, second = jobs(1), jobs(2)
    required = REQUIRED_JOBS[Path(run["path"]).name]
    if {job["name"] for job in original} != required or any(job.get("run_attempt") != 1
            or type(job.get("run_attempt")) is not int for job in original):
        raise ValueError("component_ci_retry_original_jobs_changed")
    cancelled = {job["name"] for job in original if job.get("conclusion") == "cancelled"}
    if not cancelled:
        raise ValueError("component_ci_retry_no_capacity_failure")
    eligible, qualified = set(cancelled), {}
    for job in original:
        if job["name"] in cancelled:
            if not unassigned(job):
                raise ValueError("component_ci_retry_job_was_acquired")
            checked(job, True)
        elif job.get("conclusion") == "skipped":
            if (run["path"] != ".github/workflows/mac-worker.yml" or job["name"] != "mac-cross-user"
                    or "mac-installer-context" not in cancelled or not unassigned(job)):
                raise ValueError("component_ci_retry_unrelated_skip")
            checked(job, False)
            eligible.add(job["name"])
        elif succeeded(job):
            qualified[job["name"]] = job
        else:
            raise ValueError("component_ci_retry_code_or_unknown_failure")
    rerun = set()
    for job in second:
        previous = next((item for item in original if item["name"] == job["name"]), None)
        if job["name"] in qualified and job == qualified[job["name"]]:
            continue  # The API may include the identical retained attempt-1 record; it did not rerun.
        if (previous is None or job["name"] not in eligible or type(job.get("run_attempt")) is not int
                or job["run_attempt"] != 2 or job["labels"] != ["macos-15"]
                or job["id"] in {item["id"] for item in original} or not succeeded(job)):
            raise ValueError("component_ci_retry_not_failed_jobs_only")
        qualified[job["name"]] = job
        rerun.add(job["name"])
    if rerun != eligible or set(qualified) != required:
        raise ValueError("component_ci_retry_required_jobs_missing")
    return original, list(qualified.values()), {"run_id": run["id"], "kind": "hosted_macos_capacity_retry",
        "original_attempt": first, "second_attempt": second_run, "first_attempt_jobs": original, "second_attempt_jobs": second,
        "responses": responses, "retry_attempt": 2, "first_attempt_passed": False}


def ci_gate(source, sources):
    """Authenticate first passes or one fully recorded unacquired-runner retry."""
    user = github_json("user")
    if type(user.get("id")) is not int or user["id"] <= 0:
        raise ValueError("component_authenticated_github_required")
    page = github_json(f"repos/{REPOSITORY}/actions/runs?head_sha={source}&per_page=100")
    runs = page.get("workflow_runs", [])
    if type(page.get("total_count")) is not int or page["total_count"] != len(runs) or len(runs) > 100:
        raise ValueError("component_ci_runs_incomplete")
    expected = {(f".github/workflows/{name}", event) for name in WORKFLOWS for event in ("push", "pull_request")}
    expected.add((f".github/workflows/{REVIEW_WORKFLOW}", "push"))
    selected = {}
    for run in runs:
        key = (run.get("path"), run.get("event"))
        if key not in expected:
            continue
        if (key in selected or run.get("head_sha") != source or type(run.get("run_attempt")) is not int or run["run_attempt"] not in {1, 2}
                or run.get("status") != "completed" or run.get("conclusion") != "success"
                or run.get("repository", {}).get("full_name") != REPOSITORY
                or run.get("head_repository", {}).get("full_name") != REPOSITORY
                or type(run.get("id")) is not int or run["id"] <= 0):
            raise ValueError("component_ci_first_attempt_not_passed")
        selected[key] = run
    if set(selected) != expected:
        raise ValueError("component_ci_required_matrix_missing")
    jobs_by_run, qualified_by_run, originals, retries, archives = {}, {}, {}, [], {}
    for (path, event), run in selected.items():
        if run["run_attempt"] == 2:
            jobs, qualified, retry = _retry_jobs(run, source, archives)
            jobs_by_run[run["id"]] = jobs
            qualified_by_run[run["id"]] = qualified
            originals[run["id"]] = retry["original_attempt"]
            retries.append(retry)
            continue
        jobs_page = github_json(f"repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/1/jobs?per_page=100")
        jobs = jobs_page.get("jobs", [])
        # These two fixed jobs only apply to workflow_dispatch. On this
        # required push run their measured skipped state is intentional;
        # applicable jobs, including ordinary-contracts, must still pass.
        inapplicable = {"download-public-inputs", "actual-installer-review"} if (
            path == f".github/workflows/{REVIEW_WORKFLOW}" and event == "push") else set()
        job_names = {job.get("name") for job in jobs}
        if (type(jobs_page.get("total_count")) is not int or jobs_page["total_count"] != len(jobs)
                or not 1 <= len(jobs) <= 16
                or len(job_names) != len(jobs)
                or not REQUIRED_JOBS[Path(path).name] <= job_names
                or (inapplicable and job_names != REQUIRED_JOBS[Path(path).name] | inapplicable)
                or any(type(job.get("run_attempt")) is not int or job["run_attempt"] != 1
                       or job.get("head_sha") != source or job.get("status") != "completed"
                       or job.get("conclusion") != ("skipped" if job.get("name") in inapplicable else "success")
                       for job in jobs)):
            raise ValueError("component_ci_required_jobs_not_passed")
        jobs_by_run[run["id"]] = [{"id": job["id"], "name": job["name"], "conclusion": job["conclusion"],
                                 "applicable": job["name"] not in inapplicable} for job in jobs]
        qualified_by_run[run["id"]] = jobs
    run_id = selected[(".github/workflows/mac-worker.yml", "push")]["id"]
    context = next(job for job in qualified_by_run[run_id] if job["name"] == "mac-installer-context")
    page = github_json(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100")
    artifacts = page.get("artifacts", [])
    if type(page.get("total_count")) is not int or page["total_count"] != len(artifacts) or len(artifacts) > 100:
        raise ValueError("component_ci_artifacts_incomplete")
    proofs = []
    for name, validator in (("mac-component-update-native", validate_native_report),
                            ("mac-launchctl-disable-installer-context", validate_disable_report)):
        found = [item for item in artifacts if item.get("name") == name]
        if len(found) != 1:
            raise ValueError("component_ci_artifact_missing_or_ambiguous")
        item = found[0]
        if (type(item.get("id")) is not int or item["id"] <= 0 or item.get("expired") is not False
                or type(item.get("size_in_bytes")) is not int or not 0 < item["size_in_bytes"] <= MAX_ARCHIVE
                or re.fullmatch(r"sha256:[a-f0-9]{64}", item.get("digest", "")) is None
                or item.get("workflow_run", {}).get("id") != run_id
                or item.get("workflow_run", {}).get("head_sha") != source):
            raise ValueError("component_ci_artifact_provenance_changed")
        raw = github_bytes(f"repos/{REPOSITORY}/actions/artifacts/{item['id']}/zip")
        if "sha256:" + component.digest(raw) != item["digest"]:
            raise ValueError("component_ci_artifact_server_digest_changed")
        files = archive_members(raw)
        validator(files, source=source, sources=sources, run_id=run_id, run_attempt=context["run_attempt"])
        archives[name + ".zip"] = raw
        proofs.append({"name": name, "id": item["id"], "run_id": run_id, "job_id": context["id"], "run_attempt": context["run_attempt"],
                       "sha256": component.digest(raw), "members": {key: component.digest(value) for key, value in files.items()}})
    return {"source_revision": source, "authenticated_api": True,
            "first_attempt_runs": [{"id": run["id"], "path": key[0], "event": key[1], "jobs": jobs_by_run[run["id"]],
                **({"run_attempt": 1, "conclusion": originals[run["id"]]["conclusion"]} if run["id"] in originals else {})}
                                   for key, run in sorted(selected.items())],
            "artifacts": proofs, "infrastructure_retries": retries,
            "qualification": "recorded_infrastructure_retry_passed" if retries else "first_attempts_passed",
            "qualified_runs": [{"id": run["id"], "path": key[0], "event": key[1], "run_attempt": run["run_attempt"],
                "conclusion": "success",
                "jobs": qualified_by_run[run["id"]]} for key, run in sorted(selected.items())]}, archives


def freeze(source):
    if not re.fullmatch(r"[a-f0-9]{40}", source):
        raise ValueError("exact_component_source_commit_required")
    if command(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.decode().strip() != source:
        raise ValueError("component_source_is_not_head")
    result = {}
    for path in source_paths():
        relative = str(path.relative_to(ROOT))
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 2 * 1024 * 1024:
            raise ValueError("component_source_object_changed")
        raw = command(["/usr/bin/git", "-C", str(ROOT), "show", source + ":" + relative]).stdout
        if raw != path.read_bytes():
            raise ValueError("component_source_changed")
        result[relative] = component.digest(raw)
    return result


def fingerprint(signatures):
    value = {"signatures": signatures, "layout": {
        "runtime": str(BASE / "runtime"), "browsers": str(BASE / "browsers"),
        "owner_app": str(BASE / "owner.app"), "broker": str(BASE / "bin/AccountAccess-broker"),
        "bootstrap": str(BASE / "bin/AccountAccess-bootstrap"),
        "broker_name": "_accountaccess", "label": "com.fainir.accountaccess.broker",
    }}
    return component.digest(json.dumps(value, sort_keys=True).encode())


def designated(path):
    architectures = command(["/usr/bin/lipo", "-archs", str(path)]).stdout.decode().split()
    if set(architectures) != {"arm64", "x86_64"} or len(architectures) != 2:
        raise ValueError("component_native_architectures_changed")
    values = []
    for architecture in architectures:
        result = command(["/usr/bin/codesign", "-d", "-r-", "--arch", architecture, str(path)])
        lines = (result.stdout + result.stderr).decode().splitlines()
        found = [line.removeprefix("designated => ") for line in lines if line.startswith("designated => ")]
        if len(found) != 1:
            raise ValueError("component_designated_requirement_unavailable")
        values.extend(found)
    if len(set(values)) != 1 or not values[0].startswith('identifier "com.fainir.accountaccess.'):
        raise ValueError("component_designated_requirement_unavailable")
    return values[0]


def public_base(path, expected):
    # Only named public code/metadata, never private installation records.
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o7022:
        raise ValueError("component_base_public_file_unsafe")
    data = path.read_bytes()
    if component.digest(data) != expected:
        raise ValueError("component_base_public_pin_changed")
    return data


def plan_inputs(source, sources, native):
    raw = MANIFEST.read_bytes()
    if component.digest(raw) != component.BASE_MANIFEST_SHA256:
        raise ValueError("component_base_manifest_changed")
    base = json.loads(raw)["roots"][component.SUPPORT]
    record = public_base(BASE / component.RECORD, component.BASE_RECORD_SHA256)
    runtime = public_base(BASE / "runtime-image.json", component.BASE_RUNTIME_IMAGE_SHA256)
    identity_raw = public_base(BASE / "package-identity.json", component.BASE_IDENTITY_SHA256)
    old_identity = json.loads(identity_raw)
    signatures = {name: signature(native / ("AccountAccess-" + name), "com.fainir.accountaccess." + name)
                  for name in ("broker", "bootstrap")}
    for kind, identity in signatures.items():
        command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
                 "-R=" + publisher_requirement(identity["identifier"], identity["team"]),
                 str(native / ("AccountAccess-" + kind))])
    requirements = {}
    for kind in ("broker", "bootstrap"):
        original = BASE / "bin" / ("AccountAccess-" + kind)
        public_base(original, base["bin/AccountAccess-" + kind]["sha256"])
        old, new = designated(original), designated(native / ("AccountAccess-" + kind))
        if old != new:
            raise ValueError("component_authorization_designated_requirement_changed")
        requirements[kind] = new
    replacements = {"bin/AccountAccess-" + name: (native / ("AccountAccess-" + name)).read_bytes()
                    for name in ("broker", "bootstrap")}
    replacements.update({component.SITE + name: (ROOT / name).read_bytes() for name in component.PYTHON_FILES})
    changed, target = component.derive(raw, record, runtime, identity_raw, replacements,
                                      source_commit=source, source_files=sources, signatures=signatures)
    rows = json.loads(target)["roots"][component.SUPPORT]
    delta = [{"path": path, "before": base.get(path), "after": rows[path], "resource": f"delta-{index:02d}.bin"}
             for index, path in enumerate(sorted(changed))]
    new_identity = json.loads(changed["package-identity.json"])
    plan = {"schema": 1, "managed_by": "account-access-native-component-update-v1",
            "base_source_commit": component.BASE_SOURCE, "component_source_commit": source,
            "base_manifest_sha256": component.BASE_MANIFEST_SHA256,
            "target_manifest_sha256": component.digest(target), "delta": delta,
            "old_signatures": old_identity["signatures"], "new_signatures": new_identity["signatures"],
            "old_fingerprint": fingerprint(old_identity["signatures"]),
            "new_fingerprint": fingerprint(new_identity["signatures"]),
            "designated_requirements": requirements,
            "private_schema_unchanged": True, "automatic_reboot_recovery": False,
            "normal_gui_reopen_required": True, "sms_native_port_refresh_verified": False}
    return raw, target, changed, plan, identity_raw


def postinstall(helper_sha256, team):
    if re.fullmatch(r"[a-f0-9]{64}", helper_sha256) is None or re.fullmatch(r"[A-Z0-9]{10}", team) is None:
        raise ValueError("component_helper_pin_invalid")
    requirement = publisher_requirement("com.fainir.accountaccess.componentupdate", team)
    return f'''#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
[ "$(/usr/bin/id -u)" = 0 ] && [ "${{3:-}}" = / ] || exit 1
AC_COMPONENT_SCRIPTS=$(CDPATH= cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)
AC_COMPONENT_HELPER="$AC_COMPONENT_SCRIPTS/AccountAccess-componentupdate"
for AC_COMPONENT_PATH in "$AC_COMPONENT_SCRIPTS" "$AC_COMPONENT_HELPER"; do
  [ ! -L "$AC_COMPONENT_PATH" ] && [ "$(/usr/bin/stat -f %u "$AC_COMPONENT_PATH")" = 0 ] || exit 1
  AC_COMPONENT_MODE=$(/usr/bin/stat -f %p "$AC_COMPONENT_PATH")
  [ "$((0$AC_COMPONENT_MODE & 07022))" = 0 ] || exit 1
  AC_COMPONENT_LISTING=$(/bin/ls -lde "$AC_COMPONENT_PATH")
  /usr/bin/printf '%s\\n' "$AC_COMPONENT_LISTING" | /usr/bin/awk 'NR > 1 {{ bad=1 }} END {{ exit bad }}' || exit 1
done
[ ! -L "$AC_COMPONENT_HELPER" ] && [ -f "$AC_COMPONENT_HELPER" ] || exit 1
[ "$(/usr/bin/stat -f %u "$AC_COMPONENT_HELPER")" = 0 ] && [ "$(/usr/bin/stat -f %l "$AC_COMPONENT_HELPER")" = 1 ] || exit 1
[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum -a 256 "$AC_COMPONENT_HELPER" | /usr/bin/awk '{{print $1}}')" = '{helper_sha256}' ] || exit 1
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/codesign --verify --strict --all-architectures -R '={requirement}' "$AC_COMPONENT_HELPER" || exit 1
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C "$AC_COMPONENT_HELPER"
'''.encode()


def snapshot_scripts(directory):
    result = {}
    for path in sorted(directory.iterdir()):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16 * 1024 * 1024:
            raise ValueError("component_script_object_changed")
        result[path.name] = {"sha256": component.digest(path.read_bytes()), "mode": stat.S_IMODE(info.st_mode), "bytes": info.st_size}
    return result


def review_package(package, scripts, output, *, identifier=IDENTIFIER):
    if identifier not in {IDENTIFIER, REVALIDATION_IDENTIFIER}:
        raise ValueError("component_package_identity_changed")
    expected = snapshot_scripts(scripts)
    expanded = output / "expanded"
    result = command(["/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded)])
    (output / "expand.log").write_bytes(result.stdout + result.stderr)
    if snapshot_scripts(expanded / "Scripts") != expected or (expanded / "Payload").exists():
        raise ValueError("component_expanded_scripts_or_payload_changed")
    info_raw = (expanded / "PackageInfo").read_bytes()
    info = ET.fromstring(info_raw)
    if info.get("identifier") != identifier or info.get("version") != "0.1.0":
        raise ValueError("component_package_identity_changed")
    payload = info.find("payload")
    if payload is not None and any(int(payload.get(key, "0")) != 0 for key in ("numberOfFiles", "installKBytes")):
        raise ValueError("component_package_has_payload")
    result = subprocess.run(["/usr/sbin/pkgutil", "--check-signature", str(package)],
                            stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=30, check=False)
    signature_output = result.stdout + result.stderr
    if b"no signature" not in signature_output.lower():
        raise ValueError("component_local_container_must_be_unsigned")
    (output / "container-signature.log").write_bytes(signature_output)
    return {"scripts": expected, "expanded_scripts_equal": True, "payload_files": 0,
            "package_info_sha256": component.digest(info_raw), "unsigned_container_verified": True}


def build_root_revalidation(output, *, source, sources, gate, component_scripts,
                            component_package_sha256, plan_raw, signing_identity):
    """Build the matching Installer-only attestation from this invocation's resources.

    This is deliberately not a CLI accepting an existing package or a supplied
    receipt. The component producer has just compiled and checked every input.
    No installed policies, credentials or private receipt files are read here.
    """
    if os.getuid() == 0 or os.getuid() != os.geteuid() or os.path.lexists(output):
        raise ValueError("ordinary_new_revalidation_builder_required")
    if freeze(source) != sources:
        raise ValueError("component_sources_changed_before_revalidation_build")
    output.mkdir(mode=0o700)
    scripts = output / "scripts"
    scripts.mkdir(mode=0o700)
    source_snapshot = snapshot_scripts(component_scripts)
    plan = strict_json(plan_raw)
    resources = {"BaseManifest.json", "TargetManifest.json", "BaseIdentity.json", "ComponentPlan.json",
                 *(row["resource"] for row in plan["delta"])}
    if set(source_snapshot) != resources | {"postinstall", "AccountAccess-componentupdate"}:
        raise ValueError("component_resource_set_changed")
    for name in sorted(resources):
        raw = (component_scripts / name).read_bytes()
        if component.digest(raw) != source_snapshot[name]["sha256"] or source_snapshot[name]["mode"] != 0o644:
            raise ValueError("component_resources_changed_before_revalidation_build")
        (scripts / name).write_bytes(raw)
        (scripts / name).chmod(0o644)
    if (scripts / "ComponentPlan.json").read_bytes() != plan_raw:
        raise ValueError("revalidation_compiled_plan_changed")
    pin = output / "ComponentPlanPin.swift"
    pin.write_text('enum ComponentUpdateCompiledPins { static let planSHA256 = "' + component.digest(plan_raw) + '" }\n')
    helper = scripts / "AccountAccess-componentupdate"
    command(["/usr/bin/xcrun", "swiftc", "-O", "-parse-as-library", "-warnings-as-errors",
             "-module-cache-path", str(output.parent / "module-cache"),
             "-D", "ACCOUNT_ACCESS_INSTALLATION_ROOT_REVALIDATION_MAIN", "-target", "arm64-apple-macos14",
             "-framework", "Foundation", "-framework", "Security", "-framework", "CryptoKit",
             *(str(ROOT / "macos" / name) for name in (
                 "InstallerPayload.swift", "ComponentUpdate.swift", "ComponentUpdatePolicies.swift",
                 "ComponentUpdateIdentity.swift", "InstallationRootBinding.swift", "InstallationRootRevalidation.swift")),
             str(pin), "-o", str(helper)], timeout=300)
    command(["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp",
             "--identifier", "com.fainir.accountaccess.componentupdate", "--sign", signing_identity, str(helper)])
    identity = signature(helper, "com.fainir.accountaccess.componentupdate")
    if identity["team"] != plan["old_signatures"]["owner"]["team"]:
        raise ValueError("component_helper_publisher_changed")
    command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
             "-R=" + publisher_requirement(identity["identifier"], identity["team"]), str(helper)])
    helper.chmod(0o755)
    (scripts / "postinstall").write_bytes(postinstall(component.digest(helper.read_bytes()), identity["team"]))
    (scripts / "postinstall").chmod(0o755)
    command(["/bin/sh", "-n", str(scripts / "postinstall")])
    if set(snapshot_scripts(scripts)) != resources | {"postinstall", "AccountAccess-componentupdate"}:
        raise ValueError("component_resource_set_changed")
    package = output / REVALIDATION_PACKAGE_NAME
    result = command(["/usr/bin/pkgbuild", "--nopayload", "--identifier", REVALIDATION_IDENTIFIER,
                      "--version", "0.1.0", "--scripts", str(scripts), str(package)], timeout=120)
    (output / "pkgbuild.log").write_bytes(result.stdout + result.stderr)
    package_review = review_package(package, scripts, output, identifier=REVALIDATION_IDENTIFIER)
    if freeze(source) != sources or snapshot_scripts(component_scripts) != source_snapshot:
        raise ValueError("component_sources_or_resources_changed_during_revalidation_build")
    record = {"schema": 1, "status": "ASSEMBLED_AND_EXPANSION_REVIEWED", "not_installed": True,
              "helper_executed": False, "owner_data_read": False, "production_ready": False,
              "actual_candidate_installer_ci_required_before_owner_install": True,
              "base_source_commit": component.BASE_SOURCE, "component_source_commit": source,
              "source_files": sources, "ci_gate": gate, "native_helper_identity": identity,
              "component_package_sha256": component_package_sha256,
              "plan_sha256": component.digest(plan_raw), "compiled_pin_source_sha256": component.digest(pin.read_bytes()),
              "package": str(package), "package_sha256": component.digest(package.read_bytes()),
              "package_bytes": package.stat().st_size, **package_review}
    (output / "review.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    return record


def build(output, source, signing_identity):
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError("ordinary_component_builder_required")
    if os.path.lexists(output):
        raise ValueError("new_component_output_required")
    if shutil.disk_usage(output.parent).free < 200 * 1024 * 1024:
        raise ValueError("component_build_space_required")
    sources = freeze(source)
    gate, archives = ci_gate(source, sources)
    if freeze(source) != sources:
        raise ValueError("component_sources_changed_during_ci_gate")
    output.mkdir(mode=0o700)
    evidence = output / "ci-evidence"
    evidence.mkdir(mode=0o700)
    for name, raw in archives.items():
        (evidence / name).write_bytes(raw)
    (output / "ci-gate.json").write_bytes(component.encoded(gate))
    for name, checksum in sources.items():
        raw = (ROOT / name).read_bytes()
        if component.digest(raw) != checksum:
            raise ValueError("component_sources_changed_before_compile")
        target = output / "source" / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o600)
    native = output / "native"
    command(["/bin/bash", str(ROOT / "macos/build-broker.sh"), str(native)],
            env={**ENV, "ACCOUNT_ACCESS_SIGNING_IDENTITY": signing_identity}, timeout=600)
    scripts = output / "scripts"
    scripts.mkdir(mode=0o700)
    old, new, changed, plan, base_identity = plan_inputs(source, sources, native)
    plan_raw = component.encoded(plan)
    pin = output / "ComponentPlanPin.swift"
    pin.write_text('enum ComponentUpdateCompiledPins { static let planSHA256 = "' + component.digest(plan_raw) + '" }\n')
    helper = scripts / "AccountAccess-componentupdate"
    command(["/usr/bin/xcrun", "swiftc", "-O", "-parse-as-library", "-warnings-as-errors",
             "-module-cache-path", str(output / "module-cache"),
             "-D", "ACCOUNT_ACCESS_COMPONENT_UPDATE_MAIN", "-target", "arm64-apple-macos14",
             "-framework", "Foundation", "-framework", "Security", "-framework", "CryptoKit",
             str(ROOT / "macos/InstallerPayload.swift"), str(ROOT / "macos/ComponentUpdate.swift"),
             str(ROOT / "macos/InstallationRootBinding.swift"),
             str(ROOT / "macos/ComponentUpdatePolicies.swift"), str(ROOT / "macos/ComponentUpdateIdentity.swift"), str(pin),
             "-o", str(helper)], timeout=300)
    command(["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp",
             "--identifier", "com.fainir.accountaccess.componentupdate", "--sign", signing_identity, str(helper)])
    helper_identity = signature(helper, "com.fainir.accountaccess.componentupdate")
    if helper_identity["team"] != plan["old_signatures"]["owner"]["team"]:
        raise ValueError("component_helper_publisher_changed")
    command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
             "-R=" + publisher_requirement(helper_identity["identifier"], helper_identity["team"]), str(helper)])
    for name, data in (("BaseManifest.json", old), ("TargetManifest.json", new),
                       ("BaseIdentity.json", base_identity), ("ComponentPlan.json", plan_raw)):
        (scripts / name).write_bytes(data)
        (scripts / name).chmod(0o644)
    for row in plan["delta"]:
        (scripts / row["resource"]).write_bytes(changed[row["path"]])
        (scripts / row["resource"]).chmod(0o644)
    helper.chmod(0o755)
    (scripts / "postinstall").write_bytes(postinstall(component.digest(helper.read_bytes()), helper_identity["team"]))
    (scripts / "postinstall").chmod(0o755)
    command(["/bin/sh", "-n", str(scripts / "postinstall")])
    if freeze(source) != sources:
        raise ValueError("component_sources_changed_during_build")
    expected_names = {"BaseManifest.json", "TargetManifest.json", "BaseIdentity.json", "ComponentPlan.json",
                      "AccountAccess-componentupdate", "postinstall", *(row["resource"] for row in plan["delta"])}
    if set(snapshot_scripts(scripts)) != expected_names:
        raise ValueError("component_resource_set_changed")
    package = output / PACKAGE_NAME
    result = command(["/usr/bin/pkgbuild", "--nopayload", "--identifier", IDENTIFIER,
        "--version", "0.1.0", "--scripts", str(scripts), str(package)], timeout=120)
    (output / "pkgbuild.log").write_bytes(result.stdout + result.stderr)
    package_review = review_package(package, scripts, output)
    if freeze(source) != sources:
        raise ValueError("component_sources_changed_during_assembly")
    revalidation = build_root_revalidation(output / "root-revalidation", source=source, sources=sources, gate=gate,
        component_scripts=scripts, component_package_sha256=component.digest(package.read_bytes()),
        plan_raw=plan_raw, signing_identity=signing_identity)
    record = {"schema": 1, "status": "ASSEMBLED_AND_EXPANSION_REVIEWED", "not_installed": True,
              "helper_executed": False, "owner_data_read": False, "production_ready": False,
              "actual_candidate_installer_ci_required_before_owner_install": True,
              "base_source_commit": component.BASE_SOURCE, "component_source_commit": source,
              "base_gui_and_project_wheel_sha256": component.BASE_WHEEL_SHA256,
              "source_files": sources, "ci_gate": gate, "native_helper_identity": helper_identity,
              "plan_sha256": component.digest(plan_raw), "compiled_pin_source_sha256": component.digest(pin.read_bytes()),
              "package": str(package), "package_sha256": component.digest(package.read_bytes()),
              "root_revalidation_package_sha256": revalidation["package_sha256"],
              "package_bytes": package.stat().st_size, **package_review}
    (output / "review.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signing-identity", required=True)
    args = parser.parse_args()
    build(args.output.absolute(), args.source, args.signing_identity)


if __name__ == "__main__":
    main()
