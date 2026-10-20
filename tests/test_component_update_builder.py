"""Synthetic CI/package gate checks; no network, signing, compile or root work."""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace
import zipfile

import pytest

from scripts.mac_launchctl_disable_probe import root_source


SPEC = importlib.util.spec_from_file_location("component_builder", Path(__file__).parents[1] / "macos/build-component-update.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
SOURCE = "a" * 40
TEAM = "WBULD6N4NQ"


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as container:
        for name, raw in files.items():
            container.writestr(name, raw)
    return output.getvalue()


@pytest.fixture
def evidence():
    sources = {name: builder.component.digest(name.encode()) for name in builder.NATIVE_CI_SOURCES}
    sources["scripts/mac_launchctl_disable_probe.py"] = builder.component.digest(
        (builder.ROOT / "scripts/mac_launchctl_disable_probe.py").read_bytes())
    run_id = 1006
    core = {"schema": 1, "status": "PASSED", "ordinary_fixture_assertions": 87,
            "checks": dict.fromkeys(builder.CORE_CHECKS, True), "installed_reads": False, "service_actions": False}
    policy = {"schema": 1, "status": "PASSED", "count": 41,
              "checks": dict.fromkeys(builder.POLICY_CHECKS, True), "installed_reads": False, "service_actions": False}
    main = {"returncode": 78, "result": {"schema": 1, "status": "REFUSED", "reason": "component_update_context_required"}}
    native = {"schema": 1, "status": "PASSED", "environment": "ordinary-disposable-mac-ci",
              "source_revision": SOURCE, "source_sha256": {name: sources[name] for name in builder.NATIVE_CI_SOURCES},
              "run_id": str(run_id), "run_attempt": "1", "checks": dict.fromkeys(
                  ("core_fixture", "policy_fixture", "ordinary_main_refusal"), True),
              "core_fixture_json": core, "policy_fixture_json": policy, "ordinary_main": main,
              "logs": {}, "generated_pin_source": builder.ZERO_PIN,
              "generated_pin_source_sha256": builder.component.digest(builder.ZERO_PIN.encode()),
              "installed_reads": False, "service_actions": False, "root_execution": False, "production_ready": False}
    native_files = {"core-fixture.json": encoded(core), "policy-fixture.json": encoded(policy), "ordinary-main.json": encoded(main)}
    for action in ("compile", "run"):
        for kind in ("core", "policy", "main"):
            name = action + "-" + kind + ".log"
            value = {"returncode": 78 if (action, kind) == ("run", "main") else 0,
                     "stdout": json.dumps({"core": core, "policy": policy, "main": main["result"]}[kind]) if action == "run" else "",
                     "stderr": ""}
            native_files[name] = encoded(value)
            native["logs"][name] = builder.component.digest(native_files[name])
    native_files["report.json"] = encoded(native)
    token = "f" * 32
    generated = root_source(token).encode()
    absent = ('Bad request.\nCould not find service "local.account-access-disable-probe.' + token
              + '" in domain for system\n').encode()

    def command(code=0, output=b""):
        return {"returncode": code, "client_reaped": True, "timed_out": False,
                "output_limited": False, "invocation_failed": False,
                "output_bytes": len(output), "output_sha256": builder.component.digest(output)}

    scope = "unique_system_job_registration_exclusion_while_disabled_no_reboot"
    probe = {"schema": 1, "status": "PASSED", "status_scope": scope,
             "root_probe_sha256": builder.component.digest(generated), "actual_installer_script": True,
             "failure_stage": None, "measurement_failure_stage": None,
             "private_data_accessed": False, "production_namespace_accessed": False,
             "production_ready": False, "reboot_tested": False, "service_health_verified": False,
             "initial_disabled_override": "absent", "disabled_override": "true",
             "disabled_override_after_attempt": "true", "enabled_override": "false", "zero_override_state_claimed": False}
    for key in ("preflight_definitively_absent", "initial_enabled_marker_created", "after_bootout_definitively_absent",
                "disabled_definitively_absent", "disabled_marker_absent_for_2000ms", "already_absent_state_confirmed",
                "reenabled_marker_created", "fixture_removed", "service_removed", "effective_enabled_restored",
                "unique_false_override_retained_until_vm_teardown"):
        probe[key] = True
    for key in ("initial_disabled_query", "initial_bootstrap", "disable", "disabled_query", "bootout",
                "disabled_query_after_attempt", "enable", "enabled_query", "reenabled_bootstrap",
                "cleanup_enable", "cleanup_disabled_query", "cleanup_bootout"):
        probe[key] = command()
    for key in ("preflight_lookup", "after_bootout_lookup", "disabled_lookup", "lookup_after_absent_bootout", "cleanup_lookup"):
        probe[key] = command(113, absent)
    probe["disabled_bootstrap"] = command(5)
    probe["bootout_already_absent"] = command(113)
    label = "local.account-access-disable-probe." + token
    for key, normalized, word in (("initial_disabled_query", "absent", None), ("disabled_query", "true", "disabled"),
                                  ("disabled_query_after_attempt", "true", "disabled"), ("enabled_query", "false", "enabled"),
                                  ("cleanup_disabled_query", "false", "enabled")):
        line = '\t"' + label + '" => ' + word if word else None
        output = ('disabled services = {\n' + (line + '\n' if line else '') + '}\n').encode()
        probe[key] = command(output=output)
        probe[key]["override_evidence"] = {"target_line": line, "token": word, "normalized": normalized}
    disable = {"schema": 1, "status": "PASSED", "environment": "disposable-mac-ci-installer",
               "status_scope": scope, "run_id": str(run_id), "run_attempt": "1",
               "actual_installer_used": True, "installer_exit_code": 0, "private_data_accessed": False,
               "production_namespace_accessed": False, "production_ready": False, "reboot_tested": False,
               "source_binding": {"git_head": SOURCE, "github_sha": SOURCE,
                   "probe_script_sha256": sources["scripts/mac_launchctl_disable_probe.py"],
                   "workflow_sha256": sources[".github/workflows/mac-worker.yml"],
                   "root_probe_sha256": builder.component.digest(generated)}, "probe": probe}
    disable_files = {"report.json": encoded(disable), "installer-context.json": encoded(probe), "root-probe.py": generated}
    runs = [{"id": 1000 + 2 * index + event_index, "path": ".github/workflows/" + name,
             "event": event, "head_sha": SOURCE, "run_attempt": 1, "status": "completed", "conclusion": "success",
             "repository": {"full_name": builder.REPOSITORY}, "head_repository": {"full_name": builder.REPOSITORY}}
            for index, name in enumerate(builder.WORKFLOWS) for event_index, event in enumerate(("push", "pull_request"))]
    runs.append(dict(runs[0], id=2000, path=".github/workflows/" + builder.REVIEW_WORKFLOW))
    archives = {5001: archive(native_files), 5002: archive(disable_files)}
    artifacts = [{"id": identifier, "name": name, "expired": False, "size_in_bytes": len(archives[identifier]),
                  "digest": "sha256:" + builder.component.digest(archives[identifier]),
                  "workflow_run": {"id": run_id, "head_sha": SOURCE}}
                 for identifier, name in [(5001, "mac-component-update-native"), (5002, "mac-launchctl-disable-installer-context")]]
    jobs = {run["id"]: [{"id": run["id"] * 100 + index, "name": name, "run_attempt": 1,
                         "head_sha": SOURCE, "status": "completed", "conclusion": "success"}
                        for index, name in enumerate(sorted(builder.REQUIRED_JOBS[Path(run["path"]).name]))] for run in runs}
    jobs[2000].extend(dict(jobs[2000][0], id=200001 + index, name=name, conclusion="skipped")
                      for index, name in enumerate(("download-public-inputs", "actual-installer-review")))
    return SimpleNamespace(sources=sources, run_id=run_id, native=native, native_files=native_files,
                           disable=disable, probe=probe, disable_files=disable_files,
                           runs=runs, jobs=jobs, archives=archives, artifacts=artifacts)


def remote(monkeypatch, evidence):
    calls = []

    def get(endpoint):
        calls.append(endpoint)
        if endpoint == "user":
            return {"id": 42}
        if "actions/runs?" in endpoint:
            return {"total_count": len(evidence.runs), "workflow_runs": evidence.runs}
        if "/attempts/1/jobs?" in endpoint:
            jobs = evidence.jobs[int(endpoint.split("/runs/")[1].split("/")[0])]
            return {"total_count": len(jobs), "jobs": jobs}
        if endpoint.endswith("/artifacts?per_page=100"):
            return {"total_count": len(evidence.artifacts), "artifacts": evidence.artifacts}
        raise AssertionError(endpoint)

    monkeypatch.setattr(builder, "github_json", get)
    monkeypatch.setattr(builder, "github_bytes", lambda endpoint: evidence.archives[int(endpoint.split("/")[-2])])
    return calls


def test_gate_authenticates_complete_first_attempt_matrix_and_server_archives(monkeypatch, evidence):
    calls = remote(monkeypatch, evidence)
    proof, archives = builder.ci_gate(SOURCE, evidence.sources)
    assert calls[0] == "user" and len(proof["first_attempt_runs"]) == 9
    assert len(proof["artifacts"]) == 2 and len(archives) == 2
    assert all(item["run_id"] == evidence.run_id for item in proof["artifacts"])
    review = next(item for item in proof["first_attempt_runs"] if item["id"] == 2000)
    assert {(job["name"], job["conclusion"], job["applicable"]) for job in review["jobs"]} == {
        ("ordinary-contracts", "success", True), ("download-public-inputs", "skipped", False),
        ("actual-installer-review", "skipped", False)}


@pytest.mark.parametrize("change", ["applicable-skipped", "dispatch-passed", "unknown-skipped", "missing-dispatch",
                                  "wrong-event", "dispatch-rerun", "dispatch-foreign-source", "duplicate-job"])
def test_only_exact_review_push_inapplicable_jobs_may_be_skipped(monkeypatch, evidence, change):
    jobs = evidence.jobs[2000]
    if change == "applicable-skipped":
        jobs[0]["conclusion"] = "skipped"
    elif change == "dispatch-passed":
        jobs[1]["conclusion"] = "success"
    elif change == "unknown-skipped":
        jobs[1]["name"] = "foreign-skipped-job"
    elif change == "missing-dispatch":
        jobs.pop()
    elif change == "wrong-event":
        evidence.runs[-1]["event"] = "pull_request"
    elif change == "dispatch-rerun":
        jobs[1]["run_attempt"] = 2
    elif change == "dispatch-foreign-source":
        jobs[1]["head_sha"] = "b" * 40
    else:
        jobs.append(copy.deepcopy(jobs[1]))
    remote(monkeypatch, evidence)
    with pytest.raises(ValueError, match="component_ci_"):
        builder.ci_gate(SOURCE, evidence.sources)


@pytest.mark.parametrize("change", ["rerun", "skipped", "cancelled", "pending", "failed", "duplicate", "missing", "foreign-repo", "different-source"])
def test_failed_missing_ambiguous_or_rerun_ci_never_becomes_candidate(monkeypatch, evidence, change):
    first = evidence.runs[0]
    if change == "rerun":
        first["run_attempt"] = 2
    elif change in {"skipped", "cancelled", "failed"}:
        first["conclusion"] = {"failed": "failure"}.get(change, change)
    elif change == "pending":
        first["status"] = "in_progress"
    elif change == "duplicate":
        evidence.runs.append(copy.deepcopy(first))
    elif change == "missing":
        evidence.runs.pop()
    elif change == "foreign-repo":
        first["head_repository"]["full_name"] = "foreign/account-access"
    else:
        first["head_sha"] = "b" * 40
    remote(monkeypatch, evidence)
    with pytest.raises(ValueError, match="component_ci_"):
        builder.ci_gate(SOURCE, evidence.sources)


@pytest.mark.parametrize("change", ["skipped", "missing", "rerun", "foreign-source"])
def test_successful_workflow_cannot_mask_missing_or_skipped_required_job(monkeypatch, evidence, change):
    jobs = evidence.jobs[1000]
    if change == "missing":
        jobs.pop()
    elif change == "rerun":
        jobs[0]["run_attempt"] = 2
    elif change == "foreign-source":
        jobs[0]["head_sha"] = "b" * 40
    else:
        jobs[0]["conclusion"] = "skipped"
    remote(monkeypatch, evidence)
    with pytest.raises(ValueError, match="component_ci_required_jobs_not_passed"):
        builder.ci_gate(SOURCE, evidence.sources)


@pytest.mark.parametrize("change", ["digest", "expired", "wrong-run", "wrong-source", "duplicate", "missing", "oversized"])
def test_archive_provenance_cannot_be_supplied_by_optimistic_json(monkeypatch, evidence, change):
    first = evidence.artifacts[0]
    if change == "digest":
        first["digest"] = "sha256:" + "0" * 64
    elif change == "expired":
        first["expired"] = True
    elif change == "wrong-run":
        first["workflow_run"]["id"] += 1
    elif change == "wrong-source":
        first["workflow_run"]["head_sha"] = "b" * 40
    elif change == "duplicate":
        evidence.artifacts.append(copy.deepcopy(first))
    elif change == "missing":
        evidence.artifacts.pop()
    else:
        first["size_in_bytes"] = builder.MAX_ARCHIVE + 1
    remote(monkeypatch, evidence)
    with pytest.raises(ValueError, match="component_ci_"):
        builder.ci_gate(SOURCE, evidence.sources)


@pytest.mark.parametrize("change", ["old-source", "missing-input", "root-claim", "count-only", "missing-check",
                                  "wrong-policy", "wrong-main", "wrong-pin", "log-digest", "raw-mismatch", "extra-member"])
def test_native_acceptance_requires_actual_bound_checks_and_raw_logs(evidence, change):
    report, files = evidence.native, evidence.native_files
    if change == "old-source":
        report["source_revision"] = "b" * 40
    elif change == "missing-input":
        report["source_sha256"].pop("macos/ComponentUpdateIdentity.swift")
    elif change == "root-claim":
        report["root_execution"] = True
    elif change == "count-only":
        report["core_fixture_json"]["checks"] = {}
    elif change == "missing-check":
        report["core_fixture_json"]["checks"].pop(next(iter(builder.CORE_CHECKS)))
    elif change == "wrong-policy":
        report["policy_fixture_json"]["checks"][next(iter(builder.POLICY_CHECKS))] = False
    elif change == "wrong-main":
        report["ordinary_main"]["returncode"] = 0
    elif change == "wrong-pin":
        report["generated_pin_source"] += "// foreign\n"
    elif change == "log-digest":
        files["compile-core.log"] += b"changed"
    elif change == "raw-mismatch":
        files["policy-fixture.json"] = b"{}"
    else:
        files["executable.py"] = b"raise RuntimeError('must never execute')"
    files["report.json"] = encoded(report)
    with pytest.raises(ValueError, match="component_native_ci_"):
        builder.validate_native_report(files, source=SOURCE, sources=evidence.sources, run_id=evidence.run_id)


@pytest.mark.parametrize("query", ["initial_disabled_query", "disabled_query", "disabled_query_after_attempt",
                                 "enabled_query", "cleanup_disabled_query"])
def test_each_actual_disable_query_requires_retained_override_evidence(evidence, query):
    evidence.probe[query].pop("override_evidence")
    evidence.disable_files["report.json"] = encoded(evidence.disable)
    evidence.disable_files["installer-context.json"] = encoded(evidence.probe)
    with pytest.raises(ValueError, match="component_disable_ci_override_evidence_changed"):
        builder.validate_disable_report(evidence.disable_files, source=SOURCE, sources=evidence.sources, run_id=evidence.run_id)


@pytest.mark.parametrize("change", ["other-label", "newline", "unknown-token", "wrong-normalization", "extra-key",
                                  "no-line", "wrong-token", "absent-with-line", "unverified", "zero-bytes",
                                  "missing-digest", "too-many-bytes", "query-failed"])
def test_retained_override_evidence_cannot_replace_actual_matching_success(evidence, change):
    command = evidence.probe["disabled_query"]
    value = command["override_evidence"]
    if change == "other-label":
        value["target_line"] = value["target_line"].replace("f" * 32, "e" * 32)
    elif change == "newline":
        value["target_line"] += "\n"
    elif change == "unknown-token":
        value["token"] = "unknown"
        value["target_line"] = value["target_line"].replace("disabled", "unknown")
    elif change == "wrong-normalization":
        value["normalized"] = "false"
    elif change == "extra-key":
        value["unrelated_job"] = "private"
    elif change == "no-line":
        value["target_line"] = None
    elif change == "wrong-token":
        value["token"] = "true"
    elif change == "absent-with-line":
        evidence.probe["initial_disabled_query"]["override_evidence"]["target_line"] = value["target_line"]
    elif change == "unverified":
        value["normalized"] = "unverified"
    elif change == "zero-bytes":
        command["output_bytes"] = 0
    elif change == "missing-digest":
        command.pop("output_sha256")
    elif change == "too-many-bytes":
        command["output_bytes"] = 128 * 1024 + 1
    else:
        command["returncode"] = 1
    evidence.disable_files["report.json"] = encoded(evidence.disable)
    evidence.disable_files["installer-context.json"] = encoded(evidence.probe)
    with pytest.raises(ValueError, match="component_disable_ci_"):
        builder.validate_disable_report(evidence.disable_files, source=SOURCE, sources=evidence.sources, run_id=evidence.run_id)


def test_retained_legacy_boolean_rows_preserve_closed_state_binding(evidence):
    for name, normalized in (("disabled_query", "true"), ("disabled_query_after_attempt", "true"),
                             ("enabled_query", "false"), ("cleanup_disabled_query", "false")):
        command = evidence.probe[name]
        value = command["override_evidence"]
        value["target_line"] = value["target_line"].replace(value["token"], normalized)
        value["token"] = normalized
        raw = ("disabled services = {\n" + value["target_line"] + "\n}\n").encode()
        command["output_bytes"], command["output_sha256"] = len(raw), builder.component.digest(raw)
    evidence.disable_files["report.json"] = encoded(evidence.disable)
    evidence.disable_files["installer-context.json"] = encoded(evidence.probe)
    builder.validate_disable_report(evidence.disable_files, source=SOURCE, sources=evidence.sources, run_id=evidence.run_id)


@pytest.mark.parametrize("change", ["timeout", "not-reaped", "bootstrap-allowed", "generic-absence", "marker-exists",
                                  "cleanup-unverified", "source-changed", "generated-code", "reboot-claim"])
def test_disable_gate_requires_measured_registration_exclusion_and_cleanup(evidence, change):
    report, probe, files = evidence.disable, evidence.probe, evidence.disable_files
    if change == "timeout":
        probe["disable"]["timed_out"] = True
    elif change == "not-reaped":
        probe["bootout"]["client_reaped"] = False
    elif change == "bootstrap-allowed":
        probe["disabled_bootstrap"]["returncode"] = 0
    elif change == "generic-absence":
        probe["disabled_lookup"]["returncode"] = 5
    elif change == "marker-exists":
        probe["disabled_marker_absent_for_2000ms"] = False
    elif change == "cleanup-unverified":
        probe["effective_enabled_restored"] = False
    elif change == "source-changed":
        report["source_binding"]["workflow_sha256"] = "0" * 64
    elif change == "generated-code":
        files["root-probe.py"] += b"\nraise RuntimeError('never execute archive code')\n"
        report["source_binding"]["root_probe_sha256"] = builder.component.digest(files["root-probe.py"])
        probe["root_probe_sha256"] = report["source_binding"]["root_probe_sha256"]
    else:
        report["reboot_tested"] = True
    files["report.json"], files["installer-context.json"] = encoded(report), encoded(probe)
    with pytest.raises(ValueError, match="component_disable_ci_"):
        builder.validate_disable_report(files, source=SOURCE, sources=evidence.sources, run_id=evidence.run_id)


@pytest.mark.parametrize("kind", ["traversal", "absolute", "symlink", "oversized", "too-many"])
def test_zip_never_extracts_paths_links_or_unbounded_members(tmp_path, kind):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as container:
        if kind in {"traversal", "absolute"}:
            container.writestr("../escaped.py" if kind == "traversal" else "/escaped.py", b"must not execute")
        elif kind == "symlink":
            entry = zipfile.ZipInfo("report.json")
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            container.writestr(entry, b"/private/path")
        elif kind == "oversized":
            container.writestr("report.json", b"x" * (128 * 1024 + 1))
        else:
            for index in range(17):
                container.writestr(f"item-{index}.json", b"{}")
    with pytest.raises(ValueError, match="component_ci_archive_invalid"):
        builder.archive_members(output.getvalue())
    assert list(tmp_path.iterdir()) == []


def test_duplicate_json_and_escaped_duplicate_keys_are_refused():
    for raw in (b'{"status": "FAILED", "status": "PASSED"}', b'{"status":1,"sta\\u0074us":2}'):
        with pytest.raises(ValueError, match="component_ci_duplicate_json_key"):
            builder.strict_json(raw)


def test_authenticated_cli_preserves_only_existing_auth_config_without_logging_token(monkeypatch):
    captured = {}
    token = "fictional-unit-test-token"
    monkeypatch.setenv("GH_TOKEN", token)
    monkeypatch.setenv("GH_HOST", "foreign.invalid")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/fixture/config")
    monkeypatch.setattr(builder.shutil, "which", lambda _: "/fixture/gh")

    class Child:
        def __init__(self, arguments, **kwargs):
            captured.update(arguments=arguments, environment=kwargs["env"])
            streams = []
            for raw in (b'{"id":42}', b""):
                reader, writer = os.pipe()
                os.write(writer, raw)
                os.close(writer)
                streams.append(os.fdopen(reader, "rb"))
            self.stdout, self.stderr = streams

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(builder.subprocess, "Popen", Child)
    result = builder.github_json("user")
    assert result == {"id": 42}
    assert captured["environment"]["GH_TOKEN"] == token
    assert captured["environment"]["XDG_CONFIG_HOME"] == "/fixture/config"
    if "HOME" in os.environ:
        assert captured["environment"]["HOME"] == os.environ["HOME"]
    assert "GH_HOST" not in captured["environment"]
    assert token not in json.dumps(result) and token not in " ".join(captured["arguments"])
    assert captured["arguments"] == ["/fixture/gh", "api", "--hostname", "github.com", "user"]


def test_failed_ci_stops_before_any_output_compile_or_installed_base_read(monkeypatch, tmp_path):
    monkeypatch.setattr(builder, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(builder, "os", SimpleNamespace(getuid=lambda: 501, geteuid=lambda: 501, path=os.path))
    monkeypatch.setattr(builder.shutil, "disk_usage", lambda _: SimpleNamespace(free=1024**3))
    monkeypatch.setattr(builder, "freeze", lambda _: {})
    monkeypatch.setattr(builder, "ci_gate", lambda *_: (_ for _ in ()).throw(ValueError("component_ci_required_matrix_missing")))
    monkeypatch.setattr(builder, "command", lambda *_args, **_kwargs: pytest.fail("failed gate cannot compile"))
    monkeypatch.setattr(builder, "plan_inputs", lambda *_: pytest.fail("failed gate cannot read installed base"))
    output = tmp_path / "candidate"
    with pytest.raises(ValueError, match="component_ci_required_matrix_missing"):
        builder.build(output, SOURCE, "fixture identity")
    assert not output.exists()


def test_root_builder_refuses_before_git_network_or_files(monkeypatch, tmp_path):
    monkeypatch.setattr(builder, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(builder, "os", SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0))
    monkeypatch.setattr(builder, "freeze", lambda _: pytest.fail("root must refuse before source reads"))
    with pytest.raises(ValueError, match="ordinary_component_builder_required"):
        builder.build(tmp_path / "candidate", SOURCE, "fixture identity")


def test_postinstall_pins_only_zero_argument_native_helper_and_genuine_team():
    script = builder.postinstall("a" * 64, TEAM)
    assert subprocess.run(["/bin/sh", "-n"], input=script, capture_output=True, timeout=5).returncode == 0
    assert b"codesign --verify --strict --all-architectures" in script
    assert b"certificate leaf[subject.OU]" in script and TEAM.encode() in script
    assert b"07022" in script
    assert b"python" not in script and b"launchctl" not in script
    assert script.endswith(b'LANG=C "$AC_COMPONENT_HELPER"\n')
    for digest, team in [("moving", TEAM), ("a" * 64, "injected' text")]:
        with pytest.raises(ValueError):
            builder.postinstall(digest, team)


def test_expansion_review_detects_changed_resources_or_payload(monkeypatch, tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "postinstall").write_bytes(b"#!/bin/sh\nexit 1\n")
    (scripts / "postinstall").chmod(0o755)
    package = tmp_path / "candidate.pkg"
    package.write_bytes(b"fixture package, never executed")

    def expand(_arguments):
        expanded = tmp_path / "expanded"
        shutil.copytree(scripts, expanded / "Scripts")
        (expanded / "PackageInfo").write_text('<pkg-info identifier="' + builder.IDENTIFIER + '" version="0.1.0"><payload numberOfFiles="0" installKBytes="0"/></pkg-info>')
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(builder, "command", expand)
    monkeypatch.setattr(builder.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout=b"Status: no signature", stderr=b""))
    review = builder.review_package(package, scripts, tmp_path)
    assert review["payload_files"] == 0 and review["expanded_scripts_equal"]
    shutil.rmtree(tmp_path / "expanded")

    def bad_expand(arguments):
        result = expand(arguments)
        (tmp_path / "expanded/Scripts/postinstall").write_bytes(b"changed")
        return result

    monkeypatch.setattr(builder, "command", bad_expand)
    with pytest.raises(ValueError, match="component_expanded_scripts_or_payload_changed"):
        builder.review_package(package, scripts, tmp_path)


def test_frozen_inputs_include_identity_header_and_all_ci_producers():
    paths = {str(path.relative_to(builder.ROOT)) for path in builder.source_paths()}
    assert {"macos/ComponentUpdateIdentity.swift", "macos/KeychainInteraction.h",
            "scripts/mac_component_update_native_probe.py", "scripts/mac_launchctl_disable_probe.py",
            "macos/build-component-update.py"} <= paths
    assert set(builder.NATIVE_CI_SOURCES) <= paths


def test_plan_is_derived_before_helper_compile_and_bound_into_its_literal_pin(monkeypatch, tmp_path):
    repository = tmp_path / "repository"
    source_path = repository / "account_access/worker_host.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(b"# synthetic source only\n")
    sources = {"account_access/worker_host.py": builder.component.digest(source_path.read_bytes())}
    monkeypatch.setattr(builder, "ROOT", repository)
    monkeypatch.setattr(builder, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(builder, "os", SimpleNamespace(getuid=lambda: 501, geteuid=lambda: 501, path=os.path))
    monkeypatch.setattr(builder.shutil, "disk_usage", lambda _: SimpleNamespace(free=1024**3))
    monkeypatch.setattr(builder, "freeze", lambda _: sources)
    monkeypatch.setattr(builder, "ci_gate", lambda *_: ({"fixture_authenticated_gate": True}, {}))
    output = tmp_path / "candidate"
    events, commands = [], []
    changed = {"fixture-" + str(index): b"public fixture " + str(index).encode() for index in range(9)}
    plan = {"old_signatures": {"owner": {"team": TEAM}},
            "delta": [{"path": path, "resource": f"delta-{index:02d}.bin"}
                      for index, path in enumerate(changed)]}

    def derive(_source, _sources, native):
        assert (native / "AccountAccess-broker").exists()
        assert not (output / "scripts/AccountAccess-componentupdate").exists()
        events.append("derive-plan")
        return b"base manifest", b"target manifest", changed, plan, b"original base identity"

    def command(arguments, **_kwargs):
        commands.append(arguments)
        if arguments[0] == "/bin/bash":
            native = Path(arguments[-1])
            native.mkdir()
            for kind in ("broker", "bootstrap"):
                (native / ("AccountAccess-" + kind)).write_bytes(b"synthetic native bytes")
            events.append("native-pair")
        elif arguments[:2] == ["/usr/bin/xcrun", "swiftc"]:
            assert events == ["native-pair", "derive-plan"]
            pin = output / "ComponentPlanPin.swift"
            assert builder.component.digest(builder.component.encoded(plan)) in pin.read_text()
            assert str(repository / "macos/ComponentUpdateIdentity.swift") in arguments
            assert str(repository / "macos/ComponentUpdatePolicies.swift") in arguments
            Path(arguments[-1]).write_bytes(b"synthetic helper bytes")
            events.append("helper-compiled-with-plan")
        elif arguments[0] == "/usr/bin/pkgbuild":
            Path(arguments[-1]).write_bytes(b"synthetic package, never installed")
        return SimpleNamespace(stdout=b"", stderr=b"")

    def review(_package, scripts, _output):
        assert (scripts / "BaseIdentity.json").read_bytes() == b"original base identity"
        assert (scripts / "ComponentPlan.json").read_bytes() == builder.component.encoded(plan)
        assert len(builder.snapshot_scripts(scripts)) == 15
        return {"payload_files": 0, "expanded_scripts_equal": True}

    monkeypatch.setattr(builder, "plan_inputs", derive)
    monkeypatch.setattr(builder, "command", command)
    monkeypatch.setattr(builder, "signature", lambda *_: {"team": TEAM, "identifier": "com.fainir.accountaccess.componentupdate", "hashes": ["a" * 40]})
    monkeypatch.setattr(builder, "review_package", review)
    result = builder.build(output, SOURCE, "synthetic signer; no signing executed")
    assert events == ["native-pair", "derive-plan", "helper-compiled-with-plan"]
    assert result["not_installed"] and result["helper_executed"] is False
    assert result["plan_sha256"] == builder.component.digest((output / "scripts/ComponentPlan.json").read_bytes())
    assert not any("installer" == Path(arguments[0]).name or "launchctl" == Path(arguments[0]).name
                   or arguments[0] == str(output / "scripts/AccountAccess-componentupdate") for arguments in commands)
