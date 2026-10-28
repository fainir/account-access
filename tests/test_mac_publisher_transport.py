"""Public fixtures only; never install, launch a peer, or change OS authority."""

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import tarfile
from types import SimpleNamespace

import pytest

from account_access.package_manifest import build


def load(name):
    path = Path(__file__).resolve().parents[1] / "scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load("mac_publisher_transport_probe")
checker = load("check_mac_publisher_transport_report")
REVISION = "a" * 40


def hosted():
    return {"GITHUB_ACTIONS": "true", "CI": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY": probe.REPOSITORY,
            "GITHUB_RUN_ID": "12345", "GITHUB_SHA": REVISION}


def test_host_guard_accepts_only_explicit_hosted_arm64_roles():
    probe.guard(root=True, environment=hosted(), system="darwin", machine="arm64", uid=0, euid=0)
    probe.guard(root=False, environment=hosted(), system="darwin", machine="arm64", uid=501, euid=501)


@pytest.mark.parametrize("field,value", [
    ("GITHUB_ACTIONS", "false"), ("CI", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
    ("RUNNER_OS", "Linux"), ("RUNNER_ARCH", "X64"), ("GITHUB_REPOSITORY", "other/repo"),
    ("GITHUB_RUN_ID", ""), ("GITHUB_SHA", "main"),
])
def test_host_guard_refuses_personal_or_unbound_execution(field, value):
    env = hosted()
    env[field] = value
    with pytest.raises(probe.ReviewError, match="hosted_review_only"):
        probe.guard(root=True, environment=env, system="darwin", machine="arm64", uid=0, euid=0)


@pytest.mark.parametrize("system,machine,uid,euid", [
    ("linux", "arm64", 0, 0), ("darwin", "x86_64", 0, 0),
    ("darwin", "arm64", 501, 501), ("darwin", "arm64", 501, 0),
])
def test_host_guard_refuses_wrong_platform_or_privilege(system, machine, uid, euid):
    with pytest.raises(probe.ReviewError):
        probe.guard(root=True, environment=hosted(), system=system, machine=machine, uid=uid, euid=euid)


@pytest.fixture
def public_image(tmp_path):
    payload = tmp_path / "payload"
    support = payload / probe.BASE.relative_to("/")
    app = payload / probe.APP.relative_to("/")
    for name in ["bin", "browsers", "runtime"]:
        (support / name).mkdir(parents=True)
    app.mkdir(parents=True)
    alias = payload / probe.PUBLIC_APP.relative_to("/")
    alias.parent.mkdir(parents=True)
    alias.symlink_to(probe.APPLICATION_TARGET)
    for name in ["AccountAccess-broker", "AccountAccess-bootstrap"]:
        (support / "bin" / name).write_bytes(b"public fixture " + name.encode())
    (support / "runtime/python").write_bytes(b"public fixture runtime")
    (support / "runtime/current").symlink_to("python")
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/MacOS/AccountAccess").write_bytes(b"public owner executable fixture")
    (app / "public-resource").write_bytes(b"public app fixture")
    for path in [payload, *payload.rglob("*")]:
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)
    manifest_raw = build(payload, "0.8.0", "arm64")
    review = {"managed_by": "account-access-publisher-transport-review-v1", "schema": 1,
              "source_revision": REVISION, "architecture": "arm64", "publisher_team": probe.TEAM,
              "image_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}
    return tmp_path, payload, review, manifest_raw


def tar_bytes(image, mutation=None):
    _, payload, review, manifest_raw = image
    nodes = probe.archive_nodes(json.loads(manifest_raw))
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, node in nodes.items():
            member = tarfile.TarInfo(name)
            member.mode = node.get("mode", 0o644)
            data = None
            if node["kind"] == "directory":
                member.type = tarfile.DIRTYPE
            elif node["kind"] == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = node["target"]
                member.mode = 0o777  # Normal tar metadata; no target permission is inherited.
            else:
                data = (json.dumps(review).encode() if name == "review.json" else manifest_raw
                        if name == "image-manifest.json" else (payload.parent / name).read_bytes())
                member.size = len(data)
            if mutation:
                member, data = mutation(member, data)
            archive.addfile(member, io.BytesIO(data) if data is not None else None)
    stream.seek(0)
    return stream


def test_exact_public_archive_extracts_and_rehashes_without_authority(public_image):
    base, _, _, manifest = public_image
    archive = base / "review.tar.gz"
    archive.write_bytes(tar_bytes(public_image).read())
    target = base / "extract"
    target.mkdir()
    probe.extract_review(archive, target, REVISION)
    assert build(target / "payload", "0.8.0", "arm64") == manifest
    assert (target / "payload" / probe.BASE.relative_to("/") / "runtime/current").is_symlink()


@pytest.mark.parametrize("attack", ["traversal", "absolute", "extra", "hardlink", "alias", "writable", "body"])
def test_unsafe_or_substituted_archive_refused(public_image, attack):
    changed = False

    def mutate(member, data):
        nonlocal changed
        if not changed and member.name.endswith("runtime/python"):
            changed = True
            if attack == "traversal":
                member.name = "../outside"
            elif attack == "absolute":
                member.name = "/outside"
            elif attack == "extra":
                member.name = "payload/extra"
            elif attack == "hardlink":
                member.type, member.linkname, member.size, data = tarfile.LNKTYPE, "review.json", 0, None
            elif attack == "alias":
                member.type, member.linkname, member.size, data = tarfile.SYMTYPE, "/outside", 0, None
            elif attack == "writable":
                member.mode = 0o666
            elif attack == "body":
                data = b"x" * len(data)
        return member, data

    base = public_image[0]
    archive = base / "bad.tar.gz"
    archive.write_bytes(tar_bytes(public_image, mutate).read())
    target = base / "extract"
    target.mkdir()
    with pytest.raises((probe.ReviewError, ValueError)):
        probe.extract_review(archive, target, REVISION)
    assert changed
    assert not (base / "outside").exists()


@pytest.mark.parametrize("field,value", [("schema", True), ("publisher_team", "OTHER"),
    ("source_revision", "b" * 40), ("architecture", "x86_64"), ("extra", "unexpected")])
def test_review_contract_rejects_wrong_source_authority_and_schema(public_image, field, value):
    _, _, review, manifest = public_image
    review[field] = value
    with pytest.raises(probe.ReviewError, match="review_contract_mismatch"):
        probe.contract(json.dumps(review), manifest, REVISION)


def valid_report():
    result = {"schema": 2, "status": "PASSED", "platform": "macos", "architecture": "arm64",
              "environment": "disposable-hosted-ci-public-review", "owner_context": "existing-hosted-runner-fresh-browser-profile",
              "source_revision": REVISION,
              "controller_revision": "b" * 40, "review_archive_sha256": "c" * 64,
              "publisher_team": probe.TEAM, "chrome_version": "Chrome/142.0.7444.60",
              "component_hashes": {name: ["d" * 40] for name in ["owner", "broker", "bootstrap"]},
              "extension_resources_sha256": {name: "e" * 64 for name in probe.RESOURCES},
              "checks": dict.fromkeys(checker.CHECKS, True), "private_signins": 0,
              "limits": "Public signed transport before owner enrollment; no key, website login, personal account, phone, approval or consumer installation was validated."}
    result.update(dict.fromkeys(checker.TRUE_FLAGS, True))
    result.update(dict.fromkeys(checker.FALSE_FLAGS, False))
    return result


def test_report_distinguishes_application_source_from_controller_and_limits_truthfully():
    assert checker.validate(valid_report())
    assert not checker.validate(None)


@pytest.mark.parametrize("flag", sorted(checker.FALSE_FLAGS))
def test_transport_report_never_claims_real_approval_or_account_coverage(flag):
    report = valid_report()
    report[flag] = True
    assert not checker.validate(report)


@pytest.mark.parametrize("attack", ["missing", "false", "extra", "schema", "private", "hash", "source"])
def test_incomplete_or_misleading_transport_evidence_refused(attack):
    report = valid_report()
    if attack == "missing":
        report["checks"].pop("chrome_and_native_children_stopped")
    elif attack == "false":
        report["checks"]["chrome_and_native_children_stopped"] = False
    elif attack == "extra":
        report["unreviewed"] = True
    elif attack == "schema":
        report["schema"] = True
    elif attack == "private":
        report["private_signins"] = True
    elif attack == "hash":
        report["component_hashes"]["owner"] = ["not-a-hash"]
    elif attack == "source":
        report["source_revision"] = "main"
    assert not checker.validate(report)


def test_exact_registered_rule_cannot_downgrade_presence_or_forge_registrar():
    value = {"identifier": probe.LABEL, "requirement": "genuine designated requirement", "class": "user",
             "session-owner": True, "authenticate-user": True, "allow-root": False, "shared": False,
             "timeout": 30, "tries": 3, "version": 1}
    assert probe.exact_rule(value, value["requirement"])
    for field, changed in [("identifier", "other"), ("requirement", "other"), ("timeout", True),
                           ("authenticate-user", 1), ("allow-root", True), ("shared", True)]:
        modified = copy.deepcopy(value)
        modified[field] = changed
        assert not probe.exact_rule(modified, value["requirement"])


def test_git_trust_exception_is_command_local_and_exact_checkout(monkeypatch):
    calls = []
    monkeypatch.setattr(probe, "command", lambda args: calls.append(args))
    probe.git(["rev-parse", "HEAD"])
    assert calls == [["/usr/bin/git", "-c", "safe.directory=" + str(probe.SOURCE),
                      "-C", str(probe.SOURCE), "rev-parse", "HEAD"]]


def test_draft_download_uses_immutable_release_id_and_checks_exact_binding(tmp_path, monkeypatch, capsys):
    body = b"public immutable archive fixture"
    sha = hashlib.sha256(body).hexdigest()
    args = SimpleNamespace(source=REVISION, sha256=sha, tag="qa-review", asset="review.tar.gz",
                           release_id=416327595, asset_id=652938188, output=str(tmp_path / "review.tar.gz"))
    metadata = {"id": args.release_id, "tag_name": args.tag, "draft": True, "target_commitish": REVISION,
                "assets": [{"id": args.asset_id, "name": args.asset, "digest": "sha256:" + sha, "size": len(body)}]}
    calls = []
    monkeypatch.setattr(probe.os, "getuid", lambda: 501)
    monkeypatch.setenv("GITHUB_REPOSITORY", probe.REPOSITORY)

    def api(arguments, **kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, json.dumps(metadata).encode(), b"")

    def binary(arguments, **kwargs):
        calls.append(arguments)
        kwargs["stdout"].write(body)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(probe, "command", api)
    monkeypatch.setattr(probe.subprocess, "run", binary)
    probe.download(args)
    assert calls[0] == ["gh", "api", "repos/fainir/account-access/releases/416327595"]
    assert calls[1][:3] == ["gh", "api", "repos/fainir/account-access/releases/assets/652938188"]
    assert json.loads(capsys.readouterr().out)["draft"] is True
    assert Path(args.output).read_bytes() == body
    metadata["tag_name"] = "substituted"
    args.output = str(tmp_path / "must-not-exist")
    with pytest.raises(probe.ReviewError, match="review_draft_source_mismatch"):
        probe.download(args)
    assert not Path(args.output).exists()


def test_unavailable_draft_fails_before_download_with_no_raw_api_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(probe.os, "getuid", lambda: 501)
    monkeypatch.setenv("GITHUB_REPOSITORY", probe.REPOSITORY)
    monkeypatch.setattr(probe, "command", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, b"", b"private raw API failure"))
    assert probe.main(["download", "--tag", "qa-review", "--asset", "review.tar.gz", "--asset-id", "652938188",
                       "--release-id", "416327595", "--source", REVISION, "--sha256", "a" * 64,
                       "--output", str(tmp_path / "must-not-exist")]) == 1
    assert json.loads(capsys.readouterr().out) == {"status": "FAILED", "reason": "review_draft_metadata_unavailable",
                                                "failure_type": "ReviewError", "production_ready": False}
    assert not (tmp_path / "must-not-exist").exists()


def test_parent_diagnostics_only_include_presence_uid_mode_and_alias_metadata(tmp_path):
    public = tmp_path / "public"
    public.mkdir(mode=0o775)
    public.chmod(0o775)
    (public / "must-never-read").write_text("unrelated contents")
    assert probe.public_parent_metadata([("applications", public), ("helpers", tmp_path / "absent")]) == {
        "applications": {"present": True, "owner_uid": os.getuid(), "mode": 0o775, "symlink": False},
        "helpers": {"present": False}}


@pytest.mark.parametrize("uid,mode,accepted", [(0, 0o40775, True), (0, 0o40755, True),
    (0, 0o40777, False), (501, 0o40775, False), (0, 0o42775, False), (0, 0o100755, False)])
def test_shared_applications_parent_is_read_only_metadata_and_never_runtime_trust(uid, mode, accepted):
    assert probe.shared_parent_metadata_valid(SimpleNamespace(st_uid=uid, st_mode=mode)) is accepted
    assert probe.APP == probe.BASE / "owner.app"
    assert probe.PUBLIC_APP == Path("/Applications/Account Access.app")
    assert stat.S_IFMT(mode) != 0


def test_designated_requirement_comes_from_stdout_only(monkeypatch):
    monkeypatch.setattr(probe, "command", lambda *args, **kwargs: subprocess.CompletedProcess([], 0,
        b'designated => anchor apple generic and identifier "fixed-fixture"\n',
        b'Executable=/private/path\ndesignated => untrusted stderr decoy\n'))
    assert probe.designated_requirement(Path("/public/fixture")) == 'anchor apple generic and identifier "fixed-fixture"'


@pytest.mark.parametrize("stdout", [b"", b"unrelated output\n",
    b"designated => first\ndesignated => second\n"])
def test_missing_or_ambiguous_stdout_requirement_is_refused_even_with_stderr_decoy(monkeypatch, stdout):
    monkeypatch.setattr(probe, "command", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, stdout,
        b'designated => plausible but wrong stream\n'))
    with pytest.raises(probe.ReviewError, match="broker_designated_requirement_missing"):
        probe.designated_requirement(Path("/public/fixture"))


def test_command_failure_exposes_only_known_operation_and_exitcode(monkeypatch, capsys):
    secret = "fixture-private-value-never-print"
    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 7,
        secret.encode(), secret.encode()))
    with pytest.raises(probe.ReviewError) as caught:
        probe.command(["/usr/bin/codesign", "-d", "-r-", "/private/" + secret], env={"TOKEN": secret})
    report = probe.public_error(caught.value)
    assert report == {"reason": "review_command_failed", "failure_type": "ReviewError",
                      "command_failure": {"kind": "codesign_designated", "exitcode": 7, "timed_out": False}}
    assert secret not in json.dumps(report) and capsys.readouterr().out == ""


def test_command_timeout_never_serializes_exception_arguments_output_or_environment(monkeypatch):
    secret = "fixture-private-timeout-value"
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired([secret], 25, output=secret.encode(), stderr=secret.encode())
    monkeypatch.setattr(probe.subprocess, "run", timeout)
    with pytest.raises(probe.ReviewError) as caught:
        probe.command(["/bin/launchctl", "asuser", secret], env={"TOKEN": secret})
    report = probe.public_error(caught.value)
    assert report["reason"] == "review_command_timeout"
    assert report["command_failure"] == {"kind": "launchctl_owner_child", "exitcode": None, "timed_out": True}
    assert secret not in json.dumps(report)


def test_unknown_error_reason_and_forged_command_details_cannot_leak():
    secret = "private-message-should-not-appear"
    error = probe.ReviewError(secret, command_failure={"kind": secret, "exitcode": 3, "timed_out": False})
    assert probe.public_error(error) == {"reason": "publisher_transport_failed", "failure_type": "ReviewError"}
    class PrivateExceptionName(Exception):
        pass
    assert probe.public_error(PrivateExceptionName(secret)) == {"reason": "publisher_transport_failed", "failure_type": "Exception"}


def test_cleanup_failure_keeps_the_primary_stage_and_reason_with_redacted_separate_diagnostics():
    checks, failures, command_failures = {}, {}, {}
    primary = probe.failed_report(probe.ReviewError("broker_designated_requirement_missing"), "broker-designated-requirement", checks)
    def failed_cleanup():
        raise probe.ReviewError("review_command_failed", command_failure={"kind": "launchctl_bootout", "exitcode": 5, "timed_out": False})
    probe.cleanup_step("chrome_and_native_children_stopped", failed_cleanup, checks, failures, command_failures)
    result = probe.cleanup_result(primary, failures, command_failures)
    assert result["stage"] == "cleanup" and result["reason"] == "publisher_transport_cleanup_failed"
    assert result["failed_stage"] == "broker-designated-requirement"
    assert result["failed_reason"] == "broker_designated_requirement_missing"
    assert result["cleanup_failures"] == {"chrome_and_native_children_stopped": "review_command_failed"}
    assert result["cleanup_command_failures"] == {"chrome_and_native_children_stopped": {
        "kind": "launchctl_bootout", "exitcode": 5, "timed_out": False}}
    assert checks == {"chrome_and_native_children_stopped": False}
    def unknown_cleanup():
        raise ValueError("private unrelated data")
    probe.cleanup_step("created_service_identity_removed", unknown_cleanup, checks, failures, command_failures)
    assert failures["created_service_identity_removed"] == "ValueError"
    assert "private" not in json.dumps(probe.cleanup_result(primary, failures, command_failures)).replace("private_signins", "")


def test_successful_cleanup_keeps_the_exact_strict_success_contract():
    report = valid_report()
    assert probe.cleanup_result(report, {}, {}) is report
    assert checker.validate(report)


def test_absent_rule_cleanup_does_not_write_and_foreign_rule_is_preserved(monkeypatch):
    monkeypatch.setattr(probe, "authorization", lambda: None)
    monkeypatch.setattr(probe, "command", lambda *args, **kwargs: pytest.fail("No authorization write"))
    probe.remove_review_authorization("exact designated fixture")
    monkeypatch.setattr(probe, "authorization", lambda: {"identifier": "unrelated registrar"})
    with pytest.raises(probe.ReviewError, match="cleanup_authorization_changed"):
        probe.remove_review_authorization("exact designated fixture")


@pytest.mark.parametrize("damage", [None, "raw", "extra", "unknown-reason", "unknown-type", "unknown-command", "duplicate"])
def test_child_failures_propagate_only_the_strict_fixed_public_diagnostic(monkeypatch, damage):
    secret = "fixture-private-stdout-value"
    child = {"status": "FAILED", "reason": "production_transport_not_reached", "failure_type": "ReviewError", "production_ready": False}
    if damage == "extra":
        child["raw_output"] = secret
    elif damage == "unknown-reason":
        child["reason"] = secret
    elif damage == "unknown-type":
        child["failure_type"] = secret
    elif damage == "unknown-command":
        child["command_failure"] = {"kind": secret, "exitcode": 5, "timed_out": False}
    raw = secret.encode() if damage == "raw" else json.dumps(child).encode()
    if damage == "duplicate":
        raw = b'{"status":"FAILED","status":"FAILED","reason":"production_transport_not_reached","failure_type":"ReviewError","production_ready":false}'
    monkeypatch.setattr(probe, "command", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, raw, secret.encode()))
    with pytest.raises(probe.ReviewError) as caught:
        probe.owner_child_command(["/bin/launchctl", "asuser", "50023"], env={"SECRET": secret})
    report = probe.failed_report(caught.value, "chrome-owner-child", {})
    assert report["command_failure"] == {"kind": "launchctl_owner_child", "exitcode": 1, "timed_out": False}
    assert report.get("child_failure") == (child if damage is None else None)
    assert secret not in json.dumps(report)


def test_owner_child_restores_only_public_environment_after_sudo(monkeypatch):
    for key, value in hosted().items():
        monkeypatch.setenv(key, value)
    for key in ["GH_TOKEN", "PYTHONPATH", "DYLD_LIBRARY_PATH"]:
        monkeypatch.setenv(key, "private-fixture-value")
    prefix = Path("/Library/Application Support/account-access-publisher-qa-" + "1" * 16)
    home = Path("/Users/runner")
    temporary = prefix / "browser-tmp"
    args = probe.owner_child_arguments(501, "runner", home, prefix / "probe.py", prefix / "child.json", temporary=temporary)
    start = args.index("--") + 1
    assert args[start:start + 2] == ["/usr/bin/env", "-i"]
    end = args.index(str(probe.BASE / "runtime/bin/python"))
    values = dict(item.split("=", 1) for item in args[start + 2:end])
    assert set(values) == probe.ENV_KEYS | {"PATH", "LANG", "HOME", "TMPDIR"}
    assert values["HOME"] == str(home) and values["TMPDIR"] == str(temporary)
    assert args[end:] == [str(probe.BASE / "runtime/bin/python"), "-I", "-B", str(prefix / "probe.py"), "chrome-child", str(prefix / "child.json")]
    assert "private-fixture-value" not in repr(args)
    probe.guard(root=False, environment=values, system="darwin", machine="arm64", uid=501, euid=501)


def test_real_child_configuration_failure_reports_the_fixed_inner_stage_only(monkeypatch, capsys):
    from account_access import worker_bootstrap
    monkeypatch.setattr(probe, "guard", lambda **kwargs: None)
    def configuration(path):
        raise ModuleNotFoundError("private module/path text must be suppressed")
    monkeypatch.setattr(worker_bootstrap, "root_managed_path", configuration)
    assert probe.main(["chrome-child", "/private-unread-fixture"]) == 1
    value = json.loads(capsys.readouterr().out)
    assert value == {"status": "FAILED", "reason": "publisher_transport_failed", "failure_type": "ModuleNotFoundError",
                     "child_stage": "configuration", "production_ready": False}
    assert probe.public_child_failure(value) == value


def test_child_oserror_keeps_only_bounded_errno_and_fixed_stage(monkeypatch, capsys):
    def child(path):
        probe.CHILD_STAGE = "chrome-launch"
        raise PermissionError(13, "private OS detail", "/private/fixture-file")
    monkeypatch.setattr(probe, "child", child)
    assert probe.main(["chrome-child", "/ignored-fixture"]) == 1
    value = json.loads(capsys.readouterr().out)
    assert value == {"status": "FAILED", "reason": "publisher_transport_failed", "failure_type": "PermissionError",
                     "errno": 13, "child_stage": "chrome-launch", "production_ready": False}
    assert probe.public_child_failure(value) == value


@pytest.mark.parametrize("field,value", [("child_stage", "private-stage"), ("child_stage", []),
    ("errno", True), ("errno", -1), ("errno", 999999), ("errno", "13"), ("filename", "/private/path")])
def test_child_optional_diagnostics_accept_only_exact_fixed_values(field, value):
    child = {"status": "FAILED", "reason": "publisher_transport_failed", "failure_type": "Error", "production_ready": False}
    child[field] = value
    assert probe.public_child_failure(child) is None



def test_schema_two_explicitly_records_existing_runner_and_replaces_domain_claim():
    report = valid_report()
    assert len(checker.CHECKS) == 28
    assert "temporary_owner_identity_and_domain_removed" not in checker.CHECKS
    assert "temporary_browser_profile_and_registration_removed" in checker.CHECKS
    assert report["runner_identity_unchanged"] is True
    for key, value in [("schema", 1), ("owner_context", "temporary-owner"), ("runner_identity_unchanged", False)]:
        changed = copy.deepcopy(report)
        changed[key] = value
        assert not checker.validate(changed)


def runner_record(home="/Users/runner", uid=501, gid=20):
    return SimpleNamespace(pw_name="runner", pw_uid=uid, pw_gid=gid, pw_dir=str(home))


def test_existing_runner_is_derived_from_checkout_and_never_created(monkeypatch):
    owner = runner_record()
    source = SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=501))
    monkeypatch.setattr(probe.pwd, "getpwuid", lambda uid: owner)
    monkeypatch.setattr(probe.grp, "getgrgid", lambda gid: SimpleNamespace(gr_name="staff", gr_gid=20))
    monkeypatch.setattr(probe, "verify_runner_identity", lambda candidate: None)
    assert probe.runner_identity(source) is owner
    for uid in [0, 499, 50000]:
        with pytest.raises(probe.ReviewError, match="review_runner_identity_invalid"):
            probe.runner_identity(SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=uid)))


@pytest.mark.parametrize("field,value", [("pw_uid", 502), ("pw_gid", 21), ("pw_name", "other"), ("pw_dir", "/Users/other")])
def test_runner_identity_change_is_rejected_before_any_cleanup(monkeypatch, field, value):
    owner = runner_record()
    changed = SimpleNamespace(**vars(owner))
    setattr(changed, field, value)
    monkeypatch.setattr(probe.pwd, "getpwuid", lambda uid: changed)
    monkeypatch.setattr(probe.pwd, "getpwnam", lambda name: owner)
    with pytest.raises(probe.ReviewError, match="cleanup_identity_changed"):
        probe.verify_runner_identity(owner)


def test_runner_metadata_binds_home_inode_and_group_without_reading_contents(tmp_path, monkeypatch):
    owner = runner_record(tmp_path, os.getuid(), os.getgid())
    monkeypatch.setattr(probe, "verify_runner_identity", lambda actual: None)
    monkeypatch.setattr(probe.grp, "getgrgid", lambda gid: SimpleNamespace(gr_name="fixture", gr_gid=owner.pw_gid))
    before = probe.runner_metadata(owner)
    assert before[6:8] == (tmp_path.stat().st_dev, tmp_path.stat().st_ino)
    changed = list(before)
    changed[7] += 1
    assert tuple(changed) != before


@pytest.fixture
def registration_files(tmp_path, monkeypatch):
    owner = runner_record(tmp_path, os.getuid(), os.getgid())
    monkeypatch.setattr(probe, "verify_runner_identity", lambda candidate: None)
    paths = probe.registration_payloads(tmp_path)
    for path, data, mode in paths:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data)
        path.chmod(mode)
    return owner, paths


def test_exact_new_native_registration_is_captured_and_removed_without_browsing_reads(registration_files):
    owner, paths = registration_files
    sentinel = Path(owner.pw_dir) / "Library/Application Support/Google/Chrome/Default/private-placeholder"
    sentinel.parent.mkdir()
    sentinel.write_bytes(b"unread unrelated fixture")
    bindings = []
    probe.capture_registrations(owner, bindings)
    assert len(bindings) == 2 and all(set(item) == {"path", "stamp", "parents", "sha256"} for item in bindings)
    probe.remove_registrations(owner, bindings)
    assert all(not path.exists() for path, _, _ in paths)
    assert sentinel.read_bytes() == b"unread unrelated fixture"


def test_existing_registration_is_refused_without_mutation(registration_files):
    owner, paths = registration_files
    before = [(path.stat().st_ino, path.read_bytes()) for path, _, _ in paths]
    with pytest.raises(probe.ReviewError, match="existing_review_browser_registration"):
        probe.registration_absent(owner.pw_dir)
    assert before == [(path.stat().st_ino, path.read_bytes()) for path, _, _ in paths]


@pytest.mark.parametrize("damage", ["contents", "inode", "mode", "hardlink", "symlink", "parent"])
def test_substituted_registration_or_parent_is_preserved(registration_files, damage):
    owner, paths = registration_files
    bindings = []
    probe.capture_registrations(owner, bindings)
    path, data, mode = paths[0]
    if damage == "contents":
        path.write_bytes(b"unknown fixture")
    elif damage == "inode":
        replacement = path.with_name("replacement")
        replacement.write_bytes(data)
        replacement.chmod(mode)
        replacement.replace(path)
    elif damage == "mode":
        path.chmod(0o600)
    elif damage == "hardlink":
        os.link(path, path.with_name("other"))
    elif damage == "symlink":
        path.unlink()
        path.symlink_to(path.with_name("missing"))
    else:
        path.parent.rename(path.parent.with_name("original"))
        path.parent.mkdir(mode=0o700)
        path.write_bytes(data)
        path.chmod(mode)
    with pytest.raises((probe.ReviewError, OSError)):
        probe.remove_registrations(owner, bindings)
    assert path.exists() or path.is_symlink()
    assert paths[1][0].exists()


def test_partial_prepare_captures_only_recognized_created_file(registration_files):
    owner, paths = registration_files
    paths[1][0].unlink()
    bindings = []
    with pytest.raises(probe.ReviewError, match="review_registration_missing"):
        probe.capture_registrations(owner, bindings)
    assert [binding["path"] for binding in bindings] == [str(paths[0][0])]
    probe.remove_registrations(owner, bindings)
    assert not paths[0][0].exists()


def test_unknown_partial_prepare_file_is_preserved(registration_files):
    owner, paths = registration_files
    paths[0][0].write_bytes(b"unrecognized fixture")
    bindings = []
    with pytest.raises(probe.ReviewError, match="review_registration_changed"):
        probe.capture_registrations(owner, bindings)
    assert [binding["path"] for binding in bindings] == [str(paths[1][0])]
    with pytest.raises(probe.ReviewError, match="existing_review_browser_registration"):
        probe.remove_registrations(owner, bindings)
    assert paths[0][0].read_bytes() == b"unrecognized fixture"


def test_browser_cleanup_rescans_late_children_and_never_signals_runner_infrastructure(monkeypatch):
    owner = runner_record()
    calls = []
    scans = iter([("fresh-chrome",), ("fresh-native-child",), ()])
    api = SimpleNamespace(snapshot=lambda uid, roots: next(scans), stop=lambda ids, roots, **kwargs: calls.append(ids) or True)
    monkeypatch.setattr(probe, "verify_runner_identity", lambda actual: None)
    probe.stop_browser_processes(owner, api)
    assert calls == [("fresh-chrome",), ("fresh-native-child",)]


def test_browser_cleanup_failure_does_not_claim_exit_or_remove_the_profile(monkeypatch, tmp_path):
    owner = runner_record()
    api = SimpleNamespace(snapshot=lambda uid, roots: ("still-running",), stop=lambda *args, **kwargs: False)
    monkeypatch.setattr(probe, "verify_runner_identity", lambda actual: None)
    with pytest.raises(probe.ReviewError, match="cleanup_processes_still_running"):
        probe.stop_browser_processes(owner, api)
    with pytest.raises(probe.ReviewError, match="cleanup_processes_still_running"):
        probe.remove_browser_profile(tmp_path, (), owner, api)
    assert tmp_path.exists()


def test_fresh_browser_profile_removal_binds_the_original_directory(tmp_path, monkeypatch):
    owner = runner_record(tmp_path.parent, os.getuid(), os.getgid())
    profile = tmp_path / "browser-profile"
    profile.mkdir(mode=0o700)
    (profile / "fixture").write_bytes(b"test profile only")
    info = profile.lstat()
    stamp = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
    monkeypatch.setattr(probe, "verify_runner_identity", lambda actual: None)
    api = SimpleNamespace(snapshot=lambda uid, roots: ())
    probe.remove_browser_profile(profile, stamp, owner, api)
    assert not profile.exists()


def test_obsolete_owner_account_mutation_and_uid_wide_kill_paths_are_removed():
    source = Path(probe.__file__).read_text()
    assert '"/usr/bin/pkill"' not in source
    assert '"user/"' not in source
    assert "def fresh_owner_identity" not in source
    assert "def remove_owner_identity" not in source
    assert "def stop_uid" not in source


def test_process_helper_import_requires_exact_controller_revision_bytes(monkeypatch):
    monkeypatch.setattr(probe.sys, "modules", {})
    monkeypatch.setenv("GITHUB_SHA", REVISION)
    monkeypatch.setattr(probe, "git_file", lambda revision, name: b"changed helper fixture")
    with pytest.raises(probe.ReviewError, match="review_source_tree_changed"):
        probe.process_api()


def test_capture_contract_matches_actual_production_prepare_bytes(tmp_path, monkeypatch):
    from account_access.browser_setup import prepare
    from account_access.google_messages_host import RESOURCES
    owner = runner_record(tmp_path, os.getuid(), os.getgid())
    prepared = prepare(tmp_path, app=probe.APP / "Contents/MacOS/AccountAccess", resources=RESOURCES, protected=lambda path: None)
    assert prepared["status"] == "PREPARED"
    bindings = []
    probe.capture_registrations(owner, bindings)
    assert len(bindings) == 2
    monkeypatch.setattr(probe, "verify_runner_identity", lambda actual: None)
    probe.remove_registrations(owner, bindings)


def test_browser_cleanup_near_deadline_keeps_helper_options_inside_remaining_budget(monkeypatch):
    clock, calls = [0.0], []
    scans = iter([("fresh-chrome",), ()])
    def snapshot(uid, roots):
        clock[0] = 7.8
        return next(scans)
    def stop(ids, roots, **options):
        calls.append(options)
        assert 0 <= options["kill_after"] < options["timeout"] <= 8 - clock[0]
        return True
    monkeypatch.setattr(probe, "verify_runner_identity", lambda actual: None)
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    probe.stop_browser_processes(runner_record(), SimpleNamespace(snapshot=snapshot, stop=stop))
    assert len(calls) == 1 and calls[0]["timeout"] < 0.5


@pytest.mark.parametrize("reason", sorted(probe.PROCESS_ERROR_REASONS))
def test_fixed_process_inspection_reasons_are_preserved_without_loading_the_helper(monkeypatch, reason):
    class ProcessInspectionError(Exception):
        pass
    monkeypatch.setattr(probe, "process_api", lambda: pytest.fail("Error formatting must not import or inspect processes"))
    assert probe.public_error(ProcessInspectionError(reason)) == {"reason": reason, "failure_type": "ProcessInspectionError"}


def test_unknown_process_inspection_text_and_wrong_exception_types_remain_redacted(monkeypatch):
    class ProcessInspectionError(Exception):
        pass
    monkeypatch.setattr(probe, "process_api", lambda: pytest.fail("Error formatting must not import or inspect processes"))
    assert probe.public_error(ProcessInspectionError("private path or kernel text")) == {
        "reason": "publisher_transport_failed", "failure_type": "ProcessInspectionError"}
    assert probe.public_error(ValueError("process_path_read_failed")) == {
        "reason": "publisher_transport_failed", "failure_type": "ValueError"}


@pytest.mark.parametrize("category", sorted(probe.NATIVE_CATEGORIES))
@pytest.mark.parametrize("phase", ["first", "second"])
def test_only_fixed_native_phase_category_leaves_error_formatter(category, phase):
    failure = {"status": "FAILED", "phase": phase, "category": category}
    with pytest.raises(probe.ReviewError) as caught:
        probe.check_native_exchange(failure)
    detail = probe.public_error(caught.value)
    assert detail == {"reason": "production_native_" + category, "failure_type": "ReviewError",
                      "native_failure": {"phase": phase, "category": category}}
    child = {"status": "FAILED", **detail, "production_ready": False, "child_stage": "native-exchange"}
    assert probe.public_child_failure(child) == child


@pytest.mark.parametrize("changed", [{"raw": "private response"}, {"phase": "private-phase"},
    {"category": "private-error"}, {"phase": []}, {"category": []}, {"status": "other"}])
def test_malformed_native_failure_and_private_fields_are_rejected(changed):
    value = {"status": "FAILED", "phase": "first", "category": "unknown", **changed}
    with pytest.raises(probe.ReviewError) as caught:
        probe.check_native_exchange(value)
    detail = probe.public_error(caught.value)
    assert detail == {"reason": "production_transport_not_reached", "failure_type": "ReviewError"}
    assert "private" not in json.dumps(detail)
    child = {"status": "FAILED", "reason": "production_native_unknown", "failure_type": "ReviewError",
             "production_ready": False, "native_failure": {key: item for key, item in value.items() if key != "status"}}
    if "status" in changed:
        child["native_failure"]["status"] = changed["status"]
    assert probe.public_child_failure(child) is None


def native_wrapper_result(*, scenario="success", message="", phase="first", permission=False):
    import shutil
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required only for the pure JavaScript public fixture")
    fixture = {"wrapper": probe.NATIVE_EXCHANGE_JS, "scenario": scenario, "message": message,
               "phase": phase, "permission": permission}
    script = r'''const fs=require("fs"), input=JSON.parse(fs.readFileSync(0,"utf8"));
let calls=0;
global.chrome={runtime:{getManifest:()=>({permissions:["nativeMessaging","alarms"]})},
  permissions:{getAll:async()=>({origins:input.permission?["https://private.fixture/"]:[],permissions:["nativeMessaging","alarms"]})}};
global.port=null;
global.native=()=>{
  calls++;
  const listeners=[];
  const current={onDisconnect:{addListener:listener=>listeners.push(listener),removeListener:listener=>{}}};
  global.port=current;
  const target=input.phase==="first"?1:2;
  if(calls!==target || input.scenario==="success") return Promise.resolve({status:"NEEDS_USER",reason:"vault_setup_required"});
  if(input.scenario==="reply") return Promise.resolve({password:"private native reply",status:"NEEDS_USER",reason:"vault_setup_required"});
  if(input.scenario==="timeout") return Promise.reject(new Error("The local SMS connection timed out."));
  if(input.scenario==="exception") return Promise.reject(new Error(input.message));
  return new Promise((resolve,reject)=>setImmediate(()=>{
    chrome.runtime.lastError=input.message===null?undefined:{message:input.message};
    for(const listener of listeners) listener();
    reject(new Error("Open Account Access and prepare the SMS connection first."));
  }));
};
(async()=>{const value=await eval("("+input.wrapper+")")();console.log(JSON.stringify({value,calls}));})().catch(()=>process.exit(2));'''
    result = subprocess.run([node, "-e", script], input=json.dumps(fixture).encode(), capture_output=True, timeout=5, check=True)
    assert not result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("message,category", [
    ("Specified native messaging host not found.", "host_not_found"),
    ("Native host has exited.", "host_exited"),
    ("Failed to start native messaging host.", "failed_start"),
    ("Error when communicating with the native messaging host.", "disconnected"),
    ("Access to the specified native messaging host is forbidden.", "forbidden"),
    (None, "disconnected"), ("private message with path or code", "unknown"),
])
@pytest.mark.parametrize("phase", ["first", "second"])
def test_actual_worker_wrapper_classifies_only_exact_chrome_disconnect_messages(message, category, phase):
    result = native_wrapper_result(scenario="disconnect", message=message, phase=phase)
    assert result == {"value": {"status": "FAILED", "phase": phase, "category": category}, "calls": 1 if phase == "first" else 2}
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("scenario,category", [("reply", "unknown"), ("exception", "unknown"), ("timeout", "timeout")])
def test_actual_worker_wrapper_never_exports_unexpected_native_replies_or_errors(scenario, category):
    result = native_wrapper_result(scenario=scenario, message="private exception text")
    assert result == {"value": {"status": "FAILED", "phase": "first", "category": category}, "calls": 1}
    assert "private" not in json.dumps(result)


def test_actual_worker_wrapper_preserves_both_exact_replies_and_permission_requirements():
    result = native_wrapper_result()
    assert result["calls"] == 2
    probe.check_native_exchange(result["value"])
    permission = native_wrapper_result(permission=True)
    assert permission["calls"] == 2 and permission["value"]["permissions_match"] is False
    assert "private" not in json.dumps(permission)
    with pytest.raises(probe.ReviewError, match="review_optional_permission_granted"):
        probe.check_native_exchange(permission["value"])


def isolated_profile(tmp_path, owner):
    profile = tmp_path / "isolated-profile"
    profile.mkdir(mode=0o700)
    return profile, probe.profile_stamp(profile)


def test_isolated_profile_registration_copies_exact_bound_production_bytes(registration_files, tmp_path):
    owner, paths = registration_files
    bindings = []
    probe.capture_registrations(owner, bindings)
    profile, stamp = isolated_profile(tmp_path, owner)
    captured = probe.install_profile_registration(profile, stamp, owner, bindings)
    target = profile / "NativeMessagingHosts" / paths[1][0].name
    assert target.read_bytes() == paths[1][0].read_bytes()
    assert target.stat().st_uid == owner.pw_uid and stat.S_IMODE(target.stat().st_mode) == 0o600
    assert captured == probe.capture_profile_registration(profile, owner)
    assert captured["sha256"] == bindings[1]["sha256"]
    assert "fresh_profile_registration_matches_production" in checker.CHECKS
    probe.remove_browser_profile(profile, stamp, owner, SimpleNamespace(snapshot=lambda *args: ()), captured)
    assert not profile.exists() and all(path.exists() for path, _, _ in paths)


@pytest.mark.parametrize("damage", ["populated-profile", "source-inode", "source-bytes"])
def test_profile_copy_refuses_existing_content_or_changed_production_source(registration_files, tmp_path, damage):
    owner, paths = registration_files
    bindings = []
    probe.capture_registrations(owner, bindings)
    profile, stamp = isolated_profile(tmp_path, owner)
    if damage == "populated-profile":
        (profile / "preserve").write_text("unknown fixture")
    elif damage == "source-inode":
        path, data, mode = paths[1]
        path.unlink()
        path.write_bytes(data)
        path.chmod(mode)
    else:
        paths[1][0].write_bytes(b"changed fixture")
    with pytest.raises(probe.ReviewError):
        probe.install_profile_registration(profile, stamp, owner, bindings)
    assert profile.exists() and not (profile / "NativeMessagingHosts").exists()


@pytest.mark.parametrize("damage", ["bytes", "inode", "symlink", "mode", "directory"])
def test_isolated_profile_cleanup_preserves_changed_registration(registration_files, tmp_path, damage):
    owner, paths = registration_files
    bindings = []
    probe.capture_registrations(owner, bindings)
    profile, stamp = isolated_profile(tmp_path, owner)
    captured = probe.install_profile_registration(profile, stamp, owner, bindings)
    target = profile / "NativeMessagingHosts" / paths[1][0].name
    if damage == "bytes":
        target.write_bytes(b"changed fixture")
    elif damage == "inode":
        data = target.read_bytes()
        target.unlink()
        target.write_bytes(data)
        target.chmod(0o600)
    elif damage == "symlink":
        target.unlink()
        target.symlink_to(paths[1][0])
    elif damage == "mode":
        target.chmod(0o644)
    else:
        target.parent.rename(profile / "original")
        target.parent.mkdir(mode=0o700)
        target.write_bytes(paths[1][1])
        target.chmod(0o600)
    with pytest.raises((probe.ReviewError, OSError)):
        probe.remove_browser_profile(profile, stamp, owner, SimpleNamespace(snapshot=lambda *args: ()), captured)
    assert profile.exists() and (target.exists() or target.is_symlink())


def test_profile_registration_destination_uses_descriptors_and_no_path_chown(registration_files, tmp_path, monkeypatch):
    owner, _paths = registration_files
    bindings = []
    probe.capture_registrations(owner, bindings)
    profile, stamp = isolated_profile(tmp_path, owner)
    monkeypatch.setattr(probe.os, "chown", lambda *args, **kwargs: pytest.fail("Path-based chown must not be used"))
    result = probe.install_profile_registration(profile, stamp, owner, bindings)
    assert result == probe.capture_profile_registration(profile, owner)


def test_profile_registration_refuses_destination_parent_symlink_without_external_writes(registration_files, tmp_path, monkeypatch):
    owner, _paths = registration_files
    bindings = []
    probe.capture_registrations(owner, bindings)
    profile, stamp = isolated_profile(tmp_path, owner)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    original_open = probe.os.open
    def changed_open(path, flags, *args, **kwargs):
        if path == "NativeMessagingHosts":
            (profile / "NativeMessagingHosts").rmdir()
            (profile / "NativeMessagingHosts").symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(probe.os, "open", changed_open)
    with pytest.raises(OSError):
        probe.install_profile_registration(profile, stamp, owner, bindings)
    assert not list(outside.iterdir())


def test_profile_registration_refuses_namespace_swap_after_writing_bound_directory(registration_files, tmp_path, monkeypatch):
    owner, _paths = registration_files
    bindings = []
    probe.capture_registrations(owner, bindings)
    profile, stamp = isolated_profile(tmp_path, owner)
    original_capture = probe.capture_profile_registration
    def changed_capture(profile, owner):
        (profile / "NativeMessagingHosts").rename(profile / "original")
        replacement = profile / "NativeMessagingHosts"
        replacement.mkdir(mode=0o700)
        target = replacement / "com.account_access.google_messages.json"
        target.write_bytes(probe.registration_payloads(owner.pw_dir)[1][1])
        target.chmod(0o600)
        return original_capture(profile, owner)
    monkeypatch.setattr(probe, "capture_profile_registration", changed_capture)
    with pytest.raises(probe.ReviewError, match="review_registration_changed"):
        probe.install_profile_registration(profile, stamp, owner, bindings)
    assert (profile / "original").is_dir() and (profile / "NativeMessagingHosts").is_dir()
