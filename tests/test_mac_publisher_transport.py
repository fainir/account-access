"""Public fixtures only; never install, launch a peer, or change OS authority."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
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
    for name in ["AccountAccess-broker", "AccountAccess-bootstrap"]:
        (support / "bin" / name).write_bytes(b"public fixture " + name.encode())
    (support / "runtime/python").write_bytes(b"public fixture runtime")
    (support / "runtime/current").symlink_to("python")
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
    result = {"schema": 1, "status": "PASSED", "platform": "macos", "architecture": "arm64",
              "environment": "disposable-hosted-ci-public-review", "source_revision": REVISION,
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


def test_name_collision_is_not_reused_even_when_uid_is_free(monkeypatch):
    def absent(_value):
        raise KeyError()

    monkeypatch.setattr(probe.pwd, "getpwuid", absent)
    monkeypatch.setattr(probe.grp, "getgrgid", absent)
    monkeypatch.setattr(probe.pwd, "getpwnam", absent)
    monkeypatch.setattr(probe.grp, "getgrnam", lambda name: object() if name == "aap" + "1" * 12 else absent(name))
    tokens = iter(["1" * 12, "2" * 12])
    monkeypatch.setattr(probe.secrets, "token_hex", lambda _size: next(tokens))
    monkeypatch.setattr(probe.secrets, "randbelow", lambda _upper: 23)
    assert probe.fresh_owner_identity() == (50023, "aap" + "2" * 12)


def test_cleanup_requires_observed_uid_process_exit(monkeypatch):
    clock, calls = [0], []
    observations = iter([[123], [123], [123], [123], []])
    monkeypatch.setattr(probe, "uid_processes", lambda uid: next(observations))
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(probe.time, "sleep", lambda _seconds: clock.__setitem__(0, clock[0] + 0.6))
    monkeypatch.setattr(probe, "command", lambda args, **_kwargs: calls.append(args))
    probe.stop_uid(50023)
    assert calls == [["/usr/bin/pkill", "-TERM", "-u", "50023"],
                     ["/usr/bin/pkill", "-KILL", "-u", "50023"]]


def test_cleanup_stuck_processes_fail_instead_of_claiming_success(monkeypatch):
    clock = [0]
    monkeypatch.setattr(probe, "uid_processes", lambda uid: [123])
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(probe.time, "sleep", lambda _seconds: clock.__setitem__(0, clock[0] + 1))
    monkeypatch.setattr(probe, "command", lambda *_args, **_kwargs: None)
    with pytest.raises(probe.ReviewError, match="cleanup_processes_still_running"):
        probe.stop_uid(50023)


def test_process_query_reads_only_pid_uid_and_filters_exact_identity(monkeypatch):
    calls = []

    def command(args):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, b" 100 0\n 101 50023\n 102 50024\n", b"")

    monkeypatch.setattr(probe, "command", command)
    assert probe.uid_processes(50023) == [101]
    assert calls == [["/bin/ps", "-Ao", "pid=,uid="]]


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
    assert json.loads(capsys.readouterr().out) == {"status": "FAILED", "reason": "review_draft_metadata_unavailable", "production_ready": False}
    assert not (tmp_path / "must-not-exist").exists()
