"""Failure-only disposable-CI metadata never expands the agent's public API."""

import json
import subprocess
from types import SimpleNamespace

import httpx2 as httpx
import pytest

from account_access.storage import private_file
from scripts import mac_signed_chrome_probe as probe
from scripts.check_mac_signed_chrome_report import validate, validate_child


def details():
    return {"http": {"stage": "http_error", "error": "ReadTimeout"},
            "pending": {"status": "available", "present": True, "phase": "watch", "source_enabled": True}}


def report():
    return {"status": "FAILED", "stage": "sms-login", "failure": "browser_fixture_cli_service_unavailable",
            "fixture_sms_forwarded": False, "production_ready": False, "private_signins": 0,
            "service": {"checked": True, "root_host_alive": True, "worker_alive": True,
                        "root_identity_matches": True, "worker_identity_matches": True},
            "provider": {"checked": True, "identity_submissions": 1, "password_submissions": 0,
                         "sms_submissions": 0},
            "sms_progress": {"completed_cli_reads": 0, "synthetic_dom_inserted": False, "active_cli": True},
            "sms_details": details()}


@pytest.mark.parametrize("kind", ["ConnectError", "ConnectTimeout", "ReadTimeout", "WriteTimeout", "RemoteProtocolError"])
def test_real_cli_preserves_public_error_and_records_only_http_exception_class(tmp_path, monkeypatch, capsys, kind):
    (tmp_path / "signed-chrome-tmp").mkdir(mode=0o700)
    token = tmp_path / "token"
    private_file(token, b"fictional-private-canary-token")
    private_file(tmp_path / "agent-client/native-host-client.json", json.dumps(
        {"token_file": str(token), "socket": str(tmp_path / "fictional.sock")}).encode())
    monkeypatch.setattr(probe, "require_fixture", lambda *args, **kwargs: SimpleNamespace(pw_dir=str(tmp_path)))
    calls = []

    def request(client, method, path, **kwargs):
        calls.append((method, path))
        raise getattr(httpx, kind)("fictional-private-canary-url-body-token")

    monkeypatch.setattr(httpx.Client, "request", request)
    monkeypatch.setenv("ACCESS_CLIENT_CONFIG", "unchanged-test-config")
    assert probe.diagnostic_cli(tmp_path) == 2
    assert json.loads(capsys.readouterr().out) == {"status": "RETRYABLE", "reason": "service_unavailable"}
    assert probe.read_http_diagnostic(tmp_path) == {"stage": "http_error", "error": kind}
    assert calls == [("POST", "/v1/run")]
    assert httpx.Client.request is request
    assert probe.os.environ["ACCESS_CLIENT_CONFIG"] == "unchanged-test-config"
    assert "private-canary" not in (tmp_path / "signed-chrome-tmp" / probe.HTTP_DIAGNOSTIC).read_text()


def test_http_recording_failure_cannot_change_cli_result(tmp_path, monkeypatch, capsys):
    token = tmp_path / "token"
    private_file(token, b"fictional")
    private_file(tmp_path / "agent-client/native-host-client.json", json.dumps(
        {"token_file": str(token), "socket": str(tmp_path / "fictional.sock")}).encode())
    monkeypatch.setattr(probe, "require_fixture", lambda *args, **kwargs: SimpleNamespace(pw_dir=str(tmp_path)))
    monkeypatch.setattr(probe, "private_file", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("private-canary")))
    monkeypatch.setattr(httpx.Client, "request", lambda *args, **kwargs: (_ for _ in ()).throw(httpx.ReadError("private-canary")))
    assert probe.diagnostic_cli(tmp_path) == 2
    assert json.loads(capsys.readouterr().out) == {"status": "RETRYABLE", "reason": "service_unavailable"}
    assert probe.read_http_diagnostic(tmp_path) == {"stage": "unavailable", "error": "none"}


def test_diagnostic_wrapper_preserves_success_output_and_does_not_emit_metadata(tmp_path, monkeypatch, capsys):
    (tmp_path / "signed-chrome-tmp").mkdir(mode=0o700)
    token = tmp_path / "token"
    private_file(token, b"fictional")
    private_file(tmp_path / "agent-client/native-host-client.json", json.dumps(
        {"token_file": str(token), "socket": str(tmp_path / "fictional.sock")}).encode())
    monkeypatch.setattr(probe, "require_fixture", lambda *args, **kwargs: SimpleNamespace(pw_dir=str(tmp_path)))
    expected = {"status": "COMPLETED", "data": {"balance": "987.65", "currency": "ILS"}}
    monkeypatch.setattr(httpx.Client, "request", lambda *args, **kwargs: httpx.Response(200, json=expected))
    assert probe.diagnostic_cli(tmp_path) == 0
    assert json.loads(capsys.readouterr().out) == expected
    assert probe.read_http_diagnostic(tmp_path) == {"stage": "completed", "error": "none"}


def test_diagnostic_cli_refuses_an_ordinary_mac_before_reading_config(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(probe, "root_managed_path", lambda *args: pytest.fail("guard before path access"))
    with pytest.raises(RuntimeError, match="signed_chrome_requires_disposable_mac_ci"):
        probe.diagnostic_cli(tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("change", [
    {"error": "fictional-private-canary"}, {"stage": "http_error", "error": "none"},
    {"stage": "completed", "error": "ReadTimeout"}, {"stage": True}, {"raw": "private-canary"},
])
def test_http_metadata_rejects_unknown_classes_fields_and_inconsistent_stage(change):
    value = {"stage": "http_error", "error": "ReadTimeout"}
    value.update(change)
    assert probe.http_diagnostic(value) is None


def test_http_sidecar_refuses_wrong_type_permissions_links_and_oversize(tmp_path):
    directory = tmp_path / "signed-chrome-tmp"
    directory.mkdir()
    target = directory / probe.HTTP_DIAGNOSTIC
    private_file(target, json.dumps({"stage": "started", "error": "none"}).encode())
    assert probe.read_http_diagnostic(tmp_path) == {"stage": "started", "error": "none"}
    target.chmod(0o644)
    assert probe.read_http_diagnostic(tmp_path)["stage"] == "unavailable"
    target.unlink()
    target.symlink_to(tmp_path / "private-canary")
    assert probe.read_http_diagnostic(tmp_path)["stage"] == "unavailable"
    target.unlink()
    private_file(target, b" " * 513)
    assert probe.read_http_diagnostic(tmp_path)["stage"] == "unavailable"


def test_pending_probe_has_fixed_cap_and_discards_raw_or_invalid_native_data():
    calls = []

    def evaluate(script):
        calls.append(script)
        assert "1500" in script and "Promise.race" in script
        assert "item?.source === 'chrome-sms'" in script
        return details()["pending"]

    assert probe.read_pending_diagnostic(SimpleNamespace(evaluate=evaluate)) == details()["pending"]
    assert len(calls) == 1
    value = {**details()["pending"], "code": "123456", "private": "private-canary"}
    assert probe.read_pending_diagnostic(SimpleNamespace(evaluate=lambda _: value)) == {
        "status": "unavailable", "present": False, "phase": "none", "source_enabled": False}


@pytest.mark.parametrize("change", [
    {"status": "timeout"}, {"present": 1}, {"phase": "private-canary"},
    {"present": False}, {"source_enabled": 1}, {"raw_output": "private-canary"},
])
def test_pending_metadata_rejects_non_boolean_inconsistent_and_unknown_fields(change):
    value = details()["pending"]
    value.update(change)
    assert probe.pending_diagnostic(value) is None


def test_service_liveness_is_read_only_fixed_metadata_without_pids_or_ps_output(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert args[0] == "/bin/ps" and kwargs["timeout"] == 2
        data = b"0 0 100 1\n" if args[2] == "100" else b"203 204 100 100\n"
        return subprocess.CompletedProcess(args, 0, stdout=data, stderr=b"private-canary")

    monkeypatch.setattr(probe.subprocess, "run", run)
    roles = {"broker": SimpleNamespace(pw_uid=203, pw_gid=204)}
    value = probe.service_diagnostic(roles, {"root_pid": 100, "worker_pid": 101})
    assert value == dict.fromkeys(["checked", "root_host_alive", "worker_alive",
                                   "root_identity_matches", "worker_identity_matches"], True)
    assert len(calls) == 2 and "private-canary" not in json.dumps(value)
    assert "100" not in json.dumps(value) and "101" not in json.dumps(value)


def test_bad_service_identity_never_inspects_a_process(monkeypatch):
    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: pytest.fail("no process inspection"))
    for identity in [None, {}, {"root_pid": True, "worker_pid": 101}, {"root_pid": 0, "worker_pid": 101}]:
        assert not probe.service_diagnostic({}, identity)["checked"]


def test_fictional_provider_counter_overflow_is_not_serialized():
    provider = SimpleNamespace(login_count=4, sms_count=3, identity_count=5)
    assert probe.provider_diagnostic(provider, (3, 3, 4)) == {
        "checked": True, "identity_submissions": 1, "password_submissions": 1, "sms_submissions": 0}
    provider.login_count = 99
    assert probe.provider_diagnostic(provider, (0, 0, 0)) == {
        "checked": False, "identity_submissions": 0, "password_submissions": 0, "sms_submissions": 0}


def test_failure_artifact_is_strict_bounded_and_can_never_satisfy_success_checkers():
    value = report()
    assert probe.failure_report(value) == value
    assert not validate(value) and not validate_child(value)
    mutations = [
        lambda v: v.update(raw="private-canary"), lambda v: v.update(stage="private-canary"),
        lambda v: v.update(private_signins=True), lambda v: v.update(production_ready=True),
        lambda v: v["service"].update(worker_pid=999),
        lambda v: v["service"].update(worker_alive=False),
        lambda v: v["provider"].update(password_submissions=3),
        lambda v: v["provider"].update(password_submissions=True),
        lambda v: v["sms_details"]["http"].update(error="private-canary"),
        lambda v: v["sms_details"]["pending"].update(code="123456"),
    ]
    for mutate in mutations:
        value = report()
        mutate(value)
        assert probe.failure_report(value) is None


def test_child_emits_only_validated_details_when_it_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(probe, "require_fixture", lambda *args, **kwargs: None)

    def failed(prefix):
        probe.stage("sms-login")
        probe.SMS_FAILURE_DETAILS = details()
        raise RuntimeError("browser_fixture_cli_service_unavailable")

    monkeypatch.setattr(probe, "run_child", failed)
    assert probe.main(["--prefix", str(tmp_path)]) == 1
    value = json.loads(capsys.readouterr().out)
    assert value == {"status": "FAILED", "reason": "signed_chrome_roundtrip_failed", "stage": "sms-login",
                     "failure": "browser_fixture_cli_service_unavailable", "sms_details": details()}
