import json
import io
import signal
import subprocess
from types import SimpleNamespace

import pytest

from scripts.check_mac_protected_browser_report import CHECKS, UNVERIFIED, VERIFIED, main, validate
from scripts.mac_protected_browser_fixture import exercise_browser_gateway


def report():
    return dict(
        status="PASSED", platform="macos", environment="controlled-demo", production_ready=False,
        private_signins=0, checks=dict.fromkeys(CHECKS, True),
        **dict.fromkeys(VERIFIED, True), **dict.fromkeys(UNVERIFIED, False),
    )


def test_every_composed_native_browser_check_is_mandatory(tmp_path):
    assert len(CHECKS) == 18 and validate(report())
    for key in CHECKS:
        for replacement in [False, None, 1, "true"]:
            value = report()
            value["checks"][key] = replacement
            assert not validate(value)
        value = report()
        del value["checks"][key]
        assert not validate(value)
    target = tmp_path / "report.json"
    target.write_text(json.dumps(report()))
    assert main([str(target)]) == 0


@pytest.mark.parametrize("key", sorted(VERIFIED | UNVERIFIED))
def test_native_browser_evidence_cannot_change_its_verified_scope(key):
    value = report()
    value[key] = not value[key]
    assert not validate(value)
    value[key] = 1 if key in VERIFIED else 0
    assert not validate(value)


@pytest.mark.parametrize("key,value", [
    ("production_ready", True), ("private_signins", True), ("private_signins", 1),
    ("environment", "personal"), ("platform", "linux"),
])
def test_native_browser_evidence_cannot_claim_private_or_consumer_acceptance(key, value):
    changed = report()
    changed[key] = value
    assert not validate(changed)


def test_native_browser_journey_refuses_an_ordinary_mac_before_any_file_write(tmp_path):
    with pytest.raises(RuntimeError, match="protected_browser_requires_disposable_mac_ci"):
        exercise_browser_gateway(tmp_path, None, None, None, "a" * 40)
    assert not list(tmp_path.iterdir())


def test_native_browser_journey_rejects_unrelated_ci_identity_before_paths(tmp_path, monkeypatch):
    import scripts.mac_protected_browser_fixture as fixture

    monkeypatch.setattr(fixture.sys, "platform", "darwin")
    monkeypatch.setattr(fixture.os, "getuid", lambda: 0)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    roles = {"agent": SimpleNamespace(pw_uid=501, pw_dir="/Users/owner"),
             "broker": SimpleNamespace(pw_uid=502)}
    with pytest.raises(RuntimeError, match="protected_browser_requires_fixture_identity"):
        exercise_browser_gateway(tmp_path, roles, None, None, "a" * 40)
    assert not list(tmp_path.iterdir())


def test_system_key_fixture_seeds_distinct_native_framed_and_chrome_sms_accounts(tmp_path, monkeypatch):
    import secrets

    from account_access.models import Configuration
    from account_access.storage import Store
    from scripts import mac_key_handoff_probe as handoff
    from scripts.mac_native_sms_fixture import native_account

    tmp_path.chmod(0o700)
    store = Store(tmp_path, secrets.token_bytes(32))
    store.configure(Configuration(test_mode=True, accounts={}))
    monkeypatch.setattr("account_access.worker_bootstrap.root_managed_path", lambda path: path)
    monkeypatch.setattr(handoff.runpy, "run_path", lambda path: {"native_account": native_account})
    handoff.seed_native_host_fixture(store, {
        "provider_url": "http://127.0.0.1:1234", "client_digest": "a" * 64,
    })
    config = store.config()
    assert set(config.accounts) == {"native-sms", "browser-sms", "chrome-sms"}
    assert config.accounts["native-sms"].login.factor("sms").code_source == "native-sms"
    assert config.accounts["browser-sms"].login.factor("sms").code_source == "browser-sms"
    assert config.code_sources["native-sms"].kind == "mac_messages"
    assert config.code_sources["browser-sms"].kind == "google_messages"
    assert config.accounts["chrome-sms"].login.factor("sms").code_source == "chrome-sms"
    assert config.code_sources["chrome-sms"].kind == "google_messages"
    assert store.get("credential:chrome-sms") == store.get("credential:browser-sms")
    assert store.get("source:chrome-sms") == {"enabled": True}
    assert config.test_mode is True


@pytest.mark.parametrize("contents", [None, b"", b"{}", b"null", b"not JSON"])
def test_missing_or_malformed_native_browser_evidence_fails(tmp_path, contents):
    target = tmp_path / "report.json"
    if contents is not None:
        target.write_bytes(contents)
    assert main([str(target)]) == 1


class Child:
    def __init__(self, *, status=None, stubborn=False, unkillable=False):
        self.pid = 999
        self.returncode = status
        self.stdin, self.stdout, self.stderr = io.BytesIO(), io.BytesIO(), None
        self.stubborn, self.unkillable = stubborn, unkillable
        self.waits = []

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.waits.append(timeout)
        if self.unkillable or (self.stubborn and len(self.waits) == 1):
            raise subprocess.TimeoutExpired("fixture", timeout)
        self.returncode = 0
        return self.returncode


def test_fixture_cleanup_escalates_ignored_term_and_reaps_without_threads(monkeypatch):
    from scripts import mac_protected_browser_fixture as fixture

    calls = []
    monkeypatch.setattr(fixture.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    child = Child(stubborn=True)
    clients = fixture.ClientReads([], {}, 0)
    clients.process = child
    clients.close()
    assert calls == [(999, signal.SIGTERM), (999, signal.SIGKILL)]
    assert child.waits == [1, 2] and child.returncode == 0
    assert clients.process is None and child.stdin.closed and child.stdout.closed


def test_fixture_cleanup_reaps_an_exited_child_without_signaling(monkeypatch):
    from scripts import mac_protected_browser_fixture as fixture

    monkeypatch.setattr(fixture.os, "killpg", lambda *args: pytest.fail("exited child must not be signaled"))
    child = Child(status=0)
    fixture.stop_process(child)
    assert child.waits == [0] and child.stdin.closed and child.stdout.closed


def test_fixture_cleanup_still_closes_streams_when_kill_cannot_reap(monkeypatch):
    from scripts import mac_protected_browser_fixture as fixture

    monkeypatch.setattr(fixture.os, "killpg", lambda *args: None)
    child = Child(unkillable=True)
    with pytest.raises(RuntimeError, match="browser_fixture_child_did_not_stop"):
        fixture.stop_process(child)
    assert child.waits == [1, 2] and child.stdin.closed and child.stdout.closed


def test_expired_shared_deadline_never_launches_another_cli_or_writes_a_frame(monkeypatch):
    from scripts import mac_protected_browser_fixture as fixture

    monkeypatch.setattr(fixture.time, "monotonic", lambda: 100)
    monkeypatch.setattr(fixture.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("deadline passed"))
    clients = fixture.ClientReads([], {}, 99)
    with pytest.raises(RuntimeError, match="browser_fixture_deadline_expired"):
        clients.tick()
    child = Child()
    with pytest.raises(RuntimeError, match="browser_fixture_deadline_expired"):
        fixture.Frames(child, 99).request({"method": "pending"})
    assert child.stdin.getvalue() == b""


def test_frame_failure_immediately_cancels_cli_then_native_and_restores_delivery(tmp_path, monkeypatch):
    from scripts import mac_protected_browser_fixture as fixture

    native, cli = Child(), Child()
    cli.pid = 998
    signals = []
    monkeypatch.setattr(fixture, "require_fixture", lambda *args: None)
    monkeypatch.setattr(fixture, "root_managed_path", lambda *args: None)
    monkeypatch.setattr(fixture.subprocess, "Popen", lambda *args, **kwargs: native)
    monkeypatch.setattr(fixture.os, "killpg", lambda pid, sig: signals.append((pid, sig)))

    class PendingClient:
        def __init__(self, *args):
            pass

        def tick(self):
            return False

        def close(self):
            fixture.stop_process(cli)

    class BrokenFrame:
        def __init__(self, *args):
            self.polls = 0

        def request(self, body):
            if body["method"] == "session-import":
                return {"status": "DENIED", "reason": "unsupported_browser_connection_request"}
            if body["method"] == "connect":
                return {"status": "NEEDS_USER", "reason": "browser_connection_unavailable"}
            self.polls += 1
            if self.polls == 3:
                raise RuntimeError("synthetic_frame_failure")
            return {"pending": [], "source_enabled": True}

    monkeypatch.setattr(fixture, "ClientReads", PendingClient)
    monkeypatch.setattr(fixture, "Frames", BrokenFrame)
    original_delivery = object()
    provider = SimpleNamespace(delivery=original_delivery, login_count=0, sms_count=0, identity_count=0)
    roles = {"agent": SimpleNamespace(pw_uid=1234, pw_gid=1234)}
    with pytest.raises(RuntimeError, match="synthetic_frame_failure"):
        fixture.exercise_browser_gateway(tmp_path, roles, SimpleNamespace(provider=provider),
                                         tmp_path / "fictional-client.json", "a" * 40)
    assert signals == [(998, signal.SIGTERM), (999, signal.SIGTERM)]
    assert native.waits == cli.waits == [1]
    assert provider.delivery is original_delivery


def completed_reply():
    return dict(status="COMPLETED", account="browser-sms", operation="summary", environment="controlled-demo",
                environment_source="connector-configuration", data={"balance": "987.65", "currency": "ILS"},
                untrusted_data=True)


def test_cli_acceptance_requires_exact_public_result_and_rejects_secret_fields():
    from account_access.demo import DEMO_PASSWORD
    from scripts.mac_protected_browser_fixture import completed_cli

    value = completed_reply()
    assert completed_cli(json.dumps(value)) == value
    chrome = {**value, "account": "chrome-sms"}
    assert completed_cli(json.dumps(chrome), account="chrome-sms") == chrome
    with pytest.raises(RuntimeError, match="browser_fixture_cli_failed"):
        completed_cli(json.dumps(value), account="chrome-sms")
    with pytest.raises(RuntimeError, match="browser_fixture_cli_failed"):
        completed_cli(json.dumps(chrome))
    for key, secret in [("password", DEMO_PASSWORD), ("session", "fixture-session"), ("code", "123456")]:
        with pytest.raises(RuntimeError, match="browser_fixture_cli_failed"):
            completed_cli(json.dumps({**value, key: secret}))
    with pytest.raises(RuntimeError, match="browser_fixture_cli_failed"):
        completed_cli('{"password":"' + DEMO_PASSWORD + '",' + json.dumps(value)[1:])
    with pytest.raises(RuntimeError, match="browser_fixture_cli_failed"):
        completed_cli('{"status":"private-leak",' + json.dumps(value)[1:])


def test_cli_failure_diagnostics_allow_only_fixed_public_prerequisites():
    from scripts.mac_protected_browser_fixture import cli_failure

    assert cli_failure(json.dumps({"status": "RETRYABLE", "reason": "login_retry_cooldown"})) == "browser_fixture_cli_login_retry_cooldown"
    for value in [None, [], {}, {"status": []}, {"status": "RETRYABLE", "reason": []},
                  {"status": "RETRYABLE", "reason": "fictional-private-canary"}]:
        assert cli_failure(json.dumps(value)) == "browser_fixture_cli_failed"
    assert cli_failure(b"not JSON") == "browser_fixture_cli_failed"
