import io
import json
from pathlib import Path
import signal
import subprocess
from types import SimpleNamespace

import pytest

from scripts.check_mac_signed_chrome_report import (
    CHECKS, CHILD_CHECKS, EXTENSION_ID, RESOURCES, UNVERIFIED, VERIFIED,
    SMS_CHECKS, SMS_CHILD_CHECKS, SMS_UNVERIFIED, SMS_VERIFIED,
    main, validate, validate_child,
)
from scripts import mac_signed_chrome_probe as probe


def child_report():
    return {"status": "PASSED", "chrome_version": "Chrome/155.0.8042.1",
            "extension_id": EXTENSION_ID, "extension_resources_sha256": dict.fromkeys(RESOURCES, "a" * 64),
            "checks": dict.fromkeys(CHILD_CHECKS, True), "sms_journey": sms_report(child=True)}


def sms_report(*, child=False):
    return {"status": "PASSED", "checks": dict.fromkeys(SMS_CHILD_CHECKS if child else SMS_CHECKS, True),
            "script_resources_sha256": dict.fromkeys(RESOURCES - {"manifest.json"}, "a" * 64),
            "synthetic_manifest_sha256": "b" * 64,
            **dict.fromkeys(SMS_VERIFIED, True), **dict.fromkeys(SMS_UNVERIFIED, False)}


def report():
    return {**child_report(), "platform": "macos", "environment": "controlled-demo",
            "production_ready": False, "private_signins": 0,
            "checks": dict.fromkeys(CHECKS, True),
            "sms_journey": sms_report(),
            **dict.fromkeys(VERIFIED, True), **dict.fromkeys(UNVERIFIED, False)}


def test_real_chrome_evidence_requires_every_native_roundtrip_and_cleanup_check(tmp_path):
    assert len(CHILD_CHECKS) == 13 and len(CHECKS) == 17
    assert len(SMS_CHILD_CHECKS) == 14 and len(SMS_CHECKS) == 16
    assert validate_child(child_report()) and validate(report())
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


def test_synthetic_manifest_dom_join_requires_every_runtime_and_provider_check():
    for child, keys in [(True, SMS_CHILD_CHECKS), (False, SMS_CHECKS)]:
        make = child_report if child else report
        check = validate_child if child else validate
        for key in keys:
            for replacement in [False, None, 1, "true"]:
                value = make()
                value["sms_journey"]["checks"][key] = replacement
                assert not check(value)
            value = make()
            del value["sms_journey"]["checks"][key]
            assert not check(value)


@pytest.mark.parametrize("key", sorted(SMS_VERIFIED | SMS_UNVERIFIED))
def test_synthetic_manifest_join_cannot_claim_owner_approval_or_production_manifest(key):
    for replacement in [key not in SMS_VERIFIED, 1 if key in SMS_VERIFIED else 0]:
        value = report()
        value["sms_journey"][key] = replacement
        assert not validate(value)


def test_sms_join_refuses_changed_script_digests_missing_boundary_and_unknown_fields():
    for change in [
        lambda item: item.update(cookie="fictional"),
        lambda item: item.update(synthetic_manifest_sha256="a" * 64),
        lambda item: item.update(synthetic_manifest_sha256=True),
        lambda item: item["script_resources_sha256"].update({"reader.js": "b" * 64}),
        lambda item: item["script_resources_sha256"].update({"manifest.json": "a" * 64}),
    ]:
        value = report()
        change(value["sms_journey"])
        assert not validate(value)
    value = report()
    del value["sms_journey"]
    assert not validate(value)


def test_fixture_manifest_moves_only_one_declared_optional_origin():
    target = Path(__file__).resolve().parents[1] / "account_access/google_messages_extension/manifest.json"
    original = json.loads(target.read_bytes())
    before = json.dumps(original, sort_keys=True)
    candidate = probe.fixture_manifest(original)
    assert json.dumps(original, sort_keys=True) == before
    assert candidate["host_permissions"] == [probe.MESSAGES_ORIGIN]
    assert candidate["optional_host_permissions"] == ["https://github.com/*"]
    assert probe.validate_fixture_manifest(original, candidate)
    for key in original.keys() - {"optional_host_permissions"}:
        assert candidate[key] == original[key]
    for changed in [
        dict(candidate, optional_host_permissions=[]),
        dict(candidate, host_permissions=["<all_urls>"]),
        dict(candidate, permissions=original["permissions"] + ["cookies"]),
        dict(candidate, key="other"),
    ]:
        assert not probe.validate_fixture_manifest(original, changed)
    for changed in [dict(original, host_permissions=[]), dict(original, optional_host_permissions=[]), {}]:
        with pytest.raises(RuntimeError, match="signed_chrome_fixture_manifest_changed"):
            probe.fixture_manifest(changed)


@pytest.mark.parametrize("value", [None, {}, {"code": 123456}, {"code": "12345"}, {"code": "123456", "extra": True}])
def test_fixture_delivery_pipe_accepts_only_bounded_fictional_code(value):
    with pytest.raises(RuntimeError, match="^signed_chrome_fixture_delivery_invalid$"):
        probe.fictional_message(value)


def test_fixture_delivery_preserves_leading_zeroes_and_cached_dom_boundary():
    assert probe.fictional_message({"code": "012345"}) == "012345"
    document = probe.sms_page()
    assert '/web/conversations/cached-fixture' in document
    assert 'aria-label="10 min ago"' in document
    assert "<script" not in document


@pytest.mark.parametrize("key", sorted(VERIFIED | UNVERIFIED))
def test_signed_chrome_native_proof_cannot_claim_dom_sms_or_consumer_acceptance(key):
    value = report()
    value[key] = not value[key]
    assert not validate(value)
    value[key] = 1 if key in VERIFIED else 0
    assert not validate(value)


@pytest.mark.parametrize("key,value", [
    ("private_signins", True), ("private_signins", 1), ("production_ready", True),
    ("platform", "linux"), ("environment", "personal"),
    ("extension_id", "other"), ("chrome_version", "Chromium/155.0.8042.1"),
    ("chrome_version", "Chrome for Testing/155.0.8042.1"),
    ("extension_resources_sha256", {"background.js": "a" * 64}),
])
def test_chrome_evidence_refuses_wrong_browser_missing_resource_or_private_claim(key, value):
    changed = report()
    changed[key] = value
    assert not validate(changed)


def test_evidence_rejects_unknown_or_secret_fields():
    assert not validate({**report(), "cookie": "fictional"})
    assert not validate_child({**child_report(), "cookie": "fictional"})
    value = child_report()
    value["checks"]["unexpected"] = True
    assert not validate_child(value)
    value = child_report()
    value["extension_resources_sha256"]["reader.js"] = True
    assert not validate_child(value)


@pytest.mark.parametrize("contents", [None, b"", b"{}", b"null", b"not JSON"])
def test_missing_or_malformed_chrome_evidence_fails(tmp_path, contents):
    target = tmp_path / "report.json"
    if contents is not None:
        target.write_bytes(contents)
    assert main([str(target)]) == 1


def test_signed_chrome_journey_refuses_owner_mac_before_any_read_write_or_launch(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(probe, "root_managed_path", lambda *a: pytest.fail("no path inspection"))
    monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **kw: pytest.fail("no process launch"))
    with pytest.raises(RuntimeError, match="signed_chrome_requires_disposable_mac_ci"):
        probe.exercise_signed_chrome_gateway(tmp_path, None)
    with pytest.raises(RuntimeError, match="signed_chrome_requires_disposable_mac_ci"):
        probe.run_child(tmp_path)
    assert not list(tmp_path.iterdir())


def test_ci_child_refuses_wrong_prefix_before_any_path_read_or_launch(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.sys, "platform", "darwin")
    monkeypatch.setattr(probe.os, "getuid", lambda: 501)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 501)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(probe, "root_managed_path", lambda *a: pytest.fail("guard before paths"))
    monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **kw: pytest.fail("no process launch"))
    with pytest.raises(RuntimeError, match="signed_chrome_requires_fixture_identity"):
        probe.run_child(tmp_path)
    assert not list(tmp_path.iterdir())


def test_ci_prefix_and_role_must_be_the_dedicated_synthetic_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.sys, "platform", "darwin")
    monkeypatch.setattr(probe.os, "getuid", lambda: 0)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(probe, "root_managed_path", lambda *a: pytest.fail("guard before paths"))
    roles = {"agent": SimpleNamespace(pw_uid=501, pw_dir="/Users/owner"),
             "broker": SimpleNamespace(pw_uid=502)}
    with pytest.raises(RuntimeError, match="signed_chrome_requires_fixture_identity"):
        probe.exercise_signed_chrome_gateway(tmp_path, roles)
    prefix = Path("/Library/PrivilegedHelperTools/account-access-worker-qa-AbCd1234")
    with pytest.raises(RuntimeError, match="signed_chrome_requires_fixture_identity"):
        probe.exercise_signed_chrome_gateway(prefix, roles)
    assert not list(tmp_path.iterdir())


def test_browser_launch_uses_stable_identity_empty_profile_sandbox_and_mock_keychain(tmp_path):
    options = probe.launch_options(tmp_path / "profile", tmp_path / "home")
    assert options["executable_path"] == "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    assert options["user_data_dir"] == str(tmp_path / "profile")
    assert options["chromium_sandbox"] is True
    assert options["ignore_default_args"] == ["--disable-extensions"]
    assert {"--enable-unsafe-extension-debugging", "--password-store=basic", "--use-mock-keychain"} <= set(options["args"])
    assert not any(item.startswith(("--no-sandbox", "--load-extension", "--disable-web-security"))
                   for item in options["args"])
    assert options["env"] == {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(tmp_path / "home"),
                              "TMPDIR": str(tmp_path / "home/signed-chrome-tmp"), "GITHUB_ACTIONS": "true"}
    assert probe.CHROME_REQUIREMENT == (
        'anchor apple generic and identifier "com.google.Chrome" '
        'and certificate leaf[subject.OU] = "EQHXZ8M8AV" '
        'and !(entitlement["com.apple.security.get-task-allow"] exists)'
    )


def test_native_registration_has_exact_origin_and_direct_macho_path():
    binary = Path("/Library/PrivilegedHelperTools/account-access-worker-qa-AbCd1234/root-owner-client")
    assert probe.native_manifest(binary) == {
        "name": "com.account_access.google_messages",
        "description": "Account Access disposable signed-Chrome check",
        "path": str(binary), "type": "stdio", "allowed_origins": [probe.EXTENSION_ORIGIN],
    }


class Child:
    def __init__(self, *, status=None, stubborn=False):
        self.pid, self.returncode, self.stubborn = 1234, status, stubborn
        self.waits = []
        self.stdout = io.BytesIO()

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.waits.append(timeout)
        if self.stubborn and len(self.waits) == 1:
            raise subprocess.TimeoutExpired("fixture", timeout)
        self.returncode = 0


def test_timeout_cleanup_kills_and_reaps_only_its_created_group(monkeypatch):
    signals = []
    monkeypatch.setattr(probe.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    child = Child(stubborn=True)
    probe.stop_process(child)
    assert signals == [(1234, signal.SIGTERM), (1234, signal.SIGKILL)]
    assert child.waits == [2, 3]


def test_cleanup_reaps_exited_child_without_signaling(monkeypatch):
    monkeypatch.setattr(probe.os, "killpg", lambda *a: pytest.fail("already exited"))
    child = Child(status=1)
    probe.stop_process(child)
    assert child.waits == [0]


def test_child_failure_diagnostics_only_accept_a_fixed_public_stage():
    for value in probe.STAGES:
        assert probe.failure_diagnostic({"status": "FAILED", "stage": value}) == value
    for value in [None, [], {}, {"stage": []}, {"stage": "private-canary"}, {"stage": True}]:
        assert probe.failure_diagnostic(value) is None
