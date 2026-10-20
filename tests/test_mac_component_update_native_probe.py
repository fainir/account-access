"""Negative acceptance contracts only; no native compilation or root execution."""

import importlib.util
import json
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parent.parent / "scripts/mac_component_update_native_probe.py"
SPEC = importlib.util.spec_from_file_location("mac_component_native_probe", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def report(kind):
    checks = probe.CORE_CHECKS if kind == "core" else probe.POLICY_CHECKS
    result = {"schema": 1, "status": "PASSED", "checks": dict.fromkeys(checks, True),
              "installed_reads": False, "service_actions": False}
    result["ordinary_fixture_assertions" if kind == "core" else "count"] = 79 if kind == "core" else 41
    return result


@pytest.mark.parametrize("kind", ["core", "policy"])
def test_every_named_native_assertion_is_required(kind):
    value = report(kind)
    assert probe.fixture_result(json.dumps(value), kind=kind) == value
    for name in value["checks"]:
        missing = report(kind)
        del missing["checks"][name]
        with pytest.raises(ValueError):
            probe.fixture_result(json.dumps(missing), kind=kind)
        false = report(kind)
        false["checks"][name] = 1  # Truthiness is insufficient.
        with pytest.raises(ValueError):
            probe.fixture_result(json.dumps(false), kind=kind)


@pytest.mark.parametrize("kind", ["core", "policy"])
@pytest.mark.parametrize("field,value", [("schema", True), ("status", "SKIPPED"),
                                        ("installed_reads", True), ("service_actions", True),
                                        ("extra", True)])
def test_optimistic_counts_or_changed_scope_cannot_pass(kind, field, value):
    changed = report(kind)
    changed[field] = value
    with pytest.raises(ValueError):
        probe.fixture_result(json.dumps(changed), kind=kind)


def test_main_requires_actual_refusal_exit_and_exact_closed_result():
    raw = json.dumps(probe.MAIN_REFUSAL)
    assert probe.main_result(78, raw) == {"returncode": 78, "result": probe.MAIN_REFUSAL}
    for code in (0, -9, 77):
        with pytest.raises(ValueError):
            probe.main_result(code, raw)
    for change in ({"schema": True}, {"status": "PASSED"}, {"extra": "unreviewed"}):
        with pytest.raises(ValueError):
            probe.main_result(78, json.dumps({**probe.MAIN_REFUSAL, **change}))


def test_owner_mac_refused_before_git_compile_or_output(tmp_path, monkeypatch):
    output = tmp_path / "evidence"
    monkeypatch.setattr(probe.sys, "argv", [str(SOURCE), "--output", str(output)])
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setattr(probe.subprocess, "check_output", lambda *args, **kwargs: pytest.fail("git must not run"))
    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: pytest.fail("compiler must not run"))
    with pytest.raises(SystemExit) as error:
        probe.main()
    assert error.value.code == 2
    assert not output.exists()
