"""Closed fixture-report and refusal contracts; no compiler or native execution."""

import importlib.util
import json
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parent.parent / "scripts/mac_full_image_installed_probe.py"
SPEC = importlib.util.spec_from_file_location("full_image_installed_probe", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def reports():
    scope = dict.fromkeys(["installed_reads", "root_execution", "service_actions", "production_ready"], False)
    return [
        dict(scope, status="PASSED", count=156, checks=dict.fromkeys(map(str, range(156)), True)),
        dict(scope, status="PASSED", checks=142),
        dict(scope, status="PASSED", checks=40,
             supplemental_group_case="PASSED_INHERITED_DIFFERENT_GROUP_CORRECTED_ONLY_ON_NEW_INODE"),
        dict(scope, status="PASSED", checks=63, ordinary_temp_only=True,
             supplemental_group_case="PASSED_DISTINCT_OLD_AND_NEW_GROUPS", optional_polarities=2, recovery_polarities=3),
        {"status": "FULL_IMAGE_DURABLE_JOURNAL_CHECKS_PASSED", "assertions": 164,
         "installed_or_provider_operations": False},
        {"schema": 1, "status": "PASSED", "source_assertions": 54, "recovery_assertions": 49, "transaction_assertions": 74,
         "installed_reads": False, "payload_executed": False, "production_ready": False},
    ]


class InertProbe:
    """Supply explicit subprocess results to the real acceptance path."""

    def __init__(self, values=None, refusal=None):
        self.result = {}
        self.compiler = ["compiler-must-not-run"]
        self.output = Path("/unused-no-filesystem")
        self.values = reports() if values is None else values
        self.refusal = refusal
        self.calls = []

    def stable(self):
        pass

    def run(self, command, name, seconds, *, guard=None):
        self.calls.append((name, guard, command))
        if name == "compile":
            return 0, b"", b""
        if name == "runtime":
            return 0, "".join(json.dumps(value) + "\n" for value in self.values).encode(), b""
        if guard == self.refusal:
            return 0, b"", b""
        if guard == "entrypoint":
            return 78, b'{"schema":1,"status":"REFUSED","reason":"full_image_update_context_required"}\n', b""
        if guard == "repair-entrypoint":
            return 78, b'{"schema":1,"status":"REFUSED","reason":"broker_repair_installer_context_required"}\n', b""
        return 77, b"", b""


def test_one_compile_requires_every_fixture_and_all_six_guards():
    inert = InertProbe()
    probe.Probe.qualify(inert)
    assert inert.result["status"] == "PASSED"
    assert inert.result["combined_compile_count"] == 1
    assert inert.result["guarded_main_refusals"] == 6
    assert [name for name, _, _ in inert.calls].count("compile") == 1
    assert [guard for name, guard, _ in inert.calls if name.startswith("guard-")] == [
        "predecessor", "installed", "namespace", "legacy-group", "global-journal", "broker-repair",
    ]
    assert inert.result["entrypoint_ordinary_refusal"]["exit_code"] == 78
    assert inert.result["repair_entrypoint_ordinary_refusal"]["exit_code"] == 78


@pytest.mark.parametrize("index,key,value", [
    (0, "count", 141),
    (1, "checks", 141),
    (2, "supplemental_group_case", "UNREVIEWED"),
    (3, "status", "SKIPPED"),
    (3, "checks", 62),
    (3, "ordinary_temp_only", 1),
    (3, "supplemental_group_case", "UNAVAILABLE_NO_DISTINCT_GROUP"),
    (3, "optional_polarities", 1),
    (3, "recovery_polarities", 2),
    (3, "installed_reads", 0),
    (4, "assertions", 147),
    (4, "installed_or_provider_operations", 0),
    (4, "extra", "unreviewed"),
    (5, "source_assertions", 53),
    (5, "recovery_assertions", 48),
    (5, "transaction_assertions", 73),
    (5, "installed_reads", 0),
    (5, "payload_executed", 0),
    (5, "production_ready", 0),
    (5, "schema", True),
    (5, "extra", "unreviewed"),
])
def test_changed_or_optimistic_fixture_reports_cannot_qualify(index, key, value):
    values = reports()
    values[index][key] = value
    with pytest.raises(probe.Refused):
        probe.Probe.qualify(InertProbe(values))


def test_missing_journal_report_and_truthy_named_assertion_are_refused():
    with pytest.raises(probe.Refused):
        probe.Probe.qualify(InertProbe(reports()[:-1]))
    values = reports()
    values[0]["checks"]["0"] = 1
    with pytest.raises(probe.Refused):
        probe.Probe.qualify(InertProbe(values))


@pytest.mark.parametrize("guard", ["predecessor", "installed", "namespace", "legacy-group", "global-journal", "broker-repair", "entrypoint", "repair-entrypoint"])
def test_a_missing_actual_refusal_cannot_pass(guard):
    with pytest.raises(probe.Refused):
        probe.Probe.qualify(InertProbe(refusal=guard))
