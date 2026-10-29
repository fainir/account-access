"""Pure probe contracts and an ordinary fixed marker; no root or launchctl."""

import ast
import importlib.util
import json
from pathlib import Path
import re
import subprocess

import pytest


SOURCE = Path(__file__).resolve().parent.parent / "scripts/mac_launchctl_disable_probe.py"
SPEC = importlib.util.spec_from_file_location("launchctl_disable_probe_contract", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
TOKEN = "0" * 32


@pytest.fixture
def contract():
    # Execute only pure predicate/parser definitions, never the root main,
    # subprocess wrapper, filesystem helpers, package builder or launchctl.
    tree = ast.parse(probe.root_source(TOKEN))
    names = {"unambiguous", "succeeded", "definitively_absent", "disabled_override", "record_disabled"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    label = "local.account-access-disable-probe." + TOKEN
    namespace = {"LABEL": label, "re": re,
                 "ABSENT": ("Bad request.\nCould not find service \"" + label
                            + "\" in domain for system\n").encode()}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace


def result(code=0, **changes):
    value = {"returncode": code, "client_reaped": True, "timed_out": False,
             "output_limited": False, "invocation_failed": False}
    value.update(changes)
    return value


@pytest.mark.parametrize("change", [{"timed_out": True}, {"client_reaped": False},
                                  {"output_limited": True}, {"invocation_failed": True},
                                  {"returncode": None}, {"returncode": True}])
def test_ambiguous_or_unreaped_client_is_never_success(contract, change):
    assert contract["succeeded"](result(**change)) is False
    assert contract["definitively_absent"](result(113, **{key: value for key, value in change.items()
                                                        if key != "returncode"}), b"other") is False


def test_exact_absent_response_is_required_in_addition_to_exit_code(contract):
    missing = contract["ABSENT"]
    assert contract["definitively_absent"](result(113), missing) is True
    for response in (b"", missing + b" ", missing.replace(b"system", b"gui"),
                     missing.replace(TOKEN.encode(), b"1" * 32), b"permission denied\n"):
        assert contract["definitively_absent"](result(113), response) is False
    assert contract["definitively_absent"](result(3), missing) is False
    assert contract["succeeded"](result()) is True
    assert contract["succeeded"](result(113)) is False


def envelope(*rows):
    return ("\ndisabled services = {\n" + "\n".join(rows) + ("\n" if rows else "") + "}\n").encode()


@pytest.mark.parametrize("token,expected", [("disabled", "true"), ("enabled", "false"),
                                           ("true", "true"), ("false", "false")])
def test_disabled_parser_normalizes_known_tokens_with_exact_fixture_evidence(contract, token, expected):
    label = contract["LABEL"]
    parse = contract["disabled_override"]
    line = '\t"' + label + '" => ' + token + '  '
    evidence = {}
    assert parse(envelope('  "unrelated.system.label" => enabled', line), evidence) == expected
    assert evidence == {"target_line": line, "token": token, "normalized": expected}
    assert "unrelated" not in json.dumps(evidence)


def test_absent_requires_complete_valid_envelope_and_all_other_rows(contract):
    parse = contract["disabled_override"]
    assert parse(envelope()) == "absent"
    evidence = {}
    assert parse(envelope('  "unrelated.a" => disabled', '\t"unrelated.b" => false'), evidence) == "absent"
    assert evidence == {"target_line": None, "token": None, "normalized": "absent"}
    for raw in (b"", b"other text\n", b'disabled services = {\n', b'{\n}\n',
                b'disabled services = {\n}\nextra', b'disabled services = {\n\n}\n',
                envelope('"other" => unknown'), envelope('"other" => true extra'),
                envelope('"other" => true', '"other" => true'), envelope('"other" => disabled', '"other" => enabled'),
                envelope('"other\\escape" => true'), envelope('"other"=>true'),
                envelope('"' + "x" * 256 + '" => true'), b"\xff", envelope() + b"\x00",
                envelope().replace(b"\n", b"\r\n"), b"x" * (128 * 1024 + 1)):
        with pytest.raises(ValueError):
            parse(raw)


def test_duplicate_target_or_target_substring_cannot_authorize_disable(contract):
    label = contract["LABEL"]
    parse = contract["disabled_override"]
    line = '"' + label + '" => disabled'
    for raw in (envelope(line, line), envelope(line, '"' + label + '" => enabled')):
        evidence = {}
        with pytest.raises(ValueError):
            parse(raw, evidence)
        assert evidence == {"target_line": None, "token": None, "normalized": "unverified"}
    assert parse(envelope('"prefix.' + label + '" => disabled')) == "absent"


def test_failed_grammar_retains_only_safe_unique_fixture_line_as_unverified(contract):
    label = contract["LABEL"]
    line = '\t"' + label + '" => disabled'
    evidence = {}
    with pytest.raises(ValueError):
        contract["disabled_override"](("wrong envelope\n" + line + '\n"unrelated" => true\n}\n').encode(), evidence)
    assert evidence == {"target_line": line, "token": "disabled", "normalized": "unverified"}
    assert "unrelated" not in json.dumps(evidence)


def test_query_evidence_needs_success_and_cannot_convert_error_output_to_absence(contract):
    command = result()
    assert contract["record_disabled"](command, envelope()) == "absent"
    assert command["override_evidence"] == {"target_line": None, "token": None, "normalized": "absent"}
    command = result(1)
    assert contract["record_disabled"](command, envelope()) == "unverified"
    assert command["override_evidence"] == {"target_line": None, "token": None, "normalized": "unverified"}
    command = result()
    with pytest.raises(ValueError):
        contract["record_disabled"](command, b"malformed")
    assert command["override_evidence"]["normalized"] == "unverified"


@pytest.mark.parametrize("token", ["", "0" * 31, "0" * 33, "G" * 32, "x; id"])
def test_root_source_requires_fresh_hex_token_shape(token):
    with pytest.raises(ValueError):
        probe.root_source(token)


def test_ci_revision_binding_allows_slow_checkout_but_stays_bounded():
    tree = ast.parse(SOURCE.read_text())
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute)
             and node.func.attr == "check_output"
             and isinstance(node.func.value, ast.Name)
             and node.func.value.id == "subprocess"
             and len(node.args) == 1
             and isinstance(node.args[0], ast.List)
             and [item.value for item in node.args[0].elts if isinstance(item, ast.Constant)]
             == ["/usr/bin/git", "rev-parse", "HEAD"]]
    assert len(calls) == 1
    timeout = next(keyword.value.value for keyword in calls[0].keywords
                   if keyword.arg == "timeout" and isinstance(keyword.value, ast.Constant))
    assert timeout == 30


def test_owner_mac_is_refused_before_package_or_output_creation(tmp_path, monkeypatch):
    output = tmp_path / "evidence"
    monkeypatch.setattr(probe.sys, "argv", [str(SOURCE), "--output", str(output)])
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setattr(probe.subprocess, "check_output", lambda *args, **kwargs: pytest.fail("git not permitted"))
    with pytest.raises(SystemExit) as error:
        probe.main()
    assert error.value.code == 2
    assert not output.exists()


def test_fixed_fixture_marker_and_noclobber_work_as_ordinary_user(tmp_path):
    tree = ast.parse(probe.root_source(TOKEN))
    commands = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                and isinstance(node.value, str) and node.value.startswith("umask 077; set -C; printf")]
    assert len(commands) == 1
    marker = tmp_path / "public-marker"
    command = ["/bin/sh", "-c", commands[0], "ordinary-fixture", str(marker)]
    assert subprocess.run(command, capture_output=True, timeout=2, check=False).returncode == 0
    assert marker.read_bytes() == b"ACCOUNT_ACCESS_DISABLE_FIXTURE_V1\n"
    assert marker.stat().st_mode & 0o777 == 0o600
    assert subprocess.run(command, capture_output=True, timeout=2, check=False).returncode != 0
    assert marker.read_bytes() == b"ACCOUNT_ACCESS_DISABLE_FIXTURE_V1\n"
