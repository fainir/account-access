"""Pure probe contracts and an ordinary fixed marker; no root or launchctl."""

import ast
import importlib.util
from pathlib import Path
import subprocess

import pytest


SOURCE = Path(__file__).resolve().parent.parent / "scripts/mac_launchctl_disable_probe.py"
SPEC = importlib.util.spec_from_file_location("launchctl_disable_probe_contract", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
TOKEN = "0" * 32


@pytest.fixture
def contract():
    # Execute only four pure predicate/parser definitions, never the root main,
    # subprocess wrapper, filesystem helpers, package builder or launchctl.
    tree = ast.parse(probe.root_source(TOKEN))
    names = {"unambiguous", "succeeded", "definitively_absent", "disabled_override"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    label = "local.account-access-disable-probe." + TOKEN
    namespace = {"LABEL": label,
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


def test_disabled_parser_accepts_only_one_exact_unique_target(contract):
    label = contract["LABEL"]
    parse = contract["disabled_override"]
    assert parse(b'disabled services = {\n}\n') == "absent"
    assert parse(('  "' + label + '" => true\n').encode()) == "true"
    assert parse(('  "' + label + '" => false\n').encode()) == "false"
    assert parse(('  "other.' + TOKEN + '" => true\n').encode()) == "absent"
    for value in ('"' + label + '" => 1', '"' + label + '" => true extra',
                  ('"' + label + '" => true\n') * 2):
        with pytest.raises(ValueError):
            parse(value.encode())


@pytest.mark.parametrize("token", ["", "0" * 31, "0" * 33, "G" * 32, "x; id"])
def test_root_source_requires_fresh_hex_token_shape(token):
    with pytest.raises(ValueError):
        probe.root_source(token)


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
