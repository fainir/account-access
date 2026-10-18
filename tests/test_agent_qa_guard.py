import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.agent_qa_guard import digest, permitted
from scripts.agent_verification_smoke import (
    AgentQABoundaryError, agent_environment, blocked_report, check,
    claude_fixture_guard, codex_fixture_preflight, fixture_trace_boundary, select_codex_cli,
)


@pytest.fixture
def policy(tmp_path):
    workspace = tmp_path.resolve() / "workspace"
    skill = workspace / ".claude/skills/account-access-qa-example"
    (skill / "scripts").mkdir(parents=True)
    paths = [workspace / "CLAUDE.md", skill / "SKILL.md", skill / "scripts/access",
             skill / "scripts/access.py", skill / "installation.json"]
    for path in paths:
        path.write_text("fixture")
    return {"workspace": str(workspace), "skill_name": skill.name,
            "launcher": str(skill / "scripts/access"),
            "read_files": [str(workspace / "CLAUDE.md"), str(skill / "SKILL.md")],
            "steps": ["example-password:profile", "example-email:profile"],
            "pins": {str(path): digest(path) for path in paths}}


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


@pytest.mark.parametrize("arguments", [
    "accounts", "status", "run example-password profile",
    "task submit --key qa_example-54 --steps example-password:profile,example-email:profile",
    "task submit --steps example-email:profile --key qa",
    "task get " + "a" * 32, "task wait " + "b" * 32 + " --timeout 60",
])
def test_guard_accepts_only_fixture_discovery_and_declared_read_operations(policy, arguments):
    assert permitted(bash(shlex.quote(policy["launcher"]) + " " + arguments), policy)[0]


@pytest.mark.parametrize("command", [
    "access accounts", "/unrelated/.agents/skills/account-access/scripts/access accounts",
    "python3 -m account_access.cli accounts", "bash -lc 'access accounts'",
    "{launcher} run personal-github profile", "{launcher} --root /elsewhere accounts",
    "{launcher} task submit --key qa --steps personal-namecheap:profile",
    "{launcher} task submit --key qa --steps example-email:profile,example-email:profile",
    "{launcher} task submit --key qa --steps example-email:profile --root /elsewhere",
    "{launcher} accounts && access accounts", "{launcher} accounts; access accounts",
    "{launcher} accounts\naccess accounts", "{launcher} accounts | cat",
    "{launcher} accounts >/tmp/output", "$(access accounts) accounts",
    "`access accounts` accounts", "{launcher} task wait " + "a" * 32 + " --timeout 120",
    "{launcher} task get ../../private", "env ACCESS_CLIENT_CONFIG=/elsewhere {launcher} accounts",
    "{launcher} owner", "{launcher} accounts &", "{launcher} accounts < /private",
    "{launcher} accounts # command", "{launcher} task submit --key '*' --steps example-email:profile",
])
def test_guard_rejects_global_clients_shell_expansion_and_unapproved_tasks(policy, command):
    command = command.replace("{launcher}", shlex.quote(policy["launcher"]))
    assert not permitted(bash(command), policy)[0]


@pytest.mark.parametrize("tool,input", [
    ("Skill", {"skill": "account-access"}), ("Skill", {"skill": "other"}),
    ("Read", {"file_path": "/outside/client.json"}),
    ("Write", {"file_path": "SKILL.md", "content": "replace launcher"}),
    ("Edit", {}), ("WebFetch", {}), ("Agent", {}), ("mcp__arbitrary", {}),
])
def test_guard_rejects_other_skills_files_writes_and_execution_tools(policy, tool, input):
    assert not permitted({"tool_name": tool, "tool_input": input}, policy)[0]


def test_guard_allows_only_pinned_instructions_and_unique_skill(policy):
    for name in policy["read_files"]:
        assert permitted({"tool_name": "Read", "tool_input": {"file_path": name}}, policy)[0]
    assert permitted({"tool_name": "Skill", "tool_input": {"skill": policy["skill_name"]}}, policy)[0]
    assert not permitted({"tool_name": "Skill", "tool_input": {
        "skill": policy["skill_name"], "args": "!access accounts"}}, policy)[0]
    for flag in ["run_in_background", "dangerouslyDisableSandbox"]:
        event = bash(shlex.quote(policy["launcher"]) + " accounts")
        event["tool_input"][flag] = True
        assert not permitted(event, policy)[0]


@pytest.mark.parametrize("mutation", ["content", "symlink"])
def test_guard_refuses_launcher_replacement_even_if_path_or_contents_match(policy, tmp_path, mutation):
    launcher = Path(policy["launcher"])
    if mutation == "content":
        launcher.write_text("unexpected")
    else:
        other = tmp_path / "same-content"
        other.write_text(launcher.read_text())
        launcher.unlink()
        launcher.symlink_to(other)
    assert not permitted(bash(shlex.quote(str(launcher)) + " accounts"), policy)[0]


def test_generated_hook_denies_without_executing_global_launcher_and_fails_closed(policy, tmp_path):
    skill = Path(policy["launcher"]).parents[1]
    config = tmp_path / "fixture-client.json"
    config.write_text("fixture-client")
    settings, audit = claude_fixture_guard(tmp_path, Path(policy["workspace"]), skill, config, policy["steps"])
    hook = json.loads(settings.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
    assert hook["onFailure"] == "block"
    result = subprocess.run(hook["command"], shell=True, input=json.dumps(bash("access accounts")),
                            text=True, capture_output=True)
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(audit.read_text())["reason"] == "fixture_launcher_only"
    guard = Path(__file__).resolve().parents[1] / "scripts/agent_qa_guard.py"
    for content in ["not json", "{}", '[]']:
        result = subprocess.run([sys.executable, "-I", str(guard), str(tmp_path / "claude-guard.json")],
                                input=content, text=True, capture_output=True)
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    config.write_text("changed-client")
    result = subprocess.run(hook["command"], shell=True,
                            input=json.dumps(bash(shlex.quote(policy["launcher"]) + " accounts")),
                            text=True, capture_output=True)
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("global_succeeded", [False, True])
def test_trace_acceptance_rejects_any_successful_tool_outside_fixture_policy(policy, global_succeeded):
    fixture = shlex.quote(policy["launcher"]) + " accounts"
    calls = [{"type": "tool_use", "name": "Bash", "id": name, "input": {"command": command}}
             for name, command in [("fixture", fixture), ("global", "access accounts")]]
    results = [{"type": "tool_result", "tool_use_id": name, "is_error": failed}
               for name, failed in [("fixture", False), ("global", not global_succeeded)]]
    trace = "\n".join(json.dumps({"message": {"content": [block]}}) for block in [*calls, *results])
    assert fixture_trace_boundary(trace, policy) == (not global_succeeded)
    missing_result = "\n".join(trace.splitlines()[:-1])
    assert not fixture_trace_boundary(missing_result, policy)


@pytest.mark.parametrize("script", ["agent_smoke.py", "implicit_agent_smoke.py"])
def test_legacy_qa_entry_points_refuse_before_any_account_connection(tmp_path, script):
    path = Path(__file__).resolve().parents[1] / "scripts" / script
    result = subprocess.run([sys.executable, str(path), "claude", "--workspace", str(tmp_path)],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "legacy harness is retired" in result.stderr
    assert "agent_verification_smoke.py" in result.stderr
    assert not list(tmp_path.iterdir())


@pytest.fixture
def modern_cli(tmp_path, monkeypatch):
    executable = tmp_path / "codex"
    executable.write_text("unused mocked executable")
    executable.chmod(0o700)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        output = ("codex-cli 0.163.0-alpha.10.2\n" if command[-1] == "--version"
                  else "--ignore-user-config --strict-config --ephemeral --json")
        return subprocess.CompletedProcess(command, 0, output, "unreported stderr")

    monkeypatch.setattr("scripts.agent_verification_smoke.subprocess.run", run)
    return executable, calls


def test_codex_selector_uses_explicit_modern_cli_without_path_auth_or_config_reads(modern_cli):
    executable, calls = modern_cli
    selected, diagnostics = select_codex_cli(executable)
    assert selected == str(executable.resolve())
    assert diagnostics == {"cli_selection": "explicit", "cli_version": "0.163.0"}
    assert [command[1:] for command, _ in calls] == [["--version"], ["exec", "--help"]]
    assert all(options["env"] == {"PATH": "/usr/bin:/bin"} for _, options in calls)
    assert all(options["timeout"] == 5 for _, options in calls)


def test_codex_default_is_bundled_executable_and_never_path_fallback(modern_cli, monkeypatch):
    executable, _ = modern_cli
    monkeypatch.setattr("scripts.agent_verification_smoke.CODEX_BUNDLED", executable)
    monkeypatch.setattr("scripts.agent_verification_smoke.shutil.which",
                        lambda name: pytest.fail("PATH CLI selection is forbidden"))
    assert select_codex_cli()[1]["cli_selection"] == "bundled"


@pytest.mark.parametrize("name", ["codex", "./codex", "/not-present/account-access-qa-codex"])
def test_codex_selector_refuses_missing_or_relative_paths_before_running(modern_cli, name):
    _, calls = modern_cli
    with pytest.raises(AgentQABoundaryError, match="^codex_modern_cli_required$"):
        select_codex_cli(name)
    assert calls == []


@pytest.mark.parametrize("version", ["codex-cli 0.155.1", "codex-cli 0.162.99", "private-output",
                                    "codex-cli 0.163.0\nprivate-output", "codex-cli " + "1" * 5000],
                         ids=["old-path-cli", "too-old", "malformed", "extra-output", "oversize"])
def test_codex_selector_rejects_old_or_malformed_versions_without_echoing_output(modern_cli, monkeypatch, version):
    executable, _ = modern_cli
    monkeypatch.setattr("scripts.agent_verification_smoke.subprocess.run", lambda *a, **k:
                        subprocess.CompletedProcess(a[0], 0, version, "private-error"))
    with pytest.raises(AgentQABoundaryError) as error:
        select_codex_cli(executable)
    assert blocked_report(error.value)["reason"] == "codex_modern_cli_required"
    public = json.dumps(blocked_report(error.value))
    assert "private-output" not in public and "private-error" not in public
    assert str(executable) not in public


@pytest.mark.parametrize("missing", ["--ignore-user-config", "--strict-config", "--ephemeral", "--json"])
def test_codex_selector_refuses_missing_isolation_capabilities(modern_cli, monkeypatch, missing):
    executable, _ = modern_cli

    def run(command, **kwargs):
        output = ("codex-cli 0.163.0\n" if command[-1] == "--version" else
                  " ".join({"--ignore-user-config", "--strict-config", "--ephemeral", "--json"} - {missing}))
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr("scripts.agent_verification_smoke.subprocess.run", run)
    with pytest.raises(AgentQABoundaryError, match="^codex_isolation_capabilities_required$"):
        select_codex_cli(executable)


@pytest.mark.parametrize("error", [OSError("private-path-or-message"),
                                  subprocess.TimeoutExpired("private-command", 5, output="private-output")])
def test_codex_selector_redacts_cli_failures(modern_cli, monkeypatch, error):
    executable, _ = modern_cli

    def failed(*args, **kwargs):
        raise error

    monkeypatch.setattr("scripts.agent_verification_smoke.subprocess.run", failed)
    with pytest.raises(AgentQABoundaryError) as failure:
        select_codex_cli(executable)
    assert failure.value.reason == "codex_cli_preflight_failed"
    public = json.dumps(blocked_report(failure.value))
    assert all(value not in public for value in ["private-path-or-message", "private-command", "private-output"])


def test_modern_codex_still_refuses_before_workspace_fixture_credentials_or_model(modern_cli, tmp_path, monkeypatch):
    executable, calls = modern_cli
    workspace = tmp_path / "new-workspace"

    def forbidden(*args, **kwargs):
        pytest.fail("Codex QA crossed its unverified pre-execution boundary")

    monkeypatch.setattr("scripts.agent_verification_smoke.environment", forbidden)
    monkeypatch.setattr("scripts.agent_verification_smoke.tempfile.mkdtemp", forbidden)
    with pytest.raises(AgentQABoundaryError) as error:
        check("codex", workspace, "model-preserved-for-compatibility", "blocked", executable)
    assert error.value.reason == "codex_effective_permissions_unverifiable"
    report = blocked_report(error.value)
    assert not report["fixture_started"] and not report["model_started"] and not report["passed"]
    assert report["private_signins"] == 0 and not workspace.exists()
    assert len(calls) == 2 and all(command[-1] in {"--version", "--help"} for command, _ in calls)
    with pytest.raises(AgentQABoundaryError, match="^codex_effective_permissions_unverifiable$"):
        codex_fixture_preflight(executable)


def test_codex_cli_refusal_report_preserves_historical_success_and_never_starts_fixture(tmp_path):
    executable = tmp_path / "codex-public-help-only"
    executable.write_text("#!/bin/sh\ncase \"$*\" in\n"
                          "  --version) echo 'codex-cli 0.163.0-alpha.10.2';;\n"
                          "  'exec --help') echo '--ignore-user-config --strict-config --ephemeral --json';;\n"
                          "  *) exit 99;;\nesac\n")
    executable.chmod(0o700)
    artifacts = tmp_path / "artifacts/agent-tests"
    artifacts.mkdir(parents=True)
    previous = artifacts / "codex-verification-080-fixed.json"
    previous.write_text('{"historical":true}\n')
    path = Path(__file__).resolve().parents[1] / "scripts/agent_verification_smoke.py"
    workspace = tmp_path / "untouched-workspace"
    result = subprocess.run([sys.executable, str(path), "codex", "--workspace", str(workspace),
                             "--report-suffix", "fixed", "--codex-cli", str(executable)],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2 and result.stderr == ""
    report = json.loads(result.stdout)
    assert report["reason"] == "codex_effective_permissions_unverifiable"
    expected_revision = subprocess.check_output(
        ["git", "-C", str(path.parents[1]), "rev-parse", "HEAD"], text=True).strip()
    assert report["evidence_revision"] == expected_revision
    assert not report["fixture_started"] and not report["model_started"]
    assert not workspace.exists()
    assert json.loads((artifacts / "codex-verification-080-fixed.blocked.json").read_text()) == report
    assert previous.read_text() == '{"historical":true}\n'


def test_claude_environment_keeps_parent_login_and_hooks_but_scrubs_tool_children():
    parent = {"ANTHROPIC_API_KEY": "fictional-parent-login", "CLAUDE_CONFIG_DIR": "/fictional-config",
              "CLAUDE_CODE_SHELL_PREFIX": "/reviewed-policy-wrapper", "ACCESS_CLIENT_CONFIG": "fixture",
              "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0", "BASH_ENV": "/untrusted-startup",
              "PYTHONPATH": "/untrusted-modules", "PATH": "/usr/bin:/bin"}
    child = agent_environment("claude", parent)
    assert child["ANTHROPIC_API_KEY"] == parent["ANTHROPIC_API_KEY"]
    assert child["CLAUDE_CONFIG_DIR"] == parent["CLAUDE_CONFIG_DIR"]
    assert child["CLAUDE_CODE_SHELL_PREFIX"] == parent["CLAUDE_CODE_SHELL_PREFIX"]
    assert child["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    assert "BASH_ENV" not in child and "PYTHONPATH" not in child
    assert parent["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "0" and "BASH_ENV" in parent
