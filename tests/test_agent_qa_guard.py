import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.agent_qa_guard import digest, permitted
from scripts.agent_verification_smoke import claude_fixture_guard


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
