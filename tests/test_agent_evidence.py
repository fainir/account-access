import json
import shlex

import pytest

from scripts.agent_verification_smoke import used_installed_launcher


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("style", ["absolute", "relative", "cd_bare", "cd_dot", "echo", "echo_operator", "cat", "failed", "other"])
def test_launcher_evidence_checks_execution_and_resolves_real_command_paths(tmp_path, agent, style):
    skill = tmp_path / "a space/.claude/skills/account-access"
    launcher = skill / "scripts/access"
    command = {
        "absolute": shlex.quote(str(launcher)) + " accounts",
        "relative": "'./a space/.claude/skills/account-access/scripts/access' task submit",
        "cd_bare": "cd " + shlex.quote(str(skill)) + " && scripts/access task wait example",
        "cd_dot": "cd " + shlex.quote(str(skill)) + " && ./scripts/access accounts",
        "echo": "echo " + shlex.quote(str(launcher)) + " accounts",
        "echo_operator": "echo '&&' " + shlex.quote(str(launcher)) + " accounts",
        "cat": "cat " + shlex.quote(str(launcher)),
        "failed": shlex.quote(str(launcher)) + " accounts",
        "other": "/unrelated/.agents/skills/account-access/scripts/access accounts",
    }[style]
    if agent == "claude":
        events = [
            {"message": {"content": [{"type": "tool_use", "name": "Bash", "id": "one", "input": {"command": command}}]}},
            {"message": {"content": [{"type": "tool_result", "tool_use_id": "one", "is_error": style == "failed"}]}},
        ]
    else:
        events = [{"type": "item.completed", "item": {"type": "command_execution", "exit_code": 1 if style == "failed" else 0,
                   "command": "/bin/zsh -lc " + shlex.quote(command)}}]
    trace = "\n".join(json.dumps(event) for event in events)
    assert used_installed_launcher(trace, skill, tmp_path) == (style in {"absolute", "relative", "cd_bare", "cd_dot"})
