"""Invocation-only Claude tool gate for the fictional-account acceptance harness.

This is a narrow test boundary, not a sandbox for arbitrary untrusted programs.
The policy and this hook live outside the agent's permitted files. Only the
installed fixture client may execute; neither writes nor other tools are allowed.
"""

import hashlib
import json
import re
import shlex
import sys
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def permitted(event, policy):
    """Fail closed on malformed inputs, changed fixtures, and unsupported syntax."""
    try:
        for name, expected in policy["pins"].items():
            path = Path(name)
            if path.is_symlink() or str(path.resolve(strict=True)) != name or digest(path) != expected:
                return False, "fixture_changed"
        tool = event["tool_name"]
        args = event["tool_input"]
        if not isinstance(args, dict):
            return False, "invalid_tool_input"
        if tool == "Skill":
            return (args.get("skill") == policy["skill_name"] and not args.get("args"), "fixture_skill_only")
        if tool == "Read":
            path = Path(args["file_path"])
            if not path.is_absolute():
                path = Path(policy["workspace"]) / path
            return (str(path.resolve(strict=True)) in policy["read_files"], "fixture_instructions_only")
        if tool != "Bash":
            return False, "tool_not_permitted"
        command = args["command"]
        if (not isinstance(command, str) or len(command) > 4096
                or any(char in command for char in "\n\r\x00$`;&|<>()*?[]{}~")
                or args.get("run_in_background") or args.get("dangerouslyDisableSandbox")):
            return False, "simple_foreground_command_only"
        argv = shlex.split(command)
        if not argv or argv[0] != policy["launcher"]:
            return False, "fixture_launcher_only"
        argv = argv[1:]
        if argv in [["accounts"], ["status"]]:
            return True, "fixture_discovery"
        if len(argv) == 3 and argv[0] == "run":
            return (argv[1] + ":" + argv[2] in policy["steps"], "fixture_operation_only")
        if len(argv) >= 3 and argv[:2] in [["task", "get"], ["task", "wait"]]:
            valid = re.fullmatch(r"[a-f0-9]{32}", argv[2]) is not None
            if argv[1] == "get":
                valid = valid and len(argv) == 3
            else:
                valid = valid and (len(argv) == 3 or (len(argv) == 5 and argv[3] == "--timeout"
                                   and argv[4].isdigit() and 1 <= int(argv[4]) <= 60))
            return valid, "fixture_task_read_only"
        if len(argv) == 6 and argv[:2] == ["task", "submit"]:
            pairs = dict(zip(argv[2::2], argv[3::2]))
            if set(pairs) != {"--key", "--steps"} or not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", pairs["--key"]):
                return False, "invalid_fixture_task"
            steps = pairs["--steps"].split(",")
            return (len(steps) == len(set(steps)) and set(steps) <= set(policy["steps"]), "fixture_task_only")
        return False, "command_not_permitted"
    except (KeyError, ValueError, OSError, TypeError):
        return False, "invalid_guard_input"


def main():
    allowed, reason = False, "guard_failed"
    policy = None
    event = {}
    try:
        policy = json.loads(Path(sys.argv[1]).read_text())
        event = json.load(sys.stdin)
        allowed, reason = permitted(event, policy)
        # No commands, file contents, account identifiers, or tool results in audit.
        with Path(policy["audit"]).open("a") as audit:
            audit.write(json.dumps({"allowed": allowed, "tool": event.get("tool_name"), "reason": reason}) + "\n")
    except Exception:
        allowed, reason = False, "guard_failed"
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "allow" if allowed else "deny",
        "permissionDecisionReason": "Account Access fixture guard: " + reason}}))


if __name__ == "__main__":
    main()
