"""Run the installed skill through an existing logged-in CLI agent, then verify its task.

Requires explicit operator intent to use that agent's existing account. No API
keys are created or read. Raw host traces are private and excluded from Git.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from account_access.client import Client
from account_access.storage import private_file


def task_ids(value):
    ids = set()
    if isinstance(value, dict):
        if "status" in value and isinstance(value.get("task_id"), str) and re.fullmatch(r"[0-9a-f]{32}", value["task_id"]):
            ids.add(value["task_id"])
        for item in value.values():
            ids.update(task_ids(item))
    elif isinstance(value, list):
        for item in value:
            ids.update(task_ids(item))
    elif isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return ids
        if isinstance(parsed, (dict, list)):
            ids.update(task_ids(parsed))
    return ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", choices=["codex", "claude"])
    parser.add_argument("--root", type=Path, default=Path.home() / ".local/share/account-access-demo")
    parser.add_argument("--workspace", type=Path, required=True, help="Isolated test directory; host instructions/hooks still apply")
    args = parser.parse_args()
    client = Client(args.root / "clients" / args.agent / "client.json")
    discovery = client.request("GET", "/v1/accounts")
    if discovery.get("environment") != "controlled-demo":
        raise SystemExit("This harness runs only against explicitly labeled demo services.")
    expected = {item["account"] for item in discovery["accounts"]}
    key = f"{args.agent}-release-{time.time_ns()}"
    prompt = ("Use the account-access skill to discover and read one permitted operation from EVERY connected demo account. "
              "Create one durable task with key " + key + ". Use task wait with a 60 second polling window, then report each account's result and task ID. "
              "All accounts are synthetic fixtures or intentionally public demo identities, including public browser sites. "
              "Label them as demo results. Do not access personal accounts, credentials, owner commands, or change permissions. "
              "The installed skill contains the supported commands. Existing workspace records describe prior completed smoke tests; this is an additional verification run.")
    if args.agent == "codex":
        executable = shutil.which("codex") or str(Path.home() / ".cloudos-agents/bin/codex")
        command = [executable, "exec", "--ephemeral", "--ignore-user-config", "--skip-git-repo-check",
                   "--sandbox", "workspace-write", "-c", "sandbox_workspace_write.network_access=true",
                   "--json", "-C", str(args.workspace), prompt]
    else:
        executable = shutil.which("claude")
        if not executable:
            raise SystemExit("Claude Code CLI not installed")
        skill = Path.home() / ".claude/skills/account-access/scripts/access.py"
        command = [executable, "-p", "--output-format", "stream-json", "--verbose", "--no-session-persistence",
                   "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--tools", "Bash,Read,Skill",
                   "--permission-mode", "dontAsk", "--allowedTools", "Read", "Skill",
                   "Bash(python3 " + str(skill) + " *)", "--", prompt]
    artifacts = Path("artifacts/agent-tests")
    artifacts.mkdir(parents=True, exist_ok=True)
    raw_path = artifacts / (args.agent + "-release.jsonl")
    error_path = artifacts / (args.agent + "-release.stderr.txt")
    started = time.monotonic()
    result = subprocess.run(command, cwd=args.workspace, capture_output=True, text=True, timeout=240,
                            env=dict(os.environ))
    private_file(raw_path, result.stdout.encode(), replace=raw_path.exists())
    private_file(error_path, result.stderr.encode(), replace=error_path.exists())
    ids, final, permission_denials = set(), "", []
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        ids.update(task_ids(event))
        if event.get("type") == "result":
            final = event.get("result", "")
            permission_denials = event.get("permission_denials", [])
        item = event.get("item", {})
        if event.get("type") == "item.completed" and item.get("type") == "agent_message":
            final = item.get("text", "")
    verified = []
    for ident in sorted(ids):
        task = client.request("GET", "/v1/tasks/" + ident)
        verified.append({"task_id": ident, "status": task["status"], "progress": task.get("progress"),
                         "total": task.get("total"), "accounts": [r["account"] for r in task.get("results", [])]})
    passed = (result.returncode == 0 and bool(final) and not permission_denials
              and any(t["status"] == "COMPLETED" and set(t["accounts"]) == expected for t in verified))
    summary = {"agent": args.agent, "service_version": discovery.get("service_version"),
               "environment": discovery["environment"], "exit_code": result.returncode,
               "elapsed_seconds": round(time.monotonic() - started, 3), "passed": passed,
               "expected_accounts": sorted(expected), "independently_verified_tasks": verified,
               "permission_denial_count": len(permission_denials), "final_report": final,
               "limits": ["Public demo/fixture accounts only", "Existing host login and hooks used; no hooks disabled",
                          "This is a CLI agent test; desktop-chat discovery is a separate host interaction"]}
    destination = artifacts / (args.agent + "-summary.json")
    destination.write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "final_report"}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
