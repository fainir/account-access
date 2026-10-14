"""Test an existing logged-in agent with a plain-language public-account request."""

import argparse
import json
import subprocess
import time
from pathlib import Path

from agent_smoke import task_ids
from account_access.client import Client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", choices=["codex", "claude"])
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--model", help="Optional Codex model for this isolated compatibility test; never changes user settings")
    args = parser.parse_args()
    root = Path.home() / ".local/share/account-access"
    client = Client(root / "clients/generic/client.json")
    expected = {"personal-store", "work-store", "member-portal"}
    discovery = client.request("GET", "/v1/accounts")
    if {row["account"] for row in discovery["accounts"]} != expected:
        raise SystemExit("This test only uses the three explicitly configured public examples.")
    prompt = ("Compare the cheapest item in my personal and work shopping accounts and get my "
              "membership welcome message. Save the results together so I can check them later. "
              "Use only those three connected public example accounts. Do not access private "
              "accounts or change settings.")
    if args.agent == "codex":
        command = ["codex", "exec", "--ephemeral", "--skip-git-repo-check", "--json", "-C", str(args.workspace)]
        if args.model:
            command += ["--model", args.model]
        command.append(prompt)
    else:
        command = ["claude", "-p", "--output-format", "stream-json", "--verbose",
                   "--no-session-persistence", "--", prompt]
    prior_audit = {row["id"] for row in client.request("GET", "/v1/audit")["events"]}
    started = time.monotonic()
    result = subprocess.run(command, cwd=args.workspace, capture_output=True, text=True, timeout=240)
    directory = Path("artifacts/agent-tests")
    directory.mkdir(exist_ok=True)
    raw = directory / (args.agent + "-implicit-06.jsonl")
    raw.write_text(result.stdout)
    raw.chmod(0o600)
    error = directory / (args.agent + "-implicit-06.stderr.txt")
    error.write_text(result.stderr)
    error.chmod(0o600)
    ids, denied = set(), []
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        ids.update(task_ids(event))
        if event.get("type") == "result":
            denied.extend(event.get("permission_denials", []))
    verified = []
    for ident in sorted(ids):
        task = client.request("GET", "/v1/tasks/" + ident)
        verified.append({"task_id": ident, "status": task["status"], "progress": task.get("progress"),
                         "total": task.get("total"), "accounts": [r["account"] for r in task.get("results", [])]})
    completed = [{"account": row["account"], "operation": row["operation"]}
                 for row in client.request("GET", "/v1/audit")["events"]
                 if row["id"] not in prior_audit and row["event"] == "operation_completed"]
    account_denials = [row for row in denied if "/skills/account-access/scripts/access" in
                      str(row.get("tool_input", {}))]
    saved = [path.name for path in args.workspace.glob("*.md") if path.stat().st_size > 0]
    durable = any(t["status"] == "COMPLETED" and set(t["accounts"]) == expected for t in verified)
    passed = (result.returncode == 0 and not account_denials and (bool(saved) or durable) and
              {row["account"] for row in completed} == expected)
    report = {"agent": args.agent, "service_version": discovery["service_version"], "passed": passed,
              "prompt": prompt, "explicit_skill_or_command_in_prompt": False,
              "persistent_instructions": "Existing user profile with managed Account Access guidance",
              "host_approval_and_hooks": "Existing modes and hooks inherited; installed client integration applied", "exit_code": result.returncode,
              "test_model_override": args.model,
              "elapsed_seconds": round(time.monotonic() - started, 2),
              "permission_denial_count": len(denied), "account_access_permission_denials": len(account_denials),
              "verified_tasks": verified, "independently_verified_operations": completed,
              "saved_results": saved,
              "limits": "Public testing websites only; CLI session, not a desktop recording. "
                        "Unrelated host housekeeping denials are reported separately from Account Access."}
    (directory / (args.agent + "-implicit-06.json")).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
