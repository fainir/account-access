"""Disposable-Mac-CI owner-user skill setup against an actual isolated worker."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from account_access.agent_setup import RELATIVE, install, prepare, status
from account_access.worker_bootstrap import root_managed_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("phase", choices=["prepare", "install"])
    args = parser.parse_args()
    if (
        sys.platform != "darwin"
        or os.getuid() == 0
        or os.getuid() != os.geteuid()
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or not str(args.prefix).startswith(
            "/Library/PrivilegedHelperTools/account-access-worker-qa-"
        )
    ):
        raise RuntimeError("disposable_agent_setup_required")
    root_managed_path(args.prefix)
    root_managed_path(Path(__file__))
    home = args.prefix / "portable-owner-home"
    hosts = ["codex", "claude"]
    options = {"python": args.prefix / "runtime/bin/python", "socket": args.socket}
    if args.phase == "prepare":
        for name, filename in [(".codex", "AGENTS.md"), (".claude", "CLAUDE.md")]:
            directory = home / name
            directory.mkdir(mode=0o700)
            file = directory / filename
            file.write_text("Keep my existing preferences.\n")
            file.chmod(0o600)
        result = prepare(home, hosts, **options)
        assert result["status"] == "PREPARED"
        assert not (home / ".agents/skills/account-access").exists()
        print(json.dumps({"status": "PREPARED", "client_id": result["client_id"]}))
        return 0
    result = install(home, hosts, **options)
    token = (home / RELATIVE / "token").read_text()
    assert token not in json.dumps(result)
    assert status(home, hosts, **options)["client_id"] == result["client_id"]
    checks = {}
    for name, folder in [("portable", ".agents"), ("claude", ".claude")]:
        launcher = home / folder / "skills/account-access/scripts/access"
        invoked = subprocess.run(
            [str(launcher), "accounts"],
            capture_output=True,
            timeout=15,
            env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
        )
        value = json.loads(invoked.stdout)
        checks[name + "_launcher_discovers_empty_approved_account_set"] = (
            invoked.returncode == 0 and value["accounts"] == []
        )
        checks[name + "_launcher_omits_client_capability"] = (
            token.encode() not in invoked.stdout + invoked.stderr
        )
    for folder, filename in [(".codex", "AGENTS.md"), (".claude", "CLAUDE.md")]:
        value = (home / folder / filename).read_text()
        assert (
            value.startswith("Keep my existing preferences.")
            and value.count("<!-- account-access:automatic:start -->") == 1
        )
        assert token not in value
    checks["both_host_session_instructions_preserved"] = True
    try:
        with (args.prefix / "first-enrollment-destination/state.db").open("rb"):
            blocked = False
    except PermissionError:
        blocked = True
    checks["owner_user_client_install_has_no_broker_store_access"] = blocked
    assert all(value is True for value in checks.values())
    print(json.dumps({"status": "PASSED", "checks": checks, "client_id": result["client_id"]}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print('{"status":"FAILED","reason":"agent_setup_fixture_failed"}')
        raise SystemExit(78) from None
