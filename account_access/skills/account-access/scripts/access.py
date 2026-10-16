#!/usr/bin/env python3
"""Portable entrypoint. Installation metadata contains paths, not secrets."""
import json
import os
import subprocess
import sys
from pathlib import Path

settings = Path(__file__).resolve().parents[1] / "installation.json"
if not settings.exists():
    print(json.dumps({"status": "NEEDS_USER", "reason": "skill_not_installed"}))
    sys.exit(2)
config = json.loads(settings.read_text())
env = dict(os.environ)
env["ACCESS_CLIENT_CONFIG"] = config["client_config"]
allowed = {"accounts", "status", "run", "task", "audit", "doctor"}
if len(sys.argv) < 2 or sys.argv[1] not in allowed:
    print(json.dumps({"status": "DENIED", "reason": "agent_command_not_supported"}))
    sys.exit(3)
sys.exit(subprocess.call([config["python"], "-I", "-m", "account_access.cli", *sys.argv[1:]], env=env))
