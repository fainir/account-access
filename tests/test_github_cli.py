import hashlib
import json

import pytest
from pydantic import ValidationError

from account_access import github_cli
from account_access.errors import AccessError
from account_access.models import GitHubCLIAccount, TaskRequest


@pytest.fixture
def vendor(tmp_path, monkeypatch):
    binary = tmp_path / "gh"
    binary.write_text('''#!/bin/sh
[ "$1" = api ] && [ "$2" = --hostname ] && [ "$3" = github.com ] || exit 2
[ "$4" = --method ] && [ "$5" = GET ] && [ "$6" = user ] || exit 2
[ "$7" = --jq ] && [ "$8" = '{id,login}' ] && [ "$#" = 8 ] || exit 2
[ -z "${GH_TOKEN:-}" ] && [ -z "${GITHUB_TOKEN:-}" ] && [ -z "${GH_DEBUG:-}" ] || exit 2
printf '%s\\n' '{"id":123,"login":"fictional-user"}'
''')
    binary.chmod(0o700)
    monkeypatch.setenv("GH_TOKEN", "fictional-inherited-token")
    monkeypatch.setenv("GITHUB_TOKEN", "fictional-other-token")
    monkeypatch.setenv("GH_DEBUG", "api")
    monkeypatch.setattr(github_cli, "installed_executable", lambda: str(binary))
    return binary


def test_existing_vendor_login_runs_through_agent_task_without_token_copy(env, vendor):
    _, broker, _ = env
    broker.store.new_client("generic")
    preview = github_cli.preview(broker.store)
    assert preview["login"] == "fictional-user"
    assert not any(x["account"] == github_cli.HANDLE for x in broker.accounts("generic")["accounts"])
    connected = github_cli.apply(broker, preview["id"])
    assert connected["authenticated"]
    task = broker.submit("generic", TaskRequest(key="vendor-identity", steps=[
        {"account": github_cli.HANDLE, "operation": "status"}]))
    broker.advance(task["task_id"])
    result = broker.task("generic", task["task_id"])
    assert result["status"] == "COMPLETED"
    assert result["results"][0]["data"] == {"authenticated": True, "login": "fictional-user"}
    assert "token" not in json.dumps(result)
    assert broker.store.get("credential:" + github_cli.HANDLE) is None
    assert broker.store.get("connection:" + github_cli.HANDLE)["provider"] == "github_cli"
    assert broker.run("generic", github_cli.HANDLE, "delete_repo")["status"] == "DENIED"
    broker.revoke(account=github_cli.HANDLE)
    assert broker.run("generic", github_cli.HANDLE, "status")["status"] == "DENIED"


def test_binary_update_requires_new_owner_review(env, vendor):
    _, broker, _ = env
    broker.store.new_client("generic")
    preview = github_cli.preview(broker.store)
    vendor.write_text("#!/bin/sh\nexit 0\n")
    with pytest.raises(AccessError, match="github_cli_installation_changed"):
        github_cli.apply(broker, preview["id"])
    assert github_cli.HANDLE not in broker.store.config().accounts


def test_identity_switch_does_not_silently_read_another_account(env, vendor, monkeypatch):
    _, broker, _ = env
    broker.store.new_client("generic")
    github_cli.apply(broker, github_cli.preview(broker.store)["id"])
    monkeypatch.setattr(github_cli, "_execute", lambda _: {"id": 456, "login": "different-user"})
    first = broker.run("generic", github_cli.HANDLE, "status")
    assert first["status"] == "NEEDS_USER" and first["reason"] == "github_cli_account_changed"
    assert "different-user" not in json.dumps(first)
    assert broker.run("generic", github_cli.HANDLE, "status")["challenge"]["id"] == first["challenge"]["id"]


def test_model_cannot_configure_arbitrary_commands_or_operations(vendor):
    data = {"label": "Example", "executable": str(vendor),
            "executable_sha256": hashlib.sha256(vendor.read_bytes()).hexdigest(),
            "user_id": 123, "login": "fictional-user", "operations": {"status": {}}}
    GitHubCLIAccount(**data)
    for change in [{"command": "auth token"}, {"host": "attacker.example"},
                   {"operations": {"write": {}}}, {"operations": {"status": {"url": "/repos"}}}]:
        with pytest.raises(ValidationError):
            GitHubCLIAccount(**{**data, **change})


def test_vendor_errors_do_not_disclose_stderr(vendor):
    vendor.write_text("#!/bin/sh\nprintf 'fictional-private-token' >&2\nexit 1\n")
    with pytest.raises(AccessError, match="github_cli_login_required") as failure:
        github_cli._execute(str(vendor))
    assert "fictional-private-token" not in str(failure.value)
