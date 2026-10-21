import asyncio
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from account_access import onepassword_source as source
from account_access.errors import AccessError
from account_access.password_sync import enroll, refresh, unlink, validate_link, view


@pytest.fixture
def request_data():
    return {"token": "synthetic-service-account-token", "vault": "a" * 26,
            "item": "b" * 26, "origin": "https://example.test"}


@pytest.fixture
def item(request_data):
    return SimpleNamespace(
        id=request_data["item"], vault_id=request_data["vault"], category="Login",
        websites=[SimpleNamespace(url="https://example.test/login", autofill_behavior="ExactDomain")],
        fields=[SimpleNamespace(id="username", value="owner@example.test", field_type="Text", section_id=None),
                SimpleNamespace(id="password", value="synthetic-password", field_type="Concealed", section_id=None),
                SimpleNamespace(id="totp", value="must-not-return-or-resolve", field_type="Totp", section_id=None)],
        notes="must-not-return-notes", files=["must-not-download"])


def test_reads_only_builtin_credentials_for_exact_item_and_origin(item, request_data):
    assert source._credentials(item, request_data) == {
        "username": "owner@example.test", "password": "synthetic-password"}


@pytest.mark.parametrize("change", ["item", "vault", "category", "origin", "never", "username_type",
                                  "password_type", "section", "duplicate", "missing", "empty", "oversize"])
def test_rejects_changed_authority_and_ambiguous_fields(item, request_data, change):
    if change == "item":
        item.id = "c" * 26
    elif change == "vault":
        item.vault_id = "c" * 26
    elif change == "category":
        item.category = "CreditCard"
    elif change == "origin":
        item.websites[0].url = "https://different.example.test"
    elif change == "never":
        item.websites[0].autofill_behavior = "Never"
    elif change == "username_type":
        item.fields[0].field_type = "Concealed"
    elif change == "password_type":
        item.fields[1].field_type = "Text"
    elif change == "section":
        item.fields[1].section_id = "custom-section"
    elif change == "duplicate":
        item.fields.append(copy.deepcopy(item.fields[1]))
    elif change == "missing":
        item.fields.pop(0)
    elif change == "empty":
        item.fields[1].value = ""
    else:
        item.fields[1].value = "x" * 4097
    with pytest.raises(AccessError, match="password_source_item_changed"):
        source._credentials(item, request_data)


@pytest.fixture
def sdk(monkeypatch, item):
    calls = []

    class RateLimitExceededException(Exception):
        pass

    class Client:
        @classmethod
        async def authenticate(cls, **kwargs):
            calls.append(("authenticate", kwargs))

            async def get(vault, item_id):
                calls.append(("get", vault, item_id))
                return item

            return SimpleNamespace(items=SimpleNamespace(get=get))

    monkeypatch.setitem(sys.modules, "onepassword", SimpleNamespace(Client=Client))
    monkeypatch.setitem(sys.modules, "onepassword.errors", SimpleNamespace(
        RateLimitExceededException=RateLimitExceededException))
    return calls, Client, RateLimitExceededException


def test_sdk_has_no_desktop_token_environment_list_or_write_fallback(sdk, request_data, monkeypatch):
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "unrelated-environment-token")
    monkeypatch.setenv("OP_CONNECT_HOST", "https://unrelated.example.test")
    calls, _, _ = sdk
    assert asyncio.run(source._read(request_data))["password"] == "synthetic-password"
    assert calls == [
        ("authenticate", {"auth": request_data["token"], "integration_name": "Account Access",
                          "integration_version": "0.8.0"}),
        ("get", request_data["vault"], request_data["item"])]


@pytest.mark.parametrize("failure", ["timeout", "rate_limit", "provider_secret", "runtime"])
def test_sdk_errors_never_return_exception_contents(sdk, request_data, failure):
    _, client, rate_limit = sdk

    async def fail(**kwargs):
        error = {"timeout": TimeoutError, "rate_limit": rate_limit,
                 "provider_secret": Exception, "runtime": OSError}[failure]
        raise error("synthetic-password synthetic-service-account-token raw-provider-error")

    client.authenticate = fail
    with pytest.raises(AccessError) as caught:
        asyncio.run(source._read(request_data))
    reason = {"provider_secret": "password_source_access_removed",
              "runtime": "password_source_runtime_unavailable"}.get(failure, "password_source_unavailable")
    assert caught.value.reason == reason
    assert "synthetic" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_sdk_async_cancellation_is_bounded(sdk, request_data, monkeypatch):
    _, client, _ = sdk
    canceled = []

    async def stall(**kwargs):
        try:
            await asyncio.sleep(60)
        finally:
            canceled.append(True)

    client.authenticate = stall
    monkeypatch.setattr(source, "SDK_DEADLINE", 0.02)
    with pytest.raises(AccessError, match="password_source_unavailable"):
        asyncio.run(source._read(request_data))
    assert canceled == [True]


def test_private_subprocess_ignores_owner_environment_and_uses_temporary_home(tmp_path, monkeypatch):
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "unrelated-secret")
    monkeypatch.setenv("PYTHONPATH", "/unrelated-agent-code")
    program = ("import json,os,sys; request=json.load(sys.stdin); "
               "print(json.dumps({'request':request,'environment':dict(os.environ),'cwd':os.getcwd(),"
               "'isolated':sys.flags.isolated,'bytecode':sys.flags.dont_write_bytecode}))")
    result = json.loads(source._exchange([sys.executable, "-I", "-B", "-c", program],
                                        b'{"request":"synthetic"}', str(tmp_path)))
    assert result["request"] == {"request": "synthetic"}
    assert result["cwd"] == str(tmp_path)
    assert result["environment"]["HOME"] == str(tmp_path)
    assert result["isolated"] == result["bytecode"] == 1
    assert not {"OP_SERVICE_ACCOUNT_TOKEN", "PYTHONPATH", "OP_CONNECT_HOST"} & result["environment"].keys()


def test_native_process_timeout_kills_and_reaps_descendants(tmp_path):
    pid_file = tmp_path / "synthetic-child-pid"
    program = ("import pathlib,subprocess,sys,time; "
               "p=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(60)']); "
               f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); time.sleep(60)")
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        source._exchange([sys.executable, "-I", "-B", "-c", program], b"{}", str(tmp_path), deadline=0.3)
    assert time.monotonic() - started < 6
    if pid_file.exists():
        pid = int(pid_file.read_text())
        # The killed descendant can briefly remain a zombie until the system
        # reaps it; it must never remain a running SDK helper after cancellation.
        for _ in range(100):
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                   capture_output=True, text=True).stdout.strip()
            if not state or state.startswith("Z"):
                break
            time.sleep(0.01)
        assert not state or state.startswith("Z")


def test_subprocess_output_is_capped_before_allocating_unbounded_data(tmp_path):
    program = "import os;os.write(1,b'x'*1000000)"
    with pytest.raises(ValueError):
        source._exchange([sys.executable, "-I", "-B", "-c", program], b"{}", str(tmp_path), deadline=2)


@pytest.mark.parametrize("response", [b'{"reason":"raw-secret"}', b'{"reason":[]}',
                                      b'{"password":"secret"}', b'{"username":"x","password":"p","extra":"secret"}',
                                      b'provider-secret-is-not-json'])
def test_parent_refuses_unexpected_child_outputs_without_leaking(request_data, monkeypatch, response):
    monkeypatch.setattr(source, "_exchange", lambda *args: response)
    with pytest.raises(AccessError, match="password_source_item_changed") as caught:
        source.fetch(request_data, request_data["origin"])
    assert "secret" not in str(caught.value)


def test_parent_pipeline_keeps_token_out_of_argv_environment_and_removes_temporary_home(request_data, monkeypatch):
    observed = {}

    def exchange(command, payload, directory):
        observed.update(command=command, payload=json.loads(payload), directory=directory)
        assert os.stat(directory).st_mode & 0o777 == 0o700
        return b'{"username":"owner@example.test","password":"synthetic-password"}'

    monkeypatch.setattr(source, "_exchange", exchange)
    assert source.fetch(request_data, request_data["origin"])["password"] == "synthetic-password"
    assert observed["command"] == [sys.executable, "-I", "-B", "-m", "account_access.onepassword_source"]
    assert request_data["token"] not in json.dumps(observed["command"])
    assert observed["payload"] == request_data
    assert not Path(observed["directory"]).exists()


def test_service_account_link_rotation_and_unlink_preserve_grants(env, monkeypatch):
    provider, broker, _ = env
    store = broker.store
    username = store.get("credential:demo-web")["username"]
    state = {"username": username, "password": "new-synthetic-password"}
    link = {"provider": "onepassword-service-account", "token": "synthetic-service-token",
            "vault": "a" * 26, "item": "b" * 26}
    monkeypatch.setattr(source, "_exchange", lambda *args: json.dumps(state).encode())
    with store.db() as db:
        grants = [tuple(x) for x in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    store.put("connection:demo-web", {"synthetic": "old-session"})
    assert validate_link(store, "demo-web", link) == link
    assert enroll(store, "demo-web", link)["status"] == "SYNCED"
    assert store.get("credential:demo-web") == state
    assert store.get("connection:demo-web") is None
    assert view(store)[0]["provider"] == "1Password service account"
    assert "token" not in json.dumps(view(store))
    state["password"] = provider.password = "second-synthetic-password"
    with store.lock("account:demo-web"):
        refresh(store, "demo-web", force=True)
    assert store.get("credential:demo-web") == state
    with store.db() as db:
        assert grants == [tuple(x) for x in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    unlink(store, "demo-web")
    assert store.get("credential:demo-web") is None
    assert store.get("password-link:demo-web") is None


def test_source_token_is_redacted_if_website_content_echoes_it(env, monkeypatch):
    _, broker, _ = env
    token = "synthetic-service-token-never-return-to-agent"
    credential = broker.store.get("credential:demo-web")
    monkeypatch.setattr(source, "_exchange", lambda *args: json.dumps(credential).encode())
    enroll(broker.store, "demo-web", {"provider": "onepassword-service-account", "token": token,
                                    "vault": "a" * 26, "item": "b" * 26})

    def page(*args, secret_values):
        assert token in secret_values
        return {"heading": "Untrusted page echoed " + token}

    monkeypatch.setattr(broker.browser, "read", page)
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] == "COMPLETED"
    assert result["data"]["heading"] == "Untrusted page echoed [REDACTED]"
    assert token not in json.dumps(result)


def test_runtime_repair_clears_only_its_source_prerequisite(env, monkeypatch):
    _, broker, _ = env
    store = broker.store
    credential = store.get("credential:demo-web")
    response = dict(credential)
    monkeypatch.setattr(source, "_exchange", lambda *args: json.dumps(response).encode())
    enroll(store, "demo-web", {"provider": "onepassword-service-account", "token": "synthetic-token",
                              "vault": "a" * 26, "item": "b" * 26})
    saved = store.get("password-link:demo-web")
    saved["next_at"] = 0
    store.put("password-link:demo-web", saved)
    response.clear()
    response["reason"] = "password_source_runtime_unavailable"
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] == "NEEDS_USER"
    assert result["reason"] == "password_source_runtime_unavailable"
    presence = store.challenge("demo-web", "action", "browser_action_required")
    response.clear()
    response.update(credential)
    with store.lock("account:demo-web"):
        refresh(store, "demo-web", force=True)
    assert [x["id"] for x in store.pending("demo-web")] == [presence["id"]]


@pytest.mark.parametrize("updates", [{"endpoint": "https://attacker.example"}, {"provider": "desktop"},
                                      {"token": "token\nsecret"}, {"vault": "../vault"}])
def test_service_connection_cannot_override_sdk_endpoint_or_use_desktop_auth(env, updates):
    _, broker, _ = env
    link = {"provider": "onepassword-service-account", "token": "synthetic-service-token",
            "vault": "a" * 26, "item": "b" * 26}
    with pytest.raises(AccessError, match="invalid_password_sync_link"):
        validate_link(broker.store, "demo-web", {**link, **updates})
