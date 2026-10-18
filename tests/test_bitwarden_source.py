"""Real private subprocess/profile custody with fictional Password Manager data."""

import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from account_access import bitwarden_source as source, password_sync
from account_access.errors import AccessError


USER = "10000000-0000-4000-8000-000000000001"
ITEM = "20000000-0000-4000-8000-000000000002"
SESSION = base64.b64encode(b"f" * 64).decode()


@pytest.fixture
def cli(tmp_path, monkeypatch, env):
    _, broker, _ = env
    username = broker.store.get("credential:demo-web")["username"]
    state = {
        "user": USER,
        "email": "owner@example.test",
        "session": SESSION,
        "item": {
            "id": ITEM,
            "type": 1,
            "reprompt": 0,
            "deletedDate": None,
            "archivedDate": None,
            "login": {
                "username": username,
                "password": "rotated-fictional-password",
                "totp": "never-return-this-key",
                "uris": [{"uri": broker.store.config().accounts["demo-web"].login_url}],
            },
        },
        "calls": [],
    }
    state_path = tmp_path / "provider.json"
    state_path.write_text(json.dumps(state))
    program = tmp_path / "node"
    entry = tmp_path / "build/bw.js"
    entry.parent.mkdir()
    entry.write_text("// Fictional CLI entry; never executed as JavaScript.\n")
    entry.chmod(0o600)
    entry_hash = hashlib.sha256(entry.read_bytes()).hexdigest()
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_text(json.dumps({
        "schema": 1, "version": source.VERSION, "architecture": "arm64",
        "entrypoint": "build/bw.js",
        "node_relative": "lib/python3.12/site-packages/playwright/driver/node",
        "node_version": source.NODE_VERSION, "native_addons": False,
        "entrypoint_sha256": entry_hash, "upstream_archive_sha256": source.ARCHIVE_SHA256,
    }))
    manifest.chmod(0o600)
    program.write_text(
        "#!/usr/bin/python3\n"
        + f"STATE={str(state_path)!r}\n"
        + r"""
import datetime,json,os,pathlib,sys,time
state_path=pathlib.Path(STATE)
state=json.loads(state_path.read_text())
args=sys.argv[1:]
assert args[:2]==['--no-global-search-paths','--no-addons']
assert pathlib.Path(args[2]).name=='bw.js'
args=args[3:]
assert args.pop()=='--nointeraction'
directory=pathlib.Path(os.environ['BITWARDENCLI_APPDATA_DIR'])
assert os.environ['HOME']==os.environ['TMPDIR']==str(directory)
assert os.environ['BW_NOINTERACTION']=='true'
assert os.environ['BITWARDEN_DESKTOP_PROXY_PATH']==str(directory/'.account-access-disabled-desktop-ipc')
assert not pathlib.Path(os.environ['BITWARDEN_DESKTOP_PROXY_PATH']).exists()
assert not {'NODE_OPTIONS','BW_PASSWORD','PYTHONPATH','UNRELATED_SECRET'} & os.environ.keys()
profile_path=directory/'data.json'
profile=json.loads(profile_path.read_text()) if profile_path.exists() else {}
state['calls'].append({'args':args,'environment':sorted(os.environ),'profile_nonce':profile.get('nonce'),
                       'home':str(directory),'mode':directory.stat().st_mode & 511})
state_path.write_text(json.dumps(state))
def save():
 profile_path.write_text(json.dumps(profile))
 profile_path.chmod(384)
if args==['--version']:
 print(state.get('version','2026.10.0'))
elif args[:2]==['config','server']:
 profile={'server':args[2],'nonce':0,'refresh_token':'fictional-refresh-0'}; save()
elif args[:2]==['login','--apikey']:
 assert os.environ['BW_CLIENTID']=='user.'+state['user']
 assert os.environ['BW_CLIENTSECRET']=='fictional-api-secret'
 assert 'ACCOUNT_ACCESS_BW_MASTER_PASSWORD' not in os.environ
 profile['authenticated']=True; save(); print('discarded-api-login-session')
elif args[0]=='unlock':
 assert args==['unlock','--passwordenv','ACCOUNT_ACCESS_BW_MASTER_PASSWORD','--raw']
 assert os.environ['ACCOUNT_ACCESS_BW_MASTER_PASSWORD']=='fictional-master-password'
 assert not {'BW_CLIENTID','BW_CLIENTSECRET'} & os.environ.keys()
 if state.get('echo_master'): profile['bad']='fictional-master-password'
 save(); print(state['session'])
elif args==['status']:
 assert not {'BW_CLIENTID','BW_CLIENTSECRET','ACCOUNT_ACCESS_BW_MASTER_PASSWORD'} & os.environ.keys()
 status={'status':'unlocked','serverUrl':profile['server'],'userId':state['user'],
         'userEmail':state['email'],'lastSync':profile.get('lastSync')}
 if state.get('revoked'): status['status']='unauthenticated'
 status.update(state.get('status_override',{})); print(json.dumps(status))
elif args==['sync','--force']:
 assert os.environ['BW_SESSION']==state['session']
 profile['nonce']+=1; profile['refresh_token']='fictional-refresh-'+str(profile['nonce'])
 if not state.get('stale_sync'): profile['lastSync']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 save()
 if state.get('failure'):
  print('fictional-api-secret provider-diagnostic-must-not-escape'); sys.exit(3)
 time.sleep(state.get('delay',0)); print('Syncing complete.')
elif args[:2]==['get','item']:
 assert args==['get','item',state['item']['id']]
 assert os.environ['BW_SESSION']==state['session']
 if state.get('oversize'): print('x'*300000)
 else: print(json.dumps(state['item']))
else: raise AssertionError('Unexpected command; no list/export/serve/write permitted')
"""
    )
    program.chmod(0o700)
    monkeypatch.setattr(source, "CLI", entry)
    monkeypatch.setattr(source, "NODE", program)
    monkeypatch.setattr(source, "MANIFEST", manifest)
    monkeypatch.setattr(source, "ENTRYPOINT_SHA256", entry_hash)
    monkeypatch.setenv("NODE_OPTIONS", "--inspect=0")
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-inherit")
    monkeypatch.setenv("BITWARDEN_DESKTOP_PROXY_PATH", "/unrelated-owner-binary")
    return broker.store, state_path


def setup_data(**updates):
    return {
        "region": "us",
        "client_id": "user." + USER,
        "client_secret": "fictional-api-secret",
        "master_password": "fictional-master-password",
        "consent_vault_access": True,
        **updates,
    }


def mutate(path, **updates):
    value = json.loads(path.read_text())
    value.update(updates)
    path.write_text(json.dumps(value))


def link(connection):
    return {
        "provider": "bitwarden",
        "connection": connection["id"],
        "connection_generation": connection["generation"],
        "item": ITEM,
    }


def test_fresh_enrollment_private_pipes_encrypted_profile_no_master_persistence(cli):
    store, provider = cli
    connection = source.connect(store, setup_data())
    assert connection["status"] == "CONNECTED"
    assert source.available(store)
    assert source.connections(store) == [connection]
    record = store.get(source.PREFIX + connection["id"])
    encoded = json.dumps(record)
    assert "fictional-master-password" not in encoded
    assert record["session"] == SESSION
    assert record["profile"]["refresh_token"] == "fictional-refresh-1"
    assert not any(store.root.glob("bitwarden-*"))
    assert b"fictional-refresh" not in store.path.read_bytes()
    public = json.dumps(source.connections(store))
    assert not any(
        secret in public for secret in [SESSION, "fictional-api-secret", "fictional-refresh"]
    )
    calls = json.loads(provider.read_text())["calls"]
    assert len(calls) == 8
    assert all(call["mode"] == 0o700 for call in calls)
    assert len({call["home"] for call in calls}) == 1
    assert not Path(calls[0]["home"]).exists()
    assert not any("fictional" in json.dumps(call["args"]) for call in calls)
    assert all(
        not {"list", "export", "serve", "edit", "create"} & set(call["args"]) for call in calls
    )


@pytest.mark.parametrize(
    "change",
    [
        {"region": []},
        {"region": "https://attacker.example"},
        {"client_id": "organization." + USER},
        {"client_id": "user." + USER.upper()},
        {"client_id": "user.not-an-id"},
        {"client_secret": "secret\n"},
        {"master_password": "secret\0"},
        {"extra": "unknown"},
    ],
)
def test_enrollment_rejects_untrusted_shape_before_any_cli(cli, change):
    store, provider = cli
    # This identifier's digits alone have no case; use a noncanonical UUID.
    if change.get("client_id") == "user." + USER.upper():
        change = {"client_id": "user.A0000000-0000-4000-8000-000000000001"}
    with pytest.raises(AccessError, match="bitwarden_connection_invalid"):
        source.connect(store, setup_data(**change))
    assert json.loads(provider.read_text())["calls"] == []


def test_vault_authority_requires_explicit_boolean_consent(cli):
    store, provider = cli
    for consent in [False, 1, "true", None]:
        with pytest.raises(AccessError, match="bitwarden_vault_consent_required"):
            source.connect(store, setup_data(consent_vault_access=consent))
    assert json.loads(provider.read_text())["calls"] == []


@pytest.mark.parametrize(
    "failure,reason",
    [
        ("echo_master", "password_source_item_changed"),
        ("stale_sync", "password_source_unavailable"),
        ("version", "password_source_runtime_unavailable"),
    ],
)
def test_failed_initial_setup_never_publishes_a_connection(cli, failure, reason):
    store, provider = cli
    mutate(provider, **{failure: "0.0.0" if failure == "version" else True})
    with pytest.raises(AccessError, match=reason):
        source.connect(store, setup_data())
    assert source.connections(store) == []
    assert not any(store.root.glob("bitwarden-*"))


def test_exact_item_rotation_replaces_password_and_session_but_not_grants(cli):
    store, provider = cli
    connection = source.connect(store, setup_data())
    with store.db() as db:
        grants = [tuple(row) for row in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    password_sync.enroll(store, "demo-web", link(connection))
    store.put("connection:demo-web", {"fictional": "old-browser-session"})
    value = json.loads(provider.read_text())
    value["item"]["login"]["password"] = "newer-fictional-password"
    provider.write_text(json.dumps(value))
    with store.lock("account:demo-web"):
        password_sync.refresh(store, "demo-web", force=True)
    assert store.get("credential:demo-web")["password"] == "newer-fictional-password"
    assert store.get("connection:demo-web") is None
    assert password_sync.view(store)[0]["provider"] == "Bitwarden"
    record = store.get(source.PREFIX + connection["id"])
    assert record["profile"]["nonce"] == 3
    assert record["generation"] == connection["generation"]
    with store.db() as db:
        assert grants == [tuple(row) for row in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]


@pytest.mark.parametrize(
    "change",
    [
        "item",
        "type",
        "archived",
        "deleted",
        "reprompt",
        "origin",
        "username",
        "missing-password",
        "never",
        "userinfo",
        "oversize",
    ],
)
def test_drift_and_oversize_fail_closed_and_remove_cached_login(cli, change):
    store, provider = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    state = json.loads(provider.read_text())
    item = state["item"]
    if change == "item":
        # Keep the requested UUID fixed but return an unexpected response ID.
        original = source._credentials

        def changed(value, *args, **kwargs):
            value["id"] = "30000000-0000-4000-8000-000000000003"
            return original(value, *args, **kwargs)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(source, "_credentials", changed)
            with pytest.raises(AccessError, match="password_source_item_changed"):
                password_sync.refresh(store, "demo-web", force=True)
        assert store.get("credential:demo-web") is None
        return
    if change == "type":
        item["type"] = 2
    elif change == "archived":
        item["archivedDate"] = "2026-01-01T00:00:00Z"
    elif change == "deleted":
        item["deletedDate"] = "2026-01-01T00:00:00Z"
    elif change == "reprompt":
        item["reprompt"] = 1
    elif change == "origin":
        item["login"]["uris"] = [{"uri": "https://attacker.example"}]
    elif change == "username":
        item["login"]["username"] = "different-owner"
    elif change == "missing-password":
        item["login"].pop("password")
    elif change == "never":
        item["login"]["uris"][0]["match"] = 5
    elif change == "userinfo":
        item["login"]["uris"] = [{"uri": "https://fake:secret@example.test"}]
    elif change == "oversize":
        state["oversize"] = True
    provider.write_text(json.dumps(state))
    with pytest.raises(AccessError):
        password_sync.refresh(store, "demo-web", force=True)
    assert store.get("credential:demo-web") is None
    assert store.get("connection:demo-web") is None


@pytest.mark.parametrize(
    "change",
    [
        {"userId": "30000000-0000-4000-8000-000000000003"},
        {"serverUrl": "https://attacker.example"},
        {"status": "locked"},
        {"userEmail": "other@example.test"},
    ],
)
def test_source_identity_drift_stops_before_get_and_invalidates_linked_cache(cli, change):
    store, provider = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    before = len(json.loads(provider.read_text())["calls"])
    mutate(provider, status_override=change)
    with pytest.raises(AccessError):
        password_sync.refresh(store, "demo-web", force=True)
    calls = json.loads(provider.read_text())["calls"][before:]
    assert not any(call["args"][:2] == ["get", "item"] for call in calls)
    assert store.get("credential:demo-web") is None
    assert store.get("connection:demo-web") is None


def test_failed_sync_saves_refresh_rotation_without_exposing_diagnostic_or_stale_password(cli):
    store, provider = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    mutate(provider, failure=True)
    with pytest.raises(AccessError, match="password_source_unavailable") as failure:
        password_sync.refresh(store, "demo-web", force=True)
    assert "fictional" not in str(failure.value)
    record = store.get(source.PREFIX + connection["id"])
    assert record["profile"]["refresh_token"] == "fictional-refresh-3"
    assert record["status"] == "RETRYABLE"
    assert store.get("credential:demo-web") is None
    mutate(provider, failure=False)
    password_sync.refresh(store, "demo-web", force=True)
    assert store.get("credential:demo-web")["password"] == "rotated-fictional-password"


def test_local_disconnect_clears_secrets_and_blocks_even_not_due_link(cli):
    store, _ = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    assert (
        source.disconnect(store, connection["id"], connection["generation"])["status"]
        == "DISCONNECTED"
    )
    assert source.connections(store) == []
    assert store.get("credential:demo-web") is None
    assert store.get("connection:demo-web") is None
    record = store.get(source.PREFIX + connection["id"])
    assert not {"profile", "session", "redactions"} & record.keys()
    with pytest.raises(AccessError, match="password_source_access_removed"):
        password_sync.refresh(store, "demo-web")


def test_explicit_reenrollment_rotates_generation_without_reviving_old_link(cli):
    store, _ = cli
    first = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(first))
    second = source.connect(store, setup_data())
    assert first["id"] == second["id"]
    assert first["generation"] != second["generation"]
    assert store.get("credential:demo-web") is None
    with pytest.raises(AccessError, match="bitwarden_connection_changed"):
        source.disconnect(store, first["id"], first["generation"])
    with pytest.raises(AccessError, match="bitwarden_connection_changed"):
        source.fetch(store, link(first), "https://example.test")
    assert source.connections(store) == [second]


def test_disconnect_between_read_and_publication_cannot_recreate_credentials(cli, monkeypatch):
    store, _ = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    original = password_sync._fetch

    def delayed(*args):
        value = original(*args)
        source.disconnect(store, connection["id"], connection["generation"])
        return value

    monkeypatch.setattr(password_sync, "_fetch", delayed)
    with pytest.raises(AccessError, match="password_source_access_removed"):
        password_sync.refresh(store, "demo-web", force=True)
    assert store.get("credential:demo-web") is None
    assert store.get("connection:demo-web") is None


def test_parallel_item_reads_serialize_shared_profile_rotation(cli):
    store, provider = cli
    connection = source.connect(store, setup_data())
    expected_origin = source.origin(store.config().accounts["demo-web"].login_url)
    values, errors = [], []

    def read():
        try:
            values.append(source.fetch(store, link(connection), expected_origin))
        except Exception as error:
            errors.append(error)

    workers = [threading.Thread(target=read) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
    assert not errors and len(values) == 2
    assert store.get(source.PREFIX + connection["id"])["profile"]["nonce"] == 3
    seen = [
        call["profile_nonce"]
        for call in json.loads(provider.read_text())["calls"]
        if call["args"] == ["sync", "--force"]
    ]
    assert seen == [0, 1, 2]


def test_missing_or_same_user_runtime_is_unavailable_without_running_cli(cli, monkeypatch):
    store, provider = cli
    config = store.config()
    config.test_mode = False
    monkeypatch.setattr(store, "config", lambda: config)
    assert source.available(store) is False
    with pytest.raises(AccessError, match="password_source_runtime_unavailable"):
        source.connect(store, setup_data())
    assert json.loads(provider.read_text())["calls"] == []


@pytest.mark.parametrize("change", ["entry", "node-mode", "portable-profile", "manifest-node", "manifest-schema", "manifest-duplicate"])
def test_runtime_requires_pinned_protected_layout_without_command_fallback(cli, change):
    store, provider = cli
    if change == "entry":
        source.CLI.write_text("modified entrypoint")
    elif change == "node-mode":
        source.NODE.chmod(0o722)
    elif change == "portable-profile":
        (source.NODE.parent / "bw-data").mkdir()
    elif change == "manifest-duplicate":
        source.MANIFEST.write_text('{"schema":1,"schema":1}')
    else:
        manifest = json.loads(source.MANIFEST.read_text())
        manifest["node_version" if change == "manifest-node" else "schema"] = (
            "22.15.1" if change == "manifest-node" else True
        )
        source.MANIFEST.write_text(json.dumps(manifest))
    assert source.available(store) is False
    with pytest.raises(AccessError, match="password_source_runtime_unavailable"):
        source.connect(store, setup_data())
    assert json.loads(provider.read_text())["calls"] == []


def uri_item(uris):
    return {"id": ITEM, "type": 1, "reprompt": 0,
            "login": {"username": "fictional-owner", "password": "fictional-password", "uris": uris}}


@pytest.mark.parametrize("match", [None, 0, 1, 2, 3])
def test_web_uri_remains_usable_with_mobile_null_regex_and_never_entries(match):
    item = uri_item([
        {"uri": "androidapp://com.example.app", "match": None},
        {"uri": "iosapp://example", "match": 0},
        {"uri": None},
        {"uri": "https://unrelated.example/.*", "match": 4},
        {"uri": "https://unrelated.example", "match": 5},
        {"uri": "https://approved.example/path#fragment", "match": match},
    ])
    assert source._credentials(item, {"item": ITEM}, "https://approved.example") == {
        "username": "fictional-owner", "password": "fictional-password"
    }


@pytest.mark.parametrize("uri", [
    {"uri": "https://approved.example", "match": 4},
    {"uri": "https://approved.example", "match": 5},
    {"uri": "https://approved.example.attacker.example", "match": 0},
    {"uri": "androidapp://approved.example", "match": 1},
    {"uri": None},
    {"uri": "https://user:password@approved.example", "match": None},
    {"uri": "http://approved.example"},
])
def test_ineligible_uris_cannot_confer_approved_website_authority(uri):
    with pytest.raises(AccessError, match="password_source_item_changed"):
        source._credentials(uri_item([uri]), {"item": ITEM}, "https://approved.example")


@pytest.mark.parametrize("malformed", [
    None, "https://approved.example", {"uri": 1},
    {"uri": "https://approved.example", "match": True},
    {"uri": "https://approved.example", "match": "1"},
    {"uri": "https://approved.example", "match": 6},
    {"uri": "https://approved.example", "match": -1},
    {"uri": "https://approved.example:bad"},
    {"uri": "https://approved.example:0"},
    {"uri": "https://[invalid"},
])
def test_malformed_uri_metadata_fails_even_beside_valid_web_binding(malformed):
    with pytest.raises(AccessError, match="password_source_item_changed"):
        source._credentials(uri_item([{"uri": "https://approved.example"}, malformed]),
                            {"item": ITEM}, "https://approved.example")


@pytest.mark.parametrize("event", ["disconnect", "reenroll"])
def test_stale_fetch_failure_preserves_atomically_revoked_source_link(cli, monkeypatch, event):
    store, _ = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    published = {}

    def delayed(*args):
        if event == "disconnect":
            source.disconnect(store, connection["id"], connection["generation"])
        else:
            source.connect(store, setup_data())
        published.update(store.get("password-link:demo-web"))
        raise AccessError("RETRYABLE", "password_source_unavailable")

    monkeypatch.setattr(password_sync, "_fetch", delayed)
    with store.lock("account:demo-web"), pytest.raises(AccessError, match="password_source_unavailable"):
        password_sync.refresh(store, "demo-web", force=True)
    assert store.get("password-link:demo-web") == published
    assert published["status"] == "BLOCKED" and published["next_at"] == 0
    assert store.get("credential:demo-web") is None
    assert store.get("connection:demo-web") is None


@pytest.mark.parametrize("phase", ["fetch", "publication"])
def test_stale_failure_cannot_erase_explicitly_repaired_new_generation(cli, monkeypatch, phase):
    store, _ = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    original_fetch, original_authority = password_sync._fetch, password_sync._authority
    published = {}

    def repair():
        fresh = source.connect(store, setup_data())
        with monkeypatch.context() as patch:
            patch.setattr(password_sync, "_fetch", original_fetch)
            patch.setattr(password_sync, "_authority", original_authority)
            password_sync._enroll_locked(store, "demo-web", link(fresh))
        store.put("connection:demo-web", {"fixture": "new-approved-browser-session"})
        for key in ["password-link:demo-web", "credential:demo-web", "connection:demo-web"]:
            published[key] = store.get(key)

    def delayed_fetch(*args):
        repair()
        raise AccessError("DENIED", "password_source_access_removed")

    @contextmanager
    def delayed_authority(*args):
        repair()
        with original_authority(*args):
            yield

    monkeypatch.setattr(password_sync, "_fetch" if phase == "fetch" else "_authority",
                        delayed_fetch if phase == "fetch" else delayed_authority)
    with store.lock("account:demo-web"), pytest.raises(AccessError) as failure:
        password_sync.refresh(store, "demo-web", force=True)
    assert failure.value.status == "RETRYABLE"
    assert failure.value.reason == "password_source_unavailable"
    for key, value in published.items():
        assert store.get(key) == value
    assert published["password-link:demo-web"]["connection_generation"] != connection["generation"]


def test_process_pipe_budget_ignores_environment_and_kills_descendants(tmp_path):
    child_pid = tmp_path / "child.pid"
    program = (
        "import pathlib,subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(60)']); "
        f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid)); time.sleep(60)"
    )
    started = time.monotonic()
    with pytest.raises(AccessError, match="password_source_unavailable"):
        source._run([sys.executable, "-I", "-c", program], [], tmp_path, time.monotonic() + 0.4)
    assert time.monotonic() - started < 3
    if child_pid.exists():
        process = subprocess.run(
            ["ps", "-o", "stat=", "-p", child_pid.read_text()], capture_output=True, text=True
        )
        assert not process.stdout.strip() or process.stdout.strip().startswith("Z")


def test_exact_source_link_validation_and_redaction_have_no_master_or_vault_listing(cli):
    store, _ = cli
    connection = source.connect(store, setup_data())
    data = link(connection)
    assert password_sync.validate_link(store, "demo-web", data) == data
    for change in [
        {"item": "named-search"},
        {"item": ITEM.upper().replace("2", "A", 1)},
        {"token": "session-substitution"},
        {"endpoint": "https://attacker.example"},
    ]:
        with pytest.raises(AccessError, match="invalid_password_sync_link"):
            password_sync.validate_link(store, "demo-web", {**data, **change})
    values = source.secret_values(store, data)
    assert SESSION in values and "fictional-api-secret" in values
    assert "fictional-master-password" not in values


def test_explicit_relink_repairs_only_previously_approved_identity_and_source_challenge(cli):
    store, provider = cli
    first = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(first))
    source.disconnect(store, first["id"], first["generation"])
    old_challenge = store.challenge("demo-web", "login", "bitwarden_connection_changed")
    presence = store.challenge("demo-web", "device", "browser_device_approval_required")
    second = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(second))
    assert (
        store.get("credential:demo-web")["username"]
        == json.loads(provider.read_text())["item"]["login"]["username"]
    )
    assert old_challenge["id"] not in {row["id"] for row in store.pending("demo-web")}
    assert store.pending("demo-web") == [presence]


def test_remote_revocation_stops_all_linked_accounts_before_item_read(cli):
    store, provider = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    second = dict(store.get("password-link:demo-web"))
    store.put("password-link:second-fictional-account", second)
    store.put("credential:second-fictional-account", {"username": "old", "password": "old"})
    store.put("connection:second-fictional-account", {"cookie": "old"})
    before = len(json.loads(provider.read_text())["calls"])
    mutate(provider, revoked=True)
    with pytest.raises(AccessError, match="password_source_access_removed"):
        password_sync.refresh(store, "demo-web", force=True)
    assert not any(
        row["args"][:2] == ["get", "item"]
        for row in json.loads(provider.read_text())["calls"][before:]
    )
    for account in ["demo-web", "second-fictional-account"]:
        assert store.get("credential:" + account) is None
        assert store.get("connection:" + account) is None
    assert source.connections(store)[0]["status"] == "BLOCKED"


def test_disconnection_preserves_a_manually_replaced_unlinked_password(cli):
    store, _ = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    manual = {"username": "manual-owner", "password": "new-manual-fictional-password"}
    with store.db() as db:
        store.put("password-link:demo-web", None, db=db)
        store.put("credential:demo-web", manual, db=db)
    source.disconnect(store, connection["id"], connection["generation"])
    assert store.get("credential:demo-web") == manual


@pytest.mark.parametrize(
    "raw", [b'{"status":"unlocked","status":"locked"}', b'{"value":NaN}', b"not-json", b"[]"]
)
def test_unexpected_profile_and_duplicate_fields_fail_closed(tmp_path, raw):
    (tmp_path / "data.json").write_bytes(raw)
    with pytest.raises(AccessError, match="password_source_item_changed"):
        source._profile(tmp_path)


@pytest.mark.parametrize(
    "override",
    [
        {"serverUrl": []},
        {"lastSync": "not-a-date"},
        {"lastSync": "2099-01-01T00:00:00+00:00"},
        {"lastSync": "2026-01-01T00:00:00"},
    ],
)
def test_malformed_identity_and_unfresh_sync_never_publishes_credentials(cli, override):
    store, provider = cli
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    mutate(provider, status_override=override)
    with pytest.raises(AccessError):
        password_sync.refresh(store, "demo-web", force=True)
    assert store.get("credential:demo-web") is None


def test_connection_deadline_is_shared_across_all_cli_steps(cli, monkeypatch):
    store, provider = cli
    mutate(provider, delay=1)
    monkeypatch.setattr(source, "CONNECT_DEADLINE", 2.2)
    started = time.monotonic()
    with pytest.raises(AccessError, match="password_source_unavailable"):
        source.connect(store, setup_data())
    assert time.monotonic() - started < 3
    assert source.connections(store) == []
    assert not any(store.root.glob("bitwarden-*"))


def test_successful_cli_cannot_leave_background_descendants(tmp_path):
    child_pid = tmp_path / "child.pid"
    program = (
        "import pathlib,subprocess,sys; "
        "p=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(60)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid)); print('ok')"
    )
    assert (
        source._run(
            [sys.executable, "-I", "-c", program], [], tmp_path, time.monotonic() + 2
        ).strip()
        == b"ok"
    )
    process = subprocess.run(
        ["ps", "-o", "stat=", "-p", child_pid.read_text()], capture_output=True, text=True
    )
    assert not process.stdout.strip() or process.stdout.strip().startswith("Z")


def test_source_writer_wait_is_bounded_and_rolls_back_without_partial_publication(env):
    _, broker, _ = env
    store = broker.store
    blocked = sqlite3.connect(store.path)
    try:
        blocked.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        with pytest.raises(AccessError, match="password_source_unavailable"):
            with source._database(store) as database:
                store.put("fictional-source-wait", {"value": "must-not-publish"}, db=database)
        assert time.monotonic() - started < 2
    finally:
        blocked.rollback()
        blocked.close()
    assert store.get("fictional-source-wait") is None


def test_desktop_proxy_override_cannot_adopt_an_existing_executable(tmp_path):
    reserved = tmp_path / ".account-access-disabled-desktop-ipc"
    reserved.write_text("must-not-execute")
    with pytest.raises(AccessError, match="password_source_item_changed"):
        source._run(["must-not-run"], [], tmp_path, time.monotonic() + 2)
