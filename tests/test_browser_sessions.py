import copy
import io
import json
import secrets
import struct
import time

import pytest

from account_access.browser_sessions import accept, begin, cancel, candidates, requests, validate_state
from account_access.errors import AccessError
from account_access.google_messages_host import prepare, run_host
from account_access.models import TaskRequest


@pytest.fixture
def chrome_session(env):
    provider, broker, _ = env
    broker.store.new_client("generic")
    broker.grant("generic", "demo-web", ["summary"])
    parent = provider.server.RequestHandlerClass
    provider.session_identity = "fixture-owner"

    class Handler(parent):
        def page(self, body):
            identity = '<meta name="user-login" content="' + provider.session_identity + '">' if self.authenticated() else ""
            super().page(identity + body)

    provider.server.RequestHandlerClass = Handler
    token = secrets.token_hex(24)
    provider.sessions.add(token)
    state = {"cookies": [{"name": "demo_session", "value": token, "domain": "127.0.0.1", "path": "/",
                          "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"}], "origins": []}
    return provider, broker, state


def request(broker, state):
    config = broker.store.config()
    item = begin(broker, "demo-web", config.fingerprint("demo-web"), "fixture-owner")
    return {"method": "session-import", "account": "demo-web", "request": item["id"],
            "fingerprint": config.fingerprint("demo-web"),
            "origin": next(item["origin"] for item in requests(broker)), "state": state}


@pytest.mark.parametrize("kind", ["passkey", "method"])
def test_verified_chrome_session_resumes_original_task_without_password_or_factor_access(chrome_session, monkeypatch, kind):
    provider, broker, state = chrome_session
    challenge = broker.store.challenge("demo-web", kind, "browser_" + kind + "_required")
    task = broker.submit("generic", TaskRequest(key="original-chrome-task", steps=[{"account": "demo-web", "operation": "summary"}]))
    broker.tick()
    assert broker.task("generic", task["task_id"])["status"] == "NEEDS_USER"
    with broker.store.db() as db:
        grants = [dict(row) for row in db.execute("SELECT * FROM grants")]

    def no_codes(*args, **kwargs):
        raise AssertionError("Session reuse cannot request a verification code")

    monkeypatch.setattr(broker.codes, "begin", no_codes)
    monkeypatch.setattr(broker.codes, "resolve", no_codes)
    message = request(broker, state)
    result = accept(broker, message)
    assert result == {"status": "SESSION_CONNECTED", "account": "demo-web"}
    assert state["cookies"][0]["value"] not in json.dumps(result)
    assert not broker.store.pending("demo-web")
    assert broker.store.get("browser-session-request:demo-web")["status"] == "CONNECTED"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        broker.tick()
        if broker.task("generic", task["task_id"])["status"] == "COMPLETED":
            break
        time.sleep(.05)
    assert broker.task("generic", task["task_id"])["status"] == "COMPLETED"
    assert provider.login_count == provider.totp_count == 0
    with broker.store.db() as db:
        assert [dict(row) for row in db.execute("SELECT * FROM grants")] == grants
        assert db.execute("SELECT resolved FROM challenges WHERE id=?", (challenge["id"],)).fetchone()[0]
    with pytest.raises(AccessError, match="expired_or_changed"):
        accept(broker, message)


@pytest.mark.parametrize("case,reason", [
    ("other_username", "browser_session_identity_mismatch"),
    ("expired_cookie", "browser_login_required"),
    ("action", "browser_action_required"),
])
def test_failed_chrome_verification_never_saves_session_or_clears_existing_challenge(chrome_session, case, reason):
    provider, broker, state = chrome_session
    broker.store.challenge("demo-web", "passkey", "browser_passkey_required")
    before = broker.store.get("connection:demo-web")
    if case == "other_username":
        provider.session_identity = "someone-else"
    elif case == "expired_cookie":
        provider.sessions.clear()
    else:
        provider.transaction_challenge = True
    message = request(broker, state)
    with pytest.raises(AccessError, match=reason):
        accept(broker, message)
    assert broker.store.get("connection:demo-web") == before
    assert broker.store.pending("demo-web")
    assert provider.login_count == 0
    with pytest.raises(AccessError, match="expired_or_changed"):
        accept(broker, message)


def test_verified_session_does_not_clear_an_independent_transaction_approval(chrome_session):
    _, broker, state = chrome_session
    broker.store.challenge("demo-web", "action", "owner_action_required")
    assert accept(broker, request(broker, state))["status"] == "SESSION_CONNECTED"
    assert broker.run("generic", "demo-web", "summary")["challenge"]["kind"] == "action"


@pytest.mark.parametrize("kind", ["method", "action"])
def test_owner_recheck_of_saved_session_resumes_login_task_but_keeps_transaction_approval(chrome_session, monkeypatch, kind):
    import threading
    import httpx2 as httpx
    from account_access.owner import make_owner_server

    provider, broker, state = chrome_session
    accept(broker, request(broker, state))
    broker.store.challenge("demo-web", kind, "owner_action_required" if kind == "action" else "verification_method_unavailable")
    task = broker.submit("generic", TaskRequest(key="saved-session-recheck", steps=[{"account": "demo-web", "operation": "summary"}]))
    broker.tick()
    assert broker.task("generic", task["task_id"])["status"] == "NEEDS_USER"
    monkeypatch.setattr(broker.codes, "begin", lambda *a: pytest.fail("Cached session requested a code"))
    server, token = make_owner_server(broker, guided=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, headers={"Authorization": "Bearer " + token, "Origin": base}, trust_env=False) as client:
            result = client.post("/owner/verify", json={"account": "demo-web"})
            assert result.status_code == 200
            ident = result.json()["id"]
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                job = client.get("/owner/state").json()["connection_jobs"][ident]
                if job["status"] != "RUNNING":
                    break
                time.sleep(.05)
            assert job["status"] == "CONNECTED", job
        assert bool(broker.store.pending("demo-web")) == (kind == "action")
        deadline = time.monotonic() + 5
        while kind == "method" and time.monotonic() < deadline:
            broker.tick()
            if broker.task("generic", task["task_id"])["status"] == "COMPLETED":
                break
            time.sleep(.05)
        assert broker.task("generic", task["task_id"])["status"] == ("NEEDS_USER" if kind == "action" else "COMPLETED")
        assert provider.login_count == provider.totp_count == 0
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.mark.parametrize("change", ["expired", "request", "fingerprint", "origin", "grant", "configuration", "no_request"])
def test_changed_or_unapproved_session_request_never_opens_a_browser(chrome_session, monkeypatch, change):
    _, broker, state = chrome_session
    message = request(broker, state)
    if change == "expired":
        value = broker.store.get("browser-session-request:demo-web")
        value["expires"] = time.time() - 1
        broker.store.put("browser-session-request:demo-web", value)
    elif change in {"request", "fingerprint", "origin"}:
        message[change] = "wrong"
    elif change == "grant":
        broker.revoke(principal="generic")
    elif change == "configuration":
        config = broker.store.config()
        config.accounts["demo-web"].ready_selector = "#changed"
        broker.store.configure(config)
    else:
        broker.store.put("browser-session-request:demo-web", None)
    monkeypatch.setattr(broker.browser, "verify_imported_state", lambda *a: pytest.fail("Unapproved request opened a browser"))
    with pytest.raises(AccessError):
        accept(broker, message)
    assert not requests(broker) or change in {"request", "fingerprint", "origin"}


@pytest.mark.parametrize("change", ["foreign_cookie", "parent_cookie", "extra_cookie_field", "duplicate_cookie",
                                    "nan", "invalid_type", "too_many", "too_large", "foreign_storage",
                                    "duplicate_storage", "indexeddb", "unknown_root"])
def test_state_validation_rejects_unapproved_or_unbounded_transfer(chrome_session, change):
    _, _, original = chrome_session
    state = copy.deepcopy(original)
    cookie = state["cookies"][0]
    if change == "foreign_cookie":
        cookie["domain"] = "other.example"
    elif change == "parent_cookie":
        cookie["domain"] = ".0.0.1"
    elif change == "extra_cookie_field":
        cookie["partitionKey"] = "https://other.example"
    elif change == "duplicate_cookie":
        state["cookies"].append(copy.deepcopy(cookie))
    elif change == "nan":
        cookie["expires"] = float("nan")
    elif change == "invalid_type":
        cookie["httpOnly"] = "true"
    elif change == "too_many":
        state["cookies"] *= 129
    elif change == "too_large":
        cookie["value"] = "x" * 50_000
    elif change == "foreign_storage":
        state["origins"] = [{"origin": "https://other.example", "localStorage": []}]
    elif change == "duplicate_storage":
        state["origins"] = [{"origin": "http://127.0.0.1:1234", "localStorage": [{"name": "key", "value": "one"}] * 2}]
    elif change == "indexeddb":
        state["origins"] = [{"origin": "http://127.0.0.1:1234", "localStorage": [], "indexedDB": []}]
    else:
        state["password"] = "fictional-secret"
    with pytest.raises(AccessError, match="invalid_browser_session_state"):
        validate_state(state, "http://127.0.0.1:1234")


def test_native_session_transfer_is_bound_to_exact_helper_origin_and_does_not_echo_cookies(chrome_session, tmp_path):
    _, broker, state = chrome_session
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    info = prepare(broker.store, home=home)
    message = request(broker, state)
    raw = json.dumps({"id": 0, "body": message}).encode()
    incoming = struct.pack("=I", len(raw)) + raw
    denied = io.BytesIO()
    assert run_host(broker.store, io.BytesIO(incoming), denied, "chrome-extension://wrong/") == 2
    assert not denied.getvalue()
    output = io.BytesIO()
    assert run_host(broker.store, io.BytesIO(incoming), output, "chrome-extension://" + info["extension_id"] + "/") == 0
    reply = json.loads(output.getvalue()[4:])
    assert reply["result"]["status"] == "SESSION_CONNECTED"
    assert state["cookies"][0]["value"].encode() not in output.getvalue()
    assert not requests(broker)


def test_session_connection_requires_existing_approved_read_and_cannot_use_legacy_unverified_import(env):
    _, broker, _ = env
    assert not candidates(broker) and not requests(broker)
    with pytest.raises(AccessError):
        begin(broker, "demo-web", broker.store.config().fingerprint("demo-web"), "fixture-owner")
    with pytest.raises(AccessError, match="owner_request_required"):
        broker.browser.import_state("demo-web", {"cookies": [], "origins": []})


def test_owner_session_request_requires_local_owner_and_preserves_read_permissions(chrome_session, monkeypatch, tmp_path):
    import threading
    import httpx2 as httpx
    from account_access.owner import make_owner_server

    _, broker, _ = chrome_session
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr("account_access.google_messages_host.prepare", lambda store: prepare(store, home=home))
    with broker.store.db() as db:
        grants = [dict(row) for row in db.execute("SELECT * FROM grants")]
    server, token = make_owner_server(broker, guided=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            body = {"account": "demo-web", "fingerprint": broker.store.config().fingerprint("demo-web"), "username": "fixture-owner"}
            assert client.post("/owner/browser-session/start", json=body).status_code == 403
            headers = {"Authorization": "Bearer " + token, "Origin": base}
            assert client.post("/owner/browser-session/start", json={**body, "url": "https://other.example"}, headers=headers).status_code == 400
            response = client.post("/owner/browser-session/start", json=body, headers=headers)
            assert response.status_code == 200, response.text
            result = response.json()
            assert result["status"] == "AWAITING_BROWSER"
            state = client.get("/owner/state", headers=headers).json()
            assert state["browser_session_requests"][0]["status"] == "AWAITING_BROWSER"
            assert "password" not in state["browser_session_accounts"][0]
            assert not broker.store.get("connection:demo-web")
            cancel_body = {"account": "demo-web", "id": result["id"]}
            assert client.post("/owner/browser-session/cancel", json=cancel_body).status_code == 403
            assert client.post("/owner/browser-session/cancel", json=cancel_body, headers=headers).json()["status"] == "CANCELLED"
            assert not requests(broker)
        with broker.store.db() as db:
            assert [dict(row) for row in db.execute("SELECT * FROM grants")] == grants
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.mark.parametrize("change", ["cancel", "revoke", "expire", "save_failure"])
def test_late_cancel_revocation_expiry_or_failed_commit_cannot_replace_a_connection(chrome_session, monkeypatch, change):
    _, broker, state = chrome_session
    broker.store.challenge("demo-web", "passkey", "browser_passkey_required")
    message = request(broker, state)
    verify = broker.browser.verify_imported_state
    previous = broker.store.get("connection:demo-web")

    def changed(*args):
        verified = verify(*args)
        if change == "cancel":
            assert cancel(broker.store, "demo-web", message["request"])["status"] == "CANCELLED"
        elif change == "revoke":
            broker.revoke(principal="generic")
        elif change == "expire":
            record = broker.store.get("browser-session-request:demo-web")
            record["expires"] = time.time() - 1
            broker.store.put("browser-session-request:demo-web", record)
        return verified

    monkeypatch.setattr(broker.browser, "verify_imported_state", changed)
    if change == "save_failure":
        resolve = broker.store.resolve_login

        def rollback(account, db=None):
            resolve(account, db=db)
            raise RuntimeError("simulated commit failure")

        monkeypatch.setattr(broker.store, "resolve_login", rollback)
    with pytest.raises(AccessError):
        accept(broker, message)
    assert broker.store.get("connection:demo-web") == previous
    assert broker.store.pending("demo-web")
    assert not requests(broker)


@pytest.mark.parametrize("case", ["success", "popup_closed", "approval_early", "expired_intent", "wrong_origin", "changed_tab", "permission_missing", "unapproved", "partitioned", "too_large", "native_failure"])
def test_browser_helper_captures_only_the_requested_github_cookie_store_and_removes_temporary_permissions(case):
    from playwright.sync_api import sync_playwright
    from account_access.google_messages_host import RESOURCES

    with sync_playwright() as pw:
        browser = pw.chromium.launch(chromium_sandbox=True)
        page = browser.new_page()
        page.set_content("<p>Isolated browser-helper contract fixture</p>")
        page.evaluate("""scenario => {
          window.scenario=scenario;window.fixtureCalls={cookies:[],native:[],removed:[]};
          window.fixtureGranted=!['permission_missing','popup_closed','approval_early','expired_intent'].includes(scenario);
          const memory={};
          let nativeReply,earlyApproval=false;
          const request={account:'github',id:'a'.repeat(32),fingerprint:'b'.repeat(64),origin:'https://github.com',username:'fixture-owner'};
          window.chrome={
            runtime:{
              id:'fixture',
              getURL:path=>'chrome-extension://fixture/'+path,
              onMessage:{addListener:handler=>window.fixtureHandler=handler},
              onStartup:{addListener:()=>{}},
              connectNative:()=>({
                onMessage:{addListener:handler=>nativeReply=handler},onDisconnect:{addListener:()=>{}},
                postMessage:msg=>{
                  if(scenario==='approval_early' && !earlyApproval){earlyApproval=true;fixtureGranted=true;fixturePermissionAdded();}
                  queueMicrotask(()=>nativeReply({id:msg.id,result:{accounts:scenario==='unapproved'?[]:[request]}}));
                }
              }),
              sendNativeMessage:async(host,message)=>{
                fixtureCalls.native.push(message);
                if(scenario==='native_failure')throw new Error('fictional failure');
                return {id:0,result:{status:'SESSION_CONNECTED'}};
              }
            },
            storage:{local:{get:async()=>({enabled:false})},session:{
              get:async key=>({[key]:memory[key]}),set:async value=>Object.assign(memory,value),
              remove:async keys=>{for(const key of [].concat(keys))delete memory[key];}}},
            permissions:{contains:async()=>fixtureGranted,
              onAdded:{addListener:handler=>window.fixturePermissionAdded=handler},
              remove:async value=>{fixtureCalls.removed.push(value);fixtureGranted=false;return true;}},
            alarms:{create:()=>{},onAlarm:{addListener:()=>{}}},
            tabs:{query:async()=>[{id:7,url:scenario==='wrong_origin'?'https://other.example/':'https://github.com/settings/profile'}],
                  get:async()=>({id:7,url:scenario==='changed_tab'||scenario==='wrong_origin'?'https://other.example/':'https://github.com/settings/profile'})},
            cookies:{getAllCookieStores:async()=>[{id:'wrong-store',tabIds:[8]},{id:'selected-store',tabIds:[7]}],
              getAll:async details=>{
                fixtureCalls.cookies.push(details);
                return [{name:'user_session',value:scenario==='too_large'?'x'.repeat(49000):'fictional-session-cookie',domain:'.github.com',path:'/',httpOnly:true,secure:true,sameSite:'lax',
                  ...(scenario==='partitioned'?{partitionKey:{topLevelSite:'https://github.com'}}:{})}];
              }}
          };
        }""", case)
        page.add_script_tag(path=RESOURCES / "background.js")
        result = page.evaluate("""async() => {
          const message={account:'github',request:'a'.repeat(32),fingerprint:'b'.repeat(64)};
          const send=method=>new Promise((resolve,reject)=>{
            setTimeout(()=>reject(new Error('Fixture callback timed out')),3000);
            const accepted=fixtureHandler({method,...message},
              {id:'fixture',url:'chrome-extension://fixture/popup.html'},resolve);
            if(accepted!==true)reject(new Error('Fixture sender was rejected'));
          });
          const prepared=await send('session-prepare');
          if(prepared.status!=='AWAITING_PERMISSION')return prepared;
          if(scenario==='expired_intent'){
            const intent=(await chrome.storage.session.get('sessionIntent')).sessionIntent;
            intent.expires=Date.now()-1;await chrome.storage.session.set({sessionIntent:intent});
            fixtureGranted=true;fixturePermissionAdded();
            return await send('session-connect');
          }
          if(scenario==='popup_closed'||scenario==='approval_early'){
            if(scenario==='popup_closed'){fixtureGranted=true;fixturePermissionAdded();}
            // Never call session-connect or its implementation again. Only the
            // approval event or the finishing preparation can complete this.
            const deadline=Date.now()+2500;
            while(Date.now()<deadline){
              const outcome=(await chrome.storage.session.get('sessionOutcome')).sessionOutcome;
              if(outcome)return outcome;
              await new Promise(resolve=>setTimeout(resolve,10));
            }
            throw new Error('Approval did not resume the closed popup');
          }
          return await send('session-connect');
        }""")
        calls = page.evaluate("fixtureCalls")
        if case not in {"unapproved", "permission_missing", "expired_intent"}:
            assert calls["removed"] == [{"permissions": ["cookies"], "origins": ["https://github.com/*"]}]
        assert "fictional-session-cookie" not in json.dumps(result)
        if case in {"success", "popup_closed", "approval_early", "native_failure"}:
            assert calls["cookies"] == [{"url": "https://github.com/", "storeId": "selected-store"}]
            assert len(calls["native"]) == 1
            body = calls["native"][0]["body"]
            assert body["origin"] == "https://github.com" and body["request"] == "a" * 32
            assert body["state"]["origins"] == []
            assert body["state"]["cookies"][0]["value"] == "fictional-session-cookie"
        else:
            assert not calls["native"]
        if case in {"success", "popup_closed", "approval_early"}:
            assert result["status"] == "SESSION_CONNECTED"
        elif case == "permission_missing":
            assert result["status"] == "AWAITING_PERMISSION"
        else:
            assert result["status"] in {"DENIED", "NEEDS_USER"}
        assert page.evaluate("fixtureHandler({method:'session-status'}, {id:'fixture',url:'https://github.com'}, ()=>{})") is False
        if case in {"success", "popup_closed", "approval_early", "native_failure"}:
            metadata = page.evaluate("""() => new Promise(resolve=>fixtureHandler({method:'session-status'},
                {id:'fixture',url:'chrome-extension://fixture/popup.html'},resolve))""")
            assert metadata["temporaryAccess"] == {"cookies": False, "github": False}
            assert "fictional-session-cookie" not in json.dumps(metadata)
        browser.close()
