"""An ephemeral private owner console, on loopback or an inherited Unix socket."""

import json
import hashlib
import hmac
import secrets
import re
import socket
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .errors import AccessError
from .models import BrowserAccount, OAuthAccount
from .storage import check_private, private_file


def make_owner_server(broker, *, guided=False, instance_key=None, owner_token=None,
                      server_socket=None, origin_port=None, local_host_actions=True, ready=None,
                      native_messages=None):
    if native_messages is not None and (server_socket is None or local_host_actions):
        raise AccessError("DENIED", "trusted_owner_route_required")
    if ready is not None and not callable(ready):
        raise AccessError("DENIED", "invalid_owner_readiness")
    if owner_token is not None and (not isinstance(owner_token, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", owner_token)):
        raise AccessError("DENIED", "invalid_owner_bootstrap")
    if (server_socket is None) != (origin_port is None):
        raise AccessError("DENIED", "invalid_owner_transport")
    if server_socket is not None and (not isinstance(server_socket, socket.socket)
            or server_socket.family != socket.AF_UNIX
            or server_socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or type(origin_port) is not int or not 1 <= origin_port <= 65535):
        raise AccessError("DENIED", "invalid_owner_transport")
    if server_socket is not None:
        server_socket.listen(128)
    if native_messages is None:
        reader_key = broker.store.root / "native-reader.key"
        with broker.store.lock("native-reader-key"):
            if not reader_key.exists():
                private_file(reader_key, secrets.token_bytes(32))
            check_private(reader_key)
    from .phone import PhoneRelay
    phone = PhoneRelay(broker.store)
    try:
        phone.restore()
    except (AccessError, OSError, ValueError):
        # A changed Wi-Fi address or busy port requires re-pairing, not a failed local app.
        phone.server = None
    token = owner_token or secrets.token_urlsafe(32)
    instance_key = instance_key or secrets.token_bytes(32)
    jobs = {}
    reviews = {}
    sms_setups = {}
    guard = threading.Lock()
    verification_slots = threading.BoundedSemaphore(4)

    def verify(account, job_id, visible=False, setup_method=None, review_stop=None):
        with verification_slots:
            if review_stop and review_stop.is_set():
                with guard:
                    jobs[job_id] = {"status": "CANCELLED", "account": account}
                return
            _verify(account, job_id, visible, setup_method, review_stop)

    def _verify(account, job_id, visible=False, setup_method=None, review_stop=None):
        try:
            config = broker.store.config().accounts[account]
            def requested(kind, at, http_status, diagnostics):
                with guard:
                    jobs[job_id]["code_requested"] = {"kind": kind, "at": at, "http_status": http_status,
                                                     "diagnostics": diagnostics}
            def attention(status, reason, kind, diagnostics):
                with guard:
                    jobs[job_id]["attention"] = {"status": status, "reason": reason, "kind": kind,
                                                 "diagnostics": diagnostics}
            with broker.store.lock("account:" + account, timeout=5):
                broker.browser.read(account, next(iter(config.operations.values())), config,
                                    secret_values=set(), visible=visible, setup_method=setup_method,
                                    review_stop=review_stop,
                                    on_attention=attention,
                                    on_code_request=requested if setup_method else None)
                # A confirmed cached session can repair a historical method
                # picker too. Keep independent action approvals unresolved.
                broker.store.resolve_login(account)
            try:
                broker.tick()
            except AccessError as exc:
                if exc.status != "RETRYABLE":
                    raise
            result = {"status": "CONNECTED", "account": account}
        except AccessError as exc:
            result = broker.error(exc, account)
        except Exception:
            result = {"status": "NEEDS_USER", "reason": "connection_not_completed", "account": account}
        with guard:
            for key in ["code_requested", "attention"]:
                if key in jobs[job_id]:
                    result[key] = jobs[job_id][key]
            jobs[job_id] = result
            reviews.pop(job_id, None)

    def new_job(account):
        ident = secrets.token_hex(16)
        with guard:
            if sum(x["status"] == "RUNNING" for x in jobs.values()) >= 64:
                raise AccessError("RETRYABLE", "connection_limit")
            jobs[ident] = {"status": "RUNNING", "account": account}
        return ident

    def connect(account, job_id):
        try:
            config = broker.store.config().accounts[account]
            mailbox_identity_verified = None
            if isinstance(config, OAuthAccount):
                from .cli import connect_oauth
                connect_oauth(broker, account)
                from .mailbox_oauth import check, supported
                if supported(broker.store.config(), account):
                    # Consent is already committed. An address-check failure
                    # must not force another password or consent prompt.
                    try:
                        checked = check(broker, account, broker.store.config().fingerprint(account))
                        mailbox_identity_verified = checked.get("status") == "VERIFIED"
                    except AccessError:
                        mailbox_identity_verified = False
            else:
                broker.browser.connect(account, complete=lambda page: page.locator(config.ready_selector).first.wait_for(state="visible", timeout=300000))
            try:
                broker.tick()
            except AccessError as exc:
                if exc.status != "RETRYABLE":
                    raise
            result = {"status": "CONNECTED", "account": account}
            if mailbox_identity_verified is not None:
                result["mailbox_identity_verified"] = mailbox_identity_verified
        except AccessError as exc:
            result = {"status": exc.status, "reason": exc.reason}
        except Exception:
            result = {"status": "NEEDS_USER", "reason": "connection_not_completed"}
        with guard:
            jobs[job_id] = result

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def send(self, status, body, kind="application/json"):
            raw = json.dumps(body).encode() if kind == "application/json" else body
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(raw)

        def authorized(self, *, mutate=False):
            expected_host = f"127.0.0.1:{self.server.server_port}"
            if self.headers.get("Host") != expected_host:
                return False
            if mutate and self.headers.get("Origin") != "http://" + expected_host:
                return False
            presented = self.headers.get("Authorization", "")
            return secrets.compare_digest(presented, "Bearer " + token)

        def do_GET(self):
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                self.send(403, {"status": "DENIED"})
                return
            static = {"/": ("welcome.html" if guided else "index.html", "text/html"),
                      "/manage": ("index.html", "text/html"),
                      "/owner.js": ("owner.js", "text/javascript"),
                      "/owner.css": ("owner.css", "text/css"),
                      "/welcome.js": ("welcome.js", "text/javascript"),
                      "/welcome.css": ("welcome.css", "text/css")}
            if self.path in static:
                filename, mime = static[self.path]
                self.send(200, (Path(__file__).parent / "ui" / filename).read_bytes(), mime)
                return
            if not self.authorized():
                self.send(401, {"status": "DENIED", "reason": "owner_authorization_required"})
                return
            if self.path == "/owner/native-messages/next":
                if native_messages is None:
                    self.send(403, {"status": "DENIED", "reason": "trusted_owner_route_required"})
                else:
                    self.send(200, native_messages.next())
                return
            if guided and self.path.startswith("/owner/ready?"):
                challenge = parse_qs(urlsplit(self.path).query).get("challenge", [""])[0]
                if len(challenge) != 64 or any(c not in "0123456789abcdef" for c in challenge):
                    self.send(400, {"status": "DENIED"})
                    return
                self.send(200, {"proof": hmac.new(instance_key, challenge.encode(), hashlib.sha256).hexdigest()})
                return
            if self.path == "/owner/health":
                if ready is not None:
                    try:
                        available = ready() is True
                    except Exception:
                        available = False
                    if not available:
                        self.send(503, {"status": "STARTING", "reason": "worker_not_ready"})
                        return
                self.send(200, broker.worker_health.view())
                return
            if self.path == "/owner/state":
                from .account_context import aggregate, describe
                config = broker.store.config()
                accounts = []
                for account, spec in config.accounts.items():
                    accounts.append({"account": account, **describe(spec, test_mode=config.test_mode), "route": spec.kind,
                                     **broker.connection_view(account, config),
                                     "operations": [{"name": name, "description": op.description} for name, op in spec.operations.items()],
                                     "challenges": [broker.challenge_view(x) for x in broker.store.pending(account)]})
                with broker.store.db() as db:
                    principals = [r[0] for r in db.execute("SELECT DISTINCT principal FROM clients WHERE revoked=0")]
                    grants = [dict(r) for r in db.execute("SELECT * FROM grants")]
                    failures = db.execute("""
                        WITH checks AS (
                            SELECT account, MAX(id) AS id FROM audit
                            WHERE principal='service' AND event='browser_check_started'
                            GROUP BY account
                        )
                        SELECT failure.account,failure.at,failure.reason FROM audit AS failure
                        LEFT JOIN checks ON checks.account=failure.account
                        WHERE failure.principal='service' AND failure.event='browser_navigation_failed'
                          AND failure.id > COALESCE(checks.id,0)
                        ORDER BY failure.id DESC LIMIT 100
                    """).fetchall()
                    routes = db.execute("SELECT account,at,reason FROM audit WHERE principal='service' AND event='browser_navigation_route' ORDER BY id DESC LIMIT 100").fetchall()
                from .navigation import valid_hint
                route_views = {}
                for route in routes:
                    if route["account"] not in route_views and valid_hint(route["reason"]):
                        route_views[route["account"]] = route
                navigation_failures = []
                seen_failures = set()
                pattern = r"(?:request|redirect):(?:destination|method|http_[1-5][0-9]{2}|missing_location|response_size|redirect_limit|transport):(?:configured_path_[0-9]{1,3}|unreviewed_destination):(?:query|no_query)"
                for failure in failures:
                    if (failure["account"] in config.accounts and failure["account"] not in seen_failures
                            and re.fullmatch(pattern, failure["reason"])):
                        item = dict(failure)
                        route = route_views.get(failure["account"])
                        if route and abs(route["at"] - failure["at"]) < 1:
                            item["route"] = route["reason"]
                        navigation_failures.append(item)
                        seen_failures.add(failure["account"])
                for item in accounts:
                    approved = {g["operation"] for g in grants if g["principal"] == "generic" and g["account"] == item["account"]
                        and g["fingerprint"] == config.fingerprint(item["account"])
                        and (g["expires"] is None or g["expires"] > time.time())}
                    item["portable_ready"] = bool(approved)
                    item["approved_operations"] = [operation for operation in item["operations"] if operation["name"] in approved]
                with guard:
                    connection_jobs = dict(jobs)
                state = {"accounts": accounts, "principals": principals, "grants": grants,
                         "local_host_actions": local_host_actions,
                         "background_recovery": broker.worker_health.view(),
                         "integrations": broker.store.get("agent-integrations", principals),
                         "automatic_sessions": broker.store.get("session-integrations", {}),
                         "connection_jobs": connection_jobs,
                         "navigation_failures": navigation_failures,
                         "environment": aggregate(accounts, test_mode=config.test_mode)}
                if not local_host_actions:
                    from .managed_client import view as managed_client
                    state["managed_client"] = managed_client(broker.store)
                from .password_sync import view
                state["password_sync"] = view(broker.store)
                from .bitwarden_source import available as bitwarden_available, connections as bitwarden_connections
                state["bitwarden_available"] = bitwarden_available(broker.store)
                state["bitwarden_connections"] = bitwarden_connections(broker.store)
                from .password_import import sync_suggestion
                for item in accounts:
                    suggestion = sync_suggestion(broker.store, item["account"], config=config)
                    if suggestion:
                        item["password_sync_suggestion"] = suggestion
                from .browser_updates import view as browser_updates
                state["browser_updates"] = browser_updates(broker.store)
                from .sms_setup import view as sms_setup
                state["sms_setups"] = sms_setup(broker.store)
                from .device_email_setup import view as device_email_setups
                state["device_email_setups"] = device_email_setups(broker.store)
                from .browser_sessions import candidates, requests
                state["browser_session_accounts"] = candidates(broker)
                state["browser_session_requests"] = requests(broker, owner=True)
                if guided:
                    from .catalog import view
                    state["catalog"] = view()
                    present = {item["id"] for item in state["catalog"]}
                    state["catalog"] += [{"id": key, **describe(spec, test_mode=config.test_mode), "url": spec.login_url,
                                          "operations": [{"name": n, "description": op.description}
                                                         for n, op in spec.operations.items()]}
                                         for key, spec in config.accounts.items()
                                         if isinstance(spec, BrowserAccount) and key not in present]
                    state["portable_cli"] = (str(Path.home() / ".agents/skills/account-access/scripts/access")
                                             if local_host_actions else None)
                from .mailbox_health import view as mailbox_health
                from .mailboxes import view as mailboxes
                from .mailbox_oauth import view as mailbox_oauth
                state["mailboxes"] = mailboxes(broker.store)
                state["mailbox_oauth"] = mailbox_oauth(broker)
                source_views = []
                for key, source in config.code_sources.items():
                    credential = broker.store.get("source:" + key)
                    enrolled = (credential.get("enabled") is True if source.kind == "gmail"
                                else credential.get("enabled") is not False) if isinstance(credential, dict) else False
                    source_views.append({"id": key, "kind": source.kind,
                                          "message_purpose": source.message_purpose,
                                          "mailbox_account": source.account,
                                          "mail_server": source.host,
                                          "mail_port": source.port,
                                          "recipient": source.recipient if source.kind in {"imap", "gmail"} else None,
                                          "linked_mailbox": credential.get("mailbox") if isinstance(credential, dict) else None,
                                          "connection_check": mailbox_health(broker.store, key),
                                          "enrolled": bool(credential) and enrolled,
                                          "accounts": [key2 for key2, spec in config.accounts.items()
                                                       if isinstance(spec, BrowserAccount) and spec.login
                                                       and key in spec.login.sources()]})
                state["code_sources"] = source_views
                self.send(200, state)
            else:
                self.send(404, {"status": "DENIED"})

        def do_POST(self):
            if not self.authorized(mutate=True):
                self.send(403, {"status": "DENIED", "reason": "owner_authorization_required"})
                return
            if not local_host_actions and (self.path in {
                    "/owner/install", "/owner/google-messages/prepare", "/owner/sms/setup-start",
                    "/owner/connect", "/owner/mailbox/oauth/connect"} or self.path.startswith("/owner/browser-session/")):
                self.send(403, {"status": "NEEDS_USER", "reason": "trusted_host_action_required"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                limit = 8_000_000 if self.path == "/owner/import/preview" else 65536
                if not 0 < length <= limit:
                    raise ValueError()
                data = json.loads(self.rfile.read(length))
                if self.path in {"/owner/device-email/preview", "/owner/device-email/apply",
                                 "/owner/device-email/discard", "/owner/device-email/remove"}:
                    from . import device_email_setup
                    if self.path.endswith("/preview"):
                        if type(data) is not dict or set(data) != {"account", "fingerprint", "mailbox"}:
                            raise ValueError()
                        result = device_email_setup.preview(broker.store, data["account"], data["fingerprint"], data["mailbox"])
                    elif self.path.endswith("/remove"):
                        if type(data) is not dict or set(data) != {"account", "fingerprint"}:
                            raise ValueError()
                        result = device_email_setup.remove(broker.store, data["account"], data["fingerprint"])
                    else:
                        if type(data) is not dict or set(data) != {"id"}:
                            raise ValueError()
                        action = device_email_setup.apply if self.path.endswith("/apply") else device_email_setup.discard
                        result = action(broker.store, data["id"])
                    self.send(200, result)
                    return
                if self.path == "/owner/browser-message":
                    if local_host_actions or server_socket is None or not guided:
                        raise AccessError("DENIED", "trusted_owner_route_required")
                    if type(data) is not dict or set(data) != {"message"}:
                        raise ValueError()
                    from .google_messages import handle
                    result = handle(broker.store, data["message"])
                    if result.get("status") == "CONNECTED":
                        ident = new_job(result["account"])
                        threading.Thread(target=verify, args=(result["account"], ident), daemon=True).start()
                        result["verification_started"] = True
                    self.send(200, result)
                    return
                if self.path == "/owner/native-messages/respond":
                    if native_messages is None:
                        raise AccessError("DENIED", "trusted_owner_route_required")
                    if type(data) is not dict or set(data) != {"id", "response"}:
                        raise ValueError()
                    self.send(200, native_messages.respond(data["id"], data["response"]))
                    return
                if self.path in {"/owner/client/enroll", "/owner/client/installed"}:
                    if local_host_actions or server_socket is None:
                        raise AccessError("DENIED", "trusted_owner_route_required")
                    from .managed_client import enroll, installed
                    if self.path.endswith("/enroll"):
                        if type(data) is not dict or set(data) != {"token"}:
                            raise ValueError()
                        result = enroll(broker.store, data["token"])
                    else:
                        if type(data) is not dict or set(data) != {"client_id", "hosts"}:
                            raise ValueError()
                        result = installed(broker.store, data["client_id"], data["hosts"])
                    self.send(200, result)
                    return
                if guided and self.path == "/owner/google-messages/prepare":
                    if data != {}:
                        raise ValueError()
                    from .google_messages_host import prepare
                    self.send(200, prepare(broker.store))
                    return
                if guided and self.path == "/owner/sms/setup-start":
                    from .sms_setup import prepare
                    if set(data) != {"account", "fingerprint"}:
                        raise ValueError()
                    now = time.time()
                    with guard:
                        for key, setup in list(sms_setups.items()):
                            if setup["expires"] < now:
                                setup["stop"].set()
                                del sms_setups[key]
                        if len(sms_setups) >= 8:
                            raise AccessError("RETRYABLE", "sms_setup_limit")
                    fingerprint = prepare(broker.store, data["account"], data["fingerprint"])
                    ident = new_job(data["account"])
                    with guard:
                        stop_review = threading.Event()
                        sms_setups[ident] = {"account": data["account"], "fingerprint": fingerprint,
                                              "expires": now + 600, "stop": stop_review}
                    threading.Thread(target=verify, args=(data["account"], ident, True, "sms", stop_review), daemon=True).start()
                    self.send(200, {"status": "CONNECTING", "id": ident, "expires": now + 600})
                    return
                if guided and self.path in {"/owner/sms/setup-apply", "/owner/sms/setup-discard"}:
                    expected = {"id", "sender", "template"} if self.path.endswith("apply") else {"id"}
                    if set(data) != expected or not isinstance(data.get("id"), str):
                        raise ValueError()
                    with guard:
                        setup = sms_setups.pop(data["id"], None)
                    if not setup:
                        raise AccessError("DENIED", "sms_setup_expired")
                    setup["stop"].set()
                    if self.path.endswith("discard"):
                        self.send(200, {"status": "DISCARDED"})
                        return
                    if setup["expires"] < time.time():
                        raise AccessError("DENIED", "sms_setup_expired")
                    from .sms_setup import apply
                    self.send(200, apply(broker.store, setup["account"], setup["fingerprint"], data["sender"], data["template"]))
                    return
                if guided and self.path == "/owner/browser-update":
                    from .browser_updates import apply
                    if set(data) != {"account", "fingerprint"}:
                        raise ValueError()
                    self.send(200, apply(broker, data["account"], data["fingerprint"]))
                    return
                if self.path == "/owner/authenticator/preview":
                    from .authenticator_import import preview
                    if set(data) not in ({"source", "uri"}, {"source", "uris"}):
                        raise ValueError()
                    self.send(200, preview(broker.store, data["source"], data.get("uris", data.get("uri"))))
                    return
                if self.path == "/owner/authenticator/apply":
                    from .authenticator_import import apply
                    if set(data) != {"id", "index"}:
                        raise ValueError()
                    self.send(200, apply(broker.store, data["id"], data["index"]))
                    return
                if self.path == "/owner/authenticator/discard":
                    from .authenticator_import import discard
                    if set(data) != {"id"}:
                        raise ValueError()
                    self.send(200, discard(broker.store, data["id"]))
                    return
                if self.path == "/owner/bitwarden/connect":
                    from .bitwarden_source import connect
                    if type(data) is not dict or set(data) != {
                            "region", "client_id", "client_secret", "master_password", "consent_vault_access"}:
                        raise ValueError()
                    self.send(200, connect(broker.store, data))
                    return
                if self.path == "/owner/bitwarden/disconnect":
                    from .bitwarden_source import disconnect
                    if type(data) is not dict or set(data) != {"id", "generation"}:
                        raise ValueError()
                    self.send(200, disconnect(broker.store, data["id"], data["generation"]))
                    return
                if self.path == "/owner/password-sync":
                    from .password_sync import enroll
                    if set(data) != {"account", "connection"}:
                        raise ValueError()
                    self.send(200, enroll(broker.store, data["account"], data["connection"]))
                    return
                if self.path == "/owner/password-sync/reconnect":
                    from .password_sync import reconnect
                    if set(data) != {"account", "connection"} or not isinstance(data["account"], str):
                        raise ValueError()
                    self.send(200, reconnect(broker.store, data["account"], data["connection"]))
                    return
                if self.path == "/owner/password-sync/disconnect":
                    from .password_sync import unlink
                    if set(data) != {"account"}:
                        raise ValueError()
                    self.send(200, unlink(broker.store, data["account"]))
                    return
                if self.path == "/owner/phone/pair":
                    if set(data) != {"source"}:
                        raise ValueError()
                    self.send(200, phone.pair(data["source"]))
                    return
                if self.path == "/owner/source":
                    from .factors import enroll
                    if set(data) != {"source", "credential"}:
                        raise ValueError()
                    self.send(200, enroll(broker.store, data["source"], data["credential"]))
                    return
                if self.path == "/owner/source/check":
                    from .mailbox_health import check
                    if set(data) != {"source"}:
                        raise ValueError()
                    self.send(200, check(broker, data["source"]))
                    return
                if self.path == "/owner/mailbox/connect":
                    from .mailboxes import connect as connect_mailbox
                    self.send(200, connect_mailbox(broker, data))
                    return
                if self.path == "/owner/mailbox/oauth/begin":
                    from .mailbox_oauth import begin
                    if set(data) != {"account", "fingerprint", "redirect_uri"}:
                        raise ValueError()
                    self.send(200, begin(broker, data["account"], data["fingerprint"], data["redirect_uri"]))
                    return
                if self.path == "/owner/mailbox/oauth/check":
                    from .mailbox_oauth import check
                    if type(data) is not dict or set(data) != {"account", "fingerprint"}:
                        raise ValueError()
                    self.send(200, check(broker, data["account"], data["fingerprint"]))
                    return
                if self.path in {"/owner/mailbox/oauth/finish", "/owner/mailbox/oauth/cancel"}:
                    from .mailbox_oauth import cancel, finish
                    expected = {"account", "attempt", "callback"} if self.path.endswith("/finish") else {"account", "attempt"}
                    if set(data) != expected:
                        raise ValueError()
                    result = (finish(broker, data["account"], data["attempt"], data["callback"])
                              if self.path.endswith("/finish") else cancel(broker, data["account"], data["attempt"]))
                    self.send(200, result)
                    return
                if self.path == "/owner/mailbox/oauth/connect":
                    from .mailbox_oauth import prepare
                    if set(data) != {"account", "fingerprint"}:
                        raise ValueError()
                    prepare(broker, data["account"], data["fingerprint"])
                    ident = new_job(data["account"])
                    threading.Thread(target=connect, args=(data["account"], ident), daemon=True).start()
                    self.send(200, {"status": "RUNNING", "id": ident})
                    return
                if self.path in {"/owner/mailbox/check", "/owner/mailbox/remove"}:
                    from .mailboxes import check, remove
                    if set(data) != {"id"}:
                        raise ValueError()
                    self.send(200, check(broker, data["id"]) if self.path.endswith("/check") else remove(broker.store, data["id"]))
                    return
                if self.path == "/owner/mailbox/password":
                    from .mailboxes import update_password
                    if set(data) != {"id", "password"}:
                        raise ValueError()
                    self.send(200, update_password(broker, data["id"], data["password"]))
                    return
                if self.path == "/owner/source/revoke":
                    from .factors import revoke
                    if set(data) != {"source"}:
                        raise ValueError()
                    self.send(200, revoke(broker.store, data["source"]))
                    return
                if guided and self.path == "/owner/install":
                    from .install import install_detected, install_skill
                    if data == {}:
                        self.send(200, install_detected(broker.store))
                        return
                    agents = data.get("agents")
                    if (not isinstance(agents, list) or not 1 <= len(agents) <= 2
                            or any(x not in {"codex", "claude"} for x in agents)):
                        raise ValueError()
                    for agent in sorted(set(agents)):
                        install_skill(broker.store, agent)
                    self.send(200, {"status": "INSTALLED"})
                    return
                if self.path == "/owner/import/preview":
                    from .password_import import preview
                    if set(data) != {"csv"}:
                        raise ValueError()
                    self.send(200, preview(broker.store, data["csv"]))
                    return
                if self.path == "/owner/import/apply":
                    from .password_import import apply
                    if set(data) != {"id", "selections"}:
                        raise ValueError()
                    with broker.store.db() as db:
                        principals = [r[0] for r in db.execute("SELECT DISTINCT principal FROM clients WHERE revoked=0")]
                    result = apply(broker, data["id"], data["selections"], principals)
                    result["jobs"] = []
                    for account in result["accounts"]:
                        ident = new_job(account)
                        threading.Thread(target=verify, args=(account, ident), daemon=True).start()
                        result["jobs"].append({"account": account, "id": ident})
                    self.send(200, result)
                    return
                if guided and self.path == "/owner/add":
                    from .catalog import add, entries
                    service = data.get("service")
                    with broker.store.db() as db:
                        installed = {r[0] for r in db.execute("SELECT DISTINCT principal FROM clients WHERE revoked=0")}
                    agents = data.get("agents", sorted(installed))
                    if (set(data) not in [{"service", "username", "password", "agents"},
                                         {"service", "username", "password"}]
                            or not isinstance(service, str) or service not in entries()
                            or not isinstance(agents, list) or not 1 <= len(agents) <= 32
                            or any(x not in installed for x in agents)
                            or any(not isinstance(data[x], str) or not 0 < len(data[x]) <= 4096
                                   for x in ["username", "password"])):
                        raise ValueError()
                    if not set(agents) <= installed:
                        raise AccessError("DENIED", "install_your_agent_first")
                    ident = new_job(service)
                    try:
                        add(broker.store, service)
                        with broker.store.lock("account:" + service):
                            broker.store.put("credential:" + service,
                                             {"username": data["username"], "password": data["password"]})
                        for agent in sorted(set(agents)):
                            broker.grant(agent, service, list(broker.store.config().accounts[service].operations))
                    except Exception:
                        with guard:
                            jobs.pop(ident, None)
                        raise
                    threading.Thread(target=verify, args=(service, ident), daemon=True).start()
                    self.send(200, {"status": "CONNECTING", "id": ident})
                    return
                if guided and self.path == "/owner/stop":
                    if data not in [{}, {"updating": True}]:
                        raise ValueError()
                    if not data:
                        paused = broker.store.root / "service.paused"
                        private_file(paused, b"paused", replace=paused.exists())
                    from .supervisor import disable
                    disable(broker.store.root)
                    self.send(200, {"status": "STOPPED"})
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return
                if guided and self.path == "/owner/verify/finish-review":
                    if set(data) != {"id"} or not isinstance(data["id"], str):
                        raise ValueError()
                    with guard:
                        job = jobs.get(data["id"], {})
                        stop = reviews.get(data["id"])
                        if not stop or job.get("status") != "RUNNING" or not job.get("attention"):
                            raise AccessError("DENIED", "verification_review_not_active")
                        stop.set()
                    self.send(200, {"status": "REVIEW_FINISHED"})
                    return
                account = data.get("account")
                config = broker.store.config()
                if account not in config.accounts:
                    raise AccessError("DENIED", "unknown_account")
                if guided and self.path == "/owner/browser-session/start":
                    if set(data) != {"account", "fingerprint", "username"}:
                        raise ValueError()
                    from .browser_sessions import begin
                    from .google_messages_host import prepare
                    # Stage the existing helper update; site/cookie access is
                    # optional and is granted only by the Chrome owner action.
                    result = begin(broker, account, data["fingerprint"], data["username"])
                    staged = prepare(broker.store)
                    self.send(200, {**staged, **result})
                elif guided and self.path == "/owner/browser-session/cancel":
                    if set(data) != {"account", "id"}:
                        raise ValueError()
                    from .browser_sessions import cancel
                    self.send(200, cancel(broker.store, account, data["id"]))
                elif guided and self.path == "/owner/verify":
                    if (set(data) not in ({"account"}, {"account", "visible"})
                            or not isinstance(data.get("visible", False), bool)
                            or not isinstance(config.accounts[account], BrowserAccount)):
                        raise ValueError()
                    visible = data.get("visible", False)
                    if visible and not local_host_actions:
                        raise AccessError("NEEDS_USER", "trusted_browser_handoff_required")
                    ident = new_job(account)
                    stop = threading.Event() if visible else None
                    if stop:
                        with guard:
                            reviews[ident] = stop
                    threading.Thread(target=verify, args=(account, ident, visible, None, stop), daemon=True).start()
                    self.send(200, {"status": "CONNECTING", "id": ident})
                elif self.path == "/owner/credential":
                    if isinstance(config.accounts[account], OAuthAccount):
                        value = {"client_secret": data["client_secret"]}
                    else:
                        value = {"username": data["username"], "password": data["password"]}
                    if not all(isinstance(v, str) and 0 < len(v) <= 4096 for v in value.values()):
                        raise ValueError()
                    with broker.store.lock("account:" + account):
                        with broker.store.db() as db:
                            previous = broker.store.get("credential:" + account)
                            previous_link = broker.store.get("password-link:" + account)
                            broker.store.put("credential:" + account, value, db=db)
                            if isinstance(config.accounts[account], BrowserAccount) and previous != value:
                                # A session for the old identity must not be
                                # reported as the edited account's connection.
                                broker.store.put("connection:" + account, None, db=db)
                                # An explicit owner edit replaces the source,
                                # just like a fresh CSV import. An old manager
                                # link must not silently restore its former
                                # username/password on the next refresh.
                                broker.store.put("password-link:" + account, None, db=db)
                                from .password_import import SYNC_HINT
                                broker.store.put(SYNC_HINT + account, None, db=db)
                                if previous_link:
                                    # Replacing this source repairs its own
                                    # prerequisite, not website authentication.
                                    # Unbound historical gates stay pending.
                                    from .password_sync import _resolve_source_prerequisites
                                    _resolve_source_prerequisites(db, account, time.time())
                            # Saving a credential is not verified login and
                            # cannot clear presence, CAPTCHA, unknown-page or
                            # transaction challenges or restart their tasks.
                            db.execute("UPDATE challenges SET resolved=? WHERE account=? AND resolved IS NULL AND kind='login' AND reason IN ('password_not_connected','browser_login_required','client_secret_not_configured')",
                                       (time.time(), account))
                    self.send(200, {"status": "SAVED"})
                elif self.path == "/owner/connect":
                    ident = secrets.token_hex(16)
                    with guard:
                        if len([x for x in jobs.values() if x["status"] == "RUNNING"]) >= 4:
                            raise AccessError("RETRYABLE", "connection_limit")
                        jobs[ident] = {"status": "RUNNING", "account": account}
                    threading.Thread(target=connect, args=(account, ident), daemon=True).start()
                    self.send(200, {"status": "RUNNING", "id": ident})
                elif self.path == "/owner/grant":
                    with broker.store.db() as db:
                        principals = {r[0] for r in db.execute("SELECT DISTINCT principal FROM clients WHERE revoked=0")}
                    if data["principal"] not in principals:
                        raise AccessError("DENIED", "unknown_client")
                    broker.grant(data["principal"], account, data["operations"])
                    self.send(200, {"status": "GRANTED"})
                elif self.path == "/owner/revoke":
                    broker.revoke(account=account)
                    self.send(200, {"status": "REVOKED"})
                else:
                    self.send(404, {"status": "DENIED"})
            except AccessError as exc:
                self.send(403, {"status": exc.status, "reason": exc.reason})
            except Exception:
                self.send(400, {"status": "DENIED", "reason": "invalid_request"})

    class OwnerServer(ThreadingHTTPServer):
        def server_close(self):
            with guard:
                for setup in sms_setups.values():
                    setup["stop"].set()
                for stop in reviews.values():
                    stop.set()
            phone.close()
            super().server_close()

    if server_socket is None:
        server = OwnerServer(("127.0.0.1", 0), Handler)
    else:
        class UnixOwnerServer(OwnerServer):
            address_family = socket.AF_UNIX
        server = UnixOwnerServer(server_socket.getsockname(), Handler, bind_and_activate=False)
        server.socket.close()
        server.socket = server_socket
        server.server_name = "localhost"
        server.server_port = origin_port
    return server, token


def open_owner(broker):
    server, token = make_owner_server(broker)
    with server:
        # Fragment avoids transmitting the bootstrap capability in HTTP URLs or referrers.
        webbrowser.open(f"http://127.0.0.1:{server.server_port}/#" + token)
        print("Owner console opened in your browser. Close this command to end the owner session.")
        server.serve_forever()
