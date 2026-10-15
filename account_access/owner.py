"""An ephemeral, loopback-only owner console. This authority is never an agent API."""

import json
import hashlib
import hmac
import secrets
import re
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .errors import AccessError
from .models import BrowserAccount, OAuthAccount
from .storage import check_private, private_file


def make_owner_server(broker, *, guided=False, instance_key=None):
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
    token = secrets.token_urlsafe(32)
    instance_key = instance_key or secrets.token_bytes(32)
    jobs = {}
    guard = threading.Lock()
    verification_slots = threading.BoundedSemaphore(4)

    def verify(account, job_id, visible=False):
        with verification_slots:
            _verify(account, job_id, visible)

    def _verify(account, job_id, visible=False):
        try:
            config = broker.store.config().accounts[account]
            with broker.store.lock("account:" + account, timeout=5):
                broker.browser.read(account, next(iter(config.operations.values())), config,
                                    secret_values=set(), visible=visible)
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
            jobs[job_id] = result

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
            if isinstance(config, OAuthAccount):
                from .cli import connect_oauth
                connect_oauth(broker, account)
            elif isinstance(config, BrowserAccount):
                broker.browser.connect(account, complete=lambda page: page.locator(config.ready_selector).first.wait_for(state="visible", timeout=300000))
            else:
                raise AccessError("NEEDS_USER", "github_cli_reconnect_in_owner", "login")
            try:
                broker.tick()
            except AccessError as exc:
                if exc.status != "RETRYABLE":
                    raise
            result = {"status": "CONNECTED", "account": account}
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
            if guided and self.path.startswith("/owner/ready?"):
                challenge = parse_qs(urlsplit(self.path).query).get("challenge", [""])[0]
                if len(challenge) != 64 or any(c not in "0123456789abcdef" for c in challenge):
                    self.send(400, {"status": "DENIED"})
                    return
                self.send(200, {"proof": hmac.new(instance_key, challenge.encode(), hashlib.sha256).hexdigest()})
                return
            if self.path == "/owner/state":
                config = broker.store.config()
                accounts = []
                for account, spec in config.accounts.items():
                    accounts.append({"account": account, "label": spec.label, "route": spec.kind,
                                     **broker.connection_view(account, config),
                                     "operations": [{"name": name, "description": op.description} for name, op in spec.operations.items()],
                                     "challenges": [broker.challenge_view(x) for x in broker.store.pending(account)]})
                with broker.store.db() as db:
                    principals = [r[0] for r in db.execute("SELECT DISTINCT principal FROM clients WHERE revoked=0")]
                    grants = [dict(r) for r in db.execute("SELECT * FROM grants")]
                    failures = db.execute("SELECT account,at,reason FROM audit WHERE principal='service' AND event='browser_navigation_failed' ORDER BY id DESC LIMIT 100").fetchall()
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
                         "integrations": broker.store.get("agent-integrations", principals),
                         "automatic_sessions": broker.store.get("session-integrations", {}),
                         "connection_jobs": connection_jobs,
                         "navigation_failures": navigation_failures,
                         "environment": "controlled-demo" if config.test_mode else "live"}
                from .password_sync import view
                state["password_sync"] = view(broker.store)
                if guided:
                    from .catalog import view
                    state["catalog"] = view()
                    present = {item["id"] for item in state["catalog"]}
                    state["catalog"] += [{"id": key, "label": spec.label, "url": spec.login_url,
                                          "operations": [{"name": n, "description": op.description}
                                                         for n, op in spec.operations.items()]}
                                         for key, spec in config.accounts.items()
                                         if isinstance(spec, BrowserAccount) and key not in present]
                    state["portable_cli"] = str(Path.home() / ".agents/skills/account-access/scripts/access")
                state["code_sources"] = [{"id": key, "kind": source.kind,
                                          "mailbox_account": source.account,
                                          "mail_server": source.host,
                                          "enrolled": bool(broker.store.get("source:" + key)) and broker.store.get("source:" + key, {}).get("enabled") is not False,
                                          "accounts": [key2 for key2, spec in config.accounts.items()
                                                       if isinstance(spec, BrowserAccount) and spec.login
                                                       and spec.login.code_source == key]}
                                         for key, source in config.code_sources.items()]
                self.send(200, state)
            else:
                self.send(404, {"status": "DENIED"})

        def do_POST(self):
            if not self.authorized(mutate=True):
                self.send(403, {"status": "DENIED", "reason": "owner_authorization_required"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                limit = 8_000_000 if self.path == "/owner/import/preview" else 65536
                if not 0 < length <= limit:
                    raise ValueError()
                data = json.loads(self.rfile.read(length))
                if guided and self.path == "/owner/github-cli/preview":
                    from .github_cli import preview
                    if data != {}:
                        raise ValueError()
                    self.send(200, preview(broker.store))
                    return
                if guided and self.path == "/owner/github-cli/apply":
                    from .github_cli import apply
                    if set(data) != {"id"}:
                        raise ValueError()
                    self.send(200, apply(broker, data["id"]))
                    return
                if self.path == "/owner/authenticator/preview":
                    from .authenticator_import import preview
                    if set(data) != {"source", "uri"}:
                        raise ValueError()
                    self.send(200, preview(broker.store, data["source"], data["uri"]))
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
                if self.path == "/owner/password-sync":
                    from .password_sync import enroll
                    if set(data) != {"account", "connection"}:
                        raise ValueError()
                    self.send(200, enroll(broker.store, data["account"], data["connection"]))
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
                    self.send(200, {"status": "STOPPED"})
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return
                account = data.get("account")
                config = broker.store.config()
                if account not in config.accounts:
                    raise AccessError("DENIED", "unknown_account")
                if guided and self.path == "/owner/verify":
                    if (set(data) not in ({"account"}, {"account", "visible"})
                            or not isinstance(data.get("visible", False), bool)
                            or not isinstance(config.accounts[account], BrowserAccount)):
                        raise ValueError()
                    ident = new_job(account)
                    threading.Thread(target=verify, args=(account, ident, data.get("visible", False)), daemon=True).start()
                    self.send(200, {"status": "CONNECTING", "id": ident})
                elif self.path == "/owner/credential":
                    if isinstance(config.accounts[account], OAuthAccount):
                        value = {"client_secret": data["client_secret"]}
                    else:
                        value = {"username": data["username"], "password": data["password"]}
                    if not all(isinstance(v, str) and 0 < len(v) <= 4096 for v in value.values()):
                        raise ValueError()
                    with broker.store.lock("account:" + account):
                        broker.store.put("credential:" + account, value)
                        broker.store.resolve_login(account)
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
            phone.close()
            super().server_close()

    server = OwnerServer(("127.0.0.1", 0), Handler)
    return server, token


def open_owner(broker):
    server, token = make_owner_server(broker)
    with server:
        # Fragment avoids transmitting the bootstrap capability in HTTP URLs or referrers.
        webbrowser.open(f"http://127.0.0.1:{server.server_port}/#" + token)
        print("Owner console opened in your browser. Close this command to end the owner session.")
        server.serve_forever()
