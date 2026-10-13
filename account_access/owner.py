"""An ephemeral, loopback-only owner console. This authority is never an agent API."""

import json
import hashlib
import hmac
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .errors import AccessError
from .models import BrowserAccount, OAuthAccount


def make_owner_server(broker, *, guided=False, instance_key=None):
    token = secrets.token_urlsafe(32)
    instance_key = instance_key or secrets.token_bytes(32)
    jobs = {}
    guard = threading.Lock()

    def verify(account, job_id):
        try:
            config = broker.store.config().accounts[account]
            with broker.store.lock("account:" + account, timeout=5):
                broker.browser.read(account, next(iter(config.operations.values())), config,
                                    secret_values=set())
            broker.tick()
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
            if sum(x["status"] == "RUNNING" for x in jobs.values()) >= 4:
                raise AccessError("RETRYABLE", "connection_limit")
            jobs[ident] = {"status": "RUNNING", "account": account}
        return ident

    def connect(account, job_id):
        try:
            config = broker.store.config().accounts[account]
            if isinstance(config, OAuthAccount):
                from .cli import connect_oauth
                connect_oauth(broker, account)
            else:
                broker.browser.connect(account, complete=lambda page: page.locator(config.ready_selector).first.wait_for(state="visible", timeout=300000))
            broker.tick()
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
                    state = broker.store.get("connection:" + account)
                    accounts.append({"account": account, "label": spec.label, "route": spec.kind,
                                     "connected": bool(state and not state.get("revoked")),
                                     "operations": [{"name": name, "description": op.description} for name, op in spec.operations.items()],
                                     "challenges": [broker.challenge_view(x) for x in broker.store.pending(account)]})
                with broker.store.db() as db:
                    principals = [r[0] for r in db.execute("SELECT DISTINCT principal FROM clients WHERE revoked=0")]
                    grants = [dict(r) for r in db.execute("SELECT * FROM grants")]
                with guard:
                    connection_jobs = dict(jobs)
                state = {"accounts": accounts, "principals": principals, "grants": grants,
                         "connection_jobs": connection_jobs,
                         "environment": "controlled-demo" if config.test_mode else "live"}
                if guided:
                    from .catalog import view
                    state["catalog"] = view()
                self.send(200, state)
            else:
                self.send(404, {"status": "DENIED"})

        def do_POST(self):
            if not self.authorized(mutate=True):
                self.send(403, {"status": "DENIED", "reason": "owner_authorization_required"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    raise ValueError()
                data = json.loads(self.rfile.read(length))
                if guided and self.path == "/owner/install":
                    from .install import install_skill
                    agents = data.get("agents")
                    if (not isinstance(agents, list) or not 1 <= len(agents) <= 2
                            or any(x not in {"codex", "claude"} for x in agents)):
                        raise ValueError()
                    for agent in sorted(set(agents)):
                        install_skill(broker.store, agent)
                    self.send(200, {"status": "INSTALLED"})
                    return
                if guided and self.path == "/owner/add":
                    from .catalog import add, entries
                    service = data.get("service")
                    agents = data.get("agents")
                    if (set(data) != {"service", "username", "password", "agents"}
                            or not isinstance(service, str) or service not in entries()
                            or not isinstance(agents, list) or not 1 <= len(agents) <= 2
                            or any(x not in {"codex", "claude"} for x in agents)
                            or any(not isinstance(data[x], str) or not 0 < len(data[x]) <= 4096
                                   for x in ["username", "password"])):
                        raise ValueError()
                    with broker.store.db() as db:
                        installed = {r[0] for r in db.execute("SELECT DISTINCT principal FROM clients WHERE revoked=0")}
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
                    self.send(200, {"status": "STOPPED"})
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return
                account = data.get("account")
                config = broker.store.config()
                if account not in config.accounts:
                    raise AccessError("DENIED", "unknown_account")
                if guided and self.path == "/owner/verify":
                    if set(data) != {"account"} or not isinstance(config.accounts[account], BrowserAccount):
                        raise ValueError()
                    ident = new_job(account)
                    threading.Thread(target=verify, args=(account, ident), daemon=True).start()
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

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    return server, token


def open_owner(broker):
    server, token = make_owner_server(broker)
    with server:
        # Fragment avoids transmitting the bootstrap capability in HTTP URLs or referrers.
        webbrowser.open(f"http://127.0.0.1:{server.server_port}/#" + token)
        print("Owner console opened in your browser. Close this command to end the owner session.")
        server.serve_forever()
