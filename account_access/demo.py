"""Controlled OAuth and website provider. Never represents a real bank or live integration."""

import base64
import hashlib
import json
import secrets
import threading
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2 as httpx
import pyotp

from .broker import Broker
from .models import Configuration
from .storage import Store, load_key

DEMO_PASSWORD = "controlled-demo-password-only"
DEMO_SEED = "JBSWY3DPEHPK3PXP"


class DemoProvider:
    def __init__(self):
        self.codes = {}
        self.access_tokens = {}
        self.refresh_tokens = {}
        self.sessions = set()
        self.pending_mfa = set()
        self.pending_codes = {}
        self.email_count = 0
        self.sms_count = 0
        self.delivery = None
        self.refresh_count = 0
        self.api_count = 0
        self.login_count = 0
        self.totp_count = 0
        self.force_forbidden = False
        self.force_401 = False
        self.temporary_failure = False
        self.drop_refresh_response = False
        self.transaction_challenge = False
        self.posted_paths = []
        self.echo_login_code = False
        self.last_login_code = ""
        self.password = DEMO_PASSWORD
        self.login_redirect = None
        self.lock = threading.Lock()
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def send(self, status, body, headers=None, content_type="application/json"):
                payload = json.dumps(body).encode() if content_type == "application/json" else body.encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(payload)

            def cookie(self, name):
                cookies = SimpleCookie(self.headers.get("Cookie", ""))
                return cookies[name].value if name in cookies else None

            def authenticated(self):
                return self.cookie("demo_session") in provider.sessions

            def page(self, body):
                self.send(200, "<!doctype html><html><body>" + body + "</body></html>", content_type="text/html")

            def login_form(self, mfa=False, prefix=None):
                path = (prefix or ("/mfa" if mfa else "/web")) + "/login"
                return f'<h1>Example account sign-in</h1><p>Controlled testing account</p><form id="password-login" action="{path}" method="post"><label>Email<input name="username" id="username"></label><label>Password<input name="password" id="password" type="password"></label><button id="login-submit">Sign in</button></form>'

            def do_GET(self):
                parts = urlsplit(self.path)
                query = parse_qs(parts.query)
                if parts.path == "/oauth/authorize":
                    code = secrets.token_urlsafe(24)
                    provider.codes[code] = {k: v[0] for k, v in query.items()}
                    target = query["redirect_uri"][0] + "?" + urlencode({"code": code, "state": query["state"][0]})
                    self.send(302, {}, {"Location": target})
                elif parts.path.startswith("/api/"):
                    provider.api_count += 1
                    if provider.temporary_failure:
                        self.send(503, {"error": "temporary"})
                    elif provider.force_forbidden:
                        self.send(403, {"error": "forbidden"})
                    elif provider.force_401 or self.headers.get("Authorization", "").removeprefix("Bearer ") not in provider.access_tokens:
                        self.send(401, {"error": "invalid_token"})
                    else:
                        self.send(200, {"balance": "1234.56", "currency": "ILS", "environment": "controlled-demo",
                                        "access_token": self.headers["Authorization"].removeprefix("Bearer ")})
                elif parts.path in {prefix + suffix for prefix in ["/web", "/mfa", "/email", "/sms"] for suffix in ["/summary", "/login"]}:
                    if self.authenticated():
                        challenge = '<div id="action-challenge">Confirm payment</div>' if provider.transaction_challenge else ""
                        if provider.echo_login_code:
                            challenge += '<p id="echo">' + provider.last_login_code + '</p>'
                        self.page('<div id="ready">Controlled demo account</div><p id="balance">987.65</p><p id="currency">ILS</p>' + challenge)
                    else:
                        self.page(self.login_form(prefix=parts.path.rsplit("/", 1)[0]))
                elif parts.path in {"/mfa/code", "/email/code", "/sms/code"}:
                    kind = {"/mfa/code": "totp", "/email/code": "email", "/sms/code": "sms"}[parts.path]
                    label = {"totp": "Authenticator", "email": "Email", "sms": "SMS"}[kind]
                    self.page(f'<h1>{label} verification</h1><p>Enter the current sign-in code for this example account.</p><form id="{kind}-challenge" action="{parts.path}" method="post"><label>Verification code<input name="code" id="code" autocomplete="one-time-code"></label><button id="code-submit">Verify login</button></form>')
                elif parts.path == "/redirect":
                    self.send(302, {}, {"Location": "https://example.org/secret"})
                else:
                    self.send(404, {})

            def do_POST(self):
                provider.posted_paths.append(self.path)
                length = min(int(self.headers.get("Content-Length", "0")), 65536)
                data = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
                if self.path == "/oauth/token":
                    with provider.lock:
                        if data.get("grant_type") == "authorization_code":
                            grant = provider.codes.pop(data.get("code"), None)
                            challenge = base64.urlsafe_b64encode(hashlib.sha256(data.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
                            if not grant or grant.get("code_challenge") != challenge or grant.get("redirect_uri") != data.get("redirect_uri"):
                                self.send(400, {"error": "invalid_grant"})
                                return
                            scope = grant["scope"]
                        else:
                            scope = provider.refresh_tokens.pop(data.get("refresh_token"), None)
                            if not scope:
                                self.send(400, {"error": "invalid_grant"})
                                return
                            provider.refresh_count += 1
                        access = secrets.token_urlsafe(24)
                        refresh = secrets.token_urlsafe(24)
                        provider.access_tokens[access] = scope
                        provider.refresh_tokens[refresh] = scope
                        if provider.drop_refresh_response and data.get("grant_type") == "refresh_token":
                            self.connection.close()
                            return
                        self.send(200, {"access_token": access, "refresh_token": refresh,
                                        "token_type": "Bearer", "expires_in": 60, "scope": scope})
                elif self.path in {"/web/login", "/mfa/login", "/email/login", "/sms/login"}:
                    provider.login_count += 1
                    if provider.login_redirect:
                        self.send(307, {}, {"Location": provider.login_redirect})
                        return
                    if data.get("username") != "demo@example.test" or data.get("password") != provider.password:
                        self.page(self.login_form())
                        return
                    if not self.path.startswith("/web"):
                        token = secrets.token_urlsafe(24)
                        provider.pending_mfa.add(token)
                        prefix = self.path.rsplit("/", 1)[0]
                        if prefix in {"/email", "/sms"}:
                            code = f"{secrets.randbelow(1_000_000):06d}"
                            provider.pending_codes[token] = code
                            if provider.delivery:
                                provider.delivery(prefix[1:], code)
                        self.send(303, {}, {"Location": prefix + "/code", "Set-Cookie": f"demo_pending={token}; HttpOnly; SameSite=Strict; Path=/"})
                    else:
                        self.finish_login("/web/summary")
                elif self.path in {"/mfa/code", "/email/code", "/sms/code"}:
                    kind = self.path.split("/")[1]
                    setattr(provider, {"mfa": "totp_count", "email": "email_count", "sms": "sms_count"}[kind], getattr(provider, {"mfa": "totp_count", "email": "email_count", "sms": "sms_count"}[kind]) + 1)
                    provider.last_login_code = data.get("code", "")
                    token = self.cookie("demo_pending")
                    valid = (pyotp.TOTP(DEMO_SEED).verify(data.get("code", ""), valid_window=1) if kind == "mfa"
                             else secrets.compare_digest(provider.pending_codes.get(token, "missing"), data.get("code", "")))
                    if token not in provider.pending_mfa or not valid:
                        self.send(403, {})
                        return
                    provider.pending_mfa.remove(token)
                    provider.pending_codes.pop(token, None)
                    self.finish_login("/" + kind + "/summary")
                else:
                    self.send(404, {})

            def finish_login(self, path):
                session = secrets.token_urlsafe(24)
                provider.sessions.add(session)
                self.send(303, {}, {"Location": path, "Set-Cookie": f"demo_session={session}; HttpOnly; SameSite=Strict; Path=/"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def configuration(base):
    def website(prefix, mfa=False):
        form = {"username_selector": "#username", "password_selector": "#password", "submit_selector": "#login-submit"}
        resources = [base + prefix + suffix for suffix in ["/login", "/summary"]]
        challenges = {"login": "#password-login", "action": "#action-challenge"}
        if mfa:
            form.update({"code_selector": "#code", "code_submit_selector": "#code-submit", "code_source": "demo-totp"})
            resources.append(base + prefix + "/code")
            challenges["totp"] = "#totp-challenge"
        return {"kind": "browser", "label": "Controlled demo website" + (" with authenticator" if mfa else ""),
                "login_url": base + prefix + "/login", "ready_selector": "#ready", "login": form,
                "challenge_selectors": challenges, "login_resources": resources,
                "login_post_urls": [base + prefix + "/login"] + ([base + prefix + "/code"] if mfa else []),
                "operations": {"summary": {"description": "Read the synthetic demo balance", "url": base + prefix + "/summary",
                                           "fields": {"balance": "#balance", "currency": "#currency"}}}}
    return Configuration.model_validate({"test_mode": True, "accounts": {
        "demo-api": {"kind": "oauth", "label": "Controlled demo API", "authorization_url": base + "/oauth/authorize",
                     "token_url": base + "/oauth/token", "client_id": "controlled-demo-client", "scopes": ["read"],
                     "api_origins": [base], "operations": {
                         "summary": {"description": "Read the synthetic demo balance", "url": base + "/api/summary", "required_scopes": ["read"], "fields": ["balance", "currency", "environment"]},
                         "details": {"description": "Read additional synthetic demo data", "url": base + "/api/details", "required_scopes": ["read"], "fields": ["balance"]},
                     }},
        "demo-web": website("/web"), "demo-mfa": website("/mfa", mfa=True),
    }, "code_sources": {"demo-totp": {"kind": "totp"}}})


def connect_demo(broker, account="demo-api"):
    callback = "http://127.0.0.1:8766/callback/" + account
    url = broker.oauth.begin(account, callback)
    response = httpx.get(url, follow_redirects=False, trust_env=False)
    broker.oauth.finish(account, response.headers["Location"])


@contextmanager
def environment(root, *, install=False, public_sites=False):
    provider = DemoProvider().start()
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        store = Store(root, load_key(root, root / "demo.key", create=True))
        config = configuration(provider.base)
        if public_sites:
            from .public_demo import configuration as public_configuration
            external = public_configuration()
            for account in ["sauce-standard", "internet-valid"]:
                config.accounts[account] = external.accounts[account]
            store.put("credential:sauce-standard", {"username": "standard_user", "password": "secret_sauce"})
            store.put("credential:internet-valid", {"username": "tomsmith", "password": "SuperSecretPassword!"})
        store.configure(config)
        broker = Broker(store)
        connect_demo(broker)
        store.put("credential:demo-web", {"username": "demo@example.test", "password": DEMO_PASSWORD})
        store.put("credential:demo-mfa", {"username": "demo@example.test", "password": DEMO_PASSWORD})
        store.put("source:demo-totp", {"seed": DEMO_SEED})
        # New demo provider invalidates prior synthetic sessions; preserve historical encrypted task state.
        store.put("connection:demo-web", None)
        store.put("connection:demo-mfa", None)
        for account in ["demo-api", "demo-web", "demo-mfa"]:
            store.resolve_login(account)
        installations = []
        if install:
            from .install import install_skill
            for agent in ("codex", "claude", "generic"):
                installation = install_skill(store, agent, store.root / "portable-skills" if agent == "generic" else None)
                installations.append(installation)
                for account in store.config().accounts:
                    broker.grant(agent, account, list(store.config().accounts[account].operations))
        yield provider, broker, installations
    finally:
        provider.close()


def serve_demo(root: Path, *, install=False, public_sites=False):
    import uvicorn
    from .service import create_app
    with environment(root, install=install, public_sites=public_sites) as (_, broker, installations):
        print(json.dumps({"environment": "controlled-demo", "root": str(root),
                          "installations": installations,
                          "public_demo_sites": public_sites,
                          "message": "Demo identities only. Keep this process running while testing agents."}), flush=True)
        socket = root / "service.sock"
        with broker.store.lock("service", timeout=0):
            if socket.exists():
                socket.unlink()
            uvicorn.run(create_app(broker), uds=str(socket), access_log=False, log_level="critical")
