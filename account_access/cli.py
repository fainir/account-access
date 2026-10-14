"""User setup and a stable, JSON-only agent CLI."""

import argparse
import getpass
import json
import os
import secrets
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import quote

from pydantic import ValidationError

from .client import Client
from .errors import AccessError
from .models import Configuration, OAuthAccount, TaskRequest


def default_root():
    canonical = Path.home() / ".local/share/account-access"
    legacy = Path.home() / "Library/Application Support/AccountAccess"
    if sys.platform == "darwin" and not (canonical / "config.json").exists() and (legacy / "config.json").exists():
        return legacy
    return canonical


def print_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def owner_store(args, create=False):
    from .storage import Store, load_key
    root = Path(args.root).expanduser()
    key_file = Path(args.key_file).expanduser() if args.key_file else None
    if key_file and not args.development:
        raise AccessError("DENIED", "file_key_requires_development_mode")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return Store(root, load_key(root, key_file, create=create))


def steps(text):
    return [{"account": part.split(":", 1)[0], "operation": part.split(":", 1)[1]}
            for part in text.split(",") if ":" in part]


def connect_oauth(broker, account):
    outcome = {"complete": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Callback URLs contain authorization codes; never log them.

        def do_GET(self):
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                self.send_error(400)
                return
            try:
                callback = f"http://127.0.0.1:{self.server.server_port}" + self.path
                broker.oauth.finish(account, callback)
                outcome["complete"] = True
                body = b"Connected. You can close this page; pending tasks will resume."
                self.send_response(200)
            except AccessError:
                body = b"Connection was not completed. Restart the connection from your owner app."
                self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        server.timeout = 1
        callback = f"http://127.0.0.1:{server.server_port}/callback/{account}"
        url = broker.oauth.begin(account, callback)
        if not webbrowser.open(url):
            raise AccessError("NEEDS_USER", "system_browser_unavailable")
        print("Complete the account connection in your browser.", file=sys.stderr)
        deadline = time.monotonic() + 300
        while not outcome["complete"] and time.monotonic() < deadline:
            server.handle_request()
        if not outcome["complete"]:
            raise AccessError("NEEDS_USER", "connection_timed_out")


def parser():
    p = argparse.ArgumentParser(description="Account Access: a portable agent client and private service")
    p.add_argument("--root", default=str(default_root()), help="Owner service data directory")
    p.add_argument("--key-file", help="Development only; production uses the OS keyring")
    p.add_argument("--development", action="store_true", help="Explicitly allow development file-key custody")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("accounts")
    sub.add_parser("doctor")
    sub.add_parser("audit")
    status = sub.add_parser("status")
    status.add_argument("account")
    status.add_argument("operation")
    run = sub.add_parser("run")
    run.add_argument("account")
    run.add_argument("operation")
    task = sub.add_parser("task").add_subparsers(dest="action", required=True)
    submit = task.add_parser("submit")
    submit.add_argument("--key", required=True)
    submit.add_argument("--steps", required=True, help="Comma-separated ACCOUNT:OPERATION steps")
    wait = task.add_parser("wait", help="Wait for a task to finish or require owner action")
    wait.add_argument("id")
    wait.add_argument("--timeout", type=int, default=60, help="Polling window, 1 to 120 seconds")
    task.add_parser("get").add_argument("id")
    init = sub.add_parser("init")
    init.add_argument("--config", required=True)
    configure = sub.add_parser("configure")
    configure.add_argument("--config", required=True)
    sub.add_parser("serve")
    sub.add_parser("setup")
    start = sub.add_parser("start", help="Open guided setup and run the local service in the background")
    start.add_argument("--no-open", action="store_true", help=argparse.SUPPRESS)
    start.add_argument("--on-demand", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("stop", help="Stop the guided local app while preserving saved connections")
    sub.add_parser("desktop-host", help=argparse.SUPPRESS)
    sub.add_parser("metrics")
    sub.add_parser("challenges")
    sub.add_parser("grants")
    connect = sub.add_parser("connect")
    connect.add_argument("account")
    credential = sub.add_parser("credential")
    credential.add_argument("account")
    source = sub.add_parser("enroll-source")
    source.add_argument("source")
    grant = sub.add_parser("grant")
    grant.add_argument("principal")
    grant.add_argument("account")
    grant.add_argument("operations", nargs="+")
    grant.add_argument("--days", type=int)
    revoke = sub.add_parser("revoke")
    revoke.add_argument("--account")
    revoke.add_argument("--principal")
    install = sub.add_parser("install")
    install.add_argument("--agent", choices=["auto", "codex", "claude", "generic"], default="auto")
    install.add_argument("--skills-dir", help="Custom destination for another skills-compatible agent")
    schedule = sub.add_parser("schedule")
    schedule.add_argument("principal")
    schedule.add_argument("--steps", required=True)
    schedule.add_argument("--interval", type=int, required=True)
    sub.add_parser("schedules")
    disable = sub.add_parser("disable-schedule")
    disable.add_argument("id")
    session = sub.add_parser("import-session")
    session.add_argument("account")
    session.add_argument("--file", required=True)
    demo = sub.add_parser("demo")
    demo.add_argument("--install", action="store_true", help="Install test-only skill connections into Codex and Claude Code")
    demo.add_argument("--public-sites", action="store_true", help="Also enroll published SauceDemo and The Internet demo identities")
    demo.add_argument("--verification", action="store_true", help="Empty guided examples with real TLS IMAP and a Messages-format SMS fixture")
    return p


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    try:
        if args.command in {"accounts", "doctor", "audit", "status", "run", "task"}:
            client = Client()
            if args.command in {"accounts", "doctor"}:
                result = client.request("GET", "/v1/accounts")
                if args.command == "doctor" and result.get("status") == "OK":
                    result["service_reachable"] = True
            elif args.command == "audit":
                result = client.request("GET", "/v1/audit")
            elif args.command == "status":
                result = client.request("GET", f"/v1/status/{quote(args.account, safe='')}/{quote(args.operation, safe='')}")
            elif args.command == "run":
                result = client.request("POST", "/v1/run", {"account": args.account, "operation": args.operation})
            elif args.action == "submit":
                request = TaskRequest.model_validate({"key": args.key, "steps": steps(args.steps)})
                result = client.request("POST", "/v1/tasks", request.model_dump())
            else:
                result = client.request("GET", "/v1/tasks/" + quote(args.id, safe=""))
                if args.action == "wait":
                    if not 1 <= args.timeout <= 120:
                        raise AccessError("DENIED", "invalid_wait_timeout")
                    deadline = time.monotonic() + args.timeout
                    while result.get("status") in {"QUEUED", "RUNNING", "RETRYABLE"} and time.monotonic() < deadline:
                        time.sleep(min(1, max(0, deadline - time.monotonic())))
                        result = client.request("GET", "/v1/tasks/" + quote(args.id, safe=""))
                    if result.get("status") in {"QUEUED", "RUNNING", "RETRYABLE"}:
                        result["wait_timed_out"] = True
            print_json(result)
            return 0 if result.get("status") not in {"DENIED", "RETRYABLE", "NEEDS_USER"} else 2
        if args.command == "demo":
            if args.verification:
                if args.install or args.public_sites:
                    raise AccessError("DENIED", "verification_demo_requires_owner_enrollment")
                from .verification_demo import serve
                serve(Path(args.root))
                return 0
            from .demo import serve_demo
            serve_demo(Path(args.root), install=args.install, public_sites=args.public_sites)
            return 0
        if args.command == "start":
            from .desktop import launch
            if args.key_file and not args.development:
                raise AccessError("DENIED", "file_key_requires_development_mode")
            launch(Path(args.root), key_file=Path(args.key_file).expanduser() if args.key_file else None,
                   open_browser=not args.no_open, on_demand=args.on_demand)
            return 0
        if args.command == "stop":
            from .desktop import stop
            stop(Path(args.root))
            return 0
        from .broker import Broker
        store = owner_store(args, create=args.command == "init")
        broker = Broker(store)
        if args.command == "desktop-host":
            from .desktop import host
            host(broker)
            return 0
        if args.command in {"init", "configure"}:
            configuration = Configuration.model_validate_json(Path(args.config).read_bytes())
            if configuration.test_mode and not args.development:
                raise AccessError("DENIED", "test_configuration_requires_development_mode")
            store.configure(configuration)
            print_json({"status": "OK", "configured_accounts": list(configuration.accounts)})
        elif args.command == "serve":
            import uvicorn
            from .service import create_app
            socket = store.root / "service.sock"
            if len(str(socket).encode()) >= 104:
                raise AccessError("DENIED", "socket_path_too_long")
            with store.lock("service", timeout=0):
                if socket.exists():
                    socket.unlink()
                uvicorn.run(create_app(broker), uds=str(socket), access_log=False, log_level="critical")
        elif args.command == "setup":
            from .owner import open_owner
            open_owner(broker)
        elif args.command == "connect":
            config = store.config().accounts[args.account]
            if isinstance(config, OAuthAccount):
                connect_oauth(broker, args.account)
            else:
                broker.browser.connect(args.account)
            broker.tick()
            print_json({"status": "CONNECTED", "account": args.account})
        elif args.command == "credential":
            config = store.config().accounts[args.account]
            if isinstance(config, OAuthAccount):
                value = {"client_secret": getpass.getpass("OAuth application secret: ")}
            else:
                value = {"username": input("Email or username: "), "password": getpass.getpass("Password: ")}
            store.put("credential:" + args.account, value)
            print_json({"status": "OK", "account": args.account})
        elif args.command == "enroll-source":
            source = store.config().code_sources[args.source]
            if source.kind == "totp":
                import pyotp
                seed = getpass.getpass("Explicitly enrolled login-only authenticator seed: ").replace(" ", "")
                pyotp.TOTP(seed).now()
                value = {"seed": seed}
            elif source.kind == "twilio":
                value = {"sid": input("Twilio account SID: "), "auth_token": getpass.getpass("Twilio auth token: ")}
            else:
                print_json({"status": "NEEDS_USER", "reason": "connect_mailbox_oauth", "account": source.account})
                return 2
            store.put("source:" + args.source, value)
            print_json({"status": "OK", "source": args.source})
        elif args.command == "grant":
            expires = time.time() + args.days * 86400 if args.days else None
            broker.grant(args.principal, args.account, args.operations, expires)
            print_json({"status": "OK", "principal": args.principal, "account": args.account})
        elif args.command == "revoke":
            if not args.account and not args.principal:
                raise AccessError("DENIED", "revoke_target_required")
            broker.revoke(args.account, args.principal)
            print_json({"status": "REVOKED", "provider_revocation": "Separate provider settings may also require revocation"})
        elif args.command == "install":
            from .install import install_detected, install_skill
            if args.agent == "auto":
                if args.skills_dir:
                    raise AccessError("DENIED", "custom_directory_requires_generic")
                print_json(install_detected(store))
            else:
                print_json({"status": "INSTALLED", **install_skill(store, args.agent, args.skills_dir)})
        elif args.command in {"grants", "challenges", "schedules"}:
            with store.db() as db:
                table = {"grants": "grants", "challenges": "challenges", "schedules": "schedules"}[args.command]
                print_json({"status": "OK", args.command: [dict(r) for r in db.execute("SELECT * FROM " + table)]})
        elif args.command == "metrics":
            print_json(broker.metrics())
        elif args.command == "schedule":
            if args.interval < 60:
                raise AccessError("DENIED", "schedule_interval_too_short")
            request = TaskRequest.model_validate({"key": "schedule-check", "steps": steps(args.steps)})
            for step in request.steps:
                broker.permit(args.principal, step.account, step.operation)
            ident = secrets.token_hex(12)
            with store.db() as db:
                store.put("schedule:" + ident, {"steps": [s.model_dump() for s in request.steps]}, db=db)
                db.execute("INSERT INTO schedules VALUES (?,?,?,?,1)",
                           (ident, args.principal, args.interval, time.time()))
            print_json({"status": "SCHEDULED", "schedule_id": ident})
        elif args.command == "disable-schedule":
            with store.db() as db:
                db.execute("UPDATE schedules SET enabled=0 WHERE id=?", (args.id,))
            print_json({"status": "DISABLED"})
        elif args.command == "import-session":
            from .storage import check_private
            path = Path(args.file)
            check_private(path)
            with store.lock("account:" + args.account):
                broker.browser.import_state(args.account, json.loads(path.read_text()))
            broker.tick()
            print_json({"status": "CONNECTED", "account": args.account})
        return 0
    except AccessError as exc:
        print_json({"status": exc.status, "reason": exc.reason})
        return 2
    except (ValidationError, ValueError, KeyError, FileNotFoundError):
        print_json({"status": "NEEDS_USER", "reason": "invalid_or_missing_configuration"})
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception:
        print_json({"status": "RETRYABLE", "reason": "internal_error"})
        return 2


if __name__ == "__main__":
    sys.exit(main())
