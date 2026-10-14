"""Controlled verification provider for repeatable tests and clearly identified examples.

Email travels over real TLS IMAP. SMS uses a Messages-shaped test database or the
real HTTPS phone ingress. Neither channel represents delivery from a public carrier.
"""

import datetime
import os
import shlex
import socketserver
import sqlite3
import ssl
import threading
import time
from contextlib import contextmanager
from email.message import EmailMessage

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .broker import Broker
from .demo import DEMO_PASSWORD, DemoProvider, configuration
from .models import CodeSource, Configuration
from .storage import Store, load_key, private_file


class ExampleMailbox:
    def __init__(self, root):
        self.messages = []
        self.lock = threading.Lock()
        self.fetches = 0
        self.cert_path = root / "example-mail-certificate.pem"
        key_path = root / "example-mail-key.pem"
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Account Access test mailbox")])
        now = datetime.datetime.now(datetime.timezone.utc)
        import ipaddress
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .sign(key, hashes.SHA256()))
        private_file(self.cert_path, cert.public_bytes(serialization.Encoding.PEM), replace=self.cert_path.exists())
        private_file(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), replace=key_path.exists())
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def send(self, value):
                self.wfile.write(value.encode())
                self.wfile.flush()

            def handle(self):
                self.connection.settimeout(15)
                self.send("* OK Example TLS mailbox ready\r\n")
                authenticated = False
                while True:
                    line = self.rfile.readline(8192)
                    if not line:
                        return
                    parts = shlex.split(line.decode().strip())
                    tag, command = parts[0], parts[1].upper()
                    if command == "CAPABILITY":
                        self.send("* CAPABILITY IMAP4rev1\r\n" + tag + " OK CAPABILITY\r\n")
                    elif command == "LOGIN":
                        authenticated = parts[2:] == ["demo@example.test", DEMO_PASSWORD]
                        self.send(tag + (" OK LOGIN\r\n" if authenticated else " NO Invalid credentials\r\n"))
                    elif command == "LOGOUT":
                        self.send("* BYE Closing mailbox\r\n" + tag + " OK LOGOUT\r\n")
                        return
                    elif not authenticated:
                        self.send(tag + " NO Authenticate first\r\n")
                    elif command in {"EXAMINE", "SELECT"}:
                        self.send(f"* {len(owner.messages)} EXISTS\r\n* OK [UIDVALIDITY 1] Stable test mailbox\r\n* OK [UIDNEXT {len(owner.messages) + 1}] Next UID\r\n" + tag + " OK [READ-ONLY] EXAMINE\r\n")
                    elif command == "UID" and parts[2].upper() == "SEARCH":
                        with owner.lock:
                            ids = " ".join(str(i + 1) for i in range(len(owner.messages)))
                        self.send("* SEARCH " + ids + "\r\n" + tag + " OK SEARCH\r\n")
                    elif command == "UID" and parts[2].upper() == "FETCH":
                        with owner.lock:
                            value = owner.messages[int(parts[3]) - 1]
                        owner.fetches += 1
                        raw = value["raw"]
                        date = datetime.datetime.fromtimestamp(value["at"], datetime.timezone.utc).strftime('%d-%b-%Y %H:%M:%S +0000')
                        self.send(f'* 1 FETCH (UID {parts[3]} INTERNALDATE "{date}" BODY[] {{{len(raw)}}}\r\n')
                        self.wfile.write(raw)
                        self.send(")\r\n" + tag + " OK FETCH\r\n")
                    else:
                        self.send(tag + " OK Completed\r\n")

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_path, key_path)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def deliver(self, code):
        message = EmailMessage()
        message["From"] = "login@example.test"
        message["To"] = "demo@example.test"
        message["Subject"] = "Your example sign-in code"
        message.set_content("Example sign-in: " + code)
        with self.lock:
            self.messages.append({"raw": message.as_bytes(), "at": time.time()})

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def setup_config(base, mailbox, *, relay=False):
    config = configuration(base)
    web = config.accounts["demo-web"]
    for kind in ["email", "sms"]:
        spec = config.accounts["demo-mfa"].model_copy(deep=True)
        spec.label = "Example " + kind.upper() + " verification account"
        spec.login_url = base + "/" + kind + "/login"
        spec.login_resources = [base + "/" + kind + part for part in ["/login", "/code", "/summary"]]
        spec.login_post_urls = [base + "/" + kind + part for part in ["/login", "/code"]]
        spec.challenge_selectors = {"login": "#password-login", kind: "#" + kind + "-challenge", "action": "#action-challenge"}
        spec.login.code_source = "example-" + kind
        spec.operations["summary"].url = base + "/" + kind + "/summary"
        config.accounts["example-" + kind] = spec
    web.label = "Example password account"
    config.accounts["demo-mfa"].label = "Example authenticator account"
    config.accounts.pop("demo-api")
    config.code_sources["example-email"] = CodeSource(kind="imap", host="127.0.0.1", port=mailbox.port,
        sender="login@example.test", recipient="demo@example.test", subject="Your example sign-in code", template="Example sign-in: {code}")
    config.code_sources["example-sms"] = CodeSource(kind="phone_relay" if relay else "mac_messages", sender="Example", recipient="demo@example.test", template="Example sign-in: {code}")
    return Configuration.model_validate(config.model_dump())


@contextmanager
def environment(root, *, relay=False, secure_keyring=False):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    provider = DemoProvider().start()
    mailbox = ExampleMailbox(root)
    old_cert = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = str(mailbox.cert_path)
    path = root / "example-messages.db"
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE IF NOT EXISTS handle (id TEXT); CREATE TABLE IF NOT EXISTS message (guid TEXT, text TEXT, handle_id INTEGER, is_from_me INTEGER, date INTEGER);")
        if not db.execute("SELECT 1 FROM handle").fetchone():
            db.execute("INSERT INTO handle VALUES ('Example')")
    os.chmod(path, 0o600)
    store = Store(root, load_key(root, None if secure_keyring else root / "demo.key", create=True))
    store.configure(setup_config(provider.base, mailbox, relay=relay))
    broker = Broker(store)
    if not relay:
        broker.codes.messages = lambda source_id, source, started, used: broker.codes.messages_at(path, source, started, used)
    def deliver(kind, code):
        if kind == "email":
            mailbox.deliver(code)
        elif not relay:
            with sqlite3.connect(path) as db:
                db.execute("INSERT INTO message VALUES (?,?,?,?,?)", (str(time.time_ns()), "Example sign-in: " + code, 1, 0, int((time.time() - 978307200) * 1_000_000_000)))
    provider.delivery = deliver
    try:
        yield provider, broker, mailbox
    finally:
        mailbox.close()
        provider.close()
        if old_cert is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = old_cert


def write_password_export(root, config):
    import csv
    path = root / "example-password-export.csv"
    with path.open("w") as output:
        writer = csv.writer(output)
        writer.writerow(["name", "url", "username", "password"])
        for account, spec in config.accounts.items():
            writer.writerow([account, spec.login_url, "demo@example.test", DEMO_PASSWORD])
    os.chmod(path, 0o600)
    return path


def serve(root):
    from .desktop import host
    with environment(root) as (_, broker, _):
        export = write_password_export(root, broker.store.config())
        print("Controlled verification examples only. Password export: " + str(export), flush=True)
        print("Use the graphical app with ACCOUNT_ACCESS_DATA_DIR set to this example root.", flush=True)
        host(broker)
