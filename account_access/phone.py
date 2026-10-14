"""Optional LAN HTTPS ingress for a paired Android phone; accepts login messages only."""

import datetime
import hashlib
import ipaddress
import json
import secrets
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .codes import match_code
from .errors import AccessError
from .storage import check_private, private_file


def deliver(store, source_id, data):
    source = store.config().code_sources.get(source_id)
    if not source or source.kind != "phone_relay":
        raise AccessError("DENIED", "unknown_phone_source")
    if (not isinstance(data, dict) or set(data) != {"id", "sender", "recipient", "body", "received_at"}
            or any(not isinstance(data[x], str) or len(data[x]) > 2048
                   for x in ["id", "sender", "recipient", "body"])
            or not data["id"] or not isinstance(data["received_at"], (int, float))):
        raise AccessError("DENIED", "invalid_phone_message")
    if data["sender"] != source.sender or data["recipient"] != source.recipient:
        raise AccessError("DENIED", "phone_message_mismatch")
    code = match_code(source.template, data["body"])
    if not code:
        raise AccessError("DENIED", "phone_message_mismatch")
    with store.lock("code-window:" + source_id):
        window = store.get("code-window:" + source_id)
        if (not window or window["expires"] < time.time() or window["consumed"]
                or not window["started"] <= data["received_at"] <= time.time() + 5):
            raise AccessError("DENIED", "no_current_login_window")
        seen = window.setdefault("seen", [])
        if data["id"] in seen:
            return {"status": "RECEIVED"}
        if len(seen) >= 8:
            raise AccessError("DENIED", "phone_message_limit")
        seen.append(data["id"])
        window["incoming"].append({"code": code})
        store.put("code-window:" + source_id, window)
    return {"status": "RECEIVED"}


class PhoneRelay:
    def __init__(self, store):
        self.store = store
        self.server = None
        self.thread = None
        self.guard = threading.Lock()
        self.requests = {}

    def pair(self, source_id):
        source = self.store.config().code_sources.get(source_id)
        if not source or source.kind != "phone_relay":
            raise AccessError("DENIED", "unknown_phone_source")
        with self.guard:
            if not self.server:
                self.start()
            token = secrets.token_urlsafe(32)
            self.store.put("phone-pair:" + source_id, {"token": token})
            self.store.put("source:" + source_id, {"enabled": True})
            return {"status": "PAIRING", "version": 1, "source": source_id,
                    "url": f"https://{self.ip}:{self.server.server_port}/v1/login-code/{source_id}",
                    "token": token, "certificate_sha256": self.fingerprint,
                    "sender": source.sender, "recipient": source.recipient,
                    "template": source.template}

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as discovery:
            discovery.connect(("192.0.2.1", 9))
            self.ip = discovery.getsockname()[0]
        address = ipaddress.ip_address(self.ip)
        if not address.is_private or address.is_loopback:
            raise AccessError("NEEDS_USER", "private_wifi_required", "sms")
        folder = self.store.root / "phone"
        folder.mkdir(mode=0o700, exist_ok=True)
        check_private(folder)
        pem, private = folder / "certificate.pem", folder / "private.pem"
        saved = self.store.get("phone-listener")
        reuse = False
        if saved and saved["ip"] == self.ip and pem.is_file() and private.is_file():
            check_private(pem)
            check_private(private)
            existing = x509.load_pem_x509_certificate(pem.read_bytes())
            reuse = existing.not_valid_after_utc > datetime.datetime.now(datetime.timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Account Access phone link")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(address)]), critical=False)
                .sign(key, hashes.SHA256()))
        if reuse:
            cert = existing
        else:
            private_file(pem, cert.public_bytes(serialization.Encoding.PEM), replace=pem.exists())
            private_file(private, key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), replace=private.exists())
        self.fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.connection.settimeout(5)
                response = {"status": "DENIED"}
                status = 403
                try:
                    if not self.path.startswith("/v1/login-code/"):
                        raise ValueError()
                    ident = self.path.removeprefix("/v1/login-code/")
                    pair = owner.store.get("phone-pair:" + ident) or {}
                    expected = pair.get("token", "")
                    presented = self.headers.get("Authorization", "").removeprefix("Bearer ")
                    if not expected or not secrets.compare_digest(expected, presented):
                        raise ValueError()
                    with owner.guard:
                        times = [t for t in owner.requests.get(ident, []) if t > time.time() - 60]
                        if len(times) >= 32:
                            raise ValueError()
                        owner.requests[ident] = times + [time.time()]
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 4096:
                        raise ValueError()
                    response = deliver(owner.store, ident, json.loads(self.rfile.read(length)))
                    status = 200
                except (ValueError, AccessError, OSError):
                    pass
                raw = json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(raw)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(pem, private)
        self.server = ThreadingHTTPServer((self.ip, saved["port"] if reuse else 0), Handler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.store.put("phone-listener", {"ip": self.ip, "port": self.server.server_port,
                       "fingerprint": self.fingerprint})

    def restore(self):
        if self.store.get("phone-listener"):
            with self.guard:
                self.start()

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
