"""Owner-only native messaging session adoption. Never provides a password-vault read API."""

import json
import struct
import sys

from .errors import AccessError
from .models import BrowserAccount, origin

MAX_MESSAGE = 1_000_000


def handle(broker, message):
    if message.get("method") == "accounts":
        config = broker.store.config()
        return {"accounts": [{"account": name, "label": spec.label, "origin": origin(spec.login_url)}
                             for name, spec in config.accounts.items() if isinstance(spec, BrowserAccount)]}
    if message.get("method") != "import":
        raise AccessError("DENIED", "unsupported_native_message")
    account = message.get("account")
    config = broker.store.config()
    spec = config.accounts.get(account)
    if not isinstance(spec, BrowserAccount) or origin(message.get("url", "")) != origin(spec.login_url):
        raise AccessError("DENIED", "session_origin_mismatch")
    state = message.get("state", {})
    if len(json.dumps(state)) > MAX_MESSAGE:
        raise AccessError("DENIED", "session_state_too_large")
    with broker.store.lock("account:" + account):
        broker.browser.import_state(account, state)
    return {"status": "SESSION_IMPORTED", "account": account,
            "verification": "The next permitted operation verifies the session with the provider"}


def run_host(broker):
    allowed = broker.store.get("chrome-extension-origin")
    if not allowed or len(sys.argv) < 2 or sys.argv[-1] != allowed:
        # No stdout prose: this channel carries framed JSON and can contain credentials.
        return 2
    while True:
        header = sys.stdin.buffer.read(4)
        if not header:
            return 0
        if len(header) != 4:
            return 2
        length = struct.unpack("=I", header)[0]
        if length > MAX_MESSAGE:
            return 2
        raw = sys.stdin.buffer.read(length)
        if len(raw) != length:
            return 2
        try:
            result = handle(broker, json.loads(raw))
        except AccessError as exc:
            result = {"status": exc.status, "reason": exc.reason}
        except Exception:
            result = {"status": "DENIED", "reason": "invalid_native_message"}
        encoded = json.dumps(result).encode()
        sys.stdout.buffer.write(struct.pack("=I", len(encoded)) + encoded)
        sys.stdout.buffer.flush()
