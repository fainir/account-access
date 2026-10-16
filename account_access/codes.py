"""Purpose-specific code resolvers. No raw inbox or code retrieval API is exposed to agents."""

import base64
import email
import email.policy
import imaplib
import re
import sqlite3
import ssl
import subprocess
import sys
import json
import hashlib
import hmac
import secrets
import time
from pathlib import Path
from contextlib import contextmanager
from email.utils import parseaddr, parsedate_to_datetime

import pyotp

from .errors import AccessError
from .providers import get_json


def match_code(template, message):
    pattern = re.escape(template).replace(re.escape("{code}"), r"([0-9]{6})")
    match = re.fullmatch(pattern, message.strip())
    return match[1] if match else None


def unique_code(candidates):
    # Two matching messages may correspond to two different logins. Do not choose the newest blindly.
    if len(candidates) > 1:
        raise AccessError("NEEDS_USER", "ambiguous_login_code")
    return candidates[0] if candidates else None


class Codes:
    def __init__(self, store, oauth):
        self.store = store
        self.oauth = oauth

    def check_window(self, source_id, started):
        """Recheck after delivery as well as before it; network calls can block."""
        config = self.store.config()
        source = config.code_sources.get(source_id)
        if time.time() - started > 120 or started > time.time():
            raise AccessError("NEEDS_USER", "login_code_window_expired")
        window = self.store.get("code-window:" + source_id)
        if not window or window["started"] != started or window["expires"] < time.time():
            raise AccessError("DENIED", "login_code_window_missing")
        if source is None or window.get("source_config") != source.model_dump():
            raise AccessError("DENIED", "login_code_source_changed")
        credentials = self.store.get("source:" + source_id, {}) or {}
        if credentials.get("enabled") is False:
            raise AccessError("NEEDS_USER", "verification_source_disabled")
        current = hashlib.sha256(json.dumps(credentials, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if window.get("source_enrollment") != current:
            raise AccessError("DENIED", "verification_source_enrollment_changed")
        return source, window, credentials

    def resolve(self, source_id, started, used):
        source, window, credentials = self.check_window(source_id, started)
        config = self.store.config()
        if source.kind == "totp":
            if not credentials.get("seed"):
                raise AccessError("NEEDS_USER", "authenticator_not_enrolled", "totp")
            try:
                return pyotp.TOTP(credentials["seed"]).now()
            except Exception:
                raise AccessError("NEEDS_USER", "invalid_authenticator_seed", "totp") from None
        if source.kind == "gmail":
            with self.store.lock("account:" + source.account):
                token = self.oauth.token(source.account, config)
                if "https://www.googleapis.com/auth/gmail.readonly" not in token["scope"].split():
                    raise AccessError("NEEDS_USER", "mailbox_scope_missing", "email")
                headers = {"Authorization": "Bearer " + token["access_token"]}
                base = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
                listing = get_json(base, headers=headers, params={
                    "q": f"from:{source.sender} to:{source.recipient} after:{int(started) - 1}",
                    "maxResults": 10,
                })
                candidates = []
                for item in listing.get("messages", []):
                    ident = item.get("id", "")
                    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", ident) or ident in used:
                        continue
                    message = get_json(base + "/" + ident, headers=headers, params={"format": "full"})
                    if float(message.get("internalDate", 0)) / 1000 < started:
                        continue
                    payload = message.get("payload", {})
                    meta = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
                    if (parseaddr(meta.get("from", ""))[1].lower() != source.sender.lower()
                        or parseaddr(meta.get("to", ""))[1].lower() != source.recipient.lower()
                        or meta.get("subject") != source.subject):
                        continue
                    body = self.plaintext(payload)
                    code = match_code(source.template, body)
                    if code:
                        candidates.append((ident, code))
                candidate = unique_code(candidates)
                if candidate:
                    used.add(candidate[0])
                    return candidate[1]
                return None
        if source.kind == "imap":
            return self.imap(source_id, source, credentials, started, used, config)
        if source.kind == "mac_messages":
            if credentials.get("enabled") is not True:
                raise AccessError("NEEDS_USER", "message_permission_required", "sms")
            return self.messages(source_id, source, started, used)
        if source.kind in {"phone_relay", "google_messages"}:
            with self.store.lock("code-window:" + source_id):
                window = self.store.get("code-window:" + source_id)
                if not window or window["started"] != started or window["expires"] < time.time():
                    return None
                if window.get("lost"):
                    raise AccessError("RETRYABLE", "google_messages_tab_reloaded", "sms")
                incoming = window.get("incoming", [])
                if len(incoming) > 1:
                    raise AccessError("NEEDS_USER", "ambiguous_login_code", "sms")
                if incoming:
                    code = incoming[0]["code"]
                    window["incoming"] = []
                    window["consumed"] = True
                    self.store.put("code-window:" + source_id, window)
                    return code
                return None
        if not credentials.get("sid") or not credentials.get("auth_token"):
            raise AccessError("NEEDS_USER", "sms_gateway_not_connected", "sms")
        sid = credentials["sid"]
        if not re.fullmatch(r"AC[0-9a-fA-F]{32}", sid):
            raise AccessError("NEEDS_USER", "invalid_sms_gateway", "sms")
        data = get_json(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                        auth=(sid, credentials["auth_token"]),
                        params={"To": source.recipient, "From": source.sender, "PageSize": 20})
        candidates = []
        for item in data.get("messages", []):
            if (item.get("sid") in used or item.get("direction") != "inbound"
                or item.get("from") != source.sender or item.get("to") != source.recipient):
                continue
            try:
                sent = parsedate_to_datetime(item["date_sent"]).timestamp()
            except Exception:
                continue
            if sent < started:
                continue
            code = match_code(source.template, item.get("body", ""))
            if code:
                candidates.append((item["sid"], code))
        candidate = unique_code(candidates)
        if candidate:
            used.add(candidate[0])
            return candidate[1]
        return None

    def begin(self, source_id, account, started):
        window = {"account": account, "started": started,
                  "expires": started + 120, "incoming": [], "consumed": False}
        config = self.store.config()
        source = config.code_sources[source_id]
        window["source_config"] = source.model_dump()
        credentials = self.store.get("source:" + source_id, {}) or {}
        window["source_enrollment"] = hashlib.sha256(
            json.dumps(credentials, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if source.kind == "imap":
            try:
                with self.mailbox(source, self.store.get("source:" + source_id, {}), config) as mailbox:
                    for name in ["UIDVALIDITY", "UIDNEXT"]:
                        values = mailbox.response(name)[1]
                        if not values or not values[0] or not values[0].isdigit():
                            raise AccessError("NEEDS_USER", "mailbox_uid_tracking_unavailable", "email")
                        window[name] = int(values[0])
            except (imaplib.IMAP4.error, OSError):
                raise AccessError("NEEDS_USER", "mailbox_connection_failed", "email") from None
        if source.kind == "mac_messages":
            credentials = self.store.get("source:" + source_id, {}) or {}
            if credentials.get("enabled") is not True:
                raise AccessError("NEEDS_USER", "message_permission_required", "sms")
            window["after_row"] = self.messages_baseline(source_id, source, started)
        if source.kind == "google_messages":
            if credentials.get("enabled") is not True:
                raise AccessError("NEEDS_USER", "google_messages_not_connected", "sms")
            window["google_window"] = secrets.token_hex(16)
        self.store.put("code-window:" + source_id, window)
        if source.kind == "google_messages":
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                _, current, _ = self.check_window(source_id, started)
                if current.get("armed"):
                    return
                time.sleep(.1)
            self.finish(source_id, started)
            raise AccessError("RETRYABLE", "google_messages_tab_unavailable", "sms")

    def finish(self, source_id, started):
        with self.store.lock("code-window:" + source_id):
            window = self.store.get("code-window:" + source_id)
            if window and window["started"] == started:
                self.store.put("code-window:" + source_id, None)

    @contextmanager
    def mailbox(self, source, credentials, config):
        if not credentials.get("username") or (not source.account and not credentials.get("password")):
            raise AccessError("NEEDS_USER", "mailbox_not_connected", "email")
        with imaplib.IMAP4_SSL(source.host, source.port,
                              ssl_context=ssl.create_default_context(), timeout=10) as mailbox:
            if source.account:
                with self.store.lock("account:" + source.account):
                    token = self.oauth.token(source.account, config)
                auth = ("user=" + credentials["username"] + "\x01auth=Bearer "
                        + token["access_token"] + "\x01\x01").encode()
                mailbox.authenticate("XOAUTH2", lambda _: auth)
            else:
                mailbox.login(credentials["username"], credentials["password"])
            status, _ = mailbox.select("INBOX", readonly=True)
            if status != "OK":
                raise AccessError("NEEDS_USER", "mailbox_not_available", "email")
            yield mailbox

    def imap(self, source_id, source, credentials, started, used, config):
        window = self.store.get("code-window:" + source_id)
        if not window or window["started"] != started or "UIDNEXT" not in window:
            raise AccessError("NEEDS_USER", "mailbox_login_window_missing", "email")
        try:
            with self.mailbox(source, credentials, config) as mailbox:
                values = mailbox.response("UIDVALIDITY")[1]
                if not values or not values[0] or int(values[0]) != window["UIDVALIDITY"]:
                    raise AccessError("NEEDS_USER", "mailbox_uid_validity_changed", "email")
                # Search values are owner-authored, but still quote IMAP metacharacters.
                def quote(s):
                    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
                if any("\r" in x or "\n" in x for x in [source.sender, source.recipient, source.subject]):
                    raise AccessError("NEEDS_USER", "invalid_mail_filter", "email")
                status, data = mailbox.uid("SEARCH", None, "FROM", quote(source.sender),
                                           "TO", quote(source.recipient), "SUBJECT", quote(source.subject))
                if status != "OK":
                    raise AccessError("RETRYABLE", "mailbox_search_failed")
                ids = data[0].split() if data and data[0] else []
                candidates = []
                for ident in ids[-20:]:
                    key = ident.decode("ascii")
                    if not key.isdigit() or int(key) < window["UIDNEXT"] or key in used:
                        continue
                    status, fetched = mailbox.uid("FETCH", ident, "(INTERNALDATE BODY.PEEK[]<0.256000>)")
                    if status != "OK":
                        continue
                    for item in fetched or []:
                        if not isinstance(item, tuple) or len(item[1]) > 256_000:
                            continue
                        received = imaplib.Internaldate2tuple(item[0])
                        if not received or time.mktime(received) < int(started) or time.time() > window["expires"]:
                            continue
                        message = email.message_from_bytes(item[1], policy=email.policy.default)
                        if (parseaddr(str(message.get("From", "")))[1].lower() != source.sender.lower()
                                or parseaddr(str(message.get("To", "")))[1].lower() != source.recipient.lower()
                                or str(message.get("Subject", "")) != source.subject):
                            continue
                        part = message.get_body(preferencelist=("plain",))
                        body = part.get_content() if part else ""
                        code = match_code(source.template, body)
                        if code:
                            candidates.append((key, code))
                candidate = unique_code(candidates)
                if candidate:
                    used.add(candidate[0])
                    return candidate[1]
                return None
        except (imaplib.IMAP4.error, OSError, ssl.SSLError):
            raise AccessError("NEEDS_USER", "mailbox_connection_failed", "email") from None

    def native_messages(self, source_id, source, started, **fields):
        """Authenticated transport to the signed app; never exposed to agents."""
        binary = Path.home() / "Applications/Account Access.app/Contents/MacOS/AccountAccess"
        if sys.platform != "darwin" or not binary.is_file() or binary.is_symlink():
            raise AccessError("NEEDS_USER", "mac_messages_app_required", "sms")
        try:
            from .storage import check_private
            key_path = self.store.root / "native-reader.key"
            check_private(key_path)
            key = key_path.read_bytes()
            if len(key) != 32:
                raise AccessError("NEEDS_USER", "mac_messages_app_required", "sms")
            request = json.dumps({"source": source_id, "sender": source.sender,
                                 "template": source.template, "started": started,
                                 "nonce": secrets.token_hex(16), **fields}, separators=(",", ":"))
            signature = hmac.new(key, request.encode(), hashlib.sha256).hexdigest()
            checked = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binary)],
                                     capture_output=True, timeout=3)
            if checked.returncode:
                raise AccessError("NEEDS_USER", "mac_messages_app_required", "sms")
            result = subprocess.run([str(binary), "--read-login-code"], input=json.dumps({
                "request": request, "signature": signature}),
                text=True, capture_output=True, timeout=5, check=True)
            payload = json.loads(result.stdout)
        except (ValueError, OSError, subprocess.SubprocessError):
            raise AccessError("NEEDS_USER", "mac_messages_permission_required", "sms") from None
        if not isinstance(payload, dict):
            raise AccessError("NEEDS_USER", "invalid_message_reader_response", "sms")
        return payload

    def messages_baseline(self, source_id, source, started):
        payload = self.native_messages(source_id, source, started, action="begin")
        baseline = payload.get("after_row")
        if (payload.get("status") != "READY" or type(baseline) is not int
                or not 0 <= baseline <= 2**63 - 1):
            raise AccessError("NEEDS_USER", "mac_messages_permission_required", "sms")
        return baseline

    def messages(self, source_id, source, started, used):
        """Read only new incoming texts from the exact owner-reviewed sender."""
        window = self.store.get("code-window:" + source_id) or {}
        baseline = window.get("after_row")
        if window.get("started") != started or type(baseline) is not int or baseline < 0:
            raise AccessError("DENIED", "message_login_window_missing", "sms")
        payload = self.native_messages(source_id, source, started, action="read",
                                       after_row=baseline, used=list(used))
        if payload.get("status") == "FOUND":
            code, ident = payload.get("code", ""), payload.get("id", "")
            if not re.fullmatch(r"[0-9]{6}", code) or not isinstance(ident, str) or ident in used:
                raise AccessError("NEEDS_USER", "invalid_message_reader_response", "sms")
            used.add(ident)
            return code
        if payload.get("status") == "WAITING":
            return None
        reason = "ambiguous_login_code" if payload.get("reason") == "ambiguous_login_code" else "mac_messages_permission_required"
        raise AccessError("NEEDS_USER", reason, "sms")

    def messages_at(self, path, source, started, used, *, after_row=None):
        # Fictional Messages database adapter used by the end-to-end fixtures.
        since = (started - (5 if after_row is not None else 0) - 978307200) * 1_000_000_000
        try:
            with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2) as db:
                rows = db.execute("SELECT message.guid, message.text FROM message "
                                  "JOIN handle ON handle.ROWID=message.handle_id "
                                  "WHERE message.is_from_me=0 AND handle.id=? AND message.date>=? "
                                  + ("AND message.ROWID>? " if after_row is not None else "")
                                  + "ORDER BY message.date DESC LIMIT 20",
                                  (source.sender, since, after_row) if after_row is not None else (source.sender, since)).fetchall()
        except (sqlite3.Error, OSError):
            raise AccessError("NEEDS_USER", "mac_messages_permission_required", "sms") from None
        candidates = [(ident, match_code(source.template, body)) for ident, body in rows
                      if ident not in used and isinstance(body, str)]
        candidate = unique_code([(ident, code) for ident, code in candidates if code])
        if candidate:
            used.add(candidate[0])
            return candidate[1]
        return None

    def plaintext(self, payload, depth=0):
        if depth > 6:
            return ""
        if payload.get("mimeType") == "text/plain":
            value = payload.get("body", {}).get("data", "")
            try:
                return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
            except Exception:
                return ""
        return "\n".join(self.plaintext(p, depth + 1) for p in payload.get("parts", [])[:20])
