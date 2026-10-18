"""Purpose-specific code resolvers. No raw inbox or code retrieval API is exposed to agents."""

import base64
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
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from email.utils import parsedate_to_datetime

import pyotp

from .errors import AccessError
from .email_codes import MAX_MESSAGE_BYTES, login_code as email_login_code
from .factors import source_mutation
from .mailboxes import enrollment
from .providers import get_json

GMAIL_MESSAGES = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_ID = re.compile(r"[a-zA-Z0-9_-]{1,100}")


def imap_number(values):
    """A mailbox UID/validity response is one non-zero unsigned 32-bit value."""
    if (not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], bytes)
            or not re.fullmatch(rb"[1-9][0-9]{0,9}", values[0])
            or int(values[0]) > 2**32 - 1):
        raise AccessError("NEEDS_USER", "mailbox_uid_tracking_unavailable", "email")
    return int(values[0])


def mailbox_error(error):
    if isinstance(error, ssl.SSLCertVerificationError):
        return AccessError("NEEDS_USER", "mailbox_tls_verification_failed", "email")
    if isinstance(error, (imaplib.IMAP4.abort, OSError)):
        return AccessError("RETRYABLE", "mailbox_temporarily_unavailable", "email")
    return AccessError("NEEDS_USER", "mailbox_connection_failed", "email")


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
        self.native_transport = None

    @staticmethod
    def mailbox_account(source):
        return source.account if source and source.kind in {"imap", "gmail"} else None

    def check_window(self, source_id, started, *, mailbox_locked=None):
        """Recheck after delivery as well as before it; network calls can block."""
        if time.time() - started > 120 or started > time.time():
            raise AccessError("NEEDS_USER", "login_code_window_expired")
        source = self.store.config().code_sources.get(source_id)
        account = self.mailbox_account(source)
        if mailbox_locked is not None and mailbox_locked != account:
            raise AccessError("DENIED", "login_code_source_changed")
        if account and mailbox_locked is None:
            # Refresh/owner authorization can hold this lock for network I/O.
            # Read the live window only after waiting; revocation and finish
            # can clear it while we wait. No source/window lock is taken here.
            with self.store.lock("account:" + account):
                return self.check_window(source_id, started, mailbox_locked=account)
        window = self.store.get("code-window:" + source_id)
        if not window or window["started"] != started or window["expires"] < time.time():
            raise AccessError("DENIED", "login_code_window_missing")
        if source is None or window.get("source_config") != source.model_dump():
            raise AccessError("DENIED", "login_code_source_changed")
        result = self.check_binding(source_id, window, mailbox_locked=mailbox_locked)
        current = self.store.get("code-window:" + source_id)
        if (not current or current["started"] != started or current["expires"] < time.time()
                or current.get("source_generation") != window.get("source_generation")
                or current.get("source_enrollment") != window.get("source_enrollment")):
            raise AccessError("DENIED", "login_code_window_missing")
        return result

    def mailbox_authorization(self, config, source):
        """Stable owner authorization, without including renewable token bytes."""
        connection = self.store.get("connection:" + source.account) or {}
        return {"fingerprint": config.fingerprint(source.account),
                "authorization": connection.get("authorization_id") or connection.get("generation"),
                "connected": bool(connection), "revoked": bool(connection.get("revoked")),
                "invalid": bool(connection.get("invalid")),
                "refresh_in_flight": bool(connection.get("refresh_in_flight"))}

    def check_binding(self, source_id, window, *, mailbox_locked=None):
        """Validate an unpublished or live window against current authority."""
        config = self.store.config()
        source = config.code_sources.get(source_id)
        if source is None or window.get("source_config") != source.model_dump():
            raise AccessError("DENIED", "login_code_source_changed")
        account = self.mailbox_account(source)
        if mailbox_locked is not None and mailbox_locked != account:
            raise AccessError("DENIED", "login_code_source_changed")
        if account and mailbox_locked is None:
            # Re-enter after the wait so an unpublished window's binding is
            # checked against current configuration/enrollment as well.
            with self.store.lock("account:" + account):
                return self.check_binding(source_id, window, mailbox_locked=account)
        credentials = enrollment(self.store, source_id)
        if credentials.get("enabled") is False:
            raise AccessError("NEEDS_USER", "verification_source_disabled")
        current = hashlib.sha256(json.dumps(credentials, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if (window.get("source_enrollment") != current
                or window.get("source_generation") != self.store.get("source-generation:" + source_id)):
            raise AccessError("DENIED", "verification_source_enrollment_changed")
        if account:
            # Gmail message reads already own this OAuth account lock. Other
            # callers wait for an ordinary refresh before checking its flags;
            # a completed refresh preserves authorization_id and the window.
            # Final publication orders source -> window -> mailbox OAuth
            # account. OAuth account holders never acquire source/window locks;
            # mailbox_locked names the held account, preventing a source from
            # switching to a different mailbox beneath a nested Gmail check.
            authorization = self.mailbox_authorization(config, source)
            if not authorization["connected"]:
                raise AccessError("NEEDS_USER", "account_not_connected", "email")
            if authorization["revoked"]:
                raise AccessError("DENIED", "connection_revoked", "email")
            if authorization["invalid"]:
                raise AccessError("NEEDS_USER", "provider_grant_revoked_or_expired", "email")
            if authorization["refresh_in_flight"]:
                raise AccessError("NEEDS_USER", "refresh_outcome_uncertain", "email")
            if window.get("mailbox_authorization") != authorization:
                raise AccessError("DENIED", "verification_source_enrollment_changed", "email")
        return source, window, credentials

    def publish_window(self, source_id, window, *, existing=False):
        # Baseline requests can block while the owner changes enrollment.
        # Never publish their stale result after disable/re-enable, even if
        # the replacement credentials have exactly the same value.
        with source_mutation(self.store, source_id):
            if existing:
                self.check_window(source_id, window["started"])
            self.check_binding(source_id, window)
            if time.time() > window["expires"]:
                raise AccessError("NEEDS_USER", "login_code_window_expired")
            self.store.put("code-window:" + source_id, window)

    def resolve(self, source_id, started, used):
        source, window, credentials = self.check_window(source_id, started)
        config = self.store.config()
        if source.kind == "totp":
            if not credentials.get("seed"):
                raise AccessError("NEEDS_USER", "authenticator_not_enrolled", "totp")
            try:
                otp = pyotp.TOTP(credentials["seed"])
                now = time.time()
                if otp.interval - now % otp.interval < 5:
                    # Leave enough time to fill and submit a code. Normal
                    # polling waits for the next interval without asking the
                    # owner or retrying a rejected code at the website.
                    return None
                return otp.at(now)
            except Exception:
                raise AccessError("NEEDS_USER", "invalid_authenticator_seed", "totp") from None
        if source.kind == "gmail":
            with self.store.lock("account:" + source.account):
                get = self.gmail_reader(source, config)
                ids = self.gmail_ids(source, started, get)
                candidates = []
                for ident in ids:
                    self.check_window(source_id, started, mailbox_locked=source.account)
                    if ident in used or ident in window["gmail_baseline"]:
                        continue
                    message = get(GMAIL_MESSAGES + "/" + ident, {"format": "raw"})
                    if not isinstance(message, dict) or message.get("id") != ident:
                        raise AccessError("RETRYABLE", "invalid_mailbox_response", "email")
                    received = message.get("internalDate", "")
                    if (not isinstance(received, str) or not re.fullmatch(r"[0-9]{1,16}", received)
                            or not started <= int(received) / 1000 <= time.time() + 5):
                        continue
                    value = message.get("raw", "")
                    if (not isinstance(value, str) or not 0 < len(value) <= 4 * ((MAX_MESSAGE_BYTES + 2) // 3)
                            or not re.fullmatch(r"[a-zA-Z0-9_-]+={0,2}", value)):
                        continue
                    try:
                        raw = base64.b64decode(value + "=" * (-len(value) % 4),
                                               altchars=b"-_", validate=True)
                    except ValueError:
                        continue
                    code = email_login_code(raw, source)
                    if code:
                        candidates.append((ident, code))
                self.check_window(source_id, started, mailbox_locked=source.account)
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
                _, window, _ = self.check_window(source_id, started)
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
        if not isinstance(window.get("gateway_baseline"), list):
            raise AccessError("NEEDS_USER", "sms_gateway_login_window_missing", "sms")
        messages = self.gateway_messages(source, credentials, started)
        candidates = []
        for item in messages:
            if (item["sid"] in used or item["sid"] in window["gateway_baseline"] or item.get("direction") != "inbound"
                or item.get("from") != source.sender or item.get("to") != source.recipient):
                continue
            if not isinstance(item.get("date_sent"), str) or len(item["date_sent"]) > 128:
                continue
            try:
                sent_date = parsedate_to_datetime(item["date_sent"])
                if sent_date.tzinfo is None:
                    continue
                sent = sent_date.timestamp()
            except (KeyError, TypeError, ValueError, OverflowError):
                continue
            if not started <= sent <= min(window["expires"], time.time() + 5):
                continue
            body = item.get("body")
            code = match_code(source.template, body) if isinstance(body, str) and len(body) <= 2000 else None
            if code:
                candidates.append((item["sid"], code))
        self.check_window(source_id, started)
        candidate = unique_code(candidates)
        if candidate:
            used.add(candidate[0])
            return candidate[1]
        return None

    def gateway_messages(self, source, credentials, started):
        sid = credentials.get("sid")
        if not sid or not credentials.get("auth_token"):
            raise AccessError("NEEDS_USER", "sms_gateway_not_connected", "sms")
        if not isinstance(sid, str) or not re.fullmatch(r"AC[0-9a-fA-F]{32}", sid):
            raise AccessError("NEEDS_USER", "invalid_sms_gateway", "sms")
        try:
            data = get_json(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                            auth=(sid, credentials["auth_token"]),
                            params={"To": source.recipient, "From": source.sender, "PageSize": 20,
                                    "DateSent>": datetime.fromtimestamp(started, timezone.utc).strftime("%Y-%m-%d")})
        except AccessError as exc:
            raise AccessError(exc.status, exc.reason, "sms") from None
        if not isinstance(data, dict) or not isinstance(data.get("messages"), list):
            raise AccessError("RETRYABLE", "invalid_sms_gateway_response", "sms")
        if data.get("next_page_uri") or len(data["messages"]) > 20:
            # Never choose from only part of the matching result set or follow
            # a provider-supplied URI with gateway credentials.
            raise AccessError("NEEDS_USER", "sms_gateway_result_limit", "sms")
        seen = set()
        for item in data["messages"]:
            if (not isinstance(item, dict) or not isinstance(item.get("sid"), str)
                    or not re.fullmatch(r"(?:SM|MM)[0-9a-fA-F]{32}", item["sid"])
                    or item["sid"] in seen):
                raise AccessError("RETRYABLE", "invalid_sms_gateway_response", "sms")
            seen.add(item["sid"])
        return data["messages"]

    def begin(self, source_id, account, started):
        window = {"account": account, "started": started,
                  "expires": started + 120, "incoming": [], "consumed": False}
        with self.store.lock("source:" + source_id):
            config = self.store.config()
            source = config.code_sources[source_id]
            window["source_config"] = source.model_dump()
            credentials = enrollment(self.store, source_id)
            window["source_generation"] = self.store.get("source-generation:" + source_id)
        if credentials.get("enabled") is False:
            kind = "email" if source.kind in {"imap", "gmail"} else "totp" if source.kind == "totp" else "sms"
            raise AccessError("NEEDS_USER", "verification_source_disabled", kind)
        if source.kind == "totp":
            if not credentials.get("seed"):
                raise AccessError("NEEDS_USER", "authenticator_not_enrolled", "totp")
        window["source_enrollment"] = hashlib.sha256(
            json.dumps(credentials, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if source.account and source.kind in {"imap", "gmail"}:
            with self.store.lock("account:" + source.account):
                window["mailbox_authorization"] = self.mailbox_authorization(self.store.config(), source)
        if source.kind == "gmail":
            # Check consent/access and remember current message IDs before the
            # password can trigger delivery. A pre-existing imported message
            # with a future internalDate must never become a fresh login code.
            with self.store.lock("account:" + source.account):
                window["gmail_baseline"] = self.gmail_ids(source, started, self.gmail_reader(source, config))
        if source.kind == "phone_relay":
            pair = self.store.get("phone-pair:" + source_id) or {}
            if credentials.get("enabled") is not True or not pair.get("token"):
                raise AccessError("NEEDS_USER", "phone_not_paired", "sms")
        if source.kind == "twilio":
            window["gateway_baseline"] = [item["sid"] for item in self.gateway_messages(source, credentials, started)]
        if source.kind == "imap":
            try:
                with self.mailbox(source, credentials, config) as mailbox:
                    for name in ["UIDVALIDITY", "UIDNEXT"]:
                        window[name] = imap_number(mailbox.response(name)[1])
            except (imaplib.IMAP4.error, OSError) as exc:
                raise mailbox_error(exc) from None
        if source.kind == "mac_messages":
            if credentials.get("enabled") is not True:
                raise AccessError("NEEDS_USER", "message_permission_required", "sms")
            if self.native_transport is not None:
                # Publish the short-lived window before asking the private root
                # collector for a baseline. No password has been submitted yet.
                self.publish_window(source_id, window)
                try:
                    baseline = self.messages_baseline(source_id, source, started)
                    self.check_window(source_id, started)
                except Exception:
                    self.finish(source_id, started)
                    raise
                window["after_row"] = baseline
            else:
                window["after_row"] = self.messages_baseline(source_id, source, started)
        if source.kind == "google_messages":
            if credentials.get("enabled") is not True:
                raise AccessError("NEEDS_USER", "google_messages_not_connected", "sms")
            window["google_window"] = secrets.token_hex(16)
        self.publish_window(source_id, window,
                            existing=source.kind == "mac_messages" and self.native_transport is not None)
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

    def gmail_headers(self, source, config, *, force=False):
        try:
            token = self.oauth.token(source.account, config, force=force)
        except AccessError as exc:
            raise AccessError(exc.status, exc.reason, "email") from None
        if GMAIL_SCOPE not in token["scope"].split():
            raise AccessError("NEEDS_USER", "mailbox_scope_missing", "email")
        return {"Authorization": "Bearer " + token["access_token"]}

    def gmail_reader(self, source, config):
        # Caller holds the mailbox account lock. Share one renewal budget
        # across a listing and all its message reads, including scope rechecks.
        headers = self.gmail_headers(source, config)
        renewed = False

        def get(url, params):
            nonlocal headers, renewed
            try:
                return get_json(url, headers=headers, params=params)
            except AccessError as exc:
                if exc.reason != "provider_rejected_access" or renewed:
                    raise AccessError(exc.status, exc.reason, "email") from None
            renewed = True
            headers = self.gmail_headers(source, config, force=True)
            try:
                return get_json(url, headers=headers, params=params)
            except AccessError as exc:
                raise AccessError(exc.status, exc.reason, "email") from None

        return get

    def gmail_ids(self, source, started, get):
        listing = get(GMAIL_MESSAGES, {
            "q": f"from:{source.sender} to:{source.recipient} after:{int(started) - 1}",
            "maxResults": 20,
        })
        if not isinstance(listing, dict) or not isinstance(listing.get("messages", []), list):
            raise AccessError("RETRYABLE", "invalid_mailbox_response", "email")
        if listing.get("nextPageToken") or len(listing.get("messages", [])) > 20:
            # Choosing a code from only part of the matching result set would
            # hide ambiguity. Do not follow unbounded mailbox pagination.
            raise AccessError("NEEDS_USER", "mailbox_result_limit", "email")
        ids = []
        for item in listing.get("messages", []):
            if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                    or not GMAIL_ID.fullmatch(item["id"])):
                raise AccessError("RETRYABLE", "invalid_mailbox_response", "email")
            if item["id"] not in ids:
                ids.append(item["id"])
        return ids

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
                if imap_number(mailbox.response("UIDVALIDITY")[1]) != window["UIDVALIDITY"]:
                    raise AccessError("NEEDS_USER", "mailbox_uid_validity_changed", "email")
                # Search values are owner-authored, but still quote IMAP metacharacters.
                def quote(s):
                    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
                if any("\r" in x or "\n" in x for x in [source.sender, source.recipient, source.subject]):
                    raise AccessError("NEEDS_USER", "invalid_mail_filter", "email")
                status, data = mailbox.uid("SEARCH", None, "UID", str(window["UIDNEXT"]) + ":*", "FROM", quote(source.sender),
                                           "TO", quote(source.recipient), "SUBJECT", quote(source.subject))
                if status != "OK":
                    raise AccessError("RETRYABLE", "mailbox_search_failed", "email")
                if (not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], bytes)):
                    raise AccessError("RETRYABLE", "invalid_mailbox_response", "email")
                if len(data[0]) > 4096:
                    raise AccessError("NEEDS_USER", "mailbox_result_limit", "email")
                ids = []
                for value in data[0].split():
                    number = imap_number([value])
                    # A UID sequence range ending in * can include the last
                    # old message when UIDNEXT exceeds the highest current UID.
                    if number >= window["UIDNEXT"] and value not in ids:
                        ids.append(value)
                if len(ids) > 20:
                    raise AccessError("NEEDS_USER", "mailbox_result_limit", "email")
                candidates = []
                for ident in ids:
                    self.check_window(source_id, started)
                    key = ident.decode("ascii")
                    if key in used:
                        continue
                    status, fetched = mailbox.uid("FETCH", ident, "(UID INTERNALDATE BODY.PEEK[]<0.256001>)")
                    if status != "OK":
                        raise AccessError("RETRYABLE", "mailbox_fetch_failed", "email")
                    if not isinstance(fetched, list):
                        raise AccessError("RETRYABLE", "invalid_mailbox_response", "email")
                    bodies = [item for item in fetched if isinstance(item, tuple)]
                    if len(bodies) != 1:
                        # Do not choose another candidate from a partial result.
                        raise AccessError("RETRYABLE", "invalid_mailbox_response", "email")
                    for item in bodies:
                        if (len(item) != 2 or not isinstance(item[0], bytes) or len(item[0]) > 4096
                                or not isinstance(item[1], bytes)):
                            raise AccessError("RETRYABLE", "invalid_mailbox_response", "email")
                        uids = re.findall(rb"(?:^|[ (])UID ([0-9]+)(?=[ )])", item[0])
                        if uids != [ident]:
                            raise AccessError("RETRYABLE", "invalid_mailbox_response", "email")
                        if len(item[1]) > MAX_MESSAGE_BYTES:
                            continue
                        try:
                            received = imaplib.Internaldate2tuple(item[0])
                            received_at = time.mktime(received) if received else None
                        except (TypeError, ValueError, OverflowError):
                            received_at = None
                        if (received_at is None or not int(started) <= received_at <= time.time() + 5
                                or time.time() > window["expires"]):
                            continue
                        code = email_login_code(item[1], source)
                        if code:
                            candidates.append((key, code))
                self.check_window(source_id, started)
                candidate = unique_code(candidates)
                if candidate:
                    used.add(candidate[0])
                    return candidate[1]
                return None
        except (imaplib.IMAP4.error, OSError) as exc:
            raise mailbox_error(exc) from None

    def native_messages(self, source_id, source, started, **fields):
        """Authenticated transport to the signed app; never exposed to agents."""
        if self.native_transport is not None:
            result = self.native_transport(
                {"source": source_id, "sender": source.sender, "template": source.template,
                 "started": started, **fields}, lambda: self.check_window(source_id, started))
            self.check_window(source_id, started)
            return result
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
