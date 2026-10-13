"""Purpose-specific code resolvers. No raw inbox or code retrieval API is exposed to agents."""

import base64
import re
import time
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

    def resolve(self, source_id, started, used):
        config = self.store.config()
        source = config.code_sources[source_id]
        if time.time() - started > 120:
            raise AccessError("NEEDS_USER", "login_code_window_expired")
        credentials = self.store.get("source:" + source_id, {})
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
