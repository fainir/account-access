"""One reviewed PyPI device email, never a generic link or token authenticator.

Payload inspection binds a mail to the user named by PyPI's HTTPS password
response. PyPI alone verifies the signature, action and device IP on use.
"""

import base64
import ipaddress
import json
import re
import time
import uuid
import zlib
from datetime import datetime

from .email_codes import message_body
from .pypi_challenge import TOKEN

PURPOSE = "pypi-device-confirmation"
SENDER = "noreply@pypi.org"
SUBJECT = "[PyPI] Unrecognized login to your PyPI account"
CONFIRM_URL = "https://pypi.org/account/confirm-login/?token="
PROJECTS_PATH = "/manage/projects/"
PREFIX = ("A login attempt was made from an unrecognized device.\n\n"
          "To complete your login, please visit the following link from the same device\n"
          "from which you attempted to log in:\n\n")
SUFFIX = ("\n\nIn the future, you can automatically trust new devices without needing email\n"
          "verification by using a security device as your 2FA method. See\n"
          "https://pypi.org/help/#utfkey for more details.\n\n"
          "If you did not initiate this login, you can email admin@pypi.org to\n"
          "communicate with the PyPI administrators.")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate token field")
        result[key] = value
    return result


def decode_token(token):
    """Bounded structural inspection only; does not establish authentication."""
    if not isinstance(token, str) or len(token) > 2048 or not TOKEN.fullmatch(token):
        raise ValueError("invalid token structure")
    compressed = token.startswith(".")
    payload, timestamp, _ = token.removeprefix(".").split(".")
    raw = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
    if compressed:
        decoder = zlib.decompressobj()
        try:
            raw = decoder.decompress(raw, 4097)
        except zlib.error:
            raise ValueError("invalid token compression") from None
        if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
            raise ValueError("invalid token compression")
    if len(raw) > 4096:
        raise ValueError("token payload too large")
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object)
    except RecursionError:
        raise ValueError("invalid token nesting") from None
    if type(data) is not dict or any(type(value) is not str or len(value) > 512 for value in data.values()):
        raise ValueError("invalid token payload")
    stamp = base64.b64decode(timestamp + "=" * (-len(timestamp) % 4), altchars=b"-_", validate=True)
    if not 1 <= len(stamp) <= 8:
        raise ValueError("invalid token timestamp")
    return data, int.from_bytes(stamp, "big")


def user_id(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("invalid token user")
    return value


def password_user(token):
    data, _ = decode_token(token)
    if set(data) not in [{"userid"}, {"userid", "redirect_to"}]:
        raise ValueError("invalid password response token")
    return user_id(data["userid"])


def confirmation_token(token, expected_user, started, *, now=None):
    data, stamp = decode_token(token)
    if (set(data) != {"action", "user.id", "user.last_login", "unique_login_id"}
            or data["action"] != "login-confirmation" or user_id(data["user.id"]) != expected_user
            or user_id(data["unique_login_id"]) != data["unique_login_id"]
            or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\+00:00", data["user.last_login"]) is None
            or not started - 5 <= stamp <= (time.time() if now is None else now) + 5):
        raise ValueError("confirmation token does not match login")
    datetime.fromisoformat(data["user.last_login"])
    return token


def confirmation_link(raw, source, expected_user, started):
    if source.message_purpose != PURPOSE or source.sender != SENDER or source.subject != SUBJECT:
        return None
    body = message_body(raw, source)
    if not body or body[0] != "text/plain":
        return None  # The reviewed Warehouse multipart mail includes this plain-text template.
    text = body[1].replace("\r\n", "\n").strip()
    pattern = (re.escape(PREFIX + CONFIRM_URL) + r"([^\n]{1,2048})"
               + re.escape("\n\nThis login attempt was made from:\n- IP address: ")
               + r"([^\n]{1,100})\n- Location: ([^\n]{1,500})\n- User agent: ([^\n]{1,1000})"
               + re.escape(SUFFIX))
    match = re.fullmatch(pattern, text)
    if not match:
        return None
    try:
        ipaddress.ip_address(match[2])
        token = confirmation_token(match[1], expected_user, started)
        return CONFIRM_URL + token
    except (ValueError, TypeError, UnicodeError, zlib.error, RecursionError):
        return None
