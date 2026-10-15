"""Owner-only Google Authenticator transfer import, with bounded protobuf parsing.

Interoperability format: the original research linked from google/google-
authenticator-android#118. Google does not publish a supported migration API.
Only one complete export batch and standard SHA-1, six-digit TOTP are accepted.
"""

import base64
import binascii
import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit

from .errors import AccessError
from .models import BrowserAccount


def _bindings(config, source_id):
    return {key: config.fingerprint(key) for key, spec in config.accounts.items()
            if isinstance(spec, BrowserAccount) and spec.login and source_id in spec.login.sources()}


def _fields(data):
    offset = 0

    def varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise ValueError()
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                if value > (1 << 64) - 1:
                    raise ValueError()
                return value
        raise ValueError()

    fields = {}
    while offset < len(data):
        tag = varint()
        number, wire = tag >> 3, tag & 7
        if not 1 <= number <= 7:
            raise ValueError()
        if wire == 0:
            value = varint()
        elif wire == 2:
            length = varint()
            if length > 16384 or offset + length > len(data):
                raise ValueError()
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError()
        fields.setdefault(number, []).append(value)
    return fields


def _one(fields, number, default=None):
    values = fields.get(number, [default])
    if len(values) != 1:
        raise ValueError()
    return values[0]


def parse(uri):
    try:
        if not isinstance(uri, str) or len(uri) > 32000:
            raise ValueError()
        url = urlsplit(uri)
        query = parse_qs(url.query, strict_parsing=True)
        if (url.scheme != "otpauth-migration" or url.netloc != "offline" or url.path
                or url.fragment or set(query) != {"data"} or len(query["data"]) != 1):
            raise ValueError()
        payload = _fields(base64.b64decode(query["data"][0], validate=True))
        if set(payload) - {1, 2, 3, 4, 5} or _one(payload, 2, 1) != 1:
            raise ValueError()
        if _one(payload, 3, 1) not in {0, 1} or _one(payload, 4, 0) != 0:
            raise AccessError("DENIED", "authenticator_multiple_batches")
        if 5 in payload and not isinstance(_one(payload, 5), int):
            raise ValueError()
        parameters = payload.get(1, [])
        if not 1 <= len(parameters) <= 100:
            raise ValueError()
        result = []
        for parameter in parameters:
            item = _fields(parameter)
            if set(item) - {1, 2, 3, 4, 5, 6, 7}:
                raise ValueError()
            secret = _one(item, 1)
            if not isinstance(secret, bytes) or not 10 <= len(secret) <= 128:
                raise ValueError()
            if (_one(item, 4) != 1 or _one(item, 5) != 1 or _one(item, 6) != 2
                    or _one(item, 7, 0) != 0):
                raise AccessError("DENIED", "unsupported_authenticator_settings")
            seed = base64.b32encode(secret).decode().rstrip("=")
            labels = []
            for field in [3, 2]:
                label = _one(item, field, b"").decode("utf-8")
                label = "".join(c for c in label if c.isprintable())[:120].strip()
                label = label.replace(seed, "[hidden]")
                if label and label not in labels:
                    labels.append(label)
            result.append({"seed": seed, "label": " · ".join(labels) or "Authenticator account"})
        return result
    except AccessError:
        raise
    except (ValueError, TypeError, AttributeError, UnicodeError, binascii.Error):
        raise AccessError("DENIED", "invalid_authenticator_export") from None


def preview(store, source_id, uri):
    source = store.config().code_sources.get(source_id) if isinstance(source_id, str) else None
    if not source or source.kind != "totp":
        raise AccessError("DENIED", "unknown_authenticator_source")
    items = parse(uri)
    ident = secrets.token_hex(24)
    with store.lock("authenticator-import"):
        with store.db() as db:
            live = 0
            for row in db.execute("SELECT id,value FROM records WHERE id LIKE 'authenticator-import:%'").fetchall():
                staged = store.unseal(row["id"], row["value"])
                if not staged or staged["expires"] <= time.time():
                    db.execute("DELETE FROM records WHERE id=?", (row["id"],))
                else:
                    live += 1
            if live >= 8:
                raise AccessError("DENIED", "too_many_import_previews")
            store.put("authenticator-import:" + ident, {"source": source_id,
                      "source_config": source.model_dump(), "items": items,
                      "bindings": _bindings(store.config(), source_id),
                      "expires": time.time() + 600}, db=db)
    return {"status": "PREVIEW", "id": ident, "expires_in": 600,
            "accounts": [{"index": i, "label": item["label"]} for i, item in enumerate(items)]}


def apply(store, ident, index):
    if (not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{48}", ident)
            or type(index) is not int or not 0 <= index < 100):
        raise AccessError("DENIED", "invalid_authenticator_selection")
    from .factors import enroll
    with store.lock("authenticator-import"):
        staged = store.get("authenticator-import:" + ident)
        if not staged or staged["expires"] <= time.time():
            raise AccessError("DENIED", "authenticator_preview_expired")
        config = store.config()
        source = config.code_sources.get(staged["source"])
        if (not source or source.model_dump() != staged["source_config"] or index >= len(staged["items"])
                or _bindings(config, staged["source"]) != staged["bindings"]):
            raise AccessError("DENIED", "authenticator_selection_changed")
        result = enroll(store, staged["source"], {"seed": staged["items"][index]["seed"]})
        store.put("authenticator-import:" + ident, None)
        return result


def discard(store, ident):
    if not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{48}", ident):
        raise AccessError("DENIED", "invalid_authenticator_selection")
    with store.lock("authenticator-import"):
        store.put("authenticator-import:" + ident, None)
    return {"status": "DISCARDED"}
