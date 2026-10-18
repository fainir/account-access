"""Owner-only Google Authenticator transfer import, with bounded protobuf parsing.

Interoperability format: the original research linked from google/google-
authenticator-android#118. Google does not publish a supported migration API.
Complete single- or multi-image exports and standard SHA-1, six-digit TOTP are accepted.
"""

import base64
import binascii
import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit

from .errors import AccessError
from .models import BrowserAccount

MAX_PARTS = 16
MAX_EXPORT_BYTES = 60000
MAX_ACCOUNTS = 100


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


def _parse_part(uri):
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
        size, index, batch_id = _one(payload, 3, 1), _one(payload, 4, 0), _one(payload, 5)
        if (type(size) is not int or not 0 <= size <= MAX_PARTS
                or type(index) is not int or not 0 <= index < max(size, 1)
                or (batch_id is not None and type(batch_id) is not int)
                or (size > 1 and batch_id is None)):
            raise ValueError()
        parameters = payload.get(1, [])
        if not 1 <= len(parameters) <= MAX_ACCOUNTS:
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
        return {"size": max(size, 1), "index": index, "batch_id": batch_id, "items": result}
    except AccessError:
        raise
    except (ValueError, TypeError, AttributeError, UnicodeError, binascii.Error):
        raise AccessError("DENIED", "invalid_authenticator_export") from None


def parse_many(uris):
    if (type(uris) is not list or not 1 <= len(uris) <= MAX_PARTS
            or any(type(uri) is not str or not uri.isascii() or len(uri) > 32000 for uri in uris)
            or sum(len(uri) for uri in uris) > MAX_EXPORT_BYTES):
        raise AccessError("DENIED", "invalid_authenticator_export")
    parts = [_parse_part(uri) for uri in uris]
    first = parts[0]
    if len(parts) != first["size"]:
        raise AccessError("DENIED", "authenticator_export_incomplete")
    if (any(part["size"] != first["size"] or part["batch_id"] != first["batch_id"] for part in parts)
            or {part["index"] for part in parts} != set(range(first["size"]))):
        raise AccessError("DENIED", "authenticator_export_mismatch")
    result = [item for part in sorted(parts, key=lambda part: part["index"]) for item in part["items"]]
    if len(result) > MAX_ACCOUNTS:
        raise AccessError("DENIED", "invalid_authenticator_export")
    return result


def parse(uri):
    return parse_many([uri])


def preview(store, source_id, uri):
    source = store.config().code_sources.get(source_id) if isinstance(source_id, str) else None
    if not source or source.kind != "totp":
        raise AccessError("DENIED", "unknown_authenticator_source")
    items = parse_many(uri) if type(uri) is list else parse(uri)
    ident = secrets.token_hex(24)
    with store.lock("authenticator-import"), store.lock("source:" + source_id):
        config = store.config()
        current = config.code_sources.get(source_id)
        if current is None or current.model_dump() != source.model_dump():
            raise AccessError("DENIED", "authenticator_selection_changed")
        generation = store.get("source-generation:" + source_id)
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
                      "bindings": _bindings(config, source_id),
                      "source_generation": generation,
                      "expires": time.time() + 600}, db=db)
    return {"status": "PREVIEW", "id": ident, "expires_in": 600,
            "accounts": [{"index": i, "label": item["label"]} for i, item in enumerate(items)]}


def apply(store, ident, index):
    if (not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{48}", ident)
            or type(index) is not int or not 0 <= index < 100):
        raise AccessError("DENIED", "invalid_authenticator_selection")
    from .factors import replace_source, source_mutation, totp_seed
    with store.lock("authenticator-import"):
        staged = store.get("authenticator-import:" + ident)
        if not staged or staged["expires"] <= time.time():
            raise AccessError("DENIED", "authenticator_preview_expired")
        source_id = staged["source"]
        with source_mutation(store, source_id):
            if staged["expires"] <= time.time():
                raise AccessError("DENIED", "authenticator_preview_expired")
            config = store.config()
            source = config.code_sources.get(source_id)
            if (not source or source.model_dump() != staged["source_config"] or index >= len(staged["items"])
                    or _bindings(config, source_id) != staged["bindings"]
                    or store.get("source-generation:" + source_id) != staged.get("source_generation")):
                raise AccessError("DENIED", "authenticator_selection_changed")
            seed = totp_seed(staged["items"][index]["seed"])
            with store.db() as db:
                replace_source(store, source_id, {"seed": seed}, db=db)
                store.put("authenticator-import:" + ident, None, db=db)
        store.audit("owner", "", "", "factor_enrolled", "totp")
        return {"status": "ENROLLED", "source": source_id, "kind": "totp"}


def discard(store, ident):
    if not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{48}", ident):
        raise AccessError("DENIED", "invalid_authenticator_selection")
    with store.lock("authenticator-import"):
        store.put("authenticator-import:" + ident, None)
    return {"status": "DISCARDED"}
