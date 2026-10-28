"""Ephemeral worker-to-root SMS work queue. Never mounted on the agent API.

The private owner Unix channel carries bounded requests to the native system
host. The host reads as the OS owner; this queue never opens a Messages database.
"""

from dataclasses import dataclass
import math
import json
import re
import secrets
import threading
import time

from .errors import AccessError


class NativeMessagesUnavailable(AccessError):
    def __init__(self):
        super().__init__("RETRYABLE", "mac_messages_reader_unavailable", "sms")


def request_body(value):
    if type(value) is not dict or value.get("action") not in {"begin", "read"}:
        raise AccessError("DENIED", "invalid_native_messages_request", "sms")
    expected = {"action", "source", "sender", "template", "started"}
    if value["action"] == "read":
        expected |= {"after_row", "used"}
    if set(value) != expected:
        raise AccessError("DENIED", "invalid_native_messages_request", "sms")
    for name, maximum in [("source", 128), ("sender", 200), ("template", 1024)]:
        text = value[name]
        if (
            type(text) is not str
            or not 0 < len(text.encode()) <= maximum
            or any(ord(c) < 32 for c in text)
        ):
            raise AccessError("DENIED", "invalid_native_messages_request", "sms")
    if value["template"].count("{code}") != 1:
        raise AccessError("DENIED", "invalid_native_messages_request", "sms")
    started = value["started"]
    if (
        type(started) not in {int, float}
        or not math.isfinite(started)
        or not 0 <= time.time() - started <= 120
    ):
        raise AccessError("DENIED", "invalid_native_messages_request", "sms")
    if value["action"] == "read":
        if type(value["after_row"]) is not int or not 0 <= value["after_row"] < 2**63:
            raise AccessError("DENIED", "invalid_native_messages_request", "sms")
        used = value["used"]
        if (
            type(used) is not list
            or len(used) > 100
            or any(type(x) is not str or not 0 < len(x.encode()) <= 128 for x in used)
        ):
            raise AccessError("DENIED", "invalid_native_messages_request", "sms")
    if len(json.dumps(value, separators=(",", ":")).encode()) > 8192:
        raise AccessError("DENIED", "invalid_native_messages_request", "sms")
    return {**value, **({"used": list(value["used"])} if "used" in value else {})}


def response_body(action, value):
    if type(value) is not dict:
        raise AccessError("DENIED", "invalid_message_reader_response", "sms")
    status = value.get("status")
    if status == "READY" and action == "begin" and set(value) == {"status", "after_row"}:
        if type(value["after_row"]) is int and 0 <= value["after_row"] < 2**63:
            return dict(value)
    elif status == "WAITING" and action == "read" and set(value) == {"status"}:
        return dict(value)
    elif status == "FOUND" and action == "read" and set(value) == {"status", "id", "code"}:
        if (
            type(value["code"]) is str
            and re.fullmatch(r"[0-9]{6}", value["code"])
            and type(value["id"]) is str
            and 0 < len(value["id"].encode()) <= 128
        ):
            return dict(value)
    elif status in {"NEEDS_USER", "RETRYABLE"} and set(value) == {"status", "reason"}:
        if (
            status == "NEEDS_USER"
            and value["reason"] in {"mac_messages_permission_required", "ambiguous_login_code"}
            or status == "RETRYABLE"
            and value["reason"] == "mac_messages_reader_unavailable"
        ):
            return dict(value)
    raise AccessError("DENIED", "invalid_message_reader_response", "sms")


@dataclass(repr=False)
class Pending:
    body: dict
    guard: object
    deadline: float
    response: dict | None = None


class NativeMessagesRelay:
    def __init__(self, *, timeout=8):
        self.timeout = timeout
        self.condition = threading.Condition()
        self.pending = {}
        self.closed = False

    def __repr__(self):
        return "<NativeMessagesRelay redacted>"

    def request(self, body, guard):
        body = request_body(body)
        guard()
        ident = secrets.token_hex(16)
        item = Pending(body, guard, time.monotonic() + self.timeout)
        with self.condition:
            if self.closed or len(self.pending) >= 4:
                raise NativeMessagesUnavailable()
            self.pending[ident] = item
        try:
            while True:
                guard()
                with self.condition:
                    if self.closed or time.monotonic() >= item.deadline:
                        raise NativeMessagesUnavailable()
                    if item.response is not None:
                        result = item.response
                        if result["status"] == "RETRYABLE":
                            raise NativeMessagesUnavailable()
                        return result
                    self.condition.wait(min(0.05, max(0, item.deadline - time.monotonic())))
        finally:
            with self.condition:
                self.pending.pop(ident, None)

    def next(self):
        with self.condition:
            candidates = list(self.pending.items()) if not self.closed else []
        for ident, item in candidates:
            try:
                item.guard()
            except AccessError:
                continue
            with self.condition:
                if (
                    self.pending.get(ident) is item
                    and item.response is None
                    and time.monotonic() < item.deadline
                ):
                    return {"status": "OK", "request": {"id": ident, "body": dict(item.body)}}
        return {"status": "OK", "request": None}

    def respond(self, ident, value):
        if type(ident) is not str or not re.fullmatch(r"[a-f0-9]{32}", ident):
            raise AccessError("DENIED", "native_messages_request_missing", "sms")
        with self.condition:
            item = self.pending.get(ident)
        if item is None or self.closed or time.monotonic() >= item.deadline:
            raise AccessError("DENIED", "native_messages_request_missing", "sms")
        item.guard()
        response = response_body(item.body["action"], value)
        with self.condition:
            if self.pending.get(ident) is not item or item.response is not None or self.closed:
                raise AccessError("DENIED", "native_messages_request_missing", "sms")
            item.response = response
            self.condition.notify_all()
        return {"status": "ACCEPTED"}

    def close(self):
        with self.condition:
            self.closed = True
            self.pending.clear()
            self.condition.notify_all()
