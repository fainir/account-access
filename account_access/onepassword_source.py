"""Exact-item reads through the pinned official 1Password SDK.

The short-lived child inherits the protected runtime, never the owner's CLI,
desktop app, environment token, home directory or current working directory.
Only credentials for the already-approved website return over its private pipe.
"""

import asyncio
import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time

from .errors import AccessError
from .models import origin

DEADLINE = 20
SDK_DEADLINE = 15
MAX_MESSAGE = 65536
REASONS = {
    "password_source_unavailable": "RETRYABLE",
    "password_source_access_removed": "DENIED",
    "password_source_item_changed": "DENIED",
    "password_source_runtime_unavailable": "NEEDS_USER",
}


def _credentials(item, request):
    try:
        if (item.id != request["item"] or item.vault_id != request["vault"]
                or item.category != "Login" or len(item.fields) > 128
                or len(item.websites) > 128):
            raise ValueError()
        # The SDK's Item is its active-item DTO. Do not follow references, list a
        # vault, resolve an OTP, download attachments or inspect custom fields.
        websites = {origin(x.url) for x in item.websites
                    if x.autofill_behavior != "Never"}
        username = [x for x in item.fields if x.id == "username"]
        password = [x for x in item.fields if x.id == "password"]
        if (request["origin"] not in websites or len(username) != 1 or len(password) != 1
                or username[0].field_type not in {"Text", "Email"}
                or password[0].field_type != "Concealed"
                or username[0].section_id is not None or password[0].section_id is not None
                or any(not isinstance(x.value, str) or not 0 < len(x.value) <= 4096
                       for x in [username[0], password[0]])):
            raise ValueError()
        return {"username": username[0].value, "password": password[0].value}
    except (AttributeError, KeyError, TypeError, ValueError):
        raise AccessError("DENIED", "password_source_item_changed") from None


async def _read(request):
    # Service-token authentication cannot fall back to the desktop app or CLI.
    # A fresh process also releases native SDK clients and memory on every read.
    from onepassword import Client
    from onepassword.errors import RateLimitExceededException

    try:
        async with asyncio.timeout(SDK_DEADLINE):
            client = await Client.authenticate(
                auth=request["token"], integration_name="Account Access",
                integration_version="0.8.0")
            item = await client.items.get(request["vault"], request["item"])
            return _credentials(item, request)
    except (TimeoutError, RateLimitExceededException):
        raise AccessError("RETRYABLE", "password_source_unavailable") from None
    except (ImportError, OSError):
        raise AccessError("NEEDS_USER", "password_source_runtime_unavailable") from None
    except AccessError:
        raise
    except Exception:
        # SDK provider errors may contain item contents or a token. They never
        # cross this boundary, even when a future SDK changes its error shape.
        raise AccessError("DENIED", "password_source_access_removed") from None


def _exchange(command, payload, directory, *, deadline=DEADLINE):
    """Bound both private pipes and kill/reap a stalled native SDK process."""
    environment = {"HOME": directory, "TMPDIR": directory,
                   "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    output = bytearray()
    expires = time.monotonic() + deadline
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        cwd=directory, env=environment, close_fds=True, start_new_session=True)
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            sent = 0
            while selector.get_map():
                remaining = expires - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                for key, _ in selector.select(remaining):
                    if key.fileobj is process.stdin:
                        sent += os.write(process.stdin.fileno(), payload[sent:])
                        if sent == len(payload):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), min(4096, MAX_MESSAGE + 1 - len(output)))
                        if not chunk:
                            selector.unregister(process.stdout)
                            process.stdout.close()
                        else:
                            output.extend(chunk)
                            if len(output) > MAX_MESSAGE:
                                raise ValueError()
        process.wait(timeout=max(0, expires - time.monotonic()))
        if process.returncode != 0:
            raise ValueError()
        return bytes(output)
    finally:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        for stream in [process.stdin, process.stdout]:
            if stream and not stream.closed:
                stream.close()


def fetch(link, expected_origin):
    request = {key: link[key] for key in ["token", "vault", "item"]}
    request["origin"] = expected_origin
    payload = json.dumps(request, ensure_ascii=False).encode()
    try:
        with tempfile.TemporaryDirectory(prefix="account-access-password-source-") as directory:
            raw = _exchange([sys.executable, "-I", "-B", "-m", "account_access.onepassword_source"],
                            payload, directory)
        response = json.loads(raw)
        if (isinstance(response, dict) and set(response) == {"reason"}
                and response["reason"] in REASONS):
            raise AccessError(REASONS[response["reason"]], response["reason"])
        if (not isinstance(response, dict) or set(response) != {"username", "password"}
                or any(not isinstance(x, str) or not 0 < len(x) <= 4096
                       for x in response.values())):
            raise ValueError()
        return response
    except AccessError:
        raise
    except (TimeoutError, subprocess.TimeoutExpired, OSError):
        raise AccessError("RETRYABLE", "password_source_unavailable") from None
    except (ValueError, TypeError):
        raise AccessError("DENIED", "password_source_item_changed") from None


def main():
    try:
        from .password_sync import IDENTIFIER
        request = json.loads(sys.stdin.buffer.read(MAX_MESSAGE + 1))
        if (not isinstance(request, dict) or set(request) != {"token", "vault", "item", "origin"}
                or any(not isinstance(x, str) for x in request.values())
                or not 0 < len(request["token"]) <= 8192
                or any(c in request["token"] for c in "\r\n")
                or any(not IDENTIFIER.fullmatch(request[x]) for x in ["vault", "item"])
                or not 0 < len(request["origin"]) <= 4096
                or origin(request["origin"]) != request["origin"]):
            raise ValueError()
        result = asyncio.run(_read(request))
    except (ImportError, OSError):
        result = {"reason": "password_source_runtime_unavailable"}
    except AccessError as exc:
        result = {"reason": exc.reason if exc.reason in REASONS else "password_source_item_changed"}
    except Exception:
        result = {"reason": "password_source_item_changed"}
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False).encode())


if __name__ == "__main__":
    main()
