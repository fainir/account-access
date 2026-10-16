"""Separate, SMS-only Chrome native messaging host and owner registration."""

import argparse
import base64
import hashlib
import json
import os
import shlex
import struct
import sys
from pathlib import Path

import httpx2 as httpx

from .errors import AccessError
from .google_messages import handle
from .storage import Store, check_private, load_key, private_file

HOST = "com.account_access.google_messages"
RESOURCES = Path(__file__).with_name("google_messages_extension")


def verification_service(store):
    from .desktop import running
    info = running(store.root)
    if not info:
        raise AccessError("NEEDS_USER", "open_account_access_first")
    return info


def start_verification(info, account):
    base = info["url"].rstrip("/")
    try:
        response = httpx.post(base + "/owner/verify", json={"account": account},
                              headers={"Authorization": "Bearer " + info["token"], "Origin": base},
                              timeout=5, trust_env=False, follow_redirects=False)
        if response.status_code != 200:
            raise AccessError("RETRYABLE", "google_messages_verification_not_started")
    except httpx.HTTPError:
        raise AccessError("RETRYABLE", "google_messages_verification_not_started") from None


def extension_id():
    key = json.loads((RESOURCES / "manifest.json").read_text())["key"]
    digest = hashlib.sha256(base64.b64decode(key, validate=True)).hexdigest()[:32]
    return "".join(chr(ord("a") + int(n, 16)) for n in digest)


def prepare(store, *, home=None, key_file=None):
    """Stage the reviewed extension and exact-origin host through owner setup."""
    if sys.platform != "darwin" and not sys.platform.startswith("linux"):
        raise AccessError("NEEDS_USER", "google_messages_platform_unsupported")
    home = home or Path.home()
    folder = (home / "Library/Application Support/Google/Chrome/NativeMessagingHosts" if sys.platform == "darwin"
              else home / ".config/google-chrome/NativeMessagingHosts")
    for parent in [folder, *folder.parents]:
        if parent.is_symlink():
            raise AccessError("DENIED", "unsafe_google_messages_path")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    if folder.stat().st_uid != os.getuid() or folder.stat().st_mode & 0o022:
        raise AccessError("DENIED", "unsafe_google_messages_path")
    destination = store.root / "GoogleMessagesExtension"
    destination.mkdir(mode=0o700, exist_ok=True)
    check_private(destination)
    for name in ["manifest.json", "background.js", "reader.js", "popup.js", "popup.html", "popup.css"]:
        target = destination / name
        if target.exists() or target.is_symlink():
            check_private(target)
        private_file(target, (RESOURCES / name).read_bytes(), replace=target.exists())
    launcher = store.root / "google-messages-native-host"
    if launcher.exists() or launcher.is_symlink():
        check_private(launcher)
    command = [sys.executable, "-m", "account_access.google_messages_host", "--root", str(store.root)]
    if key_file:
        command += ["--key-file", str(key_file)]
    private_file(launcher, ("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n').encode(), replace=launcher.exists())
    os.chmod(launcher, 0o700)
    origin = "chrome-extension://" + extension_id() + "/"
    manifest = folder / (HOST + ".json")
    if manifest.exists() or manifest.is_symlink():
        check_private(manifest)
    private_file(manifest, json.dumps({"name": HOST, "description": "Account Access login SMS only",
                 "path": str(launcher), "type": "stdio", "allowed_origins": [origin]}).encode(), replace=manifest.exists())
    store.put("google-messages-extension-origin", origin)
    store.put("google-messages-host-runtime", sys.executable)
    return {"extension_path": str(destination), "extension_id": extension_id(), "status": "PREPARED"}


def run_host(store, incoming, outgoing, presented_origin):
    expected = store.get("google-messages-extension-origin")
    if not expected or presented_origin != expected:
        return 2
    while True:
        header = incoming.read(4)
        if not header:
            return 0
        if len(header) != 4:
            return 2
        if store.get("google-messages-host-runtime", sys.executable) != sys.executable:
            return 2  # Reconnect to the refreshed launcher after an app repair.
        length = struct.unpack("=I", header)[0]
        if not 0 < length <= 65_536:
            return 2
        raw = incoming.read(length)
        if len(raw) != length:
            return 2
        ident = None
        try:
            message = json.loads(raw)
            if (not isinstance(message, dict) or set(message) != {"id", "body"}
                    or type(message["id"]) is not int or not 0 <= message["id"] <= 2**31):
                raise ValueError()
            ident = message["id"]
            connecting = isinstance(message["body"], dict) and message["body"].get("method") == "connect"
            service = verification_service(store) if connecting and not store.config().test_mode else None
            result = handle(store, message["body"])
            if service and result.get("status") == "CONNECTED":
                start_verification(service, result["account"])
                result["verification_started"] = True
        except AccessError as error:
            result = {"status": error.status, "reason": error.reason}
        except Exception:
            result = {"status": "DENIED", "reason": "invalid_google_messages_message"}
        encoded = json.dumps({"id": ident, "result": result}).encode()
        outgoing.write(struct.pack("=I", len(encoded)) + encoded)
        outgoing.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--key-file")
    parser.add_argument("origin")
    args = parser.parse_args()
    try:
        root = Path(args.root)
        store = Store(root, load_key(root, Path(args.key_file) if args.key_file else None))
        return run_host(store, sys.stdin.buffer, sys.stdout.buffer, args.origin)
    except Exception:
        return 2


if __name__ == "__main__":
    sys.exit(main())
