"""Disposable-Mac composed acceptance. Never read a real Messages database."""

from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import plistlib
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time

from account_access.demo import DEMO_PASSWORD, DemoProvider, configuration
from account_access.models import CodeSource, LoginFactor
from account_access.storage import private_file
from account_access.worker_bootstrap import root_managed_path


def native_account(base):
    spec = configuration(base).accounts["demo-mfa"].model_copy(deep=True)
    spec.label = "Controlled native SMS browser fixture"
    spec.login_url = spec.login_url.replace("/mfa/", "/sms/")
    for name in ["login_resources", "login_post_urls", "read_resources"]:
        setattr(spec, name, [url.replace("/mfa/", "/sms/") for url in getattr(spec, name)])
    for operation in spec.operations.values():
        operation.url = operation.url.replace("/mfa/", "/sms/")
    spec.login.code_source = spec.login.code_selector = spec.login.code_submit_selector = None
    spec.login.factors = {
        "sms": LoginFactor(
            code_source="native-sms", code_selector="#code", code_submit_selector="#code-submit"
        )
    }
    spec.challenge_selectors.pop("totp")
    spec.challenge_selectors["sms"] = "#sms-challenge"
    return spec


class NativeSMSFixture:
    label = "com.fainir.accountaccess.qa.native-browser"

    def __init__(self, prefix, owner, *, tag="native-browser"):
        if (
            sys.platform != "darwin"
            or os.getuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
        ):
            raise RuntimeError("native_browser_requires_disposable_mac_ci")
        if (
            prefix.parent != Path("/Library/PrivilegedHelperTools")
            or not prefix.name.startswith("account-access-worker-qa-")
            or owner.pw_uid == 0
            or not owner.pw_dir.startswith(str(prefix) + "/")
        ):
            raise RuntimeError("native_browser_requires_fixture_identity")
        if tag not in {"native-browser", "native-host"}:
            raise RuntimeError("invalid_native_fixture_tag")
        root_managed_path(prefix)
        self.prefix, self.owner = prefix, owner
        folder = prefix / (tag + "-owner")
        folder.mkdir(mode=0o700)
        os.chown(folder, owner.pw_uid, owner.pw_gid)
        self.database = folder / "messages.sqlite"
        with sqlite3.connect(self.database) as db:
            db.executescript(
                "CREATE TABLE handle(id TEXT); INSERT INTO handle VALUES('Example'); "
                "CREATE TABLE message(guid TEXT,text TEXT,attributedBody BLOB,handle_id INTEGER,is_from_me INTEGER,date INTEGER);"
            )
            # Fresh-looking cached code must be excluded by the pre-password row boundary.
            db.execute(
                "INSERT INTO message VALUES('cached','Example login: 000000',NULL,1,0,?)",
                (self.date(),),
            )
        os.chown(self.database, owner.pw_uid, owner.pw_gid)
        self.database.chmod(0o600)
        self.delivered = 0
        self.provider = DemoProvider().start()
        self.provider.delivery = self.deliver

    @staticmethod
    def date():
        return int((time.time() - 978307200) * 1_000_000_000)

    def deliver(self, kind, code):
        assert kind == "sms"
        with sqlite3.connect(self.database) as db:
            db.execute(
                "INSERT INTO message VALUES(?,?,NULL,1,0,?)",
                ("new-login-" + str(self.delivered + 1), "Example login: " + code, self.date()),
            )
        self.delivered += 1

    def enroll(self, broker):
        config = broker.store.config()
        config.accounts["native-sms"] = native_account(self.provider.base)
        config.code_sources["native-sms"] = CodeSource(
            kind="mac_messages",
            sender="Example",
            recipient="owner",
            template="Example login: {code}",
        )
        broker.store.configure(config)
        broker.store.put("source:native-sms", {"enabled": True})
        broker.store.put(
            "credential:native-sms", {"username": "demo@example.test", "password": DEMO_PASSWORD}
        )
        # No broker reference survives this setup call.

    def close(self):
        self.provider.close()

    @contextmanager
    def collector(self, capability, policy):
        prefix = self.prefix
        binary, helper = prefix / "native-browser-collector", prefix / "native-messages-helper"

        def signature(path):
            root_managed_path(path)
            signed = subprocess.run(
                ["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
                capture_output=True,
                timeout=10,
            )
            hashes = re.findall(rb"^CDHash=([a-f0-9]{40})$", signed.stderr, re.MULTILINE)
            assert signed.returncode == 0 and len(hashes) == 1
            return hashes[0].decode()

        parent_hash, helper_hash = signature(binary), signature(helper)
        if (
            subprocess.run(
                ["/bin/launchctl", "print", "system/" + self.label], capture_output=True
            ).returncode
            == 0
        ):
            raise RuntimeError("native_browser_namespace_already_occupied")
        profile = prefix / "native-browser-profile.json"
        private_file(
            profile,
            json.dumps({"owner_uid": self.owner.pw_uid, "parent_hash": parent_hash}).encode(),
        )
        profile.chmod(0o644)
        boot = prefix / "control/native-browser-boot.sock"
        settings = prefix / "native-browser-policy.json"
        private_file(
            settings,
            json.dumps(
                {
                    "fixture": "account-access-native-browser-ci-v1",
                    "owner_uid": self.owner.pw_uid,
                    "helper_hash": helper_hash,
                    "owner_socket": policy["owner_socket"],
                    "owner_port": policy["owner_port"],
                    "bootstrap_socket": str(boot),
                }
            ).encode(),
        )
        launch = prefix / "native-browser.plist"
        private_file(
            launch,
            plistlib.dumps(
                {
                    "Label": self.label,
                    "ProgramArguments": [str(binary), "--policy", str(settings)],
                    "UserName": "root",
                    "GroupName": "wheel",
                    "RunAtLoad": True,
                    "KeepAlive": False,
                    "ProcessType": "Background",
                    "StandardOutPath": "/dev/null",
                    "StandardErrorPath": "/dev/null",
                }
            ),
        )
        launch.chmod(0o644)
        issued, booted = threading.Event(), False
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(boot))
            listener.listen(1)
            listener.settimeout(40)
            boot.chmod(0o600)

            def supply():
                try:
                    channel, _ = listener.accept()
                    with channel:
                        system = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
                        system.getpeereid.argtypes = [
                            ctypes.c_int,
                            ctypes.POINTER(ctypes.c_uint),
                            ctypes.POINTER(ctypes.c_uint),
                        ]
                        system.getpeereid.restype = ctypes.c_int
                        uid, gid = ctypes.c_uint(), ctypes.c_uint()
                        assert (
                            system.getpeereid(
                                channel.fileno(), ctypes.byref(uid), ctypes.byref(gid)
                            )
                            == 0
                            and uid.value == 0
                        )
                        channel.sendall(capability.encode())
                        channel.shutdown(socket.SHUT_WR)
                    issued.set()
                except Exception:
                    pass

            sender = threading.Thread(target=supply, daemon=True)
            sender.start()
            try:
                result = subprocess.run(
                    ["/bin/launchctl", "bootstrap", "system", str(launch)],
                    capture_output=True,
                    timeout=30,
                )
                assert result.returncode == 0, "native_browser_bootstrap_failed"
                booted = True
                assert issued.wait(45), "native_browser_capability_handoff_failed"
                ready = prefix / "native-browser-ready.json"
                deadline = time.monotonic() + 15
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert json.loads(ready.read_bytes()) == {
                    "status": "READY",
                    "owner_uid": self.owner.pw_uid,
                }
                yield
                private_file(prefix / "native-browser-stop", b"stop\n")
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    service = subprocess.run(
                        ["/bin/launchctl", "print", "system/" + self.label],
                        capture_output=True,
                        timeout=10,
                    )
                    if re.findall(rb"last exit code = ([0-9]+)", service.stdout) == [b"0"]:
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("native_browser_collector_stop_failed")
            finally:
                listener.close()
                sender.join(timeout=2)
                if booted:
                    subprocess.run(
                        ["/bin/launchctl", "bootout", "system/" + self.label],
                        capture_output=True,
                        timeout=20,
                        check=True,
                    )
                boot.unlink(missing_ok=True)
        assert not sender.is_alive()


@contextmanager
def native_sms_fixture(prefix, roles, broker):
    if sys.platform != "darwin":
        yield None
        return
    fixture = NativeSMSFixture(prefix, roles["agent"])
    try:
        fixture.enroll(broker)
        yield fixture
    finally:
        fixture.close()
