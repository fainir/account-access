"""Disposable CI: framed native host -> desktop -> XPC -> isolated worker.

Synthetic provider delivery replaces Google Messages DOM/physical delivery.
The fixture entrypoint deliberately calls serve, never the signed-parent run
entrypoint. No owner account, browser profile or installed state is opened.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import struct
import subprocess
import sys
import threading
import time

from account_access.storage import private_file
from account_access.worker_bootstrap import root_managed_path


def remaining(deadline, maximum=45):
    value = min(maximum, deadline - time.monotonic())
    if value <= 0:
        raise RuntimeError("browser_fixture_deadline_expired")
    return value


def stop_process(process):
    """Cancel an owned new-session child, escalate, reap and close its pipes.

    Only the fixture's children enter here. The operation budget is separate
    from the fixed one-second TERM/two-second KILL cleanup budget per child.
    """
    try:
        if process.stdin is not None and not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("browser_fixture_child_did_not_stop") from None
        else:
            process.wait(timeout=0)
    finally:
        for stream in [process.stdin, process.stdout, process.stderr]:
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass


def completed_cli(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError()
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except ValueError:
        raise RuntimeError("browser_fixture_cli_failed") from None
    expected = {
        "status": "COMPLETED", "account": "browser-sms", "operation": "summary",
        "environment": "controlled-demo", "environment_source": "connector-configuration",
        "data": {"balance": "987.65", "currency": "ILS"}, "untrusted_data": True,
    }
    if value != expected or value["untrusted_data"] is not True:
        raise RuntimeError("browser_fixture_cli_failed")
    return value


class ClientReads:
    """Two sequential CLI children supervised by the framing coordinator.

    There is no executor/thread whose shutdown could delay cancellation. Output
    is drained while the child runs, bounded and never copied into exceptions.
    """
    def __init__(self, arguments, environment, deadline):
        self.arguments, self.environment, self.deadline = arguments, environment, deadline
        self.process = None
        self.output = bytearray()
        self.eof = False
        self.values = []

    def tick(self):
        remaining(self.deadline)
        if self.process is None:
            self.process = subprocess.Popen(
                self.arguments, env=self.environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
            )
            self.output = bytearray()
            self.eof = False
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while not self.eof and selector.select(0):
                part = os.read(self.process.stdout.fileno(), 8192)
                if not part:
                    self.eof = True
                elif len(self.output) + len(part) > 65536:
                    raise RuntimeError("browser_fixture_cli_output_limit")
                else:
                    self.output.extend(part)
        if self.process.poll() is None or not self.eof:
            return False
        self.process.wait(timeout=0)
        if self.process.returncode != 0:
            raise RuntimeError("browser_fixture_cli_failed")
        value = completed_cli(self.output)
        self.values.append(value)
        stop_process(self.process)
        self.process = None
        return len(self.values) == 2

    def close(self):
        if self.process is not None:
            stop_process(self.process)
            self.process = None


class Frames:
    def __init__(self, process, deadline):
        self.process = process
        self.deadline = deadline
        self.ident = 0

    def read(self, length):
        result = bytearray()
        deadline = min(self.deadline, time.monotonic() + 45)
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while len(result) < length:
                if not selector.select(remaining(deadline)):
                    raise RuntimeError("browser_fixture_frame_timeout")
                part = os.read(self.process.stdout.fileno(), length - len(result))
                if not part:
                    raise RuntimeError("browser_fixture_frame_closed")
                result.extend(part)
        return bytes(result)

    def request(self, body):
        remaining(self.deadline)
        self.ident += 1
        raw = json.dumps({"id": self.ident, "body": body}).encode()
        if not 0 < len(raw) <= 65536:
            raise RuntimeError("browser_fixture_frame_bounds")
        self.process.stdin.write(struct.pack("<I", len(raw)) + raw)
        self.process.stdin.flush()
        length = struct.unpack("<I", self.read(4))[0]
        if not 0 < length <= 65536:
            raise RuntimeError("browser_fixture_reply_bounds")
        value = json.loads(self.read(length))
        if set(value) != {"id", "result"} or value["id"] != self.ident or type(value["result"]) is not dict:
            raise RuntimeError("browser_fixture_reply_invalid")
        return value["result"]


def require_fixture(prefix, roles):
    if sys.platform != "darwin" or os.getuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("protected_browser_requires_disposable_mac_ci")
    if (
        prefix.parent != Path("/Library/PrivilegedHelperTools")
        or not prefix.name.startswith("account-access-worker-qa-")
        or roles["agent"].pw_uid in {0, roles["broker"].pw_uid}
        or not roles["agent"].pw_dir.startswith(str(prefix) + "/")
    ):
        raise RuntimeError("protected_browser_requires_fixture_identity")
    root_managed_path(prefix)


def exercise_browser_gateway(prefix, roles, fixture, config, server_hash):
    require_fixture(prefix, roles)
    binary = prefix / "root-owner-client"
    root_managed_path(binary)
    policy = prefix / "browser-host-owner-policy.json"
    private_file(policy, json.dumps({
        "fixture": "account-access-root-owner-ci-v1", "owner_uid": roles["agent"].pw_uid,
        "owner_hash": "0" * 40, "server_hash": server_hash,
        "owner_socket": str(prefix / "control/native-host.sock"), "owner_port": 8767,
        "bootstrap_socket": str(prefix / "control/unused-browser-bootstrap.sock"),
    }).encode())
    policy.chmod(0o644)
    owner = roles["agent"]
    dropped = ["/bin/launchctl", "asuser", str(owner.pw_uid), "/usr/bin/sudo", "-n", "-H",
               "-u", "#" + str(owner.pw_uid), "-g", "#" + str(owner.pw_gid), "--"]
    # One shared operation deadline includes preparation, both CLI reads and
    # every frame (header and body). Cleanup adds at most three seconds for each
    # of the two concurrently owned children; no background executor survives.
    deadline = time.monotonic() + 90
    process = subprocess.Popen(
        [*dropped, "/usr/bin/env", "GITHUB_ACTIONS=true", str(binary), "--policy", str(policy), "browser-bridge"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        start_new_session=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "GITHUB_ACTIONS": "true"},
    )
    bridge = Frames(process, deadline)
    clients = ClientReads(
        [*dropped, "/usr/bin/env", "ACCESS_CLIENT_CONFIG=" + str(config),
         sys.executable, "-I", "-B", "-m", "account_access.cli", "run", "browser-sms", "summary"],
        {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "ACCESS_CLIENT_CONFIG": str(config)},
        deadline,
    )
    checks = {}
    incoming, lock = [], threading.Lock()
    prior_delivery = fixture.provider.delivery

    def deliver(kind, code):
        if kind != "sms" or re.fullmatch(r"[0-9]{6}", code) is None:
            raise RuntimeError("browser_fixture_delivery_invalid")
        with lock:
            incoming.append({"id": hashlib.sha256(("fictional-message:" + code).encode()).hexdigest(),
                             "code": code, "observed_at": time.time()})

    started = fixture.provider.login_count, fixture.provider.sms_count, fixture.provider.identity_count
    base = None
    try:
        first = bridge.request({"method": "pending"})
        checks["framed_desktop_xpc_reaches_enrolled_worker"] = first == {"pending": [], "source_enabled": True}
        checks["unsupported_cookie_import_refused"] = bridge.request({"method": "session-import"}) == {
            "status": "DENIED", "reason": "unsupported_browser_connection_request"
        }
        checks["new_connection_requires_genuine_setup_proof"] = bridge.request({
            "method": "connect", "account": "browser-sms", "fingerprint": "a" * 64,
        }) == {"status": "NEEDS_USER", "reason": "browser_connection_unavailable"}
        # The invalid setup reference retires its desktop connection. A routine
        # enrolled poll must reconnect without acquiring another setup proof.
        checks["routine_poll_reconnects_after_denied_setup"] = bridge.request({"method": "pending"}) == first
        fixture.provider.delivery = deliver
        sent = False
        while not clients.tick():
            current = bridge.request({"method": "pending"})
            pending = current.get("pending")
            if type(pending) is not list or len(pending) > 1:
                raise RuntimeError("browser_fixture_pending_invalid")
            if pending:
                request = pending[0]
                if request.get("source") != "browser-sms":
                    raise RuntimeError("browser_fixture_unrelated_source")
                base = {"source": request["source"], "window": request["window"]}
                if request["phase"] == "baseline":
                    checks["baseline_armed_before_password_submission"] = (
                        fixture.provider.login_count, fixture.provider.sms_count,
                        fixture.provider.identity_count) == started
                    if bridge.request({"method": "armed", **base}) != {"status": "RECEIVED"}:
                        raise RuntimeError("browser_fixture_arm_failed")
                with lock:
                    messages = list(incoming)
                if request["phase"] == "watch" and messages and not sent:
                    message = {"method": "deliver", **base, "messages": messages}
                    def denied(value):
                        return value.get("status") in {"DENIED", "NEEDS_USER"}
                    wrong_window = dict(message, window="0" * 32)
                    wrong_source = dict(message, source="unrelated-source")
                    stale = dict(message, messages=[dict(messages[0], observed_at=0)])
                    checks["wrong_window_delivery_refused"] = denied(bridge.request(wrong_window))
                    checks["unrelated_source_delivery_refused"] = denied(bridge.request(wrong_source))
                    checks["stale_message_delivery_refused"] = denied(bridge.request(stale))
                    response = bridge.request(message)
                    checks["delivery_ack_contains_no_code"] = response == {"status": "RECEIVED"}
                    sent = True
            time.sleep(min(0.05, remaining(deadline)))
        values = clients.values
        checks["fresh_password_identity_sms_login_completed"] = sent and (
            fixture.provider.login_count, fixture.provider.sms_count, fixture.provider.identity_count
        ) == tuple(value + 1 for value in started)
        checks["saved_session_reused_for_second_cli_read"] = len(values) == 2
        checks["cli_returns_only_approved_data_without_code"] = re.search(
            r"\b[0-9]{6}\b", json.dumps(values)
        ) is None
        checks["consumed_window_rejects_replayed_delivery"] = base is not None and bridge.request({
            "method": "deliver", **base, "messages": incoming,
        }).get("status") in {"DENIED", "NEEDS_USER"}
        checks["completed_window_no_longer_pending"] = bridge.request({"method": "pending"}) == first
        process.stdin.close()
        process.wait(timeout=remaining(deadline, 5))
        checks["native_frame_process_exits_cleanly"] = process.returncode == 0
    finally:
        try:
            clients.close()
        finally:
            try:
                stop_process(process)
            finally:
                fixture.provider.delivery = prior_delivery
    if not checks or not all(value is True for value in checks.values()):
        raise RuntimeError("protected_browser_journey_failed")
    return {
        "status": "PASSED", "platform": "macos", "environment": "controlled-demo",
        "production_ready": False, "private_signins": 0,
        "actual_native_framing_used": True, "actual_desktop_connection_used": True,
        "actual_native_xpc_used": True, "production_composed_host_used": True,
        "system_key_used": True, "actual_distinct_uids": True,
        "password_sms_browser_login_verified": True,
        "signed_chrome_parent_verified": False, "actual_chrome_extension_used": False,
        "google_messages_dom_used": False, "physical_sms_delivery_verified": False,
        "genuine_owner_approval_verified": False, "publisher_signed_peers": False,
        "consumer_deployment_verified": False, "checks": checks,
    }
