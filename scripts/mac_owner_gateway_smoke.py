"""Opt-in Mac native owner-channel acceptance with fictional data and local helpers.

No installed app, vault, authorization rule, login item or OS permission changes.
The setup approval is synthetic; actual Security.framework negative checks and
XPC peer requirements run on this Mac. Publisher signing is optional for CI.
"""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import plistlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

from account_access.demo import environment
from account_access.owner import make_owner_server


SOURCE = Path(__file__).resolve().parents[1]
NATIVE_CHECKS = {
    "health_readiness_deadline_enforced", "invalid_health_timeouts_rejected",
    "worker_generation_retires_live_owner_session", "worker_generation_accepts_new_owner_connection",
    "actual_python_owner_api_reached", "allow_authorization_rule_rejected", "authorization_cannot_survive_disconnect",
    "authorized_authenticator_setup_reached_broker", "authorized_csv_preview_reached_broker",
    "authorized_grant_reached_broker", "bounded_http_framing", "client_rejects_wrong_server_code",
    "closed_channel_refuses_setup_input", "closed_session_cannot_reauthorize", "code_identity_injection_rejected",
    "dedicated_owner_rule_validated", "different_owner_uid_rejected", "ended_setup_cannot_grant",
    "fixture_password_and_seed_not_returned", "fixture_setup_authorized", "fixture_setup_session_authorizes",
    "helper_ran", "legacy_long_lived_delegation_rejected", "owner_capability_never_returned", "prepared",
    "production_peer_requirement_compiles", "reject_boolean_timeout", "reject_browser_handoff_route",
    "reject_chunked_http", "reject_duplicate_http_length", "reject_external_route", "reject_fractional_timeout",
    "reject_http_redirect", "reject_indefinite_auth", "reject_local_install_route", "reject_no_user_auth",
    "reject_non_owner_auth", "reject_numeric_boolean", "reject_oversized_http", "reject_query_route",
    "reject_root_shortcut", "reject_shared_credentials", "reject_traversal_route", "reject_unlimited_tries",
    "revocation_does_not_need_setup_auth", "setup_needs_authorization", "setup_session_expires",
    "short_os_authorization_rejected", "signed_owner_state", "state_read_after_revocation",
    "test_clients_have_distinct_code_hashes", "test_helpers_exited", "unconfigured_or_ungranted_setup_rejected",
    "untrusted_code_cannot_reach_gateway", "untrusted_helper_ran", "hardened_test_peers", "os_authorization_reference_round_trip",
    "host_default_cannot_replace_dedicated_rule",
    "vault_enrollment_requires_setup", "vault_enrollment_rejects_caller_configuration",
    "unapproved_vault_enrollment_refused", "invalid_vault_enrollment_proof_refused",
    "approved_vault_enrollment_uses_typed_authority", "expired_vault_enrollment_refused",
    "closed_vault_enrollment_refused", "vault_enrollment_not_forwarded_to_legacy_backend",
    "prepared_client_rejects_invalid_enrollment_body",
    "saved_login_export_requires_owner_authorization", "saved_login_forget_is_explicit_restricted_action",
    "saved_login_routes_require_exact_account_handle",
    "bitwarden_connect_requires_setup_and_bounded_budget",
    "bitwarden_connect_rejects_invalid_scope_credentials_and_numeric_consent",
    "bitwarden_disconnect_is_restriction_with_normal_budget",
    "bitwarden_exact_item_and_generation_are_validated",
}


@contextmanager
def stalled_health(path):
    """Accept one read-only health request and intentionally send no reply."""
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(8)
    server.settimeout(0.2)
    stopped = threading.Event()
    requests = []

    def serve():
        while not stopped.is_set():
            try:
                peer, _ = server.accept()
            except TimeoutError:
                continue
            with peer:
                peer.settimeout(2)
                try:
                    data = peer.recv(4096)
                    requests.append(data.startswith(b"GET /owner/health HTTP/1.0\r\n"))
                except TimeoutError:
                    requests.append(False)
                stopped.wait(2)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield requests
    finally:
        stopped.set()
        thread.join(timeout=5)
        server.close()
        path.unlink(missing_ok=True)
        assert not thread.is_alive()


def validate_report(value, *, publisher):
    return (isinstance(value, dict) and value.get("status") == "PASSED"
        and value.get("environment") == "controlled-demo" and value.get("platform") == "macos"
        and value.get("production_ready") is False and type(value.get("private_signins")) is int
        and value["private_signins"] == 0 and value.get("publisher_signed_peers") is publisher
        and value.get("real_owner_auth_approval_tested") is False and value.get("root_service_installed") is False
        and isinstance(value.get("checks"), dict) and set(value["checks"]) == NATIVE_CHECKS
        and all(item is True for item in value["checks"].values()))


def command(arguments, *, timeout=120):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout)
    if result.returncode:
        # Compiler diagnostics contain only project code, not fixture inputs.
        if arguments[0] == "xcrun":
            sys.stderr.buffer.write(result.stderr[:12000])
        raise RuntimeError("native_gateway_build_failed")


def build(root, identity):
    app = root / "GatewayChecks.app"
    contents = app / "Contents"
    (contents / "MacOS").mkdir(parents=True, mode=0o700)
    suffix = secrets.token_hex(6)
    bundle_id = "com.fainir.accountaccess.gateway.qa." + suffix
    helpers = []
    for name in ["TrustedProbe", "DeniedProbe"]:
        folder = contents / "XPCServices" / (name + ".xpc") / "Contents"
        (folder / "MacOS").mkdir(parents=True, mode=0o700)
        identifier = bundle_id + "." + name.lower()
        helpers.append(identifier)
        (folder / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": identifier,
            "CFBundleExecutable": "GatewayProbe", "CFBundlePackageType": "XPC!", "CFBundleVersion": "1",
            "XPCService": {"ServiceType": "Application", "RunLoopType": "dispatch_main", "JoinExistingSession": True}}))
        command(["xcrun", "swiftc", "-O", "-parse-as-library", "-D", "ACCOUNT_ACCESS_GATEWAY_CHECKS",
            "-D", "ACCOUNT_ACCESS_GATEWAY_PROBE", "-framework", "Foundation", "-framework", "Security",
            str(SOURCE / "macos/OwnerGateway.swift"), str(SOURCE / "macos/Tests/OwnerGatewayProbe.swift"),
            "-o", str(folder / "MacOS/GatewayProbe")])
        command(["/usr/bin/codesign", "--force", "--options", "runtime", "--identifier", identifier,
                 "--sign", identity or "-", str(folder.parent)])
    (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": bundle_id,
        "CFBundleExecutable": "GatewayChecks", "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "LSUIElement": True}))
    command(["xcrun", "swiftc", "-O", "-parse-as-library", "-D", "ACCOUNT_ACCESS_GATEWAY_CHECKS",
        "-framework", "Foundation", "-framework", "Security", str(SOURCE / "macos/OwnerGateway.swift"),
        str(SOURCE / "macos/Tests/OwnerGatewayProbe.swift"), str(SOURCE / "macos/Tests/OwnerGatewayChecks.swift"),
        "-o", str(contents / "MacOS/GatewayChecks")])
    command(["/usr/bin/codesign", "--force", "--options", "runtime", "--sign", identity or "-", str(app)])
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
    return app, helpers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signing-identity", help="Existing public Developer ID identity label/hash; never a secret")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin" or os.getuid() == 0:
        parser.error("Run as an ordinary Mac user, never root")
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="aa-gateway-", dir="/tmp"))
    # On failure, keep only fictional artifacts for investigation, never replace
    # or restart an installed Account Access instance to make a test pass.
    completed = False
    stage = "build"
    try:
        app, helpers = build(root, args.signing_identity)
        stage = "fixture"
        state = root / "state"
        with environment(state) as (provider, broker, _), stalled_health(root / "health.sock") as health_requests:
            broker.store.new_client("gateway-qa")
            path = str(root / "owner.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(16)
            server, capability = make_owner_server(broker, guided=True, server_socket=listener,
                origin_port=8765, local_host_actions=False)
            parent_handler = server.RequestHandlerClass

            class BufferedHealthHandler(parent_handler):
                def send(self, status, body, kind="application/json"):
                    # Force the real native parser to drain several recv calls
                    # after this HTTP/1.0 response closes. Darwin refuses a new
                    # SO_RCVTIMEO on a closed peer even with buffered data left.
                    if self.path == "/owner/health" and status == 200 and kind == "application/json":
                        body = {**body, "fixture_buffered_response": "x" * 16384}
                    return super().send(status, body, kind)

            server.RequestHandlerClass = BufferedHealthHandler
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stage = "native_xpc"
            try:
                message = {"socket": path, "health_socket": str(root / "health.sock"), "capability": capability, "trusted_service": helpers[0],
                           "denied_service": helpers[1], "login_url": provider.base + "/web/login"}
                result = subprocess.run([str(app / "Contents/MacOS/GatewayChecks")],
                    input=json.dumps(message).encode(), capture_output=True, timeout=240)
                # Raw traces are synthetic but may contain setup payloads. Keep
                # them private; emit only the fixed acceptance report below.
                diagnostics = SOURCE / "artifacts/video/work/private-pilot/mac-owner-gateway" / root.name
                diagnostics.mkdir(parents=True, exist_ok=True, mode=0o700)
                (diagnostics / "stdout.txt").write_bytes(result.stdout)
                (diagnostics / "stderr.txt").write_bytes(result.stderr)
                (diagnostics / "fixture-path.txt").write_text(str(root))
                report = json.loads(result.stdout)
                if result.returncode or report.get("status") != "PASSED":
                    print(json.dumps({"status": "FAILED", "stage": report.get("stage", stage),
                                      "failed_checks": report.get("failed_checks", []), "production_ready": False}))
                    return 1
                assert validate_report(report, publisher=bool(args.signing_identity))
                assert health_requests == [True]  # No write, invalid-timeout I/O or replay.
                assert all(secret not in result.stdout + result.stderr for secret in
                    [capability.encode(), b"controlled-demo-password-only", b"JBSWY3DPEHPK3PXP"])
                assert not provider.login_count  # No browser sign-ins in this owner-channel test.
                with broker.store.db() as database:
                    assert not database.execute("SELECT 1 FROM grants WHERE principal='gateway-qa'").fetchone()
                report["broker_confirmed_revocation"] = True
                report["installed_owner_app_changed"] = False
                report["authorization_database_changed"] = False
                report["consumer_deployment_verified"] = False
                assert report["real_owner_auth_approval_tested"] is False and report["root_service_installed"] is False
                assert report["checks"] and all(item is True for item in report["checks"].values())
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(report, indent=2) + "\n")
                print(json.dumps({"status": "PASSED", "checks": len(report["checks"]),
                                  "publisher_signed_peers": report["publisher_signed_peers"], "production_ready": False}))
                completed = True
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
    except Exception as exc:
        print(json.dumps({"status": "FAILED", "stage": stage, "exception_type": type(exc).__name__, "production_ready": False}))
        return 1
    finally:
        if completed:
            shutil.rmtree(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
