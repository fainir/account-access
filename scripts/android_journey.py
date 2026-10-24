"""Run the real phone companion on an emulator against the real HTTPS login-code ingress."""

import json
import os
import re
import shlex
import subprocess
import tempfile
import threading
from pathlib import Path

import httpx2 as httpx

from account_access.demo import DEMO_PASSWORD
from account_access.factors import enroll
from account_access.install import install_skill
from account_access.owner import make_owner_server
from account_access.password_import import apply, preview
from account_access.verification_demo import environment, write_password_export


def fixture_acknowledged(output):
    # A successful `am broadcast` process can still have invoked no receiver.
    # Accept only the test receiver's closed acknowledgement, never its extras.
    return isinstance(output, str) and re.search(
        r'^Broadcast completed: result=1, data="fixture_notification_posted"\s*$',
        output, re.MULTILINE) is not None


def main():
    sdk = Path(os.environ.get("ANDROID_SDK_ROOT", os.environ.get("ANDROID_HOME", str(Path.home() / "Library/Android/sdk"))))
    adb = sdk / "platform-tools/adb"
    build = Path("dist/android")
    def command(*args):
        return subprocess.run([str(adb), *args], capture_output=True, text=True, timeout=60, check=True)
    for name in ["Account-Access-Phone-preview.apk", "Account-Access-Phone-tests.apk"]:
        command("install", "-r", str(build / name))
    android_api = int(command("shell", "getprop", "ro.build.version.sdk").stdout.strip())
    if android_api >= 33:
        command("shell", "pm", "grant", "com.fainir.accountaccess.phone.tests", "android.permission.POST_NOTIFICATIONS")
    listener = "com.fainir.accountaccess.phone/com.fainir.accountaccess.LoginNotifications"
    fixture = "com.fainir.accountaccess.phone.tests/com.fainir.accountaccess.NotificationFixture"
    command("shell", "cmd", "notification", "disallow_listener", listener)
    with tempfile.TemporaryDirectory(prefix="aa-phone-", dir="/tmp") as temporary:
        root = Path(temporary)
        with environment(root, relay=True) as (provider, broker, mailbox):
            install_skill(broker.store, "generic", root / "skills")
            server, token = make_owner_server(broker, guided=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                response = httpx.post(base + "/owner/phone/pair", json={"source": "example-sms"},
                     headers={"Authorization": "Bearer " + token, "Origin": base}, trust_env=False)
                assert response.status_code == 200, response.text
                pairing = response.json()
                pairing_path = root / "pairing.json"
                pairing_path.write_text(json.dumps(pairing))
                os.chmod(pairing_path, 0o600)
                command("push", str(pairing_path), "/data/local/tmp/account-access-pairing.json")
                staged = preview(broker.store, write_password_export(root, broker.store.config()).read_text())
                apply(broker, staged["id"], [{"row": "3", "account": "example-sms", "operations": ["summary"]}], ["generic"])
                enroll(broker.store, "example-sms", {})
                results = []
                workers = []
                delivery_diagnostics = []
                def deliver(kind, code):
                    assert kind == "sms"
                    def instrument():
                        process = subprocess.Popen([str(adb), "shell", "am", "instrument", "-w", "-e", "pairing_file", "/data/local/tmp/account-access-pairing.json", "-e", "login_code", code,
                               "com.fainir.accountaccess.phone.tests/com.fainir.accountaccess.LoginChecks"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        output = []
                        timed_out = threading.Event()
                        def stop_instrumentation():
                            timed_out.set()
                            process.kill()
                        deadline = threading.Timer(90, stop_instrumentation)
                        deadline.start()
                        try:
                            for line in process.stdout:
                                output.append(line)
                                if "phase=PAIRING_AND_FILTER_READY" in line:
                                    command("shell", "cmd", "notification", "allow_listener", listener)
                                if "phase=NOTIFICATION_READY" in line:
                                    broadcast = command("shell", shlex.join([
                                        # This is the shell-permission-protected test APK,
                                        # which may still be stopped after installation.
                                        "am", "broadcast", "--include-stopped-packages", "--receiver-foreground", "-n", fixture,
                                        "--es", "sender", pairing["sender"],
                                        "--es", "body", pairing["template"].replace("{code}", code),
                                    ]))
                                    acknowledged = fixture_acknowledged(broadcast.stdout)
                                    delivery_diagnostics.append({"fixture_notification_posted": acknowledged})
                                    assert acknowledged, "Test notification receiver did not acknowledge posting"
                                if "phase=UNRELATED_NOTIFICATION_POSTED" in line:
                                    delivery_diagnostics.append({"unrelated_notification_posted": True})
                            assert process.wait(timeout=30) == 0
                            assert not timed_out.is_set(), "Android instrumentation exceeded 90 seconds"
                        finally:
                            deadline.cancel()
                            if process.poll() is None:
                                process.kill()
                            process.wait(timeout=5)
                            results.append("".join(output))
                    worker = threading.Thread(target=instrument)
                    workers.append(worker)
                    worker.start()
                provider.delivery = deliver
                completed = broker.run("generic", "example-sms", "summary")
                for worker in workers:
                    worker.join(timeout=100)
                    assert not worker.is_alive(), "Android instrumentation did not stop"
                diagnostics = [[line for line in output.splitlines() if "INSTRUMENTATION_RESULT: result=" in line] for output in results]
                if android_api >= 35:
                    assert completed["status"] == "NEEDS_USER" and completed["reason"] == "login_code_not_received", {"result": completed, "instrumentation": diagnostics}
                    assert results and "PASS_BLOCKED:" in results[0], results
                else:
                    assert completed["status"] == "COMPLETED", {"result": completed, "instrumentation": diagnostics,
                                                                 "fixture_delivery": delivery_diagnostics}
                    assert results and "PASS:" in results[0], results
                assert delivery_diagnostics and any(d.get("fixture_notification_posted") is True for d in delivery_diagnostics)
                assert all(all(v is True for v in d.values()) for d in delivery_diagnostics)
                if android_api >= 35:
                    assert any(d.get("unrelated_notification_posted") is True for d in delivery_diagnostics)
                assert provider.sms_count == (0 if android_api >= 35 else 1)
                assert DEMO_PASSWORD not in json.dumps(completed)
                report = {"status": "BLOCKED_AS_EXPECTED" if android_api >= 35 else "COMPLETED",
                          "browser_sms_verifications": provider.sms_count,
                          "android_api": str(android_api),
                          "notification_forwarding_without_association_refused": android_api >= 35,
                          "positive_bluetooth_computer_association_qualified": False,
                          "physical_phone_delivery_qualified": False,
                          "test_notification_posting_acknowledged": True,
                          "blocked_status_preserved_after_unrelated_notification": android_api >= 35,
                          "checks": (["Keystore encrypted pairing", "Legacy QR requests new discovery", "Invalid discovery UUID rejected",
                                      "QR alone cannot grant permission", "Actual Android notification refused without association",
                                      "Unrelated notification preserves blocked login status"]
                                     if android_api >= 35 else
                                     ["Keystore encrypted pairing", "Private destination restriction", "Actual Android notification listener",
                                      "Certificate-pinned HTTPS ingress", "Browser code submission", "No code in agent result"]),
                          "limits": "Synthetic emulator checks only. Android 15 positive Bluetooth pairing and all physical-phone delivery remain unqualified."}
                Path("artifacts/android-journey.json").write_text(json.dumps(report, indent=2) + "\n")
                print(json.dumps(report))
            finally:
                command("shell", "am", "broadcast", "-n", fixture, "--ez", "cancel", "true")
                command("shell", "cmd", "notification", "disallow_listener", listener)
                command("shell", "rm", "-f", "/data/local/tmp/account-access-pairing.json")
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    main()
