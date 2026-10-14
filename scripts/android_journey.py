"""Run the real phone companion on an emulator against the real HTTPS login-code ingress."""

import json
import os
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


def main():
    sdk = Path(os.environ.get("ANDROID_SDK_ROOT", os.environ.get("ANDROID_HOME", str(Path.home() / "Library/Android/sdk"))))
    adb = sdk / "platform-tools/adb"
    build = Path("dist/android")
    def command(*args):
        return subprocess.run([str(adb), *args], capture_output=True, text=True, timeout=60, check=True)
    for name in ["Account-Access-Phone-preview.apk", "Account-Access-Phone-tests.apk"]:
        command("install", "-r", str(build / name))
    command("shell", "cmd", "notification", "allow_listener", "com.fainir.accountaccess.phone/com.fainir.accountaccess.LoginNotifications")
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
                def deliver(kind, code):
                    assert kind == "sms"
                    def instrument():
                        result = command("shell", "am", "instrument", "-w", "-e", "pairing_file", "/data/local/tmp/account-access-pairing.json", "-e", "login_code", code,
                               "com.fainir.accountaccess.phone.tests/com.fainir.accountaccess.LoginChecks")
                        results.append(result.stdout)
                    worker = threading.Thread(target=instrument)
                    workers.append(worker)
                    worker.start()
                provider.delivery = deliver
                completed = broker.run("generic", "example-sms", "summary")
                for worker in workers:
                    worker.join(timeout=30)
                diagnostics = [[line for line in output.splitlines() if "INSTRUMENTATION_RESULT: result=" in line] for output in results]
                assert completed["status"] == "COMPLETED", {"result": completed, "instrumentation": diagnostics}
                assert provider.sms_count == 1
                assert results and "PASS:" in results[0], results
                assert DEMO_PASSWORD not in json.dumps(completed)
                report = {"status": "COMPLETED", "browser_sms_verifications": provider.sms_count,
                          "android_api": command("shell", "getprop", "ro.build.version.sdk").stdout.strip(),
                          "checks": ["Keystore encrypted pairing", "Private destination restriction",
                                     "Actual Android notification listener", "Certificate-pinned HTTPS ingress",
                                     "Browser code submission", "No code in agent result"],
                          "limits": "Synthetic login notification on an emulator; no physical phone or carrier delivery validated."}
                Path("artifacts/android-journey.json").write_text(json.dumps(report, indent=2) + "\n")
                print(json.dumps(report))
            finally:
                command("shell", "rm", "-f", "/data/local/tmp/account-access-pairing.json")
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    main()
