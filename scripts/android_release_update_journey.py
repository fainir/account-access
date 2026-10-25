"""Update only the fictional app on one guarded GitHub-hosted Android emulator.

No physical-device entrypoint, publisher key, real association or network delivery.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "com.fainir.accountaccess.phone"
TESTS = PACKAGE + ".tests"


def require(value):
    if not value:
        raise ValueError("android_update_fixture_refused")


def hosted_guard():
    require(os.getuid() == os.geteuid() != 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ID", "")))


def emulator_serial(output):
    require(type(output) is str and len(output) <= 65536)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    require(len(lines) == 2 and lines[0] == "List of devices attached")
    match = re.fullmatch(r"(emulator-[0-9]{4,5})\s+device(?:\s+[^\r\n]+)?", lines[1])
    require(match is not None)
    return match[1]


def main():
    hosted_guard()  # Before reading fixture paths or invoking ADB.
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=10).decode().strip()
    inputs = ROOT / "dist/android-update-fixture"
    require(inputs.is_dir() and not inputs.is_symlink())
    record = inputs / "inputs.json"
    require(record.is_file() and not record.is_symlink() and record.stat().st_size <= 8192)
    value = json.loads(record.read_bytes())
    require(set(value) == {"schema", "source_commit", "certificate_sha256", "files", "disposable_test_key_only"}
            and value["schema"] == 1 and value["source_commit"] == source and value["disposable_test_key_only"] is True
            and re.fullmatch(r"[a-f0-9]{64}", value["certificate_sha256"])
            and set(value["files"]) == {"version2.apk", "version3.apk", "checks.apk"})
    sdk = Path(os.environ.get("ANDROID_SDK_ROOT", os.environ.get("ANDROID_HOME", "")))
    require(sdk.is_absolute())
    tools = sdk / "build-tools/36.0.0"
    adb = sdk / "platform-tools/adb"

    def command(args, *, checked=True):
        result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=90,
                                stdin=subprocess.DEVNULL, cwd=ROOT, check=False)
        require(len(result.stdout) <= 256 * 1024 and len(result.stderr) <= 65536
                and (not checked or result.returncode == 0))
        return result

    for name, checksum in value["files"].items():
        path = inputs / name
        require(path.is_file() and not path.is_symlink() and 1 <= path.stat().st_size <= 8 * 1024**2)
        with path.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == checksum)
        signed = command([tools / "apksigner", "verify", "--print-certs", path]).stdout
        require(re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([a-f0-9]{64})$", signed, re.M)
                == [value["certificate_sha256"]])
        badging = command([tools / "aapt2", "dump", "badging", path]).stdout
        package = re.findall(r"^package: name='([^']+)' versionCode='([0-9]+)'", badging, re.M)
        require(package == [(TESTS, "1")] if name == "checks.apk" else
                package == [(PACKAGE, "2" if name == "version2.apk" else "3")])
    serial = emulator_serial(command([adb, "devices", "-l"]).stdout)

    def device(*args, checked=True):
        return command([adb, "-s", serial, *args], checked=checked)

    require(device("shell", "getprop", "ro.kernel.qemu").stdout.strip() == "1")
    api = device("shell", "getprop", "ro.build.version.sdk").stdout.strip()
    require(api in {"30", "35"})
    prior = json.loads((ROOT / "artifacts/android-journey.json").read_bytes())
    require(prior["android_api"] == api and prior["physical_phone_delivery_qualified"] is False
            and prior["status"] == ("COMPLETED" if api == "30" else "BLOCKED_AS_EXPECTED"))

    def remove_fictional_apps():
        for package in (TESTS, PACKAGE):
            found = device("shell", "pm", "path", package, checked=False)
            if found.returncode == 0 and found.stdout.startswith("package:"):
                require(device("uninstall", package).stdout.strip() == "Success")

    def uid():
        raw = device("shell", "cmd", "package", "list", "packages", "-U", PACKAGE).stdout
        found = re.findall(r"^package:" + re.escape(PACKAGE) + r" uid:([0-9]+)$", raw, re.M)
        require(len(found) == 1 and int(found[0]) >= 10000)
        return found[0]

    def instrument(phase):
        raw = device("shell", "am", "instrument", "-w", "-e", "phase", phase,
                     TESTS + "/com.fainir.accountaccess.PairingUpgradeChecks").stdout
        expected = "created" if phase == "create" else "preserved"
        require(re.findall(r"^INSTRUMENTATION_RESULT: result=(.+)$", raw, re.M)
                == ["PASS: release_update_pairing_" + expected]
                and re.findall(r"^INSTRUMENTATION_CODE: (-?[0-9]+)$", raw, re.M) == ["-1"])

    try:
        remove_fictional_apps()
        device("install", inputs / "version2.apk")
        device("install", inputs / "checks.apk")
        before_uid = uid()
        instrument("create")
        device("shell", "am", "force-stop", PACKAGE)
        device("install", "-r", inputs / "version3.apk")
        require(uid() == before_uid)
        instrument("verify")
        device("install", "-r", inputs / "version3.apk")
        require(uid() == before_uid)
        instrument("verify")
    finally:
        remove_fictional_apps()
    report = {"schema": 1, "status": "PASSED_EMULATOR_ONLY", "source_commit": source,
              "workflow_run": int(os.environ["GITHUB_RUN_ID"]), "android_api": int(api),
              "certificate_sha256": value["certificate_sha256"], "apk_sha256": value["files"],
              "versions": [2, 3, 3], "normal_android_package_update": True, "same_app_uid": True,
              "keystore_pairing_decrypted_after_update": True, "encrypted_pairing_bytes_unchanged": True,
              "sms_preferences_preserved": True, "same_version_reapply_preserves_pairing": True,
              "physical_device_used": False, "positive_computer_association_tested": False,
              "carrier_sms_tested": False, "publisher_key_used": False, "production_ready": False}
    with (ROOT / f"artifacts/android-update-journey-api{api}.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"status":"REFUSED","reason":"android_update_fixture_not_completed"}')
        raise SystemExit(78) from None
