"""Signing/version gates, plus an explicit SDK-only fixture with no installation."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
RELEASE = runpy.run_path(str(ROOT / "scripts/build_android_release.py"))
MANIFEST = (ROOT / "android/app/AndroidManifest.xml").read_bytes()
PIN = "a" * 64


@pytest.mark.parametrize("code,name", [(1, "0.6.0"), (True, "0.6.0"), (2147483648, "0.6.0"),
    (2, "0.6.0-preview"), (2, "0.6.0-debug"), (2, "0.6.0-test"), (2, "bad"), (2, "0.6.0\n")])
def test_release_version_must_be_explicit_and_non_preview(code, name):
    with pytest.raises(ValueError):
        RELEASE["release_manifest"](MANIFEST, code, name)


@pytest.mark.parametrize("change", [b'android:allowBackup="true"', b'android:usesCleartextTraffic="true"',
                                     b'android:debuggable="true"', b'android:testOnly="true"'])
def test_release_keeps_phone_privacy_settings(change):
    if b"allowBackup" in change:
        raw = MANIFEST.replace(b'android:allowBackup="false"', change)
    elif b"usesCleartextTraffic" in change:
        raw = MANIFEST.replace(b'android:usesCleartextTraffic="false"', change)
    else:
        raw = MANIFEST.replace(b"<application ", b"<application " + change + b" ")
    with pytest.raises(ValueError):
        RELEASE["release_manifest"](raw, 2, "0.6.0")


@pytest.mark.parametrize("text", [
    "Signer #1 certificate SHA-256 digest: " + "b" * 64 + "\nSigner #1 certificate DN: CN=Publisher\n",
    "Signer #1 certificate SHA-256 digest: " + PIN + "\nSigner #1 certificate DN: CN=Account Access development preview\n",
    "Signer #1 certificate SHA-256 digest: " + PIN + "\nSigner #1 certificate DN: CN=Android Debug\n",
    "Signer #1 certificate SHA-256 digest: " + PIN + "\nSigner #1 certificate DN: CN=Publisher\n"
        + "Signer #2 certificate SHA-256 digest: " + PIN + "\nSigner #2 certificate DN: CN=Other\n",
])
def test_release_refuses_wrong_development_or_multiple_signers(text):
    with pytest.raises(ValueError):
        RELEASE["certificate"](text.encode(), PIN)


def test_public_certificate_pin_and_exact_package_are_required():
    raw = f"Signer #1 certificate SHA-256 digest: {PIN}\nSigner #1 certificate DN: CN=Publisher\n".encode()
    assert RELEASE["certificate"](raw, PIN) == PIN
    assert RELEASE["apk_version"](b"package: name='com.fainir.accountaccess.phone' versionCode='2' versionName='0.6.0'\n") == (2, "0.6.0")
    with pytest.raises(ValueError):
        RELEASE["apk_version"](b"package: name='unrelated.application' versionCode='2' versionName='0.6.0'\n")


def test_signing_key_requires_private_single_link_outside_checkout(tmp_path):
    key = tmp_path / "isolated-fixture-key"
    key.write_bytes(b"not a real keystore")
    key.chmod(0o600)
    assert RELEASE["private_keystore"](key)
    key.chmod(0o644)
    with pytest.raises(ValueError):
        RELEASE["private_keystore"](key)
    key.chmod(0o600)
    os.link(key, tmp_path / "second-name")
    with pytest.raises(ValueError):
        RELEASE["private_keystore"](key)


@pytest.mark.skipif(os.environ.get("ACCOUNT_ACCESS_ANDROID_RELEASE_FIXTURE") != "1", reason="explicit JDK/Android SDK signing fixture")
def test_actual_sdk_signs_successive_versions_and_refuses_wrong_pin_or_downgrade(tmp_path, monkeypatch):
    java = Path(os.environ.get("ACCOUNT_ACCESS_JAVA_HOME", os.environ.get("JAVA_HOME", "")))
    assert (java / "bin/keytool").is_file()
    password = "isolated-fixture-password-no-owner-account"
    key = tmp_path / "fixture.jks"
    environment = {"PATH": os.environ["PATH"], "JAVA_HOME": str(java), "AC_ANDROID_FIXTURE_PASSWORD": password}
    subprocess.run([str(java / "bin/keytool"), "-genkeypair", "-keystore", str(key), "-storepass:env", "AC_ANDROID_FIXTURE_PASSWORD",
        "-keypass:env", "AC_ANDROID_FIXTURE_PASSWORD", "-alias", "releasefixture", "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "3650", "-dname", "CN=Account Access isolated signing fixture"],
        env=environment, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=60)
    key.chmod(0o600)
    public = subprocess.check_output([str(java / "bin/keytool"), "-exportcert", "-keystore", str(key),
        "-storepass:env", "AC_ANDROID_FIXTURE_PASSWORD", "-alias", "releasefixture"], env=environment, timeout=30)
    pin = hashlib.sha256(public).hexdigest()
    monkeypatch.setitem(RELEASE["build"].__globals__, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)))

    def args(code, output, previous=None, certificate=pin):
        return SimpleNamespace(keystore=key, alias="releasefixture", certificate_sha256=certificate,
            version_code=code, version_name="0.6.0", output=tmp_path / output,
            previous_apk=previous, initial_release=previous is None, separate_key_password=False)

    first = RELEASE["build"](args(2, "first"), read_password=lambda _: password)
    previous = tmp_path / "first/Account-Access-Phone.apk"
    second = RELEASE["build"](args(3, "second", previous), read_password=lambda _: password)
    for request in (args(2, "downgrade", previous), args(3, "wrong-signer", previous, "0" * 64)):
        with pytest.raises(ValueError):
            RELEASE["build"](request, read_password=lambda _: pytest.fail("invalid release requested a password"))
        assert not request.output.exists()
    assert first["certificate_sha256"] == second["certificate_sha256"] == pin
    assert second["previous"] == {"apk_sha256": first["apk_sha256"], "version_code": 2}
    for folder in (tmp_path / "first", tmp_path / "second"):
        review = (folder / "release-review.json").read_bytes()
        assert password.encode() not in review and not list(folder.rglob("*.jks"))
        assert not list(folder.rglob("*.keystore"))
        assert json.loads(review)["production_ready"] is False
    report = {"schema": 1, "status": "PASSED", "source_commit": second["source_commit"],
        "scope": "actual Android SDK signing fixture; no installed phone or publisher key",
        "versions": [2, 3], "certificate_sha256": pin, "apk_sha256": [first["apk_sha256"], second["apk_sha256"]],
        "same_signer_verified": True, "wrong_signer_refused_before_password": True,
        "non_increasing_version_refused_before_password": True, "key_and_password_absent_from_artifacts": True,
        "publisher_key_used": False, "physical_phone_verified": False, "installed": False, "production_ready": False}
    (ROOT / "dist/android-release-fixture-evidence.json").write_text(json.dumps(report, indent=2) + "\n")
