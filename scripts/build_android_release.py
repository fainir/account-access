"""Build a pinned-signer Android candidate; never install, upload, or create a key.

Passwords are entered without echo in the publisher's terminal and passed only
to the SDK signer environment. Neither passwords nor key files enter artifacts.
"""

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "com.fainir.accountaccess.phone"
ANDROID = "{http://schemas.android.com/apk/res/android}"


def require(value):
    if not value:
        raise ValueError("android_release_refused")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def private_keystore(path):
    require(path.is_absolute() and not path.is_symlink() and not path.is_relative_to(ROOT))
    info, parent = path.lstat(), path.parent.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
            and 1 <= info.st_size <= 1024**2 and stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == os.getuid() and not parent.st_mode & 0o077)
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def release_manifest(raw, code, name):
    require(type(code) is int and 2 <= code <= 2147483647
            and type(name) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?", name)
            and len(name) <= 60 and not any(x in name for x in ("preview", "debug", "test")))
    root = ET.fromstring(raw)
    require(root.tag == "manifest" and root.get("package") == PACKAGE)
    app = root.findall("application")
    require(len(app) == 1 and app[0].get(ANDROID + "debuggable", "false") == "false"
            and app[0].get(ANDROID + "testOnly", "false") == "false"
            and app[0].get(ANDROID + "allowBackup") == "false"
            and app[0].get(ANDROID + "usesCleartextTraffic") == "false")
    root.set(ANDROID + "versionCode", str(code))
    root.set(ANDROID + "versionName", name)
    ET.register_namespace("android", ANDROID[1:-1])
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def certificate(raw, expected):
    require(type(raw) is bytes and len(raw) <= 65536 and re.fullmatch(r"[a-f0-9]{64}", expected))
    text = raw.decode("utf-8")
    hashes = re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]{64})$", text, re.M)
    names = re.findall(r"^Signer #\d+ certificate DN: (.+)$", text, re.M)
    require([value.lower() for value in hashes] == [expected] and len(names) == 1
            and not any(x in names[0].lower() for x in ("development preview", "android debug", "androiddebugkey")))
    return expected


def apk_version(raw):
    require(type(raw) is bytes and len(raw) <= 65536)
    matches = re.findall(rb"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']*)'", raw, re.M)
    require(len(matches) == 1 and matches[0][0].decode() == PACKAGE)
    return int(matches[0][1]), matches[0][2].decode()


def source_names():
    app = ROOT / "android/app"
    require(not (ROOT / "android").is_symlink() and not app.is_symlink()
            and all(not p.is_symlink() for p in app.rglob("*")))
    assets = sorted(p for p in (app / "assets").rglob("*") if p.is_file())
    require([str(p.relative_to(app / "assets")) for p in assets] == ["THIRD_PARTY_NOTICES.txt"])
    names = ["android/build.sh", "android/app/AndroidManifest.xml", "scripts/build_android_release.py",
             *(str(p.relative_to(ROOT)) for p in sorted((app / "src").rglob("*.java"))),
             *(str(p.relative_to(ROOT)) for p in assets)]
    require(all((ROOT / name).is_file() and not (ROOT / name).is_symlink() for name in names))
    return names


def build(args, read_password=getpass.getpass):
    require(os.getuid() == os.geteuid() != 0 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", args.alias)
            and re.fullmatch(r"[a-f0-9]{64}", args.certificate_sha256))
    key = args.keystore.absolute()
    before_key = private_keystore(key)
    names = source_names()
    manifest = release_manifest((ROOT / "android/app/AndroidManifest.xml").read_bytes(), args.version_code, args.version_name)
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=10).decode().strip()
    sources = {name: digest(ROOT / name) for name in names}
    require(all(hashlib.sha256(subprocess.check_output(["git", "show", source + ":" + name], cwd=ROOT, timeout=10)).hexdigest() == checksum
                for name, checksum in sources.items()))
    sdk = Path(os.environ.get("ANDROID_SDK_ROOT", os.environ.get("ANDROID_HOME", str(Path.home() / "Library/Android/sdk"))))
    java = Path(os.environ.get("ACCOUNT_ACCESS_JAVA_HOME", os.environ.get("JAVA_HOME", "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home")))
    tools = sdk / "build-tools/36.0.0"
    require(all(p.is_file() and os.access(p, os.X_OK) for p in (tools / "apksigner", tools / "aapt2", java / "bin/java")))
    env = {key: value for key, value in os.environ.items() if key in {"HOME", "PATH", "LANG", "LC_ALL", "TMPDIR"}}
    env.update(JAVA_HOME=str(java), ACCOUNT_ACCESS_JAVA_HOME=str(java), ANDROID_SDK_ROOT=str(sdk))

    def command(values, *, environment=env, timeout=600):
        result = subprocess.run([str(x) for x in values], cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout, check=False)
        # No exception or tool output is printed or saved: signer errors may
        # contain publisher-specific paths or other signing context.
        require(result.returncode == 0)
        return result.stdout

    previous = None
    if args.previous_apk:
        require(args.previous_apk.is_file() and not args.previous_apk.is_symlink()
                and 1 <= args.previous_apk.stat().st_size <= 64 * 1024**2)
        certificate(command([tools / "apksigner", "verify", "--print-certs", args.previous_apk]), args.certificate_sha256)
        code, _ = apk_version(command([tools / "aapt2", "dump", "badging", args.previous_apk]))
        require(args.version_code > code)
        previous = {"apk_sha256": digest(args.previous_apk), "version_code": code}
    else:
        require(args.initial_release is True)
    require(sys.stdin.isatty())
    output = args.output.absolute()
    require(output.parent.is_dir() and not os.path.lexists(output))
    output.mkdir(mode=0o700)
    (output / "AndroidManifest.xml").write_bytes(manifest)
    env.update(ACCOUNT_ACCESS_ANDROID_OUTPUT=str(output / "build"), ACCOUNT_ACCESS_ANDROID_MANIFEST=str(output / "AndroidManifest.xml"),
               ACCOUNT_ACCESS_ANDROID_UNSIGNED_ONLY="1")
    command(["/bin/sh", ROOT / "android/build.sh"])
    password = read_password("Publisher keystore password (local only): ")
    key_password = read_password("Key password (local only): ") if args.separate_key_password else password
    require(password and key_password and "\x00" not in password + key_password)
    sign_env = {**env, "ACCOUNT_ACCESS_RELEASE_STORE_PASSWORD": password, "ACCOUNT_ACCESS_RELEASE_KEY_PASSWORD": key_password}
    candidate = output / "candidate.apk"
    try:
        require(private_keystore(key) == before_key)
        command([tools / "apksigner", "sign", "--ks", key, "--ks-key-alias", args.alias,
                 "--ks-pass", "env:ACCOUNT_ACCESS_RELEASE_STORE_PASSWORD", "--key-pass", "env:ACCOUNT_ACCESS_RELEASE_KEY_PASSWORD",
                 "--out", candidate, output / "build/aligned.apk"], environment=sign_env)
    finally:
        sign_env.clear()
        password = key_password = ""
    certificate(command([tools / "apksigner", "verify", "--print-certs", candidate]), args.certificate_sha256)
    require(apk_version(command([tools / "aapt2", "dump", "badging", candidate])) == (args.version_code, args.version_name)
            and private_keystore(key) == before_key and all(digest(ROOT / name) == checksum for name, checksum in sources.items()))
    final = output / "Account-Access-Phone.apk"
    candidate.rename(final)
    report = {"schema": 1, "status": "SIGNED_CANDIDATE", "source_commit": source, "source_sha256": sources,
              "package": PACKAGE, "version_code": args.version_code, "version_name": args.version_name,
              "certificate_sha256": args.certificate_sha256, "apk_sha256": digest(final), "apk_bytes": final.stat().st_size,
              "previous": previous, "signing_key_created": False, "signing_key_in_artifacts": False,
              "installed": False, "uploaded": False, "physical_phone_verified": False, "production_ready": False}
    (output / "release-review.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--certificate-sha256", required=True)
    parser.add_argument("--version-code", type=int, required=True)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--separate-key-password", action="store_true")
    history = parser.add_mutually_exclusive_group(required=True)
    history.add_argument("--previous-apk", type=Path)
    history.add_argument("--initial-release", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = build(args)
        print(json.dumps({key: report[key] for key in ("status", "certificate_sha256", "apk_sha256", "version_code")}))
        return 0
    except Exception:
        print('{"status":"REFUSED","reason":"android_release_not_completed"}')
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
