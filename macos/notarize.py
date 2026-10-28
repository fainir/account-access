"""Maintainer-only, resumable notarization. Credentials stay in a Keychain profile.

This never publishes a GitHub release or modifies the input app/package. `prepare` is
local-only. A successful upload is not a successful notarization or product QA.
"""

import argparse
import fcntl
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

APP_ID = "com.fainir.accountaccess"
ARCHES = {"arm64", "x86_64"}
BACKGROUND = "AccountAccessBackground"
AGENT_PLIST = "com.fainir.accountaccess.background.plist"
BROWSER_EXTENSION = "GoogleMessagesExtension"
BROWSER_FILES = {"manifest.json", "background.js", "reader.js", "popup.js", "popup.html", "popup.css"}
HEX256 = re.compile(r"[a-f0-9]{64}")
TOOLS = {name: "/usr/bin/" + name for name in ["codesign", "lipo", "ditto", "xcrun", "syspolicy_check"]}
TOOLS.update({name: "/usr/sbin/" + name for name in ["pkgutil", "spctl"]})


class ReleaseError(Exception):
    def __init__(self, reason, status="DENIED"):
        self.reason, self.status = reason, status


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def private_file(path, content):
    if path.exists() or path.is_symlink():
        private_check(path)
    fd, name = tempfile.mkstemp(prefix=".release-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def private_check(path, directory=False):
    info = path.lstat()
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not valid_type or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or (not directory and info.st_nlink != 1)):
        raise ReleaseError("unsafe_release_path")


def run_tool(argv, timeout=60):
    if not argv or argv[0] not in TOOLS:
        raise ReleaseError("unsupported_release_tool")
    try:
        return subprocess.run([TOOLS[argv[0]], *argv[1:]], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout,
                              env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except subprocess.TimeoutExpired as exc:
        def decoded(value):
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
        return subprocess.CompletedProcess(argv, 124, decoded(exc.stdout), decoded(exc.stderr))
    except OSError:
        # No exception string: it may contain tool output or local account data.
        raise ReleaseError("tool_unavailable_or_timed_out", "RETRYABLE") from None


def valid_id(value):
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) else None
    except ValueError:
        return None


class Notarization:
    kind = None  # Preserve the original app-state format.
    metadata_key = "app"
    report_key = "bundle"

    def __init__(self, root, runner=run_tool):
        raw = Path(root).expanduser().absolute()
        if raw.is_symlink():
            raise ReleaseError("unsafe_release_path")
        marker = raw / ".account-access-notarization"
        if raw.is_dir() and not marker.exists() and any(raw.iterdir()):
            raise ReleaseError("unrecognized_release_work_directory")
        raw.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = raw.resolve()
        private_check(self.root, directory=True)
        if marker.exists() or marker.is_symlink():
            private_check(marker)
            if marker.read_bytes() != b"account-access-notarization-v1\n":
                raise ReleaseError("unrecognized_release_work_directory")
        else:
            private_file(marker, b"account-access-notarization-v1\n")
        self.runner = runner
        self.app = self.root / "Account Access.app"
        self.archive = self.root / "submission.zip"
        self.output = self.root / "Account-Access-Mac-notarized.zip"
        self.state_path = self.root / "state.json"

    @contextmanager
    def locked(self):
        lock = self.root / ".lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            private_check(lock)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ReleaseError("notarization_already_running", "RETRYABLE") from None
            yield
        finally:
            os.close(fd)

    def tool(self, argv, *, allow_failure=False, timeout=60):
        result = self.runner(argv, timeout=timeout)
        # Logs are private; raw tool errors are never returned in the CLI report.
        private_file(self.root / "last-tool.stdout", result.stdout.encode())
        private_file(self.root / "last-tool.stderr", result.stderr.encode())
        if len(result.stdout) + len(result.stderr) > 4_000_000:
            raise ReleaseError("tool_response_too_large", "NEEDS_REVIEW")
        if result.returncode and not allow_failure:
            stage = ("apple_status_check" if argv[:3] == ["xcrun", "notarytool", "info"] else
                     "apple_log_check" if argv[:3] == ["xcrun", "notarytool", "log"] else
                     "ticket_check" if argv[:2] == ["xcrun", "stapler"] else
                     "distribution_check" if argv[0] in {"syspolicy_check", "spctl"} else
                     "signature_check" if argv[0] in {"codesign", "pkgutil"} else "archive_or_architecture_check")
            raise ReleaseError(stage + "_failed", "RETRYABLE")
        return result

    def read_state(self):
        private_check(self.state_path)
        if self.state_path.stat().st_size > 65536:
            raise ReleaseError("invalid_release_state")
        state = json.loads(self.state_path.read_text())
        if not isinstance(state, dict) or type(state.get("schema")) is not int or state["schema"] != 1:
            raise ReleaseError("invalid_release_state")
        return state

    def load(self):
        state = self.read_state()
        if state.get("kind") != self.kind or not isinstance(state.get(self.metadata_key), dict):
            raise ReleaseError("invalid_release_state")
        return state

    def save(self, state):
        private_file(self.state_path, (json.dumps(state, indent=2) + "\n").encode())

    def app_info(self, app, team):
        if (app.is_symlink() or not app.is_dir() or any(path.is_symlink() for path in app.rglob("*"))
                or not re.fullmatch(r"[A-Z0-9]{10}", team)):
            raise ReleaseError("invalid_app_or_team")
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        if (not isinstance(info.get("CFBundleShortVersionString"), str)
                or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", info["CFBundleShortVersionString"])
                or not isinstance(info.get("CFBundleVersion"), str)
                or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", info["CFBundleVersion"])):
            raise ReleaseError("invalid_bundle_version")
        resources = app / "Contents/Resources"
        background = info.get("AccountAccessBackgroundFormat")
        if background is not None and (type(background) is not int or background != 1):
            raise ReleaseError("unsupported_background_format")
        browser_format = info.get("AccountAccessBrowserExtensionFormat")
        if ("AccountAccessBrowserExtensionFormat" in info
                and (type(browser_format) is not int or browser_format != 1)):
            raise ReleaseError("unsupported_browser_extension_format")
        expected_resources = {"account_access.whl", "install.sh"}
        if browser_format == 1:
            expected_resources.add(BROWSER_EXTENSION)
        executables = {"AccountAccess", BACKGROUND} if background == 1 else {"AccountAccess"}
        if (info.get("CFBundleIdentifier") != APP_ID or info.get("CFBundleExecutable") != "AccountAccess"
                or {path.name for path in resources.iterdir()} != expected_resources
                or {path.name for path in (app / "Contents/MacOS").iterdir()} != executables):
            raise ReleaseError("unexpected_app_contents")
        browser_hashes = None
        if browser_format == 1:
            browser = resources / BROWSER_EXTENSION
            if (not browser.is_dir() or {path.name for path in browser.iterdir()} != BROWSER_FILES
                    or any(not path.is_file() for path in browser.iterdir())):
                raise ReleaseError("unexpected_browser_extension_contents")
            browser_hashes = {name: sha256(browser / name) for name in sorted(BROWSER_FILES)}
        if not os.access(app / "Contents/MacOS/AccountAccess", os.X_OK):
            raise ReleaseError("app_executable_permission_missing")
        wheel = info.get("AccountAccessWheelSHA256", "")
        if not isinstance(wheel, str) or not HEX256.fullmatch(wheel) or sha256(resources / "account_access.whl") != wheel:
            raise ReleaseError("wheel_pin_mismatch")
        hashes = self.code_info(app, app / "Contents/MacOS/AccountAccess", APP_ID, team)
        result = {"identifier": APP_ID, "version": info.get("CFBundleShortVersionString"),
                  "build": info.get("CFBundleVersion"), "team": team, "wheel_sha256": wheel, "cdhashes": hashes}
        if browser_hashes is not None:
            result["browser_extension"] = {"format": 1, "sha256": browser_hashes}
        library = app / "Contents/Library"
        if background == 1:
            agents = library / "LaunchAgents"
            if ({path.name for path in library.iterdir()} != {"LaunchAgents"}
                    or {path.name for path in agents.iterdir()} != {AGENT_PLIST}):
                raise ReleaseError("unexpected_background_contents")
            policy = plistlib.loads((agents / AGENT_PLIST).read_bytes())
            if policy != {"Label": APP_ID + ".background", "BundleProgram": "Contents/MacOS/" + BACKGROUND,
                          "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                          "ThrottleInterval": 10, "ProcessType": "Background"}:
                raise ReleaseError("unsafe_background_restart_policy")
            helper = app / "Contents/MacOS" / BACKGROUND
            if not os.access(helper, os.X_OK):
                raise ReleaseError("background_executable_permission_missing")
            result["background_helper"] = {"cdhashes": self.code_info(helper, helper, APP_ID + ".background", team),
                                           "launch_agent_sha256": sha256(agents / AGENT_PLIST)}
        elif library.exists():
            raise ReleaseError("unexpected_background_contents")
        return result

    def code_info(self, target, executable, identifier, team):
        requirement = ('identifier "' + identifier + '" and anchor apple generic and '
                       'certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
                       'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and '
                       'certificate leaf[subject.OU] = "' + team + '"')
        self.tool(["codesign", "--verify", "--deep", "--strict", "--all-architectures",
                   "-R=" + requirement, str(target)])
        architectures = self.tool(["lipo", "-archs", str(executable)]).stdout.split()
        if set(architectures) != ARCHES:
            raise ReleaseError("universal_app_required")
        hashes = {}
        for arch in sorted(ARCHES):
            signature = self.tool(["codesign", "-d", "--verbose=4", "--arch", arch, str(target)])
            metadata = signature.stdout + signature.stderr
            def field(name):
                match = re.search(r"^" + re.escape(name) + r"=(.+)$", metadata, re.MULTILINE)
                return match[1].strip() if match else ""
            flags = re.findall(r"^CodeDirectory[ \t]+[^\r\n]*\bflags=0x([0-9a-fA-F]+)\b",
                               metadata, re.MULTILINE)
            code_hash = field("CDHash")
            if (field("Identifier") != identifier or field("TeamIdentifier") != team
                    or not re.search(r"^Authority=Developer ID Application:", metadata, re.MULTILINE)
                    or len(flags) != 1 or not int(flags[0], 16) & 0x10000
                    or field("Timestamp") in {"", "none"} or not re.fullmatch(r"[a-f0-9]{40}", code_hash)):
                raise ReleaseError("developer_id_runtime_timestamp_required")
            hashes[arch] = code_hash
        return hashes

    def verify(self, state):
        if self.app_info(self.app, state["app"]["team"]) != state["app"]:
            raise ReleaseError("prepared_app_changed")
        private_check(self.archive)
        if sha256(self.archive) != state["archive_sha256"]:
            raise ReleaseError("submitted_archive_changed")

    def prepare(self, source, team):
        source = Path(source).expanduser().absolute()
        if source.is_symlink() or self.root.is_relative_to(source.resolve()):
            raise ReleaseError("invalid_app_or_work_directory")
        pinned = self.app_info(source, team)
        if self.state_path.exists():
            state = self.load()
            self.verify(state)
            if pinned != state["app"]:
                raise ReleaseError("different_app_already_prepared")
            return self.report(state, cached=True)
        if self.app.exists() or self.archive.exists() or self.output.exists():
            raise ReleaseError("incomplete_prepare_use_new_work_directory")
        shutil.copytree(source, self.app)
        if self.app_info(self.app, team) != pinned:
            raise ReleaseError("app_changed_during_copy")
        self.tool(["ditto", "-c", "-k", "--keepParent", str(self.app), str(self.archive)])
        os.chmod(self.archive, 0o600)
        state = {"schema": 1, "phase": "PREPARED", "app": pinned,
                 "archive_sha256": sha256(self.archive), "submission_id": None}
        self.save(state)
        return self.report(state)

    @staticmethod
    def auth(profile):
        if (not profile or len(profile) > 128 or profile.startswith("-")
                or any(ord(char) < 32 for char in profile)):
            raise ReleaseError("keychain_profile_label_required")
        return ["--keychain-profile", profile]

    def submit(self, profile):
        auth = self.auth(profile)
        state = self.load()
        self.verify(state)
        if state.get("submission_id"):
            return self.check(profile)
        if state["phase"] != "PREPARED":
            receipt = self.root / "upload-receipt.json"
            if state["phase"] == "SUBMISSION_UNKNOWN" and receipt.exists():
                private_check(receipt)
                saved = json.loads(receipt.read_text())
                if (isinstance(saved, dict) and saved.get("archive_sha256") == state["archive_sha256"]
                        and valid_id(saved.get("submission_id"))):
                    state.update(phase="SUBMITTED", submission_id=valid_id(saved["submission_id"]))
                    self.save(state)
                    return self.check(profile)
            raise ReleaseError("submission_outcome_uncertain_adopt_known_id", "NEEDS_REVIEW")
        state["phase"] = "SUBMISSION_UNKNOWN"
        self.save(state)  # Persist uncertainty before any upload, including process interruption.
        try:
            result = self.tool(["xcrun", "notarytool", "submit", str(self.archive), *auth,
                                "--output-format", "json", "--no-wait"], allow_failure=True, timeout=120)
            response = json.loads(result.stdout)
        except (ReleaseError, ValueError, OSError):
            raise ReleaseError("submission_outcome_uncertain_adopt_known_id", "NEEDS_REVIEW") from None
        ident = valid_id(response.get("id")) if isinstance(response, dict) else None
        if not ident:
            raise ReleaseError("submission_outcome_uncertain_adopt_known_id", "NEEDS_REVIEW")
        private_file(self.root / "upload-receipt.json", json.dumps({
            "archive_sha256": state["archive_sha256"], "submission_id": ident}).encode())
        state.update(phase="SUBMITTED", submission_id=ident)
        self.save(state)
        return self.report(state)

    def check(self, profile, *, adopt=None):
        auth = self.auth(profile)
        state = self.load()
        self.verify(state)
        if adopt is not None:
            if state["phase"] not in {"SUBMISSION_UNKNOWN", "ASSOCIATION_FAILED"}:
                raise ReleaseError("adoption_not_needed")
            ident = valid_id(adopt)
        else:
            ident = valid_id(state.get("submission_id"))
        if not ident:
            raise ReleaseError("known_submission_id_required", "NEEDS_REVIEW")
        result = self.tool(["xcrun", "notarytool", "info", ident, *auth, "--output-format", "json"])
        try:
            response = json.loads(result.stdout)
        except ValueError:
            raise ReleaseError("malformed_apple_response", "NEEDS_REVIEW") from None
        if not isinstance(response, dict) or valid_id(response.get("id")) != ident:
            raise ReleaseError("submission_identity_mismatch", "NEEDS_REVIEW")
        status = response.get("status")
        if status not in {"In Progress", "Accepted", "Invalid", "Rejected"}:
            raise ReleaseError("unrecognized_apple_status", "NEEDS_REVIEW")
        if response.get("name") != self.archive.name:
            raise ReleaseError("submission_archive_name_mismatch", "NEEDS_REVIEW")
        state.update(submission_id=ident, phase="SUBMITTED", apple_status=status)
        if status == "In Progress":
            self.save(state)
            return self.report(state)
        log = self.tool(["xcrun", "notarytool", "log", ident, *auth])
        private_file(self.root / "apple-log.json", log.stdout.encode())
        try:
            document = json.loads(log.stdout)
        except ValueError:
            raise ReleaseError("malformed_apple_log", "NEEDS_REVIEW") from None
        if (not isinstance(document, dict) or type(document.get("logFormatVersion")) is not int
                or document["logFormatVersion"] != 1
                or valid_id(document.get("jobId")) != ident or document.get("status") != status
                or document.get("archiveFilename") != self.archive.name
                or document.get("sha256") != state["archive_sha256"]):
            state["phase"] = "ASSOCIATION_FAILED"
            self.save(state)
            raise ReleaseError("apple_log_does_not_match_archive", "NEEDS_REVIEW")
        if status == "Accepted" and (type(document.get("statusCode")) is not int or document["statusCode"] != 0):
            raise ReleaseError("apple_acceptance_not_confirmed", "NEEDS_REVIEW")
        state["phase"] = "ACCEPTED" if status == "Accepted" else "REJECTED"
        self.save(state)
        return self.report(state)

    def finalize(self, profile):
        current = self.check(profile)  # Revalidate the actual job, never trust a cached Accepted flag.
        if current["status"] != "ACCEPTED":
            return current
        state = self.load()
        ticket = self.tool(["xcrun", "stapler", "validate", "-q", str(self.app)], allow_failure=True)
        if ticket.returncode:
            self.tool(["xcrun", "stapler", "staple", "-q", str(self.app)])
        self.tool(["xcrun", "stapler", "validate", "-q", str(self.app)])
        self.verify(state)
        # Require the current policy tool; don't replace a failed assessment
        # with a weaker check or change Gatekeeper/quarantine settings.
        self.tool(["syspolicy_check", "distribution", str(self.app)])
        if self.output.exists():
            private_check(self.output)
            if not state.get("output_sha256") or sha256(self.output) != state["output_sha256"]:
                raise ReleaseError("release_archive_already_exists")
            self.verify_archive(self.output, state)
        else:
            temporary = self.root / "release.tmp.zip"
            if temporary.exists() or temporary.is_symlink():
                private_check(temporary)
                if state.get("output_sha256") and sha256(temporary) != state["output_sha256"]:
                    raise ReleaseError("incomplete_release_archive_needs_review", "NEEDS_REVIEW")
            else:
                self.tool(["ditto", "-c", "-k", "--keepParent", str(self.app), str(temporary)])
                os.chmod(temporary, 0o600)
            self.verify_archive(temporary, state)
            state["output_sha256"] = sha256(temporary)
            state["phase"] = "PACKAGED"
            self.save(state)
            os.replace(temporary, self.output)
        state["phase"] = "READY_FOR_RELEASE_REVIEW"
        self.save(state)
        return self.report(state)

    def verify_archive(self, archive, state):
        """Verify the bytes recipients unpack, including ticket preservation."""
        with zipfile.ZipFile(archive) as source:
            entries = source.infolist()
            if len(entries) > 5000 or sum(entry.file_size for entry in entries) > 512 * 1024 * 1024:
                raise ReleaseError("release_archive_too_large")
            names = set()
            for entry in entries:
                parts = PurePosixPath(entry.filename).parts
                allowed = bool(parts) and (parts[0] == self.app.name or
                    (parts[0] == "__MACOSX" and (len(parts) == 1 or parts[1] in {self.app.name, "._" + self.app.name})))
                if (not allowed or ".." in parts or "\\" in entry.filename or "\x00" in entry.orig_filename
                        or entry.filename in names or stat.S_ISLNK(entry.external_attr >> 16)):
                    raise ReleaseError("unexpected_release_archive_contents")
                names.add(entry.filename)
            if source.testzip() is not None:
                raise ReleaseError("release_archive_crc_failed")
        with tempfile.TemporaryDirectory(prefix=".unpack-", dir=self.root) as location:
            self.tool(["ditto", "-x", "-k", str(archive), location])
            if {path.name for path in Path(location).iterdir()} - {self.app.name, "__MACOSX"}:
                raise ReleaseError("unexpected_release_archive_contents")
            unpacked = Path(location) / self.app.name
            if self.app_info(unpacked, state["app"]["team"]) != state["app"]:
                raise ReleaseError("packaged_app_changed")
            self.tool(["xcrun", "stapler", "validate", "-q", str(unpacked)])
            self.tool(["syspolicy_check", "distribution", str(unpacked)])

    def report(self, state, *, cached=False):
        result = {"status": "CACHED_STATE" if cached else state["phase"], "submission_id": state.get("submission_id"),
                  "apple_status": state.get("apple_status"), self.report_key: state[self.metadata_key],
                  "archive_sha256": state["archive_sha256"], "production_qa": "not_evaluated"}
        if cached:
            result["cached_phase"] = state["phase"]
        elif state["phase"] == "READY_FOR_RELEASE_REVIEW":
            result.update(artifact=str(self.output), sha256=state["output_sha256"],
                          ticket_and_distribution_check="passed_on_this_mac")
        return result


class PackageNotarization(Notarization):
    """Notarize the complete signed flat installer, without installing it.

    Keep the submitted bytes immutable. Stapling operates on a separate copy;
    the entire original archive must remain its unchanged prefix. Only Apple's
    validated ticket may be appended, with a bounded size allowance.
    """
    kind = "flat-installer-v1"
    metadata_key = "package"
    report_key = "package"
    max_package = 4 * 1024 * 1024 * 1024
    max_ticket = 16 * 1024 * 1024

    def __init__(self, root, runner=run_tool):
        super().__init__(root, runner)
        self.archive = self.root / "submission.pkg"
        self.output = self.root / "Account-Access-arm64-notarized.pkg"

    def package_info(self, package, team):
        if (not isinstance(team, str) or not re.fullmatch(r"[A-Z0-9]{10}", team)
                or any(path.is_symlink() for path in [package, *package.parents])):
            raise ReleaseError("invalid_package_or_team")
        info = package.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o022
                or not 4 <= info.st_size <= self.max_package + self.max_ticket):
            raise ReleaseError("unsafe_package_input")
        with package.open("rb") as stream:
            if stream.read(4) != b"xar!":
                raise ReleaseError("signed_flat_package_required")
        signed = self.tool(["pkgutil", "--check-signature", str(package)], allow_failure=True)
        text = signed.stdout + signed.stderr
        statuses = re.findall(r"^[ \t]*Status:[ \t]*(.+)$", text, re.MULTILINE)
        trusted = {"signed by a developer certificate issued by Apple for distribution",
                   "signed by a certificate trusted by macOS", "signed by a certificate trusted by Mac OS X"}
        leaf = re.search(r"^[ \t]*1\.[ \t]+Developer ID Installer:[^\r\n]+ \(([A-Z0-9]{10})\)[ \t]*$",
                         text, re.MULTILINE)
        timestamp = re.findall(r"^[ \t]*Signed with a trusted timestamp on:[ \t]*(.+)$", text, re.MULTILINE)
        if (signed.returncode or len(statuses) != 1 or statuses[0].strip() not in trusted
                or leaf is None or leaf[1] != team or len(timestamp) != 1 or not timestamp[0].strip()):
            raise ReleaseError("developer_id_installer_team_timestamp_required")
        # Bind the first certificate, not a later chain entry or an arbitrary
        # matching certificate name somewhere in diagnostic text.
        block = re.split(r"^[ \t]*2\.", text[leaf.end():], maxsplit=1, flags=re.MULTILINE)[0]
        fingerprint = re.search(r"SHA256 Fingerprint:[ \t\r\n]*([a-fA-F0-9: \t\r\n]+)", block)
        checksum = re.sub(r"[\s:]", "", fingerprint[1]).lower() if fingerprint else ""
        if not HEX256.fullmatch(checksum):
            raise ReleaseError("installer_certificate_fingerprint_required")
        return {"team": team, "certificate_sha256": checksum, "trusted_timestamp": timestamp[0].strip()}

    def load(self):
        state = super().load()
        metadata = state["package"]
        if (not isinstance(metadata.get("team"), str) or not re.fullmatch(r"[A-Z0-9]{10}", metadata["team"])
                or not isinstance(metadata.get("certificate_sha256"), str)
                or not HEX256.fullmatch(metadata["certificate_sha256"])
                or not isinstance(metadata.get("trusted_timestamp"), str) or not metadata["trusted_timestamp"]
                or not isinstance(state.get("archive_sha256"), str) or not HEX256.fullmatch(state["archive_sha256"])
                or type(state.get("archive_bytes")) is not int or not 4 <= state["archive_bytes"] <= self.max_package
                or state.get("phase") not in {"PREPARED", "SUBMISSION_UNKNOWN", "SUBMITTED", "ASSOCIATION_FAILED",
                                              "ACCEPTED", "REJECTED", "PACKAGED", "READY_FOR_RELEASE_REVIEW"}):
            raise ReleaseError("invalid_release_state")
        return state

    def verify(self, state):
        private_check(self.archive)
        if (self.archive.stat().st_size != state["archive_bytes"]
                or sha256(self.archive) != state["archive_sha256"]):
            raise ReleaseError("submitted_archive_changed")
        if self.package_info(self.archive, state["package"]["team"]) != state["package"]:
            raise ReleaseError("prepared_package_changed")

    def prepare(self, source, team):
        source = Path(source).expanduser().absolute()
        if self.root.is_relative_to(source.resolve()) or source.stat().st_size > self.max_package:
            raise ReleaseError("invalid_package_or_work_directory")
        pinned = self.package_info(source, team)
        digest = sha256(source)
        if self.state_path.exists():
            state = self.load()
            self.verify(state)
            if digest != state["archive_sha256"] or pinned != state["package"]:
                raise ReleaseError("different_package_already_prepared")
            return self.report(state, cached=True)
        if any(path.exists() or path.is_symlink() for path in [self.archive, self.output]):
            raise ReleaseError("incomplete_prepare_use_new_work_directory")
        shutil.copyfile(source, self.archive)
        os.chmod(self.archive, 0o600)
        if sha256(self.archive) != digest or self.package_info(self.archive, team) != pinned:
            raise ReleaseError("package_changed_during_copy")
        state = {"schema": 1, "kind": self.kind, "phase": "PREPARED", "package": pinned,
                 "archive_sha256": digest, "archive_bytes": self.archive.stat().st_size, "submission_id": None}
        self.save(state)
        return self.report(state)

    def verify_copy(self, package, state):
        private_check(package)
        if not state["archive_bytes"] <= package.stat().st_size <= state["archive_bytes"] + self.max_ticket:
            raise ReleaseError("stapled_package_size_invalid")
        remaining = state["archive_bytes"]
        with self.archive.open("rb") as original, package.open("rb") as stapled:
            while remaining:
                size = min(1024 * 1024, remaining)
                before, after = original.read(size), stapled.read(size)
                if len(before) != size or before != after:
                    raise ReleaseError("stapled_package_content_changed")
                remaining -= size
        if self.package_info(package, state["package"]["team"]) != state["package"]:
            raise ReleaseError("stapled_package_signature_changed")
        extra = package.stat().st_size - state["archive_bytes"]
        if extra:
            # Apple's package_trailer_t is a 16-byte little-endian record on
            # supported Macs. Fresh stapling adds a terminator, ticket data and
            # ticket trailer. Bind both frames to the original archive boundary;
            # native ticket validation alone need not reject unrelated padding.
            if extra <= 32:
                raise ReleaseError("stapled_package_framing_invalid")
            with package.open("rb") as stream:
                stream.seek(state["archive_bytes"])
                start = struct.unpack("<4sHHI4s", stream.read(16))
                stream.seek(-16, os.SEEK_END)
                end = struct.unpack("<4sHHI4s", stream.read(16))
            if (start != (b"t8lr", 1, 1, 0, b"\0" * 4)
                    or end != (b"t8lr", 1, 2, extra - 32, b"\0" * 4)):
                raise ReleaseError("stapled_package_framing_invalid")

    def verify_output(self, package, state):
        self.verify_copy(package, state)
        self.tool(["xcrun", "stapler", "validate", "-q", str(package)])
        self.tool(["spctl", "--assess", "--type", "install", "--ignore-cache", "--no-cache", str(package)])

    def finalize(self, profile):
        current = self.check(profile)
        if current["status"] != "ACCEPTED":
            return current
        state = self.load()
        if self.output.exists() or self.output.is_symlink():
            private_check(self.output)
            if not state.get("output_sha256") or sha256(self.output) != state["output_sha256"]:
                raise ReleaseError("release_archive_already_exists")
            self.verify_output(self.output, state)
        else:
            temporary = self.root / "release.tmp.pkg"
            if temporary.exists() or temporary.is_symlink():
                private_check(temporary)
                if state.get("output_sha256") and sha256(temporary) != state["output_sha256"]:
                    raise ReleaseError("incomplete_release_archive_needs_review", "NEEDS_REVIEW")
            else:
                shutil.copyfile(self.archive, temporary)
                os.chmod(temporary, 0o600)
            self.verify_copy(temporary, state)
            ticket = self.tool(["xcrun", "stapler", "validate", "-q", str(temporary)], allow_failure=True)
            if ticket.returncode:
                self.tool(["xcrun", "stapler", "staple", "-q", str(temporary)])
            self.verify(state)
            self.verify_output(temporary, state)
            state.update(output_sha256=sha256(temporary), phase="PACKAGED")
            self.save(state)
            os.replace(temporary, self.output)
        state["phase"] = "READY_FOR_RELEASE_REVIEW"
        self.save(state)
        return self.report(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "submit", "check", "adopt", "finalize", "status"])
    parser.add_argument("--workdir", type=Path, required=True)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--app", type=Path)
    inputs.add_argument("--package", type=Path, help="Signed flat installer, not an unsigned review package")
    parser.add_argument("--team-id")
    parser.add_argument("--profile", help="Existing Keychain profile label, never an app password")
    parser.add_argument("--submission-id", help="Known Apple job ID for an uncertain upload")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if sys.platform != "darwin":
            raise ReleaseError("macos_publisher_required")
        if args.action == "prepare":
            source = args.package if args.package is not None else args.app
            if source is None or args.team_id is None:
                raise ReleaseError("app_and_expected_team_required")
            if args.workdir.expanduser().resolve().is_relative_to(source.expanduser().resolve()):
                raise ReleaseError("invalid_app_or_work_directory")
        if args.action == "prepare" and args.package is not None:
            task = PackageNotarization(args.workdir)
        else:
            task = Notarization(args.workdir)
            if args.action != "prepare" and task.read_state().get("kind") == PackageNotarization.kind:
                task = PackageNotarization(args.workdir)
        with task.locked():
            if args.action == "prepare":
                result = task.prepare(source, args.team_id)
            elif args.action == "status":
                result = task.report(task.load(), cached=True)
            elif args.action == "submit":
                result = task.submit(args.profile)
            elif args.action == "check":
                result = task.check(args.profile)
            elif args.action == "adopt":
                if args.submission_id is None:
                    raise ReleaseError("known_submission_id_required", "NEEDS_REVIEW")
                result = task.check(args.profile, adopt=args.submission_id)
            else:
                result = task.finalize(args.profile)
        print(json.dumps(result, indent=2))
        return 1 if result["status"] in {"REJECTED", "ASSOCIATION_FAILED"} else 0
    except ReleaseError as exc:
        print(json.dumps({"status": exc.status, "reason": exc.reason}))
        return 1
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        print(json.dumps({"status": "DENIED", "reason": "invalid_or_incomplete_release_state"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
