"""Opt-in hosted Mac VM only: unchanged publisher binaries, before enrollment.

Never invoke the privileged mode on a personal Mac. This installs only a
hash-pinned public review image into an otherwise empty disposable VM. It does
not enroll a vault, obtain approval, connect an account or send a login code.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import pwd
import grp
import re
import runpy
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import zipfile

REPOSITORY = "fainir/account-access"
TEAM = "WBULD6N4NQ"
SOURCE = Path(__file__).resolve().parents[1]
BASE = Path("/Library/Application Support/Account Access")
APP = BASE / "owner.app"
PUBLIC_APP = Path("/Applications/Account Access.app")
APPLICATION_TARGET = "../Library/Application Support/Account Access/owner.app"
JOB = Path("/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist")
LABEL = "com.fainir.accountaccess.broker"
RIGHT = "com.fainir.accountaccess.owner-enrollment.v1"
EXTENSION = "nidjfmpcbbneapibefbhniaiijgigofo"
ORIGIN = "chrome-extension://" + EXTENSION + "/"
RESOURCES = {"manifest.json", "background.js", "reader.js", "popup.js", "popup.html", "popup.css"}
CHROME = Path("/Applications/Google Chrome.app")
MAX_ARCHIVE = 2 * 1024**3
MAX_IMAGE = 8 * 1024**3
ENV_KEYS = {"GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_SHA",
            "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "CI"}


class ReviewError(Exception):
    pass


def require(value, reason):
    if not value:
        raise ReviewError(reason)


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_review_field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def guard(*, root, environment=None, system=None, machine=None, uid=None, euid=None):
    environment = os.environ if environment is None else environment
    require((system or sys.platform) == "darwin" and (machine or platform.machine()) == "arm64",
            "hosted_arm64_mac_required")
    require(environment.get("GITHUB_ACTIONS") == "true" and environment.get("CI") == "true"
            and environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and environment.get("RUNNER_OS") == "macOS" and environment.get("RUNNER_ARCH") == "ARM64"
            and environment.get("GITHUB_REPOSITORY") == REPOSITORY
            and re.fullmatch(r"[0-9]+", environment.get("GITHUB_RUN_ID", ""))
            and re.fullmatch(r"[a-f0-9]{40}", environment.get("GITHUB_SHA", "")), "hosted_review_only")
    uid, euid = (os.getuid() if uid is None else uid), (os.geteuid() if euid is None else euid)
    require(uid == euid and (uid == 0) == root, "review_identity_invalid")


def environment(home=None):
    result = {key: os.environ[key] for key in ENV_KEYS if key in os.environ}
    result.update(PATH="/usr/bin:/bin:/usr/sbin:/sbin", LANG="en_US.UTF-8")
    if home is not None:
        result.update(HOME=str(home), TMPDIR=str(Path(home) / "tmp"))
    return result


def command(arguments, *, timeout=25, check=True, env=None, **kwargs):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout, close_fds=True,
                            env=environment() if env is None else env, **kwargs)
    require(len(result.stdout) + len(result.stderr) <= 1_000_000, "review_command_output_limit")
    if check:
        require(result.returncode == 0, "review_command_failed")
    return result


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_inputs(source, sha):
    require(type(source) is str and re.fullmatch(r"[a-f0-9]{40}", source)
            and type(sha) is str and re.fullmatch(r"[a-f0-9]{64}", sha), "invalid_review_inputs")


def download(args):
    """Read a same-repository draft asset before any privileged VM changes."""
    validate_inputs(args.source, args.sha256)
    require(os.getuid() != 0 and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY,
            "ordinary_ci_download_required")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", args.tag)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.tar\.gz", args.asset)
            and args.asset_id > 0 and args.release_id > 0, "invalid_review_asset")
    env = dict(os.environ)
    response = command(["gh", "api", "repos/" + REPOSITORY + "/releases/" + str(args.release_id)], env=env, check=False)
    require(response.returncode == 0, "review_draft_metadata_unavailable")
    metadata = unique_json(response.stdout)
    require(metadata.get("id") == args.release_id and metadata.get("tag_name") == args.tag
            and metadata.get("draft") is True and metadata.get("target_commitish") == args.source,
            "review_draft_source_mismatch")
    matches = [item for item in metadata.get("assets", []) if item.get("id") == args.asset_id]
    require(len(matches) == 1 and matches[0].get("name") == args.asset
            and matches[0].get("digest") == "sha256:" + args.sha256
            and type(matches[0].get("size")) is int and 0 < matches[0]["size"] <= MAX_ARCHIVE,
            "review_asset_metadata_mismatch")
    output = Path(args.output)
    require(not output.exists() and not output.is_symlink(), "review_download_already_exists")
    with output.open("xb") as target:
        result = subprocess.run(["gh", "api", "repos/" + REPOSITORY + "/releases/assets/" + str(args.asset_id),
                                 "-H", "Accept: application/octet-stream"], stdout=target, stderr=subprocess.DEVNULL,
                                timeout=240, env=env, close_fds=True)
    require(result.returncode == 0 and output.stat().st_size == matches[0]["size"]
            and digest(output) == args.sha256, "review_download_hash_mismatch")
    print(json.dumps({"status": "DOWNLOADED", "asset_id": args.asset_id, "sha256": args.sha256,
                      "source_revision": args.source, "draft": True}))


def contract(review_raw, manifest_raw, expected_source):
    from account_access.install_image import ImageManifest
    review = unique_json(review_raw)
    require(type(review) is dict and set(review) == {"managed_by", "schema", "source_revision", "architecture",
            "publisher_team", "image_manifest_sha256"} and review["managed_by"] == "account-access-publisher-transport-review-v1"
            and type(review["schema"]) is int and review["schema"] == 1
            and review["source_revision"] == expected_source and review["architecture"] == "arm64"
            and review["publisher_team"] == TEAM
            and review["image_manifest_sha256"] == hashlib.sha256(manifest_raw).hexdigest(),
            "review_contract_mismatch")
    ImageManifest(manifest_raw, review["image_manifest_sha256"])
    manifest = unique_json(manifest_raw)
    require(manifest["architecture"] == "arm64", "review_architecture_mismatch")
    support = manifest["roots"][str(BASE)]
    require({name.split("/")[0] for name in support if name} == {"runtime", "browsers", "bin", "owner.app"}
            and {name for name in support if name.startswith("bin/")} == {
                "bin/AccountAccess-broker", "bin/AccountAccess-bootstrap"}
            and manifest["roots"][str(PUBLIC_APP)] == {"": {"kind": "symlink", "target": APPLICATION_TARGET}},
            "review_contains_nonpublic_state")
    return review, manifest


def archive_nodes(manifest):
    nodes = {"review.json": {"kind": "file"}, "image-manifest.json": {"kind": "file"}}
    for root, children in manifest["roots"].items():
        for name, node in children.items():
            path = "payload" + root + ("/" + name if name else "")
            nodes[path] = node
            parent = PurePosixPath(path).parent
            while str(parent) != ".":
                nodes.setdefault(str(parent), {"kind": "directory", "mode": 0o755})
                parent = parent.parent
    return nodes


def inspect_archive(archive, expected_source):
    members = archive.getmembers()
    require(1 <= len(members) <= 100_100, "review_archive_entry_limit")
    indexed, total = {}, 0
    for member in members:
        name = member.name.rstrip("/")
        parts = PurePosixPath(name).parts
        require(name and not name.startswith("/") and len(name.encode()) <= 4096
                and "\\" not in name and ":" not in name and ".." not in parts
                and not any(ord(char) < 32 or ord(char) == 127 for char in name)
                and str(PurePosixPath(name)) == name and name not in indexed
                and (member.isdir() or member.isreg() or member.issym()) and not member.issparse()
                and (member.issym() or member.mode & 0o7022 == 0), "unsafe_review_archive_entry")
        require(member.size <= 1024**3 and member.size >= 0, "review_archive_size_limit")
        total += member.size
        require(total <= MAX_IMAGE, "review_archive_size_limit")
        indexed[name] = member
    for name in ["review.json", "image-manifest.json"]:
        require(name in indexed and indexed[name].isreg() and indexed[name].size <= 16 * 1024**2,
                "review_metadata_missing")
    review_raw = archive.extractfile(indexed["review.json"]).read()
    manifest_raw = archive.extractfile(indexed["image-manifest.json"]).read()
    _, manifest = contract(review_raw, manifest_raw, expected_source)
    nodes = archive_nodes(manifest)
    require(set(indexed) == set(nodes), "review_archive_inventory_mismatch")
    for name, member in indexed.items():
        node = nodes[name]
        kind = "directory" if member.isdir() else "symlink" if member.issym() else "file"
        require(kind == node["kind"], "review_archive_inventory_mismatch")
        if kind == "symlink":
            require(member.linkname == node["target"], "review_archive_alias_mismatch")
        elif name not in {"review.json", "image-manifest.json"}:
            require(member.mode == node["mode"] and (kind != "file" or member.size == node["size"]),
                    "review_archive_inventory_mismatch")
    return indexed, nodes, manifest_raw


def extract_review(path, target, expected_source):
    from account_access.package_manifest import build
    with tarfile.open(path, "r:gz") as archive:
        indexed, nodes, manifest_raw = inspect_archive(archive, expected_source)
        # Parents are created before regular files, aliases only after all
        # writes. No archive-selected ownership, hard link, ACL or xattr is used.
        for name in sorted(nodes, key=lambda item: (len(PurePosixPath(item).parts), item)):
            if nodes[name]["kind"] == "directory":
                (target / name).mkdir(mode=nodes[name]["mode"])
        for name, member in indexed.items():
            node = nodes[name]
            if node["kind"] == "file":
                with archive.extractfile(member) as incoming, (target / name).open("xb") as output:
                    shutil.copyfileobj(incoming, output, 1024 * 1024)
                os.chmod(target / name, node.get("mode", 0o644))
            elif node["kind"] == "symlink":
                os.symlink(node["target"], target / name)
    require(build(target / "payload", "0.8.0", "arm64") == manifest_raw, "review_image_hash_mismatch")


def git_file(revision, name):
    return git(["show", revision + ":" + name]).stdout


def git(arguments):
    # This one trusted checkout is the entire exception. Do not write a
    # root/global Git config or trust any other runner-owned directory.
    return command(["/usr/bin/git", "-c", "safe.directory=" + str(SOURCE), "-C", str(SOURCE), *arguments])


def verify_source(payload, revision):
    files = git(["ls-tree", "-r", "--name-only", revision, "account_access", "macos"]).stdout.decode().splitlines()
    package = {name for name in files if name.startswith("account_access/")}
    native = {name for name in files if name.startswith("macos/") and not name.startswith("macos/Tests/")
              and Path(name).suffix in {".swift", ".h", ".c"}}
    current = git(["ls-tree", "-r", "--name-only", "HEAD", "account_access", "macos"]).stdout.decode().splitlines()
    require(package == {name for name in current if name.startswith("account_access/")}
            and native == {name for name in current if name.startswith("macos/") and not name.startswith("macos/Tests/")
                           and Path(name).suffix in {".swift", ".h", ".c"}}, "review_source_tree_changed")
    for name in sorted(package | native | {"install.sh", "pyproject.toml", "uv.lock"}):
        require(git_file(revision, name) == git_file("HEAD", name), "review_source_tree_changed")
    app = payload / APP.relative_to("/")
    support = payload / BASE.relative_to("/")
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    wheel = app / "Contents/Resources/account_access.whl"
    require(info.get("CFBundleIdentifier") == "com.fainir.accountaccess"
            and info.get("AccountAccessSystemInstallationRequired") is True
            and info.get("AccountAccessWheelSHA256") == digest(wheel), "review_app_wheel_mismatch")
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist() if name.startswith("account_access/") and not name.endswith("/")]
        require(len(names) == len(set(names)) and set(names) == package, "review_package_files_mismatch")
        for name in names:
            require(archive.read(name) == git_file(revision, name), "review_package_source_mismatch")
    roots = list((support / "runtime/lib").glob("python*/site-packages/account_access"))
    require(len(roots) == 1, "review_runtime_package_missing")
    for name in package:
        require((roots[0] / name.removeprefix("account_access/")).read_bytes() == git_file(revision, name),
                "review_runtime_source_mismatch")
    for name in RESOURCES:
        require((app / "Contents/Resources/GoogleMessagesExtension" / name).read_bytes()
                == git_file(revision, "account_access/google_messages_extension/" + name), "review_extension_source_mismatch")
    require((app / "Contents/Resources/install.sh").read_bytes() == git_file(revision, "install.sh"),
            "review_installer_source_mismatch")


def authorization():
    result = command(["/usr/bin/security", "authorizationdb", "read", RIGHT], check=False)
    if result.returncode != 0:
        require(not result.stdout and b"(-60005)" in result.stderr, "authorization_lookup_failed")
        return None
    return plistlib.loads(result.stdout)


def exact_rule(value, designated):
    metadata = {"comment", "created", "modified", "version", "description", "default-prompt", "identifier", "requirement"}
    expected = {"class": "user", "session-owner": True, "authenticate-user": True,
                "allow-root": False, "shared": False, "timeout": 30, "tries": 3}
    return (type(value) is dict and value.get("identifier") == LABEL and value.get("requirement") == designated
            and {key: item for key, item in value.items() if key not in metadata} == expected
            and all(type(value.get(key)) is bool for key in ["session-owner", "authenticate-user", "allow-root", "shared"])
            and type(value.get("timeout")) is int and type(value.get("tries")) is int)


def fresh_owner_identity():
    for _ in range(100):
        uid = 50000 + secrets.randbelow(10000)
        name = "aap" + secrets.token_hex(6)
        for lookup, value in [(pwd.getpwuid, uid), (grp.getgrgid, uid),
                              (pwd.getpwnam, name), (grp.getgrnam, name)]:
            try:
                lookup(value)
            except KeyError:
                continue
            break
        else:
            return uid, name
    raise ReviewError("fresh_review_identity_unavailable")


def uid_processes(uid):
    require(type(uid) is int and 450 <= uid < 60000, "cleanup_identity_invalid")
    rows = command(["/bin/ps", "-Ao", "pid=,uid="]).stdout.decode().splitlines()
    result = []
    for row in rows:
        fields = row.split()
        require(len(fields) == 2 and all(item.isdecimal() for item in fields), "cleanup_process_query_invalid")
        if int(fields[1]) == uid:
            result.append(int(fields[0]))
    return result


def stop_uid(uid):
    if not uid_processes(uid):
        return
    command(["/usr/bin/pkill", "-TERM", "-u", str(uid)], check=False)
    started = time.monotonic()
    killed = False
    while time.monotonic() - started < 5:
        if not uid_processes(uid):
            return
        if not killed and time.monotonic() - started >= 1:
            command(["/usr/bin/pkill", "-KILL", "-u", str(uid)], check=False)
            killed = True
        time.sleep(0.1)
    require(not uid_processes(uid), "cleanup_processes_still_running")


def public_parent_metadata(parents):
    observations = {}
    for label, path in parents:
        try:
            info = path.lstat()
            observations[label] = {"present": True, "owner_uid": info.st_uid,
                                   "mode": stat.S_IMODE(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode)}
        except FileNotFoundError:
            observations[label] = {"present": False}
    return observations


def shared_parent_metadata_valid(info):
    return stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o7002 == 0


def child(config_path):
    guard(root=False)
    from account_access.browser_setup import prepare
    from account_access.worker_bootstrap import root_managed_path
    from playwright.sync_api import sync_playwright
    path = root_managed_path(config_path)
    config = unique_json(path.read_bytes())
    user = pwd.getpwuid(os.getuid())
    home = Path(user.pw_dir)
    require(set(config) == {"owner_uid", "home", "prefix"} and config["owner_uid"] == os.getuid()
            and config["home"] == str(home) and home == Path(config["prefix"]) / "owner-home"
            and re.fullmatch(r"/Library/Application Support/account-access-publisher-qa-[a-f0-9]{16}", config["prefix"]),
            "review_child_identity_mismatch")
    require(set(home.iterdir()) == {home / "tmp"}, "review_owner_home_not_empty")
    prepared = prepare(home)
    require(prepared["extension_path"] == str(APP / "Contents/Resources/GoogleMessagesExtension")
            and prepared["extension_id"] == EXTENSION, "production_browser_setup_failed")
    launcher = home / "Library/Application Support/Account Access/browser-v1/native-host"
    negative = command([str(launcher), ORIGIN], timeout=10, check=False, env=environment(home), input=b"")
    require(negative.returncode == 78 and negative.stdout == b"", "production_parent_guard_failed")
    hashes = {name: digest(APP / "Contents/Resources/GoogleMessagesExtension" / name) for name in RESOURCES}
    manifest = unique_json((APP / "Contents/Resources/GoogleMessagesExtension/manifest.json").read_bytes())
    require("host_permissions" not in manifest, "production_manifest_changed")
    profile = home / "Library/Application Support/Google/Chrome"
    require({item.name for item in profile.iterdir()} == {"NativeMessagingHosts"}, "review_browser_profile_not_fresh")
    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(str(profile), executable_path=str(CHROME / "Contents/MacOS/Google Chrome"),
            headless=True, chromium_sandbox=True, ignore_default_args=["--disable-extensions"],
            args=["--enable-unsafe-extension-debugging", "--password-store=basic", "--use-mock-keychain"],
            env=environment(home), timeout=25000)
        try:
            context.route("**/*", lambda route: route.abort())
            cdp = context.browser.new_browser_cdp_session()
            version = cdp.send("Browser.getVersion")["product"]
            require(cdp.send("Extensions.loadUnpacked", {"path": prepared["extension_path"]}) == {"id": EXTENSION},
                    "packaged_extension_not_loaded")
            origin = ORIGIN + "background.js"
            worker = next((item for item in context.service_workers if item.url == origin), None)
            if worker is None:
                worker = context.wait_for_event("serviceworker", predicate=lambda item: item.url == origin, timeout=15000)
            replies = worker.evaluate("""async () => ({first: await native({method:'pending'}),
                second: await native({method:'pending'}), permissions: await chrome.permissions.getAll()})""")
            expected = {"status": "NEEDS_USER", "reason": "vault_setup_required"}
            require(replies.get("first") == expected and replies.get("second") == expected, "production_transport_not_reached")
            permissions = replies.get("permissions", {})
            require(permissions.get("origins", []) == [] and set(permissions.get("permissions", [])) == set(manifest["permissions"]),
                    "review_optional_permission_granted")
            require(all(page.url in {"about:blank", "chrome://newtab/"} for page in context.pages), "review_external_page_opened")
            require(hashes == {name: digest(APP / "Contents/Resources/GoogleMessagesExtension" / name) for name in RESOURCES},
                    "review_extension_changed")
        finally:
            context.close()
    print(json.dumps({"status": "PASSED", "chrome_version": version, "extension_resources_sha256": hashes}))


def run(args):
    guard(root=True)
    validate_inputs(args.source, args.sha256)
    from account_access.system_provision import Layout, activate, prepare, signature
    from account_access.worker_bootstrap import reject_grant_acl, root_managed_path
    checks, stage = {}, "guard"
    prefix = None
    copied = []
    owner = None
    owner_records = []
    expected_job = None
    signatures = None
    designated = None
    preflight_failure_type = None
    applications_parent_stamp = None
    report = {"status": "FAILED", "reason": "publisher_transport_incomplete"}
    try:
        checks["hosted_arm64_mac_guard_passed"] = True
        stage = "controller-source"
        require(git(["rev-parse", "HEAD"]).stdout.decode().strip() == os.environ["GITHUB_SHA"],
                "controller_revision_mismatch")
        stage = "baseline-paths"
        for path in [BASE, PUBLIC_APP, JOB]:
            require(not path.exists() and not path.is_symlink(), "existing_production_installation")
        for lookup in [pwd.getpwnam, grp.getgrnam]:
            try:
                lookup("_accountaccess")
            except KeyError:
                pass
            else:
                raise ReviewError("existing_production_identity")
        stage = "baseline-authorization"
        require(authorization() is None, "existing_production_authorization_rule")
        stage = "baseline-job"
        require(command(["/bin/launchctl", "print", "system/" + LABEL], check=False).returncode != 0,
                "existing_production_job")
        for path, label in [(BASE.parent, "support"), (JOB.parent, "launchdaemons")]:
            stage = "baseline-" + label + "-parent"
            try:
                root_managed_path(path)
            except Exception as exc:
                preflight_failure_type = type(exc).__name__ if type(exc).__name__ in {
                    "BootstrapError", "FileNotFoundError", "PermissionError", "ValueError"} else "Exception"
                raise ReviewError("untrusted_review_" + label + "_parent") from None
        stage = "baseline-applications-parent"
        parent_info = PUBLIC_APP.parent.lstat()
        require(shared_parent_metadata_valid(parent_info), "unsafe_shared_applications_parent")
        reject_grant_acl(PUBLIC_APP.parent)
        applications_parent_stamp = (parent_info.st_dev, parent_info.st_ino, parent_info.st_uid, parent_info.st_gid, parent_info.st_mode)
        checks["fresh_production_paths_only"] = True
        candidate = BASE.parent / ("account-access-publisher-qa-" + secrets.token_hex(8))
        candidate.mkdir(mode=0o755)
        prefix = candidate
        private = prefix / "private"
        private.mkdir(mode=0o700)
        stage = "archive"
        incoming = Path(args.archive)
        require(incoming.is_file() and not incoming.is_symlink() and incoming.stat().st_size <= MAX_ARCHIVE,
                "review_archive_unavailable")
        archive = private / "review.tar.gz"
        source_fd = os.open(incoming, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(source_fd, "rb") as source, archive.open("xb") as output:
            require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "review_archive_unavailable")
            total = 0
            while block := source.read(1024 * 1024):
                total += len(block)
                require(total <= MAX_ARCHIVE, "review_archive_size_limit")
                output.write(block)
        require(archive.stat().st_size <= MAX_ARCHIVE and digest(archive) == args.sha256, "review_archive_hash_mismatch")
        checks["immutable_review_archive_verified"] = True
        extract_review(archive, private, args.source)
        checks["archive_matches_exact_public_image"] = True
        payload = private / "payload"
        verify_source(payload, args.source)
        checks["application_wheel_and_runtime_match_source"] = True
        stage = "signatures"
        audit = runpy.run_path(str(SOURCE / "macos/payload_audit.py"))
        audit["audit_payload"]([payload / BASE.relative_to("/")], [], "arm64", command, development=False)
        for relative, identifier in [(APP, "com.fainir.accountaccess"),
                (BASE / "bin/AccountAccess-broker", LABEL), (BASE / "bin/AccountAccess-bootstrap", "com.fainir.accountaccess.bootstrap")]:
            require(signature(payload / relative.relative_to("/"), identifier)["team"] == TEAM, "review_publisher_mismatch")
        chrome_requirement = ('anchor apple generic and identifier "com.google.Chrome" '
                              'and certificate leaf[subject.OU] = "EQHXZ8M8AV" '
                              'and !(entitlement["com.apple.security.get-task-allow"] exists)')
        command(["/usr/bin/codesign", "--verify", "--strict", "-R=" + chrome_requirement, str(CHROME)])
        checks["genuine_publisher_components_verified"] = True
        checks["signed_stable_chrome_used"] = True
        stage = "public-image"
        for path in [BASE]:
            path.mkdir(mode=0o755)
            copied.append((path, (path.stat().st_dev, path.stat().st_ino)))
            shutil.copytree(payload / path.relative_to("/"), path, symlinks=True, dirs_exist_ok=True)
        for path in [BASE, APP]:
            root_managed_path(path)
        checks["canonical_owner_bundle_protected"] = True
        os.symlink(APPLICATION_TARGET, PUBLIC_APP)
        info = PUBLIC_APP.lstat()
        copied.append((PUBLIC_APP, (info.st_dev, info.st_ino)))
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and os.readlink(PUBLIC_APP) == APPLICATION_TARGET, "public_app_alias_mismatch")
        checks["public_app_alias_is_navigation_only"] = True
        # A fresh non-login UID has its own empty Chrome profile and Mach domain.
        uid, name = fresh_owner_identity()
        home = prefix / "owner-home"
        home.mkdir(mode=0o700)
        os.chown(home, uid, uid)
        (home / "tmp").mkdir(mode=0o700)
        os.chown(home / "tmp", uid, uid)
        for kind in ["Groups", "Users"]:
            record = "/" + kind + "/" + name
            command(["/usr/bin/dscl", ".", "-create", record])
            owner_records.append(record)
            values = ({"PrimaryGroupID": str(uid)} if kind == "Groups" else {
                "UniqueID": str(uid), "PrimaryGroupID": str(uid), "NFSHomeDirectory": str(home),
                "UserShell": "/usr/bin/false", "IsHidden": "1", "Password": "*"})
            for key, value in values.items():
                command(["/usr/bin/dscl", ".", "-create", record, key, value])
        command(["/usr/bin/dscacheutil", "-flushcache"])
        owner = pwd.getpwnam(name)
        require(owner.pw_uid == uid and owner.pw_gid == uid and owner.pw_dir == str(home), "review_owner_identity_mismatch")
        command(["/bin/launchctl", "bootstrap", "user/" + str(uid)])
        stage = "provision"
        prepare(Layout.installed(), uid)
        expected_job = (BASE / "broker/service.plist").read_bytes()
        registered = activate(Layout.installed(), uid)
        require(registered["status"] == "REGISTERED", "production_activation_failed")
        checks["production_prepare_and_activate_used"] = True
        signatures = {key: signature(path, identifier) for key, path, identifier in [
            ("owner", APP, "com.fainir.accountaccess"), ("broker", BASE / "bin/AccountAccess-broker", LABEL),
            ("bootstrap", BASE / "bin/AccountAccess-bootstrap", "com.fainir.accountaccess.bootstrap")]}
        profile = unique_json((BASE / "owner.json").read_bytes())
        require(profile == {"managed_by": "account-access-desktop-owner-v1", "schema": 1, "owner_uid": uid,
                "publisher_team": TEAM, "server_identifier": LABEL, "server_hashes": signatures["broker"]["hashes"]},
                "production_profile_mismatch")
        checks["root_profile_pins_actual_publisher_hashes"] = True
        text = command(["/usr/bin/codesign", "-d", "-r-", str(BASE / "bin/AccountAccess-broker")]).stderr.decode()
        matches = re.findall(r"^designated => (.+)$", text, re.MULTILINE)
        require(len(matches) == 1, "broker_designated_requirement_missing")
        designated = matches[0]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            observed = authorization()
            if observed is not None:
                require(exact_rule(observed, designated), "production_authorization_registrar_mismatch")
                break
            time.sleep(0.2)
        else:
            raise ReviewError("production_authorization_not_registered")
        checks["genuine_broker_registered_its_own_exact_rule"] = True
        stage = "chrome"
        controller = prefix / "probe.py"
        shutil.copyfile(Path(__file__), controller)
        controller.chmod(0o644)
        configuration = prefix / "child.json"
        configuration.write_text(json.dumps({"owner_uid": uid, "home": str(home), "prefix": str(prefix)}))
        configuration.chmod(0o644)
        result = command(["/bin/launchctl", "asuser", str(uid), "/usr/bin/sudo", "-n", "-u", name, "--",
                          str(BASE / "runtime/bin/python"), "-I", "-B", str(controller), "chrome-child", str(configuration)],
                         timeout=100, env=environment(home))
        child_report = unique_json(result.stdout)
        require(type(child_report) is dict and set(child_report) == {"status", "chrome_version", "extension_resources_sha256"}
                and child_report["status"] == "PASSED", "production_chrome_journey_failed")
        for check in ["production_owner_browser_setup_used", "unchanged_packaged_extension_used",
                      "shell_parent_rejected_by_production_entrypoint", "native_pending_reached_initial_enrollment",
                      "second_pending_reached_initial_enrollment", "optional_permissions_stay_ungranted", "no_external_website_opened"]:
            checks[check] = True
        require(not list((BASE / "vault/data").iterdir())
                and not list((BASE / "broker").glob(".enrollment-*.publication"))
                and not list((BASE / "vault").glob(".enrollment-*.publication")), "unexpected_vault_initialization")
        checks["empty_vault_and_no_enrollment_journal"] = True
        report = {"schema": 1, "status": "PASSED", "platform": "macos", "architecture": "arm64",
            "environment": "disposable-hosted-ci-public-review", "source_revision": args.source,
            "controller_revision": os.environ["GITHUB_SHA"], "review_archive_sha256": args.sha256,
            "publisher_team": TEAM, "chrome_version": child_report["chrome_version"],
            "component_hashes": {key: value["hashes"] for key, value in signatures.items()},
            "extension_resources_sha256": child_report["extension_resources_sha256"], "checks": checks,
            "private_signins": 0, "limits": "Public signed transport before owner enrollment; no key, website login, personal account, phone, approval or consumer installation was validated."}
        checker = runpy.run_path(str(SOURCE / "scripts/check_mac_publisher_transport_report.py"))
        report.update({key: True for key in checker["TRUE_FLAGS"]})
        report.update({key: False for key in checker["FALSE_FLAGS"]})
    except Exception as exc:
        report = {"status": "FAILED", "reason": str(exc) if isinstance(exc, ReviewError) else "publisher_transport_failed",
                  "stage": stage, "checks": checks, "production_ready": False, "private_signins": 0}
        if stage.startswith("baseline-") and stage.endswith("-parent"):
            # Fixed, public system-directory metadata only; never raw errors,
            # user homes, environment values, account state or credentials.
            report["preflight_failure_type"] = preflight_failure_type
            report["public_parent_metadata"] = public_parent_metadata([
                ("support", BASE.parent), ("applications", PUBLIC_APP.parent), ("launchdaemons", JOB.parent)])
    finally:
        # Every deletion is bound to a baseline-absent name created by this run.
        cleanup_ok = True
        if prefix is not None:
            def cleanup(name, operation):
                nonlocal cleanup_ok
                try:
                    operation()
                    checks[name] = True
                except Exception:
                    checks[name] = False
                    cleanup_ok = False
            if owner is not None:
                def stop_owner():
                    current = pwd.getpwnam(owner.pw_name)
                    require((current.pw_uid, current.pw_gid, current.pw_dir)
                            == (owner.pw_uid, owner.pw_gid, owner.pw_dir), "cleanup_identity_changed")
                    domain = "user/" + str(owner.pw_uid)
                    if command(["/bin/launchctl", "print", domain], check=False).returncode == 0:
                        command(["/bin/launchctl", "bootout", domain])
                    require(command(["/bin/launchctl", "print", domain], check=False).returncode != 0,
                            "cleanup_owner_domain_still_loaded")
                    stop_uid(owner.pw_uid)
                cleanup("chrome_and_native_children_stopped", stop_owner)
            if JOB.exists():
                def stop_job():
                    require(expected_job is not None and not JOB.is_symlink()
                            and JOB.read_bytes() == expected_job, "cleanup_job_not_owned")
                    if command(["/bin/launchctl", "print", "system/" + LABEL], check=False).returncode == 0:
                        command(["/bin/launchctl", "bootout", "system/" + LABEL])
                    require(command(["/bin/launchctl", "print", "system/" + LABEL], check=False).returncode != 0,
                            "cleanup_job_still_loaded")
                    JOB.unlink()
                cleanup("created_system_job_removed", stop_job)
            if designated is not None:
                def remove_rule():
                    observed = authorization()
                    require(exact_rule(observed, designated), "cleanup_authorization_changed")
                    command(["/usr/bin/security", "authorizationdb", "remove", RIGHT])
                    require(authorization() is None, "cleanup_authorization_still_present")
                cleanup("created_authorization_rule_removed", remove_rule)
            record = BASE / "broker/install.json"
            if record.is_file():
                def remove_broker():
                    value = unique_json(record.read_bytes())
                    uid = value["broker_uid"]
                    require(value["broker_name"] == "_accountaccess" and type(uid) is int and 450 <= uid < 500
                            and pwd.getpwnam("_accountaccess").pw_uid == uid
                            and grp.getgrnam("_accountaccess").gr_gid == uid, "cleanup_service_identity_changed")
                    command(["/bin/launchctl", "bootout", "user/" + str(uid)], check=False)
                    stop_uid(uid)
                    command(["/usr/bin/dscl", ".", "-delete", "/Users/_accountaccess"])
                    command(["/usr/bin/dscl", ".", "-delete", "/Groups/_accountaccess"])
                cleanup("created_service_identity_removed", remove_broker)
            if owner_records:
                def remove_owner():
                    if owner is not None:
                        stop_owner()
                    for record in reversed(owner_records):
                        command(["/usr/bin/dscl", ".", "-delete", record])
                    command(["/usr/bin/dscacheutil", "-flushcache"])
                cleanup("temporary_owner_identity_and_domain_removed", remove_owner)
            def remove_image():
                for path, identity in reversed(copied):
                    info = path.lstat()
                    require(info.st_uid == 0
                            and (info.st_dev, info.st_ino) == identity, "cleanup_public_image_changed")
                    if path == PUBLIC_APP:
                        require(stat.S_ISLNK(info.st_mode) and os.readlink(path) == APPLICATION_TARGET,
                                "cleanup_public_alias_changed")
                        path.unlink()
                    else:
                        require(stat.S_ISDIR(info.st_mode), "cleanup_public_image_changed")
                        shutil.rmtree(path)
                shutil.rmtree(prefix)
                info = PUBLIC_APP.parent.lstat()
                require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) == applications_parent_stamp,
                        "shared_applications_parent_changed")
                checks["shared_applications_parent_unchanged"] = True
            cleanup("fresh_public_image_removed", remove_image)
        if not cleanup_ok:
            report.update(status="FAILED", reason="publisher_transport_cleanup_failed", stage="cleanup")
    if report.get("status") == "PASSED":
        require(runpy.run_path(str(SOURCE / "scripts/check_mac_publisher_transport_report.py"))["validate"](report),
                "publisher_transport_report_incomplete")
    target = Path(args.report)
    with target.open("x") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    target.chmod(0o644)
    print(json.dumps({"status": report["status"], "production_ready": False, "private_signins": 0}))
    return 0 if report["status"] == "PASSED" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("download")
    for name in ["tag", "asset", "sha256", "source", "output"]:
        fetch.add_argument("--" + name, required=True)
    fetch.add_argument("--asset-id", required=True, type=int)
    fetch.add_argument("--release-id", required=True, type=int)
    parent = commands.add_parser("run")
    for name in ["archive", "sha256", "source", "report"]:
        parent.add_argument("--" + name, required=True)
    inner = commands.add_parser("chrome-child")
    inner.add_argument("configuration")
    args = parser.parse_args(argv)
    try:
        if args.command == "download":
            download(args)
        elif args.command == "chrome-child":
            child(args.configuration)
        else:
            def expired(_signal, _frame):
                raise ReviewError("publisher_transport_deadline")
            signal.signal(signal.SIGALRM, expired)
            signal.alarm(900)
            try:
                return run(args)
            finally:
                signal.alarm(0)
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ReviewError) and re.fullmatch(r"[a-z_]{1,100}", str(exc)) else "publisher_transport_failed"
        print(json.dumps({"status": "FAILED", "reason": reason, "production_ready": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
