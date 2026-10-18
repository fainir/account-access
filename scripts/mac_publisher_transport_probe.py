"""Opt-in hosted Mac VM only: unchanged publisher binaries, before enrollment.

Never invoke the privileged mode on a personal Mac. This installs only a
hash-pinned public review image into an otherwise empty disposable VM. It does
not enroll a vault, obtain approval, connect an account or send a login code.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import pwd
import grp
import re
import shlex
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
PUBLIC_REASONS = set("""
authorization_lookup_failed broker_designated_requirement_missing cleanup_authorization_changed
cleanup_authorization_still_present cleanup_identity_changed cleanup_identity_invalid cleanup_job_not_owned
cleanup_job_still_loaded cleanup_processes_still_running
cleanup_public_alias_changed cleanup_public_image_changed cleanup_service_identity_changed controller_revision_mismatch
duplicate_review_field existing_production_authorization_rule existing_production_identity existing_production_installation
existing_production_job hosted_arm64_mac_required hosted_review_only invalid_review_asset
invalid_review_inputs ordinary_ci_download_required packaged_extension_not_loaded production_activation_failed
production_authorization_not_registered production_authorization_registrar_mismatch production_browser_setup_failed
production_chrome_journey_failed production_manifest_changed production_parent_guard_failed production_profile_mismatch
production_transport_not_reached public_app_alias_mismatch publisher_transport_deadline publisher_transport_report_incomplete
review_app_wheel_mismatch review_architecture_mismatch review_archive_alias_mismatch review_archive_entry_limit
review_archive_hash_mismatch review_archive_inventory_mismatch review_archive_size_limit review_archive_unavailable
review_asset_metadata_mismatch review_browser_profile_not_fresh review_child_identity_mismatch review_command_failed
review_command_timeout review_command_output_limit review_contains_nonpublic_state review_contract_mismatch
review_download_already_exists review_download_hash_mismatch review_draft_metadata_unavailable review_draft_source_mismatch
review_extension_changed review_extension_source_mismatch review_external_page_opened review_identity_invalid
review_image_hash_mismatch review_installer_source_mismatch review_metadata_missing review_optional_permission_granted
existing_review_browser_registration existing_review_target_processes
review_runner_identity_invalid review_registration_changed review_registration_missing cleanup_registration_changed
cleanup_browser_profile_changed review_process_inspection_failed review_package_files_mismatch review_package_source_mismatch
review_publisher_mismatch review_runtime_package_missing review_runtime_source_mismatch review_source_tree_changed
shared_applications_parent_changed unexpected_vault_initialization unsafe_review_archive_entry unsafe_shared_applications_parent
untrusted_review_support_parent untrusted_review_applications_parent untrusted_review_launchdaemons_parent
""".split())
PUBLIC_EXCEPTION_TYPES = {"ReviewError", "BootstrapError", "ProvisionError", "FileNotFoundError", "PermissionError",
                          "ValueError", "JSONDecodeError", "KeyError", "OSError", "TimeoutExpired",
                          "ModuleNotFoundError", "ImportError", "AccessError", "Error", "TargetClosedError", "TimeoutError", "ProcessInspectionError"}
CHILD_STAGES = set("""child-start hosted-guard production-imports playwright-import configuration owner-identity owner-home
production-browser-prepare negative-shell-parent extension-manifest chrome-profile playwright-driver chrome-launch
chrome-routing cdp-connection extension-load service-worker native-exchange permissions-check result-check chrome-close""".split())
CHILD_STAGE = "child-start"
PROCESS_ERROR_REASONS = {"process_identity_invalid", "process_identity_read_failed", "process_native_layout_invalid",
                         "process_path_read_failed", "process_platform_invalid", "process_roots_invalid",
                         "process_scan_failed", "process_signal_failed", "process_signal_invalid", "process_stop_invalid",
                         "process_uid_invalid"}
PUBLIC_COMMAND_KINDS = set("""codesign_designated codesign_verify codesign_metadata authorization_read authorization_remove
authorization_other launchctl_print launchctl_bootstrap launchctl_bootout launchctl_owner_child launchctl_other git_source
github_metadata lipo_architecture directory_record directory_cache identity_process_stop identity_process_query other_command""".split())


class ReviewError(Exception):
    def __init__(self, reason, *, command_failure=None, child_failure=None):
        super().__init__(reason)
        self.command_failure = command_failure
        self.child_failure = child_failure


def public_command_detail(detail):
    if (type(detail) is dict and set(detail) == {"kind", "exitcode", "timed_out"}
            and type(detail["kind"]) is str and detail["kind"] in PUBLIC_COMMAND_KINDS and type(detail["timed_out"]) is bool
            and (detail["exitcode"] is None or type(detail["exitcode"]) is int and -2**31 <= detail["exitcode"] < 2**31)):
        return dict(detail)
    return None


def public_child_failure(value):
    fields = {"status", "reason", "failure_type", "production_ready"}
    if (type(value) is not dict or not fields <= set(value) <= fields | {"command_failure", "child_stage", "errno"}
            or value.get("status") != "FAILED" or value.get("production_ready") is not False
            or type(value.get("reason")) is not str or value["reason"] not in PUBLIC_REASONS | {"publisher_transport_failed"}
            or type(value.get("failure_type")) is not str or value["failure_type"] not in PUBLIC_EXCEPTION_TYPES | {"Exception"}):
        return None
    if "command_failure" in value and public_command_detail(value["command_failure"]) is None:
        return None
    if "child_stage" in value and (type(value["child_stage"]) is not str or value["child_stage"] not in CHILD_STAGES):
        return None
    if "errno" in value and (type(value["errno"]) is not int or not 0 < value["errno"] < 4096):
        return None
    return dict(value)


def public_error(error):
    name = type(error).__name__
    result = {"reason": str(error) if (isinstance(error, ReviewError) and str(error) in PUBLIC_REASONS
                                      or name == "ProcessInspectionError" and str(error) in PROCESS_ERROR_REASONS)
              else "publisher_transport_failed", "failure_type": name if name in PUBLIC_EXCEPTION_TYPES else "Exception"}
    detail = public_command_detail(error.command_failure) if isinstance(error, ReviewError) else None
    if detail is not None:
        result["command_failure"] = detail
    child = public_child_failure(error.child_failure) if isinstance(error, ReviewError) else None
    if child is not None:
        result["child_failure"] = child
    if isinstance(error, OSError) and type(error.errno) is int and 0 < error.errno < 4096:
        result["errno"] = error.errno
    return result


def failed_report(error, stage, checks):
    return {"status": "FAILED", **public_error(error), "stage": stage, "checks": checks,
            "production_ready": False, "private_signins": 0}


def cleanup_result(report, failures, command_failures):
    if failures:
        report = dict(report)
        report.update(failed_stage=report.get("stage", "none"), failed_reason=report.get("reason", "none"),
                      status="FAILED", reason="publisher_transport_cleanup_failed", stage="cleanup",
                      cleanup_failures=failures)
        if command_failures:
            report["cleanup_command_failures"] = command_failures
    return report


def cleanup_step(name, operation, checks, failures, command_failures):
    try:
        operation()
        checks[name] = True
    except Exception as error:
        details = public_error(error)
        checks[name] = False
        failures[name] = details["reason"] if details["reason"] != "publisher_transport_failed" else details["failure_type"]
        if "command_failure" in details:
            command_failures[name] = details["command_failure"]


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


def environment(home=None, temporary=None):
    result = {key: os.environ[key] for key in ENV_KEYS if key in os.environ}
    result.update(PATH="/usr/bin:/bin:/usr/sbin:/sbin", LANG="en_US.UTF-8")
    if home is not None:
        result.update(HOME=str(home), TMPDIR=str(temporary if temporary is not None else Path(home) / "tmp"))
    return result


def command_kind(arguments):
    executable = str(arguments[0]) if arguments else ""
    if executable == "/usr/bin/codesign":
        return "codesign_designated" if "-r-" in arguments else "codesign_verify" if "--verify" in arguments else "codesign_metadata"
    if executable == "/usr/bin/security" and len(arguments) > 2 and arguments[1] == "authorizationdb":
        return {"read": "authorization_read", "remove": "authorization_remove"}.get(arguments[2], "authorization_other")
    if executable == "/bin/launchctl" and len(arguments) > 1:
        return {"print": "launchctl_print", "bootstrap": "launchctl_bootstrap", "bootout": "launchctl_bootout",
                "asuser": "launchctl_owner_child"}.get(arguments[1], "launchctl_other")
    return {"/usr/bin/git": "git_source", "gh": "github_metadata", "/usr/bin/lipo": "lipo_architecture",
            "/usr/bin/dscl": "directory_record"}.get(executable, "other_command")


def command_diagnostic(arguments, *, exitcode=None, timed_out=False):
    return {"kind": command_kind(arguments), "exitcode": exitcode, "timed_out": timed_out}


def command(arguments, *, timeout=25, check=True, env=None, **kwargs):
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=timeout, close_fds=True,
                                env=environment() if env is None else env, **kwargs)
    except subprocess.TimeoutExpired:
        raise ReviewError("review_command_timeout", command_failure=command_diagnostic(arguments, timed_out=True)) from None
    diagnostic = command_diagnostic(arguments, exitcode=result.returncode)
    if len(result.stdout) + len(result.stderr) > 1_000_000:
        raise ReviewError("review_command_output_limit", command_failure=diagnostic)
    if check and result.returncode != 0:
        raise ReviewError("review_command_failed", command_failure=diagnostic)
    return result


def owner_child_command(arguments, *, env):
    result = command(arguments, timeout=100, check=False, env=env)
    if result.returncode != 0:
        child = None
        if len(result.stdout) <= 4096:
            try:
                child = public_child_failure(unique_json(result.stdout))
            except (ValueError, TypeError, ReviewError):
                pass
        raise ReviewError("production_chrome_journey_failed",
                          command_failure=command_diagnostic(arguments, exitcode=result.returncode), child_failure=child)
    return result


def owner_child_arguments(uid, name, home, controller, configuration, *, mode="chrome-child", temporary=None):
    # sudo deliberately removes arbitrary caller variables. Restore only this
    # public CI/owner-home whitelist after credentials have changed; no token,
    # source interpreter override, or parent environment can reach the child.
    values = environment(home, temporary)
    return ["/bin/launchctl", "asuser", str(uid), "/usr/bin/sudo", "-n", "-u", name, "--",
            "/usr/bin/env", "-i", *(key + "=" + values[key] for key in sorted(values)),
            str(BASE / "runtime/bin/python"), "-I", "-B", str(controller), mode, str(configuration)]


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


def designated_requirement(binary):
    result = command(["/usr/bin/codesign", "-d", "-r-", str(binary)])
    matches = re.findall(r"^designated => (.+)$", result.stdout.decode("utf-8"), re.MULTILINE)
    require(len(matches) == 1, "broker_designated_requirement_missing")
    return matches[0]


def remove_review_authorization(designated):
    observed = authorization()
    if observed is None:
        return  # Baseline was absent; no rule was installed or remains.
    require(exact_rule(observed, designated), "cleanup_authorization_changed")
    command(["/usr/bin/security", "authorizationdb", "remove", RIGHT])
    require(authorization() is None, "cleanup_authorization_still_present")


def runner_identity(source=SOURCE):
    uid = source.stat().st_uid
    require(type(uid) is int and 500 <= uid < 50000, "review_runner_identity_invalid")
    owner = pwd.getpwuid(uid)
    require(owner.pw_uid == uid and type(owner.pw_gid) is int and 0 < owner.pw_gid < 50000
            and re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}", owner.pw_name)
            and Path(owner.pw_dir).parent == Path("/Users") and str(Path(owner.pw_dir)) == owner.pw_dir,
            "review_runner_identity_invalid")
    grp.getgrgid(owner.pw_gid)
    verify_runner_identity(owner)
    return owner


def verify_runner_identity(owner):
    current = pwd.getpwuid(owner.pw_uid)
    by_name = pwd.getpwnam(owner.pw_name)
    expected = (owner.pw_name, owner.pw_uid, owner.pw_gid, owner.pw_dir)
    require(all((item.pw_name, item.pw_uid, item.pw_gid, item.pw_dir) == expected for item in [current, by_name]),
            "cleanup_identity_changed")
    grp.getgrgid(owner.pw_gid)
    info = Path(owner.pw_dir).lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner.pw_uid and info.st_mode & 0o7022 == 0,
            "review_runner_identity_invalid")


def runner_metadata(owner):
    verify_runner_identity(owner)
    group = grp.getgrgid(owner.pw_gid)
    info = Path(owner.pw_dir).lstat()
    return (owner.pw_name, owner.pw_uid, owner.pw_gid, owner.pw_dir, group.gr_name, group.gr_gid,
            info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def process_api():
    # Imported only after the disposable hosted/root guard. Never inspect
    # processes during module import, ordinary download or pure contract tests.
    name = "account_access_publisher_qa_processes"
    if name not in sys.modules:
        path = SOURCE / "scripts/mac_publisher_processes.py"
        require(path.read_bytes() == git_file(os.environ["GITHUB_SHA"], "scripts/mac_publisher_processes.py"), "review_source_tree_changed")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def stop_browser_processes(owner, api):
    verify_runner_identity(owner)
    # Baseline was empty. Re-snapshot after each stop to include late children;
    # the helper rebinds PID, UID, kernel executable path and birth timestamp
    # immediately before each signal. Runner infrastructure is never selected.
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        identities = api.snapshot(owner.pw_uid, (BASE, CHROME))
        if not identities:
            return
        remaining = deadline - time.monotonic()
        require(remaining > 0 and api.stop(identities, (BASE, CHROME), timeout=min(2, remaining), kill_after=min(0.5, remaining / 2)),
                "cleanup_processes_still_running")
    require(not api.snapshot(owner.pw_uid, (BASE, CHROME)), "cleanup_processes_still_running")


def registration_payloads(home):
    home = Path(home)
    launcher = home / "Library/Application Support/Account Access/browser-v1/native-host"
    registration = home / "Library/Application Support/Google/Chrome/NativeMessagingHosts/com.account_access.google_messages.json"
    command = ("#!/bin/sh\nexec " + shlex.join([str(APP / "Contents/MacOS/AccountAccess"), "--browser-native-host"]) + ' "$@"\n').encode()
    body = dict(name="com.account_access.google_messages", description="Account Access approved browser connections",
                path=str(launcher), type="stdio", allowed_origins=[ORIGIN])
    return [(launcher, command, 0o700), (registration, json.dumps(body).encode(), 0o600)]


def registration_absent(home):
    # Only the two production registration names are inspected. In particular,
    # no Chrome profile, browsing content or other native registrations are read.
    for path, _data, _mode in registration_payloads(home):
        require(not path.exists() and not path.is_symlink(), "existing_review_browser_registration")


def file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def registration_parent(path, owner):
    home = Path(owner.pw_dir)
    relative = path.relative_to(home)
    require(relative in {item[0].relative_to(home) for item in registration_payloads(home)}, "review_registration_changed")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(home, flags)
    parents = []
    try:
        for part in [None, *relative.parts[:-1]]:
            if part is not None:
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner.pw_uid and info.st_mode & 0o7022 == 0,
                    "review_registration_changed")
            parents.append((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode))
        return fd, tuple(parents)
    except BaseException:
        os.close(fd)
        raise


def capture_registration(path, data, mode, owner):
    parent, parents = registration_parent(path, owner)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == owner.pw_uid
                    and info.st_gid == owner.pw_gid and stat.S_IMODE(info.st_mode) == mode
                    and info.st_size == len(data) and os.read(fd, len(data) + 1) == data,
                    "review_registration_changed")
            require(file_stamp(os.fstat(fd)) == file_stamp(info), "review_registration_changed")
            return {"path": str(path), "stamp": file_stamp(info), "parents": parents, "sha256": hashlib.sha256(data).hexdigest()}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def capture_registrations(owner, bindings):
    first_error = None
    for path, data, mode in registration_payloads(owner.pw_dir):
        try:
            binding = capture_registration(path, data, mode, owner)
            if not any(item["path"] == str(path) for item in bindings):
                bindings.append(binding)
        except FileNotFoundError:
            if first_error is None:
                first_error = ReviewError("review_registration_missing")
        except Exception as error:
            if first_error is None:
                first_error = error
    if first_error is not None:
        raise first_error


def remove_registrations(owner, bindings):
    verify_runner_identity(owner)
    for binding in bindings:
        path = Path(binding["path"])
        expected = next((item for item in registration_payloads(owner.pw_dir) if item[0] == path), None)
        require(expected is not None, "cleanup_registration_changed")
        current = capture_registration(*expected, owner)
        require(current == binding, "cleanup_registration_changed")
        parent, parents = registration_parent(path, owner)
        try:
            require(parents == binding["parents"] and file_stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == binding["stamp"],
                    "cleanup_registration_changed")
            os.unlink(path.name, dir_fd=parent)
            try:
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ReviewError("cleanup_registration_changed")
        finally:
            os.close(parent)
    registration_absent(owner.pw_dir)


def remove_browser_profile(profile, profile_stamp, owner, api):
    verify_runner_identity(owner)
    require(not api.snapshot(owner.pw_uid, (BASE, CHROME)), "cleanup_processes_still_running")
    info = profile.lstat()
    require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) == profile_stamp
            and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
            "cleanup_browser_profile_changed")
    shutil.rmtree(profile)
    require(not profile.exists() and not profile.is_symlink(), "cleanup_browser_profile_changed")


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


def child(config_path, *, prepare_only=False):
    global CHILD_STAGE
    CHILD_STAGE = "hosted-guard"
    guard(root=False)
    CHILD_STAGE = "production-imports"
    from account_access.browser_setup import prepare
    from account_access.worker_bootstrap import root_managed_path
    CHILD_STAGE = "playwright-import"
    from playwright.sync_api import sync_playwright
    CHILD_STAGE = "configuration"
    path = root_managed_path(config_path)
    config = unique_json(path.read_bytes())
    CHILD_STAGE = "owner-identity"
    user = pwd.getpwuid(os.getuid())
    home = Path(user.pw_dir)
    require(set(config) == {"owner_uid", "owner_gid", "owner_name", "home", "prefix", "profile", "temporary"}
            and config["owner_uid"] == os.getuid() and config["owner_gid"] == user.pw_gid
            and config["owner_name"] == user.pw_name and config["home"] == str(home)
            and re.fullmatch(r"/Library/Application Support/account-access-publisher-qa-[a-f0-9]{16}", config["prefix"])
            and config["profile"] == str(Path(config["prefix"]) / "browser-profile")
            and config["temporary"] == str(Path(config["prefix"]) / "browser-tmp"), "review_child_identity_mismatch")
    CHILD_STAGE = "owner-home"
    verify_runner_identity(user)
    profile = Path(config["profile"])
    temporary = Path(config["temporary"])
    for directory in [profile, temporary]:
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == user.pw_uid and info.st_gid == user.pw_gid
                and stat.S_IMODE(info.st_mode) == 0o700, "review_browser_profile_not_fresh")
    if prepare_only:
        CHILD_STAGE = "production-browser-prepare"
        registration_absent(home)
        prepared = prepare(home)
        require(prepared == {"status": "PREPARED", "extension_path": str(APP / "Contents/Resources/GoogleMessagesExtension"),
                             "extension_id": EXTENSION}, "production_browser_setup_failed")
        print(json.dumps(prepared))
        return
    bindings = []
    capture_registrations(user, bindings)
    prepared = {"extension_path": str(APP / "Contents/Resources/GoogleMessagesExtension")}
    launcher = registration_payloads(home)[0][0]
    CHILD_STAGE = "negative-shell-parent"
    negative = command([str(launcher), ORIGIN], timeout=10, check=False, env=environment(home, temporary), input=b"")
    require(negative.returncode == 78 and negative.stdout == b"", "production_parent_guard_failed")
    CHILD_STAGE = "extension-manifest"
    hashes = {name: digest(APP / "Contents/Resources/GoogleMessagesExtension" / name) for name in RESOURCES}
    manifest = unique_json((APP / "Contents/Resources/GoogleMessagesExtension/manifest.json").read_bytes())
    require("host_permissions" not in manifest, "production_manifest_changed")
    CHILD_STAGE = "chrome-profile"
    require(not list(profile.iterdir()), "review_browser_profile_not_fresh")
    CHILD_STAGE = "playwright-driver"
    with sync_playwright() as playwright:
        CHILD_STAGE = "chrome-launch"
        context = playwright.chromium.launch_persistent_context(str(profile), executable_path=str(CHROME / "Contents/MacOS/Google Chrome"),
            headless=True, chromium_sandbox=True, ignore_default_args=["--disable-extensions"],
            args=["--enable-unsafe-extension-debugging", "--password-store=basic", "--use-mock-keychain"],
            env=environment(home, temporary), timeout=25000)
        try:
            CHILD_STAGE = "chrome-routing"
            context.route("**/*", lambda route: route.abort())
            CHILD_STAGE = "cdp-connection"
            cdp = context.browser.new_browser_cdp_session()
            version = cdp.send("Browser.getVersion")["product"]
            CHILD_STAGE = "extension-load"
            require(cdp.send("Extensions.loadUnpacked", {"path": prepared["extension_path"]}) == {"id": EXTENSION},
                    "packaged_extension_not_loaded")
            CHILD_STAGE = "service-worker"
            origin = ORIGIN + "background.js"
            worker = next((item for item in context.service_workers if item.url == origin), None)
            if worker is None:
                worker = context.wait_for_event("serviceworker", predicate=lambda item: item.url == origin, timeout=15000)
            CHILD_STAGE = "native-exchange"
            replies = worker.evaluate("""async () => ({first: await native({method:'pending'}),
                second: await native({method:'pending'}), permissions: await chrome.permissions.getAll()})""")
            expected = {"status": "NEEDS_USER", "reason": "vault_setup_required"}
            require(replies.get("first") == expected and replies.get("second") == expected, "production_transport_not_reached")
            CHILD_STAGE = "permissions-check"
            permissions = replies.get("permissions", {})
            require(permissions.get("origins", []) == [] and set(permissions.get("permissions", [])) == set(manifest["permissions"]),
                    "review_optional_permission_granted")
            CHILD_STAGE = "result-check"
            require(all(page.url in {"about:blank", "chrome://newtab/"} for page in context.pages), "review_external_page_opened")
            require(hashes == {name: digest(APP / "Contents/Resources/GoogleMessagesExtension" / name) for name in RESOURCES},
                    "review_extension_changed")
        except Exception:
            # Preserve the primary fixed stage if closing a failed browser
            # also fails. The root controller still proves all UID children exit.
            try:
                context.close()
            except Exception:
                pass
            raise
        else:
            CHILD_STAGE = "chrome-close"
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
    owner_metadata = None
    process = None
    baseline_clear = False
    bindings = []
    browser_profile = None
    browser_profile_stamp = None
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
        stage = "runner-identity"
        owner = runner_identity()
        owner_metadata = runner_metadata(owner)
        uid, name, home = owner.pw_uid, owner.pw_name, Path(owner.pw_dir)
        stage = "browser-registration-baseline"
        registration_absent(home)
        stage = "target-process-baseline"
        process = process_api()
        require(not process.snapshot(uid, (BASE, CHROME)), "existing_review_target_processes")
        baseline_clear = True
        browser_profile = prefix / "browser-profile"
        browser_tmp = prefix / "browser-tmp"
        for directory in [browser_profile, browser_tmp]:
            directory.mkdir(mode=0o700)
            os.chown(directory, uid, owner.pw_gid)
        info = browser_profile.lstat()
        browser_profile_stamp = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
        stage = "provision-prepare"
        prepare(Layout.installed(), uid)
        stage = "provision-service-job"
        expected_job = (BASE / "broker/service.plist").read_bytes()
        stage = "provision-activate"
        registered = activate(Layout.installed(), uid)
        require(registered["status"] == "REGISTERED", "production_activation_failed")
        checks["production_prepare_and_activate_used"] = True
        stage = "installed-signatures"
        signatures = {key: signature(path, identifier) for key, path, identifier in [
            ("owner", APP, "com.fainir.accountaccess"), ("broker", BASE / "bin/AccountAccess-broker", LABEL),
            ("bootstrap", BASE / "bin/AccountAccess-bootstrap", "com.fainir.accountaccess.bootstrap")]}
        stage = "installed-owner-profile"
        profile = unique_json((BASE / "owner.json").read_bytes())
        require(profile == {"managed_by": "account-access-desktop-owner-v1", "schema": 1, "owner_uid": uid,
                "publisher_team": TEAM, "server_identifier": LABEL, "server_hashes": signatures["broker"]["hashes"]},
                "production_profile_mismatch")
        checks["root_profile_pins_actual_publisher_hashes"] = True
        stage = "broker-designated-requirement"
        designated = designated_requirement(BASE / "bin/AccountAccess-broker")
        stage = "broker-authorization-poll"
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
        stage = "chrome-controller-config"
        controller = prefix / "probe.py"
        shutil.copyfile(Path(__file__), controller)
        controller.chmod(0o644)
        configuration = prefix / "child.json"
        configuration.write_text(json.dumps({"owner_uid": uid, "owner_gid": owner.pw_gid, "owner_name": name,
                "home": str(home), "prefix": str(prefix), "profile": str(browser_profile), "temporary": str(browser_tmp)}))
        configuration.chmod(0o644)
        stage = "browser-registration-prepare"
        try:
            result = owner_child_command(owner_child_arguments(uid, name, home, controller, configuration,
                mode="prepare-child", temporary=browser_tmp), env=environment(home, browser_tmp))
        except BaseException:
            # A partial production prepare may have created one exact file.
            # Capture only known bytes; preserve every unknown/substituted name.
            try:
                capture_registrations(owner, bindings)
            except Exception:
                pass
            raise
        capture_registrations(owner, bindings)
        require(unique_json(result.stdout) == {"status": "PREPARED", "extension_path": str(APP / "Contents/Resources/GoogleMessagesExtension"),
                "extension_id": EXTENSION}, "production_browser_setup_failed")
        checks["production_owner_browser_setup_used"] = True
        stage = "chrome-owner-child"
        result = owner_child_command(owner_child_arguments(uid, name, home, controller, configuration, temporary=browser_tmp),
                         env=environment(home, browser_tmp))
        stage = "chrome-owner-child-report"
        child_report = unique_json(result.stdout)
        require(type(child_report) is dict and set(child_report) == {"status", "chrome_version", "extension_resources_sha256"}
                and child_report["status"] == "PASSED", "production_chrome_journey_failed")
        for check in ["production_owner_browser_setup_used", "unchanged_packaged_extension_used",
                      "shell_parent_rejected_by_production_entrypoint", "native_pending_reached_initial_enrollment",
                      "second_pending_reached_initial_enrollment", "optional_permissions_stay_ungranted", "no_external_website_opened"]:
            checks[check] = True
        stage = "empty-vault-check"
        require(not list((BASE / "vault/data").iterdir())
                and not list((BASE / "broker").glob(".enrollment-*.publication"))
                and not list((BASE / "vault").glob(".enrollment-*.publication")), "unexpected_vault_initialization")
        checks["empty_vault_and_no_enrollment_journal"] = True
        report = {"schema": 2, "status": "PASSED", "platform": "macos", "architecture": "arm64",
            "environment": "disposable-hosted-ci-public-review", "owner_context": "existing-hosted-runner-fresh-browser-profile",
            "source_revision": args.source,
            "controller_revision": os.environ["GITHUB_SHA"], "review_archive_sha256": args.sha256,
            "publisher_team": TEAM, "chrome_version": child_report["chrome_version"],
            "component_hashes": {key: value["hashes"] for key, value in signatures.items()},
            "extension_resources_sha256": child_report["extension_resources_sha256"], "checks": checks,
            "private_signins": 0, "limits": "Public signed transport before owner enrollment; no key, website login, personal account, phone, approval or consumer installation was validated."}
        checker = runpy.run_path(str(SOURCE / "scripts/check_mac_publisher_transport_report.py"))
        report.update({key: True for key in checker["TRUE_FLAGS"] if key != "runner_identity_unchanged"})
        report["runner_identity_unchanged"] = False
        report.update({key: False for key in checker["FALSE_FLAGS"]})
    except Exception as exc:
        report = failed_report(exc, stage, checks)
        if stage.startswith("baseline-") and stage.endswith("-parent"):
            # Fixed, public system-directory metadata only; never raw errors,
            # user homes, environment values, account state or credentials.
            report["preflight_failure_type"] = preflight_failure_type
            report["public_parent_metadata"] = public_parent_metadata([
                ("support", BASE.parent), ("applications", PUBLIC_APP.parent), ("launchdaemons", JOB.parent)])
    finally:
        # Every deletion is bound to a baseline-absent name created by this run.
        cleanup_failures, cleanup_command_failures = {}, {}
        if prefix is not None:
            def cleanup(name, operation):
                cleanup_step(name, operation, checks, cleanup_failures, cleanup_command_failures)
            if owner is not None and baseline_clear:
                cleanup("chrome_and_native_children_stopped", lambda: stop_browser_processes(owner, process))
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
                cleanup("created_authorization_rule_removed", lambda: remove_review_authorization(designated))
            record = BASE / "broker/install.json"
            if record.is_file():
                def remove_broker():
                    value = unique_json(record.read_bytes())
                    uid = value["broker_uid"]
                    require(value["broker_name"] == "_accountaccess" and type(uid) is int and 450 <= uid < 500
                            and pwd.getpwnam("_accountaccess").pw_uid == uid
                            and grp.getgrnam("_accountaccess").gr_gid == uid, "cleanup_service_identity_changed")
                    service_processes = process.snapshot(uid, (BASE,))
                    require(process.stop(service_processes, (BASE,), timeout=5)
                            and not process.snapshot(uid, (BASE,)), "cleanup_processes_still_running")
                    command(["/usr/bin/dscl", ".", "-delete", "/Users/_accountaccess"])
                    command(["/usr/bin/dscl", ".", "-delete", "/Groups/_accountaccess"])
                cleanup("created_service_identity_removed", remove_broker)
            if browser_profile is not None:
                def remove_browser():
                    require(checks.get("chrome_and_native_children_stopped") is True, "cleanup_processes_still_running")
                    remove_registrations(owner, bindings)
                    remove_browser_profile(browser_profile, browser_profile_stamp, owner, process)
                    require(runner_metadata(owner) == owner_metadata, "cleanup_identity_changed")
                    report["runner_identity_unchanged"] = True
                cleanup("temporary_browser_profile_and_registration_removed", remove_browser)
            def remove_image():
                require(browser_profile is None or checks.get("temporary_browser_profile_and_registration_removed") is True,
                        "cleanup_browser_profile_changed")
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
        report = cleanup_result(report, cleanup_failures, cleanup_command_failures)
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
    for mode in ["chrome-child", "prepare-child"]:
        inner = commands.add_parser(mode)
        inner.add_argument("configuration")
    args = parser.parse_args(argv)
    try:
        if args.command == "download":
            download(args)
        elif args.command in {"chrome-child", "prepare-child"}:
            if args.command == "prepare-child":
                child(args.configuration, prepare_only=True)
            else:
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
        result = {"status": "FAILED", **public_error(exc), "production_ready": False}
        if args.command in {"chrome-child", "prepare-child"}:
            result["child_stage"] = CHILD_STAGE if CHILD_STAGE in CHILD_STAGES else "child-start"
        print(json.dumps(result))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
