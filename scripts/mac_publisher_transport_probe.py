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
PUBLIC_REASONS = set("""
authorization_lookup_failed broker_designated_requirement_missing cleanup_authorization_changed
cleanup_authorization_still_present cleanup_identity_changed cleanup_identity_invalid cleanup_job_not_owned
cleanup_job_still_loaded cleanup_owner_domain_still_loaded cleanup_process_query_invalid cleanup_processes_still_running
cleanup_owner_identity_still_present cleanup_owner_records_changed cleanup_owner_domain_after_identity_removal
cleanup_public_alias_changed cleanup_public_image_changed cleanup_service_identity_changed controller_revision_mismatch
duplicate_review_field existing_production_authorization_rule existing_production_identity existing_production_installation
existing_production_job fresh_review_identity_unavailable hosted_arm64_mac_required hosted_review_only invalid_review_asset
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
review_owner_home_not_empty review_owner_identity_mismatch review_package_files_mismatch review_package_source_mismatch
review_publisher_mismatch review_runtime_package_missing review_runtime_source_mismatch review_source_tree_changed
shared_applications_parent_changed unexpected_vault_initialization unsafe_review_archive_entry unsafe_shared_applications_parent
untrusted_review_support_parent untrusted_review_applications_parent untrusted_review_launchdaemons_parent
""".split())
PUBLIC_EXCEPTION_TYPES = {"ReviewError", "BootstrapError", "ProvisionError", "FileNotFoundError", "PermissionError",
                          "ValueError", "JSONDecodeError", "KeyError", "OSError", "TimeoutExpired",
                          "ModuleNotFoundError", "ImportError", "AccessError", "Error", "TargetClosedError", "TimeoutError"}
CHILD_STAGES = set("""child-start hosted-guard production-imports playwright-import configuration owner-identity owner-home
production-browser-prepare negative-shell-parent extension-manifest chrome-profile playwright-driver chrome-launch
chrome-routing cdp-connection extension-load service-worker native-exchange permissions-check result-check chrome-close""".split())
CHILD_STAGE = "child-start"
DOMAIN_STATES = {"unknown", "active", "running", "waiting", "exited", "stopped", "terminating", "booted-out"}
PUBLIC_COMMAND_KINDS = set("""codesign_designated codesign_verify codesign_metadata authorization_read authorization_remove
authorization_other launchctl_print launchctl_bootstrap launchctl_bootout launchctl_owner_child launchctl_other git_source
github_metadata lipo_architecture directory_record directory_cache identity_process_stop identity_process_query other_command""".split())


class ReviewError(Exception):
    def __init__(self, reason, *, command_failure=None, child_failure=None, domain_diagnostic=None):
        super().__init__(reason)
        self.command_failure = command_failure
        self.child_failure = child_failure
        self.domain_diagnostic = domain_diagnostic


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


def public_domain_detail(value):
    if (type(value) is dict and set(value) == {"diagnostic_only", "last_print_succeeded", "service_count", "active_service_count", "state"}
            and value["diagnostic_only"] is True and value["last_print_succeeded"] is True
            and all(value[key] is None or type(value[key]) is int and 0 <= value[key] <= 100000
                    for key in ["service_count", "active_service_count"])
            and type(value["state"]) is str and value["state"] in DOMAIN_STATES):
        return dict(value)
    return None


def public_error(error):
    name = type(error).__name__
    result = {"reason": str(error) if isinstance(error, ReviewError) and str(error) in PUBLIC_REASONS
              else "publisher_transport_failed", "failure_type": name if name in PUBLIC_EXCEPTION_TYPES else "Exception"}
    detail = public_command_detail(error.command_failure) if isinstance(error, ReviewError) else None
    if detail is not None:
        result["command_failure"] = detail
    child = public_child_failure(error.child_failure) if isinstance(error, ReviewError) else None
    if child is not None:
        result["child_failure"] = child
    domain = public_domain_detail(error.domain_diagnostic) if isinstance(error, ReviewError) else None
    if domain is not None:
        result["domain_diagnostic"] = domain
    if isinstance(error, OSError) and type(error.errno) is int and 0 < error.errno < 4096:
        result["errno"] = error.errno
    return result


def failed_report(error, stage, checks):
    return {"status": "FAILED", **public_error(error), "stage": stage, "checks": checks,
            "production_ready": False, "private_signins": 0}


def cleanup_result(report, failures, command_failures, domain_diagnostics=None):
    if failures:
        report = dict(report)
        report.update(failed_stage=report.get("stage", "none"), failed_reason=report.get("reason", "none"),
                      status="FAILED", reason="publisher_transport_cleanup_failed", stage="cleanup",
                      cleanup_failures=failures)
        if command_failures:
            report["cleanup_command_failures"] = command_failures
        if domain_diagnostics:
            report["cleanup_domain_diagnostics"] = domain_diagnostics
    return report


def cleanup_step(name, operation, checks, failures, command_failures, domain_diagnostics=None):
    try:
        operation()
        checks[name] = True
    except Exception as error:
        details = public_error(error)
        checks[name] = False
        failures[name] = details["reason"] if details["reason"] != "publisher_transport_failed" else details["failure_type"]
        if "command_failure" in details:
            command_failures[name] = details["command_failure"]
        if domain_diagnostics is not None and "domain_diagnostic" in details:
            domain_diagnostics[name] = details["domain_diagnostic"]


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
            "/usr/bin/dscl": "directory_record", "/usr/bin/dscacheutil": "directory_cache",
            "/usr/bin/pkill": "identity_process_stop", "/bin/ps": "identity_process_query"}.get(executable, "other_command")


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


def owner_child_arguments(uid, name, home, controller, configuration):
    # sudo deliberately removes arbitrary caller variables. Restore only this
    # public CI/owner-home whitelist after credentials have changed; no token,
    # source interpreter override, or parent environment can reach the child.
    values = environment(home)
    return ["/bin/launchctl", "asuser", str(uid), "/usr/bin/sudo", "-n", "-u", name, "--",
            "/usr/bin/env", "-i", *(key + "=" + values[key] for key in sorted(values)),
            str(BASE / "runtime/bin/python"), "-I", "-B", str(controller), "chrome-child", str(configuration)]


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


def residual_domain_diagnostic(raw):
    # launchctl documents print as unstable human diagnostics, not an API.
    # These optional observations never establish absence or cleanup success.
    result = {"diagnostic_only": True, "last_print_succeeded": True,
              "service_count": None, "active_service_count": None, "state": "unknown"}
    if type(raw) is not bytes or len(raw) > 65536:
        return result
    text = raw.decode("utf-8", errors="replace")
    for key, label in [("service_count", "service count"), ("active_service_count", "active service count")]:
        matches = re.findall(r"^(?:\t| {4})" + re.escape(label) + r" = ([0-9]+)$", text, re.MULTILINE)
        if len(matches) == 1 and len(matches[0]) <= 6 and 0 <= int(matches[0]) <= 100000:
            result[key] = int(matches[0])
    states = re.findall(r"^(?:\t| {4})state = ([a-z-]+)$", text, re.MULTILINE)
    if len(states) == 1 and states[0] in DOMAIN_STATES:
        result["state"] = states[0]
    return result


def stop_owner_domain(uid):
    require(type(uid) is int and 50000 <= uid < 60000, "cleanup_identity_invalid")
    domain = "user/" + str(uid)
    bootout = None
    observed = command(["/bin/launchctl", "print", domain], check=False, timeout=5)
    if observed.returncode == 0:
        bootout = command(["/bin/launchctl", "bootout", domain], check=False, timeout=5)
    # Domain retirement may wait for its own user processes to exit. Neither
    # a nonzero bootout nor a transient domain is treated as cleanup success.
    stop_uid(uid)
    deadline = time.monotonic() + 5
    retried = False
    while time.monotonic() < deadline:
        observed = command(["/bin/launchctl", "print", domain], check=False, timeout=5)
        if observed.returncode != 0:
            require(not uid_processes(uid), "cleanup_processes_still_running")
            return
        if not retried:
            bootout = command(["/bin/launchctl", "bootout", domain], check=False, timeout=5)
            retried = True
        time.sleep(0.1)
    raise ReviewError("cleanup_owner_domain_still_loaded", command_failure=command_diagnostic(
        ["/bin/launchctl", "bootout"], exitcode=bootout.returncode if bootout is not None else None),
        domain_diagnostic=residual_domain_diagnostic(observed.stdout))


def verify_owner_identity(owner):
    current = pwd.getpwnam(owner.pw_name)
    group = grp.getgrnam(owner.pw_name)
    require((current.pw_uid, current.pw_gid, current.pw_dir) == (owner.pw_uid, owner.pw_gid, owner.pw_dir)
            and group.gr_gid == owner.pw_gid, "cleanup_identity_changed")


def stop_owner_processes(owner):
    verify_owner_identity(owner)
    require(type(owner.pw_uid) is int and 50000 <= owner.pw_uid < 60000, "cleanup_identity_invalid")
    domain = "user/" + str(owner.pw_uid)
    if command(["/bin/launchctl", "print", domain], check=False, timeout=5).returncode == 0:
        command(["/bin/launchctl", "bootout", domain], check=False, timeout=5)
    stop_uid(owner.pw_uid)
    require(not uid_processes(owner.pw_uid), "cleanup_processes_still_running")


def remove_owner_identity(owner, records):
    from account_access.system_provision import directory_value
    require(re.fullmatch(r"aap[a-f0-9]{12}", owner.pw_name) is not None
            and len(records) == 2 and set(records) == {"/Users/" + owner.pw_name, "/Groups/" + owner.pw_name},
            "cleanup_owner_records_changed")
    stop_owner_processes(owner)
    for record in reversed(records):
        command(["/usr/bin/dscl", ".", "-delete", record])
    command(["/usr/bin/dscacheutil", "-flushcache"])
    for record in records:
        require(directory_value(record, "RecordName") is None, "cleanup_owner_identity_still_present")
    # libc/OpenDirectory may retain a deleted record. The fixed local dscl
    # RecordName reads above are the authoritative absence proof.
    try:
        stop_owner_domain(owner.pw_uid)
    except ReviewError as error:
        if str(error) == "cleanup_owner_domain_still_loaded":
            raise ReviewError("cleanup_owner_domain_after_identity_removal", command_failure=error.command_failure,
                              domain_diagnostic=error.domain_diagnostic) from None
        raise
    require(not uid_processes(owner.pw_uid), "cleanup_processes_still_running")


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
    require(set(config) == {"owner_uid", "home", "prefix"} and config["owner_uid"] == os.getuid()
            and config["home"] == str(home) and home == Path(config["prefix"]) / "owner-home"
            and re.fullmatch(r"/Library/Application Support/account-access-publisher-qa-[a-f0-9]{16}", config["prefix"]),
            "review_child_identity_mismatch")
    CHILD_STAGE = "owner-home"
    require(set(home.iterdir()) == {home / "tmp"}, "review_owner_home_not_empty")
    CHILD_STAGE = "production-browser-prepare"
    prepared = prepare(home)
    require(prepared["extension_path"] == str(APP / "Contents/Resources/GoogleMessagesExtension")
            and prepared["extension_id"] == EXTENSION, "production_browser_setup_failed")
    launcher = home / "Library/Application Support/Account Access/browser-v1/native-host"
    CHILD_STAGE = "negative-shell-parent"
    negative = command([str(launcher), ORIGIN], timeout=10, check=False, env=environment(home), input=b"")
    require(negative.returncode == 78 and negative.stdout == b"", "production_parent_guard_failed")
    CHILD_STAGE = "extension-manifest"
    hashes = {name: digest(APP / "Contents/Resources/GoogleMessagesExtension" / name) for name in RESOURCES}
    manifest = unique_json((APP / "Contents/Resources/GoogleMessagesExtension/manifest.json").read_bytes())
    require("host_permissions" not in manifest, "production_manifest_changed")
    CHILD_STAGE = "chrome-profile"
    profile = home / "Library/Application Support/Google/Chrome"
    require({item.name for item in profile.iterdir()} == {"NativeMessagingHosts"}, "review_browser_profile_not_fresh")
    CHILD_STAGE = "playwright-driver"
    with sync_playwright() as playwright:
        CHILD_STAGE = "chrome-launch"
        context = playwright.chromium.launch_persistent_context(str(profile), executable_path=str(CHROME / "Contents/MacOS/Google Chrome"),
            headless=True, chromium_sandbox=True, ignore_default_args=["--disable-extensions"],
            args=["--enable-unsafe-extension-debugging", "--password-store=basic", "--use-mock-keychain"],
            env=environment(home), timeout=25000)
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
        stage = "owner-identity"
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
        stage = "owner-bootstrap-domain"
        command(["/bin/launchctl", "bootstrap", "user/" + str(uid)])
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
        configuration.write_text(json.dumps({"owner_uid": uid, "home": str(home), "prefix": str(prefix)}))
        configuration.chmod(0o644)
        stage = "chrome-owner-child"
        result = owner_child_command(owner_child_arguments(uid, name, home, controller, configuration),
                         env=environment(home))
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
        report = failed_report(exc, stage, checks)
        if stage.startswith("baseline-") and stage.endswith("-parent"):
            # Fixed, public system-directory metadata only; never raw errors,
            # user homes, environment values, account state or credentials.
            report["preflight_failure_type"] = preflight_failure_type
            report["public_parent_metadata"] = public_parent_metadata([
                ("support", BASE.parent), ("applications", PUBLIC_APP.parent), ("launchdaemons", JOB.parent)])
    finally:
        # Every deletion is bound to a baseline-absent name created by this run.
        cleanup_failures, cleanup_command_failures, cleanup_domain_diagnostics = {}, {}, {}
        if prefix is not None:
            def cleanup(name, operation):
                cleanup_step(name, operation, checks, cleanup_failures, cleanup_command_failures, cleanup_domain_diagnostics)
            if owner is not None:
                cleanup("chrome_and_native_children_stopped", lambda: stop_owner_processes(owner))
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
                    command(["/bin/launchctl", "bootout", "user/" + str(uid)], check=False)
                    stop_uid(uid)
                    command(["/usr/bin/dscl", ".", "-delete", "/Users/_accountaccess"])
                    command(["/usr/bin/dscl", ".", "-delete", "/Groups/_accountaccess"])
                cleanup("created_service_identity_removed", remove_broker)
            if owner_records:
                def remove_owner():
                    if owner is not None:
                        remove_owner_identity(owner, owner_records)
                        return
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
        report = cleanup_result(report, cleanup_failures, cleanup_command_failures, cleanup_domain_diagnostics)
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
        result = {"status": "FAILED", **public_error(exc), "production_ready": False}
        if args.command == "chrome-child":
            result["child_stage"] = CHILD_STAGE if CHILD_STAGE in CHILD_STAGES else "child-start"
        print(json.dumps(result))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
