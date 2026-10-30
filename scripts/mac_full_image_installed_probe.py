"""Reproduce the fixed installed-adapter fixtures as an ordinary Mac user.

Only frozen public source copies and invocation-owned temporary fixtures are
used. This never installs an image, invokes a provider, reads account data or
qualifies production root authority. Failed output is retained for inspection.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
# The fixtures are also run on busy owner Macs. Bound parallel compilation so
# this validation does not compete with every active desktop task at once.
COMPILE_SECONDS = 900
RUNTIME_SECONDS = 300
MAX_SOURCE = 2 * 1024 * 1024
MAX_LOG = 4 * 1024 * 1024
DEPENDENCIES = (
    "InstallerPayload.swift", "InstallationRootBinding.swift", "ComponentUpdateIdentity.swift",
    "ComponentUpdatePolicies.swift", "FullImageUpdatePolicies.swift", "FullImageTreeAttachment.swift",
    "FullImageTreeStorage.swift", "FullImagePlan.swift", "FullImageTransitionStorage.swift",
    "FullImageGlobalJournal.swift", "RuntimeUpgradeSource.swift", "DirectRuntimeUpgradeSource.swift",
    "BrokerRepairSource.swift", "BrokerRepairIntent.swift",
    "BrokerRepairHistory.swift", "BrokerRepairJournal.swift", "BrokerRepairRoutes.swift",
    "RootStoreVolumeBinding.swift", "RootStoreVolumePublication.swift", "StoreVolumeMigrationAuthority.swift", "StoreVolumeMigration.swift",
)
FIXTURES = (
    "CombinedPredecessorAuthorityChecks.swift", "FullImagePredecessorAuthorityChecks.swift",
    "FullImageInstalledSourceFixture.swift", "FullImageInstalledChecks.swift", "FullImageNamespaceChecks.swift",
    "FullImageLegacyGroupChecks.swift", "FullImageGlobalJournalChecks.swift",
    "BrokerRepairIntentChecks.swift", "BrokerRepairSourceChecks.swift",
    "BrokerRepairRecoveryChecks.swift",
)
MAIN_FIXTURES = frozenset((FIXTURES[0], FIXTURES[3], FIXTURES[4], FIXTURES[5], FIXTURES[6], FIXTURES[8]))
FRAGMENTS = ("macos/source-fragments/CompletedComponentPredecessor.swift.inc",
             "macos/source-fragments/FullImageInstalledAdapter.swift.inc",
             "macos/source-fragments/BrokerRepairInstalledAdapter.swift.inc",
             "macos/source-fragments/RuntimeUpgradeInstalledAdapter.swift.inc")
ENTRYPOINT = "FullImageUpdateMain.swift"
REPAIR_ENTRYPOINT = "BrokerRepairMain.swift"
EXACT_INPUTS = {
    'macos/BrokerRepairHistory.swift': '162597fe43479ba7c35e533a779b2766c1f740d6071c988b93aa931c74f06fb4',
    'macos/BrokerRepairIntent.swift': 'b1a54ef15d3f9c082da7f276e9818f2b46a0d1dbc139b0ba492a7884d7b9a9dd',
    'macos/BrokerRepairJournal.swift': '434d3c3e10a8c85806ce8248036838ea55c20028a8576593386e91b99b304371',
    'macos/BrokerRepairMain.swift': '94cc06f81f6c3bb32592e98658efe96fe911dc7e9d9e5b7d84877ca703239f37',
    'macos/BrokerRepairRoutes.swift': 'b49184efd4298198b16628a526b14253b5a3202a1370018b2a0c3f5b17d1b8aa',
    'macos/BrokerRepairSource.swift': '4202b1f7e9b2d08c2797037351d745798c0ab9bfcbdf4d0ee4970779c8db3fc0',
    'macos/ComponentUpdate.swift': '2ca027fed7ef90c0cdd016ef2aa681bb47fea36bc8c7e0e3c280ff6681c19bde',
    'macos/ComponentUpdateIdentity.swift': 'a19a5c5bb645e5091f987f9fd5f457b34df0e280ef272513de68f9dd12b35370',
    'macos/ComponentUpdatePolicies.swift': '7aca759f4b9fad195851ce12d81550ec08a0753c43515574c23fc74d247060ab',
    'macos/DirectRuntimeUpgradeSource.swift': 'fb89cf89aa55077527bc096f2da5b26285aa82271d74c3d6032c45a8a93bd585',
    'macos/FullImageGlobalJournal.swift': '9958edbc3ebafb6c884778ba65676cdc8e69a3c946c69a30f0c2b7639b160de3',
    'macos/FullImageInstalledIO.swift': '83e8ea141e879e4ad282e175bc5fcb1d2246ef278bc9767639d4bd047c2da184',
    'macos/FullImagePlan.swift': 'be714d798f25917690ddeced984a6a2578b05a5bbea9f8c97f333d0f8630f450',
    'macos/FullImagePredecessorAuthority.swift': '39a6c5b35ab1614f89983c799dd603b2585b9d219d7b3d7908e73b750209f603',
    'macos/FullImageTransitionStorage.swift': '6dd701694f993990bb470dce1a8065c033987af6298fd593844452d4132ef83f',
    'macos/FullImageTreeAttachment.swift': '8bb445ede216844f0a32144e99c27a9f06a80b7a76f4e78fbd9f30b65ce22a65',
    'macos/FullImageTreeStorage.swift': '17eddfb96064a6d2bdd174b546447ca0f8eeff16270724f2dfb1d39a863c8a8c',
    'macos/FullImageUpdateMain.swift': '80e8dff1dfd9aa04396cfc149087763365ebce801b3af42a6ff1bc7741d9ab5d',
    'macos/FullImageUpdatePolicies.swift': '5e7979aa6bbec9fb6d3bee200abcea482aaad753a8f2011042a9f0d62355b0d9',
    'macos/InstallationRootBinding.swift': 'bdfd959f69ce60f2c1d573d3e165b97f3303f66d9347f959f0662cf06dad0a58',
    'macos/InstallerPayload.swift': 'f00ba30f3192b556364995745d5dd0527b844a58da9d52a92fb60a6f33fb2df2',
    'macos/RootStoreVolumeBinding.swift': '850cae7fd1653e873c3d851953219ceae83b2a96a7c44d2861c4982b63cf0d6a',
    'macos/RootStoreVolumePublication.swift': '523fcd2507ec5f956178cc1951e55b0882ea385db373f17ea32b4f308c510c15',
    'macos/RuntimeUpgradeSource.swift': 'feeabd2738af0b01d52243e0669c2bb73ef1b5686e2284a749f051a219cb97d4',
    'macos/StoreVolumeMigration.swift': '6a0170525feb34144d37e0ce1580cd9f4bf007a24bd92126e00405e577315ae3',
    'macos/StoreVolumeMigrationAuthority.swift': '1aacffcd330e6d3bc0c96d3576b812ac62109bc63d67d693cbe8b96be0eadf66',
    'macos/Tests/BrokerRepairIntentChecks.swift': 'f3dc81b84c635f4ada2987d033996608522dcb1c473a2fe85d8d4e3a1235a405',
    'macos/Tests/BrokerRepairRecoveryChecks.swift': '27ae8cdc9881ebec60eb0667f09f59ea76d65fea41fcf5f3208384bd4d6f35ef',
    'macos/Tests/BrokerRepairSourceChecks.swift': 'ad6def26f6519fdc3d3b4f829ccb79b6c4134a7622983e64aabca3f14c6bb5ac',
    'macos/Tests/CombinedPredecessorAuthorityChecks.swift': '16d1921b6edc83654e46d1084ff9a3eaa904506ba0e7c04aa605c538882ee67c',
    'macos/Tests/FullImageGlobalJournalChecks.swift': '246c005c2d762c85aac191b24d641ebb97b54efd2ce806a319ae93bde2292a0d',
    'macos/Tests/FullImageInstalledChecks.swift': 'bafea83ca3b448321eda673b8646295b851b50025573fc9bddde7e9231c04ba0',
    'macos/Tests/FullImageInstalledSourceFixture.swift': '7c448f2ee2339735a9e0ac11e151ef135998143b20979f3ad963a4e747658ba4',
    'macos/Tests/FullImageLegacyGroupChecks.swift': '783c7166faf8844feb90dfe1c35c8a5364bb0c8328a2538ff6ab337bc5ee0992',
    'macos/Tests/FullImageNamespaceChecks.swift': '86a7cdc1063f8bcb497b0decc5dcc3025f8639f3f2c9d0de5e72945fdca7be92',
    'macos/Tests/FullImagePredecessorAuthorityChecks.swift': '34e940e3d6acc9878c57a1f96ed8cf2f805966db857dbea03e8c8c41b0fb75b4',
    'macos/source-fragments/BrokerRepairInstalledAdapter.swift.inc': '78bf44ef76b136733f2b21b53879872915582d463d1a12a1ef6a5fe2c8402dca',
    'macos/source-fragments/CompletedComponentPredecessor.swift.inc': 'bda8f8138e64f4f1bad0a05e35f63a4d05922ff19d12a1e0d8371ac8cb886be7',
    'macos/source-fragments/FullImageInstalledAdapter.swift.inc': '0b66200d82a8239a41bdeadb6b1be336f6644c32032aa45bbdf8d45257a732ab',
    'macos/source-fragments/RuntimeUpgradeInstalledAdapter.swift.inc': 'c5ef1e6d82019437fd7a8cb8eb373ab081333ab12db936e75e71659012698762',
}
COMPOSED_SHA256 = 'ef32b7d37ff5db6eb718e7d76b69978f2fb8ce41e149d9f342f7f5d66dd69694'
GUARD_ENV = "ACCOUNT_ACCESS_FULL_IMAGE_PROBE_GUARD"
DISPATCHER = b'''import Foundation
import Darwin
@main struct FullImageInstalledProbe {
    static func main() {
        switch ProcessInfo.processInfo.environment["ACCOUNT_ACCESS_FULL_IMAGE_PROBE_GUARD"] {
        case nil:
            CompletedComponentPredecessorChecks.main()
            FullImageInstalledChecks.main()
            FullImageNamespaceChecks.main()
            FullImageLegacyGroupChecks.main()
            FullImageGlobalJournalChecks.main()
            do { try BrokerRepairSourceChecks.main() } catch { exit(78) }
        case "predecessor": CompletedComponentPredecessorChecks.main()
        case "installed": FullImageInstalledChecks.main()
        case "namespace": FullImageNamespaceChecks.main()
        case "legacy-group": FullImageLegacyGroupChecks.main()
        case "global-journal": FullImageGlobalJournalChecks.main()
        case "broker-repair": do { try BrokerRepairSourceChecks.main() } catch { exit(78) }
        case "entrypoint": FullImageUpdateMain.main()
        case "repair-entrypoint": BrokerRepairMain.main()
        default: exit(77)
        }
    }
}
'''
DUMMY_COMPILED_PINS = b'''// Ordinary-user refusal check only. These zeros/empty source pins never
// represent a qualified package, predecessor or valid root authority.
enum FullImageUpdateCompiledPins {
    static let value = FullImageSourcePins(
        planSHA256: String(repeating: "0", count: 64),
        targetSourceCommit: String(repeating: "0", count: 40),
        targetManifestSHA256: String(repeating: "0", count: 64),
        caReceiptSHA256: String(repeating: "0", count: 64),
        predecessor: FullImagePredecessorPins(
            planSHA256: String(repeating: "0", count: 64),
            originalManifestSHA256: String(repeating: "0", count: 64),
            manifestSHA256: String(repeating: "0", count: 64),
            headSHA256: String(repeating: "0", count: 64)),
        predecessorSourceCommit: String(repeating: "0", count: 40),
        targetSourceFiles: [:],
        providerManifestSHA256: String(repeating: "0", count: 64),
        providerSourceBundleSHA256: String(repeating: "0", count: 64))
}
enum BrokerRepairCompiledPins {
    static let value = BrokerRepairSource.Pins(planSHA256: String(repeating: "0", count: 64),
        predecessorPlanSHA256: String(repeating: "0", count: 64), beforeManifestSHA256: String(repeating: "0", count: 64),
        afterManifestSHA256: String(repeating: "0", count: 64), sourceCommit: String(repeating: "0", count: 40))
}
'''


class Refused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def source_bytes(relative):
    """Read only a fixed repository source, without following source aliases."""
    parts = Path(relative).parts
    require(parts and not Path(relative).is_absolute() and all(part not in {"", ".", ".."} for part in parts),
            "source_path_refused")
    parent = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= MAX_SOURCE,
                    "source_attachment_refused")
            raw = stream.read(MAX_SOURCE + 1)
            require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno()))
                    == stamp(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)), "source_changed_during_read")
        return raw
    finally:
        os.close(parent)


def write_file(parent, name, raw):
    require(name and "/" not in name and name not in {".", ".."}, "output_name_refused")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


class Probe:
    def __init__(self, output):
        self.output = output
        self.root_fd = -1
        self.source_fd = -1
        self.originals = {}
        self.copies = {}
        self.result = {"schema": 1, "status": "REFUSED", "stage": "source-freeze", "commands": [],
                       "source_sha256": {}, "derived_source_sha256": {},
                       "installed_reads": False, "root_execution": False, "service_actions": False,
                       "provider_process_or_network_used": False, "production_ready": False}

    def attach(self):
        os.mkdir(self.output, mode=0o700)  # Existing directories and symlinks are refused.
        self.root_fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(self.root_fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "output_attachment_refused")
        self.root_identity = (info.st_dev, info.st_ino)
        os.mkdir("sources", mode=0o700, dir_fd=self.root_fd)
        self.source_fd = os.open("sources", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=self.root_fd)

    def attached(self):
        info = os.stat(self.output, follow_symlinks=False)
        held = os.fstat(self.root_fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
                and (info.st_dev, info.st_ino) == self.root_identity == (held.st_dev, held.st_ino), "output_attachment_changed")
        path = os.stat("sources", dir_fd=self.root_fd, follow_symlinks=False)
        held = os.fstat(self.source_fd)
        require(stat.S_ISDIR(path.st_mode) and path.st_uid == os.getuid() and stat.S_IMODE(path.st_mode) == 0o700
                and (path.st_dev, path.st_ino) == (held.st_dev, held.st_ino), "source_copy_attachment_changed")

    def copy(self, name, raw):
        require(name not in self.copies, "duplicate_compiler_basename")
        write_file(self.source_fd, name, raw)
        self.copies[name] = raw
        self.result["derived_source_sha256"][name] = digest(raw)
        return str(self.output / "sources" / name)

    def prepare(self):
        names = ["macos/" + name for name in DEPENDENCIES]
        names += ["macos/ComponentUpdate.swift", *FRAGMENTS, "macos/FullImageInstalledIO.swift",
                  "macos/FullImagePredecessorAuthority.swift", "macos/" + ENTRYPOINT, "macos/" + REPAIR_ENTRYPOINT,
                  *("macos/Tests/" + name for name in FIXTURES),
                  "scripts/mac_full_image_installed_probe.py"]
        require(len(names) == len(set(names)), "duplicate_source_input")
        for name in names:
            raw = source_bytes(name)
            require(name not in EXACT_INPUTS or digest(raw) == EXACT_INPUTS[name], "reviewed_source_pin_changed")
            self.originals[name] = raw
            self.result["source_sha256"][name] = digest(raw)
        composed = b"\n".join(self.originals[name] for name in ["macos/ComponentUpdate.swift", *FRAGMENTS])
        require(digest(composed) == COMPOSED_SHA256, "source_composition_changed")
        self.result["composition"] = {"inputs": ["macos/ComponentUpdate.swift", *FRAGMENTS],
                                      "separator_hex": "0a", "trimmed": False, "sha256": digest(composed)}
        paths = [self.copy(name, self.originals["macos/" + name]) for name in DEPENDENCIES]
        paths.append(self.copy("ComponentUpdate.swift", composed))
        for name in ["FullImageInstalledIO.swift", "FullImagePredecessorAuthority.swift"]:
            paths.append(self.copy(name, self.originals["macos/" + name]))
        transforms = {}
        for name in FIXTURES:
            raw = self.originals["macos/Tests/" + name]
            if name in MAIN_FIXTURES:
                require(raw.count(b"@main ") == 1, "fixture_main_annotation_changed")
                raw = raw.replace(b"@main ", b"", 1)
                transforms[name] = "Remove only one @main annotation; preserve the complete main body and guards"
            paths.append(self.copy(name, raw))
        for name in [ENTRYPOINT, REPAIR_ENTRYPOINT]:
            entrypoint = self.originals["macos/" + name]
            require(entrypoint.count(b"@main ") == 1, "entrypoint_main_annotation_changed")
            paths.append(self.copy(name, entrypoint.replace(b"@main ", b"", 1)))
            transforms[name] = "Remove only one @main annotation; preserve the production body and root guard"
        paths.append(self.copy("FullImageUpdateCompiledPins.swift", DUMMY_COMPILED_PINS))
        paths.append(self.copy("FullImageInstalledProbe.swift", DISPATCHER))
        self.result["validation_copy_transformations"] = transforms
        self.result["entrypoint_dummy_pins"] = "All-zero hashes/commits and empty source map; ordinary-user refusal only"
        self.result["entrypoint_root_authority_qualified"] = False
        self.compiler = ["/usr/bin/swiftc", "-j", "2", "-Onone", "-D", "ACCOUNT_ACCESS_FULL_IMAGE_INSTALLED_CHECKS",
                         "-D", "ACCOUNT_ACCESS_COMPONENT_PREDECESSOR_CHECKS", "-D",
                         "ACCOUNT_ACCESS_COMPONENT_PREDECESSOR_FIXTURE_MAIN", "-D",
                         "ACCOUNT_ACCESS_FULL_IMAGE_UPDATE_MAIN", "-D", "ACCOUNT_ACCESS_BROKER_REPAIR_MAIN", *paths,
                         "-o", str(self.output / "installed-probe")]
        self.result["compiler_command"] = self.compiler
        write_file(self.root_fd, "source-freeze.json", encoded({**self.result, "status": "SOURCE_FROZEN",
                                                               "combined_compile_count": 0}))

    def stable(self):
        self.attached()
        for name, raw in self.originals.items():
            require(source_bytes(name) == raw, "source_drift")
        for name, raw in self.copies.items():
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.source_fd)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stream.read(MAX_SOURCE + 1) == raw,
                        "derived_source_drift")

    def run(self, command, name, seconds, *, guard=None):
        self.stable()
        started = time.monotonic()
        stdout_fd = os.open(name + ".stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=self.root_fd)
        stderr_fd = os.open(name + ".stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=self.root_fd)
        env = dict(os.environ)
        env.pop(GUARD_ENV, None)
        if guard is not None:
            env[GUARD_ENV] = guard
        process = None
        stopped = None
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout_fd, stderr=stderr_fd,
                                       start_new_session=True, cwd=ROOT, env=env)
            while process.poll() is None:
                if time.monotonic() - started >= seconds:
                    stopped = "deadline"
                    break
                if max(os.fstat(stdout_fd).st_size, os.fstat(stderr_fd).st_size) > MAX_LOG:
                    stopped = "log_limit"
                    break
                time.sleep(0.05)
            if stopped:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                grace = time.monotonic() + 5
                while time.monotonic() < grace:
                    process.poll()  # Reap the leader; descendants may still own its process group.
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.05)
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            code = process.wait(timeout=5)
        finally:
            if process is not None:
                # A successful leader exit also must not leave an invocation-owned
                # descendant running. Never infer group lifetime from the leader.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            os.close(stdout_fd)
            os.close(stderr_fd)
        def log(suffix):
            fd = os.open(name + suffix, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=self.root_fd)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "subprocess_log_attachment_refused")
                return stream.read(MAX_LOG + 1), info.st_size

        stdout, stdout_size = log(".stdout")
        stderr, stderr_size = log(".stderr")
        record = {"name": name, "command": command, "timeout_seconds": seconds, "exit_code": code,
                  "stopped": stopped, "seconds": round(time.monotonic() - started, 3),
                  "stdout_sha256": digest(stdout) if stdout_size <= MAX_LOG else None,
                  "stderr_sha256": digest(stderr) if stderr_size <= MAX_LOG else None,
                  "stdout_bytes": stdout_size, "stderr_bytes": stderr_size}
        self.result["commands"].append(record)
        self.stable()
        require(stopped is None and max(stdout_size, stderr_size) <= MAX_LOG, "subprocess_bound_exceeded")
        return code, stdout, stderr

    def qualify(self):
        self.result["stage"] = "compile"
        code, _, stderr = self.run(self.compiler, "compile", COMPILE_SECONDS)
        require(code == 0 and stderr == b"", "native_compile_failed")
        binary = str(self.output / "installed-probe")
        self.result["stage"] = "fixture-runtime"
        code, stdout, stderr = self.run([binary], "runtime", RUNTIME_SECONDS)
        require(code == 0 and stderr == b"", "native_fixture_failed")
        reports = [json.loads(line) for line in stdout.decode("utf-8").splitlines() if line.startswith("{")]
        require(len(reports) == 6 and all(report.get("status") == "PASSED" for report in reports[:4]), "fixture_reports_refused")
        require(reports[0].get("count") == 159 and isinstance(reports[0].get("checks"), dict)
                and len(reports[0]["checks"]) == 159 and all(value is True for value in reports[0]["checks"].values())
                and reports[1].get("checks") == 625, "fixture_assertion_count_changed")
        namespace = reports[2]
        require((namespace.get("checks"), namespace.get("supplemental_group_case")) in {
            (29, "UNAVAILABLE_NO_DISTINCT_GROUP"),
            (40, "PASSED_INHERITED_DIFFERENT_GROUP_CORRECTED_ONLY_ON_NEW_INODE")}, "namespace_report_refused")
        legacy, journal, repair = reports[3:]
        require(legacy.get("checks") == 63 and legacy.get("ordinary_temp_only") is True
                and legacy.get("supplemental_group_case") == "PASSED_DISTINCT_OLD_AND_NEW_GROUPS"
                and legacy.get("optional_polarities") == 2 and legacy.get("recovery_polarities") == 3,
                "legacy_group_report_refused")
        require(journal == {"status": "FULL_IMAGE_DURABLE_JOURNAL_CHECKS_PASSED", "assertions": 164,
                            "installed_or_provider_operations": False}
                and journal["installed_or_provider_operations"] is False, "global_journal_report_refused")
        require(repair == {"schema": 1, "status": "PASSED", "source_assertions": 54, "recovery_assertions": 49, "transaction_assertions": 88,
                           "installed_reads": False, "payload_executed": False, "production_ready": False}
                and type(repair["schema"]) is int
                and all(repair[key] is False for key in ("installed_reads", "payload_executed", "production_ready")),
                "broker_repair_report_refused")
        require(all(report.get(key) is False for report in reports[:4]
                    for key in ["installed_reads", "root_execution", "service_actions", "production_ready"]),
                "fixture_scope_report_refused")
        self.result["reports"] = reports
        self.result["supplemental_group_case"] = namespace["supplemental_group_case"]
        self.result["stage"] = "guarded-main-refusal"
        for guard in ["predecessor", "installed", "namespace", "legacy-group", "global-journal", "broker-repair"]:
            code, stdout, stderr = self.run([binary, "--unexpected-argument"], "guard-" + guard, 10, guard=guard)
            require(code == 77 and stdout == stderr == b"", "guarded_main_refusal_failed")
        self.result["stage"] = "ordinary-updater-entrypoint-refusal"
        code, stdout, stderr = self.run([binary], "entrypoint-ordinary", 10, guard="entrypoint")
        require(code == 78 and stderr == b"" and stdout ==
                b'{"schema":1,"status":"REFUSED","reason":"full_image_update_context_required"}\n',
                "ordinary_updater_entrypoint_refusal_failed")
        self.result["entrypoint_ordinary_refusal"] = {"exit_code": 78, "normal_argv": True,
                                                     "reason": "full_image_update_context_required"}
        code, stdout, stderr = self.run([binary], "repair-entrypoint-ordinary", 10, guard="repair-entrypoint")
        require(code == 78 and stderr == b"" and stdout ==
                b'{"schema":1,"status":"REFUSED","reason":"broker_repair_installer_context_required"}\n',
                "ordinary_broker_repair_entrypoint_refusal_failed")
        self.result["repair_entrypoint_ordinary_refusal"] = {"exit_code": 78, "normal_argv": True,
                                                           "reason": "broker_repair_installer_context_required"}
        self.stable()
        self.result.update(status="PASSED", stage="complete", sources_stable=True,
                           combined_compile_count=1, guarded_main_refusals=6)

    def save(self):
        if self.root_fd >= 0:
            write_file(self.root_fd, "result.json", encoded(self.result))

    def close(self):
        for fd in [self.source_fd, self.root_fd]:
            if fd >= 0:
                os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New output directory; existing paths are refused")
    parser.add_argument("--prepare-only", action="store_true", help="Freeze public source copies without compiling or running")
    args = parser.parse_args()
    probe = None
    try:
        require(sys.platform == "darwin" and os.getuid() != 0 and os.geteuid() == os.getuid(), "ordinary_mac_required")
        output = args.output.absolute()
        require(output.parent.resolve(strict=True) == output.parent, "output_parent_alias_refused")
        os.umask(0o077)
        probe = Probe(output)
        probe.attach()
        probe.prepare()
        if args.prepare_only:
            probe.stable()
            probe.result.update(status="PREPARED_SOURCE_ONLY", stage="prepared", sources_stable=True,
                                combined_compile_count=0)
        else:
            probe.qualify()
        probe.save()
        print(json.dumps({"status": probe.result["status"], "output": str(output),
                          "result_sha256": digest((output / "result.json").read_bytes()),
                          "installed_reads": False, "production_ready": False}, sort_keys=True))
        return 0
    except Exception as error:
        reason = str(error) if isinstance(error, Refused) else "installed_probe_failed"
        if probe is not None:
            probe.result.update(status="REFUSED", reason=reason, error_type=type(error).__name__)
            probe.save()
        print(json.dumps({"status": "REFUSED", "reason": reason, "production_ready": False}, sort_keys=True))
        return 78
    finally:
        if probe is not None:
            probe.close()


if __name__ == "__main__":
    raise SystemExit(main())
