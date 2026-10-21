// In-development ordinary temp-only fixture; this is not an installed updater.
// No account database, Keychain, service or real owner policy is accessed.
import Foundation
import CryptoKit
import Darwin

private enum FixtureFailure: Error { case failed, interruption }

@main struct PublicTreeChecks {
    private static var count = 0
    private static func expect(_ value: Bool) throws {
        guard value else { throw FixtureFailure.failed }; count += 1
    }
    private static func refuses(_ body: () throws -> Void) throws {
        var refused = false
        do { try body() } catch { refused = true }
        try expect(refused)
    }
    private static func directory(_ parent: Int32, _ name: String, _ mode: mode_t) throws -> Int32 {
        guard mkdirat(parent, name, mode) == 0 else { throw FixtureFailure.failed }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0, fchmod(fd, mode) == 0 else { throw FixtureFailure.failed }
        _ = try InstallerPayloadIO.check(fd, owner: getuid(), directory: true)
        return fd
    }
    private static func file(_ parent: Int32, _ name: String, _ data: Data) throws {
        let fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw FixtureFailure.failed }
        defer { Darwin.close(fd) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard written > 0 else { throw FixtureFailure.failed }; offset += written
            }
        }
        guard fchmod(fd, 0o644) == 0, fsync(fd) == 0 else { throw FixtureFailure.failed }
    }
    private static func row(_ data: Data) -> [String: Any] {
        ["kind": "file", "mode": 0o644, "size": data.count, "sha256": PublicTreeInventory.digest(data)]
    }
    private static func manifest(_ unit: PublicTreeUnit, _ data: Data) throws -> PublicTreeInventory {
        let dir: [String: Any] = ["kind": "directory", "mode": 0o755]
        var rows: [String: [String: Any]] = ["": dir, "owner.app": dir, "owner.app/Contents": dir,
            "owner.app/Contents/MacOS": dir, "owner.app/Contents/MacOS/AccountAccess": row(Data("dummy-not-executed".utf8))]
        let parts = unit.path.split(separator: "/").map(String.init)
        for index in 1...parts.count { rows[parts.prefix(index).joined(separator: "/")] = dir }
        rows[unit.path + "/value.txt"] = row(data)
        rows[unit.path + "/aux.txt"] = row(Data("aux".utf8))
        rows[unit.path + "/alias"] = ["kind": "symlink", "target": "value.txt"]
        let value: [String: Any] = ["schema": 1, "managed_by": "account-access-install-payload-v1",
            "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
            "roots": [InstallerPayloadManifest.support: rows,
                InstallerPayloadManifest.application: ["": ["kind": "symlink", "target": InstallerPayloadManifest.applicationTarget]]]]
        return try PublicTreeInventory(manifest: JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), unit: unit)
    }
    private static func tree(_ parent: Int32, _ name: String, _ unit: PublicTreeUnit, _ data: Data) throws {
        let root = try directory(parent, name, 0o755)
        defer { Darwin.close(root) }
        try file(root, "value.txt", data); try file(root, "aux.txt", Data("aux".utf8))
        guard symlinkat("value.txt", root, "alias") == 0 else { throw FixtureFailure.failed }
        if unit == .owner {
            let contents = try directory(root, "Contents", 0o755)
            defer { Darwin.close(contents) }
            let macOS = try directory(contents, "MacOS", 0o755)
            defer { Darwin.close(macOS) }
            try file(macOS, "AccountAccess", Data("dummy-not-executed".utf8))
        }
    }
    private final class Scenario {
        let unit: PublicTreeUnit
        let parent: Int32, target: Int32, retained: Int32, journal: Int32
        let old: PublicTreeInventory, new: PublicTreeInventory
        let operation: PublicTreeOperation
        var quiescent = true
        init(root: Int32, name: String, unit: PublicTreeUnit) throws {
            self.unit = unit
            parent = try directory(root, name, 0o700)
            target = try directory(parent, "target-parent", 0o755)
            retained = try directory(parent, "retained-parent", 0o700)
            journal = try directory(parent, "journal", 0o700)
            let a = Data("old-tree".utf8), b = Data("new-tree-longer".utf8)
            old = try manifest(unit, a); new = try manifest(unit, b)
            try tree(target, unit.name, unit, a); try tree(retained, unit.slot, unit, b)
            operation = try PublicTreeStorage.capture(unit: unit, targetParent: target, retainedParent: retained,
                old: old, new: new, owner: getuid(), group: getgid(), planSHA256: String(repeating: "a", count: 64))
        }
        deinit { [parent, target, retained, journal].forEach { Darwin.close($0) } }
        func storage(fault: @escaping (PublicTreeStorage.Phase) throws -> Void = { _ in }) throws -> PublicTreeStorage {
            try PublicTreeStorage.open(operation: operation, unit: unit, targetParent: target, retainedParent: retained,
                journalParent: journal, old: old, new: new, owner: getuid(), group: getgid(), requireQuiescent: {
                    guard self.quiescent else { throw PublicTreeFailure.barrier }
                }, fault: fault)
        }
        func stagedFD() throws -> Int32 {
            let fd = openat(retained, unit.slot, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw FixtureFailure.failed }; return fd
        }
    }
    private static func cleanup(_ fd: Int32) throws {
        // Only descendants of this invocation's newly owned random temp root.
        for name in try InstallerPayloadIO.contents(fd) {
            var before = stat()
            guard fstatat(fd, name, &before, AT_SYMLINK_NOFOLLOW) == 0, before.st_uid == getuid() else { throw FixtureFailure.failed }
            if before.st_mode & S_IFMT == S_IFDIR {
                let child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw FixtureFailure.failed }
                do { try cleanup(child) } catch { Darwin.close(child); throw error }
                var held = stat(), path = stat()
                guard fstat(child, &held) == 0, fstatat(fd, name, &path, AT_SYMLINK_NOFOLLOW) == 0,
                      held.st_dev == path.st_dev, held.st_ino == path.st_ino else { Darwin.close(child); throw FixtureFailure.failed }
                Darwin.close(child)
                guard unlinkat(fd, name, AT_REMOVEDIR) == 0 else { throw FixtureFailure.failed }
            } else {
                guard before.st_mode & S_IFMT == S_IFREG || before.st_mode & S_IFMT == S_IFLNK,
                      unlinkat(fd, name, 0) == 0 else { throw FixtureFailure.failed }
            }
        }
    }
    static func main() {
        guard getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 1 else { exit(77) }
        umask(0o077)
        var scratch = Array("/private/tmp/account-access-public-tree-XXXXXX".utf8CString)
        do {
            let path = try scratch.withUnsafeMutableBufferPointer { buffer -> String in
                guard let pointer = mkdtemp(buffer.baseAddress!) else { throw FixtureFailure.failed }
                return String(cString: pointer) // Own the String while the buffer is alive.
            }
            let root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0 else { throw FixtureFailure.failed }
            defer { Darwin.close(root) }
            let original = try InstallerPayloadIO.check(root, owner: getuid(), directory: true)
            // This descriptor belongs to this invocation's exclusive new root.
            // BSD directory inheritance may otherwise preserve /private/tmp's GID.
            guard fchown(root, uid_t.max, getgid()) == 0, fchmod(root, 0o700) == 0 else { throw FixtureFailure.failed }
            for (index, unit) in PublicTreeUnit.allCases.enumerated() {
                let scenario = try Scenario(root: root, name: "roundtrip-\(index)", unit: unit)
                let storage = try scenario.storage()
                try expect(try storage.state() == .staged)
                try storage.apply(); try expect(try storage.state() == .applied)
                try storage.apply(); try expect(try storage.state() == .applied)
                try storage.reverse(); try expect(try storage.state() == .staged)
                try expect(try PublicTreeIO.observe(scenario.target, name: unit.name, inventory: scenario.old,
                    owner: getuid(), group: getgid()) == scenario.operation.before)
            }
            do {
                let scenario = try Scenario(root: root, name: "interrupted", unit: .owner)
                let storage = try scenario.storage { phase in
                    if phase == .afterRename { throw FixtureFailure.interruption }
                }
                try refuses { try storage.apply() }
                try expect(try storage.state() == .applied)
                let retry = try scenario.storage()
                try retry.apply(); try expect(try retry.state() == .applied)
                try retry.reverse(); try expect(try retry.state() == .staged)
            }
            for (index, mutation) in ["extra-member", "symlink-file", "hardlink-file", "bad-link-target", "wrong-mode", "wrong-bytes"].enumerated() {
                let scenario = try Scenario(root: root, name: "refusal-\(index)", unit: .project)
                let storage = try scenario.storage(), staged = try scenario.stagedFD()
                defer { Darwin.close(staged) }
                if mutation == "extra-member" { try file(staged, "unknown", Data("x".utf8)) }
                else if mutation == "symlink-file" {
                    guard unlinkat(staged, "value.txt", 0) == 0, symlinkat("aux.txt", staged, "value.txt") == 0 else { throw FixtureFailure.failed }
                } else if mutation == "hardlink-file" {
                    guard linkat(staged, "aux.txt", scenario.parent, "outside-owned-hardlink", 0) == 0 else { throw FixtureFailure.failed }
                } else if mutation == "bad-link-target" {
                    guard unlinkat(staged, "alias", 0) == 0, symlinkat("aux.txt", staged, "alias") == 0 else { throw FixtureFailure.failed }
                } else if mutation == "wrong-mode" {
                    guard fchmodat(staged, "value.txt", 0o600, 0) == 0 else { throw FixtureFailure.failed }
                } else {
                    guard unlinkat(staged, "value.txt", 0) == 0 else { throw FixtureFailure.failed }
                    try file(staged, "value.txt", Data("foreign".utf8))
                }
                try refuses { try storage.apply() }
                try expect(try PublicTreeIO.observe(scenario.target, name: scenario.unit.name, inventory: scenario.old,
                    owner: getuid(), group: getgid()) == scenario.operation.before)
            }
            do {
                let scenario = try Scenario(root: root, name: "barrier", unit: .provider)
                let storage = try scenario.storage(); scenario.quiescent = false
                try refuses { try storage.apply() }
                scenario.quiescent = true; try expect(try storage.state() == .staged)
                try refuses {
                    _ = try PublicTreeStorage.capture(unit: .provider, targetParent: scenario.target, retainedParent: scenario.retained,
                        old: scenario.old, new: scenario.new, owner: getuid() + 1, group: getgid(), planSHA256: String(repeating: "a", count: 64))
                }
            }
            try cleanup(root)
            var current = stat()
            guard lstat(path, &current) == 0, current.st_dev == original.st_dev, current.st_ino == original.st_ino,
                  current.st_uid == getuid(), rmdir(path) == 0 else { throw FixtureFailure.failed }
            print("{\"schema\":1,\"status\":\"PASSED\",\"ordinary_temp_only\":true,\"checks\":\(count),\"installed_reads\":false,\"root_execution\":false,\"service_actions\":false,\"production_ready\":false}")
        } catch {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"public_tree_temp_fixture_failed\",\"production_ready\":false}")
            exit(78)
        }
    }
}
