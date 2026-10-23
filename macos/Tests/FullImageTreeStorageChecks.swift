// Ordinary owned-temp attachment/storage fixture; not an installed updater.
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
    private static func journalSnapshot(_ parent: Int32) throws -> (Data, stat) {
        let fd = openat(parent, "intent.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw FixtureFailure.failed }; defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: getuid(), directory: false)
        let bytes = try InstallerPayloadIO.read(fd, maximum: 65536, owner: getuid())
        var current = stat()
        guard before.st_mode & 0o7777 == 0o600,
              fstatat(parent, "intent.json", &current, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(before, current) else { throw FixtureFailure.failed }
        return (bytes, before)
    }
    private static func manifest(_ unit: PublicTreeUnit, _ data: Data, present: Bool = true) throws -> PublicTreeInventory {
        let dir: [String: Any] = ["kind": "directory", "mode": 0o755]
        var rows: [String: [String: Any]] = ["": dir, "owner.app": dir, "owner.app/Contents": dir,
            "owner.app/Contents/MacOS": dir, "owner.app/Contents/MacOS/AccountAccess": row(Data("dummy-not-executed".utf8))]
        let parts = unit.path.split(separator: "/").map(String.init)
        for index in 1...parts.count where present || index < parts.count { rows[parts.prefix(index).joined(separator: "/")] = dir }
        if present {
            rows[unit.path + "/value.txt"] = row(data)
            rows[unit.path + "/aux.txt"] = row(Data("aux".utf8))
            rows[unit.path + "/alias"] = ["kind": "symlink", "target": "value.txt"]
        }
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
        let targetAttachment: PublicTreeAttachment, retainedAttachment: PublicTreeAttachment, journalAttachment: PublicTreeAttachment
        let operation: PublicTreeOperation
        var quiescent = true
        init(root: Int32, anchor: PublicTreeTrustedAnchor, name: String, unit: PublicTreeUnit) throws {
            self.unit = unit
            parent = try directory(root, name, 0o700)
            target = try directory(parent, "target-parent", 0o755)
            retained = try directory(parent, "retained-parent", 0o700)
            journal = try directory(parent, "journal", 0o700)
            let prefix = PublicTreeAncestorStep(name: try PublicTreeAncestorName(name),
                identity: try PublicTreeDirectoryIdentity.observe(parent, owner: getuid(), group: getgid()))
            func bind(_ fd: Int32, _ child: String, _ role: PublicTreeParentRole) throws -> PublicTreeAttachment {
                try PublicTreeAttachment.bind(anchor: anchor, steps: [prefix,
                    PublicTreeAncestorStep(name: try PublicTreeAncestorName(child),
                        identity: try PublicTreeDirectoryIdentity.observe(fd, owner: getuid(), group: getgid()))],
                    role: role, parentFD: fd, owner: getuid(), group: getgid())
            }
            targetAttachment = try bind(target, "target-parent", .target(unit))
            retainedAttachment = try bind(retained, "retained-parent", .retained(unit))
            journalAttachment = try bind(journal, "journal", .journal(unit))
            let a = Data("old-tree".utf8), b = Data("new-tree-longer".utf8)
            old = try manifest(unit, a, present: unit.beforePresent); new = try manifest(unit, b, present: unit.afterPresent)
            if unit.beforePresent { try tree(target, unit.name, unit, a) }
            if unit.afterPresent { try tree(retained, unit.slot, unit, b) }
            operation = try PublicTreeStorage.capture(unit: unit, targetParent: target, retainedParent: retained,
                targetAttachment: targetAttachment, retainedAttachment: retainedAttachment,
                old: old, new: new, owner: getuid(), group: getgid(), planSHA256: String(repeating: "a", count: 64))
        }
        deinit { [parent, target, retained, journal].forEach { Darwin.close($0) } }
        func storage(createIfMissing: Bool = true, fault: @escaping (PublicTreeStorage.Phase) throws -> Void = { _ in }) throws -> PublicTreeStorage {
            try PublicTreeStorage.open(operation: operation, unit: unit, targetParent: target, retainedParent: retained,
                journalParent: journal, targetAttachment: targetAttachment, retainedAttachment: retainedAttachment,
                journalAttachment: journalAttachment, old: old, new: new, owner: getuid(), group: getgid(), requireQuiescent: {
                    guard self.quiescent else { throw PublicTreeFailure.barrier }
                }, createIfMissing: createIfMissing, fault: fault)
        }
        func stagedFD() throws -> Int32 {
            let fd = openat(retained, unit.slot, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw FixtureFailure.failed }; return fd
        }
    }
    private static func oldTargetUnchanged(_ scenario: Scenario) throws -> Bool {
        try targetMatches(scenario, inventory: scenario.old, pin: scenario.operation.before)
    }
    private static func targetMatches(_ scenario: Scenario, inventory: PublicTreeInventory, pin: PublicTreePin?) throws -> Bool {
        guard let pin, let tree = inventory.tree else {
            var info = stat(); errno = 0
            return fstatat(scenario.target, scenario.unit.name, &info, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT
        }
        let fd = openat(scenario.target, scenario.unit.name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw FixtureFailure.failed }
        defer { Darwin.close(fd) }
        _ = try InstallerPayloadIO.verify(fd, tree: tree, owner: getuid())
        let info = try InstallerPayloadIO.check(fd, owner: getuid(), directory: true)
        return info.st_dev == pin.device && UInt64(info.st_ino) == pin.inode
            && info.st_gid == getgid()
    }
    private static func addNonemptyLinkACL(_ fd: Int32) throws -> Bool {
        var acl: acl_t? = acl_init(1)
        guard acl != nil else { throw FixtureFailure.failed }
        defer { if let acl { acl_free(UnsafeMutableRawPointer(acl)) } }
        var entry: acl_entry_t?
        guard acl_create_entry(&acl, &entry) == 0, let acl, let entry,
              acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0 else { throw FixtureFailure.failed }
        // A synthetic principal UUID; this fixture does not resolve an owner account.
        var principal = UUID().uuid
        guard withUnsafeBytes(of: &principal, { acl_set_qualifier(entry, $0.baseAddress!) }) == 0 else {
            throw FixtureFailure.failed
        }
        var permissions: acl_permset_t?
        guard acl_get_permset(entry, &permissions) == 0, let permissions,
              acl_clear_perms(permissions) == 0, acl_add_perm(permissions, ACL_READ_DATA) == 0,
              acl_set_permset(entry, permissions) == 0, acl_valid(acl) == 0 else { throw FixtureFailure.failed }
        // Some macOS/filesystem combinations refuse ACL creation on a link.
        // That is an unqualified fixture case, never a relaxed production guard.
        guard acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == 0 else { return false }
        guard let observed = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else { throw FixtureFailure.failed }
        defer { acl_free(UnsafeMutableRawPointer(observed)) }
        var first: acl_entry_t?
        guard acl_get_entry(observed, ACL_FIRST_ENTRY.rawValue, &first) == 0, first != nil else {
            throw FixtureFailure.failed
        }
        return true
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
            let anchor = try PublicTreeTrustedAnchor.acceptVerifiedDescriptor(root,
                expected: PublicTreeDirectoryIdentity.observe(root, owner: getuid(), group: getgid()))
            do {
                let scenario = try Scenario(root: root, anchor: anchor, name: "read-only", unit: .owner)
                try refuses { _ = try scenario.storage(createIfMissing: false) }
                try expect(try InstallerPayloadIO.contents(scenario.journal).isEmpty)
                let storage = try scenario.storage()
                let before = try journalSnapshot(scenario.journal)
                let readOnly = try scenario.storage(createIfMissing: false)
                try expect(try readOnly.state() == storage.state())
                let after = try journalSnapshot(scenario.journal)
                try expect(before.0 == after.0 && InstallerPayloadIO.same(before.1, after.1))
            }
            for (index, unit) in PublicTreeUnit.allCases.enumerated() {
                let scenario = try Scenario(root: root, anchor: anchor, name: "roundtrip-\(index)", unit: unit)
                let storage = try scenario.storage()
                try expect(try storage.state() == .staged)
                try storage.apply(); try expect(try storage.state() == .applied)
                try storage.apply(); try expect(try storage.state() == .applied)
                try storage.reverse(); try expect(try storage.state() == .staged)
                try expect(try PublicTreeIO.observeOptional(scenario.target, name: unit.name, inventory: scenario.old,
                    owner: getuid(), group: getgid(), attachment: scenario.targetAttachment) == scenario.operation.before)
            }
            do {
                let scenario = try Scenario(root: root, anchor: anchor, name: "interrupted", unit: .owner)
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
                let scenario = try Scenario(root: root, anchor: anchor, name: "refusal-\(index)", unit: .project)
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
                    owner: getuid(), group: getgid(), attachment: scenario.targetAttachment) == scenario.operation.before)
            }
            do {
                let scenario = try Scenario(root: root, anchor: anchor, name: "barrier", unit: .provider)
                let storage = try scenario.storage(); scenario.quiescent = false
                try refuses { try storage.apply() }
                scenario.quiescent = true; try expect(try storage.state() == .staged)
                try refuses {
                    _ = try PublicTreeStorage.capture(unit: .provider, targetParent: scenario.target, retainedParent: scenario.retained,
                        targetAttachment: scenario.targetAttachment, retainedAttachment: scenario.retainedAttachment,
                        old: scenario.old, new: scenario.new, owner: getuid() + 1, group: getgid(), planSHA256: String(repeating: "a", count: 64))
                }
            }
            for (index, mutation) in ["target-parent", "retained-parent", "ancestor", "journal-after-intent"].enumerated() {
                let name = "attachment-\(index)"
                let scenario = try Scenario(root: root, anchor: anchor, name: name, unit: .project)
                if mutation == "journal-after-intent" {
                    var detached = false
                    let storage = try scenario.storage { phase in
                        if phase == .afterIntent && !detached {
                            guard renameat(scenario.parent, "journal", scenario.parent, "detached-journal") == 0 else { throw FixtureFailure.failed }
                            let replacement = try directory(scenario.parent, "journal", 0o700)
                            Darwin.close(replacement); detached = true
                        }
                    }
                    try refuses { try storage.apply() }
                } else {
                    let storage = try scenario.storage()
                    if mutation == "ancestor" {
                        guard renameat(root, name, root, name + "-detached") == 0 else { throw FixtureFailure.failed }
                        let replacement = try directory(root, name, 0o700); Darwin.close(replacement)
                    } else {
                        guard renameat(scenario.parent, mutation, scenario.parent, "detached-" + mutation) == 0 else { throw FixtureFailure.failed }
                        let replacement = try directory(scenario.parent, mutation, mutation == "target-parent" ? 0o755 : 0o700)
                        Darwin.close(replacement)
                    }
                    try refuses { try storage.apply() }
                }
                try expect(try oldTargetUnchanged(scenario))
            }
            // These two cases detach the ancestor after the actual forward or
            // reverse swap, rather than only before the first exchange.
            for forward in [true, false] {
                let name = forward ? "detached-after-apply" : "detached-after-rollback"
                let scenario = try Scenario(root: root, anchor: anchor, name: name, unit: .project)
                var armed = forward, detached = false
                let storage = try scenario.storage { phase in
                    if phase == .afterRename && armed && !detached {
                        guard renameat(root, name, root, name + "-original") == 0 else { throw FixtureFailure.failed }
                        let replacement = try directory(root, name, 0o700)
                        Darwin.close(replacement); detached = true
                    }
                }
                if !forward { try storage.apply(); armed = true }
                try refuses { if forward { try storage.apply() } else { try storage.reverse() } }
                let inventory = forward ? scenario.new : scenario.old
                let pin = forward ? scenario.operation.after : scenario.operation.before
                try expect(detached && (try targetMatches(scenario, inventory: inventory, pin: pin)))
                try refuses { _ = try storage.state() }
                try refuses { try storage.apply() }
                try refuses { try storage.reverse() }
                try expect(try targetMatches(scenario, inventory: inventory, pin: pin))
                guard unlinkat(root, name, AT_REMOVEDIR) == 0,
                      renameat(root, name + "-original", root, name) == 0 else { throw FixtureFailure.failed }
                try expect(try storage.state() == (forward ? .applied : .staged))
                if forward { try storage.reverse() } else { try storage.apply(); try storage.reverse() }
                try expect(try storage.state() == .staged)
            }
            var symlinkACLQualified = false
            do {
                let scenario = try Scenario(root: root, anchor: anchor, name: "nonempty-link-acl", unit: .project)
                let storage = try scenario.storage(), staged = try scenario.stagedFD()
                defer { Darwin.close(staged) }
                let link = openat(staged, "alias", O_RDONLY | O_SYMLINK | O_CLOEXEC | O_NONBLOCK)
                guard link >= 0 else { throw FixtureFailure.failed }
                defer { Darwin.close(link) }
                symlinkACLQualified = try addNonemptyLinkACL(link)
                if symlinkACLQualified {
                    try refuses { try storage.apply() }
                    try expect(try oldTargetUnchanged(scenario))
                }
            }
            let originalChecks = 63 + (symlinkACLQualified ? 2 : 0)
            // Nine additional units add 45 round-trip checks; read-only reopen adds four.
            try expect(count == originalChecks + 49)
            let optional = PublicTreeUnit.allCases.filter { $0.beforePresent != $0.afterPresent }
            try expect(optional.count == 4 && PublicTreeUnit.allCases.count == 13)
            for (index, unit) in optional.enumerated() {
                // Both inode polarities survive a crash after the real exclusive move.
                for forward in [true, false] {
                    let scenario = try Scenario(root: root, anchor: anchor, name: "optional-crash-\(index)-\(forward)", unit: unit)
                    var armed = forward
                    let storage = try scenario.storage { phase in
                        if phase == .afterRename && armed { throw FixtureFailure.interruption }
                    }
                    if !forward { try storage.apply(); armed = true }
                    try refuses { if forward { try storage.apply() } else { try storage.reverse() } }
                    try expect(try storage.state() == (forward ? .applied : .staged))
                    let resumed = try scenario.storage()
                    if forward { try resumed.apply(); try resumed.reverse() } else { try resumed.reverse() }
                    try expect(try resumed.state() == .staged)
                    try expect(try oldTargetUnchanged(scenario))
                }
                // A newly occupied destination must never be replaced by EXCL.
                for (kindIndex, kind) in ["file", "link", "directory"].enumerated() {
                    let scenario = try Scenario(root: root, anchor: anchor, name: "optional-poison-\(index)-\(kindIndex)", unit: unit)
                    var injected = false
                    let receiver = unit.beforePresent ? scenario.retained : scenario.target
                    let name = unit.beforePresent ? unit.slot : unit.name
                    let storage = try scenario.storage { phase in
                        if phase == .beforeRename && !injected {
                            if kind == "file" { try file(receiver, name, Data("foreign".utf8)) }
                            else if kind == "link" {
                                guard symlinkat("missing", receiver, name) == 0 else { throw FixtureFailure.failed }
                            } else { Darwin.close(try directory(receiver, name, 0o755)) }
                            injected = true
                        }
                    }
                    try refuses { try storage.apply() }
                    try expect(injected)
                    // The present side still has its exact original tree/inode.
                    let presentFD = unit.beforePresent ? scenario.target : scenario.retained
                    let presentName = unit.beforePresent ? unit.name : unit.slot
                    let inventory = unit.beforePresent ? scenario.old : scenario.new
                    let expectedPin = unit.beforePresent ? scenario.operation.before : scenario.operation.after
                    try expect(try PublicTreeIO.observe(presentFD, name: presentName, inventory: inventory,
                        owner: getuid(), group: getgid(), attachment: unit.beforePresent ? scenario.targetAttachment : scenario.retainedAttachment) == expectedPin)
                }
                let scenario = try Scenario(root: root, anchor: anchor, name: "optional-schema-\(index)", unit: unit)
                let encoded = try JSONEncoder().encode(scenario.operation)
                let value = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
                try expect(value[unit.beforePresent ? "after" : "before"] is NSNull)
                try expect(try JSONDecoder().decode(PublicTreeOperation.self, from: encoded) == scenario.operation)
                for missing in ["before", "after"] {
                    var omitted = value; omitted.removeValue(forKey: missing)
                    try refuses { _ = try JSONDecoder().decode(PublicTreeOperation.self,
                        from: JSONSerialization.data(withJSONObject: omitted)) }
                }
                var foreign = value; foreign["unknown"] = true
                try refuses { _ = try JSONDecoder().decode(PublicTreeOperation.self,
                    from: JSONSerialization.data(withJSONObject: foreign)) }
                let storage = try scenario.storage(); scenario.quiescent = false
                try refuses { try storage.apply() }
                scenario.quiescent = true
                try expect(try storage.state() == .staged)
                // An operation with both pins absent cannot use manifest absence as authority.
                let empty = PublicTreeOperation(schema: 2, unit: unit.rawValue, planSHA256: scenario.operation.planSHA256,
                    beforeManifestSHA256: scenario.old.manifestSHA256, afterManifestSHA256: scenario.new.manifestSHA256,
                    before: nil, after: nil)
                try refuses { _ = try PublicTreeStorage.open(operation: empty, unit: unit, targetParent: scenario.target,
                    retainedParent: scenario.retained, journalParent: scenario.journal, targetAttachment: scenario.targetAttachment,
                    retainedAttachment: scenario.retainedAttachment, journalAttachment: scenario.journalAttachment,
                    old: scenario.old, new: scenario.new, owner: getuid(), group: getgid(), requireQuiescent: {}) }
                try refuses { _ = try PublicTreeStorage.capture(unit: unit, targetParent: scenario.target,
                    retainedParent: scenario.retained, targetAttachment: scenario.targetAttachment,
                    retainedAttachment: scenario.retainedAttachment, old: scenario.new, new: scenario.old,
                    owner: getuid(), group: getgid(), planSHA256: scenario.operation.planSHA256) }
            }
            try refuses { _ = try manifest(.project, Data(), present: false) }
            guard count == originalChecks + 49 + 2 + 4 * 26 + 1 else { throw FixtureFailure.failed }
            try cleanup(root)
            var current = stat()
            guard lstat(path, &current) == 0, current.st_dev == original.st_dev, current.st_ino == original.st_ino,
                  current.st_uid == getuid(), rmdir(path) == 0 else { throw FixtureFailure.failed }
            let status = symlinkACLQualified ? "PASSED" : "PASSED_WITH_UNQUALIFIED_CASE"
            let aclCase = symlinkACLQualified ? "PASSED" : "UNQUALIFIED_OS_DECLINED_CREATION"
            print("{\"schema\":1,\"status\":\"\(status)\",\"ordinary_temp_only\":true,\"checks\":\(count),\"original_checks_preserved\":65,\"fixed_tree_units\":13,\"optional_units\":4,\"post_exchange_ancestor_cases\":2,\"nonempty_symlink_acl_refusal\":\"\(aclCase)\",\"installed_reads\":false,\"root_execution\":false,\"service_actions\":false,\"production_ready\":false}")
        } catch {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"public_tree_temp_fixture_failed\",\"completed_checks\":\(count),\"production_ready\":false}")
            exit(78)
        }
    }
}
