// Ordinary synthetic tree-storage checks. No installed paths, services,
// accounts, package execution, or root operations are available here.
import Foundation
import Darwin

private enum LegacyGroupFixtureFailure: Error { case failed, interrupted }

@main struct FullImageLegacyGroupChecks {
    private static var count = 0
    private static let plan = String(repeating: "a", count: 64)
    private static func expect(_ value: Bool) throws {
        guard value else { throw LegacyGroupFixtureFailure.failed }; count += 1
    }
    private static func refuses(_ body: () throws -> Void) throws {
        var failed = false
        do { try body() } catch { failed = true }
        try expect(failed)
    }
    private static func directory(_ parent: Int32, _ name: String, mode: mode_t, group: gid_t) throws -> Int32 {
        guard mkdirat(parent, name, 0o700) == 0 else { throw LegacyGroupFixtureFailure.failed }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0, fchown(fd, uid_t.max, group) == 0, fchmod(fd, mode) == 0 else {
            throw LegacyGroupFixtureFailure.failed
        }
        return fd
    }
    private static func file(_ parent: Int32, _ name: String, data: Data, group: gid_t) throws {
        let fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw LegacyGroupFixtureFailure.failed }; defer { Darwin.close(fd) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard written > 0 else { throw LegacyGroupFixtureFailure.failed }; offset += written
            }
        }
        guard fchown(fd, uid_t.max, group) == 0, fchmod(fd, 0o644) == 0, fsync(fd) == 0 else {
            throw LegacyGroupFixtureFailure.failed
        }
    }
    private static func row(_ data: Data) -> [String: Any] {
        ["kind": "file", "mode": 0o644, "size": data.count, "sha256": PublicTreeInventory.digest(data)]
    }
    private static func inventory(_ unit: PublicTreeUnit, data: Data, present: Bool) throws -> PublicTreeInventory {
        let dir: [String: Any] = ["kind": "directory", "mode": 0o755]
        let dummy = Data("fictional-not-executed".utf8)
        var nodes: [String: [String: Any]] = ["": dir, "owner.app": dir, "owner.app/Contents": dir,
            "owner.app/Contents/MacOS": dir, "owner.app/Contents/MacOS/AccountAccess": row(dummy)]
        let parts = unit.path.split(separator: "/").map(String.init)
        for index in 1...parts.count where present || index < parts.count {
            nodes[parts.prefix(index).joined(separator: "/")] = dir
        }
        if present {
            nodes[unit.path + "/value.txt"] = row(data)
            nodes[unit.path + "/nested"] = dir
            nodes[unit.path + "/nested/child.txt"] = row(Data("nested".utf8))
            nodes[unit.path + "/alias"] = ["kind": "symlink", "target": "value.txt"]
        }
        let value: [String: Any] = ["schema": 1, "managed_by": "account-access-install-payload-v1",
            "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
            "roots": [InstallerPayloadManifest.support: nodes,
                InstallerPayloadManifest.application: ["": ["kind": "symlink", "target": InstallerPayloadManifest.applicationTarget]]]]
        return try PublicTreeInventory(manifest: JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), unit: unit)
    }
    private static func tree(_ parent: Int32, name: String, unit: PublicTreeUnit, data: Data, group: gid_t) throws {
        let fd = try directory(parent, name, mode: 0o755, group: group); defer { Darwin.close(fd) }
        try file(fd, "value.txt", data: data, group: group)
        let nested = try directory(fd, "nested", mode: 0o755, group: group); defer { Darwin.close(nested) }
        try file(nested, "child.txt", data: Data("nested".utf8), group: group)
        guard symlinkat("value.txt", fd, "alias") == 0 else { throw LegacyGroupFixtureFailure.failed }
        let link = openat(fd, "alias", O_RDONLY | O_SYMLINK | O_NONBLOCK | O_CLOEXEC)
        guard link >= 0 else { throw LegacyGroupFixtureFailure.failed }; defer { Darwin.close(link) }
        guard fchown(link, uid_t.max, group) == 0 else { throw LegacyGroupFixtureFailure.failed }
        if unit == .owner {
            let contents = try directory(fd, "Contents", mode: 0o755, group: group); defer { Darwin.close(contents) }
            let macOS = try directory(contents, "MacOS", mode: 0o755, group: group); defer { Darwin.close(macOS) }
            try file(macOS, "AccountAccess", data: Data("fictional-not-executed".utf8), group: group)
        }
    }
    private final class Scenario {
        let unit: PublicTreeUnit
        let oldGroup: gid_t, newGroup: gid_t
        let parent: Int32, target: Int32, retained: Int32, journal: Int32
        let targetAttachment: PublicTreeAttachment, retainedAttachment: PublicTreeAttachment, journalAttachment: PublicTreeAttachment
        let old: PublicTreeInventory, new: PublicTreeInventory
        let operation: PublicTreeOperation
        init(root: Int32, anchor: PublicTreeTrustedAnchor, name: String, unit: PublicTreeUnit, oldGroup: gid_t) throws {
            self.unit = unit; self.oldGroup = oldGroup; newGroup = getgid()
            parent = try directory(root, name, mode: 0o700, group: getgid())
            target = try directory(parent, "target", mode: 0o755, group: oldGroup)
            retained = try directory(parent, "retained", mode: 0o700, group: getgid())
            journal = try directory(parent, "journal", mode: 0o700, group: getgid())
            let step = PublicTreeAncestorStep(name: try PublicTreeAncestorName(name),
                identity: try PublicTreeDirectoryIdentity.observe(parent, owner: getuid(), group: getgid()))
            func bind(_ fd: Int32, name: String, group: gid_t, role: PublicTreeParentRole) throws -> PublicTreeAttachment {
                try PublicTreeAttachment.bind(anchor: anchor, steps: [step,
                    PublicTreeAncestorStep(name: try PublicTreeAncestorName(name),
                        identity: try PublicTreeDirectoryIdentity.observe(fd, owner: getuid(), group: group))],
                    role: role, parentFD: fd, owner: getuid(), group: group)
            }
            targetAttachment = try bind(target, name: "target", group: oldGroup, role: .target(unit))
            retainedAttachment = try bind(retained, name: "retained", group: getgid(), role: .retained(unit))
            journalAttachment = try bind(journal, name: "journal", group: getgid(), role: .journal(unit))
            let a = Data("old-tree".utf8), b = Data("new-tree-longer".utf8)
            old = try inventory(unit, data: a, present: unit.beforePresent)
            new = try inventory(unit, data: b, present: unit.afterPresent)
            if unit.beforePresent { try tree(target, name: unit.name, unit: unit, data: a, group: oldGroup) }
            if unit.afterPresent { try tree(retained, name: unit.slot, unit: unit, data: b, group: getgid()) }
            operation = try PublicTreeStorage.capture(unit: unit, targetParent: target, retainedParent: retained,
                targetAttachment: targetAttachment, retainedAttachment: retainedAttachment, old: old, new: new,
                owner: getuid(), group: getgid(), beforeGroup: oldGroup, planSHA256: plan)
        }
        deinit { [parent, target, retained, journal].forEach { Darwin.close($0) } }
        func storage(operation replacement: PublicTreeOperation? = nil, beforeGroup: gid_t? = nil,
                     fault: @escaping (PublicTreeStorage.Phase) throws -> Void = { _ in }) throws -> PublicTreeStorage {
            try PublicTreeStorage.open(operation: replacement ?? operation, unit: unit, targetParent: target,
                retainedParent: retained, journalParent: journal, targetAttachment: targetAttachment,
                retainedAttachment: retainedAttachment, journalAttachment: journalAttachment,
                old: old, new: new, owner: getuid(), group: newGroup, beforeGroup: beforeGroup ?? oldGroup,
                requireQuiescent: {}, fault: fault)
        }
        func recapture(beforeGroup: gid_t?) throws -> PublicTreeOperation {
            try PublicTreeStorage.capture(unit: unit, targetParent: target, retainedParent: retained,
                targetAttachment: targetAttachment, retainedAttachment: retainedAttachment, old: old, new: new,
                owner: getuid(), group: newGroup, beforeGroup: beforeGroup, planSHA256: plan)
        }
        func original() throws -> PublicTreePin? {
            try PublicTreeIO.observeOptional(target, name: unit.name, inventory: old,
                owner: getuid(), group: oldGroup, attachment: targetAttachment)
        }
    }
    private static func changeNodeGroup(_ parent: Int32, tree: String, group: gid_t) throws {
        let fd = openat(parent, tree, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw LegacyGroupFixtureFailure.failed }; defer { Darwin.close(fd) }
        let nested = openat(fd, "nested", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard nested >= 0 else { throw LegacyGroupFixtureFailure.failed }; defer { Darwin.close(nested) }
        let leaf = openat(nested, "child.txt", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard leaf >= 0 else { throw LegacyGroupFixtureFailure.failed }; defer { Darwin.close(leaf) }
        guard fchown(leaf, uid_t.max, group) == 0 else { throw LegacyGroupFixtureFailure.failed }
    }
    private static func pin(_ value: PublicTreePin, group: gid_t) -> PublicTreePin {
        PublicTreePin(device: value.device, inode: value.inode, owner: value.owner, group: group,
            mode: value.mode, inventorySHA256: value.inventorySHA256)
    }
    private static func replacing(_ value: PublicTreeOperation, before: PublicTreePin?, after: PublicTreePin?) -> PublicTreeOperation {
        PublicTreeOperation(schema: value.schema, unit: value.unit, planSHA256: value.planSHA256,
            beforeManifestSHA256: value.beforeManifestSHA256, afterManifestSHA256: value.afterManifestSHA256,
            before: before, after: after)
    }
    static func main() {
        guard getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 1 else { exit(77) }
        umask(0o077)
        do {
            let amount = getgroups(0, nil)
            guard amount >= 0, amount <= 256 else { throw LegacyGroupFixtureFailure.failed }
            var groups = [gid_t](repeating: 0, count: Int(amount))
            guard getgroups(amount, &groups) == amount else { throw LegacyGroupFixtureFailure.failed }
            guard let legacy = groups.first(where: { $0 != getgid() }) else {
                print("{\"status\":\"SKIPPED\",\"checks\":0,\"supplemental_group_case\":\"UNAVAILABLE_NO_DISTINCT_GROUP\",\"production_ready\":false}")
                return
            }
            var raw = Array("/private/tmp/account-access-legacy-group-XXXXXX".utf8CString)
            let path = try raw.withUnsafeMutableBufferPointer { value -> String in
                guard let made = mkdtemp(value.baseAddress!) else { throw LegacyGroupFixtureFailure.failed }
                return String(cString: made)
            }
            let root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0, fchown(root, uid_t.max, getgid()) == 0, fchmod(root, 0o700) == 0 else {
                throw LegacyGroupFixtureFailure.failed
            }
            defer { Darwin.close(root) }
            let identity = try PublicTreeDirectoryIdentity.observe(root, owner: getuid(), group: getgid())
            let anchor = try PublicTreeTrustedAnchor.acceptVerifiedDescriptor(root, expected: identity)
            let units: [PublicTreeUnit] = [.owner, .pythonPipInfo, .pythonOldPipInfo]
            for (index, unit) in units.enumerated() {
                let scenario = try Scenario(root: root, anchor: anchor, name: "roundtrip-\(index)", unit: unit, oldGroup: legacy)
                try expect((scenario.operation.before != nil) == unit.beforePresent)
                try expect((scenario.operation.after != nil) == unit.afterPresent)
                try expect(scenario.operation.before?.group == (unit.beforePresent ? legacy : nil))
                try expect(scenario.operation.after?.group == (unit.afterPresent ? getgid() : nil))
                try expect(scenario.targetAttachment.parentGroup == legacy && scenario.retainedAttachment.parentGroup == getgid())
                if unit.beforePresent { try refuses { _ = try scenario.recapture(beforeGroup: nil) } }
                let storage = try scenario.storage(); try expect(try storage.state() == .staged)
                try storage.apply(); try expect(try storage.state() == .applied)
                let reopened = try scenario.storage(); try expect(try reopened.state() == .applied)
                try reopened.reverse(); try expect(try reopened.state() == .staged)
                try expect(try scenario.original() == scenario.operation.before)
                try expect(try InstallerPayloadIO.check(scenario.target, owner: getuid(), directory: true).st_gid == legacy)
            }
            for (index, unit) in units.enumerated() {
                let scenario = try Scenario(root: root, anchor: anchor, name: "recovery-\(index)", unit: unit, oldGroup: legacy)
                let storage = try scenario.storage { phase in
                    if phase == .afterRename { throw LegacyGroupFixtureFailure.interrupted }
                }
                try refuses { try storage.apply() }; try expect(try storage.state() == .applied)
                let reopened = try scenario.storage(); try reopened.apply(); try expect(try reopened.state() == .applied)
                try reopened.reverse(); try expect(try reopened.state() == .staged)
                try expect(try scenario.original() == scenario.operation.before)
            }
            do {
                let scenario = try Scenario(root: root, anchor: anchor, name: "forged-pins", unit: .owner, oldGroup: legacy)
                try refuses { _ = try scenario.storage(beforeGroup: getgid()) }
                let before = pin(scenario.operation.before!, group: getgid())
                try refuses { _ = try scenario.storage(operation: replacing(scenario.operation, before: before, after: scenario.operation.after)) }
                let after = pin(scenario.operation.after!, group: legacy)
                try refuses { _ = try scenario.storage(operation: replacing(scenario.operation, before: scenario.operation.before, after: after)) }
                try expect(try scenario.original() == scenario.operation.before)
            }
            for (index, oldSide) in [true, false].enumerated() {
                let scenario = try Scenario(root: root, anchor: anchor, name: "mixed-node-\(index)", unit: .owner, oldGroup: legacy)
                try changeNodeGroup(oldSide ? scenario.target : scenario.retained,
                    tree: oldSide ? scenario.unit.name : scenario.unit.slot, group: oldSide ? getgid() : legacy)
                try refuses { _ = try scenario.recapture(beforeGroup: legacy) }
            }
            for (index, role) in ["target", "retained", "journal"].enumerated() {
                let scenario = try Scenario(root: root, anchor: anchor, name: "parent-drift-\(index)", unit: .owner, oldGroup: legacy)
                let storage = try scenario.storage()
                let parent = role == "target" ? scenario.target : (role == "retained" ? scenario.retained : scenario.journal)
                guard fchown(parent, uid_t.max, role == "target" ? getgid() : legacy) == 0 else { throw LegacyGroupFixtureFailure.failed }
                try refuses { _ = try storage.state() }
                try refuses { try storage.apply() }
            }
            try expect(PublicTreeDirectoryIdentity(try InstallerPayloadIO.check(root, owner: getuid(), directory: true)) == identity)
            try FileManager.default.removeItem(atPath: path) // This invocation's exclusive synthetic tree only.
            print("{\"schema\":1,\"status\":\"PASSED\",\"checks\":\(count),\"ordinary_temp_only\":true,\"supplemental_group_case\":\"PASSED_DISTINCT_OLD_AND_NEW_GROUPS\",\"optional_polarities\":2,\"recovery_polarities\":3,\"installed_reads\":false,\"root_execution\":false,\"service_actions\":false,\"production_ready\":false}")
        } catch {
            fputs("FULL_IMAGE_LEGACY_GROUP_FIXTURE_FAILED checks=\(count)\n", stderr); exit(1)
        }
    }
}
