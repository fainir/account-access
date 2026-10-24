// Full fixed-unit mixed transitions with fictional trees/files and a fake
// barrier. Only this invocation's exclusive ordinary temp root is accessed.
import Foundation
import Darwin

private enum MixedCheckFailure: Error { case failed, interrupted }
@main struct FullImageTransitionStorageChecks {
    static var checks = 0
    static func expect(_ value: Bool) throws { guard value else { throw MixedCheckFailure.failed }; checks += 1 }
    static func refuses(_ body: () throws -> Void) throws {
        var refused = false; do { try body() } catch { refused = true }; try expect(refused)
    }
    static func directory(_ parent: Int32, _ name: String, _ mode: mode_t) throws -> Int32 {
        guard mkdirat(parent, name, mode) == 0 else { throw MixedCheckFailure.failed }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0, fchmod(fd, mode) == 0, fchown(fd, uid_t.max, getgid()) == 0 else { throw MixedCheckFailure.failed }
        return fd
    }
    static func file(_ parent: Int32, _ name: String, _ text: String, _ mode: mode_t = 0o644) throws -> ComponentObject {
        try ComponentFiles.writeExclusive(parent, name, data: Data(text.utf8), owner: getuid(), mode: mode)
    }
    static func manifest(_ unit: PublicTreeUnit, _ text: String, present: Bool) throws -> PublicTreeInventory {
        let dir: [String: Any] = ["kind": "directory", "mode": 0o755]
        func node(_ text: String) -> [String: Any] {
            let data = Data(text.utf8)
            return ["kind": "file", "mode": 0o644, "size": data.count, "sha256": FullImageJSON.hash(data)]
        }
        var rows: [String: [String: Any]] = ["": dir, "owner.app": dir, "owner.app/Contents": dir,
            "owner.app/Contents/MacOS": dir, "owner.app/Contents/MacOS/AccountAccess": node("not-executed")]
        let parts = unit.path.split(separator: "/").map(String.init)
        for index in 1...parts.count where present || index < parts.count { rows[parts.prefix(index).joined(separator: "/")] = dir }
        if present { rows[unit.path + "/value"] = node(text) }
        let data = try JSONSerialization.data(withJSONObject: ["schema": 1, "managed_by": "account-access-install-payload-v1",
            "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
            "roots": [InstallerPayloadManifest.support: rows, InstallerPayloadManifest.application: ["": ["kind": "symlink", "target": InstallerPayloadManifest.applicationTarget]]]], options: [.sortedKeys])
        return try PublicTreeInventory(manifest: data, unit: unit)
    }
    static func tree(_ parent: Int32, _ name: String, _ text: String, unit: PublicTreeUnit) throws {
        let fd = try directory(parent, name, 0o755); defer { Darwin.close(fd) }
        _ = try file(fd, "value", text)
        if unit == .owner {
            let contents = try directory(fd, "Contents", 0o755); defer { Darwin.close(contents) }
            let mac = try directory(contents, "MacOS", 0o755); defer { Darwin.close(mac) }
            _ = try file(mac, "AccountAccess", "not-executed")
        }
    }
    final class Barrier: ComponentServiceBarrier {
        var disabled = false, restores = 0, failRestore = false
        func disableAndQuiesce(recovering: Bool) throws { disabled = true }
        func requireDisabledAndQuiescent() throws { guard disabled else { throw MixedCheckFailure.interrupted } }
        func restoreEnabledJob() throws {
            restores += 1
            if failRestore { failRestore = false; throw MixedCheckFailure.interrupted }
            disabled = false
        }
    }
    final class Scenario {
        let root: Int32, target: Int32, retained: Int32
        let barrier = Barrier()
        var events: [(String, Int)] = [], failNew = false
        var descriptors: [Int32] = []
        var trees: [PublicTreeStorage] = [], files: [FullImageFileStorage] = []
        init(parent: Int32, name: String, crashUnit: PublicTreeUnit? = nil) throws {
            root = try directory(parent, name, 0o700)
            target = try directory(root, "files", 0o755); retained = try directory(root, "retained", 0o700)
            let anchor = try PublicTreeTrustedAnchor.acceptVerifiedDescriptor(root,
                expected: PublicTreeDirectoryIdentity.observe(root, owner: getuid(), group: getgid()))
            let localBarrier = barrier
            for (index, unit) in PublicTreeUnit.fullImageCases.enumerated() {
                let tName = "target-\(index)", rName = "retained-\(index)", jName = "journal-\(index)"
                let t = try directory(root, tName, 0o755), r = try directory(root, rName, 0o700), j = try directory(root, jName, 0o700)
                descriptors += [t, r, j]
                func bind(_ fd: Int32, _ name: String, _ role: PublicTreeParentRole) throws -> PublicTreeAttachment {
                    try PublicTreeAttachment.bind(anchor: anchor, steps: [PublicTreeAncestorStep(name: try PublicTreeAncestorName(name),
                        identity: try PublicTreeDirectoryIdentity.observe(fd, owner: getuid(), group: getgid()))], role: role,
                        parentFD: fd, owner: getuid(), group: getgid())
                }
                let ta = try bind(t, tName, .target(unit)), ra = try bind(r, rName, .retained(unit)), ja = try bind(j, jName, .journal(unit))
                let old = try manifest(unit, "old", present: unit.beforePresent), new = try manifest(unit, "new", present: unit.afterPresent)
                if unit.beforePresent { try tree(t, unit.name, "old", unit: unit) }
                if unit.afterPresent { try tree(r, unit.slot, "new", unit: unit) }
                let operation = try PublicTreeStorage.capture(unit: unit, targetParent: t, retainedParent: r,
                    targetAttachment: ta, retainedAttachment: ra, old: old, new: new, owner: getuid(), group: getgid(), planSHA256: String(repeating: "a", count: 64))
                var crash = unit == crashUnit
                trees.append(try PublicTreeStorage.open(operation: operation, unit: unit, targetParent: t, retainedParent: r,
                    journalParent: j, targetAttachment: ta, retainedAttachment: ra, journalAttachment: ja, old: old, new: new,
                    owner: getuid(), group: getgid(), requireQuiescent: { try localBarrier.requireDisabledAndQuiescent() }, fault: { phase in
                        if phase == .afterRename && crash { crash = false; throw MixedCheckFailure.interrupted }
                    }))
            }
            let targetFD = target, retainedFD = retained
            let targetPin = try PublicTreeDirectoryIdentity.observe(target, owner: getuid(), group: getgid())
            let retainedPin = try PublicTreeDirectoryIdentity.observe(retained, owner: getuid(), group: getgid())
            let units = FullImagePlanFileUnit.fullImageCases.map { FullImageFileUnit(publicUnit: $0) } + [.hostPolicy, .ownerPolicy, .installRecord, .head]
            for (offset, unit) in units.enumerated() {
                let index = trees.count + offset
                let beforePresent = unit.publicUnit?.beforePresent ?? (unit != .head)
                let afterPresent = unit.publicUnit?.afterPresent ?? true
                let before = beforePresent ? try file(target, unit.rawValue, "old-" + unit.rawValue, mode_t(unit.mode)) : nil
                let after = afterPresent ? try file(retained, String(format: "slot-%02d", index), "new-" + unit.rawValue, mode_t(unit.mode)) : nil
                let operation = FullImageFileOperation(schema: 1, unit: unit, planSHA256: String(repeating: "a", count: 64), index: index, before: before, after: after)
                files.append(try FullImageFileStorage(operation: operation, retained: retained, owner: getuid(), resolve: { selected in
                    let fd = fcntl(targetFD, F_DUPFD_CLOEXEC, 0); guard fd >= 0 else { throw MixedCheckFailure.failed }
                    return (fd, selected.rawValue)
                }, verifyAttachments: {
                    guard try PublicTreeDirectoryIdentity.observe(targetFD, owner: getuid(), group: getgid()) == targetPin,
                          try PublicTreeDirectoryIdentity.observe(retainedFD, owner: getuid(), group: getgid()) == retainedPin else { throw MixedCheckFailure.failed }
                }, requireQuiescent: { try localBarrier.requireDisabledAndQuiescent() }))
            }
        }
        deinit { (descriptors + [target, retained, root]).forEach { Darwin.close($0) } }
        func storage() throws -> FullImageMixedStorage {
            try FullImageMixedStorage(units: trees.map { .tree($0) } + files.map { .file($0) },
                writeEvent: { self.events.append(($0, $1)) }, verifyOld: {}, verifyRecoverable: {},
                verifyNew: { if self.failNew { self.failNew = false; throw MixedCheckFailure.interrupted } })
        }
        func observe(_ operation: FullImageFileOperation, device: Int32?) throws -> FullImageFileStorage {
            let targetFD = target, retainedFD = retained
            let a = try PublicTreeDirectoryIdentity.observe(targetFD, owner: getuid(), group: getgid())
            let b = try PublicTreeDirectoryIdentity.observe(retainedFD, owner: getuid(), group: getgid())
            return try FullImageFileStorage(operation: operation, retained: retainedFD, owner: getuid(), resolve: {
                let fd = fcntl(targetFD, F_DUPFD_CLOEXEC, 0)
                guard fd >= 0 else { throw MixedCheckFailure.failed }; return (fd, $0.rawValue)
            }, verifyAttachments: {
                guard try PublicTreeDirectoryIdentity.observe(targetFD, owner: getuid(), group: getgid()) == a,
                      try PublicTreeDirectoryIdentity.observe(retainedFD, owner: getuid(), group: getgid()) == b else { throw MixedCheckFailure.failed }
            }, requireQuiescent: { throw MixedCheckFailure.failed }, observationDevice: device)
        }
    }
    static func main() {
        guard getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 1 else { exit(77) }
        umask(0o077)
        do {
            var buffer = Array("/private/tmp/account-access-mixed-v2-XXXXXX".utf8CString)
            let path = try buffer.withUnsafeMutableBufferPointer { value -> String in
                guard let pointer = mkdtemp(value.baseAddress!) else { throw MixedCheckFailure.failed }; return String(cString: pointer)
            }
            let root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0, fchown(root, uid_t.max, getgid()) == 0 else { throw MixedCheckFailure.failed }
            defer { Darwin.close(root) }
            let pin = try PublicTreeDirectoryIdentity.observe(root, owner: getuid(), group: getgid())
            for mode in ["commit", "rollback", "restore-failure", "recover-create", "recover-remove"] {
                let crashUnit: PublicTreeUnit? = mode == "recover-create" ? .pythonPipInfo : (mode == "recover-remove" ? .runtimeOldPipInfo : nil)
                let scenario = try Scenario(parent: root, name: mode, crashUnit: crashUnit), storage = try scenario.storage()
                try expect(storage.operations.count == 29 && scenario.trees.count == 13 && scenario.files.count == 16)
                if let crashUnit {
                    let index = PublicTreeUnit.fullImageCases.firstIndex(of: crashUnit)!
                    scenario.barrier.disabled = true
                    try refuses { try scenario.trees[index].apply() }
                    try expect(try storage.state(storage.operations[index]) == .applied)
                    _ = try ComponentTransition(storage: storage, service: scenario.barrier).run(recovering: true)
                    try expect(try storage.operations.allSatisfy { try storage.state($0) == .applied })
                } else if mode != "commit" {
                    if mode == "rollback" { scenario.failNew = true } else { scenario.barrier.failRestore = true }
                    try refuses { _ = try ComponentTransition(storage: storage, service: scenario.barrier).run(recovering: false) }
                    try expect(try storage.operations.allSatisfy { try storage.state($0) == .staged })
                    try expect(scenario.events.last?.0 == "old_image_restored" && !scenario.barrier.disabled)
                    try expect(try ComponentFiles.observe(scenario.target, FullImageFileUnit.head.rawValue, owner: getuid()) == nil)
                } else {
                    _ = try ComponentTransition(storage: storage, service: scenario.barrier).run(recovering: false)
                    try expect(try storage.operations.allSatisfy { try storage.state($0) == .applied })
                    try expect(scenario.events.last?.0 == "new_image_verified_gui_unverified" && !scenario.barrier.disabled)
                    let headApplied = scenario.events.firstIndex { $0.0 == "applied" && $0.1 == 28 }!
                    try expect(scenario.events[..<headApplied].filter { $0.0 == "applied" }.count == 28)
                    let original = storage.operations[0]
                    let foreign = ComponentOperation(target: original.target, path: original.path, slot: original.slot, before: nil,
                        after: ComponentObject(device: 0, inode: 0, mode: 0, bytes: original.after.bytes, sha256: String(repeating: "0", count: 64)))
                    try refuses { _ = try storage.state(foreign) }
                    try expect(try ComponentFiles.observe(scenario.target, FullImageFileUnit.pythonPip312.rawValue, owner: getuid()) == nil)
                }
            }
            for applied in [false, true] {
                let scenario = try Scenario(parent: root, name: "historical-files-\(applied)")
                let storage = try scenario.storage()
                if applied { _ = try ComponentTransition(storage: storage, service: scenario.barrier).run(recovering: false) }
                for file in scenario.files {
                    let old = file.operation
                    let current = old.before?.device ?? old.after!.device
                    let historical: Int32 = current == 123 ? 124 : 123
                    func moved(_ object: ComponentObject?) -> ComponentObject? {
                        object.map { ComponentObject(device: historical, inode: $0.inode, mode: $0.mode, bytes: $0.bytes, sha256: $0.sha256) }
                    }
                    let observed = FullImageFileOperation(schema: old.schema, unit: old.unit, planSHA256: old.planSHA256,
                        index: old.index, before: moved(old.before), after: moved(old.after))
                    try refuses { _ = try scenario.observe(observed, device: nil) }
                    let readOnly = try scenario.observe(observed, device: historical)
                    try expect(try readOnly.state() == (applied ? .applied : .staged))
                    try refuses { try readOnly.apply() }
                    try refuses { try readOnly.reverse() }
                    try refuses { _ = try scenario.observe(observed, device: historical + 1) }
                    for field in ["inode", "bytes", "sha256"] {
                        func changed(_ object: ComponentObject?) -> ComponentObject? {
                            object.map { ComponentObject(device: $0.device,
                                inode: field == "inode" ? $0.inode + 100000 : $0.inode, mode: $0.mode,
                                bytes: field == "bytes" ? $0.bytes + 1 : $0.bytes,
                                sha256: field == "sha256" ? String(repeating: "f", count: 64) : $0.sha256) }
                        }
                        let altered = FullImageFileOperation(schema: observed.schema, unit: observed.unit,
                            planSHA256: observed.planSHA256, index: observed.index,
                            before: changed(observed.before), after: changed(observed.after))
                        try expect(try scenario.observe(altered, device: historical).state() == .conflict)
                    }
                    try expect(try file.state() == (applied ? .applied : .staged))
                }
            }
            var current = stat()
            guard lstat(path, &current) == 0, PublicTreeDirectoryIdentity(current) == pin else { throw MixedCheckFailure.failed }
            try FileManager.default.removeItem(atPath: path)
            print("{\"schema\":1,\"status\":\"PASSED\",\"checks\":\(checks),\"tree_units\":13,\"public_file_units\":12,\"dynamic_file_units\":4,\"owned_temp_fake_barrier_only\":true,\"production_ready\":false}")
        } catch {
            fputs("MIXED_FIXED_UNIT_FIXTURE_FAILED\n", stderr); exit(78)
        }
    }
}
