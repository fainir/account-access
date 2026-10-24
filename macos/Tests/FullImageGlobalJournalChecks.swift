// Durable journal fixture: only synthetic authorities and exclusive own temp FDs.
// This constructs a small internal FullImageSource value to isolate journal
// recovery. It is not loader/payload/signature qualification; the strict CA-v2
// loader has separate Python/native agreement checks against independent pins.
import Foundation
import Darwin

private enum JournalCheckFailure: Error { case failed, interrupted }
@main struct FullImageGlobalJournalChecks {
    static var assertions = 0
    static func expect(_ value: Bool) throws { guard value else { throw JournalCheckFailure.failed }; assertions += 1 }
    static func refuses(_ body: () throws -> Void) throws { var failed = false; do { try body() } catch { failed = true }; try expect(failed) }
    static func source() throws -> FullImageSource {
        let directory: [String: Any] = ["kind": "directory", "mode": 0o755]
        var old: [String: Any] = ["": directory], new: [String: Any] = ["": directory]
        func put(_ rows: inout [String: Any], _ path: String, _ value: [String: Any]) {
            let parts = path.split(separator: "/").map(String.init)
            for count in 1..<parts.count { rows[parts.prefix(count).joined(separator: "/")] = directory }
            rows[path] = value
        }
        func node(_ text: String, mode: UInt16 = 0o644) -> [String: Any] {
            let data = Data(text.utf8)
            return ["kind": "file", "mode": mode, "size": data.count, "sha256": FullImageJSON.hash(data)]
        }
        for unit in PublicTreeUnit.allCases {
            if unit.beforePresent { put(&old, unit.path + "/entry.txt", node("old-" + unit.rawValue)) }
            if unit.afterPresent { put(&new, unit.path + "/entry.txt", node("new-" + unit.rawValue)) }
        }
        for unit in FullImagePlanFileUnit.allCases {
            if unit.beforePresent { put(&old, unit.path, node("old-" + unit.rawValue, mode: unit.mode)) }
            if unit.afterPresent { put(&new, unit.path, node("new-" + unit.rawValue, mode: unit.mode)) }
        }
        // Required manifest member, represented only as nonexecuted fictional
        // bytes. Keeping it identical isolates this journal fixture's changes.
        put(&old, "owner.app/Contents/MacOS/AccountAccess", node("fictional-owner-not-executed", mode: 0o755))
        put(&new, "owner.app/Contents/MacOS/AccountAccess", node("fictional-owner-not-executed", mode: 0o755))
        func manifest(_ rows: [String: Any]) throws -> InstallerPayloadManifest {
            let value: [String: Any] = ["schema": 1, "managed_by": "account-access-install-payload-v1",
                "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
                "roots": [InstallerPayloadManifest.support: rows,
                    InstallerPayloadManifest.application: ["": ["kind": "symlink",
                        "target": "../Library/Application Support/Account Access/owner.app"]]]]
            return try InstallerPayloadManifest(FullImageJSON.encode(value))
        }
        let before = try manifest(old), after = try manifest(new)
        let pins = FullImageSourcePins(planSHA256: String(repeating: "9", count: 64), targetSourceCommit: String(repeating: "4", count: 40),
            targetManifestSHA256: after.sha256, caReceiptSHA256: FullImageJSON.hash(Data("new-caReceipt".utf8)),
            predecessor: FullImagePredecessorPins(planSHA256: String(repeating: "2", count: 64), originalManifestSHA256: ComponentSource.baseDigest,
                manifestSHA256: before.sha256, headSHA256: String(repeating: "8", count: 64)),
            predecessorSourceCommit: String(repeating: "3", count: 40), targetSourceFiles: [:],
            providerManifestSHA256: String(repeating: "7", count: 64), providerSourceBundleSHA256: String(repeating: "1", count: 64))
        var units: [FullImageSource.Unit] = []
        for unit in PublicTreeUnit.allCases {
            units.append(.tree(unit, try PublicTreeInventory(validatedManifest: before, unit: unit),
                               try PublicTreeInventory(validatedManifest: after, unit: unit)))
        }
        for unit in FullImagePlanFileUnit.allCases.sorted(by: { $0.path < $1.path }) {
            units.append(.file(unit, before.trees[InstallerPayloadManifest.support]!.nodes[unit.path],
                               after.trees[InstallerPayloadManifest.support]!.nodes[unit.path]))
        }
        let changed = try Set(old.keys).union(new.keys).filter { name in
            try !FullImageJSON.same(old[name] ?? NSNull(), new[name] ?? NSNull())
        }.sorted()
        return FullImageSource(pins: pins, before: before, after: after, oldPeers: [:], newPeers: [:],
                               designatedRequirements: [:], units: units, changed: changed)
    }
    static func directory(_ parent: Int32, _ name: String) throws -> Int32 {
        guard mkdirat(parent, name, 0o700) == 0 else { throw JournalCheckFailure.failed }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0, fchmod(fd, 0o700) == 0, fchown(fd, uid_t.max, getgid()) == 0 else { throw JournalCheckFailure.failed }; return fd
    }
    final class Fixture {
        let root: Int32, fd: Int32, name: String, identity: PublicTreeDirectoryIdentity
        let source: FullImageSource, intent: FullImageGlobalIntent
        let dynamic: [FullImageFileUnit: Data]
        let beforeGroup: gid_t
        var states: [ComponentOperationState]
        init(root: Int32, name: String, beforeGroup: gid_t? = nil) throws {
            self.root = root; self.name = name; fd = try directory(root, name)
            let legacyGroup = beforeGroup ?? getgid(); self.beforeGroup = legacyGroup
            let localIdentity = try PublicTreeDirectoryIdentity.observe(fd, owner: getuid(), group: getgid()); identity = localIdentity
            let localSource = try FullImageGlobalJournalChecks.source(); source = localSource
            let dynamic: [FullImageFileUnit: Data] = [.hostPolicy: Data("new-host-policy".utf8), .ownerPolicy: Data("new-owner-policy".utf8),
                .installRecord: Data("new-install-record".utf8), .head: try FullImageGlobalIntent.newHead(source: localSource, predecessorEvidenceSHA256: String(repeating: "5", count: 64))]
            self.dynamic = dynamic
            var serial: UInt64 = 100
            func file(_ node: InstallerPayloadNode?) -> ComponentObject? {
                guard let node else { return nil }; serial += 1
                return ComponentObject(device: localIdentity.device, inode: serial, mode: UInt16(node.mode!), bytes: node.size!, sha256: node.sha256!)
            }
            func pin(_ inventory: PublicTreeInventory, group: gid_t) -> PublicTreePin? {
                guard let sha = inventory.inventorySHA256 else { return nil }
                serial += 1
                return PublicTreePin(device: localIdentity.device, inode: serial, owner: getuid(), group: group, mode: 0o755,
                    inventorySHA256: sha)
            }
            var operations: [FullImageDurableOperation] = []
            for (index, unit) in localSource.units.enumerated() {
                switch unit {
                case .file(let unit, let before, let after):
                    operations.append(FullImageDurableOperation(file: FullImageFileOperation(schema: 1, unit: FullImageFileUnit(publicUnit: unit), planSHA256: localSource.pins.planSHA256,
                        index: index, before: file(before), after: file(after))))
                case .tree(let unit, let before, let after):
                    operations.append(FullImageDurableOperation(tree: PublicTreeOperation(schema: 2, unit: unit.rawValue,
                        planSHA256: localSource.pins.planSHA256, beforeManifestSHA256: localSource.before.sha256, afterManifestSHA256: localSource.after.sha256,
                        before: pin(before, group: legacyGroup), after: pin(after, group: getgid()))))
                }
            }
            for unit in [FullImageFileUnit.hostPolicy, .ownerPolicy, .installRecord, .head] {
                let data = dynamic[unit]!
                func node(_ hash: String) -> InstallerPayloadNode {
                    InstallerPayloadNode(kind: "file", mode: mode_t(unit.mode), size: Int64(data.count), sha256: hash, target: nil)
                }
                operations.append(FullImageDurableOperation(file: FullImageFileOperation(schema: 1, unit: unit,
                    planSHA256: localSource.pins.planSHA256, index: operations.count,
                    before: unit == .head ? nil : file(node(String(repeating: "a", count: 64))), after: file(node(FullImageJSON.hash(data))))))
            }
            let worker = ComponentObject(device: localIdentity.device, inode: 9001, mode: 0o644, bytes: 10, sha256: String(repeating: "e", count: 64))
            let plist = ComponentObject(device: localIdentity.device, inode: 9002, mode: 0o644, bytes: 10, sha256: String(repeating: "f", count: 64))
            intent = FullImageGlobalIntent(schema: 2, managedBy: "account-access-full-image-transition-v2",
                planSHA256: localSource.pins.planSHA256, beforeManifestSHA256: localSource.before.sha256, afterManifestSHA256: localSource.after.sha256,
                targetSourceCommit: localSource.pins.targetSourceCommit, predecessorEvidenceSHA256: String(repeating: "5", count: 64),
                ownerUID: 501, brokerUID: 473, initialService: nil, workerPolicy: worker, servicePlist: plist,
                operations: operations, automaticRebootRecovery: false)
            states = Array(repeating: .staged, count: operations.count)
        }
        deinit { Darwin.close(fd) }
        func validate(_ value: FullImageGlobalIntent) throws {
            try value.validate(source: source, predecessorEvidenceSHA256: String(repeating: "5", count: 64),
                workerPolicy: intent.workerPolicy, servicePlist: intent.servicePlist, ownerUID: 501, brokerUID: 473,
                publicOwner: getuid(), publicGroup: getgid(), beforeGroup: beforeGroup, device: identity.device, dynamic: dynamic)
        }
        func attached(_ candidate: Int32) throws {
            var path = stat()
            guard fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) == 0, PublicTreeDirectoryIdentity(path) == identity,
                  try PublicTreeDirectoryIdentity.observe(candidate, owner: getuid(), group: getgid()) == identity else { throw JournalCheckFailure.failed }
        }
        func open(createIfMissing: Bool = true, fault: @escaping (FullImageGlobalJournal.Phase) throws -> Void = { _ in }) throws -> FullImageGlobalJournal {
            try FullImageGlobalJournal.open(directory: fd, owner: getuid(), group: getgid(), beforeGroup: beforeGroup, expected: intent,
                validateIntent: validate, verifyAttachment: attached, createIfMissing: createIfMissing, fault: fault)
        }
        func state(_ token: ComponentOperation) throws -> ComponentOperationState {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            let raw = try encoder.encode(token)
            guard let index = try intent.operations.indices.first(where: { try encoder.encode(intent.operations[$0].token()) == raw }) else { throw JournalCheckFailure.failed }
            return states[index]
        }
    }
    static func rewrite(_ parent: Int32, _ name: String, _ raw: Data) throws {
        let fd = openat(parent, name, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw JournalCheckFailure.failed }; defer { Darwin.close(fd) }
        try raw.withUnsafeBytes { bytes in
            guard Darwin.write(fd, bytes.baseAddress!, bytes.count) == bytes.count, fsync(fd) == 0 else { throw JournalCheckFailure.failed }
        }
    }
    static func encoded(_ intent: FullImageGlobalIntent) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: JSONEncoder().encode(intent)) as! [String: Any]
    }
    static func mutateTree(_ intent: FullImageGlobalIntent, unit: PublicTreeUnit,
                           edit: (inout [String: Any]) throws -> Void) throws -> FullImageGlobalIntent {
        var value = try encoded(intent), operations = value["operations"] as! [[String: Any]]
        guard let index = operations.firstIndex(where: { ($0["tree"] as? [String: Any])?["unit"] as? String == unit.rawValue }) else {
            throw JournalCheckFailure.failed
        }
        var operation = operations[index], tree = operation["tree"] as! [String: Any]
        try edit(&tree); operation["tree"] = tree; operations[index] = operation; value["operations"] = operations
        return try JSONDecoder().decode(FullImageGlobalIntent.self, from: JSONSerialization.data(withJSONObject: value))
    }
    static func main() {
        guard getuid() != 0, getuid() == geteuid(), CommandLine.arguments.count == 1 else { exit(77) }
        umask(0o077)
        do {
            var bytes = Array("/private/tmp/account-access-global-journal-XXXXXX".utf8CString)
            let path = try bytes.withUnsafeMutableBufferPointer { buffer -> String in
                guard let pointer = mkdtemp(buffer.baseAddress!) else { throw JournalCheckFailure.failed }; return String(cString: pointer)
            }
            let root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0, fchown(root, uid_t.max, getgid()) == 0 else { throw JournalCheckFailure.failed }
            defer { Darwin.close(root) }
            let rootPin = try PublicTreeDirectoryIdentity.observe(root, owner: getuid(), group: getgid())
            do {
                let f = try Fixture(root: root, name: "historical-device-readonly")
                _ = try f.open()
                let historicalDevice: Int32 = f.identity.device == 123 ? 124 : 123
                func translated(_ value: Any) -> Any {
                    if let fields = value as? [String: Any] {
                        return fields.mapValues { translated($0) }.merging(fields.keys.contains("device")
                            ? ["device": NSNumber(value: historicalDevice)] : [:]) { _, replacement in replacement }
                    }
                    if let array = value as? [Any] { return array.map { translated($0) } }
                    return value
                }
                let raw = try JSONSerialization.data(withJSONObject: translated(try encoded(f.intent)), options: [.sortedKeys, .withoutEscapingSlashes])
                let historical = try JSONDecoder().decode(FullImageGlobalIntent.self, from: raw)
                try historical.validateStructure(device: historicalDevice, publicOwner: getuid(), publicGroup: getgid())
                try rewrite(f.fd, "intent.json", raw)
                let before = try ComponentFiles.read(f.fd, "intent.json", owner: getuid(), mode: 0o600)
                var reachedAuthority = false
                try refuses {
                    _ = try FullImageGlobalJournal.readIntent(directory: f.fd, owner: getuid(), group: getgid(),
                        validateIntent: { _ in reachedAuthority = true }, verifyAttachment: f.attached)
                }
                try expect(!reachedAuthority)
                let after = try ComponentFiles.read(f.fd, "intent.json", owner: getuid(), mode: 0o600)
                try expect(before.0 == after.0 && before.1 == after.1)
            }
            do {
                let f = try Fixture(root: root, name: "optional-contract")
                try f.validate(f.intent)
                try expect(f.source.units.count == 25 && f.intent.operations.count == 29)
                let trees = f.intent.operations.compactMap(\.tree)
                try expect(trees.count == 13 && trees.filter({ $0.before == nil }).count == 2
                           && trees.filter({ $0.after == nil }).count == 2)
                for tree in trees {
                    let unit = PublicTreeUnit(rawValue: tree.unit)!
                    let raw = try JSONSerialization.jsonObject(with: JSONEncoder().encode(tree)) as! [String: Any]
                    try expect(raw.keys.contains("before") && raw.keys.contains("after"))
                    try expect((raw["before"] is NSNull) == !unit.beforePresent
                               && (raw["after"] is NSNull) == !unit.afterPresent)
                    for pin in [tree.before, tree.after].compactMap({ $0 }) { try expect(pin.inode > 0 && pin.device == f.identity.device) }
                }
                for (unit, side) in [(PublicTreeUnit.pythonPipInfo, "before"), (.runtimeOldPipInfo, "after")] {
                    try refuses { _ = try mutateTree(f.intent, unit: unit) { $0.removeValue(forKey: side) } }
                    try refuses { _ = try mutateTree(f.intent, unit: unit) { $0[side] = [:] as [String: Any] } }
                    try refuses {
                        let altered = try mutateTree(f.intent, unit: unit) {
                            $0[side] = ["device": 0, "inode": 0, "owner": getuid(), "group": getgid(),
                                        "mode": 0, "inventorySHA256": String(repeating: "0", count: 64)] as [String: Any]
                        }
                        try f.validate(altered)
                    }
                }
                for mutation in ["both-absent", "reverse-polarity", "schema-one", "wrong-manifest", "wrong-plan", "wrong-owner", "duplicate-inode"] {
                    let altered = try mutateTree(f.intent, unit: .pythonPipInfo) { value in
                        if mutation == "both-absent" { value["after"] = NSNull() }
                        else if mutation == "reverse-polarity" { let after = value["after"]; value["after"] = NSNull(); value["before"] = after }
                        else if mutation == "schema-one" { value["schema"] = 1 }
                        else if mutation == "wrong-manifest" { value["afterManifestSHA256"] = String(repeating: "1", count: 64) }
                        else if mutation == "wrong-plan" { value["planSHA256"] = String(repeating: "1", count: 64) }
                        else {
                            var pin = value["after"] as! [String: Any]
                            if mutation == "wrong-owner" { pin["owner"] = getuid() + 1 }
                            else { pin["inode"] = trees.first!.before!.inode }
                            value["after"] = pin
                        }
                    }
                    try refuses { try f.validate(altered) }
                }
                let missingReplacement = try mutateTree(f.intent, unit: .owner) { $0["before"] = NSNull() }
                try refuses { try f.validate(missingReplacement) }
                // Public source plan sides are explicit. Existing file schema1
                // Codable records retain canonical omitted nil, whereas tree
                // schema2 records encode nil explicitly. Neither can reverse
                // the fixed source unit's allowed presence/absence polarity.
                var deleted = try encoded(f.intent), deletedOperations = deleted["operations"] as! [[String: Any]]
                let deletedIndex = deletedOperations.firstIndex { ($0["file"] as? [String: Any])?["unit"] as? String == FullImageFileUnit.componentIdentity.rawValue }!
                var deletedOperation = deletedOperations[deletedIndex], deletedFile = deletedOperation["file"] as! [String: Any]
                try expect(deletedFile["after"] == nil && deletedFile["before"] != nil)
                deletedFile["after"] = deletedFile["before"]; deletedFile["before"] = NSNull()
                deletedOperation["file"] = deletedFile; deletedOperations[deletedIndex] = deletedOperation; deleted["operations"] = deletedOperations
                let reversedFile = try JSONDecoder().decode(FullImageGlobalIntent.self, from: JSONSerialization.data(withJSONObject: deleted))
                try refuses { try f.validate(reversedFile) }
                let owner = trees.first(where: { $0.unit == PublicTreeUnit.owner.rawValue })!
                let originalToken = try FullImageTreeToken.operation(owner)
                let tokenEncoder = JSONEncoder(); tokenEncoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                let typedRecord = try tokenEncoder.encode(owner)
                try expect(originalToken.after.sha256 == FullImageJSON.hash(typedRecord)
                           && originalToken.after.bytes == typedRecord.count)
                for key in ["planSHA256", "beforeManifestSHA256", "afterManifestSHA256", "unit", "before", "after"] {
                    let altered = try mutateTree(f.intent, unit: .owner) { value in
                        if ["before", "after"].contains(key) {
                            var pin = value[key] as! [String: Any]; pin["inode"] = (pin["inode"] as! NSNumber).uint64Value + 10_000
                            value[key] = pin
                        } else if key == "unit" { value[key] = PublicTreeUnit.provider.rawValue }
                        else { value[key] = String(repeating: "1", count: 64) }
                    }
                    let changed = altered.operations.compactMap(\.tree).first { $0.unit == (key == "unit" ? PublicTreeUnit.provider.rawValue : PublicTreeUnit.owner.rawValue) }!
                    let token = try FullImageTreeToken.operation(changed)
                    try expect(token.after.sha256 != originalToken.after.sha256)
                }
                let optional = trees.first { $0.unit == PublicTreeUnit.pythonPipInfo.rawValue }!
                let token = try FullImageTreeToken.operation(optional)
                try expect(token.before == nil && token.after.inode == 0 && token.after.bytes > 0)
                // Token zero fields are routing bytes. Typed absent sides stay
                // explicit nil and are never passed to an inode observer.
                try expect(optional.before == nil && optional.after!.inode > 0)
                var reordered = try encoded(f.intent), operations = reordered["operations"] as! [[String: Any]]
                operations.insert(operations.removeLast(), at: 0); reordered["operations"] = operations
                let earlyHead = try JSONDecoder().decode(FullImageGlobalIntent.self, from: JSONSerialization.data(withJSONObject: reordered))
                try refuses { try f.validate(earlyHead) }
            }
            do {
                let f = try Fixture(root: root, name: "optional-recovery"), journal = try f.open()
                try journal.writeService("disable_intent_prior_enabled"); try journal.writeService("disabled_confirmed")
                try journal.writeService("user_domain_bootout_intent"); try journal.writeService("user_domain_quiescence_confirmed")
                try journal.writeService("disabled_quiescence_confirmed")
                let indices = f.intent.operations.indices.filter {
                    guard let tree = f.intent.operations[$0].tree else { return false }
                    return tree.before == nil || tree.after == nil
                }
                try expect(indices.count == 4)
                for index in indices {
                    try journal.writeTransition("apply_intent", operation: index, state: f.state)
                    f.states[index] = .applied; try journal.writeTransition("applied", operation: index, state: f.state)
                }
                let loaded = try FullImageGlobalJournal.readIntent(directory: f.fd, owner: getuid(), group: getgid(),
                    validateIntent: f.validate, verifyAttachment: f.attached)
                try expect(loaded == f.intent && loaded.operations.compactMap(\.tree).filter { $0.before == nil || $0.after == nil }.count == 4)
                let resumed = try f.open()
                try expect(try resumed.recovery().ownsDisable && !resumed.recovery().finished)
                for index in indices.reversed() {
                    try resumed.writeTransition("rollback_intent", operation: index, state: f.state)
                    f.states[index] = .staged; try resumed.writeTransition("rolled_back", operation: index, state: f.state)
                }
                try resumed.writeTransition("old_image_restored", operation: -1, state: f.state)
                try expect(try f.open().recovery().ownsDisable)
            }
            do {
                let f = try Fixture(root: root, name: "complete"); try f.validate(f.intent)
                try refuses { _ = try f.open(createIfMissing: false) }
                try expect(try InstallerPayloadIO.contents(f.fd).isEmpty)
                let journal = try f.open(); try expect(try journal.recovery().recordCount == 0)
                try refuses { _ = try journal.completedEvidence() }
                let loaded = try FullImageGlobalJournal.readIntent(directory: f.fd, owner: getuid(), group: getgid(),
                    validateIntent: f.validate, verifyAttachment: f.attached)
                try expect(loaded == f.intent && loaded.operations.last?.file?.before == nil)
                try expect(FullImageFixedNamespace.head != FullImageFixedNamespace.predecessorHead)
                try expect(try FullImageFixedNamespace.transition(f.source.pins.planSHA256).hasPrefix(FullImageFixedNamespace.namespace + "/transition-"))
                try journal.writeService("disable_intent_prior_enabled")
                try journal.writeService("disabled_confirmed")
                try expect(try journal.recovery().ownsDisable)
                let job = ComponentJobIdentity(pid: 12345, group: 12345, birthSec: 1, birthUsec: 2, bootSession: "12345678-1234-1234-1234-123456789abc")
                try journal.writeSnapshot(job)
                try journal.writeService("user_domain_bootout_intent")
                try journal.writeService("user_domain_quiescence_confirmed")
                try journal.writeService("disabled_quiescence_confirmed")
                for index in f.intent.operations.indices {
                    try journal.writeTransition("apply_intent", operation: index, state: f.state)
                    f.states[index] = .applied
                    try journal.writeTransition("applied", operation: index, state: f.state)
                }
                try journal.writeTransition("new_image_verified_gui_unverified", operation: -1, state: f.state)
                try journal.writeService("user_domain_bootstrap_intent")
                try journal.writeService("user_domain_bootstrap_confirmed")
                try journal.writeService("coherent_image_enable_intent")
                try journal.writeService("canonical_job_bootstrapped_gui_unverified")
                let recovered = try f.open().recovery()
                try expect(recovered.finished && !recovered.ownsDisable && recovered.snapshots == [job])
                let beforeReadOnly = try InstallerPayloadIO.contents(f.fd)
                let readOnly = try f.open(createIfMissing: false)
                try expect(try readOnly.completedEvidence() == journal.completedEvidence())
                try expect(try InstallerPayloadIO.contents(f.fd) == beforeReadOnly)
                try refuses { try journal.writeTransition("apply_intent", operation: -1, state: f.state) }
                try refuses { try journal.writeTransition("old_image_restored", operation: -1, state: f.state) }
            }
            do {
                let f = try Fixture(root: root, name: "old-image-restored"), journal = try f.open()
                try refuses { try journal.writeService("disabled_confirmed") }
                try journal.writeService("disable_intent_prior_enabled")
                try journal.writeService("disabled_confirmed")
                try journal.writeService("user_domain_bootout_intent")
                try journal.writeService("user_domain_quiescence_confirmed")
                try journal.writeService("disabled_quiescence_confirmed")
                try journal.writeTransition("old_image_restored", operation: -1, state: f.state)
                try journal.writeService("user_domain_bootstrap_intent")
                try journal.writeService("user_domain_bootstrap_confirmed")
                try journal.writeService("coherent_image_enable_intent")
                try journal.writeService("canonical_job_bootstrapped_gui_unverified")
                let state = try f.open().recovery()
                try expect(!state.ownsDisable && !state.finished)
                // A new retry must persist a new prior-enabled intent. The
                // previous restoration is never ownership of a later pause.
                try refuses { try journal.writeService("disabled_confirmed") }
                try journal.writeService("disable_intent_prior_enabled")
                try expect(try f.open().recovery().ownsDisable)
            }
            for (index, phase) in [FullImageGlobalJournal.Phase.pendingCreated, .pendingSynced].enumerated() {
                let f = try Fixture(root: root, name: "intent-interrupt-\(index)")
                try refuses { _ = try f.open { if $0 == phase { throw JournalCheckFailure.interrupted } } }
                try expect(try InstallerPayloadIO.contents(f.fd) == ["pending-intent-00"])
                let recovered = try f.open(); try expect(try recovered.recovery().recordCount == 0)
                try expect(try InstallerPayloadIO.contents(f.fd) == ["pending-intent-00", "intent.json"])
            }
            for (index, phase) in [FullImageGlobalJournal.Phase.pendingCreated, .pendingSynced, .published].enumerated() {
                let f = try Fixture(root: root, name: "record-interrupt-\(index)")
                _ = try f.open()
                let journal = try f.open { if $0 == phase { throw JournalCheckFailure.interrupted } }
                try refuses { try journal.writeService("disable_intent_prior_enabled") }
                let recovered = try f.open(), state = try recovered.recovery()
                if phase == .published { try expect(state.recordCount == 1 && state.ownsDisable) }
                else {
                    try expect(state.recordCount == 0 && !state.ownsDisable)
                    try recovered.writeService("disable_intent_prior_enabled")
                    try expect(try f.open().recovery().ownsDisable)
                }
            }
            do {
                let f = try Fixture(root: root, name: "orphan-bound")
                for _ in 0..<8 { try refuses { _ = try f.open { if $0 == .pendingCreated { throw JournalCheckFailure.interrupted } } } }
                try expect(try InstallerPayloadIO.contents(f.fd).count == 8)
                try refuses { _ = try f.open() }
                try expect(try InstallerPayloadIO.contents(f.fd).count == 8)
            }
            for mutation in ["intent-rewrite", "record-rewrite", "record-gap", "foreign-name", "intent-hardlink", "ancestor-detach"] {
                let f = try Fixture(root: root, name: mutation), journal = try f.open()
                try journal.writeService("disable_intent_prior_enabled")
                if mutation == "intent-rewrite" { try rewrite(f.fd, "intent.json", Data("{}".utf8)) }
                else if mutation == "record-rewrite" { try rewrite(f.fd, "record-0000.json", Data("{}".utf8)) }
                else if mutation == "record-gap" { try ComponentFiles.rename(f.fd, "record-0000.json", f.fd, "record-0001.json", swap: false) }
                else if mutation == "foreign-name" { _ = try ComponentFiles.writeExclusive(f.fd, "foreign.json", data: Data("{}".utf8), owner: getuid(), mode: 0o600) }
                else if mutation == "intent-hardlink" { guard linkat(f.fd, "intent.json", root, "outside-hardlink", 0) == 0 else { throw JournalCheckFailure.failed } }
                else { try ComponentFiles.rename(root, mutation, root, "detached-" + mutation, swap: false); let replacement = try directory(root, mutation); Darwin.close(replacement) }
                try refuses { _ = try journal.recovery() }
                try refuses { _ = try f.open() }
            }
            // A structurally well-formed foreign source/proof cannot replace a
            // compiled-source-bound intent merely by matching the JSON schema.
            do {
                let f = try Fixture(root: root, name: "proof-source")
                let encoder = JSONEncoder(); var value = try JSONSerialization.jsonObject(with: encoder.encode(f.intent)) as! [String: Any]
                value["predecessorEvidenceSHA256"] = String(repeating: "6", count: 64)
                let altered = try JSONDecoder().decode(FullImageGlobalIntent.self, from: JSONSerialization.data(withJSONObject: value))
                try refuses { try f.validate(altered) }
                // Recompute the after-object pin AND caller payload together.
                // The deterministic new namespace head must still reject it.
                let foreignHead = Data("{\"schema\":1,\"managed_by\":\"account-access-component-head-v1\"}".utf8)
                var foreignValue = try JSONSerialization.jsonObject(with: encoder.encode(f.intent)) as! [String: Any]
                var operations = foreignValue["operations"] as! [[String: Any]]
                var last = operations[operations.count - 1], file = last["file"] as! [String: Any]
                var after = file["after"] as! [String: Any]; after["sha256"] = FullImageJSON.hash(foreignHead); after["bytes"] = foreignHead.count
                file["after"] = after; last["file"] = file; operations[operations.count - 1] = last; foreignValue["operations"] = operations
                let foreign = try JSONDecoder().decode(FullImageGlobalIntent.self, from: JSONSerialization.data(withJSONObject: foreignValue))
                var foreignDynamic = f.dynamic; foreignDynamic[.head] = foreignHead
                try refuses { try foreign.validate(source: f.source, predecessorEvidenceSHA256: String(repeating: "5", count: 64),
                    workerPolicy: f.intent.workerPolicy, servicePlist: f.intent.servicePlist, ownerUID: 501, brokerUID: 473,
                    publicOwner: getuid(), publicGroup: getgid(), device: f.identity.device, dynamic: foreignDynamic) }
                value["operations"] = [["kind": "file"]]
                let malformed = try JSONDecoder().decode(FullImageGlobalIntent.self, from: JSONSerialization.data(withJSONObject: value))
                try refuses { try malformed.validateStructure(device: f.identity.device, publicOwner: getuid(), publicGroup: getgid()) }
            }
            // These are synthetic group pins; no file ownership is changed.
            // The persisted journal still belongs to this ordinary invocation.
            do {
                let legacy = getgid() ^ 1
                let f = try Fixture(root: root, name: "legacy-group-journal", beforeGroup: legacy)
                try f.validate(f.intent); try expect(true)
                try f.intent.validateStructure(device: f.identity.device, publicOwner: getuid(), publicGroup: getgid(), beforeGroup: legacy)
                try expect(true)
                try refuses { try f.intent.validateStructure(device: f.identity.device, publicOwner: getuid(), publicGroup: getgid()) }
                try refuses { try f.intent.validateStructure(device: f.identity.device, publicOwner: getuid(), publicGroup: getgid(), beforeGroup: getgid()) }
                for (side, group) in [("before", getgid()), ("after", legacy)] {
                    let forged = try mutateTree(f.intent, unit: .owner) { tree in
                        var pin = tree[side] as! [String: Any]; pin["group"] = group; tree[side] = pin
                    }
                    try refuses { try f.validate(forged) }
                }
                try refuses {
                    _ = try FullImageGlobalJournal.open(directory: f.fd, owner: getuid(), group: getgid(), expected: f.intent,
                        validateIntent: f.validate, verifyAttachment: f.attached)
                }
                let journal = try f.open(); try expect(journal.intent == f.intent)
                let loaded = try FullImageGlobalJournal.readIntent(directory: f.fd, owner: getuid(), group: getgid(), beforeGroup: legacy,
                    validateIntent: f.validate, verifyAttachment: f.attached)
                try expect(loaded == f.intent)
                try refuses {
                    _ = try FullImageGlobalJournal.readIntent(directory: f.fd, owner: getuid(), group: getgid(),
                        validateIntent: f.validate, verifyAttachment: f.attached)
                }
                try refuses {
                    _ = try FullImageGlobalJournal.readIntent(directory: f.fd, owner: getuid(), group: getgid(), beforeGroup: getgid(),
                        validateIntent: f.validate, verifyAttachment: f.attached)
                }
                try journal.writeService("disable_intent_prior_enabled")
                let resumed = try f.open(), recovery = try resumed.recovery()
                try expect(resumed.intent == f.intent)
                try expect(recovery.recordCount == 1 && recovery.ownsDisable && !recovery.finished)
                try expect(f.intent.operations.compactMap(\.tree).allSatisfy {
                    ($0.before == nil || $0.before?.group == legacy) && ($0.after == nil || $0.after?.group == getgid())
                })
            }
            var observed = stat(); guard lstat(path, &observed) == 0, PublicTreeDirectoryIdentity(observed) == rootPin else { throw JournalCheckFailure.failed }
            try FileManager.default.removeItem(atPath: path) // Exclusive invocation-owned 0700 tree only.
            print("{\"status\":\"FULL_IMAGE_DURABLE_JOURNAL_CHECKS_PASSED\",\"assertions\":" + String(assertions) + ",\"installed_or_provider_operations\":false}")
        } catch { fputs("FULL_IMAGE_DURABLE_JOURNAL_CHECK_FAILED\n", stderr); exit(1) }
    }
}
