// Fixed-schema durable mixed transition journal. No main/installed path lookup.
// A future fixed native adapter supplies a qualified attached 0700 descriptor;
// journal bytes never choose a destination, namespace, target or authority root.
import Foundation
import Darwin

// First complete-image transition only. The predecessor component namespace
// stays untouched. These literals are future fixed-adapter roots, never data
// accepted from a journal, manifest, command argument or owner request.
enum FullImageFixedNamespace {
    static let namespace = "/Library/Application Support/Account Access Full Images"
    static let head = namespace + "/head.json"
    static let predecessorHead = "/Library/Application Support/Account Access Components/head.json"
    static func transition(_ compiledPlanSHA256: String) throws -> String {
        guard FullImageJSON.hex(compiledPlanSHA256) else { throw FullImageFailure.journal }
        return namespace + "/transition-" + compiledPlanSHA256
    }
}

struct FullImageDurableOperation: Codable, Equatable {
    enum Kind: String, Codable { case file, tree }
    let kind: Kind
    let file: FullImageFileOperation?
    let tree: PublicTreeOperation?
    init(file: FullImageFileOperation) { kind = .file; self.file = file; tree = nil }
    init(tree: PublicTreeOperation) { kind = .tree; file = nil; self.tree = tree }
    func path() throws -> String {
        switch kind {
        case .file:
            guard let file, tree == nil else { throw FullImageFailure.journal }; return file.unit.path
        case .tree:
            guard file == nil, let tree, let unit = PublicTreeUnit(rawValue: tree.unit) else { throw FullImageFailure.journal }; return unit.path
        }
    }
    func token() throws -> ComponentOperation {
        switch kind {
        case .file:
            guard let file, tree == nil else { throw FullImageFailure.journal }; return file.token
        case .tree:
            guard file == nil, let tree else { throw FullImageFailure.journal }
            return try FullImageTreeToken.operation(tree)
        }
    }
    func validate(plan: String, beforeManifest: String, afterManifest: String, device: Int32,
                  publicOwner: uid_t, publicGroup: gid_t) throws {
        switch kind {
        case .file:
            guard let file, tree == nil, file.planSHA256 == plan else { throw FullImageFailure.journal }
            try file.validate(ownerDevice: device)
        case .tree:
            guard file == nil, let tree, tree.schema == 2, let unit = PublicTreeUnit(rawValue: tree.unit),
                  tree.planSHA256 == plan, tree.beforeManifestSHA256 == beforeManifest, tree.afterManifestSHA256 == afterManifest,
                  (tree.before != nil) == unit.beforePresent, (tree.after != nil) == unit.afterPresent else { throw FullImageFailure.journal }
            for pin in [tree.before, tree.after].compactMap({ $0 }) {
                guard pin.device == device, pin.owner == publicOwner, pin.group == publicGroup,
                      pin.mode == 0o755, pin.inode > 0, FullImageJSON.hex(pin.inventorySHA256) else { throw FullImageFailure.journal }
            }
            if let before = tree.before, let after = tree.after {
                guard before.inode != after.inode, before.inventorySHA256 != after.inventorySHA256 else { throw FullImageFailure.journal }
            }
        }
    }
}

struct FullImageGlobalIntent: Codable, Equatable {
    let schema: Int
    let managedBy: String
    let planSHA256: String
    let beforeManifestSHA256: String
    let afterManifestSHA256: String
    let targetSourceCommit: String
    let predecessorEvidenceSHA256: String
    let ownerUID: UInt32
    let brokerUID: UInt32
    let initialService: ComponentJobIdentity?
    let workerPolicy: ComponentObject
    let servicePlist: ComponentObject
    let operations: [FullImageDurableOperation]
    let automaticRebootRecovery: Bool

    static func newHead(source: FullImageSource, predecessorEvidenceSHA256: String) throws -> Data {
        guard FullImageJSON.hex(predecessorEvidenceSHA256) else { throw FullImageFailure.predecessor }
        let value: [String: Any] = ["schema": 1, "managed_by": "account-access-full-image-head-v1",
            "plan_sha256": source.pins.planSHA256, "before_manifest_sha256": source.before.sha256,
            "manifest_sha256": source.after.sha256, "source_commit": source.pins.targetSourceCommit,
            "predecessor_evidence_sha256": predecessorEvidenceSHA256,
            "state": "public_image_verified_gui_unverified", "automatic_reboot_recovery": false]
        var raw = try FullImageJSON.canonical(value); raw.append(10); return raw
    }
    func validateStructure(device: Int32, publicOwner: uid_t, publicGroup: gid_t) throws {
        guard schema == 2, managedBy == "account-access-full-image-transition-v2", !automaticRebootRecovery,
              [planSHA256, beforeManifestSHA256, afterManifestSHA256, predecessorEvidenceSHA256].allSatisfy({ FullImageJSON.hex($0) }),
              beforeManifestSHA256 != afterManifestSHA256, FullImageJSON.hex(targetSourceCommit, count: 40),
              ownerUID > 0, ownerUID != brokerUID, (450..<500).contains(brokerUID), (1...64).contains(operations.count) else { throw FullImageFailure.journal }
        if let initialService { try ComponentUpdateIdentity.validateSnapshot(initialService) }
        for value in [workerPolicy, servicePlist] {
            guard value.device == device, value.inode > 0, value.mode == 0o644, value.bytes >= 0, value.bytes <= 8192,
                  FullImageJSON.hex(value.sha256) else { throw FullImageFailure.journal }
        }
        for operation in operations {
            try operation.validate(plan: planSHA256, beforeManifest: beforeManifestSHA256,
                afterManifest: afterManifestSHA256, device: device, publicOwner: publicOwner, publicGroup: publicGroup)
        }
        let paths = try operations.map { try $0.path() }, slots = try operations.map { try $0.token().slot }
        guard Set(paths).count == paths.count, Set(slots).count == slots.count,
              try operations.filter({ try $0.token().target == .head }).count == 1,
              try operations.last?.token().target == .head else { throw FullImageFailure.journal }
    }
    func validate(source: FullImageSource, predecessorEvidenceSHA256: String, workerPolicy: ComponentObject,
                  servicePlist: ComponentObject, ownerUID: uid_t, brokerUID: uid_t,
                  publicOwner: uid_t, publicGroup: gid_t, device: Int32,
                  dynamic: [FullImageFileUnit: Data]) throws {
        try validateStructure(device: device, publicOwner: publicOwner, publicGroup: publicGroup)
        guard schema == 2, managedBy == "account-access-full-image-transition-v2", !automaticRebootRecovery,
              planSHA256 == source.pins.planSHA256, beforeManifestSHA256 == source.before.sha256,
              afterManifestSHA256 == source.after.sha256, targetSourceCommit == source.pins.targetSourceCommit,
              FullImageJSON.hex(predecessorEvidenceSHA256), self.predecessorEvidenceSHA256 == predecessorEvidenceSHA256,
              self.ownerUID == ownerUID, self.brokerUID == brokerUID, ownerUID > 0, ownerUID != brokerUID,
              (450..<500).contains(brokerUID), self.workerPolicy == workerPolicy, self.servicePlist == servicePlist,
              operations.count == source.units.count + 4, operations.count <= 64,
              Set(dynamic.keys) == [.hostPolicy, .ownerPolicy, .installRecord, .head] else { throw FullImageFailure.journal }
        guard dynamic[.head] == (try Self.newHead(source: source, predecessorEvidenceSHA256: predecessorEvidenceSHA256)) else { throw FullImageFailure.journal }
        if let initialService { try ComponentUpdateIdentity.validateSnapshot(initialService) }
        let targets = source.units.map(\.path) + [FullImageFileUnit.hostPolicy.path, FullImageFileUnit.ownerPolicy.path,
            FullImageFileUnit.installRecord.path, FullImageFileUnit.head.path]
        guard try operations.map({ try $0.path() }) == targets, Set(targets).count == targets.count,
              Set(try operations.map { try $0.token().slot }).count == operations.count else { throw FullImageFailure.journal }
        var inodes: Set<UInt64> = []
        for (index, operation) in operations.enumerated() {
            try operation.validate(plan: planSHA256, beforeManifest: beforeManifestSHA256,
                afterManifest: afterManifestSHA256, device: device, publicOwner: publicOwner, publicGroup: publicGroup)
            if let file = operation.file {
                guard file.index == index else { throw FullImageFailure.journal }
                for pin in [file.before, file.after].compactMap({ $0 }) {
                    guard inodes.insert(pin.inode).inserted else { throw FullImageFailure.journal }
                }
            } else if let tree = operation.tree {
                for pin in [tree.before, tree.after].compactMap({ $0 }) {
                    guard inodes.insert(pin.inode).inserted else { throw FullImageFailure.journal }
                }
            }
            if index < source.units.count {
                switch source.units[index] {
                case .tree(let unit, let before, let after):
                    guard let tree = operation.tree, tree.unit == unit.rawValue,
                          (tree.before != nil) == before.isPresent, (tree.after != nil) == after.isPresent,
                          tree.before?.inventorySHA256 == before.inventorySHA256,
                          tree.after?.inventorySHA256 == after.inventorySHA256 else { throw FullImageFailure.journal }
                case .file(let unit, let before, let after):
                    guard let file = operation.file, file.unit.publicUnit == unit,
                          matches(file.before, before), matches(file.after, after) else { throw FullImageFailure.journal }
                }
            } else {
                let unit = [FullImageFileUnit.hostPolicy, .ownerPolicy, .installRecord, .head][index - source.units.count]
                guard let file = operation.file, file.unit == unit, let after = file.after,
                      let data = dynamic[unit], after.bytes == data.count,
                      after.sha256 == FullImageJSON.hash(data), (file.before == nil) == (unit == .head) else { throw FullImageFailure.journal }
            }
        }
    }
    private func matches(_ object: ComponentObject?, _ node: InstallerPayloadNode?) -> Bool {
        guard let node else { return object == nil }
        guard let object else { return false }
        return node.kind == "file" && object.mode == node.mode && object.bytes == node.size && object.sha256 == node.sha256
    }
    func verifyStorage(_ storage: FullImageMixedStorage) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard operations.count == storage.operations.count else { throw FullImageFailure.journal }
        for index in operations.indices {
            guard try encoder.encode(operations[index].token()) == encoder.encode(storage.operations[index]) else { throw FullImageFailure.journal }
        }
    }
}

final class FullImageGlobalJournal {
    enum Transition: String, Codable, CaseIterable {
        case applyIntent = "apply_intent", applied, rollbackIntent = "rollback_intent", rolledBack = "rolled_back"
        case rollbackConflict = "rollback_conflict", oldImageRestored = "old_image_restored"
        case newImageVerified = "new_image_verified_gui_unverified"
    }
    enum Service: String, Codable, CaseIterable {
        case disableIntent = "disable_intent_prior_enabled", disabled = "disabled_confirmed"
        case quiescent = "disabled_quiescence_confirmed", enableIntent = "coherent_image_enable_intent"
        case bootstrapped = "canonical_job_bootstrapped_gui_unverified"
        case userBootout = "user_domain_bootout_intent", userQuiescent = "user_domain_quiescence_confirmed"
        case userBootstrap = "user_domain_bootstrap_intent", userBootstrapped = "user_domain_bootstrap_confirmed"
    }
    struct Recovery {
        let recordCount: Int
        let snapshots: [ComponentJobIdentity]
        let ownsDisable: Bool
        let finished: Bool
    }
    enum Phase { case pendingCreated, pendingSynced, published }
    private struct Record: Codable {
        enum Kind: String, Codable { case transition, service, job }
        let schema: Int
        let managedBy: String
        let sequence: Int
        let planSHA256: String
        let intentSHA256: String
        let previousSHA256: String
        let kind: Kind
        let transition: Transition?
        let operation: Int?
        let service: Service?
        let job: ComponentJobIdentity?
    }
    private struct Pin: Equatable {
        let device: Int32, inode: UInt64, mode: mode_t, bytes: Int64, sha256: String
        let mtimeSec: Int64, mtimeNsec: Int64, ctimeSec: Int64, ctimeNsec: Int64
    }
    private struct File {
        let data: Data
        let pin: Pin
    }
    static let maximumRecords = 10_000
    private static let maximumIntent = 256 * 1024, maximumRecord = 8192, maximumOrphans = 8
    private let directory: Int32, owner: uid_t, group: gid_t
    private let identity: PublicTreeDirectoryIdentity
    private let verifyAttachment: (Int32) throws -> Void
    private let fault: (Phase) throws -> Void
    let intent: FullImageGlobalIntent
    let intentSHA256: String
    private var intentPin: Pin
    private var records: [File] = []
    private var pendingPins: [String: Pin] = [:]
    private var recordValues: [Record] = []

    private static func encoded<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let value = try FullImageJSON.object(encoder.encode(value), maximum: maximumIntent)
        var raw = try FullImageJSON.canonical(value); raw.append(10); return raw
    }
    private static func decoded<T: Decodable & Encodable>(_ type: T.Type, raw: Data, maximum: Int) throws -> T {
        _ = try FullImageJSON.object(raw, maximum: maximum)
        let value = try JSONDecoder().decode(type, from: raw)
        guard try encoded(value) == raw else { throw FullImageFailure.journal }
        return value
    }
    private init(directory: Int32, owner: uid_t, group: gid_t, identity: PublicTreeDirectoryIdentity,
                 verifyAttachment: @escaping (Int32) throws -> Void, fault: @escaping (Phase) throws -> Void,
                 intent: FullImageGlobalIntent, intentPin: Pin) throws {
        self.directory = directory; self.owner = owner; self.group = group; self.identity = identity
        self.verifyAttachment = verifyAttachment; self.fault = fault; self.intent = intent; self.intentPin = intentPin
        intentSHA256 = FullImageJSON.hash(try Self.encoded(intent))
    }
    deinit { Darwin.close(directory) }
    private func attached() throws {
        try verifyAttachment(directory)
        guard try PublicTreeDirectoryIdentity.observe(directory, owner: owner, group: group) == identity,
              identity.mode == 0o700 else { throw FullImageFailure.journal }
    }
    private static func inspect(_ directory: Int32, _ name: String, owner: uid_t, group: gid_t, maximum: Int,
                                readBody: Bool) throws -> File {
        try ComponentFiles.name(name)
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw FullImageFailure.journal }
        defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        try PublicTreeIO.noACL(fd)
        guard before.st_gid == group, before.st_mode & 0o7777 == 0o600,
              before.st_size >= 0, before.st_size <= maximum else { throw FullImageFailure.journal }
        let data = readBody ? try InstallerPayloadIO.read(fd, maximum: maximum, owner: owner) : Data()
        var path = stat()
        let after = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        guard fstatat(directory, name, &path, AT_SYMLINK_NOFOLLOW) == 0,
              path.st_gid == group, after.st_gid == group,
              InstallerPayloadIO.same(before, path), InstallerPayloadIO.same(before, after) else { throw FullImageFailure.journal }
        return File(data: data, pin: Pin(device: before.st_dev, inode: UInt64(before.st_ino), mode: before.st_mode & 0o7777,
            bytes: before.st_size, sha256: readBody ? FullImageJSON.hash(data) : "", mtimeSec: Int64(before.st_mtimespec.tv_sec),
            mtimeNsec: Int64(before.st_mtimespec.tv_nsec), ctimeSec: Int64(before.st_ctimespec.tv_sec), ctimeNsec: Int64(before.st_ctimespec.tv_nsec)))
    }
    private static func pending(_ name: String) -> (sequence: Int?, attempt: Int)? {
        if name.hasPrefix("pending-intent-") {
            let suffix = String(name.dropFirst("pending-intent-".count))
            guard let attempt = Int(suffix), (0..<maximumOrphans).contains(attempt), suffix == String(format: "%02d", attempt) else { return nil }
            return (nil, attempt)
        }
        guard name.hasPrefix("pending-record-"), name.utf8.count == 22 else { return nil }
        let parts = name.dropFirst("pending-record-".count).split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 2, let sequence = Int(parts[0]), (0..<maximumRecords).contains(sequence),
              let attempt = Int(parts[1]), (0..<maximumOrphans).contains(attempt),
              name == String(format: "pending-record-%04d-%02d", sequence, attempt) else { return nil }
        return (sequence, attempt)
    }
    private func namespace() throws -> ([String: Pin], [File], [Record]) {
        try attached()
        let names = try InstallerPayloadIO.contents(directory)
        guard names.contains("intent.json"), names.count <= Self.maximumRecords + Self.maximumOrphans + 1 else { throw FullImageFailure.journal }
        var pending: [String: Pin] = [:], count = 0
        for name in names where name != "intent.json" {
            if let item = Self.pending(name) {
                guard pending.count < Self.maximumOrphans, item.sequence == nil || item.sequence! <= Self.maximumRecords - 1 else { throw FullImageFailure.journal }
                pending[name] = try Self.inspect(directory, name, owner: owner, group: group,
                    maximum: item.sequence == nil ? Self.maximumIntent : Self.maximumRecord, readBody: false).pin
            } else {
                guard name.hasPrefix("record-"), name.hasSuffix(".json"), name.utf8.count == 16,
                      let sequence = Int(name.dropFirst(7).dropLast(5)), (0..<Self.maximumRecords).contains(sequence),
                      name == String(format: "record-%04d.json", sequence) else { throw FullImageFailure.journal }
                count += 1
            }
        }
        var files: [File] = [], values: [Record] = [], previous = intentSHA256
        for sequence in 0..<count {
            let name = String(format: "record-%04d.json", sequence)
            guard names.contains(name) else { throw FullImageFailure.journal }
            let file = try Self.inspect(directory, name, owner: owner, group: group, maximum: Self.maximumRecord, readBody: true)
            let value = try Self.decoded(Record.self, raw: file.data, maximum: Self.maximumRecord)
            guard value.schema == 1, value.managedBy == "account-access-full-image-journal-v1", value.sequence == sequence,
                  value.planSHA256 == intent.planSHA256, value.intentSHA256 == intentSHA256,
                  value.previousSHA256 == previous else { throw FullImageFailure.journal }
            try validate(value)
            files.append(file); values.append(value); previous = file.pin.sha256
        }
        for name in pending.keys {
            if let sequence = Self.pending(name)?.sequence { guard sequence <= count else { throw FullImageFailure.journal } }
        }
        guard try Self.inspect(directory, "intent.json", owner: owner, group: group,
                  maximum: Self.maximumIntent, readBody: true).pin == intentPin else { throw FullImageFailure.journal }
        _ = try history(values)
        try attached()
        return (pending, files, values)
    }
    private func validate(_ record: Record) throws {
        switch record.kind {
        case .transition:
            guard let value = record.transition, let operation = record.operation, record.service == nil, record.job == nil else { throw FullImageFailure.journal }
            if [.oldImageRestored, .newImageVerified].contains(value) { guard operation == -1 else { throw FullImageFailure.journal }; return }
            guard intent.operations.indices.contains(operation) else { throw FullImageFailure.journal }
        case .service:
            guard record.service != nil, record.transition == nil, record.operation == nil, record.job == nil else { throw FullImageFailure.journal }
        case .job:
            guard let job = record.job, record.transition == nil, record.operation == nil, record.service == nil else { throw FullImageFailure.journal }
            try ComponentUpdateIdentity.validateSnapshot(job)
        }
    }
    private func history(_ values: [Record]) throws -> (restored: Bool, targetFinished: Bool, ownsDisable: Bool) {
        var stage: Service?, coherence: Transition?, hasDisableIntent = false
        for value in values {
            switch value.kind {
            case .job:
                guard stage == .disabled else { throw FullImageFailure.journal }
            case .transition:
                guard stage == .quiescent else { throw FullImageFailure.journal }
                if [.oldImageRestored, .newImageVerified].contains(value.transition!) { coherence = value.transition }
            case .service:
                let service = value.service!
                if service == .disableIntent {
                    stage = service; coherence = nil; hasDisableIntent = true
                    continue // The existing barrier may re-disable after any failure.
                }
                let previous: Service
                switch service {
                case .disableIntent: throw FullImageFailure.journal
                case .disabled: previous = .disableIntent
                case .userBootout: previous = .disabled
                case .userQuiescent: previous = .userBootout
                case .quiescent: previous = .userQuiescent
                case .userBootstrap:
                    guard coherence != nil else { throw FullImageFailure.journal }; previous = .quiescent
                case .userBootstrapped: previous = .userBootstrap
                case .enableIntent: previous = .userBootstrapped
                case .bootstrapped: previous = .enableIntent
                }
                guard stage == previous else { throw FullImageFailure.journal }
                stage = service
            }
        }
        let restored = stage == .bootstrapped
        return (restored, restored && coherence == .newImageVerified, !restored && hasDisableIntent)
    }
    private func unchanged() throws {
        let (pending, files, values) = try namespace()
        guard pending == pendingPins, files.map(\.pin) == records.map(\.pin), values.count == recordValues.count else { throw FullImageFailure.journal }
    }
    // Read an existing authority record before reconstructing its typed
    // retained objects. Only the literal intent name is read, then the caller's
    // source/predecessor validator must accept it before it is returned.
    static func readIntent(directory: Int32, owner: uid_t, group: gid_t,
                           validateIntent: (FullImageGlobalIntent) throws -> Void,
                           verifyAttachment: (Int32) throws -> Void) throws -> FullImageGlobalIntent {
        try verifyAttachment(directory)
        let identity = try PublicTreeDirectoryIdentity.observe(directory, owner: owner, group: group)
        guard identity.mode == 0o700 else { throw FullImageFailure.journal }
        let file = try inspect(directory, "intent.json", owner: owner, group: group, maximum: maximumIntent, readBody: true)
        let value = try decoded(FullImageGlobalIntent.self, raw: file.data, maximum: maximumIntent)
        try value.validateStructure(device: identity.device, publicOwner: owner, publicGroup: group)
        try validateIntent(value)
        guard try inspect(directory, "intent.json", owner: owner, group: group, maximum: maximumIntent, readBody: true).pin == file.pin,
              try PublicTreeDirectoryIdentity.observe(directory, owner: owner, group: group) == identity else { throw FullImageFailure.journal }
        try verifyAttachment(directory)
        return value
    }
    // `expected` was validated against the source, verified predecessor and
    // staged objects before this call. Reopen always requires the same bytes.
    static func open(directory supplied: Int32, owner: uid_t, group: gid_t, expected: FullImageGlobalIntent,
                     validateIntent: (FullImageGlobalIntent) throws -> Void,
                     verifyAttachment: @escaping (Int32) throws -> Void,
                     fault: @escaping (Phase) throws -> Void = { _ in }) throws -> FullImageGlobalJournal {
        let fd = fcntl(supplied, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw FullImageFailure.journal }
        var adopted = false
        defer { if !adopted { Darwin.close(fd) } }
        try verifyAttachment(fd)
        let identity = try PublicTreeDirectoryIdentity.observe(fd, owner: owner, group: group)
        guard identity.mode == 0o700 else { throw FullImageFailure.journal }
        try expected.validateStructure(device: identity.device, publicOwner: owner, publicGroup: group)
        try validateIntent(expected)
        let raw = try encoded(expected)
        guard raw.count <= maximumIntent else { throw FullImageFailure.journal }
        let names = try InstallerPayloadIO.contents(fd)
        if !names.contains("intent.json") {
            guard names.count <= maximumOrphans, names.allSatisfy({ pending($0)?.sequence == nil && pending($0) != nil }) else { throw FullImageFailure.journal }
            for name in names { _ = try inspect(fd, name, owner: owner, group: group, maximum: maximumIntent, readBody: false) }
            try publish(fd, target: "intent.json", pendingPrefix: "pending-intent-", raw: raw,
                owner: owner, group: group, maximum: maximumIntent, verify: { try verifyAttachment(fd) }, fault: fault)
        }
        let actual = try inspect(fd, "intent.json", owner: owner, group: group, maximum: maximumIntent, readBody: true)
        let parsed = try decoded(FullImageGlobalIntent.self, raw: actual.data, maximum: maximumIntent)
        try validateIntent(parsed)
        guard parsed == expected, actual.data == raw else { throw FullImageFailure.journal }
        let value = try FullImageGlobalJournal(directory: fd, owner: owner, group: group, identity: identity,
            verifyAttachment: verifyAttachment, fault: fault, intent: expected, intentPin: actual.pin)
        adopted = true
        (value.pendingPins, value.records, value.recordValues) = try value.namespace()
        return value
    }
    private static func publish(_ directory: Int32, target: String, pendingPrefix: String, raw: Data,
                                owner: uid_t, group: gid_t, maximum: Int, verify: () throws -> Void,
                                fault: (Phase) throws -> Void) throws {
        guard !raw.isEmpty, raw.count <= maximum else { throw FullImageFailure.journal }
        try verify()
        let names = try InstallerPayloadIO.contents(directory)
        var pendingName: String?, opened: Int32 = -1
        for attempt in 0..<maximumOrphans {
            let name = pendingPrefix + String(format: "%02d", attempt)
            if names.contains(name) { continue }
            opened = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            if opened < 0 { if errno == EEXIST { continue }; throw FullImageFailure.journal }
            pendingName = name; break
        }
        guard let pendingName, opened >= 0 else { throw FullImageFailure.journal }
        defer { Darwin.close(opened) }
        let created = try InstallerPayloadIO.check(opened, owner: owner, directory: false)
        try PublicTreeIO.noACL(opened)
        guard created.st_gid == group, created.st_mode & 0o7777 == 0o600 else { throw FullImageFailure.journal }
        try fault(.pendingCreated)
        try raw.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(opened, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FullImageFailure.journal }; offset += count
            }
        }
        guard fsync(opened) == 0, fsync(directory) == 0 else { throw FullImageFailure.journal }
        try fault(.pendingSynced); try verify()
        let complete = try inspect(directory, pendingName, owner: owner, group: group, maximum: maximum, readBody: true)
        guard complete.data == raw, complete.pin.inode == UInt64(created.st_ino), complete.pin.device == created.st_dev else { throw FullImageFailure.journal }
        try ComponentFiles.rename(directory, pendingName, directory, target, swap: false)
        let final = try inspect(directory, target, owner: owner, group: group, maximum: maximum, readBody: true)
        guard final.data == raw, final.pin.inode == complete.pin.inode, final.pin.device == complete.pin.device else { throw FullImageFailure.journal }
        try verify(); try fault(.published)
    }
    private func append(kind: Record.Kind, transition: Transition? = nil, operation: Int? = nil,
                        service: Service? = nil, job: ComponentJobIdentity? = nil) throws {
        try unchanged()
        guard records.count < Self.maximumRecords, pendingPins.count < Self.maximumOrphans else { throw FullImageFailure.journal }
        let value = Record(schema: 1, managedBy: "account-access-full-image-journal-v1", sequence: records.count,
            planSHA256: intent.planSHA256, intentSHA256: intentSHA256, previousSHA256: records.last?.pin.sha256 ?? intentSHA256,
            kind: kind, transition: transition, operation: operation, service: service, job: job)
        try validate(value)
        _ = try history(recordValues + [value])
        let raw = try Self.encoded(value)
        try Self.publish(directory, target: String(format: "record-%04d.json", records.count),
            pendingPrefix: String(format: "pending-record-%04d-", records.count), raw: raw,
            owner: owner, group: group, maximum: Self.maximumRecord, verify: { try self.attached() }, fault: fault)
        let (pending, files, values) = try namespace()
        guard pending == pendingPins, files.count == records.count + 1,
              Array(files.dropLast()).map(\.pin) == records.map(\.pin) else { throw FullImageFailure.journal }
        pendingPins = pending; records = files; recordValues = values
    }
    func writeTransition(_ event: String, operation: Int, state: (ComponentOperation) throws -> ComponentOperationState) throws {
        guard let event = Transition(rawValue: event) else { throw FullImageFailure.journal }
        if [.oldImageRestored, .newImageVerified].contains(event) { guard operation == -1 else { throw FullImageFailure.journal } }
        else { guard intent.operations.indices.contains(operation) else { throw FullImageFailure.journal } }
        switch event {
        case .applyIntent: guard try state(intent.operations[operation].token()) == .staged else { throw FullImageFailure.journal }
        case .applied, .rollbackIntent: guard try state(intent.operations[operation].token()) == .applied else { throw FullImageFailure.journal }
        case .rolledBack: guard try state(intent.operations[operation].token()) == .staged else { throw FullImageFailure.journal }
        case .rollbackConflict: guard try state(intent.operations[operation].token()) == .conflict else { throw FullImageFailure.journal }
        case .oldImageRestored:
            guard operation == -1, try intent.operations.allSatisfy({ try state($0.token()) == .staged }) else { throw FullImageFailure.journal }
        case .newImageVerified:
            guard operation == -1, try intent.operations.allSatisfy({ try state($0.token()) == .applied }) else { throw FullImageFailure.journal }
        }
        try append(kind: .transition, transition: event, operation: operation)
    }
    func writeService(_ value: String) throws {
        guard let value = Service(rawValue: value) else { throw FullImageFailure.journal }
        try append(kind: .service, service: value)
    }
    func writeSnapshot(_ value: ComponentJobIdentity) throws { try append(kind: .job, job: value) }
    func recovery() throws -> Recovery {
        try unchanged()
        let state = try history(recordValues)
        // A restored old image clears disable ownership too. It does not mean
        // the target was published, and cannot authorize adoption of a later
        // owner pause. This preserves the existing component barrier contract.
        return Recovery(recordCount: records.count, snapshots: recordValues.compactMap(\.job),
            ownsDisable: state.ownsDisable, finished: state.targetFinished)
    }
}
