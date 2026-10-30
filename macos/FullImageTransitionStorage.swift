// Mixed typed file/tree transition adapter; no installed route or entrypoint.
// Fixed native callers must qualify attachment and real service barriers.
import Foundation
import CryptoKit
import Darwin

// Journal-selected strings never resolve to destinations. The native adapter
// resolves this enum through fixed support/policy/head roots only.
enum FullImageFileUnit: String, Codable, CaseIterable {
    case wheel, packageIdentity, runtimeImage, requirements, componentIdentity, caReceipt
    case pythonPip, pythonPip3, pythonPip312, runtimePip, runtimePip3, runtimePip312
    case runtimePreparation, repairIdentityRemoval, caReplacement
    case hostPolicy, ownerPolicy, installRecord, head
    case directPublicFile
    var path: String {
        switch self {
        case .wheel: return "wheels/account_access-0.8.0-py3-none-any.whl"
        case .packageIdentity: return "package-identity.json"
        case .runtimeImage: return "runtime-image.json"
        case .requirements: return "package-requirements.txt"
        case .componentIdentity: return "component-identity.json"
        case .caReceipt: return "runtime-ca-refresh.json"
        case .pythonPip: return "python/bin/pip"
        case .pythonPip3: return "python/bin/pip3"
        case .pythonPip312: return "python/bin/pip3.12"
        case .runtimePip: return "runtime/bin/pip"
        case .runtimePip3: return "runtime/bin/pip3"
        case .runtimePip312: return "runtime/bin/pip3.12"
        case .runtimePreparation: return "runtime-preparation.json"
        case .repairIdentityRemoval: return "broker-repair-identity.json"
        case .caReplacement: return "runtime-ca-refresh.json"
        case .hostPolicy: return "broker/host.json"
        case .ownerPolicy: return "owner.json"
        case .installRecord: return "broker/install.json"
        case .head: return "head.json"
        case .directPublicFile: return "direct-public-file"
        }
    }
    var target: ComponentOperation.Target {
        switch self {
        case .hostPolicy: return .hostPolicy
        case .ownerPolicy: return .ownerPolicy
        case .installRecord: return .installRecord
        case .head: return .head
        default: return .image
        }
    }
    var publicUnit: FullImagePlanFileUnit? { FullImagePlanFileUnit(rawValue: rawValue) }
    init(publicUnit: FullImagePlanFileUnit) { self = Self(rawValue: publicUnit.rawValue)! }
    var mode: UInt16 { publicUnit?.mode ?? (self == .installRecord ? 0o600 : 0o644) }
}

struct FullImageFileOperation: Codable, Equatable {
    let schema: Int
    let unit: FullImageFileUnit
    let planSHA256: String
    let index: Int
    let before: ComponentObject?
    let after: ComponentObject?
    var directPath: String? = nil
    var directMode: UInt16? = nil
    var slot: String { String(format: "slot-%02d", index) }
    var path: String { unit == .directPublicFile ? (directPath ?? "") : unit.path }
    var mode: UInt16 { unit == .directPublicFile ? (directMode ?? 0) : unit.mode }
    func validate(ownerDevice: Int32) throws {
        let directPlan = planSHA256 == "d73f29c04cce63b39abd9df657f9e2258a7cb7eb9e1c5a858bffb86be19c5e5e"
        guard schema == 1, FullImageJSON.hex(planSHA256), (0..<(directPlan ? 256 : 64)).contains(index),
              before != nil || after != nil, before != after else { throw FullImageFailure.journal }
        if unit == .directPublicFile {
            guard directPlan, let directPath, let directMode,
                  (directMode == 0o644 || directMode == 0o755),
                  let parts = try? InstallerPayloadManifest.components(directPath), !parts.isEmpty,
                  !directPath.hasPrefix("/"), !directPath.contains("\\"),
                  ["owner.app", "python", "runtime", "browsers", "wheels", "bin"].contains(parts[0]),
                  [before, after].compactMap({ $0 }).allSatisfy({ $0.mode == directMode }) else { throw FullImageFailure.journal }
        } else {
            guard (0..<64).contains(index), directPath == nil, directMode == nil else { throw FullImageFailure.journal }
        }
        if let publicUnit = unit.publicUnit {
            guard (before != nil) == publicUnit.beforePresent,
                  (after != nil) == publicUnit.afterPresent else { throw FullImageFailure.journal }
        } else if unit == .directPublicFile {
            guard before != nil || after != nil else { throw FullImageFailure.journal }
        } else {
            guard after != nil, (before == nil) == (unit == .head) else { throw FullImageFailure.journal }
        }
        for object in [before, after].compactMap({ $0 }) {
            guard object.device == ownerDevice, object.inode > 0, object.mode == mode,
                  object.bytes >= 0, object.bytes <= (unit == .directPublicFile
                    ? InstallerPayloadManifest.maximumFile : Int64(ComponentFiles.maximumFile)),
                  FullImageJSON.hex(object.sha256) else { throw FullImageFailure.journal }
        }
        if let before, let after { guard before.inode != after.inode else { throw FullImageFailure.journal } }
    }
    // ComponentTransition uses these as opaque routing tokens only. Actual
    // equality and authority always use the typed record above, including nil.
    var token: ComponentOperation {
        let absent = ComponentObject(device: 0, inode: 0, mode: 0, bytes: 0, sha256: String(repeating: "0", count: 64))
        return ComponentOperation(target: unit.target, path: path, slot: slot, before: before, after: after ?? absent)
    }
}

final class FullImageFileStorage {
    let operation: FullImageFileOperation
    private let retained: Int32, owner: uid_t
    private let resolve: (FullImageFileUnit) throws -> (Int32, String)
    private let resolveDirect: ((String) throws -> (Int32, String))?
    private let verifyAttachments: () throws -> Void
    private let requireQuiescent: () throws -> Void
    private let observationDevice: Int32?
    private let currentDevice: Int32
    private let completedProjection: (() throws -> ComponentObject?)?
    init(operation: FullImageFileOperation, retained: Int32, owner: uid_t,
         resolve: @escaping (FullImageFileUnit) throws -> (Int32, String),
         resolveDirect: ((String) throws -> (Int32, String))? = nil,
         verifyAttachments: @escaping () throws -> Void, requireQuiescent: @escaping () throws -> Void,
         observationDevice: Int32? = nil, completedProjection: (() throws -> ComponentObject?)? = nil) throws {
        let parent = try InstallerPayloadIO.check(retained, owner: owner, directory: true)
        guard parent.st_mode & 0o7777 == 0o700 else { throw FullImageFailure.object }
        try PublicTreeIO.noACL(retained)
        guard observationDevice == nil || observationDevice! >= 0 else { throw FullImageFailure.object }
        try operation.validate(ownerDevice: observationDevice ?? parent.st_dev)
        self.operation = operation; self.retained = retained; self.owner = owner
        self.resolve = resolve; self.resolveDirect = resolveDirect
        self.verifyAttachments = verifyAttachments; self.requireQuiescent = requireQuiescent
        self.observationDevice = observationDevice; currentDevice = parent.st_dev
        self.completedProjection = completedProjection
    }
    func matches(_ observed: ComponentObject?, _ recorded: ComponentObject?) -> Bool {
        guard let observed, let recorded else { return observed == nil && recorded == nil }
        guard let observationDevice else { return observed == recorded }
        return recorded.device == observationDevice && observed.device == currentDevice
            && observed == ComponentObject(device: currentDevice, inode: recorded.inode,
                mode: recorded.mode, bytes: recorded.bytes, sha256: recorded.sha256)
    }
    func state() throws -> ComponentOperationState {
        try verifyAttachments()
        if let completedProjection {
            let current = try completedProjection()
            let saved = try ComponentFiles.observe(retained, operation.slot, owner: owner)
            try verifyAttachments()
            return matches(current, operation.after) && matches(saved, operation.before) ? .applied : .conflict
        }
        let (parent, name) = try destination()
        defer { Darwin.close(parent) }
        try ComponentFiles.name(name)
        let current = try ComponentFiles.observe(parent, name, owner: owner)
        let saved = try ComponentFiles.observe(retained, operation.slot, owner: owner)
        try verifyAttachments()
        if matches(current, operation.before), matches(saved, operation.after) { return .staged }
        if matches(current, operation.after), matches(saved, operation.before) { return .applied }
        return .conflict
    }
    func originalObservation() throws -> (Data, ComponentObject) {
        guard let before = operation.before else { throw FullImageFailure.journal }
        let current = try state()
        guard current != .conflict else { throw FullImageFailure.object }
        let read: (Data, ComponentObject)
        if current == .staged {
            let (parent, name) = try destination(); defer { Darwin.close(parent) }
            read = try ComponentFiles.read(parent, name, owner: owner, mode: mode_t(operation.mode))
        } else {
            read = try ComponentFiles.read(retained, operation.slot, owner: owner, mode: mode_t(operation.unit.mode))
        }
        guard matches(read.1, before), try state() == current else { throw FullImageFailure.object }
        return read
    }
    func apply() throws { try exchange(forward: true) }
    func reverse() throws { try exchange(forward: false) }
    private func exchange(forward: Bool) throws {
        guard observationDevice == nil, completedProjection == nil else { throw FullImageFailure.journal }
        try requireQuiescent(); try verifyAttachments()
        guard try state() == (forward ? .staged : .applied) else { throw FullImageFailure.object }
        let (parent, name) = try destination()
        defer { Darwin.close(parent) }
        let source = forward ? operation.after : operation.before
        let destination = forward ? operation.before : operation.after
        if source == nil {
            // Removal is an exclusive move into our absent retained slot.
            try ComponentFiles.rename(parent, name, retained, operation.slot, swap: false)
        } else {
            try ComponentFiles.rename(retained, operation.slot, parent, name, swap: destination != nil)
        }
        try verifyAttachments(); try requireQuiescent()
        guard try state() == (forward ? .applied : .staged) else { throw FullImageFailure.object }
    }
    private func destination() throws -> (Int32, String) {
        if operation.unit == .directPublicFile {
            guard let path = operation.directPath, let resolveDirect else { throw FullImageFailure.journal }
            return try resolveDirect(path)
        }
        return try resolve(operation.unit)
    }
}

enum FullImageTreeToken {
    static func operation(_ record: PublicTreeOperation) throws -> ComponentOperation {
        guard record.schema == 2, let unit = PublicTreeUnit(rawValue: record.unit),
              (record.before != nil) == unit.beforePresent, (record.after != nil) == unit.afterPresent,
              [record.planSHA256, record.beforeManifestSHA256, record.afterManifestSHA256].allSatisfy({ FullImageJSON.hex($0) }) else { throw FullImageFailure.journal }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let raw = try encoder.encode(record)
        // All tree tokens (including replacements) identify the immutable
        // typed record. Zero fields are opaque routing bytes, never an absent
        // inode, tree pin, path observation or filesystem authority.
        let identity = ComponentObject(device: 0, inode: 0, mode: 0, bytes: Int64(raw.count), sha256: FullImageJSON.hash(raw))
        return ComponentOperation(target: .image, path: unit.path, slot: "tree-" + unit.rawValue, before: nil, after: identity)
    }
}

// One global transition ordering spans all files and trees. Per-tree journals
// remain enforced by PublicTreeStorage, including interruption after swap.
final class FullImageMixedStorage: ComponentTransitionStorage {
    enum Unit {
        case file(FullImageFileStorage)
        case tree(PublicTreeStorage)
        func token() throws -> ComponentOperation {
            switch self {
            case .file(let storage): return storage.operation.token
            case .tree(let storage): return try FullImageTreeToken.operation(storage.operation)
            }
        }
    }
    let operations: [ComponentOperation]
    private let units: [Unit]
    private let event: (String, Int) throws -> Void
    private let oldView: ([ComponentOperationState]) throws -> Void
    private let recoverableView: ([ComponentOperationState]) throws -> Void
    private let newView: ([ComponentOperationState]) throws -> Void
    init(units: [Unit], writeEvent: @escaping (String, Int) throws -> Void,
         verifyOld: @escaping ([ComponentOperationState]) throws -> Void,
         verifyRecoverable: @escaping ([ComponentOperationState]) throws -> Void,
         verifyNew: @escaping ([ComponentOperationState]) throws -> Void) throws {
        let tokens = try units.map { try $0.token() }
        let plans = units.map { unit -> String in
            switch unit { case .file(let storage): return storage.operation.planSHA256; case .tree(let storage): return storage.operation.planSHA256 }
        }
        let directPlan = "d73f29c04cce63b39abd9df657f9e2258a7cb7eb9e1c5a858bffb86be19c5e5e"
        let operationLimit = plans.first == directPlan ? 256 : 64
        guard !tokens.isEmpty, tokens.count <= operationLimit, Set(plans).count == 1, Set(tokens.map(\.path)).count == tokens.count,
              Set(tokens.map(\.slot)).count == tokens.count,
              tokens.filter({ $0.target == .head }).count == 1, tokens.last?.target == .head else { throw FullImageFailure.journal }
        self.units = units; operations = tokens; event = writeEvent
        oldView = verifyOld; recoverableView = verifyRecoverable; newView = verifyNew
    }
    private func unit(_ token: ComponentOperation) throws -> Unit {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(token)
        guard let index = try operations.indices.first(where: { try encoder.encode(operations[$0]) == bytes }) else {
            throw FullImageFailure.journal
        }
        return units[index]
    }
    func state(_ operation: ComponentOperation) throws -> ComponentOperationState {
        switch try unit(operation) {
        case .file(let storage): return try storage.state()
        case .tree(let storage): return try storage.state() == .staged ? .staged : .applied
        }
    }
    func apply(_ operation: ComponentOperation) throws {
        switch try unit(operation) { case .file(let storage): try storage.apply(); case .tree(let storage): try storage.apply() }
    }
    func reverse(_ operation: ComponentOperation) throws {
        switch try unit(operation) { case .file(let storage): try storage.reverse(); case .tree(let storage): try storage.reverse() }
    }
    func writeEvent(_ value: String, operation: Int) throws {
        guard ["apply_intent", "applied", "rollback_intent", "rolled_back", "rollback_conflict", "old_image_restored", "new_image_verified_gui_unverified"].contains(value),
              operation == -1 || operations.indices.contains(operation) else { throw FullImageFailure.journal }
        try event(value, operation)
    }
    func verifyOldView() throws {
        let states = try operations.map { try state($0) }
        guard !states.contains(.conflict), states.allSatisfy({ $0 == .staged }) else { throw FullImageFailure.object }
        try oldView(states)
    }
    func verifyRecoverableView() throws {
        let states = try operations.map { try state($0) }
        guard !states.contains(.conflict) else { throw FullImageFailure.object }
        try recoverableView(states)
    }
    func verifyNewView() throws {
        // Head remains staged until ComponentTransition publishes it last.
        let states = try operations.map { try state($0) }
        guard !states.contains(.conflict), operations.indices.filter({ operations[$0].target != .head })
            .allSatisfy({ states[$0] == .applied }) else { throw FullImageFailure.object }
        try newView(states)
    }
    func serviceDidQuiesce() throws {
        for unit in units {
            if case .tree(let storage) = unit { try storage.enableQuiescedFastState() }
        }
    }
}

