
// IGNORED completed-predecessor companion. No installed entrypoint is added.
// Production construction is root-context/fixed-reader only. The caller must
// hold the full-image maintenance locks before qualification/revalidation.
// Only these fixed categories may leave the helper. Never export an underlying
// error description, record contents, paths, identities or filesystem values.
enum CompletedPredecessorCheckpoint: String, CaseIterable {
    case snapshotBefore = "snapshot_before", snapshotAfter = "snapshot_after"
    case snapshotRoots = "snapshot_roots", rootBinding = "root_binding"
    case retainedNamespace = "retained_namespace", retainedRecords = "retained_records"
    case currentPolicies = "current_policies", currentIntent = "current_intent"
    case structure, preparations, recordBounds = "record_bounds", originalReceipts = "original_receipts"
    case intentEncoding = "intent_encoding", intentContract = "intent_contract"
    case workerBinding = "worker_binding", serviceBinding = "service_binding"
    case operations, head, journal, retainedSlots = "retained_slots", audits
    case policyDerivation = "policy_derivation", dynamicBytes = "dynamic_bytes", evidence
    case currentImage = "current_image", currentHostPolicy = "current_host_policy"
    case currentOwnerPolicy = "current_owner_policy", currentInstallRecord = "current_install_record"
    case currentHead = "current_head", publicView = "public_view", signatures, service
    case evidenceStability = "evidence_stability", expectedEvidence = "expected_evidence"
}
struct CompletedPredecessorDiagnostic: Error {
    let checkpoint: CompletedPredecessorCheckpoint
    let failure: Error
    static func checked<T>(_ checkpoint: CompletedPredecessorCheckpoint, _ operation: () throws -> T) throws -> T {
        do { return try operation() }
        catch let diagnostic as CompletedPredecessorDiagnostic { throw diagnostic }
        catch { throw CompletedPredecessorDiagnostic(checkpoint: checkpoint, failure: error) }
    }
}
struct CompletedComponentRecord {
    let data: Data
    let object: ComponentObject
}
struct CompletedComponentDirectory: Codable, Equatable {
    let device: Int32; let inode: UInt64; let owner: UInt32; let group: UInt32; let mode: UInt16
}
struct CompletedComponentVolumeBinding {
    let previousDevice: Int32
    let currentDevice: Int32
    let volumeUUID: String
    let supplementSHA256: String
    private init(previous: Int32, current: Int32, volumeUUID: String, supplementSHA256: String) {
        previousDevice = previous; currentDevice = current
        self.volumeUUID = volumeUUID; self.supplementSHA256 = supplementSHA256
    }
    private static func devices(_ intent: ComponentTransitionIntent) -> Set<Int32> {
        var result: Set<Int32> = [intent.workerPolicy.device, intent.servicePlist.device]
        for operation in intent.operations {
            result.insert(operation.after.device)
            if let before = operation.before { result.insert(before.device) }
        }
        return result
    }
    static func qualified(supplement: Data, legacy: InstallationRootBinding.Legacy,
                          current: [String: InstallationRootBinding.CurrentRoot],
                          source: ComponentSource, intent: ComponentTransitionIntent) throws -> CompletedComponentVolumeBinding {
        let root = try InstallationRootBinding.componentVolume(supplement, legacy: legacy, current: current,
            planSHA256: source.planDigest, workerSHA256: intent.workerPolicy.sha256, serviceSHA256: intent.servicePlist.sha256)
        let previous = intent.workerPolicy.device
        guard previous >= 0, previous != root.device, devices(intent) == [previous] else {
            throw ComponentUpdateFailure.journal
        }
        return CompletedComponentVolumeBinding(previous: previous, current: root.device,
            volumeUUID: root.volumeUUID, supplementSHA256: ComponentFiles.digest(supplement))
    }
    func validate(intent: ComponentTransitionIntent, snapshot: CompletedComponentSnapshot) throws {
        let objects = Array(snapshot.original.values) + Array(snapshot.records.values)
            + [snapshot.head, snapshot.worker, snapshot.service]
        guard Self.devices(intent) == [previousDevice],
              snapshot.roots.values.allSatisfy({ $0.device == currentDevice }),
              objects.allSatisfy({ $0.object.device == currentDevice }) else { throw ComponentUpdateFailure.journal }
    }
    func matches(recorded: ComponentObject, observed: ComponentObject) -> Bool {
        guard recorded.device == previousDevice, observed.device == currentDevice else { return false }
        // Translate only the transient device number, never an inode, mode,
        // byte count or content digest. Original receipts are never rewritten.
        return observed == ComponentObject(device: currentDevice, inode: recorded.inode,
            mode: recorded.mode, bytes: recorded.bytes, sha256: recorded.sha256)
    }
}
struct CompletedComponentSnapshot {
    let ownerUID: uid_t
    let ownerGroup: gid_t
    let roots: [String: CompletedComponentDirectory]
    let namespaceNames: [String]
    let original: [String: CompletedComponentRecord]
    let rootBindingSHA256: String
    let records: [String: CompletedComponentRecord]
    let head: CompletedComponentRecord
    let worker: CompletedComponentRecord
    let service: CompletedComponentRecord
    var volumeBinding: CompletedComponentVolumeBinding? = nil
    // Present only after the existing root-volume receipt qualifies the exact
    // component plan, worker/service hashes, volume UUID and unchanged roots.
    var historicalBinding: CompletedComponentHistoricalBinding? = nil
}
struct CompletedComponentHistoricalBinding {
    let currentDevice: Int32
    private let componentDevice: Int32
    private let volumeUUID: String, supplementSHA256: String
    private let binding: [String: Any]
    private init(currentDevice: Int32, componentDevice: Int32, volumeUUID: String,
                 supplementSHA256: String, binding: [String: Any]) {
        self.currentDevice = currentDevice; self.componentDevice = componentDevice
        self.volumeUUID = volumeUUID; self.supplementSHA256 = supplementSHA256; self.binding = binding
    }
    static func qualified(supplement: Data, legacy: InstallationRootBinding.Legacy,
                          current: [String: InstallationRootBinding.CurrentRoot],
                          source: ComponentSource, intent: ComponentTransitionIntent) throws -> Self {
        let root = try InstallationRootBinding.componentVolume(supplement, legacy: legacy, current: current,
            planSHA256: source.planDigest, workerSHA256: intent.workerPolicy.sha256, serviceSHA256: intent.servicePlist.sha256)
        let digest = ComponentFiles.digest(supplement)
        let roots = current.mapValues { ["inode": $0.inode, "volume_uuid": $0.volumeUUID] as [String: Any] }
        return Self(currentDevice: root.device, componentDevice: intent.workerPolicy.device,
            volumeUUID: root.volumeUUID, supplementSHA256: digest,
            binding: ["receipts": legacy.hashes, "roots": roots, "supplement_sha256": digest])
    }
    func hash(at device: Int32) throws -> String {
        guard device >= 0 else { throw ComponentUpdateFailure.journal }
        var value = binding
        if device != componentDevice {
            value["component_device_binding"] = ["previous_device": componentDevice,
                "current_device": device, "volume_uuid": volumeUUID,
                "supplement_sha256": supplementSHA256] as [String: Any]
        }
        return ComponentFiles.digest(try JSONSerialization.data(withJSONObject: value,
            options: [.sortedKeys, .withoutEscapingSlashes]))
    }
}
struct CompletedComponentProof {
    let evidence: Data
    let sha256: String
    fileprivate init(_ evidence: Data) { self.evidence = evidence; sha256 = ComponentFiles.digest(evidence) }
}

extension ComponentController {
    private struct CompletedEvidence: Codable {
        let schema: Int
        let managedBy: String
        let planSHA256: String
        let baseManifestSHA256: String
        let targetManifestSHA256: String
        let ownerUID: UInt32
        let ownerGroup: UInt32
        let brokerUID: UInt32
        let roots: [String: CompletedComponentDirectory]
        let namespaceNames: [String]
        let originalReceipts: [String: ComponentObject]
        let rootBindingSHA256: String
        let records: [String: ComponentObject]
        let head: ComponentObject
        let worker: ComponentObject
        let service: ComponentObject
    }
    private static func completedStrictJSON(_ data: Data, maximum: Int) throws -> [String: Any] {
        let value = try json(data, maximum: maximum)
        guard !data.contains(0) else { throw ComponentUpdateFailure.journal }
        // Same bounded nested duplicate scanner as InstallationRootBinding.
        let bytes = [UInt8](data)
        var stack: [(object: Bool, keys: Set<String>, key: Bool)] = [], cursor = 0
        while cursor < bytes.count {
            switch bytes[cursor] {
            case 34:
                let start = cursor; cursor += 1
                while cursor < bytes.count && bytes[cursor] != 34 { cursor += bytes[cursor] == 92 ? 2 : 1 }
                guard cursor < bytes.count else { throw ComponentUpdateFailure.journal }; cursor += 1
                if let last = stack.indices.last, stack[last].object && stack[last].key {
                    var token = Data([91]); token.append(contentsOf: bytes[start..<cursor]); token.append(93)
                    guard let key = try JSONSerialization.jsonObject(with: token) as? [String], key.count == 1,
                          stack[last].keys.insert(key[0]).inserted else { throw ComponentUpdateFailure.journal }
                    stack[last].key = false
                }
                continue
            case 123, 91:
                guard stack.count < 16 else { throw ComponentUpdateFailure.journal }
                stack.append((bytes[cursor] == 123, [], bytes[cursor] == 123))
            case 125, 93:
                guard !stack.isEmpty else { throw ComponentUpdateFailure.journal }; stack.removeLast()
            case 44:
                if let last = stack.indices.last, stack[last].object { stack[last].key = true }
            default: break
            }
            cursor += 1
        }
        guard stack.isEmpty else { throw ComponentUpdateFailure.journal }; return value
    }
    private static func completedRecord(_ record: CompletedComponentRecord, mode: mode_t, maximum: Int) throws {
        try object(record.object, mode: mode, hash: ComponentFiles.digest(record.data), size: Int64(record.data.count))
        guard record.data.count <= maximum else { throw ComponentUpdateFailure.journal }
    }
    private static func completedObjectMatches(_ observed: ComponentObject, _ recorded: ComponentObject,
                                               snapshot: CompletedComponentSnapshot) -> Bool {
        observed == recorded || snapshot.volumeBinding?.matches(recorded: recorded, observed: observed) == true
    }
    private static func completedValidated(_ source: ComponentSource, _ snapshot: CompletedComponentSnapshot) throws -> (ComponentTransitionIntent, Data) {
        var checkpoint: CompletedPredecessorCheckpoint = .structure
        do {
            guard source.oldPeers["owner"]?.team == "WBULD6N4NQ", source.newPeers["owner"] == source.oldPeers["owner"],
                  source.planDigest.utf8.count == 64, source.planDigest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  source.delta.count == 9, Set(source.delta.map(\.path)) == ComponentSource.allowed,
                  source.delta.map(\.path) == ComponentSource.allowed.sorted(),
                  snapshot.ownerUID > 0, Set(snapshot.roots.keys) == ["original", "components", "transition"],
                  snapshot.roots.values.allSatisfy({ $0.owner == 0 && $0.mode == 0o700 && $0.inode > 0 && $0.device >= 0 }),
                  Set(snapshot.roots.values.map(\.device)).count == 1,
                  Set(snapshot.roots.values.map(\.inode)).count == 3,
                  snapshot.rootBindingSHA256.utf8.count == 64,
                  snapshot.rootBindingSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  snapshot.namespaceNames == Array(Set(snapshot.namespaceNames)).sorted(),
                  snapshot.namespaceNames.contains("head.json"),
                  snapshot.namespaceNames.contains("transition-" + source.planDigest),
                  Set(snapshot.original.keys) == Set(InstallationRootBinding.receiptNames),
                  let savedIntent = snapshot.records["intent.json"], snapshot.records.count <= 2048 else { throw ComponentUpdateFailure.journal }
            checkpoint = .preparations
            let preparationPrefix = ".preparing-" + source.planDigest + "-"
            let preparations = snapshot.namespaceNames.filter { $0 != "head.json" && $0 != "transition-" + source.planDigest }
            guard preparations.count <= 8, preparations.allSatisfy({ name in
                guard name.hasPrefix(preparationPrefix), let uuid = UUID(uuidString: String(name.dropFirst(preparationPrefix.count))) else { return false }
                return uuid.uuidString.lowercased() == String(name.dropFirst(preparationPrefix.count))
            }) else { throw ComponentUpdateFailure.journal }
            checkpoint = .recordBounds
            var bytes: Int64 = 0
            for record in snapshot.records.values {
                let sum = bytes.addingReportingOverflow(Int64(record.data.count)); guard !sum.overflow, sum.partialValue <= ComponentPreparation.byteLimit else { throw ComponentUpdateFailure.journal }
                bytes = sum.partialValue
            }
            checkpoint = .originalReceipts
            for record in snapshot.original.values { try completedRecord(record, mode: 0o600, maximum: 8192) }
            _ = try InstallationRootBinding.parseLegacy(records: snapshot.original.mapValues(\.data), ownerUID: snapshot.ownerUID, manifestSHA256: source.oldManifest.sha256)
            checkpoint = .intentEncoding
            try completedRecord(savedIntent, mode: 0o600, maximum: 64 * 1024)
            let value = try completedStrictJSON(savedIntent.data, maximum: 64 * 1024)
            let intent = try JSONDecoder().decode(ComponentTransitionIntent.self, from: savedIntent.data)
            guard NSDictionary(dictionary: value).isEqual(to: try json(encoded(intent), maximum: 64 * 1024)) else { throw ComponentUpdateFailure.journal }
            let ownerUID = snapshot.ownerUID
            try completedRecord(snapshot.worker, mode: 0o644, maximum: 4096)
            try completedRecord(snapshot.service, mode: 0o644, maximum: 8192)
            checkpoint = .intentContract
            guard intent.schema == 1, intent.planSHA256 == source.planDigest,
                  intent.baseManifestSHA256 == source.oldManifest.sha256, intent.targetManifestSHA256 == source.newManifest.sha256,
                  !intent.automaticRebootRecovery, intent.ownerUID == ownerUID,
                  intent.operations.count == source.delta.count + dynamic.count else {
                throw ComponentUpdateFailure.journal
            }
            checkpoint = .workerBinding
            try snapshot.volumeBinding?.validate(intent: intent, snapshot: snapshot)
            guard completedObjectMatches(snapshot.worker.object, intent.workerPolicy, snapshot: snapshot) else { throw ComponentUpdateFailure.journal }
            checkpoint = .serviceBinding
            guard completedObjectMatches(snapshot.service.object, intent.servicePlist, snapshot: snapshot) else { throw ComponentUpdateFailure.journal }
            checkpoint = .intentContract
            guard ownerUID > 0, ownerUID != intent.brokerUID, (450..<500).contains(intent.brokerUID) else { throw ComponentUpdateFailure.base }
            if let snapshot = intent.service { try ComponentUpdateIdentity.validateSnapshot(snapshot) }
            checkpoint = .operations
            var device: Int32?
            for (index, operation) in intent.operations.enumerated() {
                guard operation.slot == String(format: "slot-%02d", index) else { throw ComponentUpdateFailure.journal }
                if index < source.delta.count {
                    let delta = source.delta[index]
                    guard operation.target == .image, operation.path == delta.path,
                          (operation.before == nil) == (delta.before == nil) else { throw ComponentUpdateFailure.journal }
                    try object(operation.after, mode: delta.after.mode!, hash: delta.after.sha256, size: delta.after.size)
                    if let before = operation.before, let node = delta.before {
                        try object(before, mode: node.mode!, hash: node.sha256, size: node.size)
                    }
                } else {
                    let entry = dynamic[index - source.delta.count]
                    guard operation.target == entry.0, operation.path == entry.1,
                          (operation.before == nil) == (entry.0 == .head) else { throw ComponentUpdateFailure.journal }
                    try object(operation.after, mode: entry.2, hash: nil, size: nil)
                    if let before = operation.before { try object(before, mode: entry.2, hash: nil, size: nil) }
                }
                if device == nil { device = operation.after.device }
                guard operation.after.device == device, operation.before == nil || operation.before?.device == device else {
                    throw ComponentUpdateFailure.journal
                }
            }

            checkpoint = .head
            guard let headOp = intent.operations.last, headOp.target == .head,
                  completedObjectMatches(snapshot.head.object, headOp.after, snapshot: snapshot),
                  snapshot.head.data == (try head(source)) else { throw ComponentUpdateFailure.journal }
            try completedRecord(snapshot.head, mode: 0o644, maximum: 4096)
            checkpoint = .journal
            let state = try completedJournal(snapshot, operations: intent.operations, source: source, intentExists: true)
            guard state.finished, !state.ownsDisable else { throw ComponentUpdateFailure.journal }
            checkpoint = .retainedSlots
            for operation in intent.operations {
                if let before = operation.before {
                    guard let slot = snapshot.records[operation.slot],
                          completedObjectMatches(slot.object, before, snapshot: snapshot) else { throw ComponentUpdateFailure.journal }
                    try completedRecord(slot, mode: mode_t(before.mode), maximum: ComponentFiles.maximumFile)
                } else { guard snapshot.records[operation.slot] == nil else { throw ComponentUpdateFailure.journal } }
            }
            checkpoint = .audits
            for (name, record) in snapshot.records where name != "intent.json" && !intent.operations.contains(where: { $0.slot == name }) {
                try completedRecord(record, mode: 0o600, maximum: 4096)
                // Complete JSON audits receive the same checks as legacy recovery;
                // incomplete audit bytes are immutable evidence, never authority.
                if (try? JSONSerialization.jsonObject(with: record.data, options: [.fragmentsAllowed])) != nil {
                    let audit = try completedStrictJSON(record.data, maximum: 4096)
                    if name.hasPrefix("event-") {
                        let allowed: Set<String> = ["apply_intent", "applied", "rollback_intent", "rolled_back", "rollback_conflict", "old_image_restored", "new_image_verified_gui_unverified"]
                        guard Set(audit.keys) == ["schema", "event", "operation"],
                              try InstallerPayloadManifest.integer(audit["schema"], maximum: 1) == 1,
                              let event = audit["event"] as? String, allowed.contains(event),
                              let number = audit["operation"] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                              number.doubleValue.isFinite, number.doubleValue == Double(number.int64Value) else { throw ComponentUpdateFailure.journal }
                        let global = event == "old_image_restored" || event == "new_image_verified_gui_unverified"
                        guard (global ? number.int64Value == -1 : (number.int64Value >= 0 && number.int64Value < Int64(intent.operations.count))) else {
                            throw ComponentUpdateFailure.journal
                        }
                    }
                }
            }
            checkpoint = .policyDerivation
            let hostOp = intent.operations[source.delta.count], ownerOp = intent.operations[source.delta.count + 1], installOp = intent.operations[source.delta.count + 2]
            let policy = try ComponentUpdatePolicies.derive(install: snapshot.records[installOp.slot]!.data,
                host: snapshot.records[hostOp.slot]!.data, owner: snapshot.records[ownerOp.slot]!.data, worker: snapshot.worker.data,
                oldPeers: source.oldPeers, newPeers: source.newPeers, oldFingerprint: source.oldFingerprint,
                newFingerprint: source.newFingerprint, consoleOwner: ownerUID)
            guard policy.brokerUID == intent.brokerUID else { throw ComponentUpdateFailure.journal }
            checkpoint = .dynamicBytes
            let expectedDynamic = try [policy.host, policy.owner, policy.install, head(source)]
            for (index, data) in expectedDynamic.enumerated() {
                let operation = intent.operations[source.delta.count + index]
                guard operation.after.sha256 == ComponentFiles.digest(data), operation.after.bytes == data.count else { throw ComponentUpdateFailure.journal }
            }
            checkpoint = .evidence
            let evidence = CompletedEvidence(schema: 1, managedBy: "account-access-completed-component-predecessor-v1",
                planSHA256: source.planDigest, baseManifestSHA256: source.oldManifest.sha256, targetManifestSHA256: source.newManifest.sha256,
                ownerUID: snapshot.ownerUID, ownerGroup: snapshot.ownerGroup, brokerUID: intent.brokerUID,
                roots: snapshot.roots, namespaceNames: snapshot.namespaceNames, originalReceipts: snapshot.original.mapValues(\.object),
                rootBindingSHA256: snapshot.rootBindingSHA256, records: snapshot.records.mapValues(\.object), head: snapshot.head.object,
                worker: snapshot.worker.object, service: snapshot.service.object)
            return (intent, try encoded(evidence))
        } catch let diagnostic as CompletedPredecessorDiagnostic { throw diagnostic }
        catch { throw CompletedPredecessorDiagnostic(checkpoint: checkpoint, failure: error) }
    }
    private static func completedProof(source: ComponentSource, read: () throws -> CompletedComponentSnapshot,
        verifyInitial: (CompletedComponentSnapshot, ComponentTransitionIntent) throws -> Void, expectedEvidence: Data?,
        expectedEvidenceSHA256: String? = nil, recordedDevice: Int32? = nil) throws -> CompletedComponentProof {
        guard expectedEvidence == nil || expectedEvidenceSHA256 == nil else { throw ComponentUpdateFailure.journal }
        guard recordedDevice == nil || (expectedEvidence == nil && expectedEvidenceSHA256 != nil) else {
            throw ComponentUpdateFailure.journal
        }
        if let expectedEvidenceSHA256 {
            guard expectedEvidenceSHA256.utf8.count == 64,
                  expectedEvidenceSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw ComponentUpdateFailure.journal }
        }
        let before = try CompletedPredecessorDiagnostic.checked(.snapshotBefore, read)
        let validated = try completedValidated(source, before)
        if expectedEvidence == nil && expectedEvidenceSHA256 == nil { try verifyInitial(before, validated.0) }
        let after = try CompletedPredecessorDiagnostic.checked(.snapshotAfter, read)
        let revalidated = try completedValidated(source, after)
        try CompletedPredecessorDiagnostic.checked(.evidenceStability) {
            guard revalidated.1 == validated.1 else { throw ComponentUpdateFailure.journal }
        }
        // A completed full-image intent binds evidence from the previous mount.
        // Reconstruct those exact bytes only after two complete current-volume
        // validations. No record is rewritten and no inode/hash/mode is relaxed.
        let evidence = try historicalCompletedEvidence(validated.1, snapshot: before, recordedDevice: recordedDevice)
        let repeated = try historicalCompletedEvidence(revalidated.1, snapshot: after, recordedDevice: recordedDevice)
        try CompletedPredecessorDiagnostic.checked(.expectedEvidence) {
            guard evidence == repeated else { throw ComponentUpdateFailure.journal }
            if let expectedEvidence { guard expectedEvidence == evidence else { throw ComponentUpdateFailure.journal } }
            if let expectedEvidenceSHA256 { guard ComponentFiles.digest(evidence) == expectedEvidenceSHA256 else { throw ComponentUpdateFailure.journal } }
        }
        return CompletedComponentProof(evidence)
    }
    private static func historicalCompletedEvidence(_ evidence: Data, snapshot: CompletedComponentSnapshot,
                                                     recordedDevice: Int32?) throws -> Data {
        guard let device = recordedDevice, device != snapshot.worker.object.device else { return evidence }
        guard device >= 0, let binding = snapshot.historicalBinding,
              binding.currentDevice == snapshot.worker.object.device,
              try binding.hash(at: binding.currentDevice) == snapshot.rootBindingSHA256 else {
            throw ComponentUpdateFailure.journal
        }
        let value = try JSONDecoder().decode(CompletedEvidence.self, from: evidence)
        func object(_ old: ComponentObject) throws -> ComponentObject {
            guard old.device == binding.currentDevice else { throw ComponentUpdateFailure.journal }
            return ComponentObject(device: device, inode: old.inode, mode: old.mode, bytes: old.bytes, sha256: old.sha256)
        }
        let roots = try value.roots.mapValues { old -> CompletedComponentDirectory in
            guard old.device == binding.currentDevice else { throw ComponentUpdateFailure.journal }
            return CompletedComponentDirectory(device: device, inode: old.inode, owner: old.owner, group: old.group, mode: old.mode)
        }
        return try encoded(CompletedEvidence(schema: value.schema, managedBy: value.managedBy,
            planSHA256: value.planSHA256, baseManifestSHA256: value.baseManifestSHA256,
            targetManifestSHA256: value.targetManifestSHA256, ownerUID: value.ownerUID,
            ownerGroup: value.ownerGroup, brokerUID: value.brokerUID, roots: roots,
            namespaceNames: value.namespaceNames, originalReceipts: value.originalReceipts.mapValues(object),
            rootBindingSHA256: binding.hash(at: device), records: value.records.mapValues(object),
            head: object(value.head), worker: object(value.worker), service: object(value.service)))
    }
    private static func completedJournal(_ snapshot: CompletedComponentSnapshot, operations: [ComponentOperation], source: ComponentSource,
                                     intentExists: Bool) throws -> JournalState {
        var nextEvent = 0, nextService = 0, nextJob = 0, service: [(Int, String)] = []
        var snapshots: [ComponentJobIdentity] = []
        let slots = Set(operations.map(\.slot))
        for name in snapshot.records.keys {
            if name == "intent.json" { guard intentExists else { throw ComponentUpdateFailure.journal }; continue }
            if slots.contains(name) { continue }
            let isService = name.hasPrefix("service-"), isJob = name.hasPrefix("job-")
            let prefix = isJob ? "job-" : isService ? "service-" : "event-"
            guard name.hasPrefix(prefix), name.hasSuffix(".json"),
                  name.utf8.count == prefix.utf8.count + 4 + 5,
                  let sequence = Int(name.dropFirst(prefix.count).dropLast(5)), sequence >= 0, sequence < 10_000,
                  name == String(format: prefix + "%04d.json", sequence), intentExists else { throw ComponentUpdateFailure.journal }
            let data = snapshot.records[name]!.data
            guard data.count <= 4096 else { throw ComponentUpdateFailure.journal }
            if isJob {
                nextJob = max(nextJob, sequence + 1)
                if let parsed = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
                    guard let value = parsed as? [String: Any],
                          let record = try? JSONDecoder().decode(JobRecord.self, from: data), record.schema == 1,
                          record.planSHA256 == source.planDigest,
                          NSDictionary(dictionary: value).isEqual(to: try json(encoded(record), maximum: 4096)) else {
                        throw ComponentUpdateFailure.journal
                    }
                    try ComponentUpdateIdentity.validateSnapshot(record.job)
                    snapshots.append(record.job)
                }
            } else if isService {
                nextService = max(nextService, sequence + 1)
                // Only incomplete/unparseable bounded audit writes lack
                // authority. A complete foreign record is a conflict.
                if let parsed = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
                    guard let value = parsed as? [String: Any],
                          Set(value.keys) == ["schema", "event", "plan_sha256"],
                          (try? InstallerPayloadManifest.integer(value["schema"], maximum: 1)) == 1,
                          value["plan_sha256"] as? String == source.planDigest,
                          let event = value["event"] as? String, serviceEvents.contains(event) else {
                        throw ComponentUpdateFailure.journal
                    }
                    service.append((sequence, event))
                }
            } else { nextEvent = max(nextEvent, sequence + 1) }
        }
        let ordered = service.sorted { $0.0 < $1.0 }.map(\.1)
        let finished = ordered.last == "canonical_job_bootstrapped_gui_unverified"
        let ownsDisable = !finished && ordered.contains("disable_intent_prior_enabled")
        return JournalState(nextEvent: nextEvent, nextService: nextService, nextJob: nextJob, snapshots: snapshots, ownsDisable: ownsDisable, finished: finished)
    }
    private static func completedDirectory(_ fd: Int32) throws -> CompletedComponentDirectory {
        let info = try InstallerPayloadIO.check(fd, owner: 0, directory: true)
        // The original component installer allowed mkdir's inherited group.
        // Root ownership, 0700 and the existing ACL check protect the directory;
        // its actual group remains part of the immutable evidence on every read.
        guard info.st_mode & 0o7777 == 0o700, info.st_nlink > 0 else { throw ComponentUpdateFailure.journal }
        return CompletedComponentDirectory(device: info.st_dev, inode: UInt64(info.st_ino), owner: info.st_uid, group: info.st_gid, mode: UInt16(info.st_mode & 0o7777))
    }
    private static func completedServiceRecord(support: CompletedComponentRecord, validatedGlobal: CompletedComponentRecord) throws -> CompletedComponentRecord {
        try completedRecord(support, mode: 0o644, maximum: 8192)
        try completedRecord(validatedGlobal, mode: 0o644, maximum: 8192)
        guard support.data == validatedGlobal.data else { throw ComponentUpdateFailure.base }
        // The immutable component intent binds the GLOBAL LaunchDaemons inode,
        // not the separate equal-byte support copy. Both reads stay validated.
        return validatedGlobal
    }
    private static func completedNativeSnapshot(_ source: ComponentSource) throws -> CompletedComponentSnapshot {
        var checkpoint: CompletedPredecessorCheckpoint = .snapshotRoots
        do {
            let (ownerUID, ownerGroup) = try owner()
            let original = try directory(oldJournal, mode: 0o700)
            defer { Darwin.close(original) }
            let components = try directory(namespace, mode: 0o700)
            defer { Darwin.close(components) }
            let transition = try child(components, "transition-" + source.planDigest, create: false)
            defer { Darwin.close(transition) }
            checkpoint = .rootBinding
            try originalReceipt(original, ownerUID: ownerUID)
            let legacy = try InstallationRootBinding.readLegacy(original, ownerUID: ownerUID, manifestSHA256: source.oldManifest.sha256)
            let current = try InstallationRootBinding.capture(withVolumeUUID: true)
            var supplementHash: String? = nil
            var supplementData: Data? = nil
            if try InstallationRootBinding.hasSupplementNamespace() {
                let directory = try InstallationRootBinding.receiptDirectory(create: false); defer { Darwin.close(directory) }
                let proof = try InstallationRootBinding.readSupplement(directory)
                try InstallationRootBinding.validateSupplement(proof, legacy: legacy, current: current)
                supplementHash = ComponentFiles.digest(proof)
                supplementData = proof
            } else { guard try InstallationRootBinding.exactLegacy(legacy, current: current) else { throw ComponentUpdateFailure.base } }
            let rootBindings: [String: [String: Any]] = current.mapValues { ["inode": $0.inode, "volume_uuid": $0.volumeUUID] }
            var binding: [String: Any] = ["receipts": legacy.hashes, "roots": rootBindings]
            binding["supplement_sha256"] = supplementHash.map { $0 as Any } ?? NSNull()
            checkpoint = .retainedNamespace
            var modes: [String: mode_t] = [:]
            for (i, delta) in source.delta.enumerated() { modes[String(format: "slot-%02d", i)] = delta.after.mode! }
            for (i, entry) in dynamic.enumerated() { modes[String(format: "slot-%02d", source.delta.count + i)] = entry.2 }
            _ = try ComponentPreparation.retained(components, plan: source.planDigest, slots: modes, owner: 0)
            func record(_ fd: Int32, _ name: String, _ mode: mode_t) throws -> CompletedComponentRecord {
                let read = try ComponentFiles.read(fd, name, owner: 0, mode: mode); return CompletedComponentRecord(data: read.0, object: read.1)
            }
            checkpoint = .retainedRecords
            var originals: [String: CompletedComponentRecord] = [:], records: [String: CompletedComponentRecord] = [:]
            for name in InstallationRootBinding.receiptNames { originals[name] = try record(original, name, 0o600) }
            let names = try InstallerPayloadIO.contents(transition); guard names.count <= 2048 else { throw ComponentUpdateFailure.journal }
            for name in names { records[name] = try record(transition, name, modes[name] ?? 0o600) }
            checkpoint = .currentPolicies
            let workerRead = try publicRead("broker/worker.json", mode: 0o644), serviceRead = try publicRead("broker/service.plist", mode: 0o644)
            let globalPlist = try jobPlist(ownerGroup: ownerGroup) // Validates global typed bytes and equality to the support copy.
            let service = try completedServiceRecord(support: CompletedComponentRecord(data: serviceRead.0, object: serviceRead.1),
                validatedGlobal: CompletedComponentRecord(data: serviceRead.0, object: globalPlist))
            checkpoint = .currentIntent
            let intent = try loadIntent(transition); try identity(ownerUID, intent.brokerUID)
            let roots = try ["original": completedDirectory(original), "components": completedDirectory(components), "transition": completedDirectory(transition)]
            var volumeBinding: CompletedComponentVolumeBinding? = nil
            let historicalBinding = try supplementData.map {
                try CompletedComponentHistoricalBinding.qualified(supplement: $0, legacy: legacy,
                    current: current, source: source, intent: intent)
            }
            if intent.workerPolicy.device != current[InstallerPayloadManifest.support]?.device, let proof = supplementData {
                checkpoint = .rootBinding
                volumeBinding = try CompletedComponentVolumeBinding.qualified(supplement: proof, legacy: legacy,
                    current: current, source: source, intent: intent)
                binding["component_device_binding"] = ["previous_device": volumeBinding!.previousDevice,
                    "current_device": volumeBinding!.currentDevice, "volume_uuid": volumeBinding!.volumeUUID,
                    "supplement_sha256": volumeBinding!.supplementSHA256] as [String: Any]
            }
            return CompletedComponentSnapshot(ownerUID: ownerUID, ownerGroup: ownerGroup, roots: roots,
                namespaceNames: try InstallerPayloadIO.contents(components).sorted(), original: originals,
                rootBindingSHA256: ComponentFiles.digest(try JSONSerialization.data(withJSONObject: binding, options: [.sortedKeys, .withoutEscapingSlashes])),
                records: records, head: try record(components, "head.json", 0o644),
                worker: CompletedComponentRecord(data: workerRead.0, object: workerRead.1), service: service,
                volumeBinding: volumeBinding, historicalBinding: historicalBinding)
        } catch let diagnostic as CompletedPredecessorDiagnostic { throw diagnostic }
        catch { throw CompletedPredecessorDiagnostic(checkpoint: checkpoint, failure: error) }
    }
    private static func completedInitialFiles(_ snapshot: CompletedComponentSnapshot, _ intent: ComponentTransitionIntent,
        observe: (ComponentOperation) throws -> ComponentObject?, verifyPublicImage: () throws -> Void) throws {
        var checkpoint: CompletedPredecessorCheckpoint = .currentImage
        do {
            for operation in intent.operations {
                switch operation.target {
                case .image: checkpoint = .currentImage
                case .hostPolicy: checkpoint = .currentHostPolicy
                case .ownerPolicy: checkpoint = .currentOwnerPolicy
                case .installRecord: checkpoint = .currentInstallRecord
                case .head: checkpoint = .currentHead
                }
                guard let observed = try observe(operation),
                      completedObjectMatches(observed, operation.after, snapshot: snapshot) else { throw ComponentUpdateFailure.journal }
            }
            checkpoint = .publicView
            try verifyPublicImage()
            // Preserve assertView's second dynamic-policy observation after the
            // public image scan, using the same qualified volume comparison.
            for operation in intent.operations where operation.target != .image && operation.target != .head {
                guard let observed = try observe(operation),
                      completedObjectMatches(observed, operation.after, snapshot: snapshot) else { throw ComponentUpdateFailure.object }
            }
        } catch let diagnostic as CompletedPredecessorDiagnostic { throw diagnostic }
        catch { throw CompletedPredecessorDiagnostic(checkpoint: checkpoint, failure: error) }
    }
    private static func completedInitialCurrent(_ source: ComponentSource, _ snapshot: CompletedComponentSnapshot, _ intent: ComponentTransitionIntent) throws {
        var checkpoint: CompletedPredecessorCheckpoint = .currentImage
        do {
            try completedInitialFiles(snapshot, intent, observe: { operation in
                let (parent, name) = try target(operation); defer { Darwin.close(parent) }
                return try ComponentFiles.observe(parent, name, owner: 0)
            }, verifyPublicImage: {
                _ = try InstallerPayloadIO.installedImage(source.newManifest, opaquePrivateBranches: true)
            })
            checkpoint = .signatures
            for kind in ["owner", "broker", "bootstrap"] {
                guard let peer = source.newPeers[kind] else { throw ComponentUpdateFailure.source }
                let path = kind == "owner" ? ComponentSource.support + "/owner.app" : ComponentSource.support + "/bin/AccountAccess-" + kind
                try ComponentUpdateIdentity.verifyStatic(path: path, peer: peer, designated: source.designated[kind])
            }
            checkpoint = .service
            let observed = try ComponentCommands.launchctl(["print", "system/" + label])
            guard observed.status == 0 else { throw ComponentUpdateFailure.base }
            // A canonical KeepAlive=false job may be idle with no PID. Attest any
            // present process; static broker/image signatures remain mandatory.
            _ = try ComponentUpdateIdentity.jobSnapshot(output: observed.output, allowedPeers: [source.newPeers["broker"]!])
        } catch let diagnostic as CompletedPredecessorDiagnostic { throw diagnostic }
        catch { throw CompletedPredecessorDiagnostic(checkpoint: checkpoint, failure: error) }
    }
    static func initialCompletedPredecessor(resources: Int32, planPin: String) throws -> CompletedComponentProof {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        let source = try ComponentSource.load(resources, planPin: planPin)
        return try completedProof(source: source, read: { try completedNativeSnapshot(source) },
            verifyInitial: { try completedInitialCurrent(source, $0, $1) }, expectedEvidence: nil)
    }
    static func revalidateCompletedPredecessor(resources: Int32, planPin: String, expectedEvidence: Data) throws -> CompletedComponentProof {
        guard getuid() == 0, geteuid() == 0, !expectedEvidence.isEmpty, expectedEvidence.count <= 1024 * 1024 else { throw ComponentUpdateFailure.context }
        let source = try ComponentSource.load(resources, planPin: planPin)
        return try completedProof(source: source, read: { try completedNativeSnapshot(source) }, verifyInitial: { _, _ in
            throw ComponentUpdateFailure.context // Recovery must never inspect a mixed current image here.
        }, expectedEvidence: expectedEvidence)
    }
    static func revalidateCompletedPredecessor(resources: Int32, planPin: String, expectedEvidenceSHA256: String,
                                               recordedDevice: Int32? = nil) throws -> CompletedComponentProof {
        guard getuid() == 0, geteuid() == 0, expectedEvidenceSHA256.utf8.count == 64,
              expectedEvidenceSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw ComponentUpdateFailure.context }
        let source = try ComponentSource.load(resources, planPin: planPin)
        // Expected SHA must come from the independently qualified protected
        // full-image intent; the same full immutable evidence is still checked.
        return try completedProof(source: source, read: { try completedNativeSnapshot(source) }, verifyInitial: { _, _ in
            throw ComponentUpdateFailure.context
        }, expectedEvidence: nil, expectedEvidenceSHA256: expectedEvidenceSHA256, recordedDevice: recordedDevice)
    }
#if ACCOUNT_ACCESS_COMPONENT_PREDECESSOR_CHECKS
    static func fixtureCompletedInitialFiles(_ snapshot: CompletedComponentSnapshot, _ intent: ComponentTransitionIntent,
        observe: (ComponentOperation) throws -> ComponentObject?, verifyPublicImage: () throws -> Void) throws {
        try completedInitialFiles(snapshot, intent, observe: observe, verifyPublicImage: verifyPublicImage)
    }
    static func fixtureCompletedServiceRecord(support: CompletedComponentRecord, validatedGlobal: CompletedComponentRecord) throws -> CompletedComponentRecord {
        try completedServiceRecord(support: support, validatedGlobal: validatedGlobal)
    }
    static func fixtureCompletedPredecessor(source: ComponentSource, read: () throws -> CompletedComponentSnapshot,
        verifyInitial: (CompletedComponentSnapshot, ComponentTransitionIntent) throws -> Void, expectedEvidence: Data? = nil,
        expectedEvidenceSHA256: String? = nil, recordedDevice: Int32? = nil) throws -> CompletedComponentProof {
        try completedProof(source: source, read: read, verifyInitial: verifyInitial, expectedEvidence: expectedEvidence,
            expectedEvidenceSHA256: expectedEvidenceSHA256, recordedDevice: recordedDevice)
    }
#endif
}
