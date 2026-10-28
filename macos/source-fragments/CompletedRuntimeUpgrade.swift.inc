// Completed-runtime qualification for one fixed owner-app successor. Composed
// with the existing controller. No CLI, arbitrary paths or service mutations.
struct CompletedRuntimeUpgradeProof {
    let evidence: Data
    var sha256: String { FullImageJSON.hash(evidence) }
    let ownerUID: uid_t, brokerUID: uid_t
    let workerPolicy: ComponentObject, servicePlist: ComponentObject
    private let historyCheck: () throws -> Void
    fileprivate init(evidence: Data, ownerUID: uid_t, brokerUID: uid_t,
                     worker: ComponentObject, service: ComponentObject, historyCheck: @escaping () throws -> Void) {
        self.evidence = evidence; self.ownerUID = ownerUID; self.brokerUID = brokerUID
        workerPolicy = worker; servicePlist = service
        self.historyCheck = historyCheck
    }
    func revalidateHistory() throws { try historyCheck() }
}

// Only the fixed successor adapter constructs this projection from its typed
// original-object storage and verifies the complete current public view.
private struct RuntimeSuccessorProjection {
    let verifyPublic: () throws -> Void
    let file: (FullImageFileUnit) throws -> (Data, ComponentObject)
    let ownerTree: () throws -> PublicTreePin?
}

private final class RuntimeVerificationDescriptor {
    let fd: Int32
    init(_ supplied: Int32) throws {
        fd = fcntl(supplied, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw FullImageFailure.object }
    }
    deinit { Darwin.close(fd) }
}

extension ComponentController {
    static func completedRuntimeUpgrade(resources: Int32, pins: RuntimeUpgradeSource.Pins,
            repairPins: BrokerRepairSource.Pins, predecessorPins: FullImageSourcePins) throws -> CompletedRuntimeUpgradeProof {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        let original = try directory(oldJournal, mode: 0o700); defer { Darwin.close(original) }
        let originalLease = try lease(original, "lock"); defer { Darwin.close(originalLease) }
        let broker = try InstallerPayloadIO.directory(ComponentSource.support + "/broker", owner: 0)
        defer { Darwin.close(broker) }
        let provisionLease = try lease(broker, "install.lock"); defer { Darwin.close(provisionLease) }
        return try completedRuntimeUpgradeLocked(resources: resources, pins: pins,
            repairPins: repairPins, predecessorPins: predecessorPins)
    }

    // The fixed successor already holds both maintenance leases. A projection
    // can only revalidate the exact digest in its protected existing intent.
    private static func completedRuntimeUpgradeLocked(resources: Int32, pins: RuntimeUpgradeSource.Pins,
            repairPins: BrokerRepairSource.Pins, predecessorPins: FullImageSourcePins,
            expectedEvidenceSHA256: String? = nil, projection: RuntimeSuccessorProjection? = nil,
            checkpoint: (FullImageInstallCheckpoint) -> Void = { _ in }) throws -> CompletedRuntimeUpgradeProof {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        guard (projection == nil) == (expectedEvidenceSHA256 == nil),
              expectedEvidenceSHA256.map({ FullImageJSON.hex($0) }) ?? true else { throw FullImageFailure.predecessor }
        checkpoint(.predecessorRuntimeSource)
        let source = try runtimeSource(resources, pins: pins)
        checkpoint(.predecessorRepairSource)
        let previous = try fullResourceDirectory(resources, "Predecessor"); defer { Darwin.close(previous) }
        let predecessor = try repairSource(previous, pins: repairPins)
        guard pins.repairPlan == repairPins.planSHA256, pins.repairSource == repairPins.sourceCommit,
              source.before.sha256 == predecessor.after.sha256, source.oldPeers == predecessor.newPeers,
              repairPins.predecessorPlanSHA256 == predecessorPins.planSHA256,
              repairPins.beforeManifestSHA256 == predecessorPins.targetManifestSHA256 else { throw FullImageFailure.predecessor }
        let (ownerUID, ownerGroup) = try owner()
        try ComponentProcesses.requireOwnerClosed()
        let original = try directory(oldJournal, mode: 0o700); defer { Darwin.close(original) }
        try originalReceipt(original, ownerUID: ownerUID)
        checkpoint(.predecessorNamespace)
        let routes = try FullImageInstalledRoutes.installed(kind: .runtimeUpgrade)
        let support = try routes.support(), namespace = try routes.namespace()
        let beforeGroup = support.identity.group
        let orphanCount = try FullImagePreparationInspector.retained(namespace.fd, plan: pins.planSHA256, owner: 0, group: 0)
        let names = try InstallerPayloadIO.contents(namespace.fd)
        guard names.contains("head.json"), names.contains("transition-" + pins.planSHA256),
              names.count == orphanCount + 2 else { throw FullImageFailure.predecessor }
        let global = try routes.globalJournal(plan: pins.planSHA256), files = try routes.files(plan: pins.planSHA256)
        checkpoint(.predecessorIntent)
        let intent = try FullImageGlobalJournal.readIntent(directory: global.fd, owner: 0, group: 0, beforeGroup: beforeGroup,
            // This is a completed, read-only predecessor. APFS may assign a
            // different transient device number after restart. The intent is
            // only tentatively decoded here. The predecessor proof below is
            // revalidated against its persistent root-volume receipt before
            // any historical device mapping is accepted.
            historicalObservation: true,
            diagnosticContext: .predecessorRuntime,
            validateIntent: { try fullPreliminary($0, source: source, ownerUID: ownerUID) }, verifyAttachment: global.verify)
        let observationDevice = intent.workerPolicy.device
        let projectedFiles: Set<FullImageFileUnit> = [.packageIdentity, .hostPolicy, .ownerPolicy, .installRecord]
        func fileStorage(_ unit: FullImageFileUnit) throws -> FullImageFileStorage {
            let records = intent.operations.compactMap(\.file).filter { $0.unit == unit }
            guard records.count == 1, let operation = records.first else { throw FullImageFailure.journal }
            let current: (() throws -> ComponentObject?)?
            if let projection, projectedFiles.contains(unit) {
                current = {
                    let read = try projection.file(unit)
                    guard read.1.mode == unit.mode, read.1.bytes == read.0.count,
                          read.1.sha256 == FullImageJSON.hash(read.0) else { throw FullImageFailure.object }
                    return read.1
                }
            } else { current = nil }
            return try FullImageFileStorage(operation: operation, retained: files.fd, owner: 0,
                resolve: routes.resolve, verifyAttachments: { try routes.verify() },
                requireQuiescent: { throw FullImageFailure.journal }, observationDevice: observationDevice,
                completedProjection: current)
        }
        func originalFile(_ unit: FullImageFileUnit) throws -> (Data, ComponentObject) {
            guard [.packageIdentity, .repairIdentityRemoval, .hostPolicy, .ownerPolicy, .installRecord].contains(unit) else {
                throw FullImageFailure.journal
            }
            return try fileStorage(unit).originalObservation()
        }
        checkpoint(.predecessorRepairHistory)
        let proof = try completedBrokerRepairLocked(resources: previous, pins: repairPins,
            predecessorPins: predecessorPins, expectedEvidenceSHA256: intent.predecessorEvidenceSHA256,
            historical: originalFile)
        // Revalidate the exact component receipt that authorized this runtime
        // transition before translating its saved device number. The receipt
        // binds unchanged support/application roots to their persistent volume
        // UUID; this operation only reads the protected predecessor history.
        checkpoint(.predecessorRepairRoute)
        let repairRoutes = try BrokerRepairRoutes(plan: repairPins.planSHA256,
            predecessorPlan: repairPins.predecessorPlanSHA256)
        let repairTransition = try repairRoutes.transition()
        checkpoint(.predecessorRepairIntent)
        let repairIntentBytes = try ComponentFiles.read(repairTransition.fd, "intent.json", owner: 0, mode: 0o600).0
        let repairIntent = try BrokerRepairIntent.decode(repairIntentBytes)
        checkpoint(.predecessorRepairEvidence)
        let proofFields = try FullImageJSON.object(proof.evidence, maximum: 8192)
        guard proofFields["intent_sha256"] as? String == FullImageJSON.hash(repairIntentBytes) else {
            throw FullImageFailure.predecessor
        }
        checkpoint(.predecessorComponentRevalidation)
        _ = try repairComponentDevice(resources: previous, pins: predecessorPins,
            intent: repairIntent, routes: repairRoutes)
        checkpoint(.predecessorRepairStability)
        try repairRoutes.verify()
        checkpoint(.predecessorAuthority)
        let authority = try RuntimeUpgradeAuthority.bind(source: source, proof: proof)
        guard authority.ownerUID == ownerUID else { throw FullImageFailure.predecessor }
        try identity(ownerUID, authority.brokerUID)
        let worker = try publicRead("broker/worker.json", mode: 0o644), service = try jobPlist(ownerGroup: ownerGroup)
        let currentDevice = support.identity.device
        guard worker.1 == authority.workerPolicy, service == authority.servicePlist else { throw FullImageFailure.object }
        checkpoint(.predecessorPolicy)
        let policy = try runtimePolicy(source: source, predecessor: predecessor,
            install: originalFile(.installRecord).0, host: originalFile(.hostPolicy).0,
            profile: originalFile(.ownerPolicy).0, worker: worker.0, ownerUID: ownerUID)
        let dynamic = try fullDynamic(policy, source: source, proofSHA256: authority.proofSHA256)
        try authority.validateHistorical(intent, source: source, publicOwner: 0, publicGroup: 0,
            beforeGroup: beforeGroup, device: observationDevice, currentDevice: currentDevice,
            observedWorker: worker.1, observedService: service, dynamic: dynamic)
        let journal = try FullImageGlobalJournal.open(directory: global.fd, owner: 0, group: 0, beforeGroup: beforeGroup,
            expected: intent, validateIntent: {
                try authority.validateHistorical($0, source: source, publicOwner: 0, publicGroup: 0,
                    beforeGroup: beforeGroup, device: observationDevice, currentDevice: currentDevice,
                    observedWorker: worker.1, observedService: service, dynamic: dynamic)
            }, verifyAttachment: global.verify, createIfMissing: false, observationDevice: observationDevice)
        let history = try journal.completedEvidence()
        var units: [FullImageMixedStorage.Unit] = [], trees: [PublicTreeStorage] = []
        for (index, record) in intent.operations.enumerated() {
            if let file = record.file { units.append(.file(try fileStorage(file.unit))) }
            else {
                guard index < source.units.count, let operation = record.tree,
                      case .tree(let unit, let old, let new) = source.units[index] else { throw FullImageFailure.journal }
                let target = try routes.treeParent(unit), retained = try routes.retained(unit, plan: pins.planSHA256)
                let local = try routes.treeJournal(unit, plan: pins.planSHA256)
                let projected: (() throws -> PublicTreePin?)? = unit == .runtimeOwner ? projection?.ownerTree : nil
                let tree = try PublicTreeStorage.open(operation: operation, unit: unit, targetParent: target.fd,
                    retainedParent: retained.fd, journalParent: local.fd,
                    targetAttachment: target.attachment(.target(unit)), retainedAttachment: retained.attachment(.retained(unit)),
                    journalAttachment: local.attachment(.journal(unit)), old: old, new: new, owner: 0, group: 0,
                    beforeGroup: beforeGroup, requireQuiescent: { throw FullImageFailure.journal },
                    createIfMissing: false, observationDevice: observationDevice, completedProjection: projected)
                trees.append(tree); units.append(.tree(tree))
            }
        }
        func unchanged(original checkedOriginal: Int32? = nil, predecessor checkedPrevious: Int32? = nil) throws {
            try routes.verify(); try ComponentProcesses.requireOwnerClosed()
            guard try owner().0 == ownerUID, try InstallerPayloadIO.contents(namespace.fd) == names,
                  try publicRead("broker/worker.json", mode: 0o644).1 == worker.1,
                  try jobPlist(ownerGroup: ownerGroup) == service,
                  try journal.completedEvidence() == history else { throw FullImageFailure.object }
            try originalReceipt(checkedOriginal ?? original, ownerUID: ownerUID)
            let rechecked = try completedBrokerRepairLocked(resources: checkedPrevious ?? previous, pins: repairPins,
                predecessorPins: predecessorPins, expectedEvidenceSHA256: intent.predecessorEvidenceSHA256,
                historical: originalFile)
            guard rechecked.sha256 == proof.sha256 else { throw FullImageFailure.predecessor }
        }
        let storage = try FullImageMixedStorage(units: units,
            writeEvent: { _, _ in throw FullImageFailure.journal }, verifyOld: {}, verifyRecoverable: {}, verifyNew: {})
        checkpoint(.predecessorStorage)
        try intent.verifyStorage(storage)
        func completeView() throws {
            try unchanged()
            guard try storage.operations.allSatisfy({ try storage.state($0) == .applied }) else { throw FullImageFailure.predecessor }
            try fullLayout(source: source, routes: routes, storage: storage, intent: intent)
            if let projection { try projection.verifyPublic() }
            else {
                try FullImagePublicView.verify(source: source, states: Array(repeating: .applied, count: source.units.count),
                    support: support.fd, owner: 0)
                try runtimeSignatures(source, root: InstallerPayloadManifest.support, after: true)
            }
            let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0 else { throw FullImageFailure.object }; defer { Darwin.close(root) }
            _ = try InstallerPayloadIO.verifyApplicationAlias(from: root, owner: 0)
            try unchanged()
        }
        checkpoint(.predecessorView)
        try completeView()
        let localHistory = try trees.map { FullImageJSON.hash(try $0.completedEvidence()) }
        let head = try ComponentFiles.read(namespace.fd, "head.json", owner: 0, mode: 0o644)
        guard head.1 == intent.operations.last?.file?.after else { throw FullImageFailure.predecessor }
        let roots = try InstallationRootBinding.capture(withVolumeUUID: true)
        checkpoint(.predecessorEvidence)
        let evidence = try FullImageJSON.encode(["schema": 1,
            "managed_by": "account-access-completed-runtime-upgrade-v1", "plan_sha256": pins.planSHA256,
            "manifest_sha256": source.after.sha256, "source_commit": pins.targetSource,
            "owner_uid": ownerUID, "broker_uid": authority.brokerUID,
            "predecessor_sha256": authority.proofSHA256, "history_sha256": FullImageJSON.hash(history),
            "tree_history_sha256": localHistory, "head_sha256": head.1.sha256,
            "worker_sha256": worker.1.sha256, "service_sha256": service.sha256,
            "roots": roots.mapValues { ["device": Int64($0.device), "inode": $0.inode, "volume_uuid": $0.volumeUUID] as [String: Any] }
        ] as [String: Any])
        if let expectedEvidenceSHA256 { guard FullImageJSON.hash(evidence) == expectedEvidenceSHA256 else { throw FullImageFailure.predecessor } }
        try completeView()
        guard try trees.map({ FullImageJSON.hash(try $0.completedEvidence()) }) == localHistory,
              try ComponentFiles.read(namespace.fd, "head.json", owner: 0, mode: 0o644).1 == head.1,
              try InstallationRootBinding.capture(withVolumeUUID: true) == roots else { throw FullImageFailure.predecessor }
        let heldOriginal = try RuntimeVerificationDescriptor(original), heldPrevious = try RuntimeVerificationDescriptor(previous)
        return CompletedRuntimeUpgradeProof(evidence: evidence, ownerUID: ownerUID, brokerUID: authority.brokerUID,
            worker: worker.1, service: service, historyCheck: {
                try unchanged(original: heldOriginal.fd, predecessor: heldPrevious.fd)
                guard try trees.map({ FullImageJSON.hash(try $0.journalEvidence()) }) == localHistory,
                      try ComponentFiles.read(namespace.fd, "head.json", owner: 0, mode: 0o644).1 == head.1,
                      try InstallationRootBinding.capture(withVolumeUUID: true) == roots else { throw FullImageFailure.predecessor }
            })
    }
}
