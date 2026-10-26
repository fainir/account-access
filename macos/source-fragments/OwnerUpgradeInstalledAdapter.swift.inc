// Fixed successor for the diagnostic owner app; no ordinary-user entrypoint.
// Called only for the newly created, still-unpublished preparation directory.
// The read-only successor projection must never initialize this journal itself.
enum OwnerUpgradeLocalJournal {
    static func prepare(_ journal: Int32, operation: PublicTreeOperation, owner: uid_t, group: gid_t) throws {
        let before = try InstallerPayloadIO.check(journal, owner: owner, directory: true)
        try PublicTreeIO.noACL(journal)
        guard before.st_gid == group, before.st_mode & 0o7777 == 0o700,
              operation.schema == 2, operation.unit == PublicTreeUnit.runtimeOwner.rawValue,
              FullImageJSON.hex(operation.planSHA256),
              try InstallerPayloadIO.contents(journal).isEmpty else { throw FullImageFailure.journal }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let raw = try encoder.encode(operation)
        _ = try ComponentFiles.writeExclusive(journal, "intent.json", data: raw, owner: owner, mode: 0o600)
        let after = try InstallerPayloadIO.check(journal, owner: owner, directory: true)
        guard fsync(journal) == 0,
              try InstallerPayloadIO.contents(journal) == ["intent.json"],
              try ComponentFiles.read(journal, "intent.json", owner: owner, mode: 0o600).0 == raw,
              PublicTreeDirectoryIdentity(before) == PublicTreeDirectoryIdentity(after) else { throw FullImageFailure.journal }
        try PublicTreeIO.noACL(journal)
    }
}

private struct OwnerUpgradeAuthority {
    let proofSHA256: String
    let ownerUID: uid_t, brokerUID: uid_t
    let workerPolicy: ComponentObject, servicePlist: ComponentObject
    private let planSHA256: String
    static func bind(source: OwnerUpgradeSource, proof: CompletedRuntimeUpgradeProof,
                     runtimePins: RuntimeUpgradeSource.Pins) throws -> Self {
        let value = try FullImageJSON.object(proof.evidence, maximum: 8192)
        let hashes: Set<String> = ["predecessor_sha256", "history_sha256", "head_sha256", "worker_sha256", "service_sha256"]
        guard Set(value.keys) == hashes.union(["schema", "managed_by", "plan_sha256", "manifest_sha256",
            "source_commit", "owner_uid", "broker_uid", "tree_history_sha256", "roots"]),
            try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
            value["managed_by"] as? String == "account-access-completed-runtime-upgrade-v1",
            value["plan_sha256"] as? String == runtimePins.planSHA256,
            source.pins.predecessorRuntimePlan == runtimePins.planSHA256,
            value["manifest_sha256"] as? String == source.before.sha256,
            runtimePins.afterSHA256 == source.before.sha256,
            value["source_commit"] as? String == runtimePins.targetSource,
            hashes.allSatisfy({ (value[$0] as? String).map { FullImageJSON.hex($0) } ?? false }),
            let trees = value["tree_history_sha256"] as? [String], !trees.isEmpty,
            trees.allSatisfy({ FullImageJSON.hex($0) }),
            try InstallerPayloadManifest.integer(value["owner_uid"], maximum: Int64(UInt32.max)) == Int64(proof.ownerUID),
            try InstallerPayloadManifest.integer(value["broker_uid"], maximum: Int64(UInt32.max)) == Int64(proof.brokerUID),
            proof.ownerUID > 0, proof.ownerUID != proof.brokerUID, (450..<500).contains(proof.brokerUID),
            value["worker_sha256"] as? String == proof.workerPolicy.sha256,
            value["service_sha256"] as? String == proof.servicePlist.sha256 else { throw FullImageFailure.predecessor }
        return Self(proofSHA256: proof.sha256, ownerUID: proof.ownerUID, brokerUID: proof.brokerUID,
            workerPolicy: proof.workerPolicy, servicePlist: proof.servicePlist, planSHA256: source.planSHA256)
    }
    func validate(_ intent: FullImageGlobalIntent, source: OwnerUpgradeSource,
                  beforeGroup: gid_t, device: Int32, dynamic: [FullImageFileUnit: Data]) throws {
        guard source.planSHA256 == planSHA256 else { throw FullImageFailure.predecessor }
        try intent.validate(source: source, predecessorEvidenceSHA256: proofSHA256,
            workerPolicy: workerPolicy, servicePlist: servicePlist, ownerUID: ownerUID, brokerUID: brokerUID,
            publicOwner: 0, publicGroup: 0, beforeGroup: beforeGroup, device: device, dynamic: dynamic)
    }
}

extension ComponentController {
    private static func ownerUpgradeSource(_ resources: Int32, pins: OwnerUpgradeSource.Pins) throws -> OwnerUpgradeSource {
        guard try InstallerPayloadIO.contents(resources) == ["OwnerUpgradePlan.json", "BaseManifest.json", "TargetManifest.json",
            "BaseIdentity.json", "TargetIdentity.json", "Predecessor", "TargetImage", "AccountAccess-ownerupgrade", "postinstall"] else {
            throw FullImageFailure.source
        }
        return try OwnerUpgradeSource.load(pins: pins,
            plan: fullRead(resources, "OwnerUpgradePlan.json", maximum: 34 * 1024 * 1024),
            before: fullRead(resources, "BaseManifest.json", maximum: InstallerPayloadManifest.maximumManifest),
            after: fullRead(resources, "TargetManifest.json", maximum: InstallerPayloadManifest.maximumManifest),
            oldIdentity: fullRead(resources, "BaseIdentity.json", maximum: 8192),
            newIdentity: fullRead(resources, "TargetIdentity.json", maximum: 8192))
    }
    private static func ownerUpgradeSignatures(_ source: OwnerUpgradeSource, root: String, after: Bool) throws {
        let peers = after ? source.newPeers : source.oldPeers
        for kind in ["owner", "broker", "bootstrap"] {
            let name = kind == "owner" ? "owner.app" : "bin/AccountAccess-" + kind
            try ComponentUpdateIdentity.verifyStatic(path: root + "/" + name, peer: peers[kind]!, designated: nil)
        }
    }
    private static func ownerUpgradePolicy(source: OwnerUpgradeSource, install: Data, host: Data, profile: Data,
                                          worker: Data, ownerUID: uid_t) throws -> ComponentPolicyResult {
        try FullImageUpdatePolicies.derive(install: install, host: host, owner: profile, worker: worker,
            oldPeers: source.oldPeers, newPeers: source.newPeers,
            oldFingerprint: FullImagePolicyFingerprint.value(source.oldPeers),
            newFingerprint: FullImagePolicyFingerprint.value(source.newPeers), consoleOwner: ownerUID)
    }
    private static func ownerOriginalFile(_ unit: FullImageFileUnit, intent: FullImageGlobalIntent,
            files: FullImageAttachedDirectory, routes: FullImageInstalledRoutes) throws -> (Data, ComponentObject) {
        guard [.packageIdentity, .hostPolicy, .ownerPolicy, .installRecord].contains(unit) else { throw FullImageFailure.journal }
        let records = intent.operations.compactMap(\.file).filter { $0.unit == unit }
        guard records.count == 1, let operation = records.first else { throw FullImageFailure.journal }
        return try FullImageFileStorage(operation: operation, retained: files.fd, owner: 0,
            resolve: routes.resolve, verifyAttachments: { try routes.verify() },
            requireQuiescent: { throw FullImageFailure.journal }).originalObservation()
    }
    private static func ownerObservedTree(source: OwnerUpgradeSource, intent: FullImageGlobalIntent,
            routes: FullImageInstalledRoutes) throws -> PublicTreeStorage {
        guard let operation = intent.operations.first?.tree, operation.unit == PublicTreeUnit.runtimeOwner.rawValue,
              case .tree(let unit, let old, let new) = source.units[0], unit == .runtimeOwner else { throw FullImageFailure.journal }
        let target = try routes.treeParent(unit), retained = try routes.retained(unit, plan: source.planSHA256)
        let local = try routes.treeJournal(unit, plan: source.planSHA256)
        return try PublicTreeStorage.open(operation: operation, unit: unit, targetParent: target.fd,
            retainedParent: retained.fd, journalParent: local.fd,
            targetAttachment: target.attachment(.target(unit)), retainedAttachment: retained.attachment(.retained(unit)),
            journalAttachment: local.attachment(.journal(unit)), old: old, new: new, owner: 0, group: 0,
            beforeGroup: routes.support().identity.group, requireQuiescent: { throw FullImageFailure.journal }, createIfMissing: false)
    }
    private static func ownerProjection(source: OwnerUpgradeSource, intent: FullImageGlobalIntent,
            files: FullImageAttachedDirectory, routes: FullImageInstalledRoutes) throws -> RuntimeSuccessorProjection {
        func view() throws {
            let tree = try ownerObservedTree(source: source, intent: intent, routes: routes)
            var units: [FullImageMixedStorage.Unit] = [.tree(tree)]
            for record in intent.operations.dropFirst() {
                guard let file = record.file else { throw FullImageFailure.journal }
                units.append(.file(try FullImageFileStorage(operation: file, retained: files.fd, owner: 0,
                    resolve: routes.resolve, verifyAttachments: { try routes.verify() },
                    requireQuiescent: { throw FullImageFailure.journal })))
            }
            let storage = try FullImageMixedStorage(units: units, writeEvent: { _, _ in throw FullImageFailure.journal },
                verifyOld: {}, verifyRecoverable: {}, verifyNew: {})
            try intent.verifyStorage(storage)
            try fullLayout(source: source, routes: routes, storage: storage, intent: intent)
            let states = try Array(storage.operations.prefix(source.units.count)).map { try storage.state($0) }
            try FullImagePublicView.verify(source: source, states: states, support: routes.support().fd, owner: 0)
            try ownerUpgradeSignatures(source, root: InstallerPayloadManifest.support, after: states[0] == .applied)
            try routes.verify()
        }
        return RuntimeSuccessorProjection(verifyPublic: view,
            file: { try ownerOriginalFile($0, intent: intent, files: files, routes: routes) },
            ownerTree: { try ownerObservedTree(source: source, intent: intent, routes: routes).originalObservation() })
    }
}

extension ComponentController {
    static func runOwnerUpgrade(resources: Int32, pins: OwnerUpgradeSource.Pins,
            runtimePins: RuntimeUpgradeSource.Pins,
            repairPins: BrokerRepairSource.Pins, predecessorPins: FullImageSourcePins,
            checkpoint: (FullImageInstallCheckpoint) -> Void = { _ in }) throws -> String {
        checkpoint(.context)
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        checkpoint(.source)
        let source = try ownerUpgradeSource(resources, pins: pins)
        let predecessorResources = try fullResourceDirectory(resources, "Predecessor")
        defer { Darwin.close(predecessorResources) }
        let predecessor = try runtimeSource(predecessorResources, pins: runtimePins)
        guard pins.predecessorRuntimePlan == runtimePins.planSHA256,
              predecessor.after.sha256 == source.before.sha256,
              predecessor.newPeers == source.oldPeers else { throw FullImageFailure.predecessor }
        checkpoint(.payload)
        let image = try fullResourceDirectory(resources, "TargetImage"); defer { Darwin.close(image) }
        _ = try InstallerPayloadIO.verifyImage(image, manifest: source.payload, owner: 0)
        let payload = try InstallerPayloadIO.walkDirectory(InstallerPayloadManifest.support, from: image, owner: 0)
        defer { Darwin.close(payload) }
        let payloadPath = try FullImageFDCanonicalPath.installed(payload)
        try payloadPath.checked { try ComponentUpdateIdentity.verifyStatic(path: $0 + "/owner.app", peer: source.newPeers["owner"]!, designated: nil) }
        _ = try InstallerPayloadIO.verifyImage(image, manifest: source.payload, owner: 0)

        checkpoint(.context)
        let (ownerUID, ownerGroup) = try owner()
        let original = try directory(oldJournal, mode: 0o700); defer { Darwin.close(original) }
        let originalLease = try lease(original, "lock"); defer { Darwin.close(originalLease) }
        try originalReceipt(original, ownerUID: ownerUID)
        let brokerDirectory = try InstallerPayloadIO.directory(ComponentSource.support + "/broker", owner: 0)
        defer { Darwin.close(brokerDirectory) }
        let provisionLease = try lease(brokerDirectory, "install.lock"); defer { Darwin.close(provisionLease) }
        try ComponentProcesses.requireOwnerClosed()
        let library = try InstallerPayloadIO.directory("/Library/Application Support", owner: 0); defer { Darwin.close(library) }
        let namespace = try FullImageNamespaceDirectory.installed(library, kind: .ownerUpgrade); defer { Darwin.close(namespace) }
        let routes = try FullImageInstalledRoutes.installed(kind: .ownerUpgrade)
        let support = try routes.support(), namespaceRoute = try routes.namespace()
        // This successor preserves the original public root.
        // Bind its qualified, unchanged group; never obtain legacy authority
        // from intent bytes or normalize an existing installed object.
        let beforeGroup = support.identity.group
        guard try InstallerPayloadIO.check(namespace, owner: 0, directory: true).st_ino == namespaceRoute.identity.inode else { throw FullImageFailure.object }
        let orphans = try FullImagePreparationInspector.retained(namespace, plan: pins.planSHA256, owner: 0, group: 0)
        let hasIntent = try InstallerPayloadIO.contents(namespace).contains("transition-" + pins.planSHA256)
        // This namespace belongs to exactly this repaired-image successor. A foreign head
        // cannot select another predecessor or authorize a second transition.
        if !hasIntent { guard try ComponentFiles.observe(namespace, "head.json", owner: 0) == nil else { throw FullImageFailure.journal } }
        let preliminary: FullImageGlobalIntent?
        if hasIntent {
            checkpoint(.journal)
            let global = try routes.globalJournal(plan: pins.planSHA256)
            preliminary = try FullImageGlobalJournal.readIntent(directory: global.fd, owner: 0, group: 0, beforeGroup: beforeGroup,
                validateIntent: { try fullPreliminary($0, source: source, ownerUID: ownerUID) }, verifyAttachment: global.verify)
        } else { preliminary = nil }
        let observationDevice: Int32? = nil
        checkpoint(.predecessor)
        let proof: CompletedRuntimeUpgradeProof
        if let preliminary {
            let retained = try routes.files(plan: pins.planSHA256)
            let projected = try ownerProjection(source: source, intent: preliminary, files: retained, routes: routes)
            proof = try completedRuntimeUpgradeLocked(resources: predecessorResources, pins: runtimePins,
                repairPins: repairPins, predecessorPins: predecessorPins,
                expectedEvidenceSHA256: preliminary.predecessorEvidenceSHA256, projection: projected,
                checkpoint: checkpoint)
        } else {
            proof = try completedRuntimeUpgradeLocked(resources: predecessorResources, pins: runtimePins,
                repairPins: repairPins, predecessorPins: predecessorPins, checkpoint: checkpoint)
        }
        let authority = try OwnerUpgradeAuthority.bind(source: source, proof: proof, runtimePins: runtimePins)
        guard authority.ownerUID == ownerUID else { throw FullImageFailure.predecessor }
        try identity(ownerUID, authority.brokerUID)
        let worker = try publicRead("broker/worker.json", mode: 0o644), plist = try jobPlist(ownerGroup: ownerGroup)
        let currentDevice = support.identity.device
        let device = observationDevice ?? currentDevice
        func matches(_ observed: ComponentObject, _ recorded: ComponentObject) -> Bool {
            guard observationDevice != nil else { return observed == recorded }
            return recorded.device == device && observed.device == currentDevice
                && observed == ComponentObject(device: currentDevice, inode: recorded.inode,
                    mode: recorded.mode, bytes: recorded.bytes, sha256: recorded.sha256)
        }
        guard matches(worker.1, authority.workerPolicy), matches(plist, authority.servicePlist) else { throw FullImageFailure.object }
        checkpoint(.preparation)
        let intent: FullImageGlobalIntent
        if let preliminary { intent = preliminary }
        else {
            guard orphans < 8 else { throw FullImageFailure.journal }
            checkpoint(.preparationCapacity)
            try ComponentPreparation.capacity(namespace, bytes: FullImagePublicStager.reserve(source), owner: 0, sameDeviceAs: support.fd)
            let install = try publicRead("broker/install.json", mode: 0o600)
            let host = try publicRead("broker/host.json", mode: 0o644), profile = try publicRead("owner.json", mode: 0o644)
            checkpoint(.preparationPolicy)
            let policy = try ownerUpgradePolicy(source: source, install: install.0, host: host.0,
                profile: profile.0, worker: worker.0, ownerUID: ownerUID)
            guard policy.brokerUID == authority.brokerUID else { throw FullImageFailure.predecessor }
            checkpoint(.preparationDynamic)
            let dynamic = try fullDynamic(policy, source: source, proofSHA256: authority.proofSHA256)
            checkpoint(.preparationBegin)
            let preparation = try ComponentPreparation.begin(namespace, plan: pins.planSHA256, owner: 0)
            let preparingName = preparation.0, preparing = preparation.1; defer { Darwin.close(preparing) }
            let files = try child(preparing, "files", create: true); defer { Darwin.close(files) }
            let trees = try child(preparing, "trees", create: true); defer { Darwin.close(trees) }
            let global = try child(preparing, "global", create: true); defer { Darwin.close(global) }
            var operations: [FullImageDurableOperation] = []
            for (index, selected) in source.units.enumerated() {
                switch selected {
                case .file(let publicUnit, let beforeNode, let afterNode):
                    checkpoint(.preparationFileStage)
                    let unit = FullImageFileUnit(publicUnit: publicUnit), slot = String(format: "slot-%02d", index)
                    let (parent, name) = try routes.resolve(unit); defer { Darwin.close(parent) }
                    let before = try ComponentFiles.observe(parent, name, owner: 0); try fullMatches(before, beforeNode)
                    if let afterNode {
                        let input = try fullPayloadParent(payload, unit.path); defer { Darwin.close(input.0) }
                        try FullImagePublicStager.copyFile(from: input.0, name: input.1, to: files, slot: slot, node: afterNode, owner: 0, group: 0)
                    }
                    let after = try ComponentFiles.observe(files, slot, owner: 0); try fullMatches(after, afterNode)
                    operations.append(FullImageDurableOperation(file: FullImageFileOperation(schema: 1, unit: unit,
                        planSHA256: pins.planSHA256, index: index, before: before, after: after)))
                case .tree(let unit, let old, let new):
                    checkpoint(.preparationTreeStage)
                    let tree = try child(trees, unit.rawValue, create: true); defer { Darwin.close(tree) }
                    let retained = try child(tree, "retained", create: true); defer { Darwin.close(retained) }
                    let localJournal = try child(tree, "journal", create: true); defer { Darwin.close(localJournal) }
                    if new.isPresent {
                        guard mkdirat(retained, unit.slot, 0o700) == 0 else { throw FullImageFailure.object }
                        let output = openat(retained, unit.slot, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                        guard output >= 0 else { throw FullImageFailure.object }; defer { Darwin.close(output) }
                        let input = try fullPayloadParent(payload, unit.path); defer { Darwin.close(input.0) }
                        let sourceTree = try fullResourceDirectory(input.0, input.1); defer { Darwin.close(sourceTree) }
                        try FullImagePublicStager.copyTree(from: sourceTree, to: output, inventory: new, owner: 0, group: 0)
                        guard fchmod(output, 0o755) == 0, fsync(output) == 0, fsync(retained) == 0 else { throw FullImageFailure.object }
                    }
                    let target = try routes.treeParent(unit), temporary = try routes.preparing(preparingName, plan: pins.planSHA256, unit: unit)
                    checkpoint(.preparationTreeCapture)
                    let record = try PublicTreeStorage.capture(unit: unit, targetParent: target.fd, retainedParent: retained,
                        targetAttachment: target.attachment(.target(unit)), retainedAttachment: temporary.attachment(.retained(unit)),
                        old: old, new: new, owner: 0, group: 0, beforeGroup: beforeGroup, planSHA256: pins.planSHA256)
                    // Seal the exact local intent before publishing its global
                    // parent. Later original-tree projections open it read-only,
                    // including after interruption immediately after publication.
                    checkpoint(.preparationJournal)
                    try OwnerUpgradeLocalJournal.prepare(localJournal, operation: record, owner: 0, group: 0)
                    operations.append(FullImageDurableOperation(tree: record))
                }
            }
            checkpoint(.preparationDynamicStage)
            for unit in [FullImageFileUnit.hostPolicy, .ownerPolicy, .installRecord, .head] {
                let before = [FullImageFileUnit.hostPolicy: host.1, .ownerPolicy: profile.1, .installRecord: install.1][unit]
                let index = operations.count, slot = String(format: "slot-%02d", index)
                let after = try staged(files, slot: slot, data: dynamic[unit]!, mode: mode_t(unit.mode))
                operations.append(FullImageDurableOperation(file: FullImageFileOperation(schema: 1, unit: unit,
                    planSHA256: pins.planSHA256, index: index, before: before, after: after)))
            }
            checkpoint(.preparationService)
            let observed = try ComponentCommands.launchctl(["print", "system/" + label])
            guard observed.status == 0 else { throw FullImageFailure.predecessor }
            let initial = try ComponentUpdateIdentity.jobSnapshot(output: observed.output, allowedPeers: [source.oldPeers["broker"]!])
            let candidate = FullImageGlobalIntent(schema: 2, managedBy: "account-access-full-image-transition-v2",
                planSHA256: pins.planSHA256, beforeManifestSHA256: source.before.sha256, afterManifestSHA256: source.after.sha256,
                targetSourceCommit: pins.targetSource, predecessorEvidenceSHA256: authority.proofSHA256,
                ownerUID: ownerUID, brokerUID: authority.brokerUID, initialService: initial,
                workerPolicy: worker.1, servicePlist: plist, operations: operations, automaticRebootRecovery: false)
            checkpoint(.preparationAuthority)
            try authority.validate(candidate, source: source, beforeGroup: beforeGroup, device: device, dynamic: dynamic)
            checkpoint(.preparationPredecessor)
            let rechecked = try completedRuntimeUpgradeLocked(resources: predecessorResources, pins: runtimePins,
                repairPins: repairPins, predecessorPins: predecessorPins)
            guard rechecked.sha256 == proof.sha256 else { throw FullImageFailure.predecessor }
            checkpoint(.preparationPayload)
            _ = try InstallerPayloadIO.verifyImage(image, manifest: source.payload, owner: 0)
            // This journal is closed before its parent is renamed. Reopen below
            // qualifies the final canonical route rather than adopting the old
            // preparation route after publication.
            do {
                checkpoint(.preparationJournal)
                let temporary = try routes.preparing(preparingName, plan: pins.planSHA256)
                _ = try FullImageGlobalJournal.open(directory: global, owner: 0, group: 0, beforeGroup: beforeGroup, expected: candidate,
                    validateIntent: { try authority.validate($0, source: source, beforeGroup: beforeGroup, device: device, dynamic: dynamic) },
                    verifyAttachment: temporary.verify)
            }
            try routes.verify()
            checkpoint(.preparationPublish)
            try ComponentPreparation.publish(namespace, name: preparingName, directory: preparing, plan: pins.planSHA256, owner: 0)
            intent = candidate
        }

        checkpoint(.journal)
        let files = try routes.files(plan: pins.planSHA256), global = try routes.globalJournal(plan: pins.planSHA256)
        let projected = try ownerProjection(source: source, intent: intent, files: files, routes: routes)
        let activeProof: CompletedRuntimeUpgradeProof
        if preliminary != nil { activeProof = proof }
        else {
            activeProof = try completedRuntimeUpgradeLocked(resources: predecessorResources, pins: runtimePins,
                repairPins: repairPins, predecessorPins: predecessorPins,
                expectedEvidenceSHA256: proof.sha256, projection: projected)
        }
        let dynamicFiles = intent.operations.suffix(4).compactMap(\.file)
        guard dynamicFiles.map(\.unit) == [.hostPolicy, .ownerPolicy, .installRecord, .head] else { throw FullImageFailure.journal }
        let policy = try ownerUpgradePolicy(source: source,
            install: fullOriginal(dynamicFiles[2], files: files, routes: routes, observationDevice: observationDevice),
            host: fullOriginal(dynamicFiles[0], files: files, routes: routes, observationDevice: observationDevice),
            profile: fullOriginal(dynamicFiles[1], files: files, routes: routes, observationDevice: observationDevice), worker: worker.0, ownerUID: ownerUID)
        guard policy.brokerUID == authority.brokerUID else { throw FullImageFailure.predecessor }
        let dynamic = try fullDynamic(policy, source: source, proofSHA256: authority.proofSHA256)
        let journal = try FullImageGlobalJournal.open(directory: global.fd, owner: 0, group: 0, beforeGroup: beforeGroup, expected: intent,
            validateIntent: { try authority.validate($0, source: source, beforeGroup: beforeGroup, device: device, dynamic: dynamic) },
            verifyAttachment: global.verify, createIfMissing: true, observationDevice: observationDevice)
        let recovery = try journal.recovery()
        let barrier = ComponentLaunchdBarrier(brokerUID: authority.brokerUID, recoveringIntent: recovery.ownsDisable,
            snapshots: (intent.initialService.map { [$0] } ?? []) + recovery.snapshots,
            peers: [source.oldPeers["broker"]!, source.newPeers["broker"]!], recordSnapshot: journal.writeSnapshot, record: journal.writeService)
        let reference = FullImageStorageReference()
        var units: [FullImageMixedStorage.Unit] = []
        for (index, record) in intent.operations.enumerated() {
            if let file = record.file {
                let storage = try FullImageFileStorage(operation: file, retained: files.fd, owner: 0,
                    resolve: routes.resolve, verifyAttachments: { try routes.verify() }, requireQuiescent: barrier.requireDisabledAndQuiescent,
                    observationDevice: observationDevice)
                units.append(.file(storage))
            } else {
                guard index < source.units.count, let operation = record.tree,
                      case .tree(let unit, let old, let new) = source.units[index] else { throw FullImageFailure.journal }
                let target = try routes.treeParent(unit), retained = try routes.retained(unit, plan: pins.planSHA256)
                let localJournal = try routes.treeJournal(unit, plan: pins.planSHA256)
                let storage = try PublicTreeStorage.open(operation: operation, unit: unit, targetParent: target.fd,
                    retainedParent: retained.fd, journalParent: localJournal.fd,
                    targetAttachment: target.attachment(.target(unit)), retainedAttachment: retained.attachment(.retained(unit)),
                    journalAttachment: localJournal.attachment(.journal(unit)), old: old, new: new, owner: 0, group: 0, beforeGroup: beforeGroup,
                    requireQuiescent: barrier.requireDisabledAndQuiescent, createIfMissing: true,
                    observationDevice: observationDevice)
                units.append(.tree(storage))
            }
        }
        let verifyUnchanged = {
            try routes.verify(); try ComponentProcesses.requireOwnerClosed()
            guard try owner().0 == ownerUID, matches(try publicRead("broker/worker.json", mode: 0o644).1, intent.workerPolicy),
                  matches(try jobPlist(ownerGroup: ownerGroup), intent.servicePlist) else { throw FullImageFailure.object }
            try originalReceipt(original, ownerUID: ownerUID)
            try activeProof.revalidateHistory()
        }
        let verifyPublic = {
            guard let storage = reference.storage else { throw FullImageFailure.journal }
            try verifyUnchanged()
            try fullLayout(source: source, routes: routes, storage: storage, intent: intent)
            let states = try Array(storage.operations.prefix(source.units.count)).map { try storage.state($0) }
            try FullImagePublicView.verify(source: source, states: states, support: support.fd, owner: 0)
            guard let ownerIndex = source.units.firstIndex(where: { $0.path == PublicTreeUnit.owner.path }) else { throw FullImageFailure.source }
            try ownerUpgradeSignatures(source, root: InstallerPayloadManifest.support, after: states[ownerIndex] == .applied)
            let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0 else { throw FullImageFailure.object }; defer { Darwin.close(root) }
            _ = try InstallerPayloadIO.verifyApplicationAlias(from: root, owner: 0)
            try routes.verify()
        }
        let storage = try FullImageMixedStorage(units: units, writeEvent: { event, operation in
            guard let storage = reference.storage else { throw FullImageFailure.journal }
            try journal.writeTransition(event, operation: operation, state: storage.state)
        }, verifyOld: {
            try verifyPublic()
            let checked = try completedRuntimeUpgradeLocked(resources: predecessorResources, pins: runtimePins,
                repairPins: repairPins, predecessorPins: predecessorPins,
                expectedEvidenceSHA256: authority.proofSHA256, projection: projected)
            guard checked.sha256 == authority.proofSHA256 else { throw FullImageFailure.predecessor }
        }, verifyRecoverable: verifyPublic, verifyNew: {
            try verifyPublic()
            let checked = try completedRuntimeUpgradeLocked(resources: predecessorResources, pins: runtimePins,
                repairPins: repairPins, predecessorPins: predecessorPins,
                expectedEvidenceSHA256: authority.proofSHA256, projection: projected)
            guard checked.sha256 == authority.proofSHA256 else { throw FullImageFailure.predecessor }
        })
        reference.storage = storage
        try intent.verifyStorage(storage)
        try storage.verifyRecoverableView()
        if try storage.state(storage.operations.last!) == .applied {
            guard try storage.operations.allSatisfy({ try storage.state($0) == .applied }) else { throw FullImageFailure.journal }
            try storage.verifyNewView()
            if recovery.finished {
                checkpoint(.complete)
                return "ALREADY_UPDATED_GUI_UNVERIFIED"
            }
        }
        try ComponentPreparation.capacity(namespace, bytes: 2 * 1024 * 1024, owner: 0, sameDeviceAs: support.fd)
        checkpoint(.transition)
        _ = try ComponentTransition(storage: storage, service: barrier).run(recovering: hasIntent)
        checkpoint(.complete)
        return "UPDATED_GUI_UNVERIFIED"
    }
}
