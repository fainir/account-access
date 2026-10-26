// Composed after the existing controller and full-image adapter. No main or
// ordinary-user authority. Packaging must independently pin this controller.
enum BrokerRepairCheckpoint: String, CaseIterable { case context, source, predecessor, preparation, journal, transition, migration, complete }

// Minted only after the completed repair's exact history, retained objects and
// current public image verify twice. It grants no account/store authority.
struct CompletedBrokerRepairProof {
    let evidence: Data
    var sha256: String { FullImageJSON.hash(evidence) }
    let ownerUID: uid_t, brokerUID: uid_t
    let workerPolicy: ComponentObject, servicePlist: ComponentObject, hostPolicy: ComponentObject
    fileprivate init(evidence: Data, ownerUID: uid_t, brokerUID: uid_t,
                     worker: ComponentObject, service: ComponentObject, host: ComponentObject) {
        self.evidence = evidence; self.ownerUID = ownerUID; self.brokerUID = brokerUID
        workerPolicy = worker; servicePlist = service; hostPolicy = host
    }
}

extension ComponentController {
    static func completedBrokerRepair(resources: Int32, pins: BrokerRepairSource.Pins,
                                     predecessorPins: FullImageSourcePins) throws -> CompletedBrokerRepairProof {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        let original = try directory(oldJournal, mode: 0o700); defer { Darwin.close(original) }
        let originalLease = try lease(original, "lock"); defer { Darwin.close(originalLease) }
        let broker = try directory(InstallerPayloadManifest.support + "/broker", mode: 0o755); defer { Darwin.close(broker) }
        let provisionLease = try lease(broker, "install.lock"); defer { Darwin.close(provisionLease) }
        return try completedBrokerRepairLocked(resources: resources, pins: pins, predecessorPins: predecessorPins)
    }
    // The runtime controller holds the maintenance leases and supplies only
    // typed current-or-retained before records from its fully validated intent.
    // No callback can select a path, and the completed proof must match the
    // digest already bound into that protected successor intent.
    private static func completedBrokerRepairLocked(resources: Int32, pins: BrokerRepairSource.Pins,
            predecessorPins: FullImageSourcePins, expectedEvidenceSHA256: String? = nil,
            historical: ((FullImageFileUnit) throws -> (Data, ComponentObject))? = nil) throws -> CompletedBrokerRepairProof {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        guard (historical == nil) == (expectedEvidenceSHA256 == nil),
              expectedEvidenceSHA256.map({ FullImageJSON.hex($0) }) ?? true else { throw ComponentUpdateFailure.journal }
        let source = try repairSource(resources, pins: pins)
        guard pins.predecessorPlanSHA256 == predecessorPins.planSHA256,
              pins.beforeManifestSHA256 == predecessorPins.targetManifestSHA256 else { throw ComponentUpdateFailure.source }
        let payloadPath = try FullImageFDCanonicalPath.installed(resources)
        try payloadPath.checked { path in
            try ComponentUpdateIdentity.verifyStatic(path: path + "/AccountAccess-broker", peer: source.newPeers["broker"]!, designated: nil)
        }
        let (ownerUID, ownerGroup) = try owner()
        let original = try directory(oldJournal, mode: 0o700); defer { Darwin.close(original) }
        try originalReceipt(original, ownerUID: ownerUID)
        try ComponentProcesses.requireOwnerClosed()
        let routes = try BrokerRepairRoutes(plan: pins.planSHA256, predecessorPlan: pins.predecessorPlanSHA256)
        let namespace = try routes.namespace(), backup = try routes.transition()
        let namespaceNames: Set<String> = ["head.json", "transition-" + pins.planSHA256]
        guard try InstallerPayloadIO.contents(namespace.fd) == namespaceNames else { throw ComponentUpdateFailure.journal }
        let mount = try routes.mount(), history = try routes.history()
        let predecessorHead = try ComponentFiles.read(routes.predecessor().fd, "head.json", owner: 0, mode: 0o644).1
        let worker = try publicRead("broker/worker.json", mode: 0o644)
        let host = try historical?(.hostPolicy) ?? publicRead("broker/host.json", mode: 0o644)
        guard host.1.bytes == host.0.count, host.1.sha256 == FullImageJSON.hash(host.0) else { throw ComponentUpdateFailure.object }
        let service = try jobPlist(ownerGroup: ownerGroup)
        let intentBytes = try ComponentFiles.read(backup.fd, "intent.json", owner: 0, mode: 0o600).0
        let intent = try BrokerRepairIntent.decode(intentBytes)
        let predecessorEvidence = try FullImageJSON.object(intent.predecessorEvidence, maximum: 8192)
        guard predecessorEvidence["source_commit"] as? String == predecessorPins.targetSourceCommit else {
            throw ComponentUpdateFailure.journal
        }
        let operations = try intent.operations(current: mount)
        guard operations.count == BrokerRepairIntent.targets.count,
              operations.enumerated().allSatisfy({ index, operation in
                operation.target == BrokerRepairIntent.targets[index].0 && operation.path == BrokerRepairIntent.targets[index].1
                && operation.slot == String(format: "slot-%02d", index) }) else { throw ComponentUpdateFailure.journal }
        func retainedOriginal(_ operation: ComponentOperation) throws -> Data {
            guard let expected = operation.before else { throw ComponentUpdateFailure.journal }
            let saved = try ComponentFiles.read(backup.fd, operation.slot, owner: 0)
            guard saved.1 == expected else { throw ComponentUpdateFailure.journal }
            return saved.0
        }
        let policy = try ComponentUpdatePolicies.derive(install: retainedOriginal(operations[4]),
            host: host.0, owner: retainedOriginal(operations[3]), worker: worker.0,
            oldPeers: source.oldPeers, newPeers: source.newPeers, oldFingerprint: source.oldFingerprint,
            newFingerprint: source.newFingerprint, consoleOwner: ownerUID)
        try identity(ownerUID, policy.brokerUID)
        guard policy.host == host.0 else { throw ComponentUpdateFailure.journal }
        try intent.validate(source: source, current: mount, policy: policy, currentHead: predecessorHead,
            currentHistorySHA256: FullImageJSON.hash(history), worker: worker.1, service: service, host: host.1)
        let names = try InstallerPayloadIO.contents(backup.fd)
        func journalEvidence() throws -> Data {
            guard try InstallerPayloadIO.contents(backup.fd) == names else { throw ComponentUpdateFailure.journal }
            let evidence = try BrokerRepairJournal.completedEvidence(names: names, plan: pins.planSHA256, operations: operations) {
                try ComponentFiles.read(backup.fd, $0, owner: 0, mode: 0o600).0
            }
            guard try InstallerPayloadIO.contents(backup.fd) == names else { throw ComponentUpdateFailure.journal }
            return evidence
        }
        func unchanged() throws {
            try routes.verify()
            guard try routes.mount() == mount, try routes.history() == history,
                  try InstallerPayloadIO.contents(namespace.fd) == namespaceNames,
                  try InstallerPayloadIO.contents(backup.fd) == names,
                  try ComponentFiles.read(backup.fd, "intent.json", owner: 0, mode: 0o600).0 == intentBytes,
                  try ComponentFiles.read(routes.predecessor().fd, "head.json", owner: 0, mode: 0o644).1 == predecessorHead,
                  try publicRead("broker/worker.json", mode: 0o644).1 == worker.1,
                  try (historical?(.hostPolicy) ?? publicRead("broker/host.json", mode: 0o644)).1 == host.1,
                  try jobPlist(ownerGroup: ownerGroup) == service, try owner().0 == ownerUID else { throw ComponentUpdateFailure.object }
            try originalReceipt(original, ownerUID: ownerUID)
        }
        func completeView() throws {
            try unchanged()
            if historical == nil {
                _ = try InstallerPayloadIO.installedImage(source.after, opaquePrivateBranches: true)
                try repairSignatures(source, after: true)
            }
            // A successor may have moved these four old files into its own
            // retained slots. Broker and repair-head objects remain installed.
            let moved: [String: FullImageFileUnit] = ["package-identity.json": .packageIdentity,
                "broker-repair-identity.json": .repairIdentityRemoval,
                "owner.json": .ownerPolicy, "broker/install.json": .installRecord]
            for operation in operations {
                let current: ComponentObject?
                if let historical, let unit = moved[operation.path], operation.target != .head {
                    let read = try historical(unit)
                    guard read.1.bytes == read.0.count, FullImageJSON.hash(read.0) == read.1.sha256 else {
                        throw ComponentUpdateFailure.object
                    }
                    current = read.1
                } else {
                    let (parent, name) = try routes.resolve(operation); defer { Darwin.close(parent) }
                    current = try ComponentFiles.observe(parent, name, owner: 0)
                }
                guard current == operation.after,
                      try ComponentFiles.observe(backup.fd, operation.slot, owner: 0) == operation.before else {
                    throw ComponentUpdateFailure.object
                }
            }
            try unchanged()
        }
        let completedHistory = try journalEvidence()
        try completeView()
        let evidence = try FullImageJSON.encode(["schema": 1,
            "managed_by": "account-access-completed-broker-repair-v1",
            "plan_sha256": pins.planSHA256, "manifest_sha256": source.after.sha256,
            "source_commit": pins.sourceCommit, "owner_uid": ownerUID, "broker_uid": policy.brokerUID,
            "intent_sha256": FullImageJSON.hash(intentBytes), "history_sha256": FullImageJSON.hash(completedHistory),
            "predecessor_evidence_sha256": FullImageJSON.hash(intent.predecessorEvidence),
            "head_sha256": operations.last!.after.sha256,
            "mount_sha256": FullImageJSON.hash(try BrokerRepairJournal.encode(intent.mount)),
            "worker_sha256": worker.1.sha256, "service_sha256": service.sha256, "host_sha256": host.1.sha256] as [String: Any])
        if let expectedEvidenceSHA256 {
            guard FullImageJSON.hash(evidence) == expectedEvidenceSHA256 else { throw ComponentUpdateFailure.journal }
        }
        try completeView()
        guard try journalEvidence() == completedHistory else { throw ComponentUpdateFailure.journal }
        try unchanged()
        return CompletedBrokerRepairProof(evidence: evidence, ownerUID: ownerUID, brokerUID: policy.brokerUID,
            worker: worker.1, service: service, host: host.1)
    }
    private static func repairSource(_ resources: Int32, pins: BrokerRepairSource.Pins) throws -> BrokerRepairSource {
        guard try InstallerPayloadIO.contents(resources) == ["BrokerRepairPlan.json", "BaseManifest.json", "TargetManifest.json",
            "BaseIdentity.json", "TargetIdentity.json", "BrokerRepairIdentity.json", "AccountAccess-broker",
            "CompletedImage", "AccountAccess-brokerrepair", "postinstall"] else { throw ComponentUpdateFailure.source }
        return try BrokerRepairSource.load(pins: pins,
            plan: fullRead(resources, "BrokerRepairPlan.json", maximum: 16384),
            before: fullRead(resources, "BaseManifest.json", maximum: InstallerPayloadManifest.maximumManifest),
            after: fullRead(resources, "TargetManifest.json", maximum: InstallerPayloadManifest.maximumManifest),
            oldIdentity: fullRead(resources, "BaseIdentity.json", maximum: 8192),
            newIdentity: fullRead(resources, "TargetIdentity.json", maximum: 8192),
            provenance: fullRead(resources, "BrokerRepairIdentity.json", maximum: 16384),
            broker: ComponentFiles.read(resources, "AccountAccess-broker", owner: 0, mode: 0o755).0)
    }
    private static func repairSignatures(_ source: BrokerRepairSource, after: Bool) throws {
        let peers = after ? source.newPeers : source.oldPeers
        for kind in ["owner", "broker", "bootstrap"] {
            let relative = kind == "owner" ? "owner.app" : "bin/AccountAccess-" + kind
            try ComponentUpdateIdentity.verifyStatic(path: InstallerPayloadManifest.support + "/" + relative,
                peer: peers[kind]!, designated: nil)
        }
    }
    private static func repairOriginal(_ operation: ComponentOperation, routes: BrokerRepairRoutes, backup: Int32) throws -> Data {
        guard [.ownerPolicy, .installRecord].contains(operation.target), let before = operation.before else {
            throw ComponentUpdateFailure.journal
        }
        let current = try routes.read(operation)
        if current.1 == before { return current.0 }
        let retained = try ComponentFiles.read(backup, operation.slot, owner: 0)
        guard retained.1 == before else { throw ComponentUpdateFailure.journal }; return retained.0
    }
    private static func repairComponentDevice(resources: Int32, pins: FullImageSourcePins,
                                               intent: BrokerRepairIntent, routes: BrokerRepairRoutes) throws -> Int32 {
        // The repair intent was already bound to the exact completed-image
        // history. Revalidate that image's component proof before using its
        // original epoch; never infer authority from a matching device number.
        let evidence = try FullImageJSON.object(intent.predecessorEvidence, maximum: 8192)
        guard let expected = evidence["predecessor_sha256"] as? String, FullImageJSON.hex(expected) else {
            throw ComponentUpdateFailure.journal
        }
        let history = try routes.predecessorHistory(), support = try routes.support()
        let fullIntent = try FullImageGlobalJournal.readIntent(directory: history.fd, owner: 0, group: 0,
            beforeGroup: support.identity.group, historicalObservation: true, validateIntent: { value in
                guard value.planSHA256 == pins.planSHA256, value.afterManifestSHA256 == pins.targetManifestSHA256,
                      value.targetSourceCommit == pins.targetSourceCommit, value.predecessorEvidenceSHA256 == expected,
                      value.ownerUID == intent.transition.ownerUID, value.brokerUID == intent.transition.brokerUID,
                      value.workerPolicy.sha256 == intent.transition.workerPolicy.sha256,
                      value.servicePlist.sha256 == intent.transition.servicePlist.sha256 else {
                    throw ComponentUpdateFailure.journal
                }
            }, verifyAttachment: history.verify)
        let image = try fullResourceDirectory(resources, "CompletedImage"); defer { Darwin.close(image) }
        let component = try fullResourceDirectory(image, "Predecessor"); defer { Darwin.close(component) }
        let proof = try revalidateCompletedPredecessor(resources: component, planPin: pins.predecessor.planSHA256,
            expectedEvidenceSHA256: expected, recordedDevice: fullIntent.workerPolicy.device)
        guard pins.predecessor.planSHA256 == StoreVolumeMigrationAuthority.componentPlan,
              pins.predecessorSourceCommit == StoreVolumeMigrationAuthority.componentSource else {
            throw ComponentUpdateFailure.source
        }
        return proof.componentDevice
    }
    static func runBrokerRepair(resources: Int32, pins: BrokerRepairSource.Pins, predecessorPins: FullImageSourcePins,
                                checkpoint: @escaping (BrokerRepairCheckpoint) -> Void = { _ in },
                                predecessorCheckpoint: (FullImageInstallCheckpoint) -> Void = { _ in }) throws -> String {
        checkpoint(.context)
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        checkpoint(.source)
        let source = try repairSource(resources, pins: pins)
        guard pins.predecessorPlanSHA256 == predecessorPins.planSHA256,
              pins.beforeManifestSHA256 == predecessorPins.targetManifestSHA256 else { throw ComponentUpdateFailure.source }
        let payloadPath = try FullImageFDCanonicalPath.installed(resources)
        try payloadPath.checked { path in
            try ComponentUpdateIdentity.verifyStatic(path: path + "/AccountAccess-broker", peer: source.newPeers["broker"]!, designated: nil)
        }
        let transitionPath = BrokerRepairIntent.namespace + "/transition-" + pins.planSHA256
        var existing = stat()
        let result = lstat(transitionPath, &existing)
        guard result == 0 || errno == ENOENT else { throw ComponentUpdateFailure.journal }
        let recovering = result == 0
        checkpoint(.predecessor)
        // This verifier owns its maintenance locks. Acquire our lease after it
        // returns, then recheck its exact public image, roots, head and history.
        let proof: CompletedFullImageProof?
        if recovering { proof = nil }
        else {
            let image = try fullResourceDirectory(resources, "CompletedImage"); defer { Darwin.close(image) }
            proof = try completedFullImage(resources: image, pins: predecessorPins, checkpoint: predecessorCheckpoint)
        }
        let (ownerUID, ownerGroup) = try owner()
        let original = try directory(oldJournal, mode: 0o700); defer { Darwin.close(original) }
        let originalLease = try lease(original, "lock"); defer { Darwin.close(originalLease) }
        try originalReceipt(original, ownerUID: ownerUID)
        let broker = try directory(InstallerPayloadManifest.support + "/broker", mode: 0o755); defer { Darwin.close(broker) }
        let provisionLease = try lease(broker, "install.lock"); defer { Darwin.close(provisionLease) }
        try ComponentProcesses.requireOwnerClosed()
        let library = try InstallerPayloadIO.directory("/Library/Application Support", owner: 0); defer { Darwin.close(library) }
        let namespace = try FullImageNamespaceDirectory.installedBrokerRepair(library, create: !recovering)
        defer { Darwin.close(namespace) }
        let routes = try BrokerRepairRoutes(plan: pins.planSHA256, predecessorPlan: pins.predecessorPlanSHA256)
        guard try routes.namespace().identity.inode == InstallerPayloadIO.check(namespace, owner: 0, directory: true).st_ino else {
            throw ComponentUpdateFailure.object
        }
        let mount = try routes.mount(), history = try routes.history()
        let predecessorHead = try ComponentFiles.read(routes.predecessor().fd, "head.json", owner: 0, mode: 0o644).1
        let worker = try publicRead("broker/worker.json", mode: 0o644), host = try publicRead("broker/host.json", mode: 0o644)
        let service = try jobPlist(ownerGroup: ownerGroup)
        let modes = Dictionary(uniqueKeysWithValues: BrokerRepairIntent.targets.enumerated().map {
            (String(format: "slot-%02d", $0.offset), mode_t($0.element.2)) })
        let reserve = recovering ? Int64(0) : Int64(source.payloads.values.reduce(0) { $0 + $1.count } + 81920)
        let orphans = try ComponentPreparation.retained(namespace, plan: pins.planSHA256, slots: modes, owner: 0, reserve: reserve)
        let backup: Int32, preparing: String?
        if recovering { backup = try child(namespace, "transition-" + pins.planSHA256, create: false); preparing = nil }
        else {
            guard orphans < 8, let proof, proof.ownerUID == ownerUID,
                  try ComponentFiles.observe(namespace, "head.json", owner: 0) == nil else { throw ComponentUpdateFailure.journal }
            _ = try InstallerPayloadIO.installedImage(source.before, opaquePrivateBranches: true)
            try repairSignatures(source, after: false)
            try ComponentPreparation.capacity(namespace, bytes: reserve + 2097152, owner: 0, sameDeviceAs: routes.support().fd)
            let created = try ComponentPreparation.begin(namespace, plan: pins.planSHA256, owner: 0)
            preparing = created.0; backup = created.1
        }
        defer { Darwin.close(backup) }
        checkpoint(.preparation)
        let intent: BrokerRepairIntent, policy: ComponentPolicyResult
        if recovering {
            intent = try BrokerRepairIntent.decode(ComponentFiles.read(backup, "intent.json", owner: 0, mode: 0o600).0)
            let operations = try intent.operations(current: mount)
            guard operations.count == BrokerRepairIntent.targets.count,
                  operations.enumerated().allSatisfy({ index, operation in
                    operation.target == BrokerRepairIntent.targets[index].0 && operation.path == BrokerRepairIntent.targets[index].1
                    && operation.slot == String(format: "slot-%02d", index) }) else { throw ComponentUpdateFailure.journal }
            policy = try ComponentUpdatePolicies.derive(install: repairOriginal(operations[4], routes: routes, backup: backup),
                host: host.0, owner: repairOriginal(operations[3], routes: routes, backup: backup), worker: worker.0,
                oldPeers: source.oldPeers, newPeers: source.newPeers, oldFingerprint: source.oldFingerprint,
                newFingerprint: source.newFingerprint, consoleOwner: ownerUID)
        } else {
            guard let proof else { throw ComponentUpdateFailure.journal }
            let install = try publicRead("broker/install.json", mode: 0o600), profile = try publicRead("owner.json", mode: 0o644)
            policy = try ComponentUpdatePolicies.derive(install: install.0, host: host.0, owner: profile.0, worker: worker.0,
                oldPeers: source.oldPeers, newPeers: source.newPeers, oldFingerprint: source.oldFingerprint,
                newFingerprint: source.newFingerprint, consoleOwner: ownerUID)
            guard policy.brokerUID == proof.brokerUID else { throw ComponentUpdateFailure.base }
            try identity(ownerUID, policy.brokerUID)
            let observed = try ComponentCommands.launchctl(["print", "system/" + label])
            guard observed.status == 0 else { throw ComponentUpdateFailure.base }
            let snapshot = try ComponentUpdateIdentity.jobSnapshot(output: observed.output, allowedPeers: [source.oldPeers["broker"]!])
            let data = BrokerRepairUnit.allCases.map { source.payloads[$0]! } + [policy.owner, policy.install,
                try BrokerRepairIntent.head(source: source, evidence: proof.evidence)]
            var operations: [ComponentOperation] = []
            for (index, target) in BrokerRepairIntent.targets.enumerated() {
                let slot = String(format: "slot-%02d", index)
                let after = try staged(backup, slot: slot, data: data[index], mode: mode_t(target.2))
                let candidate = ComponentOperation(target: target.0, path: target.1, slot: slot, before: nil, after: after)
                let (parent, name) = try routes.resolve(candidate); defer { Darwin.close(parent) }
                let before = try ComponentFiles.observe(parent, name, owner: 0)
                if index == 3 { guard before == profile.1 else { throw ComponentUpdateFailure.object } }
                if index == 4 { guard before == install.1 else { throw ComponentUpdateFailure.object } }
                operations.append(ComponentOperation(target: target.0, path: target.1, slot: slot, before: before, after: after))
            }
            intent = BrokerRepairIntent(schema: 1, managedBy: "account-access-broker-repair-transition-v1", mount: mount,
                transition: ComponentTransitionIntent(schema: 1, planSHA256: pins.planSHA256, baseManifestSHA256: pins.beforeManifestSHA256,
                    targetManifestSHA256: pins.afterManifestSHA256, operations: operations, ownerUID: ownerUID, brokerUID: policy.brokerUID,
                    service: snapshot, workerPolicy: worker.1, servicePlist: service, automaticRebootRecovery: false),
                predecessorEvidence: proof.evidence, predecessorHead: predecessorHead, hostPolicy: host.1)
        }
        try identity(ownerUID, policy.brokerUID)
        guard policy.host == host.0 else { throw ComponentUpdateFailure.journal }
        try intent.validate(source: source, current: mount, policy: policy, currentHead: predecessorHead,
            currentHistorySHA256: FullImageJSON.hash(history), worker: worker.1, service: service, host: host.1)
        let operations = try intent.operations(current: mount)
        let verifyUnchanged = {
            try routes.verify()
            guard try routes.mount() == mount, try routes.history() == history,
                  try ComponentFiles.read(routes.predecessor().fd, "head.json", owner: 0, mode: 0o644).1 == predecessorHead,
                  try publicRead("broker/worker.json", mode: 0o644).1 == worker.1,
                  try publicRead("broker/host.json", mode: 0o644).1 == host.1,
                  try jobPlist(ownerGroup: ownerGroup) == service, try owner().0 == ownerUID else { throw ComponentUpdateFailure.object }
            try originalReceipt(original, ownerUID: ownerUID)
        }
        if let preparing {
            try verifyUnchanged()
            _ = try InstallerPayloadIO.installedImage(source.before, opaquePrivateBranches: true)
            guard try InstallerPayloadIO.contents(backup) == Set(operations.map(\.slot)) else { throw ComponentUpdateFailure.journal }
            _ = try ComponentFiles.writeExclusive(backup, "intent.json", data: intent.encoded(), owner: 0, mode: 0o600)
            try ComponentPreparation.publish(namespace, name: preparing, directory: backup, plan: pins.planSHA256, owner: 0)
        }
        let attachedBackup = try routes.transition()
        guard attachedBackup.identity.inode == (try InstallerPayloadIO.check(backup, owner: 0, directory: true)).st_ino else {
            throw ComponentUpdateFailure.object
        }
        checkpoint(.journal)
        let state = try BrokerRepairJournal.load(names: InstallerPayloadIO.contents(backup), plan: pins.planSHA256, operations: operations) {
            try ComponentFiles.read(backup, $0, owner: 0, mode: 0o600).0
        }
        var serviceSequence = state.nextService, jobSequence = state.nextJob
        let barrier = ComponentLaunchdBarrier(brokerUID: policy.brokerUID, recoveringIntent: state.ownsDisable,
            snapshots: (intent.transition.service.map { [$0] } ?? []) + state.snapshots,
            peers: [source.oldPeers["broker"]!, source.newPeers["broker"]!], recordSnapshot: { snapshot in
                try verifyUnchanged(); guard jobSequence < 10000 else { throw ComponentUpdateFailure.journal }
                try ComponentUpdateIdentity.validateSnapshot(snapshot)
                let bytes = try BrokerRepairJournal.encode(BrokerRepairJournal.Job(schema: 1, planSHA256: pins.planSHA256, job: snapshot))
                _ = try ComponentFiles.writeExclusive(backup, String(format: "job-%04d.json", jobSequence), data: bytes, owner: 0, mode: 0o600)
                jobSequence += 1
            }, record: { event in
                try verifyUnchanged()
                guard serviceSequence < 10000, BrokerRepairJournal.serviceEvents.contains(event) else { throw ComponentUpdateFailure.journal }
                let bytes = try FullImageJSON.encode(["schema": 1, "event": event, "plan_sha256": pins.planSHA256])
                _ = try ComponentFiles.writeExclusive(backup, String(format: "service-%04d.json", serviceSequence), data: bytes, owner: 0, mode: 0o600)
                serviceSequence += 1
            })
        let verifyView: (Bool) throws -> Void = { after in
            try verifyUnchanged()
            _ = try InstallerPayloadIO.installedImage(after ? source.after : source.before, opaquePrivateBranches: true)
            try repairSignatures(source, after: after)
            for operation in operations where operation.target != .head {
                let (parent, name) = try routes.resolve(operation); defer { Darwin.close(parent) }
                guard try ComponentFiles.observe(parent, name, owner: 0) == (after ? operation.after : operation.before) else {
                    throw ComponentUpdateFailure.object
                }
            }
            if !after { guard try ComponentFiles.observe(namespace, "head.json", owner: 0) == nil else { throw ComponentUpdateFailure.journal } }
            try verifyUnchanged()
        }
        let storage = ComponentFileTransaction(operations: operations, backup: backup, owner: 0, nextEvent: state.nextEvent,
            target: { operation in try routes.verify(); return try routes.resolve(operation) }, verifyOld: { try verifyView(false) },
            verifyRecoverable: {
                try verifyUnchanged()
                try ComponentViews.verifyRecoverableBase(source.before, operations: operations, owner: 0)
                // mount() separately verifies the fixed application alias.
                try verifyUnchanged()
            }, verifyNew: {
                try verifyView(true)
                checkpoint(.migration)
                let install = try InstallationRootBinding.object(policy.install)
                guard let vault = install["vault_id"] as? String, let enrollment = install["enrollment_id"] as? String else {
                    throw ComponentUpdateFailure.journal
                }
                // This local lifetime releases the enrollment lock before
                // ComponentTransition restores the broker's launchd service.
                let componentDevice = try repairComponentDevice(resources: resources, pins: predecessorPins,
                    intent: intent, routes: routes)
                try verifyUnchanged()
                let migration = try StoreVolumeMigration.prepare(ownerUID: ownerUID, brokerUID: policy.brokerUID,
                    vaultID: vault, enrollmentID: enrollment, verifiedComponentDevice: componentDevice,
                    requireQuiescent: barrier.requireDisabledAndQuiescent)
                try migration.publish()
                try verifyUnchanged()
            })
        try storage.verifyRecoverableView()
        if try storage.state(operations.last!) == .applied {
            for operation in operations { guard try storage.state(operation) == .applied else { throw ComponentUpdateFailure.journal } }
            try verifyView(true)
            // Migration precedes the head. A completed retry is read-only and
            // never quiesces the service merely to prove owner-session health.
            if state.finished { checkpoint(.complete); return "ALREADY_UPDATED_GUI_UNVERIFIED" }
        }
        try ComponentPreparation.capacity(namespace, bytes: 2097152, owner: 0, sameDeviceAs: routes.support().fd)
        checkpoint(.transition)
        _ = try ComponentTransition(storage: storage, service: barrier).run(recovering: recovering)
        checkpoint(.complete)
        return "UPDATED_GUI_UNVERIFIED"
    }
}
