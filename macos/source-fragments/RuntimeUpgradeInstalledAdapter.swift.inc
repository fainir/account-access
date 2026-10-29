// Closed repaired-image successor. Composed with ComponentController; no main,
// user-supplied destination or owner-host invocation is supplied by this file.
enum RuntimeUpgradeHistoricalObjectBinding {
    static func matches(recorded: ComponentObject, observed: ComponentObject,
                        recordedDevice: Int32, currentDevice: Int32) -> Bool {
        recordedDevice >= 0 && currentDevice >= 0 && recorded.device == recordedDevice
            && observed.device == currentDevice && recorded.inode == observed.inode
            && recorded.mode == observed.mode && recorded.bytes == observed.bytes
            && recorded.sha256 == observed.sha256
    }
}

private struct RuntimeUpgradeAuthority {
    let proofSHA256: String
    let ownerUID: uid_t, brokerUID: uid_t
    let workerPolicy: ComponentObject, servicePlist: ComponentObject
    private let planSHA256: String
    static func bind(source: RuntimeUpgradeSource, proof: CompletedBrokerRepairProof) throws -> Self {
        let value = try FullImageJSON.object(proof.evidence, maximum: 8192)
        let hashes: Set<String> = ["intent_sha256", "history_sha256", "predecessor_evidence_sha256",
            "head_sha256", "mount_sha256", "worker_sha256", "service_sha256", "host_sha256"]
        guard Set(value.keys) == hashes.union(["schema", "managed_by", "plan_sha256", "manifest_sha256",
            "source_commit", "owner_uid", "broker_uid"]),
            try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
            value["managed_by"] as? String == "account-access-completed-broker-repair-v1",
            value["plan_sha256"] as? String == source.pins.repairPlan,
            value["manifest_sha256"] as? String == source.before.sha256,
            value["source_commit"] as? String == source.pins.repairSource,
            hashes.allSatisfy({ (value[$0] as? String).map { FullImageJSON.hex($0) } ?? false }),
            try InstallerPayloadManifest.integer(value["owner_uid"], maximum: Int64(UInt32.max)) == Int64(proof.ownerUID),
            try InstallerPayloadManifest.integer(value["broker_uid"], maximum: Int64(UInt32.max)) == Int64(proof.brokerUID),
            proof.ownerUID > 0, proof.ownerUID != proof.brokerUID, (450..<500).contains(proof.brokerUID),
            value["worker_sha256"] as? String == proof.workerPolicy.sha256,
            value["service_sha256"] as? String == proof.servicePlist.sha256,
            value["host_sha256"] as? String == proof.hostPolicy.sha256 else { throw FullImageFailure.predecessor }
        return Self(proofSHA256: proof.sha256, ownerUID: proof.ownerUID, brokerUID: proof.brokerUID,
            workerPolicy: proof.workerPolicy, servicePlist: proof.servicePlist, planSHA256: source.planSHA256)
    }
    static func bindDirect(source: RuntimeUpgradeSource, install: Data, host: Data, profile: Data,
                           ownerUID: uid_t, brokerUID: uid_t, workerPolicy: ComponentObject,
                           servicePlist: ComponentObject) throws -> Self {
        guard source.directRuntimeDelta, source.before.sha256 == DirectRuntimeUpgradeSource.beforeSHA256,
              source.after.sha256 == DirectRuntimeUpgradeSource.afterSHA256,
              ownerUID > 0, ownerUID != brokerUID, (450..<500).contains(brokerUID),
              workerPolicy.mode == 0o644, servicePlist.mode == 0o644 else { throw FullImageFailure.predecessor }
        let evidence: [String: Any] = ["schema": 1, "managed_by": "account-access-exact-runtime-predecessor-v1",
            "plan_sha256": source.planSHA256, "before_manifest_sha256": source.before.sha256,
            "after_manifest_sha256": source.after.sha256,
            "original_receipt_manifest_sha256": DirectRuntimeUpgradeSource.originalReceipt,
            "target_source": source.targetSourceCommit, "owner_uid": Int(ownerUID), "broker_uid": Int(brokerUID),
            "install_sha256": FullImageJSON.hash(install), "host_sha256": FullImageJSON.hash(host),
            "profile_sha256": FullImageJSON.hash(profile), "worker_sha256": workerPolicy.sha256,
            "service_sha256": servicePlist.sha256]
        let raw = try FullImageJSON.encode(evidence)
        return Self(proofSHA256: FullImageJSON.hash(raw), ownerUID: ownerUID, brokerUID: brokerUID,
            workerPolicy: workerPolicy, servicePlist: servicePlist, planSHA256: source.planSHA256)
    }
    func validate(_ intent: FullImageGlobalIntent, source: RuntimeUpgradeSource,
                  publicOwner: uid_t, publicGroup: gid_t, beforeGroup: gid_t, device: Int32,
                  dynamic: [FullImageFileUnit: Data]) throws {
        guard source.planSHA256 == planSHA256 else { throw FullImageFailure.predecessor }
        try intent.validate(source: source, predecessorEvidenceSHA256: proofSHA256,
            workerPolicy: workerPolicy, servicePlist: servicePlist, ownerUID: ownerUID, brokerUID: brokerUID,
            publicOwner: publicOwner, publicGroup: publicGroup, beforeGroup: beforeGroup, device: device, dynamic: dynamic)
    }

    // A completed predecessor may retain the device number from the mount
    // epoch in which it was installed. This path is used only after its
    // predecessor proof has revalidated the persistent volume receipt. It
    // accepts the recorded objects only when every stable field still matches
    // the current root-owned object; only st_dev may differ.
    func validateHistorical(_ intent: FullImageGlobalIntent, source: RuntimeUpgradeSource,
                  publicOwner: uid_t, publicGroup: gid_t, beforeGroup: gid_t, device: Int32,
                  currentDevice: Int32, observedWorker: ComponentObject, observedService: ComponentObject,
                  dynamic: [FullImageFileUnit: Data]) throws {
        guard source.planSHA256 == planSHA256,
              intent.workerPolicy.device == device, intent.servicePlist.device == device,
              RuntimeUpgradeHistoricalObjectBinding.matches(recorded: intent.workerPolicy, observed: observedWorker,
                  recordedDevice: device, currentDevice: currentDevice),
              RuntimeUpgradeHistoricalObjectBinding.matches(recorded: intent.servicePlist, observed: observedService,
                  recordedDevice: device, currentDevice: currentDevice),
              RuntimeUpgradeHistoricalObjectBinding.matches(recorded: workerPolicy, observed: observedWorker,
                  recordedDevice: currentDevice, currentDevice: currentDevice),
              RuntimeUpgradeHistoricalObjectBinding.matches(recorded: servicePlist, observed: observedService,
                  recordedDevice: currentDevice, currentDevice: currentDevice) else {
            throw FullImageFailure.object
        }
        try intent.validate(source: source, predecessorEvidenceSHA256: proofSHA256,
            workerPolicy: intent.workerPolicy, servicePlist: intent.servicePlist,
            ownerUID: ownerUID, brokerUID: brokerUID, publicOwner: publicOwner,
            publicGroup: publicGroup, beforeGroup: beforeGroup, device: device, dynamic: dynamic)
    }

}

extension ComponentController {
    private static func runtimeDeltaPayloadTree(_ source: RuntimeUpgradeSource) throws -> InstallerPayloadTree {
        guard source.directRuntimeDelta, let complete = source.after.trees[InstallerPayloadManifest.support] else {
            throw FullImageFailure.source
        }
        var included: Set<String> = [""]
        for unit in source.units {
            switch unit {
            case .tree(let tree, _, let after):
                guard tree.runtimeUpgrade == false, PublicTreeUnit.directRuntimeDeltaCases.contains(tree) else {
                    throw FullImageFailure.source
                }
                if after.isPresent { included.formUnion(complete.nodes.keys.filter { $0 == tree.path || $0.hasPrefix(tree.path + "/") }) }
            case .file(_, _, let after):
                if after != nil { included.insert(unit.path) }
            case .directFile(_, _, _, let after):
                if after != nil { included.insert(unit.path) }
            }
        }
        // Add all explicit manifest parents. They remain unchanged public
        // directories and are necessary to validate the sparse payload root.
        for path in Array(included).filter({ !$0.isEmpty }) {
            let parts = try InstallerPayloadManifest.components(path)
            if parts.count > 1 {
                for count in 1..<parts.count { included.insert(parts.prefix(count).joined(separator: "/")) }
            }
        }
        var nodes: [String: InstallerPayloadNode] = [:]
        for path in included {
            guard let node = complete.nodes[path], node.kind == "directory" || node.kind == "file" else {
                throw FullImageFailure.source
            }
            nodes[path] = node
        }
        var children: [String: Set<String>] = [:]
        for path in nodes.keys where !path.isEmpty {
            let parts = try InstallerPayloadManifest.components(path)
            children[parts.dropLast().joined(separator: "/"), default: []].insert(parts.last!)
        }
        return InstallerPayloadTree(nodes: nodes, children: children)
    }
    private static func verifyRuntimeDeltaPayload(_ payload: Int32, source: RuntimeUpgradeSource) throws {
        let tree = try runtimeDeltaPayloadTree(source)
        _ = try InstallerPayloadIO.verify(payload, tree: tree, owner: 0)
    }
    private static func runtimeDeltaSignatures(_ source: RuntimeUpgradeSource, root: String) throws {
        for kind in ["broker", "bootstrap"] {
            let path = root + "/bin/AccountAccess-" + kind
            guard let peer = source.newPeers[kind] else { throw FullImageFailure.source }
            try ComponentUpdateIdentity.verifyStatic(path: path, peer: peer, designated: nil)
        }
        try ComponentUpdateIdentity.verifyStaticPublisher(path: root + "/bin/AccountAccess-installerverify",
            team: "WBULD6N4NQ", identifier: "com.fainir.accountaccess.installerverify")
    }
    private static func runtimeSource(_ resources: Int32, pins: RuntimeUpgradeSource.Pins) throws -> RuntimeUpgradeSource {
        if pins.direct {
            guard try InstallerPayloadIO.contents(resources) == ["RuntimeUpgradePlan.json", "BaseManifest.json", "TargetManifest.json",
                "BaseIdentity.json", "TargetIdentity.json", "TargetImage", "AccountAccess-runtimeupgrade", "postinstall"] else {
                throw FullImageFailure.source
            }
            let raw = try fullRead(resources, "RuntimeUpgradePlan.json", maximum: 2 * InstallerPayloadManifest.maximumManifest + 256 * 1024)
            let plan = try FullImageJSON.object(raw, maximum: 2 * InstallerPayloadManifest.maximumManifest + 256 * 1024)
            let beforeRaw = try fullRead(resources, "BaseManifest.json", maximum: InstallerPayloadManifest.maximumManifest)
            let afterRaw = try fullRead(resources, "TargetManifest.json", maximum: InstallerPayloadManifest.maximumManifest)
            let oldIdentity = try fullRead(resources, "BaseIdentity.json", maximum: 8192)
            let newIdentity = try fullRead(resources, "TargetIdentity.json", maximum: 8192)
            guard let files = plan["target_source_files"] as? [String: String] else { throw FullImageFailure.source }
            let direct = try DirectRuntimeUpgradeSource.load(plan: raw, before: beforeRaw, after: afterRaw,
                oldIdentity: oldIdentity, newIdentity: newIdentity,
                pins: .init(planSHA256: pins.planSHA256, beforeSHA256: pins.beforeSHA256,
                    afterSHA256: pins.afterSHA256, targetSourceCommit: pins.targetSource))
            let mappedPins = RuntimeUpgradeSource.Pins(planSHA256: direct.planSHA256,
                beforeSHA256: direct.before.sha256, afterSHA256: direct.after.sha256,
                repairPlan: String(repeating: "0", count: 64), repairSource: String(repeating: "0", count: 40),
                targetSource: direct.targetSourceCommit, sourceFiles: files, direct: true)
            return RuntimeUpgradeSource(pins: mappedPins, before: direct.before, after: direct.after,
                oldPeers: direct.oldPeers, newPeers: direct.newPeers, units: direct.units, changed: direct.changed)
        }
        guard try InstallerPayloadIO.contents(resources) == ["RuntimeUpgradePlan.json", "BaseManifest.json", "TargetManifest.json",
            "BaseIdentity.json", "TargetIdentity.json", "Predecessor", "TargetImage", "AccountAccess-runtimeupgrade", "postinstall"] else {
            throw FullImageFailure.source
        }
        return try RuntimeUpgradeSource.load(pins: pins,
            plan: fullRead(resources, "RuntimeUpgradePlan.json", maximum: 34 * 1024 * 1024),
            before: fullRead(resources, "BaseManifest.json", maximum: InstallerPayloadManifest.maximumManifest),
            after: fullRead(resources, "TargetManifest.json", maximum: InstallerPayloadManifest.maximumManifest),
            oldIdentity: fullRead(resources, "BaseIdentity.json", maximum: 8192),
            newIdentity: fullRead(resources, "TargetIdentity.json", maximum: 8192))
    }
    private static func runtimeSignatures(_ source: RuntimeUpgradeSource, root: String, after: Bool) throws {
        let peers = after ? source.newPeers : source.oldPeers
        for kind in ["owner", "broker", "bootstrap"] {
            let relative = kind == "owner" ? "owner.app" : "bin/AccountAccess-" + kind
            try ComponentUpdateIdentity.verifyStatic(path: root + "/" + relative, peer: peers[kind]!, designated: nil)
        }
        try ComponentUpdateIdentity.verifyStaticPublisher(path: root + "/bin/AccountAccess-installerverify",
            team: "WBULD6N4NQ", identifier: "com.fainir.accountaccess.installerverify")
    }
    private static func runtimePolicy(source: RuntimeUpgradeSource, predecessor: BrokerRepairSource?,
            install: Data, host: Data, profile: Data, worker: Data, ownerUID: uid_t) throws -> ComponentPolicyResult {
        if source.directRuntimeDelta {
            return try runtimeDirectPolicy(source: source, install: install, host: host, profile: profile,
                worker: worker, ownerUID: ownerUID)
        }
        guard let predecessor else { throw FullImageFailure.predecessor }
        let oldFingerprint = try FullImagePolicyFingerprint.value(source.oldPeers)
        guard oldFingerprint == predecessor.newFingerprint else { throw FullImageFailure.predecessor }
        return try FullImageUpdatePolicies.derive(install: install, host: host, owner: profile, worker: worker,
            oldPeers: source.oldPeers, newPeers: source.newPeers, oldFingerprint: oldFingerprint,
            newFingerprint: FullImagePolicyFingerprint.value(source.newPeers), consoleOwner: ownerUID)
    }
    private static func runtimeDirectPolicy(source: RuntimeUpgradeSource, install: Data, host: Data,
            profile: Data, worker: Data, ownerUID: uid_t) throws -> ComponentPolicyResult {
        guard source.directRuntimeDelta else { throw FullImageFailure.source }
        let oldFingerprint = try FullImagePolicyFingerprint.value(source.oldPeers)
        let newFingerprint = try FullImagePolicyFingerprint.value(source.newPeers)
        return try FullImageUpdatePolicies.derive(install: install, host: host, owner: profile, worker: worker,
            oldPeers: source.oldPeers, newPeers: source.newPeers, oldFingerprint: oldFingerprint,
            newFingerprint: newFingerprint, consoleOwner: ownerUID)
    }
    // Read only one of five fixed predecessor metadata files from either its
    // exact current inode or the successor's exact retained inode. Reversed,
    // missing, substituted and partially written objects all refuse.
    private static func runtimeOriginal(_ unit: FullImageFileUnit, intent: FullImageGlobalIntent,
            files: FullImageAttachedDirectory, routes: FullImageInstalledRoutes) throws -> (Data, ComponentObject) {
        guard [.packageIdentity, .repairIdentityRemoval, .hostPolicy, .ownerPolicy, .installRecord].contains(unit) else {
            throw FullImageFailure.journal
        }
        let records = intent.operations.compactMap(\.file).filter { $0.unit == unit }
        guard records.count == 1, let operation = records.first, let before = operation.before,
              operation.planSHA256 == intent.planSHA256 else { throw FullImageFailure.journal }
        let storage = try FullImageFileStorage(operation: operation, retained: files.fd, owner: 0,
            resolve: routes.resolve, verifyAttachments: { try routes.verify() }, requireQuiescent: { throw FullImageFailure.journal })
        let read: (Data, ComponentObject)
        switch try storage.state() {
        case .staged:
            let (parent, name) = try routes.resolve(unit); defer { Darwin.close(parent) }
            read = try ComponentFiles.read(parent, name, owner: 0, mode: mode_t(unit.mode))
        case .applied: read = try ComponentFiles.read(files.fd, operation.slot, owner: 0, mode: mode_t(unit.mode))
        case .conflict: throw FullImageFailure.journal
        }
        guard read.1 == before else { throw FullImageFailure.journal }
        return read
    }
}

extension ComponentController {
    static func runRuntimeUpgrade(resources: Int32, pins: RuntimeUpgradeSource.Pins,
            repairPins: BrokerRepairSource.Pins, predecessorPins: FullImageSourcePins,
            checkpoint: (FullImageInstallCheckpoint) -> Void = { _ in }) throws -> String {
        checkpoint(.context)
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        checkpoint(.source)
        let source = try runtimeSource(resources, pins: pins)
        var predecessorResources: Int32?
        defer { if let predecessorResources { Darwin.close(predecessorResources) } }
        let predecessor: BrokerRepairSource?
        if source.directRuntimeDelta {
            guard pins.direct, repairPins.planSHA256 == String(repeating: "0", count: 64),
                  predecessorPins.planSHA256 == String(repeating: "0", count: 64) else { throw FullImageFailure.source }
            predecessorResources = nil; predecessor = nil
        } else {
            let selected = try fullResourceDirectory(resources, "Predecessor")
            predecessorResources = selected
            let repair = try repairSource(selected, pins: repairPins)
            guard pins.repairPlan == repairPins.planSHA256, pins.repairSource == repairPins.sourceCommit,
                  repair.after.sha256 == source.before.sha256, repair.newPeers == source.oldPeers,
                  repairPins.predecessorPlanSHA256 == predecessorPins.planSHA256,
                  repairPins.beforeManifestSHA256 == predecessorPins.targetManifestSHA256 else { throw FullImageFailure.predecessor }
            predecessor = repair
        }
        checkpoint(.payload)
        let image = try fullResourceDirectory(resources, "TargetImage"); defer { Darwin.close(image) }
        if source.directRuntimeDelta {
            let delta = try InstallerPayloadIO.walkDirectory(InstallerPayloadManifest.support, from: image, owner: 0)
            defer { Darwin.close(delta) }
            try verifyRuntimeDeltaPayload(delta, source: source)
        } else { _ = try InstallerPayloadIO.verifyImage(image, manifest: source.after, owner: 0) }
        let payload = try InstallerPayloadIO.walkDirectory(InstallerPayloadManifest.support, from: image, owner: 0)
        defer { Darwin.close(payload) }
        let payloadPath = try FullImageFDCanonicalPath.installed(payload)
        try payloadPath.checked {
            if source.directRuntimeDelta { try runtimeDeltaSignatures(source, root: $0) }
            else { try runtimeSignatures(source, root: $0, after: true) }
        }
        if source.directRuntimeDelta {
            try verifyRuntimeDeltaPayload(payload, source: source)
        } else { _ = try InstallerPayloadIO.verifyImage(image, manifest: source.after, owner: 0) }

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
        let namespaceKind: PublicImageNamespace = source.directRuntimeDelta ? .directRuntimeRecovery : .runtimeUpgrade
        let namespace = try FullImageNamespaceDirectory.installed(library, kind: namespaceKind); defer { Darwin.close(namespace) }
        let routes = try FullImageInstalledRoutes.installed(kind: namespaceKind)
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
                diagnosticContext: .runtimeUpgrade,
                validateIntent: { try fullPreliminary($0, source: source, ownerUID: ownerUID) }, verifyAttachment: global.verify)
        } else { preliminary = nil }
        let observationDevice: Int32? = nil
        checkpoint(.predecessor)
        let worker = try publicRead("broker/worker.json", mode: 0o644), plist = try jobPlist(ownerGroup: ownerGroup)
        let currentDevice = support.identity.device
        let device = observationDevice ?? currentDevice
        func matches(_ observed: ComponentObject, _ recorded: ComponentObject) -> Bool {
            guard observationDevice != nil else { return observed == recorded }
            return recorded.device == device && observed.device == currentDevice
                && observed == ComponentObject(device: currentDevice, inode: recorded.inode,
                    mode: recorded.mode, bytes: recorded.bytes, sha256: recorded.sha256)
        }
        if !hasIntent {
            _ = try InstallerPayloadIO.installedImage(source.before, opaquePrivateBranches: true)
            try runtimeSignatures(source, root: InstallerPayloadManifest.support, after: false)
        }
        var directOriginals: (install: Data, host: Data, profile: Data)?
        var predecessorProof: CompletedBrokerRepairProof?
        let authority: RuntimeUpgradeAuthority
        if source.directRuntimeDelta {
            func original(_ unit: FullImageFileUnit, publicPath: String, mode: mode_t) throws -> Data {
                if let preliminary {
                    let selected = preliminary.operations.compactMap(\.file).filter { $0.unit == unit }
                    guard selected.count == 1, let operation = selected.first else { throw FullImageFailure.journal }
                    let retained = try routes.files(plan: pins.planSHA256)
                    return try fullOriginal(operation, files: retained, routes: routes, observationDevice: observationDevice)
                }
                return try publicRead(publicPath, mode: mode).0
            }
            let install = try original(.installRecord, publicPath: "broker/install.json", mode: 0o600)
            let host = try original(.hostPolicy, publicPath: "broker/host.json", mode: 0o644)
            let profile = try original(.ownerPolicy, publicPath: "owner.json", mode: 0o644)
            let policy = try runtimeDirectPolicy(source: source, install: install, host: host,
                profile: profile, worker: worker.0, ownerUID: ownerUID)
            directOriginals = (install, host, profile)
            authority = try RuntimeUpgradeAuthority.bindDirect(source: source, install: install, host: host,
                profile: profile, ownerUID: ownerUID, brokerUID: policy.brokerUID,
                workerPolicy: worker.1, servicePlist: plist)
        } else {
            guard let predecessorResources else { throw FullImageFailure.predecessor }
            let proof: CompletedBrokerRepairProof
            if let preliminary {
                let retained = try routes.files(plan: pins.planSHA256)
                proof = try completedBrokerRepairLocked(resources: predecessorResources, pins: repairPins,
                    predecessorPins: predecessorPins, expectedEvidenceSHA256: preliminary.predecessorEvidenceSHA256,
                    historical: { try runtimeOriginal($0, intent: preliminary, files: retained, routes: routes) })
            } else {
                proof = try completedBrokerRepairLocked(resources: predecessorResources, pins: repairPins,
                    predecessorPins: predecessorPins)
            }
            predecessorProof = proof
            authority = try RuntimeUpgradeAuthority.bind(source: source, proof: proof)
            guard authority.ownerUID == ownerUID else { throw FullImageFailure.predecessor }
            try identity(ownerUID, authority.brokerUID)
        }
        try identity(ownerUID, authority.brokerUID)
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
            let policy = try runtimePolicy(source: source, predecessor: predecessor, install: install.0, host: host.0,
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
                case .directFile(let path, let mode, let beforeNode, let afterNode):
                    guard source.directRuntimeDelta, (mode == 0o644 || mode == 0o755) else { throw FullImageFailure.source }
                    checkpoint(.preparationFileStage)
                    let unit = FullImageFileUnit.directPublicFile, slot = String(format: "slot-%02d", index)
                    let (parent, name) = try routes.resolveDirectPublicFile(path); defer { Darwin.close(parent) }
                    let before = try ComponentFiles.observe(parent, name, owner: 0); try fullMatches(before, beforeNode)
                    if let afterNode {
                        let input = try fullPayloadParent(payload, path); defer { Darwin.close(input.0) }
                        try FullImagePublicStager.copyFile(from: input.0, name: input.1, to: files, slot: slot, node: afterNode, owner: 0, group: 0)
                    }
                    let after = try ComponentFiles.observe(files, slot, owner: 0); try fullMatches(after, afterNode)
                    operations.append(FullImageDurableOperation(file: FullImageFileOperation(schema: 1, unit: unit,
                        planSHA256: pins.planSHA256, index: index, before: before, after: after,
                        directPath: path, directMode: mode)))
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
            let candidate = FullImageGlobalIntent(schema: 2, managedBy: source.directRuntimeDelta
                    ? "account-access-exact-installed-runtime-delta-v1" : "account-access-full-image-transition-v2",
                planSHA256: pins.planSHA256, beforeManifestSHA256: source.before.sha256, afterManifestSHA256: source.after.sha256,
                targetSourceCommit: pins.targetSource, predecessorEvidenceSHA256: authority.proofSHA256,
                ownerUID: ownerUID, brokerUID: authority.brokerUID, initialService: initial,
                workerPolicy: worker.1, servicePlist: plist, operations: operations, automaticRebootRecovery: false)
            checkpoint(.preparationAuthority)
            try authority.validate(candidate, source: source, publicOwner: 0, publicGroup: 0, beforeGroup: beforeGroup, device: device, dynamic: dynamic)
            checkpoint(.preparationPredecessor)
            if source.directRuntimeDelta {
                let refreshed = try RuntimeUpgradeAuthority.bindDirect(source: source, install: install.0,
                    host: host.0, profile: profile.0, ownerUID: ownerUID, brokerUID: policy.brokerUID,
                    workerPolicy: worker.1, servicePlist: plist)
                guard refreshed.proofSHA256 == authority.proofSHA256 else { throw FullImageFailure.predecessor }
            } else {
                guard let predecessorResources else { throw FullImageFailure.predecessor }
                let rechecked = try completedBrokerRepairLocked(resources: predecessorResources, pins: repairPins,
                    predecessorPins: predecessorPins)
                guard let predecessorProof, rechecked.sha256 == predecessorProof.sha256 else { throw FullImageFailure.predecessor }
            }
            checkpoint(.preparationPayload)
            if source.directRuntimeDelta { try verifyRuntimeDeltaPayload(payload, source: source) }
            else { _ = try InstallerPayloadIO.verifyImage(image, manifest: source.after, owner: 0) }
            // This journal is closed before its parent is renamed. Reopen below
            // qualifies the final canonical route rather than adopting the old
            // preparation route after publication.
            do {
                checkpoint(.preparationJournal)
                let temporary = try routes.preparing(preparingName, plan: pins.planSHA256)
                _ = try FullImageGlobalJournal.open(directory: global, owner: 0, group: 0, beforeGroup: beforeGroup, expected: candidate,
                    validateIntent: { try authority.validate($0, source: source, publicOwner: 0, publicGroup: 0, beforeGroup: beforeGroup, device: device, dynamic: dynamic) },
                    verifyAttachment: temporary.verify)
            }
            try routes.verify()
            checkpoint(.preparationPublish)
            try ComponentPreparation.publish(namespace, name: preparingName, directory: preparing, plan: pins.planSHA256, owner: 0)
            intent = candidate
        }

        checkpoint(.journal)
        let files = try routes.files(plan: pins.planSHA256), global = try routes.globalJournal(plan: pins.planSHA256)
        let dynamicFiles = intent.operations.suffix(4).compactMap(\.file)
        guard dynamicFiles.map(\.unit) == [.hostPolicy, .ownerPolicy, .installRecord, .head] else { throw FullImageFailure.journal }
        let policy = try runtimePolicy(source: source, predecessor: predecessor,
            install: fullOriginal(dynamicFiles[2], files: files, routes: routes, observationDevice: observationDevice),
            host: fullOriginal(dynamicFiles[0], files: files, routes: routes, observationDevice: observationDevice),
            profile: fullOriginal(dynamicFiles[1], files: files, routes: routes, observationDevice: observationDevice), worker: worker.0, ownerUID: ownerUID)
        guard policy.brokerUID == authority.brokerUID else { throw FullImageFailure.predecessor }
        let dynamic = try fullDynamic(policy, source: source, proofSHA256: authority.proofSHA256)
        let journal = try FullImageGlobalJournal.open(directory: global.fd, owner: 0, group: 0, beforeGroup: beforeGroup, expected: intent,
            validateIntent: { try authority.validate($0, source: source, publicOwner: 0, publicGroup: 0, beforeGroup: beforeGroup, device: device, dynamic: dynamic) },
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
                    resolve: routes.resolve, resolveDirect: routes.resolveDirectPublicFile,
                    verifyAttachments: { try routes.verify() }, requireQuiescent: barrier.requireDisabledAndQuiescent,
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
            if source.directRuntimeDelta {
                guard let directOriginals else { throw FullImageFailure.predecessor }
                let proof = try RuntimeUpgradeAuthority.bindDirect(source: source, install: directOriginals.install,
                    host: directOriginals.host, profile: directOriginals.profile, ownerUID: ownerUID,
                    brokerUID: authority.brokerUID, workerPolicy: intent.workerPolicy, servicePlist: intent.servicePlist)
                guard proof.proofSHA256 == intent.predecessorEvidenceSHA256 else { throw FullImageFailure.predecessor }
            } else {
                guard let predecessorResources else { throw FullImageFailure.predecessor }
                _ = try completedBrokerRepairLocked(resources: predecessorResources, pins: repairPins,
                    predecessorPins: predecessorPins, expectedEvidenceSHA256: intent.predecessorEvidenceSHA256,
                    historical: { try runtimeOriginal($0, intent: intent, files: files, routes: routes) })
            }
        }
        func verifyPublic(_ operationStates: [ComponentOperationState], completeImage: Bool) throws {
            guard let storage = reference.storage else { throw FullImageFailure.journal }
            try verifyUnchanged()
            try fullLayout(source: source, routes: routes, storage: storage, intent: intent, states: operationStates)
            let states = Array(operationStates.prefix(source.units.count))
            if completeImage { try FullImagePublicView.verify(source: source, states: states, support: support.fd, owner: 0) }
            if let ownerIndex = source.units.firstIndex(where: { $0.path == PublicTreeUnit.owner.path }) {
                try runtimeSignatures(source, root: InstallerPayloadManifest.support, after: states[ownerIndex] == .applied)
            } else if source.directRuntimeDelta {
                if completeImage {
                    try runtimeSignatures(source, root: InstallerPayloadManifest.support, after: true)
                } else if states.allSatisfy({ $0 == .staged }) {
                    try runtimeSignatures(source, root: InstallerPayloadManifest.support, after: false)
                }
            } else { throw FullImageFailure.source }
            let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0 else { throw FullImageFailure.object }; defer { Darwin.close(root) }
            _ = try InstallerPayloadIO.verifyApplicationAlias(from: root, owner: 0)
            try routes.verify()
        }
        let storage = try FullImageMixedStorage(units: units, writeEvent: { event, operation in
            guard let storage = reference.storage else { throw FullImageFailure.journal }
            try journal.writeTransition(event, operation: operation, state: storage.state)
        }, verifyOld: { try verifyPublic($0, completeImage: false) },
           verifyRecoverable: { try verifyPublic($0, completeImage: false) },
           verifyNew: { try verifyPublic($0, completeImage: true) })
        reference.storage = storage
        try intent.verifyStorage(storage)
        func repairPublicAliases() throws {
            // Package95 requires a normal restart. The already-running broker
            // may retain its earlier startup failure; this path never restarts
            // it, changes its journal, or presents metadata repair as GUI QA.
            checkpoint(.verificationFinalView)
            guard let tree = source.after.trees[InstallerPayloadManifest.support] else { throw FullImageFailure.source }
            try storage.verifyNewView()
            _ = try RuntimePublicAliasPermissions.repair(support: support.fd, tree: tree, owner: 0, group: 0,
                verifyBinding: { try routes.verify(); try ComponentProcesses.requireOwnerClosed() })
            try storage.verifyNewView()
        }
        if try storage.state(storage.operations.last!) == .applied {
            guard try storage.operations.allSatisfy({ try storage.state($0) == .applied }) else { throw FullImageFailure.journal }
            try storage.verifyNewView()
            if recovery.finished {
                try repairPublicAliases()
                checkpoint(.complete)
                return "ALREADY_UPDATED_GUI_UNVERIFIED"
            }
        }
        try ComponentPreparation.capacity(namespace, bytes: 2 * 1024 * 1024, owner: 0, sameDeviceAs: support.fd)
        checkpoint(.transition)
        _ = try ComponentTransition(storage: storage, service: barrier).run(recovering: hasIntent)
        try repairPublicAliases()
        checkpoint(.complete)
        return "UPDATED_GUI_UNVERIFIED"
    }
}
