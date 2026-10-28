
// Candidate fixed complete-image wiring, appended to the exact qualified
// ComponentUpdate + completed-predecessor source so private existing helpers
// remain private and their predicates are reused unchanged. No main is added.
enum FullImageInstallCheckpoint: String, CaseIterable {
    case source, payload, context, predecessor, preparation, journal, transition, complete
    case predecessorRuntimeSource = "predecessor_runtime_source"
    case predecessorRepairSource = "predecessor_repair_source"
    case predecessorNamespace = "predecessor_namespace"
    case predecessorIntent = "predecessor_intent"
    case predecessorRepairHistory = "predecessor_repair_history"
    case predecessorRepairRoute = "predecessor_repair_route"
    case predecessorRepairIntent = "predecessor_repair_intent"
    case predecessorRepairEvidence = "predecessor_repair_evidence"
    case predecessorComponentRevalidation = "predecessor_component_revalidation"
    case predecessorRepairStability = "predecessor_repair_stability"
    case predecessorAuthority = "predecessor_authority"
    case predecessorPolicy = "predecessor_policy"
    case predecessorStorage = "predecessor_storage"
    case predecessorView = "predecessor_view"
    case predecessorViewRoutes = "predecessor_view_routes"
    case predecessorViewOwner = "predecessor_view_owner"
    case predecessorViewPolicies = "predecessor_view_policies"
    case predecessorViewJournal = "predecessor_view_journal"
    case predecessorViewOriginalReceipt = "predecessor_view_original_receipt"
    case predecessorViewRepairProof = "predecessor_view_repair_proof"
    case predecessorViewBefore = "predecessor_view_before"
    case predecessorViewStates = "predecessor_view_states"
    case predecessorViewLayout = "predecessor_view_layout"
    case predecessorViewProjection = "predecessor_view_projection"
    case predecessorViewAfter = "predecessor_view_after"
    case predecessorEvidence = "predecessor_evidence"
    case preparationCapacity = "preparation_capacity", preparationPolicy = "preparation_policy"
    case preparationDynamic = "preparation_dynamic", preparationBegin = "preparation_begin"
    case preparationFileStage = "preparation_file_stage", preparationTreeStage = "preparation_tree_stage"
    case preparationTreeCapture = "preparation_tree_capture", preparationDynamicStage = "preparation_dynamic_stage"
    case preparationService = "preparation_service", preparationAuthority = "preparation_authority"
    case preparationPredecessor = "preparation_predecessor_recheck", preparationPayload = "preparation_payload_recheck"
    case preparationJournal = "preparation_journal", preparationPublish = "preparation_publish"
    case verificationFirstView = "verification_first_view", verificationEvidence = "verification_evidence"
    case verificationFinalView = "verification_final_view"
}
private final class FullImageStorageReference {
    weak var storage: FullImageMixedStorage?
}
// An installed successor can obtain this only after the existing transition's
// complete public image, retained objects and history all verify. It has no
// ordinary constructor and makes no claim about GUI/account readiness.
struct CompletedFullImageProof {
    let evidence: Data
    var sha256: String { FullImageJSON.hash(evidence) }
    let ownerUID: uid_t, brokerUID: uid_t
    fileprivate init(evidence: Data, ownerUID: uid_t, brokerUID: uid_t) {
        self.evidence = evidence; self.ownerUID = ownerUID; self.brokerUID = brokerUID
    }
}
private enum FullImageInstalledResult {
    case updated(String), completed(CompletedFullImageProof)
}
struct CompletedFullImageDiagnostic: Error {
    let checkpoint: FullImageInstallCheckpoint
    let failure: Error
}

extension ComponentController {
    private static func fullResourceDirectory(_ parent: Int32, _ name: String) throws -> Int32 {
        try ComponentFiles.name(name)
        var path = stat()
        guard fstatat(parent, name, &path, AT_SYMLINK_NOFOLLOW) == 0 else { throw FullImageFailure.source }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw FullImageFailure.source }
        do {
            let info = try InstallerPayloadIO.check(fd, owner: 0, directory: true)
            try PublicTreeIO.noACL(fd)
            guard info.st_gid == 0, info.st_mode & 0o7777 == 0o755, InstallerPayloadIO.same(path, info) else { throw FullImageFailure.source }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    private static func fullRead(_ parent: Int32, _ name: String, maximum: Int) throws -> Data {
        try ComponentFiles.name(name)
        let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw FullImageFailure.source }; defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: 0, directory: false)
        try PublicTreeIO.noACL(fd)
        guard before.st_gid == 0, before.st_mode & 0o7777 == 0o644 else { throw FullImageFailure.source }
        let data = try InstallerPayloadIO.read(fd, maximum: maximum, owner: 0)
        var current = stat()
        guard fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0, InstallerPayloadIO.same(before, current) else { throw FullImageFailure.source }
        return data
    }
    private static func fullResourceSet(_ resources: Int32) throws {
        let expected: Set<String> = ["FullImagePlan.json", "BaseManifest.json", "TargetManifest.json", "BaseIdentity.json",
            "TargetIdentity.json", "ProviderManifest.json", "RuntimeCAReceipt.json", "Predecessor", "TargetImage",
            "AccountAccess-fullimageupdate", "postinstall"]
        guard try InstallerPayloadIO.contents(resources) == expected else { throw FullImageFailure.source }
    }
    private static func fullSource(_ resources: Int32, pins: FullImageSourcePins) throws -> FullImageSource {
        try fullResourceSet(resources)
        return try FullImageSource.load(plan: fullRead(resources, "FullImagePlan.json", maximum: 34 * 1024 * 1024),
            before: fullRead(resources, "BaseManifest.json", maximum: InstallerPayloadManifest.maximumManifest),
            after: fullRead(resources, "TargetManifest.json", maximum: InstallerPayloadManifest.maximumManifest),
            oldIdentity: fullRead(resources, "BaseIdentity.json", maximum: 8192),
            newIdentity: fullRead(resources, "TargetIdentity.json", maximum: 8192),
            providerManifest: fullRead(resources, "ProviderManifest.json", maximum: 16384),
            caReceipt: fullRead(resources, "RuntimeCAReceipt.json", maximum: 16384), pins: pins)
    }
#if ACCOUNT_ACCESS_FULL_IMAGE_INSTALLED_CHECKS
    static func fixtureFullImageResourceSet(_ resources: Int32) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw ComponentUpdateFailure.context }
        try fullResourceSet(resources)
    }
#endif
    // Only enum-derived public paths reach this payload-relative walker.
    private static func fullPayloadParent(_ support: Int32, _ relative: String) throws -> (Int32, String) {
        let parts = try InstallerPayloadManifest.components(relative)
        guard !parts.isEmpty else { throw FullImageFailure.source }
        var current = fcntl(support, F_DUPFD_CLOEXEC, 0)
        guard current >= 0 else { throw FullImageFailure.source }
        do {
            for part in parts.dropLast() {
                let next = try fullResourceDirectory(current, part)
                Darwin.close(current); current = next
            }
            return (current, parts.last!)
        } catch { Darwin.close(current); throw error }
    }
    private static func fullMatches(_ object: ComponentObject?, _ node: InstallerPayloadNode?) throws {
        guard let node else { guard object == nil else { throw FullImageFailure.object }; return }
        guard let object, node.kind == "file", object.mode == node.mode,
              object.bytes == node.size, object.sha256 == node.sha256 else { throw FullImageFailure.object }
    }
    private static func fullPolicy(source: FullImageSource, predecessor: ComponentSource, install: Data,
                                   host: Data, profile: Data, worker: Data, ownerUID: uid_t) throws -> ComponentPolicyResult {
        let oldFingerprint = try FullImagePolicyFingerprint.value(source.oldPeers)
        guard oldFingerprint == predecessor.newFingerprint else { throw FullImageFailure.predecessor }
        return try FullImageUpdatePolicies.derive(install: install, host: host, owner: profile, worker: worker,
            oldPeers: source.oldPeers, newPeers: source.newPeers, oldFingerprint: oldFingerprint,
            newFingerprint: FullImagePolicyFingerprint.value(source.newPeers), consoleOwner: ownerUID)
    }
    private static func fullDynamic(_ policy: ComponentPolicyResult, source: any PublicImageTransitionSource,
                                    proofSHA256: String) throws -> [FullImageFileUnit: Data] {
        [.hostPolicy: policy.host, .ownerPolicy: policy.owner, .installRecord: policy.install,
         .head: try FullImageGlobalIntent.newHead(source: source, predecessorEvidenceSHA256: proofSHA256)]
    }
    private static func fullOriginal(_ operation: FullImageFileOperation, files: FullImageAttachedDirectory,
                                     routes: FullImageInstalledRoutes, observationDevice: Int32? = nil) throws -> Data {
        guard [.hostPolicy, .ownerPolicy, .installRecord].contains(operation.unit), let before = operation.before else { throw FullImageFailure.journal }
        let storage = try FullImageFileStorage(operation: operation, retained: files.fd, owner: 0,
            resolve: routes.resolve, verifyAttachments: { try routes.verify() }, requireQuiescent: { throw FullImageFailure.journal },
            observationDevice: observationDevice)
        switch try storage.state() {
        case .staged:
            let (parent, name) = try routes.resolve(operation.unit); defer { Darwin.close(parent) }
            let read = try ComponentFiles.read(parent, name, owner: 0, mode: mode_t(operation.unit.mode))
            guard storage.matches(read.1, before) else { throw FullImageFailure.journal }; return read.0
        case .applied:
            let read = try ComponentFiles.read(files.fd, operation.slot, owner: 0, mode: mode_t(operation.unit.mode))
            guard storage.matches(read.1, before) else { throw FullImageFailure.journal }; return read.0
        case .conflict: throw FullImageFailure.journal
        }
    }
    private static func fullVerifySignatures(source: FullImageSource, root: String, after: Bool) throws {
        let peers = after ? source.newPeers : source.oldPeers
        for kind in ["owner", "broker", "bootstrap"] {
            guard let peer = peers[kind], let designated = source.designatedRequirements[kind] else { throw FullImageFailure.source }
            let relative = kind == "owner" ? "owner.app" : "bin/AccountAccess-" + kind
            try ComponentUpdateIdentity.verifyStatic(path: root + "/" + relative, peer: peer, designated: designated)
        }
    }
    private static func fullPreliminary(_ intent: FullImageGlobalIntent, source: any PublicImageTransitionSource, ownerUID: uid_t) throws {
        // Structure, protected inode, canonical bytes and attachment are checked
        // by readIntent. This is only enough to obtain the evidence digest for
        // opaque predecessor revalidation. Full authority/dynamic validation is
        // mandatory below before opening any transition storage or service.
        guard intent.planSHA256 == source.planSHA256, intent.beforeManifestSHA256 == source.before.sha256,
              intent.afterManifestSHA256 == source.after.sha256, intent.targetSourceCommit == source.targetSourceCommit,
              intent.ownerUID == ownerUID, intent.operations.count == source.units.count + 4 else { throw FullImageFailure.journal }
    }
    private static func fullLayout(source: any PublicImageTransitionSource, routes: FullImageInstalledRoutes,
                                    storage: FullImageMixedStorage, intent: FullImageGlobalIntent) throws {
        let transition = try routes.transition(plan: source.planSHA256)
        guard try InstallerPayloadIO.contents(transition.fd) == ["files", "trees", "global"] else { throw FullImageFailure.journal }
        let trees = openat(transition.fd, "trees", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard trees >= 0 else { throw FullImageFailure.journal }; defer { Darwin.close(trees) }
        let info = try InstallerPayloadIO.check(trees, owner: 0, directory: true); try PublicTreeIO.noACL(trees)
        guard info.st_gid == 0, info.st_mode & 0o7777 == 0o700,
              try InstallerPayloadIO.contents(trees) == Set(source.units.compactMap { if case .tree(let unit, _, _) = $0 { return unit.rawValue }; return nil }) else { throw FullImageFailure.journal }
        var fileSlots: Set<String> = []
        for (index, operation) in intent.operations.enumerated() {
            let state = try storage.state(storage.operations[index])
            guard state != .conflict else { throw FullImageFailure.object }
            if let file = operation.file {
                if (state == .staged ? file.after : file.before) != nil { fileSlots.insert(file.slot) }
            } else {
                guard let record = operation.tree, let unit = PublicTreeUnit(rawValue: record.unit) else { throw FullImageFailure.journal }
                let parent = openat(trees, unit.rawValue, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard parent >= 0 else { throw FullImageFailure.journal }; defer { Darwin.close(parent) }
                let pin = try InstallerPayloadIO.check(parent, owner: 0, directory: true); try PublicTreeIO.noACL(parent)
                guard pin.st_gid == 0, pin.st_mode & 0o7777 == 0o700,
                      try InstallerPayloadIO.contents(parent) == ["retained", "journal"] else { throw FullImageFailure.journal }
                let retained = try routes.retained(unit, plan: source.planSHA256)
                let present = (state == .staged ? record.after : record.before) != nil
                guard try InstallerPayloadIO.contents(retained.fd) == (present ? [unit.slot] : []) else { throw FullImageFailure.journal }
            }
        }
        guard try InstallerPayloadIO.contents(routes.files(plan: source.planSHA256).fd) == fileSlots else { throw FullImageFailure.journal }
        try routes.verify()
    }

    // Called only by a future sealed Installer entrypoint with compiled pins.
    // The target image and predecessor resources are fixed children of that
    // package's protected resource FD; no environment/path/JSON destination.
    static func runFullImage(resources: Int32, pins: FullImageSourcePins,
                             checkpoint: (FullImageInstallCheckpoint) -> Void = { _ in }) throws -> String {
        guard case .updated(let status) = try fullImage(resources: resources, pins: pins,
            verificationOnly: false, checkpoint: checkpoint) else { throw FullImageFailure.predecessor }
        return status
    }
    static func completedFullImage(resources: Int32, pins: FullImageSourcePins,
                                  checkpoint: (FullImageInstallCheckpoint) -> Void = { _ in }) throws -> CompletedFullImageProof {
        var stage = FullImageInstallCheckpoint.context
        do {
            guard case .completed(let proof) = try fullImage(resources: resources, pins: pins,
                verificationOnly: true, checkpoint: { stage = $0; checkpoint($0) }) else { throw FullImageFailure.predecessor }
            return proof
        } catch { throw CompletedFullImageDiagnostic(checkpoint: stage, failure: error) }
    }
    private static func fullImage(resources: Int32, pins: FullImageSourcePins, verificationOnly: Bool,
                                  checkpoint: (FullImageInstallCheckpoint) -> Void) throws -> FullImageInstalledResult {
        checkpoint(.context)
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        checkpoint(.source)
        let source = try fullSource(resources, pins: pins)
        let predecessorResources = try fullResourceDirectory(resources, "Predecessor")
        defer { Darwin.close(predecessorResources) }
        let predecessor = try ComponentSource.load(predecessorResources, planPin: pins.predecessor.planSHA256)
        guard predecessor.newManifest.sha256 == source.before.sha256, predecessor.newPeers == source.oldPeers,
              predecessor.oldManifest.sha256 == pins.predecessor.originalManifestSHA256 else { throw FullImageFailure.predecessor }
        checkpoint(.payload)
        let image = try fullResourceDirectory(resources, "TargetImage"); defer { Darwin.close(image) }
        _ = try InstallerPayloadIO.verifyImage(image, manifest: source.after, owner: 0)
        let payload = try InstallerPayloadIO.walkDirectory(InstallerPayloadManifest.support, from: image, owner: 0)
        defer { Darwin.close(payload) }
        let payloadPath = try FullImageFDCanonicalPath.installed(payload)
        try payloadPath.checked { try fullVerifySignatures(source: source, root: $0, after: true) }
        _ = try InstallerPayloadIO.verifyImage(image, manifest: source.after, owner: 0)

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
        let namespace = try FullImageNamespaceDirectory.installed(library, create: !verificationOnly); defer { Darwin.close(namespace) }
        let routes = try FullImageInstalledRoutes.installed()
        let support = try routes.support(), namespaceRoute = try routes.namespace()
        // The first full-image transition preserves the original public root.
        // Bind its qualified, unchanged group; never obtain legacy authority
        // from intent bytes or normalize an existing installed object.
        let beforeGroup = support.identity.group
        guard try InstallerPayloadIO.check(namespace, owner: 0, directory: true).st_ino == namespaceRoute.identity.inode else { throw FullImageFailure.object }
        let orphans = try FullImagePreparationInspector.retained(namespace, plan: pins.planSHA256, owner: 0, group: 0)
        let hasIntent = try InstallerPayloadIO.contents(namespace).contains("transition-" + pins.planSHA256)
        guard !verificationOnly || hasIntent else { throw FullImageFailure.predecessor }
        // This is exactly the first full-image transition. A foreign/newer head
        // cannot select another predecessor or authorize a second transition.
        if !hasIntent { guard try ComponentFiles.observe(namespace, "head.json", owner: 0) == nil else { throw FullImageFailure.journal } }
        let preliminary: FullImageGlobalIntent?
        if hasIntent {
            checkpoint(.journal)
            let global = try routes.globalJournal(plan: pins.planSHA256)
            preliminary = try FullImageGlobalJournal.readIntent(directory: global.fd, owner: 0, group: 0, beforeGroup: beforeGroup,
                historicalObservation: verificationOnly,
                diagnosticContext: .fullImage,
                validateIntent: { try fullPreliminary($0, source: source, ownerUID: ownerUID) }, verifyAttachment: global.verify)
        } else { preliminary = nil }
        // This mode never repairs an interrupted full-image transition. It can
        // only observe a fully completed transition after historical evidence
        // has been qualified by the persistent volume receipt below.
        let observationDevice: Int32? = verificationOnly ? preliminary?.workerPolicy.device : nil
        checkpoint(.predecessor)
        let proof: CompletedComponentProof
        if let preliminary {
            proof = try revalidateCompletedPredecessor(resources: predecessorResources, planPin: pins.predecessor.planSHA256,
                expectedEvidenceSHA256: preliminary.predecessorEvidenceSHA256, recordedDevice: observationDevice)
        } else { proof = try initialCompletedPredecessor(resources: predecessorResources, planPin: pins.predecessor.planSHA256) }
        let authority = try FullImagePredecessorAuthority.bind(source: source, proof: proof)
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
            let policy = try fullPolicy(source: source, predecessor: predecessor, install: install.0, host: host.0,
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
                targetSourceCommit: pins.targetSourceCommit, predecessorEvidenceSHA256: authority.proofSHA256,
                ownerUID: ownerUID, brokerUID: authority.brokerUID, initialService: initial,
                workerPolicy: worker.1, servicePlist: plist, operations: operations, automaticRebootRecovery: false)
            checkpoint(.preparationAuthority)
            try authority.validate(candidate, source: source, publicOwner: 0, publicGroup: 0, beforeGroup: beforeGroup, device: device, dynamic: dynamic)
            checkpoint(.preparationPredecessor)
            _ = try revalidateCompletedPredecessor(resources: predecessorResources, planPin: pins.predecessor.planSHA256, expectedEvidence: proof.evidence)
            checkpoint(.preparationPayload)
            _ = try InstallerPayloadIO.verifyImage(image, manifest: source.after, owner: 0)
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
        let policy = try fullPolicy(source: source, predecessor: predecessor,
            install: fullOriginal(dynamicFiles[2], files: files, routes: routes, observationDevice: observationDevice),
            host: fullOriginal(dynamicFiles[0], files: files, routes: routes, observationDevice: observationDevice),
            profile: fullOriginal(dynamicFiles[1], files: files, routes: routes, observationDevice: observationDevice), worker: worker.0, ownerUID: ownerUID)
        guard policy.brokerUID == authority.brokerUID else { throw FullImageFailure.predecessor }
        let dynamic = try fullDynamic(policy, source: source, proofSHA256: authority.proofSHA256)
        let journal = try FullImageGlobalJournal.open(directory: global.fd, owner: 0, group: 0, beforeGroup: beforeGroup, expected: intent,
            validateIntent: { try authority.validate($0, source: source, publicOwner: 0, publicGroup: 0, beforeGroup: beforeGroup, device: device, dynamic: dynamic) },
            verifyAttachment: global.verify, createIfMissing: !verificationOnly, observationDevice: observationDevice)
        let recovery = try journal.recovery()
        guard !verificationOnly || recovery.finished else { throw FullImageFailure.predecessor }
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
                    requireQuiescent: barrier.requireDisabledAndQuiescent, createIfMissing: !verificationOnly,
                    observationDevice: observationDevice)
                units.append(.tree(storage))
            }
        }
        let verifyUnchanged = {
            try routes.verify(); try ComponentProcesses.requireOwnerClosed()
            guard try owner().0 == ownerUID, matches(try publicRead("broker/worker.json", mode: 0o644).1, intent.workerPolicy),
                  matches(try jobPlist(ownerGroup: ownerGroup), intent.servicePlist) else { throw FullImageFailure.object }
            try originalReceipt(original, ownerUID: ownerUID)
            _ = try revalidateCompletedPredecessor(resources: predecessorResources, planPin: pins.predecessor.planSHA256,
                expectedEvidenceSHA256: intent.predecessorEvidenceSHA256, recordedDevice: observationDevice)
        }
        let verifyPublic = {
            guard let storage = reference.storage else { throw FullImageFailure.journal }
            try verifyUnchanged()
            try fullLayout(source: source, routes: routes, storage: storage, intent: intent)
            let states = try Array(storage.operations.prefix(source.units.count)).map { try storage.state($0) }
            try FullImagePublicView.verify(source: source, states: states, support: support.fd, owner: 0)
            guard let ownerIndex = source.units.firstIndex(where: { $0.path == PublicTreeUnit.owner.path }) else { throw FullImageFailure.source }
            try fullVerifySignatures(source: source, root: InstallerPayloadManifest.support, after: states[ownerIndex] == .applied)
            let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0 else { throw FullImageFailure.object }; defer { Darwin.close(root) }
            _ = try InstallerPayloadIO.verifyApplicationAlias(from: root, owner: 0)
            try routes.verify()
        }
        let storage = try FullImageMixedStorage(units: units, writeEvent: { event, operation in
            guard let storage = reference.storage else { throw FullImageFailure.journal }
            try journal.writeTransition(event, operation: operation, state: storage.state)
        }, verifyOld: verifyPublic, verifyRecoverable: verifyPublic, verifyNew: verifyPublic)
        reference.storage = storage
        try intent.verifyStorage(storage)
        // A completed predecessor must pass the stricter complete-image view
        // below. Do not first repeat the recoverable-image walk, which checks
        // the same trees while allowing a mixture of staged/applied units.
        // Mutable recovery retains its existing verification sequence.
        if !verificationOnly { try storage.verifyRecoverableView() }
        if try storage.state(storage.operations.last!) == .applied {
            // verifyNewView checks every non-head unit; the head was checked
            // immediately above. The mutable path keeps its existing guard.
            if !verificationOnly {
                guard try storage.operations.allSatisfy({ try storage.state($0) == .applied }) else { throw FullImageFailure.journal }
            } else { checkpoint(.verificationFirstView) }
            try storage.verifyNewView()
            if recovery.finished {
                if verificationOnly {
                    checkpoint(.verificationEvidence)
                    let roots = try InstallationRootBinding.capture(withVolumeUUID: true)
                    let rootEvidence = roots.mapValues { ["device": Int64($0.device), "inode": $0.inode,
                        "volume_uuid": $0.volumeUUID] as [String: Any] }
                    let history = try journal.completedEvidence()
                    let head = try ComponentFiles.read(namespace, "head.json", owner: 0, mode: 0o644)
                    guard let expectedHead = intent.operations.last?.file?.after,
                          matches(head.1, expectedHead) else { throw FullImageFailure.predecessor }
                    let evidence = try FullImageJSON.encode(["schema": 1,
                        "managed_by": "account-access-completed-full-image-v1", "plan_sha256": pins.planSHA256,
                        "manifest_sha256": source.after.sha256, "source_commit": pins.targetSourceCommit,
                        "predecessor_sha256": authority.proofSHA256, "owner_uid": ownerUID, "broker_uid": authority.brokerUID,
                        "roots": rootEvidence, "history_sha256": FullImageJSON.hash(history), "head_sha256": head.1.sha256,
                        "worker_sha256": worker.1.sha256, "service_sha256": plist.sha256] as [String: Any])
                    checkpoint(.verificationFinalView)
                    try storage.verifyNewView()
                    guard try journal.completedEvidence() == history,
                          try InstallationRootBinding.capture(withVolumeUUID: true) == roots,
                          try ComponentFiles.read(namespace, "head.json", owner: 0, mode: 0o644).1 == head.1 else {
                        throw FullImageFailure.predecessor
                    }
                    checkpoint(.complete)
                    return .completed(CompletedFullImageProof(evidence: evidence, ownerUID: ownerUID, brokerUID: authority.brokerUID))
                }
                checkpoint(.complete); return .updated("ALREADY_UPDATED_GUI_UNVERIFIED")
            }
        }
        guard !verificationOnly else { throw FullImageFailure.predecessor }
        try ComponentPreparation.capacity(namespace, bytes: 2 * 1024 * 1024, owner: 0, sameDeviceAs: support.fd)
        checkpoint(.transition)
        _ = try ComponentTransition(storage: storage, service: barrier).run(recovering: hasIntent)
        checkpoint(.complete)
        return .updated("UPDATED_GUI_UNVERIFIED")
    }
}
