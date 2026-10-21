// Pure connector assertions. Synthetic typed values deliberately do not claim
// to be a qualified full-image plan or real installed predecessor.
import Foundation
import Darwin

private enum FullImageAuthorityCheckFailure: Error { case failed }
enum FullImagePredecessorAuthorityChecks {
    static func run(fixture: CompletedPredecessorFixture, proof: CompletedComponentProof) throws -> [String: Bool] {
        var checks: [String: Bool] = [:]
        func expect(_ value: Bool, _ name: String) throws {
            guard value else { throw FullImageAuthorityCheckFailure.failed }; checks[name] = true
        }
        func refuses(_ name: String, _ body: () throws -> Void) throws {
            var refused = false; do { try body() } catch { refused = true }; try expect(refused, name)
        }
        let component = fixture.source
        func source(plan: String? = nil, original: String? = nil, target: String? = nil, head: String? = nil,
                    wrongBefore: Bool = false, units: [FullImageSource.Unit] = []) -> FullImageSource {
            let pins = FullImageSourcePins(planSHA256: String(repeating: "d", count: 64), targetSourceCommit: String(repeating: "e", count: 40),
                targetManifestSHA256: component.oldManifest.sha256, caReceiptSHA256: String(repeating: "0", count: 64),
                predecessor: FullImagePredecessorPins(planSHA256: plan ?? component.planDigest,
                    originalManifestSHA256: original ?? component.oldManifest.sha256,
                    manifestSHA256: target ?? component.newManifest.sha256,
                    headSHA256: head ?? fixture.snapshot.head.object.sha256),
                predecessorSourceCommit: String(repeating: "f", count: 40), targetSourceFiles: [:],
                providerManifestSHA256: String(repeating: "a", count: 64), providerSourceBundleSHA256: String(repeating: "b", count: 64))
            return FullImageSource(pins: pins, before: wrongBefore ? component.oldManifest : component.newManifest,
                after: component.oldManifest, oldPeers: component.newPeers, newPeers: component.newPeers,
                designatedRequirements: [:], units: units, changed: [])
        }
        let fullSource = source(), authority = try FullImagePredecessorAuthority.bind(source: fullSource, proof: proof)
        try expect(authority.proofSHA256 == proof.sha256 && authority.ownerUID == fixture.snapshot.ownerUID &&
            authority.brokerUID == CompletedPredecessorFixture.broker && authority.workerPolicy == fixture.snapshot.worker.object &&
            authority.servicePlist == fixture.snapshot.service.object, "authority_opaque_proof_binds_source_and_expected_identities")
        for (name, altered) in [
            ("authority_foreign_component_plan_refused", source(plan: String(repeating: "a", count: 64))),
            ("authority_foreign_original_manifest_refused", source(original: String(repeating: "a", count: 64))),
            ("authority_foreign_target_manifest_refused", source(target: String(repeating: "a", count: 64))),
            ("authority_foreign_head_refused", source(head: String(repeating: "a", count: 64))),
            ("authority_full_image_before_mismatch_refused", source(wrongBefore: true))
        ] { try refuses(name) { _ = try FullImagePredecessorAuthority.bind(source: altered, proof: proof) } }
        let dynamic: [FullImageFileUnit: Data] = [.hostPolicy: Data("synthetic-derived-host".utf8), .ownerPolicy: Data("synthetic-derived-owner".utf8),
            .installRecord: Data("synthetic-derived-install".utf8), .head: try FullImageGlobalIntent.newHead(source: fullSource, predecessorEvidenceSHA256: proof.sha256)]
        var operations: [FullImageDurableOperation] = []
        for (index, unit) in [FullImageFileUnit.hostPolicy, .ownerPolicy, .installRecord, .head].enumerated() {
            let data = dynamic[unit]!
            let before = unit == .head ? nil : ComponentObject(device: 7, inode: UInt64(10000 + index), mode: unit.mode,
                bytes: 1, sha256: String(repeating: "a", count: 64))
            let after = ComponentObject(device: 7, inode: UInt64(20000 + index), mode: unit.mode, bytes: Int64(data.count), sha256: FullImageJSON.hash(data))
            operations.append(FullImageDurableOperation(file: FullImageFileOperation(schema: 1, unit: unit,
                planSHA256: fullSource.pins.planSHA256, index: index, before: before, after: after)))
        }
        let intent = FullImageGlobalIntent(schema: 2, managedBy: "account-access-full-image-transition-v2",
            planSHA256: fullSource.pins.planSHA256, beforeManifestSHA256: fullSource.before.sha256, afterManifestSHA256: fullSource.after.sha256,
            targetSourceCommit: fullSource.pins.targetSourceCommit, predecessorEvidenceSHA256: proof.sha256,
            ownerUID: authority.ownerUID, brokerUID: authority.brokerUID, initialService: nil,
            workerPolicy: authority.workerPolicy, servicePlist: authority.servicePlist, operations: operations, automaticRebootRecovery: false)
        try authority.validate(intent, source: fullSource, publicOwner: 0, publicGroup: 0, device: 7, dynamic: dynamic)
        try expect(true, "authority_validates_global_intent_against_verified_proof")
        let encoder = JSONEncoder()
        for (key, replacement) in [("ownerUID", 502 as Any), ("predecessorEvidenceSHA256", String(repeating: "a", count: 64) as Any)] {
            var value = try JSONSerialization.jsonObject(with: encoder.encode(intent)) as! [String: Any]; value[key] = replacement
            let altered = try JSONDecoder().decode(FullImageGlobalIntent.self, from: JSONSerialization.data(withJSONObject: value))
            try refuses("authority_changed_" + key + "_refused") {
                try authority.validate(altered, source: fullSource, publicOwner: 0, publicGroup: 0, device: 7, dynamic: dynamic)
            }
        }
        // The qualified caller supplies the existing public-tree group. It is
        // independent of the new staged group and cannot come from a journal.
        let legacy: gid_t = 80
        let oldTree = try PublicTreeInventory(validatedManifest: component.newManifest, unit: .project)
        let newTree = try PublicTreeInventory(validatedManifest: component.oldManifest, unit: .project)
        let treeSource = source(units: [.tree(.project, oldTree, newTree)])
        let before = PublicTreePin(device: 7, inode: 30000, owner: 0, group: legacy, mode: 0o755,
            inventorySHA256: oldTree.inventorySHA256!)
        let after = PublicTreePin(device: 7, inode: 40000, owner: 0, group: 0, mode: 0o755,
            inventorySHA256: newTree.inventorySHA256!)
        func treeIntent(before replacementBefore: PublicTreePin? = nil, after replacementAfter: PublicTreePin? = nil) -> FullImageGlobalIntent {
            let tree = PublicTreeOperation(schema: 2, unit: PublicTreeUnit.project.rawValue, planSHA256: treeSource.pins.planSHA256,
                beforeManifestSHA256: treeSource.before.sha256, afterManifestSHA256: treeSource.after.sha256,
                before: replacementBefore ?? before, after: replacementAfter ?? after)
            let files = operations.map { operation -> FullImageDurableOperation in
                let file = operation.file!
                return FullImageDurableOperation(file: FullImageFileOperation(schema: file.schema, unit: file.unit,
                    planSHA256: file.planSHA256, index: file.index + 1, before: file.before, after: file.after))
            }
            return FullImageGlobalIntent(schema: intent.schema, managedBy: intent.managedBy, planSHA256: intent.planSHA256,
                beforeManifestSHA256: intent.beforeManifestSHA256, afterManifestSHA256: intent.afterManifestSHA256,
                targetSourceCommit: intent.targetSourceCommit, predecessorEvidenceSHA256: intent.predecessorEvidenceSHA256,
                ownerUID: intent.ownerUID, brokerUID: intent.brokerUID, initialService: intent.initialService,
                workerPolicy: intent.workerPolicy, servicePlist: intent.servicePlist,
                operations: [FullImageDurableOperation(tree: tree)] + files, automaticRebootRecovery: false)
        }
        let legacyIntent = treeIntent()
        try authority.validate(legacyIntent, source: treeSource, publicOwner: 0, publicGroup: 0,
            beforeGroup: legacy, device: 7, dynamic: dynamic)
        try expect(true, "authority_explicit_legacy_group_intent_accepted")
        try expect(legacyIntent.operations[0].tree!.before?.group == legacy && legacyIntent.operations[0].tree!.after?.group == 0,
            "authority_old_and_new_group_pins_remain_distinct")
        try refuses("authority_default_group_cannot_adopt_legacy_tree") {
            try authority.validate(legacyIntent, source: treeSource, publicOwner: 0, publicGroup: 0, device: 7, dynamic: dynamic)
        }
        try refuses("authority_wrong_legacy_context_refused") {
            try authority.validate(legacyIntent, source: treeSource, publicOwner: 0, publicGroup: 0, beforeGroup: legacy + 1, device: 7, dynamic: dynamic)
        }
        let forgedBefore = PublicTreePin(device: before.device, inode: before.inode, owner: before.owner, group: 0,
            mode: before.mode, inventorySHA256: before.inventorySHA256)
        try refuses("authority_forged_old_group_refused") {
            try authority.validate(treeIntent(before: forgedBefore), source: treeSource, publicOwner: 0, publicGroup: 0,
                beforeGroup: legacy, device: 7, dynamic: dynamic)
        }
        let forgedAfter = PublicTreePin(device: after.device, inode: after.inode, owner: after.owner, group: legacy,
            mode: after.mode, inventorySHA256: after.inventorySHA256)
        try refuses("authority_forged_new_group_refused") {
            try authority.validate(treeIntent(after: forgedAfter), source: treeSource, publicOwner: 0, publicGroup: 0,
                beforeGroup: legacy, device: 7, dynamic: dynamic)
        }
        return checks
    }
}
