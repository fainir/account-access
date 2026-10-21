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
                    wrongBefore: Bool = false) -> FullImageSource {
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
                designatedRequirements: [:], units: [], changed: [])
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
        return checks
    }
}
