// Opaque predecessor proof -> exact full-image plan/intent binding.
// No filesystem/OS calls. The proof can only be minted by the separately
// qualified completed-component verifier (or its compile-gated fixture seam).
import Foundation
import Darwin

struct FullImagePredecessorAuthority {
    let proofSHA256: String
    let ownerUID: uid_t
    let brokerUID: uid_t
    let workerPolicy: ComponentObject
    let servicePlist: ComponentObject
    private let planSHA256: String
    private init(proofSHA256: String, ownerUID: uid_t, brokerUID: uid_t, worker: ComponentObject,
                 service: ComponentObject, planSHA256: String) {
        self.proofSHA256 = proofSHA256; self.ownerUID = ownerUID; self.brokerUID = brokerUID
        workerPolicy = worker; servicePlist = service; self.planSHA256 = planSHA256
    }
    static func bind(source: FullImageSource, proof: CompletedComponentProof) throws -> FullImagePredecessorAuthority {
        let value = try FullImageJSON.object(proof.evidence, maximum: 1024 * 1024)
        guard proof.sha256 == FullImageJSON.hash(proof.evidence),
              Set(value.keys) == ["schema", "managedBy", "planSHA256", "baseManifestSHA256", "targetManifestSHA256", "ownerUID", "ownerGroup", "brokerUID", "roots", "namespaceNames", "originalReceipts", "rootBindingSHA256", "records", "head", "worker", "service"],
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["managedBy"] as? String == "account-access-completed-component-predecessor-v1",
              value["planSHA256"] as? String == source.pins.predecessor.planSHA256,
              value["baseManifestSHA256"] as? String == source.pins.predecessor.originalManifestSHA256,
              value["targetManifestSHA256"] as? String == source.pins.predecessor.manifestSHA256,
              value["targetManifestSHA256"] as? String == source.before.sha256 else { throw FullImageFailure.predecessor }
        func object(_ name: String) throws -> ComponentObject {
            guard let raw = value[name] else { throw FullImageFailure.predecessor }
            let data = try FullImageJSON.encode(raw)
            let decoded = try JSONDecoder().decode(ComponentObject.self, from: data)
            guard FullImageJSON.hex(decoded.sha256), decoded.inode > 0, decoded.device >= 0,
                  decoded.bytes >= 0, decoded.bytes <= ComponentFiles.maximumFile else { throw FullImageFailure.predecessor }
            return decoded
        }
        let head = try object("head"), worker = try object("worker"), service = try object("service")
        guard head.mode == 0o644, head.sha256 == source.pins.predecessor.headSHA256,
              worker.mode == 0o644, service.mode == 0o644 else { throw FullImageFailure.predecessor }
        let owner = uid_t(try InstallerPayloadManifest.integer(value["ownerUID"], maximum: Int64(UInt32.max)))
        let broker = uid_t(try InstallerPayloadManifest.integer(value["brokerUID"], maximum: Int64(UInt32.max)))
        guard owner > 0, owner != broker, (450..<500).contains(broker) else { throw FullImageFailure.predecessor }
        return FullImagePredecessorAuthority(proofSHA256: proof.sha256, ownerUID: owner, brokerUID: broker,
            worker: worker, service: service, planSHA256: source.pins.planSHA256)
    }
    func validate(_ intent: FullImageGlobalIntent, source: FullImageSource, publicOwner: uid_t, publicGroup: gid_t,
                  beforeGroup: gid_t? = nil, device: Int32, dynamic: [FullImageFileUnit: Data]) throws {
        guard source.pins.planSHA256 == planSHA256 else { throw FullImageFailure.predecessor }
        try intent.validate(source: source, predecessorEvidenceSHA256: proofSHA256, workerPolicy: workerPolicy,
            servicePlist: servicePlist, ownerUID: ownerUID, brokerUID: brokerUID,
            publicOwner: publicOwner, publicGroup: publicGroup, beforeGroup: beforeGroup, device: device, dynamic: dynamic)
    }
}
