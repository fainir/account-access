// Immutable broker-repair intent. Recovery revalidates the exact retained
// predecessor history and complete public image; only a device number may be
// translated when the recorded persistent volume and every root inode match.
import Foundation
import Darwin

struct BrokerRepairMount: Codable, Equatable {
    let device: Int32
    let volumeUUID: String
    let supportInode: UInt64
    let applicationAliasInode: UInt64
    let namespaceInode: UInt64
    let predecessorJournalInode: UInt64
    func validate() throws {
        guard device >= 0, let uuid = UUID(uuidString: volumeUUID), uuid.uuidString.lowercased() == volumeUUID,
              volumeUUID != "00000000-0000-0000-0000-000000000000",
              [supportInode, applicationAliasInode, namespaceInode, predecessorJournalInode]
                .allSatisfy({ $0 > 0 && $0 <= UInt64(Int64.max) }),
              Set([supportInode, applicationAliasInode, namespaceInode, predecessorJournalInode]).count == 4 else {
            throw ComponentUpdateFailure.journal
        }
    }
    func revalidate(_ current: BrokerRepairMount) throws {
        try validate(); try current.validate()
        guard volumeUUID == current.volumeUUID, supportInode == current.supportInode,
              applicationAliasInode == current.applicationAliasInode, namespaceInode == current.namespaceInode,
              predecessorJournalInode == current.predecessorJournalInode else { throw ComponentUpdateFailure.journal }
    }
}

struct BrokerRepairIntent: Codable {
    static let namespace = "/Library/Application Support/Account Access Broker Repair"
    let schema: Int
    let managedBy: String
    let mount: BrokerRepairMount
    let transition: ComponentTransitionIntent
    let predecessorEvidence: Data
    let predecessorHead: ComponentObject
    let hostPolicy: ComponentObject

    static let targets: [(ComponentOperation.Target, String, UInt16)] = [
        (.image, BrokerRepairUnit.broker.path, 0o755), (.image, BrokerRepairUnit.identity.path, 0o644),
        (.image, BrokerRepairUnit.provenance.path, 0o644), (.ownerPolicy, "owner.json", 0o644),
        (.installRecord, "broker/install.json", 0o600), (.head, "head.json", 0o644)]

    static func head(source: BrokerRepairSource, evidence: Data) throws -> Data {
        try FullImageJSON.encode(["schema": 1, "managed_by": "account-access-broker-repair-head-v1",
            "plan_sha256": source.pins.planSHA256, "manifest_sha256": source.pins.afterManifestSHA256,
            "source_commit": source.pins.sourceCommit, "predecessor_evidence_sha256": FullImageJSON.hash(evidence),
            "state": "public_image_verified_gui_unverified", "automatic_reboot_recovery": false])
    }
    func encoded() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
    static func decode(_ data: Data) throws -> BrokerRepairIntent {
        _ = try FullImageJSON.object(data, maximum: 65536)
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard try value.encoded() == data else { throw ComponentUpdateFailure.journal }
        return value
    }
    private func translated(_ object: ComponentObject, current: BrokerRepairMount) throws -> ComponentObject {
        guard object.device == mount.device, object.inode > 0, object.bytes >= 0,
              object.bytes <= ComponentFiles.maximumFile, FullImageJSON.hex(object.sha256) else { throw ComponentUpdateFailure.journal }
        return ComponentObject(device: current.device, inode: object.inode, mode: object.mode, bytes: object.bytes, sha256: object.sha256)
    }
    func operations(current: BrokerRepairMount) throws -> [ComponentOperation] {
        try mount.revalidate(current)
        return try transition.operations.map { operation in
            ComponentOperation(target: operation.target, path: operation.path, slot: operation.slot,
                before: try operation.before.map { try translated($0, current: current) },
                after: try translated(operation.after, current: current))
        }
    }
    func matches(_ recorded: ComponentObject, _ current: ComponentObject, mount: BrokerRepairMount) throws -> Bool {
        try self.mount.revalidate(mount)
        return try translated(recorded, current: mount) == current
    }
    func validate(source: BrokerRepairSource, current: BrokerRepairMount, policy: ComponentPolicyResult,
                  currentHead: ComponentObject, currentHistorySHA256: String,
                  worker: ComponentObject, service: ComponentObject, host: ComponentObject) throws {
        try mount.revalidate(current)
        let value = transition
        guard schema == 1, managedBy == "account-access-broker-repair-transition-v1",
              value.schema == 1, value.planSHA256 == source.pins.planSHA256,
              value.baseManifestSHA256 == source.pins.beforeManifestSHA256,
              value.targetManifestSHA256 == source.pins.afterManifestSHA256,
              value.ownerUID == policy.ownerUID, value.brokerUID == policy.brokerUID,
              value.ownerUID > 0, value.ownerUID != value.brokerUID, (450..<500).contains(value.brokerUID),
              !value.automaticRebootRecovery, value.operations.count == Self.targets.count,
              try matches(predecessorHead, currentHead, mount: current),
              try matches(value.workerPolicy, worker, mount: current),
              try matches(value.servicePlist, service, mount: current),
              try matches(hostPolicy, host, mount: current),
              [predecessorHead, value.workerPolicy, value.servicePlist, hostPolicy].allSatisfy({ $0.mode == 0o644 }) else {
            throw ComponentUpdateFailure.journal
        }
        if let service = value.service { try ComponentUpdateIdentity.validateSnapshot(service) }
        let proof = try FullImageJSON.object(predecessorEvidence, maximum: 8192)
        guard Set(proof.keys) == ["schema", "managed_by", "plan_sha256", "manifest_sha256", "source_commit", "predecessor_sha256",
            "owner_uid", "broker_uid", "roots", "history_sha256", "head_sha256", "worker_sha256", "service_sha256"],
              try InstallerPayloadManifest.integer(proof["schema"], maximum: 1) == 1,
              proof["managed_by"] as? String == "account-access-completed-full-image-v1",
              proof["plan_sha256"] as? String == source.pins.predecessorPlanSHA256,
              proof["manifest_sha256"] as? String == source.pins.beforeManifestSHA256,
              try InstallerPayloadManifest.integer(proof["owner_uid"], maximum: Int64(UInt32.max)) == Int64(value.ownerUID),
              try InstallerPayloadManifest.integer(proof["broker_uid"], maximum: Int64(UInt32.max)) == Int64(value.brokerUID),
              proof["history_sha256"] as? String == currentHistorySHA256, FullImageJSON.hex(currentHistorySHA256),
              proof["head_sha256"] as? String == currentHead.sha256, proof["worker_sha256"] as? String == worker.sha256,
              proof["service_sha256"] as? String == service.sha256,
              let revision = proof["source_commit"] as? String, FullImageJSON.hex(revision, count: 40),
              let predecessor = proof["predecessor_sha256"] as? String, FullImageJSON.hex(predecessor),
              let roots = proof["roots"] as? [String: [String: Any]],
              Set(roots.keys) == [InstallerPayloadManifest.support, InstallerPayloadManifest.application] else {
            throw ComponentUpdateFailure.journal
        }
        for (path, inode) in [(InstallerPayloadManifest.support, mount.supportInode),
                              (InstallerPayloadManifest.application, mount.applicationAliasInode)] {
            let root = roots[path]!
            guard Set(root.keys) == ["device", "inode", "volume_uuid"],
                  try InstallerPayloadManifest.integer(root["device"], maximum: Int64(Int32.max)) == Int64(mount.device),
                  try InstallerPayloadManifest.integer(root["inode"], maximum: Int64.max) == Int64(inode),
                  root["volume_uuid"] as? String == mount.volumeUUID else { throw ComponentUpdateFailure.journal }
        }
        let dynamic: [String: Data] = ["owner.json": policy.owner, "broker/install.json": policy.install,
            "head.json": try Self.head(source: source, evidence: predecessorEvidence)]
        var inodes = Set([predecessorHead.inode, value.workerPolicy.inode, value.servicePlist.inode, hostPolicy.inode])
        guard inodes.count == 4 else { throw ComponentUpdateFailure.journal }
        for (index, operation) in value.operations.enumerated() {
            let expected = Self.targets[index]
            guard operation.target == expected.0, operation.path == expected.1,
                  operation.slot == String(format: "slot-%02d", index),
                  (operation.before == nil) == (index == 2 || index == 5) else { throw ComponentUpdateFailure.journal }
            for object in [operation.before, operation.after].compactMap({ $0 }) {
                _ = try translated(object, current: current)
                guard object.mode == expected.2, inodes.insert(object.inode).inserted else { throw ComponentUpdateFailure.journal }
            }
            if index < 3 {
                func matches(_ object: ComponentObject?, _ manifest: InstallerPayloadManifest) -> Bool {
                    let node = manifest.trees[InstallerPayloadManifest.support]?.nodes[operation.path]
                    guard let object else { return node == nil }
                    return node?.kind == "file" && node?.mode == object.mode && node?.size == object.bytes && node?.sha256 == object.sha256
                }
                guard matches(operation.before, source.before), matches(operation.after, source.after) else { throw ComponentUpdateFailure.source }
            } else {
                guard let bytes = dynamic[operation.path], operation.after.bytes == Int64(bytes.count),
                      operation.after.sha256 == FullImageJSON.hash(bytes) else { throw ComponentUpdateFailure.journal }
            }
        }
    }
}
