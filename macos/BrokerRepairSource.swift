// Closed source contract for a broker-only successor. Package-compiled pins
// are independent of these bytes. Native signature checks remain mandatory in
// the installed adapter; this data-only loader never executes payload code.
import Foundation
import Darwin

enum BrokerRepairUnit: String, CaseIterable {
    case broker, identity, provenance
    var path: String {
        switch self {
        case .broker: return "bin/AccountAccess-broker"
        case .identity: return "package-identity.json"
        case .provenance: return "broker-repair-identity.json"
        }
    }
    var mode: UInt16 { self == .broker ? 0o755 : 0o644 }
}

struct BrokerRepairSource {
    struct Pins {
        let planSHA256: String
        let predecessorPlanSHA256: String
        let beforeManifestSHA256: String
        let afterManifestSHA256: String
        let sourceCommit: String
    }
    let pins: Pins
    let before: InstallerPayloadManifest, after: InstallerPayloadManifest
    let oldPeers: [String: ComponentPeerSignature], newPeers: [String: ComponentPeerSignature]
    let oldFingerprint: String, newFingerprint: String
    let payloads: [BrokerRepairUnit: Data]

    static func load(pins: Pins, plan: Data, before: Data, after: Data,
                     oldIdentity: Data, newIdentity: Data, provenance: Data, broker: Data) throws -> BrokerRepairSource {
        guard [pins.planSHA256, pins.predecessorPlanSHA256, pins.beforeManifestSHA256, pins.afterManifestSHA256]
                .allSatisfy({ FullImageJSON.hex($0) }), FullImageJSON.hex(pins.sourceCommit, count: 40),
              FullImageJSON.hash(plan) == pins.planSHA256,
              FullImageJSON.hash(before) == pins.beforeManifestSHA256,
              FullImageJSON.hash(after) == pins.afterManifestSHA256,
              pins.beforeManifestSHA256 != pins.afterManifestSHA256 else { throw FullImageFailure.source }
        let beforeManifest = try InstallerPayloadManifest(before), afterManifest = try InstallerPayloadManifest(after)
        let value = try FullImageJSON.object(plan, maximum: 16384)
        guard Set(value.keys) == ["schema", "managed_by", "predecessor_plan_sha256", "before_manifest_sha256",
            "after_manifest_sha256", "source_commit", "changed", "private_schema_unchanged", "worker_abi_unchanged", "production_ready"],
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["managed_by"] as? String == "account-access-broker-repair-plan-v1",
              value["predecessor_plan_sha256"] as? String == pins.predecessorPlanSHA256,
              value["before_manifest_sha256"] as? String == pins.beforeManifestSHA256,
              value["after_manifest_sha256"] as? String == pins.afterManifestSHA256,
              value["source_commit"] as? String == pins.sourceCommit,
              value["changed"] as? [String] == BrokerRepairUnit.allCases.map(\.path).sorted(),
              FullImageJSON.bool(value["private_schema_unchanged"], true), FullImageJSON.bool(value["worker_abi_unchanged"], true),
              FullImageJSON.bool(value["production_ready"], false) else { throw FullImageFailure.source }
        let oldPeers = try peers(oldIdentity), newPeers = try peers(newIdentity)
        guard oldPeers["owner"] == newPeers["owner"], oldPeers["bootstrap"] == newPeers["bootstrap"],
              oldPeers["broker"] != newPeers["broker"],
              oldPeers["broker"]?.team == newPeers["broker"]?.team else { throw FullImageFailure.source }
        let oldFingerprint = try FullImagePolicyFingerprint.value(oldPeers), newFingerprint = try FullImagePolicyFingerprint.value(newPeers)
        guard oldFingerprint != newFingerprint, !broker.isEmpty, broker.count <= ComponentFiles.maximumFile else { throw FullImageFailure.source }
        let payloads: [BrokerRepairUnit: Data] = [.broker: broker, .identity: newIdentity, .provenance: provenance]
        let beforeRoot = try FullImageJSON.object(before, maximum: InstallerPayloadManifest.maximumManifest)
        let afterRoot = try FullImageJSON.object(after, maximum: InstallerPayloadManifest.maximumManifest)
        guard let oldRoots = beforeRoot["roots"] as? [String: [String: Any]],
              let newRoots = afterRoot["roots"] as? [String: [String: Any]],
              let old = oldRoots[InstallerPayloadManifest.support], let new = newRoots[InstallerPayloadManifest.support],
              try FullImageJSON.same(oldRoots[InstallerPayloadManifest.application]!, newRoots[InstallerPayloadManifest.application]!),
              old[BrokerRepairUnit.provenance.path] == nil else { throw FullImageFailure.source }
        var changed: Set<String> = []
        for path in Set(old.keys).union(new.keys) {
            if try !FullImageJSON.same(old[path] ?? NSNull(), new[path] ?? NSNull()) { changed.insert(path) }
        }
        guard changed == Set(BrokerRepairUnit.allCases.map(\.path)),
              beforeManifest.trees[InstallerPayloadManifest.support]?.nodes[BrokerRepairUnit.identity.path]?.sha256 == FullImageJSON.hash(oldIdentity) else {
            throw FullImageFailure.source
        }
        for unit in BrokerRepairUnit.allCases {
            guard let node = afterManifest.trees[InstallerPayloadManifest.support]?.nodes[unit.path],
                  let payload = payloads[unit], node.kind == "file", node.mode == unit.mode,
                  node.size == Int64(payload.count), node.sha256 == FullImageJSON.hash(payload) else { throw FullImageFailure.source }
            if unit != .provenance {
                guard let oldNode = beforeManifest.trees[InstallerPayloadManifest.support]?.nodes[unit.path],
                      oldNode.kind == "file", oldNode.mode == unit.mode else { throw FullImageFailure.source }
            }
        }
        let history = try FullImageJSON.object(provenance, maximum: 16384)
        guard Set(history.keys) == ["schema", "managed_by", "before_manifest_sha256", "source_commit", "broker_sha256", "package_identity_sha256", "native_sources"],
              try InstallerPayloadManifest.integer(history["schema"], maximum: 1) == 1,
              history["managed_by"] as? String == "account-access-broker-repair-image-v1",
              history["before_manifest_sha256"] as? String == pins.beforeManifestSHA256,
              history["source_commit"] as? String == pins.sourceCommit,
              history["broker_sha256"] as? String == FullImageJSON.hash(broker),
              history["package_identity_sha256"] as? String == FullImageJSON.hash(newIdentity),
              let sources = history["native_sources"] as? [String: String], !sources.isEmpty, sources.count <= 64,
              sources.keys.allSatisfy({ $0.hasPrefix("macos/") && !$0.contains("..") && ($0.hasSuffix(".swift") || $0.hasSuffix(".c") || $0.hasSuffix(".h")) }),
              sources.values.allSatisfy({ FullImageJSON.hex($0) }) else { throw FullImageFailure.source }
        return BrokerRepairSource(pins: pins, before: beforeManifest, after: afterManifest, oldPeers: oldPeers,
            newPeers: newPeers, oldFingerprint: oldFingerprint, newFingerprint: newFingerprint, payloads: payloads)
    }
    private static func peers(_ data: Data) throws -> [String: ComponentPeerSignature] {
        let value = try FullImageJSON.object(data, maximum: 8192)
        guard Set(value.keys) == ["schema", "managed_by", "signatures"],
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["managed_by"] as? String == "account-access-package-identity-v1",
              let raw = value["signatures"] as? [String: [String: Any]], Set(raw.keys) == ["owner", "broker", "bootstrap"] else {
            throw FullImageFailure.source
        }
        var result: [String: ComponentPeerSignature] = [:]
        for kind in ["owner", "broker", "bootstrap"] {
            let peer = raw[kind]!, identifier = kind == "owner" ? "com.fainir.accountaccess" : "com.fainir.accountaccess." + kind
            guard Set(peer.keys) == ["team", "identifier", "hashes"], peer["team"] as? String == "WBULD6N4NQ",
                  peer["identifier"] as? String == identifier, let hashes = peer["hashes"] as? [String],
                  (1...2).contains(hashes.count), hashes == Array(Set(hashes)).sorted(),
                  hashes.allSatisfy({ FullImageJSON.hex($0, count: 40) }) else { throw FullImageFailure.source }
            result[kind] = .init(team: "WBULD6N4NQ", identifier: identifier, hashes: hashes)
        }
        return result
    }
}
