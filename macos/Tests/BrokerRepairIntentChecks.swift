// Data-only recovery contract checks; all identities and policy bytes fictional.
import Foundation
import Darwin

enum BrokerRepairIntentChecks {
    static func run(source: BrokerRepairSource) throws -> Int {
        var assertions = 0
        func check(_ condition: Bool) { precondition(condition); assertions += 1 }
        func refuses(_ body: () throws -> Void) {
            var refused = false; do { try body() } catch { refused = true }; check(refused)
        }
        let volume = "12345678-1234-4234-8234-123456789abc"
        func mount(_ device: Int32 = 20, uuid: String = volume, support: UInt64 = 100, alias: UInt64 = 101,
                   namespace: UInt64 = 500, journal: UInt64 = 501) -> BrokerRepairMount {
            .init(device: device, volumeUUID: uuid, supportInode: support, applicationAliasInode: alias,
                namespaceInode: namespace, predecessorJournalInode: journal)
        }
        func object(_ inode: UInt64, bytes: Data, mode: UInt16 = 0o644, device: Int32 = 20) -> ComponentObject {
            .init(device: device, inode: inode, mode: mode, bytes: Int64(bytes.count), sha256: FullImageJSON.hash(bytes))
        }
        let head = object(601, bytes: Data("fictional previous head".utf8))
        let worker = object(602, bytes: Data("fictional worker policy".utf8))
        let service = object(603, bytes: Data("fictional service policy".utf8))
        let host = object(604, bytes: Data("fictional host policy".utf8))
        let policy = ComponentPolicyResult(install: Data("fictional derived install".utf8),
            host: Data("fictional host policy".utf8), owner: Data("fictional derived owner".utf8), ownerUID: 501, brokerUID: 470)
        let history = String(repeating: "f", count: 64)
        let proof = try FullImageJSON.encode(["schema": 1, "managed_by": "account-access-completed-full-image-v1",
            "plan_sha256": source.pins.predecessorPlanSHA256, "manifest_sha256": source.pins.beforeManifestSHA256,
            "source_commit": String(repeating: "e", count: 40), "predecessor_sha256": String(repeating: "d", count: 64),
            "owner_uid": 501, "broker_uid": 470,
            "roots": [InstallerPayloadManifest.support: ["device": 20, "inode": 100, "volume_uuid": volume],
                InstallerPayloadManifest.application: ["device": 20, "inode": 101, "volume_uuid": volume]],
            "history_sha256": history, "head_sha256": head.sha256, "worker_sha256": worker.sha256, "service_sha256": service.sha256])
        let dynamic = ["owner.json": policy.owner, "broker/install.json": policy.install,
            "head.json": try BrokerRepairIntent.head(source: source, evidence: proof)]
        var operations: [ComponentOperation] = []
        for (index, target) in BrokerRepairIntent.targets.enumerated() {
            func image(_ manifest: InstallerPayloadManifest, inode: UInt64) -> ComponentObject? {
                guard let node = manifest.trees[InstallerPayloadManifest.support]?.nodes[target.1] else { return nil }
                return .init(device: 20, inode: inode, mode: target.2, bytes: node.size!, sha256: node.sha256!)
            }
            let before: ComponentObject?, after: ComponentObject
            if index < 3 {
                before = image(source.before, inode: UInt64(1000 + index))
                after = image(source.after, inode: UInt64(2000 + index))!
            } else {
                before = index == 5 ? nil : object(UInt64(1000 + index), bytes: Data("fictional original policy".utf8), mode: target.2)
                after = object(UInt64(2000 + index), bytes: dynamic[target.1]!, mode: target.2)
            }
            operations.append(.init(target: target.0, path: target.1, slot: String(format: "slot-%02d", index), before: before, after: after))
        }
        let transition = ComponentTransitionIntent(schema: 1, planSHA256: source.pins.planSHA256,
            baseManifestSHA256: source.pins.beforeManifestSHA256, targetManifestSHA256: source.pins.afterManifestSHA256,
            operations: operations, ownerUID: 501, brokerUID: 470, service: nil,
            workerPolicy: worker, servicePlist: service, automaticRebootRecovery: false)
        let intent = BrokerRepairIntent(schema: 1, managedBy: "account-access-broker-repair-transition-v1",
            mount: mount(), transition: transition, predecessorEvidence: proof, predecessorHead: head, hostPolicy: host)
        func moved(_ value: ComponentObject, device: Int32) -> ComponentObject {
            .init(device: device, inode: value.inode, mode: value.mode, bytes: value.bytes, sha256: value.sha256)
        }
        func validate(_ value: BrokerRepairIntent, current: BrokerRepairMount = mount(), digest: String = history,
                      observedHead: ComponentObject? = nil, observedWorker: ComponentObject? = nil,
                      observedService: ComponentObject? = nil, observedHost: ComponentObject? = nil) throws {
            try value.validate(source: source, current: current, policy: policy,
                currentHead: observedHead ?? moved(head, device: current.device), currentHistorySHA256: digest,
                worker: observedWorker ?? moved(worker, device: current.device), service: observedService ?? moved(service, device: current.device),
                host: observedHost ?? moved(host, device: current.device))
        }
        try validate(intent); check(true)
        try validate(intent, current: mount(21)); check(true)
        let bytes = try intent.encoded(), reopened = try BrokerRepairIntent.decode(bytes)
        try validate(reopened, current: mount(22)); check(try reopened.encoded() == bytes)
        let translated = try reopened.operations(current: mount(21))
        check(translated.allSatisfy { $0.after.device == 21 && ($0.before == nil || $0.before?.device == 21) })
        check(zip(translated, operations).allSatisfy { $0.after.inode == $1.after.inode && $0.after.sha256 == $1.after.sha256 })
        for bad in [mount(-1), mount(21, uuid: UUID().uuidString.lowercased()), mount(support: 999), mount(alias: 999),
                    mount(namespace: 999), mount(journal: 999), mount(namespace: 100), mount(support: 0)] {
            refuses { try validate(intent, current: bad) }
        }
        refuses { try validate(intent, digest: String(repeating: "a", count: 64)) }
        refuses { try validate(intent, observedHead: object(999, bytes: Data("fictional previous head".utf8))) }
        refuses { try validate(intent, observedWorker: object(602, bytes: Data("foreign".utf8))) }
        refuses { try validate(intent, observedService: object(603, bytes: Data("foreign".utf8))) }
        refuses { try validate(intent, observedHost: object(604, bytes: Data("foreign".utf8))) }
        func changed(_ transform: (inout [String: Any]) throws -> Void) throws -> BrokerRepairIntent {
            var value = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
            try transform(&value)
            return try BrokerRepairIntent.decode(FullImageJSON.encode(value))
        }
        for key in ["schema", "managedBy", "extra"] {
            refuses { try validate(changed { $0[key] = "foreign" }) }
        }
        for (key, replacement) in [("schema", 2 as Any), ("ownerUID", 502 as Any), ("brokerUID", 471 as Any),
            ("planSHA256", String(repeating: "a", count: 64) as Any), ("automaticRebootRecovery", true as Any)] {
            refuses { try validate(changed { var t = $0["transition"] as! [String: Any]; t[key] = replacement; $0["transition"] = t }) }
        }
        for key in ["path", "slot", "target"] {
            refuses { try validate(changed {
                var t = $0["transition"] as! [String: Any], ops = t["operations"] as! [[String: Any]]
                ops[0][key] = "foreign"; t["operations"] = ops; $0["transition"] = t
            }) }
        }
        for (key, replacement) in [("device", 21 as Any), ("inode", 602 as Any), ("mode", 0o600 as Any),
            ("sha256", String(repeating: "a", count: 64) as Any), ("bytes", 999 as Any)] {
            refuses { try validate(changed {
                var t = $0["transition"] as! [String: Any], ops = t["operations"] as! [[String: Any]]
                var after = ops[0]["after"] as! [String: Any]; after[key] = replacement
                ops[0]["after"] = after; t["operations"] = ops; $0["transition"] = t
            }) }
        }
        for key in ["owner_uid", "broker_uid", "plan_sha256", "manifest_sha256", "history_sha256", "head_sha256",
                    "worker_sha256", "service_sha256", "roots", "source_commit", "extra"] {
            refuses { try validate(changed {
                var evidence = try JSONSerialization.jsonObject(with: proof) as! [String: Any]
                evidence[key] = "foreign"; $0["predecessorEvidence"] = try FullImageJSON.encode(evidence).base64EncodedString()
            }) }
        }
        let text = String(decoding: bytes, as: UTF8.self)
        for malformed in [bytes + Data([10]), Data(("{\"schema\":1," + text.dropFirst()).utf8),
            Data(("{\"\\u0073chema\":1," + text.dropFirst()).utf8), Data(repeating: 32, count: 65537)] {
            refuses { _ = try BrokerRepairIntent.decode(malformed) }
        }
        return assertions
    }
}
