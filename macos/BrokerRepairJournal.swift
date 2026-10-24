import Foundation

// Bounded audit recovery. Partial writes never grant disable ownership; a
// complete foreign record is a conflict. Object state remains authoritative.
struct BrokerRepairJournal {
    struct Job: Codable { let schema: Int; let planSHA256: String; let job: ComponentJobIdentity }
    let nextEvent: Int, nextService: Int, nextJob: Int
    let snapshots: [ComponentJobIdentity]
    let ownsDisable: Bool, finished: Bool
    static let serviceEvents = Set(FullImageGlobalJournal.Service.allCases.map(\.rawValue))
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    // A completed successor cannot inherit the recovery parser's tolerance for
    // partial audit writes. This is data evidence only; the installed verifier
    // must also validate the intent, every retained object and the public image.
    static func completedEvidence(names: Set<String>, plan: String, operations: [ComponentOperation],
                                  read: (String) throws -> Data) throws -> Data {
        var captured: [String: Data] = [:]
        func once(_ name: String) throws -> Data {
            if let data = captured[name] { return data }
            let data = try read(name)
            _ = try FullImageJSON.object(data, maximum: name == "intent.json" ? 65536 : 4096)
            captured[name] = data
            return data
        }
        let state = try load(names: names, plan: plan, operations: operations, read: once)
        guard state.finished, !state.ownsDisable else { throw ComponentUpdateFailure.journal }
        _ = try once("intent.json")
        let expected = names.subtracting(Set(operations.map(\.slot)))
        guard Set(captured.keys) == expected else { throw ComponentUpdateFailure.journal }
        return try FullImageJSON.encode(["schema": 1,
            "managed_by": "account-access-completed-broker-repair-history-v1",
            "plan_sha256": plan, "record_sha256": captured.mapValues { FullImageJSON.hash($0) }] as [String: Any])
    }
    static func load(names: Set<String>, plan: String, operations: [ComponentOperation],
                     read: (String) throws -> Data) throws -> BrokerRepairJournal {
        guard FullImageJSON.hex(plan), names.contains("intent.json"), names.count <= 30007 else {
            throw ComponentUpdateFailure.journal
        }
        let slots = Set(operations.map(\.slot))
        var sequences: [String: Set<Int>] = ["event": [], "service": [], "job": []]
        var services: [(Int, String)] = [], jobs: [(Int, ComponentJobIdentity)] = []
        for name in names.subtracting(slots.union(["intent.json"])).sorted() {
            let parts = name.split(separator: "-")
            guard parts.count == 2, let kind = parts.first.map(String.init), sequences[kind] != nil,
                  name.hasSuffix(".json"), let sequence = Int(parts[1].dropLast(5)), (0..<10000).contains(sequence),
                  name == String(format: kind + "-%04d.json", sequence) else { throw ComponentUpdateFailure.journal }
            sequences[kind]!.insert(sequence)
            let bytes = try read(name)
            guard bytes.count <= 4096 else { throw ComponentUpdateFailure.journal }
            // A crash can leave an exclusive audit file partially written.
            guard (try? JSONSerialization.jsonObject(with: bytes, options: [.fragmentsAllowed])) != nil else { continue }
            let object = try FullImageJSON.object(bytes, maximum: 4096)
            guard try InstallerPayloadManifest.integer(object["schema"], maximum: 1) == 1 else { throw ComponentUpdateFailure.journal }
            if kind == "job" {
                let value = try JSONDecoder().decode(Job.self, from: bytes)
                guard value.planSHA256 == plan, try encode(value) == bytes else { throw ComponentUpdateFailure.journal }
                try ComponentUpdateIdentity.validateSnapshot(value.job)
                jobs.append((sequence, value.job))
            } else if kind == "service" {
                guard Set(object.keys) == ["schema", "event", "plan_sha256"], object["plan_sha256"] as? String == plan,
                      let event = object["event"] as? String, serviceEvents.contains(event) else { throw ComponentUpdateFailure.journal }
                services.append((sequence, event))
            } else {
                guard Set(object.keys) == ["schema", "event", "operation"],
                      let event = object["event"] as? String,
                      FullImageGlobalJournal.Transition(rawValue: event) != nil else { throw ComponentUpdateFailure.journal }
                let global = ["old_image_restored", "new_image_verified_gui_unverified"].contains(event)
                if global {
                    // Use canonical numeric spelling to reject booleans and fractions.
                    guard try FullImageJSON.canonical(object["operation"]!) == Data("-1".utf8) else { throw ComponentUpdateFailure.journal }
                } else {
                    let index = try InstallerPayloadManifest.integer(object["operation"], maximum: Int64(operations.count - 1))
                    guard operations.indices.contains(Int(index)) else { throw ComponentUpdateFailure.journal }
                }
            }
        }
        for values in sequences.values { guard values == Set(0..<values.count) else { throw ComponentUpdateFailure.journal } }
        let ordered = services.sorted { $0.0 < $1.0 }.map(\.1)
        let finished = ordered.last == "canonical_job_bootstrapped_gui_unverified"
        return BrokerRepairJournal(nextEvent: sequences["event"]!.count, nextService: sequences["service"]!.count,
            nextJob: sequences["job"]!.count, snapshots: jobs.sorted { $0.0 < $1.0 }.map(\.1),
            ownsDisable: !finished && ordered.contains("disable_intent_prior_enabled"), finished: finished)
    }
}
