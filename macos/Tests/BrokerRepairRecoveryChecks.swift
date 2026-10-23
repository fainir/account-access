// Ordinary-user fixtures. No installed paths, root services or credentials.
import Foundation
import Darwin

enum BrokerRepairRecoveryChecks {
    static func run(source: BrokerRepairSource) throws -> Int {
        var assertions = 0
        func check(_ value: Bool) { precondition(value); assertions += 1 }
        func refuses(_ body: () throws -> Void) {
            var refused = false; do { try body() } catch { refused = true }; check(refused)
        }
        var history: [String: Data] = ["intent.json": Data("fictional original intent".utf8),
            "record-0000.json": Data("fictional first record".utf8), "record-0001.json": Data("fictional last record".utf8)]
        func evidence(_ values: [String: Data]) throws -> Data {
            try BrokerRepairHistory.evidence(names: Set(values.keys)) { name, _ in values[name]! }
        }
        let original = try evidence(history)
        let expected = try FullImageJSON.encode(["intent_sha256": FullImageJSON.hash(history["intent.json"]!),
            "record_sha256": [FullImageJSON.hash(history["record-0000.json"]!), FullImageJSON.hash(history["record-0001.json"]!)],
            "pending_sha256": [:] as [String: String]])
        check(original == expected)
        for name in history.keys {
            var changed = history; changed[name]!.append(32)
            check(try evidence(changed) != original)
        }
        for name in ["pending-intent-00", "pending-record-0002-00", "record-0003.json", "record-001.json", "foreign"] {
            var changed = history; changed[name] = Data("fictional".utf8)
            refuses { _ = try evidence(changed) }
        }
        for name in ["intent.json", "record-0000.json"] {
            var changed = history; changed.removeValue(forKey: name)
            refuses { _ = try evidence(changed) }
        }
        for (name, limit) in [("intent.json", 262144), ("record-0000.json", 8192)] {
            for size in [0, limit + 1] {
                var changed = history; changed[name] = Data(repeating: 65, count: size)
                refuses { _ = try evidence(changed) }
            }
        }
        history["record-0002.json"] = Data("fictional appended record".utf8)
        check(try evidence(history) != original)
        let object = ComponentObject(device: 20, inode: 100, mode: 0o644, bytes: 1, sha256: String(repeating: "a", count: 64))
        let operations = BrokerRepairIntent.targets.enumerated().map { index, target in
            ComponentOperation(target: target.0, path: target.1, slot: String(format: "slot-%02d", index), before: nil, after: object)
        }
        func service(_ event: String, plan: String? = nil) throws -> Data {
            try FullImageJSON.encode(["schema": 1, "event": event, "plan_sha256": plan ?? source.pins.planSHA256])
        }
        func journal(_ records: [String: Data]) throws -> BrokerRepairJournal {
            try BrokerRepairJournal.load(names: Set(records.keys).union(["intent.json"]), plan: source.pins.planSHA256,
                operations: operations) { records[$0]! }
        }
        let empty = try journal([:]); check(!empty.ownsDisable && !empty.finished && empty.nextService == 0)
        var records = ["service-0000.json": try service("disable_intent_prior_enabled")]
        check(try journal(records).ownsDisable)
        records["service-0001.json"] = try service("canonical_job_bootstrapped_gui_unverified")
        check(try journal(records).finished && !journal(records).ownsDisable)
        records["service-0002.json"] = Data("{\"schema\":".utf8)
        let partial = try journal(records)
        check(partial.finished && !partial.ownsDisable && partial.nextService == 3)
        records["service-0002.json"] = try service("disable_intent_prior_enabled")
        check(try !journal(records).finished && journal(records).ownsDisable)
        for (name, bytes) in [
            ("service-0000.json", try service("foreign")),
            ("service-0000.json", try service("disable_intent_prior_enabled", plan: String(repeating: "f", count: 64))),
            ("service-0001.json", try service("disable_intent_prior_enabled")),
            ("service-00000.json", Data("{".utf8)), ("foreign", Data("{".utf8)),
            ("service-0000.json", Data("[]".utf8)),
            ("service-0000.json", Data(repeating: 65, count: 4097))] {
            refuses { _ = try journal([name: bytes]) }
        }
        for event in FullImageGlobalJournal.Transition.allCases {
            let global = [.oldImageRestored, .newImageVerified].contains(event)
            let bytes = try FullImageJSON.encode(["schema": 1, "event": event.rawValue, "operation": global ? -1 : 0])
            check(try journal(["event-0000.json": bytes]).nextEvent == 1)
            for bad: Any in [true, global ? 0 : -1, 6, "0", NSNull()] {
                let invalid = try FullImageJSON.encode(["schema": 1, "event": event.rawValue, "operation": bad])
                refuses { _ = try journal(["event-0000.json": invalid]) }
            }
        }
        let valid = try service("disable_intent_prior_enabled")
        let duplicate = Data(String(decoding: valid, as: UTF8.self).replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1,\"schema\":1").utf8)
        refuses { _ = try journal(["service-0000.json": duplicate]) }
        // Both installed entry points refuse before opening a descriptor.
        refuses { _ = try BrokerRepairRoutes(plan: source.pins.planSHA256, predecessorPlan: source.pins.predecessorPlanSHA256) }
        var checkpoints: [BrokerRepairCheckpoint] = []
        let predecessor = try FullImageInstalledSourceFixture.source()
        refuses { _ = try ComponentController.runBrokerRepair(resources: -1, pins: source.pins,
            predecessorPins: predecessor.pins, checkpoint: { checkpoints.append($0) }) }
        check(checkpoints == [.context])
        return assertions
    }
}
