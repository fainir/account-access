// Data-only parser tests. Ordinary identity, fictional files, no installation.
import Foundation
import Darwin

#if !ACCOUNT_ACCESS_OWNER_UPGRADE_PROBE
@main
#endif
struct OwnerUpgradeSourceChecks {
    static func main() throws {
        guard getuid() != 0, getuid() == geteuid(), CommandLine.arguments.count == 2 else { exit(78) }
        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        func read(_ name: String) throws -> Data { try Data(contentsOf: root.appendingPathComponent(name)) }
        let raw = try read("plan.json"), before = try read("before.json"), after = try read("after.json")
        let oldIdentity = try read("old-identity.json"), newIdentity = try read("new-identity.json")
        let value = try FullImageJSON.object(raw, maximum: 34 * 1024 * 1024)
        func pins(_ candidate: Data) throws -> OwnerUpgradeSource.Pins {
            guard let a = value["before_manifest_sha256"] as? String,
                  let b = value["after_manifest_sha256"] as? String,
                  let parent = value["predecessor_runtime_plan_sha256"] as? String,
                  let source = value["target_source"] as? String,
                  let files = value["target_native_source_files"] as? [String: String] else { throw FullImageFailure.source }
            return .init(planSHA256: FullImageJSON.hash(candidate), beforeSHA256: a, afterSHA256: b,
                predecessorRuntimePlan: parent, targetSource: source, sourceFiles: files)
        }
        func load(_ candidate: Data, before a: Data? = nil, after b: Data? = nil,
                  old c: Data? = nil, new d: Data? = nil) throws -> OwnerUpgradeSource {
            try OwnerUpgradeSource.load(pins: pins(candidate), plan: candidate, before: a ?? before, after: b ?? after,
                oldIdentity: c ?? oldIdentity, newIdentity: d ?? newIdentity)
        }
        var checks = 0
        func check(_ yes: Bool) { precondition(yes); checks += 1 }
        func refuses(_ body: () throws -> Void) {
            var refused = false; do { try body() } catch { refused = true }; check(refused)
        }
        let privateFailure = NSError(domain: "fictional-private-owner-upgrade", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "fictional-private-account-path"])
        for predecessorCheckpoint in CompletedPredecessorCheckpoint.allCases {
            let text = OwnerUpgradeDiagnostics.refusal(
                CompletedPredecessorDiagnostic(checkpoint: predecessorCheckpoint, failure: privateFailure),
                checkpoint: .predecessor)
            let value = try FullImageJSON.object(Data(text.utf8), maximum: 4096)
            check(value["reason"] as? String == "owner_upgrade_unavailable"
                && value["checkpoint"] as? String == "predecessor_" + predecessorCheckpoint.rawValue
                && !text.contains("fictional-private"))
        }
        let fixedRefusal = OwnerUpgradeDiagnostics.refusal(
            CompletedPredecessorDiagnostic(checkpoint: .workerBinding, failure: FullImageFailure.journal),
            checkpoint: .predecessor)
        let fixedValue = try FullImageJSON.object(Data(fixedRefusal.utf8), maximum: 4096)
        check(fixedValue["reason"] as? String == "owner_upgrade_transition_conflict"
            && fixedValue["checkpoint"] as? String == "predecessor_worker_binding")
        for repairCheckpoint in CompletedBrokerRepairCheckpoint.allCases {
            let text = OwnerUpgradeDiagnostics.refusal(
                CompletedBrokerRepairDiagnostic(checkpoint: repairCheckpoint, failure: FullImageFailure.source),
                checkpoint: .predecessorRepairHistory)
            let value = try FullImageJSON.object(Data(text.utf8), maximum: 4096)
            check(value["reason"] as? String == "owner_upgrade_source_not_verified"
                && value["checkpoint"] as? String == "predecessor_repair_history_" + repairCheckpoint.rawValue)
        }
        let intentRefusal = OwnerUpgradeDiagnostics.refusal(
            FullImageIntentReadDiagnostic(context: .predecessorRuntime, checkpoint: .structure,
                failure: FullImageFailure.journal), checkpoint: .predecessorIntent)
        let intentValue = try FullImageJSON.object(Data(intentRefusal.utf8), maximum: 4096)
        check(intentValue["reason"] as? String == "owner_upgrade_transition_conflict"
            && intentValue["checkpoint"] as? String == "predecessor_runtime_intent_structure"
            && !intentRefusal.contains("intent.json") && !intentRefusal.contains("/Library"))
        let fallbackRefusal = OwnerUpgradeDiagnostics.refusal(privateFailure, checkpoint: .predecessor)
        let fallbackValue = try FullImageJSON.object(Data(fallbackRefusal.utf8), maximum: 4096)
        check(fallbackValue["reason"] as? String == "owner_upgrade_unavailable"
            && fallbackValue["checkpoint"] as? String == "predecessor"
            && !fallbackRefusal.contains("fictional-private"))
        let source = try load(raw)
        check(source.changed == ["owner.app/Contents/Info.plist", "owner.app/Contents/MacOS/AccountAccess", "package-identity.json"])
        check(source.units.map(\.path) == ["owner.app", "package-identity.json"])
        check(source.oldPeers["owner"] != source.newPeers["owner"])
        check(source.oldPeers["broker"] == source.newPeers["broker"] && source.oldPeers["bootstrap"] == source.newPeers["bootstrap"])
        let payloadNames = Set(source.payload.trees[InstallerPayloadManifest.support]!.nodes.keys)
        check(payloadNames.allSatisfy { $0.isEmpty || $0 == "package-identity.json" || $0 == "owner.app" || $0.hasPrefix("owner.app/") })
        check(payloadNames.contains("owner.app/Contents/MacOS/AccountAccess") && payloadNames.contains("package-identity.json"))
        check(source.payload.sha256 != source.after.sha256)
        for name in value.keys {
            var changed = value; changed.removeValue(forKey: name)
            var modified = try FullImageJSON.canonical(changed); modified.append(10)
            refuses { _ = try load(modified) }
        }
        for field in ["installation_authority", "production_ready"] {
            var changed = value; changed[field] = true
            var modified = try FullImageJSON.canonical(changed); modified.append(10)
            refuses { _ = try load(modified) }
        }
        var foreign = value; foreign["unknown"] = "never a destination"
        var foreignRaw = try FullImageJSON.canonical(foreign); foreignRaw.append(10)
        refuses { _ = try load(foreignRaw) }
        refuses { _ = try load(raw + Data(" ".utf8)) }
        refuses { _ = try load(raw, before: after) }
        refuses { _ = try load(raw, after: before) }
        refuses { _ = try load(raw, old: newIdentity) }
        refuses { _ = try load(raw, new: oldIdentity) }
        let duplicate = Data("{\"schema\":1,".utf8) + raw.dropFirst()
        refuses { _ = try load(duplicate) }
        print("{\"schema\":1,\"status\":\"PASSED\",\"checks\":" + String(checks)
            + ",\"installed_reads\":false,\"installed_writes\":false,\"production_ready\":false}")
    }
}
