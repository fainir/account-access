// Ordinary-user, data-only checks. Inputs are generated public package fixtures.
// No installed path or updater entrypoint can be selected by these arguments.
import Foundation
import Darwin

@main struct RuntimeUpgradeSourceChecks {
    static func main() throws {
        guard getuid() != 0, getuid() == geteuid(),
              CommandLine.arguments.count == 2 || (CommandLine.arguments.count == 3 && CommandLine.arguments[2] == "--positive-only") else { exit(77) }
        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        func read(_ name: String) throws -> Data { try Data(contentsOf: root.appendingPathComponent(name)) }
        let raw = try read("plan.json"), before = try read("before.json"), after = try read("after.json")
        let oldIdentity = try read("old-identity.json"), newIdentity = try read("new-identity.json")
        let value = try FullImageJSON.object(raw, maximum: 34 * 1024 * 1024)
        func pins(_ plan: Data) throws -> RuntimeUpgradeSource.Pins {
            guard let before = value["before_manifest_sha256"] as? String,
                  let after = value["after_manifest_sha256"] as? String,
                  let repair = value["predecessor_repair_plan_sha256"] as? String,
                  let repairSource = value["predecessor_repair_source"] as? String,
                  let source = value["target_source"] as? String,
                  let files = value["target_source_files"] as? [String: String] else { throw FullImageFailure.source }
            return .init(planSHA256: FullImageJSON.hash(plan), beforeSHA256: before, afterSHA256: after,
                repairPlan: repair, repairSource: repairSource, targetSource: source, sourceFiles: files)
        }
        func load(_ plan: Data, before candidateBefore: Data? = nil, after candidateAfter: Data? = nil,
                  old oldCandidate: Data? = nil, new newCandidate: Data? = nil) throws -> RuntimeUpgradeSource {
            try RuntimeUpgradeSource.load(pins: pins(plan), plan: plan, before: candidateBefore ?? before,
                after: candidateAfter ?? after, oldIdentity: oldCandidate ?? oldIdentity, newIdentity: newCandidate ?? newIdentity)
        }
        var checks = 0
        func check(_ yes: Bool) { precondition(yes); checks += 1 }
        func refuses(_ body: () throws -> Void) {
            var refused = false; do { try body() } catch { refused = true }; check(refused)
        }
        let accepted = try load(raw)
        check(accepted.changed == value["changed"] as? [String])
        check(accepted.units.count == (value["units"] as? [Any])?.count)
        check(accepted.units.map(\.path) == (value["units"] as? [[String: Any]])?.compactMap { $0["path"] as? String })
        check(PublicTreeUnit.fullImageCases.count == 13 && FullImagePlanFileUnit.fullImageCases.count == 12)
        func rows(_ tree: InstallerPayloadTree) throws -> Data {
            let values = tree.nodes.mapValues { node -> [String: Any] in
                switch node.kind {
                case "directory": return ["kind": node.kind, "mode": node.mode!]
                case "file": return ["kind": node.kind, "mode": node.mode!, "size": node.size!, "sha256": node.sha256!]
                default: return ["kind": node.kind, "target": node.target!]
                }
            }
            return try FullImageJSON.canonical(values)
        }
        let count = accepted.units.count
        check(try rows(FullImagePublicView.projection(source: accepted, states: Array(repeating: .staged, count: count)))
            == rows(accepted.before.trees[InstallerPayloadManifest.support]!))
        check(try rows(FullImagePublicView.projection(source: accepted, states: Array(repeating: .applied, count: count)))
            == rows(accepted.after.trees[InstallerPayloadManifest.support]!))
        check(try FullImagePublicStager.reserve(accepted) > 2 * 1024 * 1024)
        refuses { _ = try FullImagePublicView.projection(source: accepted, states: Array(repeating: .conflict, count: count)) }
        refuses { _ = try FullImagePublicView.projection(source: accepted, states: []) }
        for (index, unit) in accepted.units.enumerated() {
            if case .file(let selected, let old, let new) = unit {
                func object(_ node: InstallerPayloadNode?, inode: UInt64) -> ComponentObject? {
                    node.map { .init(device: 5, inode: inode, mode: $0.mode!, bytes: $0.size!, sha256: $0.sha256!) }
                }
                let operation = FullImageFileOperation(schema: 1, unit: .init(publicUnit: selected),
                    planSHA256: accepted.planSHA256, index: index,
                    before: object(old, inode: 10), after: object(new, inode: 11))
                try operation.validate(ownerDevice: 5); check(true)
                let inverted = FullImageFileOperation(schema: 1, unit: operation.unit, planSHA256: operation.planSHA256,
                    index: index, before: operation.after, after: operation.before)
                if selected == .repairIdentityRemoval { refuses { try inverted.validate(ownerDevice: 5) } }
            }
        }
        if CommandLine.arguments.count == 3 {
            print("{\"status\":\"PASSED\",\"checks\":" + String(checks) + ",\"installed_reads\":false,\"production_ready\":false}")
            return
        }
        checks += try RuntimeUpgradeNamespaceChecks.run()
        checks += try RuntimeUpgradeMetadataChecks.run(source: accepted)
        // These intentionally invalid pins cannot confer authority: the root
        // guard must refuse before consulting any pin or resource descriptor.
        let zero = String(repeating: "0", count: 64), commit = String(repeating: "0", count: 40)
        let predecessor = FullImageSourcePins(planSHA256: zero, targetSourceCommit: commit,
            targetManifestSHA256: zero, caReceiptSHA256: zero,
            predecessor: .init(planSHA256: zero, originalManifestSHA256: zero, manifestSHA256: zero, headSHA256: zero),
            predecessorSourceCommit: commit, targetSourceFiles: [:], providerManifestSHA256: zero, providerSourceBundleSHA256: zero)
        let repair = BrokerRepairSource.Pins(planSHA256: zero, predecessorPlanSHA256: zero,
            beforeManifestSHA256: zero, afterManifestSHA256: zero, sourceCommit: commit)
        var stages: [FullImageInstallCheckpoint] = []
        refuses { _ = try ComponentController.runRuntimeUpgrade(resources: -1, pins: accepted.pins,
            repairPins: repair, predecessorPins: predecessor, checkpoint: { stages.append($0) }) }
        check(stages == [.context])
        for key in Array(value.keys) + ["extra"] {
            var changed = value; changed[key] = "foreign"
            var bytes = try FullImageJSON.canonical(changed); bytes.append(10)
            refuses { _ = try load(bytes) }
        }
        for name in ["before", "after", "old", "new"] {
            refuses {
                _ = try load(raw, before: name == "before" ? Data("{}".utf8) : nil,
                    after: name == "after" ? Data("{}".utf8) : nil,
                    old: name == "old" ? Data("{}".utf8) : nil, new: name == "new" ? Data("{}".utf8) : nil)
            }
        }
        var noncanonical = raw; noncanonical.append(32)
        refuses { _ = try load(noncanonical) }
        print("{\"status\":\"PASSED\",\"checks\":" + String(checks) + ",\"installed_reads\":false,\"production_ready\":false}")
    }
}
