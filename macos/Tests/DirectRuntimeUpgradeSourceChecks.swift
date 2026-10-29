// Public artifact contract checks only. This fixture never reads an installed
// Account Access path, opens account data, runs as root, or controls services.
import Foundation
import Darwin

@main struct DirectRuntimeUpgradeSourceChecks {
    private static func require(_ value: Bool, line: UInt = #line) throws {
        guard value else {
            fputs("direct runtime source assertion failed at line \(line)\n", stderr)
            throw FullImageFailure.source
        }
    }
    private static func rows(_ tree: InstallerPayloadTree) throws -> Data {
        let values = tree.nodes.mapValues { node -> [String: Any] in
            switch node.kind {
            case "directory": return ["kind": node.kind, "mode": node.mode!]
            case "file": return ["kind": node.kind, "mode": node.mode!, "size": node.size!, "sha256": node.sha256!]
            default: return ["kind": node.kind, "target": node.target!]
            }
        }
        return try FullImageJSON.canonical(values)
    }
    private static func object(_ node: InstallerPayloadNode?, inode: UInt64) -> ComponentObject? {
        node.map { .init(device: 7, inode: inode, mode: UInt16($0.mode!), bytes: $0.size!, sha256: $0.sha256!) }
    }
    static func main() {
        do {
            guard CommandLine.arguments.count == 2 else { throw FullImageFailure.source }
            let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
            func read(_ name: String, max: Int) throws -> Data {
                let url = root.appendingPathComponent(name, isDirectory: false)
                let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
                guard attributes[.type] as? FileAttributeType == .typeRegular,
                      let size = attributes[.size] as? NSNumber, size.intValue <= max else { throw FullImageFailure.source }
                return try Data(contentsOf: url, options: [.mappedIfSafe])
            }
            let planRaw = try read("plan.json", max: 34 * 1024 * 1024)
            let beforeRaw = try read("before.json", max: InstallerPayloadManifest.maximumManifest)
            let afterRaw = try read("after.json", max: InstallerPayloadManifest.maximumManifest)
            let oldIdentity = try read("old-identity.json", max: 8192)
            let newIdentity = try read("new-identity.json", max: 8192)
            let source = try DirectRuntimeUpgradeSource.load(plan: planRaw, before: beforeRaw, after: afterRaw,
                oldIdentity: oldIdentity, newIdentity: newIdentity,
                pins: .init(planSHA256: DirectRuntimeUpgradeSource.planSHA256,
                    beforeSHA256: DirectRuntimeUpgradeSource.beforeSHA256,
                    afterSHA256: DirectRuntimeUpgradeSource.afterSHA256,
                    targetSourceCommit: DirectRuntimeUpgradeSource.sourceCommit))
            let planValue = try FullImageJSON.object(planRaw, maximum: 34 * 1024 * 1024)
            guard let targetSourceFiles = planValue["target_source_files"] as? [String: String] else {
                throw FullImageFailure.source
            }
            let runtimeSource = RuntimeUpgradeSource(
                pins: .init(planSHA256: source.planSHA256, beforeSHA256: source.before.sha256,
                    afterSHA256: source.after.sha256, repairPlan: String(repeating: "0", count: 64),
                    repairSource: String(repeating: "0", count: 40), targetSource: source.targetSourceCommit,
                    sourceFiles: targetSourceFiles, direct: true),
                before: source.before, after: source.after, oldPeers: source.oldPeers,
                newPeers: source.newPeers, units: source.units, changed: source.changed)
            let payloadTree = try ComponentController.runtimeDeltaPayloadTree(runtimeSource)
            let expectedOwnerBundle = Set(source.after.trees[InstallerPayloadManifest.support]!.nodes.keys.filter {
                $0 == "owner.app" || $0.hasPrefix("owner.app/")
            })
            let actualOwnerBundle = Set(payloadTree.nodes.keys.filter {
                $0 == "owner.app" || $0.hasPrefix("owner.app/")
            })
            try require(actualOwnerBundle == expectedOwnerBundle)
            try require(payloadTree.nodes["owner.app/Contents/_CodeSignature/CodeResources"]?.kind == "file")
            let count = source.units.count
            guard let changedRows = planValue["changed"] as? [String],
                  let unitRows = planValue["units"] as? [[String: Any]] else { throw FullImageFailure.source }
            try require(count == unitRows.count && source.changed.count == changedRows.count)
            try require(PublicTreeUnit.directRuntimeDeltaCases.contains(.project)
                && PublicTreeUnit.directRuntimeDeltaCases.contains(.distInfo))
            try require(source.units.filter { if case .tree = $0 { return true }; return false }.count == 5)
            try require(source.units.filter { if case .file = $0 { return true }; return false }.count == 5)
            let directCount = source.units.filter { if case .directFile = $0 { return true }; return false }.count
            try require(directCount == unitRows.filter { $0["kind"] as? String == "direct_file" }.count)
            try require(source.targetSourceCommit == DirectRuntimeUpgradeSource.sourceCommit)
            let stagedRows = try rows(FullImagePublicView.projection(source: source,
                states: Array(repeating: .staged, count: count)))
            let appliedRows = try rows(FullImagePublicView.projection(source: source,
                states: Array(repeating: .applied, count: count)))
            try require(stagedRows == rows(source.before.trees[InstallerPayloadManifest.support]!))
            try require(appliedRows == rows(source.after.trees[InstallerPayloadManifest.support]!))
            let directPlan = source.planSHA256
            var additions = 0, removals = 0
            for (index, unit) in source.units.enumerated() {
                guard case .directFile(let path, let mode, let before, let after) = unit else { continue }
                let operation = FullImageFileOperation(schema: 1, unit: .directPublicFile, planSHA256: directPlan,
                    index: index, before: object(before, inode: UInt64(10_000 + index * 2)),
                    after: object(after, inode: UInt64(10_001 + index * 2)), directPath: path, directMode: mode)
                try operation.validate(ownerDevice: 7)
                if before == nil { additions += 1 }
                if after == nil { removals += 1 }
            }
            let expectedAdditions = unitRows.filter {
                $0["kind"] as? String == "direct_file" && $0["before"] is NSNull
            }.count
            let expectedRemovals = unitRows.filter {
                $0["kind"] as? String == "direct_file" && $0["after"] is NSNull
            }.count
            try require(additions == expectedAdditions && removals == expectedRemovals)
            let first = source.units.enumerated().compactMap { index, unit -> FullImageFileOperation? in
                guard case .directFile(let path, let mode, let before, let after) = unit else { return nil }
                return FullImageFileOperation(schema: 1, unit: .directPublicFile, planSHA256: directPlan,
                    index: index, before: object(before, inode: UInt64(20_000 + index * 2)),
                    after: object(after, inode: UInt64(20_001 + index * 2)), directPath: path, directMode: mode)
            }.first!
            var refusals = 0
            func refuses(_ operation: FullImageFileOperation) {
                do { try operation.validate(ownerDevice: 7) } catch { refusals += 1 }
            }
            refuses(.init(schema: 1, unit: .directPublicFile, planSHA256: String(repeating: "0", count: 64),
                index: first.index, before: first.before, after: first.after, directPath: first.directPath, directMode: first.directMode))
            refuses(.init(schema: 1, unit: .directPublicFile, planSHA256: directPlan,
                index: 256, before: first.before, after: first.after, directPath: first.directPath, directMode: first.directMode))
            refuses(.init(schema: 1, unit: .directPublicFile, planSHA256: directPlan,
                index: first.index, before: first.before, after: first.after, directPath: "runtime/../broker/install.json", directMode: first.directMode))
            var tampered = planRaw; tampered[tampered.startIndex] ^= 1
            do {
                _ = try DirectRuntimeUpgradeSource.load(plan: tampered, before: beforeRaw, after: afterRaw,
                    oldIdentity: oldIdentity, newIdentity: newIdentity,
                    pins: .init(planSHA256: DirectRuntimeUpgradeSource.planSHA256,
                        beforeSHA256: DirectRuntimeUpgradeSource.beforeSHA256,
                        afterSHA256: DirectRuntimeUpgradeSource.afterSHA256,
                        targetSourceCommit: DirectRuntimeUpgradeSource.sourceCommit))
            } catch { refusals += 1 }
            try require(refusals == 4)
            let report: [String: Any] = ["status": "PASSED", "changed_nodes": source.changed.count,
                "units": count, "direct_files_added": additions, "direct_files_removed": removals,
                "projection_checks": 2, "refusal_checks": refusals, "installed_reads": false,
                "service_actions": false, "production_ready": false]
            let encoded = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
            print(String(decoding: encoded, as: UTF8.self))
        } catch {
            fputs("direct_runtime_upgrade_source_checks_refused\n", stderr)
            exit(1)
        }
    }
}
