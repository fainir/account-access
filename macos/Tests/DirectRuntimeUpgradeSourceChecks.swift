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
    private static func retainedPreparationChecks() throws -> Int {
        let rootPath = NSTemporaryDirectory() + "account-access-retained-" + UUID().uuidString.lowercased()
        guard mkdir(rootPath, 0o700) == 0 else { throw FullImageFailure.object }
        defer { try? FileManager.default.removeItem(atPath: rootPath) }
        let root = open(rootPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw FullImageFailure.object }
        defer { Darwin.close(root) }
        func directory(_ parent: Int32, _ name: String) throws -> Int32 {
            guard mkdirat(parent, name, 0o700) == 0 else { throw FullImageFailure.object }
            let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw FullImageFailure.object }
            return fd
        }
        let namespace = try directory(root, "namespace"); defer { Darwin.close(namespace) }
        let current = DirectRuntimeUpgradeSource.planSHA256
        let old = "681f2b48c2b35bc1ccdb4309da636b1b88fcbeb2b2ae982b92dbf0c4198dd51e"
        let name = ".preparing-" + old + "-" + UUID().uuidString.lowercased()
        let retained = try directory(namespace, name); defer { Darwin.close(retained) }
        let content = Data("earlier unpublished preparation".utf8)
        _ = try ComponentFiles.writeExclusive(retained, "partial", data: content, owner: getuid(), mode: 0o600)
        let before = try ComponentFiles.observe(retained, "partial", owner: getuid())
        var checks = 0
        func observe(_ allow: Bool = true) throws -> Int {
            try FullImagePreparationInspector.retained(namespace, plan: current, owner: getuid(), group: getgid(),
                allowOtherPlanPreparations: allow)
        }
        func refuses(_ body: () throws -> Void) throws {
            var rejected = false
            do { try body() } catch { rejected = true }
            try require(rejected); checks += 1
        }
        try refuses { _ = try observe(false) }
        try require(try observe() == 1); checks += 1
        try require(try ComponentFiles.observe(retained, "partial", owner: getuid()) == before)
        try require(try Data(contentsOf: URL(fileURLWithPath: rootPath + "/namespace/" + name + "/partial")) == content)
        checks += 1
        let publishedName = "transition-" + old
        let published = try directory(namespace, publishedName); Darwin.close(published)
        try refuses { _ = try observe() }
        try FileManager.default.removeItem(atPath: rootPath + "/namespace/" + publishedName)
        let malformed = try directory(namespace, ".preparing-not-a-plan"); Darwin.close(malformed)
        try refuses { _ = try observe() }
        try FileManager.default.removeItem(atPath: rootPath + "/namespace/.preparing-not-a-plan")
        guard linkat(retained, "partial", root, "outside-hardlink", 0) == 0 else { throw FullImageFailure.object }
        try refuses { _ = try observe() }
        guard unlinkat(root, "outside-hardlink", 0) == 0,
              fchmodat(retained, "partial", 0o666, 0) == 0 else { throw FullImageFailure.object }
        try refuses { _ = try observe() }
        guard fchmodat(retained, "partial", 0o600, 0) == 0 else { throw FullImageFailure.object }
        for _ in 0..<7 {
            let child = try directory(namespace, ".preparing-" + old + "-" + UUID().uuidString.lowercased())
            Darwin.close(child)
        }
        try require(try observe() == 8); checks += 1
        let ninth = try directory(namespace, ".preparing-" + old + "-" + UUID().uuidString.lowercased()); Darwin.close(ninth)
        try refuses { _ = try observe() }
        return checks
    }
    static func main() {
        do {
            guard CommandLine.arguments.count == 2 else { throw FullImageFailure.source }
            // Runtime 95 already published root:wheel descendants. A later
            // root:admin support directory must not change their expected GID.
            for unit in PublicTreeUnit.directRuntimeDeltaCases {
                try require(unit.publishedPredecessorGroups && !unit.runtimeUpgrade)
                try require(unit.precedingGroup("", legacy: 80, published: 0) == 0)
                try require(unit.precedingGroup("nested/file", legacy: 80, published: 0) == 0)
            }
            try require(!PublicTreeUnit.project.publishedPredecessorGroups && !PublicTreeUnit.distInfo.publishedPredecessorGroups)
            try require(PublicTreeUnit.project.precedingGroup("", legacy: 80, published: 0) == 80)
            try require(PublicTreeUnit.distInfo.precedingGroup("", legacy: 80, published: 0) == 80)
            try require(!PublicTreeUnit.fullImageCases.contains(.directProject)
                && !PublicTreeUnit.fullImageCases.contains(.directDistInfo))
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
            try require(PublicTreeUnit.directRuntimeDeltaCases.contains(.directProject)
                && PublicTreeUnit.directRuntimeDeltaCases.contains(.directDistInfo))
            try require(source.units.filter { if case .tree = $0 { return true }; return false }.count == 8)
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
            // Exercise the complete journal, including the four policy records
            // appended beyond the original 64-operation transition limit.
            var journalOperations: [FullImageDurableOperation] = []
            for (index, unit) in source.units.enumerated() {
                let inode = UInt64(100_000 + index * 2)
                switch unit {
                case .tree(let tree, let old, let new):
                    func pin(_ inventory: PublicTreeInventory, _ inode: UInt64) -> PublicTreePin? {
                        inventory.inventorySHA256.map {
                            PublicTreePin(device: 7, inode: inode, owner: 0, group: 0, mode: 0o755, inventorySHA256: $0)
                        }
                    }
                    journalOperations.append(.init(tree: PublicTreeOperation(schema: 2, unit: tree.rawValue,
                        planSHA256: directPlan, beforeManifestSHA256: source.before.sha256,
                        afterManifestSHA256: source.after.sha256, before: pin(old, inode), after: pin(new, inode + 1))))
                case .file(let file, let before, let after):
                    journalOperations.append(.init(file: FullImageFileOperation(schema: 1,
                        unit: .init(publicUnit: file), planSHA256: directPlan, index: index,
                        before: object(before, inode: inode), after: object(after, inode: inode + 1))))
                case .directFile(let path, let mode, let before, let after):
                    journalOperations.append(.init(file: FullImageFileOperation(schema: 1,
                        unit: .directPublicFile, planSHA256: directPlan, index: index,
                        before: object(before, inode: inode), after: object(after, inode: inode + 1),
                        directPath: path, directMode: mode)))
                }
            }
            let proof = String(repeating: "e", count: 64)
            let policy = ComponentObject(device: 7, inode: 300_000, mode: 0o644, bytes: 1, sha256: proof)
            let plist = ComponentObject(device: 7, inode: 300_001, mode: 0o644, bytes: 1, sha256: proof)
            let dynamic: [FullImageFileUnit: Data] = [.hostPolicy: Data("synthetic host".utf8),
                .ownerPolicy: Data("synthetic owner".utf8), .installRecord: Data("synthetic install".utf8),
                .head: try FullImageGlobalIntent.newHead(source: source, predecessorEvidenceSHA256: proof)]
            for unit in [FullImageFileUnit.hostPolicy, .ownerPolicy, .installRecord, .head] {
                let index = journalOperations.count, inode = UInt64(100_000 + index * 2), raw = dynamic[unit]!
                let before = unit == .head ? nil : ComponentObject(device: 7, inode: inode,
                    mode: unit.mode, bytes: 1, sha256: proof)
                let after = ComponentObject(device: 7, inode: inode + 1, mode: unit.mode,
                    bytes: Int64(raw.count), sha256: FullImageJSON.hash(raw))
                journalOperations.append(.init(file: FullImageFileOperation(schema: 1, unit: unit,
                    planSHA256: directPlan, index: index, before: before, after: after)))
            }
            let intent = FullImageGlobalIntent(schema: 2, managedBy: DirectRuntimeUpgradeSource.managedBy,
                planSHA256: directPlan, beforeManifestSHA256: source.before.sha256,
                afterManifestSHA256: source.after.sha256, targetSourceCommit: source.targetSourceCommit,
                predecessorEvidenceSHA256: proof, ownerUID: 501, brokerUID: 499, initialService: nil,
                workerPolicy: policy, servicePlist: plist, operations: journalOperations, automaticRebootRecovery: false)
            try intent.validate(source: source, predecessorEvidenceSHA256: proof, workerPolicy: policy,
                servicePlist: plist, ownerUID: 501, brokerUID: 499, publicOwner: 0, publicGroup: 0,
                beforeGroup: 80, device: 7, dynamic: dynamic)
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
            let policyOperation = journalOperations[count].file!
            refuses(.init(schema: 1, unit: .hostPolicy, planSHA256: String(repeating: "0", count: 64),
                index: count, before: policyOperation.before, after: policyOperation.after))
            refuses(.init(schema: 1, unit: .requirements, planSHA256: directPlan,
                index: count, before: policyOperation.before, after: policyOperation.after))
            var tampered = planRaw; tampered[tampered.startIndex] ^= 1
            do {
                _ = try DirectRuntimeUpgradeSource.load(plan: tampered, before: beforeRaw, after: afterRaw,
                    oldIdentity: oldIdentity, newIdentity: newIdentity,
                    pins: .init(planSHA256: DirectRuntimeUpgradeSource.planSHA256,
                        beforeSHA256: DirectRuntimeUpgradeSource.beforeSHA256,
                        afterSHA256: DirectRuntimeUpgradeSource.afterSHA256,
                        targetSourceCommit: DirectRuntimeUpgradeSource.sourceCommit))
            } catch { refusals += 1 }
            try require(refusals == 6)
            let retainedChecks = try retainedPreparationChecks()
            try require(retainedChecks == 9)
            let report: [String: Any] = ["status": "PASSED", "changed_nodes": source.changed.count,
                "units": count, "direct_files_added": additions, "direct_files_removed": removals,
                "retained_preparation_checks": retainedChecks, "projection_checks": 2, "journal_operations": journalOperations.count, "refusal_checks": refusals, "installed_reads": false,
                "service_actions": false, "production_ready": false]
            let encoded = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
            print(String(decoding: encoded, as: UTF8.self))
        } catch {
            fputs("direct_runtime_upgrade_source_checks_refused: \(error)\n", stderr)
            exit(1)
        }
    }
}
