// Ordinary fixture reads only the prepared public-data input directory. No
// installed roots, payload execution, service, private policy or owner data.
import Foundation
import CryptoKit
import Darwin

private enum PlanFixtureFailure: Error { case failed }
@main struct FullImagePlanChecks {
    static var checks = 0
    static func expect(_ value: Bool) throws {
        guard value else { throw PlanFixtureFailure.failed }; checks += 1
    }
    static func refuses(_ body: () throws -> Void) throws {
        var refused = false
        do { try body() } catch { refused = true }
        try expect(refused)
    }
    static func read(_ root: Int32, _ name: String, _ maximum: Int) throws -> Data {
        let fd = openat(root, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw PlanFixtureFailure.failed }
        defer { Darwin.close(fd) }
        let info = try InstallerPayloadIO.check(fd, owner: getuid(), directory: false)
        guard info.st_mode & 0o7777 == 0o600 else { throw PlanFixtureFailure.failed }
        return try InstallerPayloadIO.read(fd, maximum: maximum, owner: getuid())
    }
    static func main() {
        guard getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 2 else { exit(77) }
        do {
            let root = open(CommandLine.arguments[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0 else { throw PlanFixtureFailure.failed }
            defer { Darwin.close(root) }
            let info = try InstallerPayloadIO.check(root, owner: getuid(), directory: true)
            guard info.st_mode & 0o7777 == 0o700 else { throw PlanFixtureFailure.failed }
            let raw = try read(root, "plan.json", 34 * 1024 * 1024)
            let before = try read(root, "before.json", 16 * 1024 * 1024)
            let after = try read(root, "after.json", 16 * 1024 * 1024)
            let oldIdentity = try read(root, "old-identity.json", 8192)
            let newIdentity = try read(root, "new-identity.json", 8192)
            let provider = try read(root, "provider.json", 16384)
            let ca = try read(root, "ca.json", 16384)
            let p = try FullImageJSON.object(read(root, "pins.json", 128 * 1024), maximum: 128 * 1024)
            let predecessor = p["predecessor"] as! [String: String]
            func pins(_ plan: Data, target: String? = nil, caPin: String? = nil) -> FullImageSourcePins {
                FullImageSourcePins(planSHA256: FullImageJSON.hash(plan), targetSourceCommit: p["targetSourceCommit"] as! String,
                    targetManifestSHA256: target ?? (p["targetManifestSHA256"] as! String), caReceiptSHA256: caPin ?? (p["caReceiptSHA256"] as! String),
                    predecessor: FullImagePredecessorPins(planSHA256: predecessor["planSHA256"]!, originalManifestSHA256: predecessor["originalManifestSHA256"]!, manifestSHA256: predecessor["manifestSHA256"]!, headSHA256: predecessor["headSHA256"]!),
                    predecessorSourceCommit: p["predecessorSourceCommit"] as! String,
                    targetSourceFiles: p["targetSourceFiles"] as! [String: String], providerManifestSHA256: p["providerManifestSHA256"] as! String,
                    providerSourceBundleSHA256: p["providerSourceBundleSHA256"] as! String)
            }
            func load(_ plan: Data, _ supplied: FullImageSourcePins? = nil,
                      before planBefore: Data? = nil, after planAfter: Data? = nil,
                      newIdentity planIdentity: Data? = nil) throws -> FullImageSource {
                try FullImageSource.load(plan: plan, before: planBefore ?? before, after: planAfter ?? after,
                    oldIdentity: oldIdentity, newIdentity: planIdentity ?? newIdentity,
                    providerManifest: provider, caReceipt: ca, pins: supplied ?? pins(plan))
            }
            print("PLAN_FIXTURE_STAGE: begin_complete_image"); fflush(stdout)
            let source = try load(raw)
            let expected = p["fixtureExpected"] as? [String: Any]
            let expectedCount = try InstallerPayloadManifest.integer(expected?["changed_nodes"] ?? 396, maximum: 100_000)
            let expectedTarget = expected?["target_manifest_sha256"] as? String ?? "ecb39f380b9666babab4384a24c6fcddce6c13274e7d9b25d75013a2464dd3d5"
            print("PLAN_FIXTURE_STAGE: complete_image_loaded"); fflush(stdout)
            try expect(Int64(source.changed.count) == expectedCount && source.units.count == 25)
            // A code-hash rotation is accepted only when the exact target
            // identity file, target manifest, update plan and policy pins all
            // agree. Team and bundle identifiers remain the product's fixed
            // Developer ID identities.
            func canonical(_ value: Any) throws -> Data {
                var data = try FullImageJSON.canonical(value); data.append(10); return data
            }
            var rotatedIdentity = try FullImageJSON.object(newIdentity, maximum: 8192)
            var signatures = rotatedIdentity["signatures"] as! [String: Any]
            for (kind, hash) in [("broker", String(repeating: "6", count: 40)),
                                 ("bootstrap", String(repeating: "7", count: 40))] {
                var peer = signatures[kind] as! [String: Any]
                peer["hashes"] = [hash]
                signatures[kind] = peer
            }
            rotatedIdentity["signatures"] = signatures
            let rotatedIdentityRaw = try canonical(rotatedIdentity)
            try refuses { _ = try load(raw, nil, before: before, after: after, newIdentity: rotatedIdentityRaw) }
            var rotatedManifest = try FullImageJSON.object(after, maximum: 16 * 1024 * 1024)
            var roots = rotatedManifest["roots"] as! [String: Any]
            var support = roots[InstallerPayloadManifest.support] as! [String: Any]
            var identityNode = support["package-identity.json"] as! [String: Any]
            identityNode["size"] = rotatedIdentityRaw.count
            identityNode["sha256"] = FullImageJSON.hash(rotatedIdentityRaw)
            support["package-identity.json"] = identityNode
            roots[InstallerPayloadManifest.support] = support
            rotatedManifest["roots"] = roots
            let rotatedAfter = try canonical(rotatedManifest)
            try refuses { _ = try load(raw, pins(raw, target: FullImageJSON.hash(rotatedAfter)),
                before: before, after: rotatedAfter, newIdentity: rotatedIdentityRaw) }
            var rotatedPlan = try FullImageJSON.object(raw, maximum: 34 * 1024 * 1024)
            rotatedPlan["new_peers"] = signatures
            var provenance = rotatedPlan["provenance"] as! [String: Any]
            provenance["target_manifest_sha256"] = FullImageJSON.hash(rotatedAfter)
            rotatedPlan["provenance"] = provenance
            var rotatedUnits = rotatedPlan["units"] as! [[String: Any]]
            let identityUnit = rotatedUnits.firstIndex { $0["path"] as? String == "package-identity.json" }!
            rotatedUnits[identityUnit]["after"] = ["kind": "file", "mode": identityNode["mode"]!,
                "size": identityNode["size"]!, "sha256": identityNode["sha256"]!]
            rotatedPlan["units"] = rotatedUnits
            let rotatedPlanRaw = try canonical(rotatedPlan)
            let rotatedSource = try load(rotatedPlanRaw,
                pins(rotatedPlanRaw, target: FullImageJSON.hash(rotatedAfter)),
                before: before, after: rotatedAfter, newIdentity: rotatedIdentityRaw)
            try expect(rotatedSource.changed.count == source.changed.count
                && rotatedSource.newPeers["broker"]?.hashes == [String(repeating: "6", count: 40)]
                && rotatedSource.newPeers["bootstrap"]?.hashes == [String(repeating: "7", count: 40)])
            let trees = source.units.compactMap { unit -> PublicTreeUnit? in
                if case .tree(let tree, _, _) = unit { return tree }; return nil
            }
            try expect(trees == PublicTreeUnit.fullImageCases)
            let optional = source.units.compactMap { unit -> PublicTreeUnit? in
                if case .tree(let tree, let old, let new) = unit, old.isPresent != new.isPresent { return tree }; return nil
            }
            try expect(optional == [.pythonOldPipInfo, .pythonPipInfo, .runtimeOldPipInfo, .runtimePipInfo])
            let files = source.units.compactMap { unit -> FullImagePlanFileUnit? in
                if case .file(let file, _, _) = unit { return file }; return nil
            }
            try expect(files.count == 12 && Set(files.map(\.path)) == Set(FullImagePlanFileUnit.fullImageCases.map(\.path)))
            try expect(source.pins.targetManifestSHA256 == expectedTarget)
            var plan = try FullImageJSON.object(raw, maximum: 34 * 1024 * 1024)
            // Re-pin every mutation to test semantic scope, not just hashing.
            for value in ["unreviewed-model-migration", NSNull(), true] as [Any] {
                var changedPlan = plan
                changedPlan["configuration_model_upgrade"] = value
                var changedRaw = try FullImageJSON.canonical(changedPlan); changedRaw.append(10)
                try refuses { _ = try load(changedRaw) }
            }
            if plan["configuration_model_upgrade"] != nil {
                var missingProfile = plan; missingProfile.removeValue(forKey: "configuration_model_upgrade")
                var changedRaw = try FullImageJSON.canonical(missingProfile); changedRaw.append(10)
                try refuses { _ = try load(changedRaw) }
                var falseClaim = plan; falseClaim["private_format_source_unchanged"] = true
                changedRaw = try FullImageJSON.canonical(falseClaim); changedRaw.append(10)
                try refuses { _ = try load(changedRaw) }
            }
            // Re-pin mutated plan bytes: these are semantic refusals, not only
            // a plan SHA mismatch. Nullable sides must agree exactly with data.
            var units = plan["units"] as! [[String: Any]]
            let index = units.firstIndex { $0["path"] as? String == PublicTreeUnit.pythonPipInfo.path }!
            units[index].removeValue(forKey: "before"); plan["units"] = units
            var missing = try FullImageJSON.canonical(plan); missing.append(10)
            print("PLAN_FIXTURE_STAGE: missing_side"); fflush(stdout)
            try refuses { _ = try load(missing) }
            plan = try FullImageJSON.object(raw, maximum: 34 * 1024 * 1024)
            units = plan["units"] as! [[String: Any]]
            units[index]["path"] = "python/lib/python3.12/site-packages"; plan["units"] = units
            var broad = try FullImageJSON.canonical(plan); broad.append(10)
            print("PLAN_FIXTURE_STAGE: broad_path"); fflush(stdout)
            try refuses { _ = try load(broad) }
            print("PLAN_FIXTURE_STAGE: wrong_target_pin"); fflush(stdout)
            try refuses { _ = try load(raw, pins(raw, target: String(repeating: "0", count: 64))) }
            print("PLAN_FIXTURE_STAGE: wrong_ca_pin"); fflush(stdout)
            try refuses { _ = try load(raw, pins(raw, caPin: String(repeating: "0", count: 64))) }
            let escaped = try FullImageJSON.canonical(["\u{10000}": "é", "\u{e000}": "x"])
            try expect(String(decoding: escaped, as: UTF8.self) == "{\"\\ue000\":\"x\",\"\\ud800\\udc00\":\"\\u00e9\"}")
            try refuses { _ = try FullImageJSON.object(Data("{\"x\":{\"a\":1,\"\\u0061\":2}}".utf8), maximum: 256) }
            print("{\"schema\":1,\"status\":\"PASSED\",\"checks\":\(checks),\"changed_nodes\":\(source.changed.count),\"tree_units\":13,\"file_units\":12,\"python_canonical_agreement\":true,\"signature_or_installed_authority_established\":false,\"production_ready\":false}")
        } catch {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"completed_checks\":\(checks),\"reason\":\"public_plan_fixture_failed\",\"production_ready\":false}")
            exit(78)
        }
    }
}
