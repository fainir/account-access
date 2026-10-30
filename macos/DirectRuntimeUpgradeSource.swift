// One exact migration from the installed build-110 public image to the
// source-current build-120 runtime image. It grants no path authority beyond the
// manifest delta and is kept separate from the general update contracts.
import Foundation

struct DirectRuntimeUpgradeSource: PublicImageTransitionSource {
    // Public-plan failures carry only a source line for fixture diagnosis.
    // Installer entrypoints continue to return their fixed refusal response.
    struct Refused: Error { let line: UInt }
    static let managedBy = "account-access-exact-installed-runtime-delta-v1"
    static let planSHA256 = FullImageFileOperation.directRuntimePlanSHA256
    static let beforeSHA256 = "568c79ca3b45ffc357bc5af2b420d481e729630b0120dc6d0058c1a396ad21b1"
    static let afterSHA256 = "6ab5f90fa72dfed84c295d5df4741d3cb9aaf6a0fa89ed155b4cb76400570874"
    static let sourceCommit = "beda6324d836458a35045ee0d2acd579238d6929"
    static let originalReceipt = "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8"

    struct Pins {
        let planSHA256: String
        let beforeSHA256: String
        let afterSHA256: String
        let targetSourceCommit: String
    }
    let pins: Pins
    var planSHA256: String { pins.planSHA256 }
    var targetSourceCommit: String { pins.targetSourceCommit }
    var directRuntimeDelta: Bool { true }
    let before: InstallerPayloadManifest
    let after: InstallerPayloadManifest
    let oldPeers: [String: ComponentPeerSignature]
    let newPeers: [String: ComponentPeerSignature]
    let units: [FullImageSource.Unit]
    let changed: [String]

    private static let support = InstallerPayloadManifest.support
    private static let application = InstallerPayloadManifest.application
    private static let site = "runtime/lib/python3.12/site-packages/"
    private static let package = site + "account_access"
    private static let fixed: [(String, FullImagePlanFileUnit)] = [
        ("package-identity.json", .packageIdentity), ("package-requirements.txt", .requirements),
        ("runtime-image.json", .runtimeImage), ("runtime-preparation.json", .runtimePreparation),
        ("runtime-ca-refresh.json", .caReplacement), ("broker-repair-identity.json", .repairIdentityRemoval)
    ]
    private static let directRoots: Set<String> = ["owner.app", "python", "runtime", "browsers", "wheels", "bin"]
    private static let privateNames: Set<String> = ["broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"]

    private static func below(_ path: String, _ prefix: String) -> Bool { path == prefix || path.hasPrefix(prefix + "/") }
    private static func node(_ value: InstallerPayloadNode?) -> Any {
        guard let value else { return NSNull() }
        switch value.kind {
        case "file": return ["kind": value.kind, "mode": value.mode!, "size": value.size!, "sha256": value.sha256!] as [String: Any]
        case "directory": return ["kind": value.kind, "mode": value.mode!] as [String: Any]
        default: return ["kind": value.kind, "target": value.target!] as [String: Any]
        }
    }
    private static func rows(_ tree: InstallerPayloadTree, prefix: String) -> [String: Any] {
        tree.nodes.filter { below($0.key, prefix) }.mapValues { node($0) }
    }
    private static func identity(_ raw: Data, tree: InstallerPayloadTree) throws -> [String: ComponentPeerSignature] {
        let value = try FullImageJSON.object(raw, maximum: 8192)
        guard tree.nodes["package-identity.json"]?.sha256 == FullImageJSON.hash(raw),
              tree.nodes["package-identity.json"]?.size == Int64(raw.count),
              Set(value.keys) == ["schema", "managed_by", "signatures"],
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["managed_by"] as? String == "account-access-package-identity-v1",
              let peers = value["signatures"] as? [String: [String: Any]],
              Set(peers.keys) == ["owner", "broker", "bootstrap"] else { throw Refused(line: #line) }
        var result: [String: ComponentPeerSignature] = [:]
        for (kind, peer) in peers {
            let identifier = "com.fainir.accountaccess" + (kind == "owner" ? "" : "." + kind)
            guard Set(peer.keys) == ["team", "identifier", "hashes"], peer["team"] as? String == "WBULD6N4NQ",
                  peer["identifier"] as? String == identifier, let hashes = peer["hashes"] as? [String],
                  (1...2).contains(hashes.count), hashes == Array(Set(hashes)).sorted(),
                  hashes.allSatisfy({ FullImageJSON.hex($0, count: 40) }) else { throw Refused(line: #line) }
            result[kind] = .init(team: "WBULD6N4NQ", identifier: identifier, hashes: hashes)
        }
        return result
    }
    private static func sourceFiles(_ supplied: Any, after: InstallerPayloadTree) throws -> [String: String] {
        guard let files = supplied as? [String: String], !files.isEmpty, files.count <= 1000,
              files.values.allSatisfy({ FullImageJSON.hex($0) }) else { throw Refused(line: #line) }
        var expected: [String: String] = [:]
        for (path, item) in after.nodes where below(path, package) && path.hasSuffix(".py") && item.kind == "file" {
            expected[String(path.dropFirst(site.count))] = item.sha256!
        }
        guard !expected.isEmpty, files == expected else { throw Refused(line: #line) }
        return files
    }
    private static func allChanged(_ old: InstallerPayloadTree, _ new: InstallerPayloadTree) throws -> [String] {
        try Set(old.nodes.keys).union(new.nodes.keys).filter {
            try !FullImageJSON.same(node(old.nodes[$0]), node(new.nodes[$0]))
        }.sorted()
    }
    private static func loadUnits(_ planUnits: [[String: Any]], changed: [String], before: InstallerPayloadManifest,
                                  after: InstallerPayloadManifest) throws -> [FullImageSource.Unit] {
        let old = before.trees[support]!, new = after.trees[support]!
        var units: [FullImageSource.Unit] = [], expected: [[String: Any]] = [], covered: [String] = []
        for unit in PublicTreeUnit.directRuntimeDeltaCases {
            let owned = changed.filter { below($0, unit.path) }
            guard !owned.isEmpty else { continue }
            let a = try PublicTreeInventory(validatedManifest: before, unit: unit)
            let b = try PublicTreeInventory(validatedManifest: after, unit: unit)
            guard unit.accepts(old: a, new: b) else { throw Refused(line: #line) }
            expected.append(["kind": "public_tree", "path": unit.path,
                "before": a.isPresent ? rows(old, prefix: unit.path) : NSNull(),
                "after": b.isPresent ? rows(new, prefix: unit.path) : NSNull(), "changed": owned])
            units.append(.tree(unit, a, b)); covered += owned
        }
        for (path, unit) in fixed {
            let a = old.nodes[path], b = new.nodes[path]
            if try FullImageJSON.same(node(a), node(b)) { continue }
            guard a == nil || a?.kind == "file", b == nil || b?.kind == "file",
                  (a == nil || a?.mode == unit.mode), (b == nil || b?.mode == unit.mode) else { throw Refused(line: #line) }
            expected.append(["kind": "fixed_file", "path": path, "before": node(a), "after": node(b), "changed": [path]])
            units.append(.file(unit, a, b)); covered.append(path)
        }
        for path in changed where !covered.contains(path) && !PublicTreeUnit.directRuntimeDeltaCases.contains(where: { below(path, $0.path) }) {
            guard !path.hasPrefix("/"), !path.contains("\\"),
                  let parts = try? InstallerPayloadManifest.components(path), let root = parts.first, directRoots.contains(root),
                  !privateNames.contains(root.lowercased()) else { throw Refused(line: #line) }
            let a = old.nodes[path], b = new.nodes[path]
            guard a == nil || a?.kind == "file", b == nil || b?.kind == "file",
                  a != nil || b != nil, (a == nil || b == nil || a?.mode == b?.mode),
                  let mode = (a ?? b)?.mode, mode == 0o644 || mode == 0o755 else { throw Refused(line: #line) }
            expected.append(["kind": "direct_file", "path": path, "mode": mode,
                "before": node(a), "after": node(b), "changed": [path]])
            units.append(.directFile(path, mode, a, b)); covered.append(path)
        }
        guard try FullImageJSON.same(planUnits, expected), covered.sorted() == changed,
              Set(covered).count == covered.count, units.count <= 240 else { throw Refused(line: #line) }
        return units
    }
    static func load(plan raw: Data, before beforeRaw: Data, after afterRaw: Data,
                     oldIdentity: Data, newIdentity: Data, pins: Pins) throws -> Self {
        guard pins.planSHA256 == planSHA256, pins.beforeSHA256 == beforeSHA256,
              pins.afterSHA256 == afterSHA256, pins.targetSourceCommit == sourceCommit,
              FullImageJSON.hash(raw) == planSHA256, FullImageJSON.hash(beforeRaw) == beforeSHA256,
              FullImageJSON.hash(afterRaw) == afterSHA256 else { throw Refused(line: #line) }
        let plan = try FullImageJSON.object(raw, maximum: 2 * InstallerPayloadManifest.maximumManifest + 256 * 1024)
        var canonical = try FullImageJSON.canonical(plan); canonical.append(10)
        guard canonical == raw, Set(plan.keys) == ["schema", "managed_by", "before_manifest_sha256", "after_manifest_sha256",
            "original_install_receipt_manifest_sha256", "target_source", "target_source_files", "old_peers", "new_peers",
            "project_wheel_sha256", "changed", "units", "delta_payload_bytes", "exact_installed_predecessor_required",
            "original_receipt_required", "native_signatures_required", "private_store_unchanged",
            "support_and_alias_inodes_preserved", "rollback_and_retry_required", "production_ready"],
              try InstallerPayloadManifest.integer(plan["schema"], maximum: 1) == 1,
              plan["managed_by"] as? String == managedBy,
              plan["before_manifest_sha256"] as? String == beforeSHA256,
              plan["after_manifest_sha256"] as? String == afterSHA256,
              plan["original_install_receipt_manifest_sha256"] as? String == originalReceipt,
              plan["target_source"] as? String == sourceCommit,
              FullImageJSON.bool(plan["exact_installed_predecessor_required"], true),
              FullImageJSON.bool(plan["original_receipt_required"], true),
              FullImageJSON.bool(plan["native_signatures_required"], true),
              FullImageJSON.bool(plan["private_store_unchanged"], true),
              FullImageJSON.bool(plan["support_and_alias_inodes_preserved"], true),
              FullImageJSON.bool(plan["rollback_and_retry_required"], true),
              FullImageJSON.bool(plan["production_ready"], false) else { throw Refused(line: #line) }
        let before = try InstallerPayloadManifest(beforeRaw), after = try InstallerPayloadManifest(afterRaw)
        let old = before.trees[support]!, new = after.trees[support]!
        guard try FullImageJSON.same(node(old.nodes[""]), ["kind": "directory", "mode": 0o755]),
              try FullImageJSON.same(node(new.nodes[""]), node(old.nodes[""])),
              try FullImageJSON.same(node(before.trees[application]!.nodes[""]), node(after.trees[application]!.nodes[""])) else {
            throw Refused(line: #line)
        }
        for path in Set(old.nodes.keys).union(new.nodes.keys) where !path.isEmpty {
            guard !privateNames.contains(String(path.split(separator: "/")[0]).lowercased()) else { throw Refused(line: #line) }
        }
        let oldPeers = try identity(oldIdentity, tree: old), newPeers = try identity(newIdentity, tree: new)
        guard oldPeers != newPeers else { throw Refused(line: #line) }
        guard let sourceFilesValue = plan["target_source_files"] else { throw Refused(line: #line) }
        _ = try sourceFiles(sourceFilesValue, after: new)
        let changed = try allChanged(old, new)
        guard let suppliedChanged = plan["changed"] as? [String], suppliedChanged == changed,
              let suppliedUnits = plan["units"] as? [[String: Any]], !changed.isEmpty else { throw Refused(line: #line) }
        let units = try loadUnits(suppliedUnits, changed: changed, before: before, after: after)
        var bytes: Int64 = 0
        for path in changed {
            if let item = new.nodes[path], item.kind == "file" {
                let next = bytes.addingReportingOverflow(item.size!)
                guard !next.overflow else { throw Refused(line: #line) }; bytes = next.partialValue
            }
        }
        let wheel = new.nodes["wheels/account_access-0.8.0-py3-none-any.whl"]
        guard wheel?.kind == "file", plan["project_wheel_sha256"] as? String == wheel?.sha256,
              try InstallerPayloadManifest.integer(plan["delta_payload_bytes"], maximum: Int64.max) == bytes else {
            throw Refused(line: #line)
        }
        return Self(pins: pins, before: before, after: after, oldPeers: oldPeers, newPeers: newPeers,
            units: units, changed: changed)
    }
}
