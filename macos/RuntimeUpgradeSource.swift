// Pure repaired-image -> runtime release contract. No installed paths, service
// control or update entrypoint. Compiled pins must come from reviewed artifacts.
import Foundation

enum RuntimeUpgradeTree: String, CaseIterable {
    case owner = "owner.app", python, runtime, browsers, wheels
}
enum RuntimeUpgradeFile: String, CaseIterable {
    case identity = "package-identity.json", requirements = "package-requirements.txt"
    case image = "runtime-image.json", preparation = "runtime-preparation.json"
    case ca = "runtime-ca-refresh.json", repairIdentity = "broker-repair-identity.json"
}
struct RuntimeUpgradeSource {
    struct Pins {
        let planSHA256: String, beforeSHA256: String, afterSHA256: String
        let repairPlan: String, repairSource: String, targetSource: String
        let sourceFiles: [String: String]
    }
    enum Unit {
        case tree(RuntimeUpgradeTree), file(RuntimeUpgradeFile)
        var path: String { switch self { case .tree(let unit): return unit.rawValue; case .file(let unit): return unit.rawValue } }
    }
    let pins: Pins
    let before: InstallerPayloadManifest, after: InstallerPayloadManifest
    let oldPeers: [String: ComponentPeerSignature], newPeers: [String: ComponentPeerSignature]
    let units: [Unit]
    let changed: [String]
    private static let support = InstallerPayloadManifest.support
    private static let site = "runtime/lib/python3.12/site-packages/"
    private static let package = site + "account_access"
    private static let privateNames: Set<String> = ["broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"]
    private static func below(_ name: String, _ prefix: String) -> Bool { name == prefix || name.hasPrefix(prefix + "/") }
    private static func node(_ item: InstallerPayloadNode?) -> Any {
        guard let item else { return NSNull() }
        switch item.kind {
        case "directory": return ["kind": item.kind, "mode": item.mode!] as [String: Any]
        case "file": return ["kind": item.kind, "mode": item.mode!, "size": item.size!, "sha256": item.sha256!] as [String: Any]
        default: return ["kind": item.kind, "target": item.target!]
        }
    }
    private static func rows(_ tree: InstallerPayloadTree, prefix: String) -> [String: Any] {
        tree.nodes.filter { below($0.key, prefix) }.mapValues { node($0) }
    }
    private static func digestRows(_ rows: [String: Any]) throws -> String {
        var raw = try FullImageJSON.canonical(rows); raw.append(10); return FullImageJSON.hash(raw)
    }
    private static func identity(_ raw: Data, tree: InstallerPayloadTree) throws -> [String: ComponentPeerSignature] {
        let value = try FullImageJSON.object(raw, maximum: 8192)
        guard tree.nodes["package-identity.json"]?.sha256 == FullImageJSON.hash(raw),
              tree.nodes["package-identity.json"]?.size == Int64(raw.count),
              Set(value.keys) == ["schema", "managed_by", "signatures"],
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["managed_by"] as? String == "account-access-package-identity-v1",
              let peers = value["signatures"] as? [String: [String: Any]], Set(peers.keys) == ["owner", "broker", "bootstrap"] else {
            throw FullImageFailure.source
        }
        var result: [String: ComponentPeerSignature] = [:]
        for (kind, peer) in peers {
            let identifier = "com.fainir.accountaccess" + (kind == "owner" ? "" : "." + kind)
            guard Set(peer.keys) == ["team", "identifier", "hashes"], peer["team"] as? String == "WBULD6N4NQ",
                  peer["identifier"] as? String == identifier, let hashes = peer["hashes"] as? [String],
                  (1...2).contains(hashes.count), hashes == Array(Set(hashes)).sorted(),
                  hashes.allSatisfy({ FullImageJSON.hex($0, count: 40) }) else { throw FullImageFailure.source }
            result[kind] = .init(team: "WBULD6N4NQ", identifier: identifier, hashes: hashes)
        }
        return result
    }
    static func load(pins: Pins, plan raw: Data, before beforeRaw: Data, after afterRaw: Data,
                     oldIdentity: Data, newIdentity: Data) throws -> Self {
        guard [pins.planSHA256, pins.beforeSHA256, pins.afterSHA256, pins.repairPlan].allSatisfy({ FullImageJSON.hex($0) }),
              [pins.repairSource, pins.targetSource].allSatisfy({ FullImageJSON.hex($0, count: 40) }),
              pins.beforeSHA256 != pins.afterSHA256, FullImageJSON.hash(raw) == pins.planSHA256,
              FullImageJSON.hash(beforeRaw) == pins.beforeSHA256, FullImageJSON.hash(afterRaw) == pins.afterSHA256,
              !pins.sourceFiles.isEmpty, pins.sourceFiles.count <= 1000,
              pins.sourceFiles.values.allSatisfy({ FullImageJSON.hex($0) }) else { throw FullImageFailure.source }
        _ = try FullImageJSON.object(beforeRaw, maximum: InstallerPayloadManifest.maximumManifest)
        _ = try FullImageJSON.object(afterRaw, maximum: InstallerPayloadManifest.maximumManifest)
        let before = try InstallerPayloadManifest(beforeRaw), after = try InstallerPayloadManifest(afterRaw)
        let old = before.trees[support]!, new = after.trees[support]!
        guard try FullImageJSON.same(node(old.nodes[""]), ["kind": "directory", "mode": 0o755]),
              try FullImageJSON.same(node(new.nodes[""]), node(old.nodes[""])),
              try FullImageJSON.same(node(before.trees[InstallerPayloadManifest.application]!.nodes[""]),
                                        node(after.trees[InstallerPayloadManifest.application]!.nodes[""])) else { throw FullImageFailure.source }
        for name in Set(old.nodes.keys).union(new.nodes.keys) where !name.isEmpty {
            guard !privateNames.contains(String(name.split(separator: "/")[0]).lowercased()) else { throw FullImageFailure.source }
        }
        let oldPeers = try identity(oldIdentity, tree: old), newPeers = try identity(newIdentity, tree: new)
        guard oldPeers["owner"] != newPeers["owner"], oldPeers["broker"] == newPeers["broker"],
              oldPeers["bootstrap"] == newPeers["bootstrap"] else { throw FullImageFailure.source }
        for path in ["bin/AccountAccess-broker", "bin/AccountAccess-bootstrap", "bin/AccountAccess-installerverify"]
            + ["storage.py", "models.py", "worker_enroll.py"].map({ package + "/" + $0 }) {
            guard new.nodes[path]?.kind == "file", try FullImageJSON.same(node(old.nodes[path]), node(new.nodes[path])) else {
                throw FullImageFailure.source
            }
        }
        var sources: [String: String] = [:]
        for (name, item) in new.nodes where below(name, package) && name.hasSuffix(".py") && item.kind == "file" {
            sources[String(name.dropFirst(site.count))] = item.sha256!
        }
        guard !sources.isEmpty, Set(pins.sourceFiles.keys) == Set(sources.keys).union(["macos/AccountAccess.swift"]),
              sources.allSatisfy({ pins.sourceFiles[$0.key] == $0.value }),
              new.nodes[package + "/agent_setup.py"] != nil,
              try !FullImageJSON.same(node(old.nodes[package + "/agent_setup.py"]), node(new.nodes[package + "/agent_setup.py"])),
              let wheel = new.nodes["wheels/account_access-0.8.0-py3-none-any.whl"], wheel.kind == "file",
              try FullImageJSON.same(node(wheel), node(new.nodes["owner.app/Contents/Resources/account_access.whl"])) else {
            throw FullImageFailure.source
        }
        var changed: [String] = []
        for name in Set(old.nodes.keys).union(new.nodes.keys) where try !FullImageJSON.same(node(old.nodes[name]), node(new.nodes[name])) {
            changed.append(name)
        }
        changed.sort()
        var units: [Unit] = [], expectedUnits: [[String: Any]] = [], covered: [String] = []
        for unit in RuntimeUpgradeTree.allCases {
            let path = unit.rawValue
            guard old.nodes[path]?.kind == "directory", old.nodes[path]?.mode == 0o755,
                  new.nodes[path]?.kind == "directory", new.nodes[path]?.mode == 0o755 else { throw FullImageFailure.source }
            let owned = changed.filter { below($0, path) }; if owned.isEmpty { continue }
            let a = rows(old, prefix: path), b = rows(new, prefix: path)
            expectedUnits.append(["kind": "public_tree", "path": path, "before": a, "after": b,
                "before_inventory_sha256": try digestRows(a), "after_inventory_sha256": try digestRows(b), "changed": owned])
            units.append(.tree(unit)); covered += owned
        }
        for unit in RuntimeUpgradeFile.allCases {
            let path = unit.rawValue, a = old.nodes[unit.rawValue], b = new.nodes[unit.rawValue]
            guard a?.kind == "file", a?.mode == 0o644,
                  unit == .repairIdentity ? b == nil : (b?.kind == "file" && b?.mode == 0o644) else { throw FullImageFailure.source }
            if try FullImageJSON.same(node(a), node(b)) { continue }
            expectedUnits.append(["kind": "public_file", "path": path, "before": node(a), "after": node(b), "changed": [path]])
            units.append(.file(unit)); covered.append(path)
        }
        guard !changed.isEmpty, covered.sorted() == changed, Set(covered).count == covered.count else { throw FullImageFailure.source }
        let encoder = JSONEncoder()
        let oldPeerValue = try JSONSerialization.jsonObject(with: encoder.encode(oldPeers))
        let newPeerValue = try JSONSerialization.jsonObject(with: encoder.encode(newPeers))
        let expected: [String: Any] = ["schema": 1, "managed_by": "account-access-repaired-runtime-upgrade-plan-v1",
            "before_manifest_sha256": pins.beforeSHA256, "after_manifest_sha256": pins.afterSHA256,
            "predecessor_repair_plan_sha256": pins.repairPlan, "predecessor_repair_source": pins.repairSource,
            "target_source": pins.targetSource, "target_source_files": pins.sourceFiles,
            "old_peers": oldPeerValue, "new_peers": newPeerValue, "project_wheel_sha256": wheel.sha256!,
            "units": expectedUnits, "changed": changed, "storage_model_and_enrollment_source_unchanged": true,
            "native_broker_and_bootstrap_unchanged": true, "completed_repair_proof_required": true,
            "native_payload_and_signature_checks_required": true, "support_and_alias_inodes_must_be_preserved": true,
            "production_ready": false]
        let decoded = try FullImageJSON.object(raw, maximum: 34 * 1024 * 1024)
        var canonical = try FullImageJSON.canonical(expected); canonical.append(10)
        guard try FullImageJSON.same(decoded, expected), raw == canonical else { throw FullImageFailure.source }
        return Self(pins: pins, before: before, after: after, oldPeers: oldPeers, newPeers: newPeers, units: units, changed: changed)
    }
}
