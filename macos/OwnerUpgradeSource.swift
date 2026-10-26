// Pure fixed-owner successor loading. No installed reads or update authority.
import Foundation

struct OwnerUpgradeSource: PublicImageTransitionSource {
    struct Pins {
        let planSHA256: String, beforeSHA256: String, afterSHA256: String
        let predecessorRuntimePlan: String, targetSource: String
        let sourceFiles: [String: String]
    }
    let pins: Pins
    var planSHA256: String { pins.planSHA256 }
    var targetSourceCommit: String { pins.targetSource }
    let before: InstallerPayloadManifest, after: InstallerPayloadManifest
    let payload: InstallerPayloadManifest
    let oldPeers: [String: ComponentPeerSignature], newPeers: [String: ComponentPeerSignature]
    let units: [FullImageSource.Unit]
    let changed: [String]
    private static let support = InstallerPayloadManifest.support
    private static let nativeSources = Set([
        "AccountAccess", "MailboxOAuthLoopback", "OwnerGateway", "DesktopOwnerConnection",
        "BrowserNativeHost", "ManagedAgentSetup", "WorkerBootstrap", "WorkerListenerBindings",
        "BackgroundRecovery", "MessageText", "MessagesReader", "SystemMessagesReader"
    ].map { "macos/" + $0 + ".swift" })
    private static let changes: Set<String> = ["owner.app/Contents/Info.plist",
        "owner.app/Contents/MacOS/AccountAccess", "package-identity.json"]
    private static func below(_ name: String) -> Bool { name == "owner.app" || name.hasPrefix("owner.app/") }
    private static func node(_ item: InstallerPayloadNode?) -> Any {
        guard let item else { return NSNull() }
        switch item.kind {
        case "file": return ["kind": item.kind, "mode": item.mode!, "size": item.size!, "sha256": item.sha256!] as [String: Any]
        case "directory": return ["kind": item.kind, "mode": item.mode!] as [String: Any]
        default: return ["kind": item.kind, "target": item.target!]
        }
    }
    private static func identity(_ raw: Data, tree: InstallerPayloadTree) throws -> [String: ComponentPeerSignature] {
        let value = try FullImageJSON.object(raw, maximum: 8192)
        guard tree.nodes["package-identity.json"]?.sha256 == FullImageJSON.hash(raw),
              tree.nodes["package-identity.json"]?.size == Int64(raw.count),
              Set(value.keys) == ["schema", "managed_by", "signatures"],
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["managed_by"] as? String == "account-access-package-identity-v1",
              let peers = value["signatures"] as? [String: [String: Any]],
              Set(peers.keys) == ["owner", "broker", "bootstrap"] else { throw FullImageFailure.source }
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
        guard [pins.planSHA256, pins.beforeSHA256, pins.afterSHA256, pins.predecessorRuntimePlan].allSatisfy({ FullImageJSON.hex($0) }),
              FullImageJSON.hex(pins.targetSource, count: 40), pins.beforeSHA256 != pins.afterSHA256,
              FullImageJSON.hash(raw) == pins.planSHA256,
              FullImageJSON.hash(beforeRaw) == pins.beforeSHA256,
              FullImageJSON.hash(afterRaw) == pins.afterSHA256,
              Set(pins.sourceFiles.keys) == nativeSources,
              pins.sourceFiles.values.allSatisfy({ FullImageJSON.hex($0) }) else { throw FullImageFailure.source }
        _ = try FullImageJSON.object(beforeRaw, maximum: InstallerPayloadManifest.maximumManifest)
        var payloadValue = try FullImageJSON.object(afterRaw, maximum: InstallerPayloadManifest.maximumManifest)
        let before = try InstallerPayloadManifest(beforeRaw), after = try InstallerPayloadManifest(afterRaw)
        let old = before.trees[support]!, new = after.trees[support]!
        guard Set(old.nodes.keys) == Set(new.nodes.keys),
              try FullImageJSON.same(node(old.nodes[""]), ["kind": "directory", "mode": 0o755]),
              try FullImageJSON.same(node(new.nodes[""]), node(old.nodes[""])),
              try FullImageJSON.same(node(old.nodes["owner.app"]), ["kind": "directory", "mode": 0o755]),
              try FullImageJSON.same(node(new.nodes["owner.app"]), node(old.nodes["owner.app"])),
              try FullImageJSON.same(node(before.trees[InstallerPayloadManifest.application]!.nodes[""]),
                                        node(after.trees[InstallerPayloadManifest.application]!.nodes[""])) else {
            throw FullImageFailure.source
        }
        let privateNames: Set<String> = ["broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"]
        guard old.nodes.keys.allSatisfy({ $0.isEmpty || !privateNames.contains(String($0.split(separator: "/")[0]).lowercased()) }) else {
            throw FullImageFailure.source
        }
        var changed: [String] = []
        for name in old.nodes.keys where try !FullImageJSON.same(node(old.nodes[name]), node(new.nodes[name])) { changed.append(name) }
        changed.sort()
        guard Set(changed) == changes else { throw FullImageFailure.source }
        for name in changes {
            let mode = name.hasSuffix("/AccountAccess") ? UInt16(0o755) : UInt16(0o644)
            guard [old, new].allSatisfy({ $0.nodes[name]?.kind == "file" && $0.nodes[name]?.mode == mode }) else { throw FullImageFailure.source }
        }
        let oldPeers = try identity(oldIdentity, tree: old), newPeers = try identity(newIdentity, tree: new)
        guard oldPeers["owner"] != newPeers["owner"], oldPeers["broker"] == newPeers["broker"],
              oldPeers["bootstrap"] == newPeers["bootstrap"] else { throw FullImageFailure.source }
        let inventories = [old, new].map { tree in tree.nodes.filter { below($0.key) }.mapValues { node($0) } }
        func inventoryHash(_ value: [String: Any]) throws -> String {
            var raw = try FullImageJSON.canonical(value); raw.append(10); return FullImageJSON.hash(raw)
        }
        let encoder = JSONEncoder()
        let expected: [String: Any] = ["schema": 1, "managed_by": "account-access-owner-successor-proposal-v1",
            "before_manifest_sha256": pins.beforeSHA256, "after_manifest_sha256": pins.afterSHA256,
            "predecessor_runtime_plan_sha256": pins.predecessorRuntimePlan, "target_source": pins.targetSource,
            "target_native_source_files": pins.sourceFiles,
            "old_peers": try JSONSerialization.jsonObject(with: encoder.encode(oldPeers)),
            "new_peers": try JSONSerialization.jsonObject(with: encoder.encode(newPeers)), "changed": changed,
            "units": [["kind": "public_tree", "path": "owner.app", "before": inventories[0], "after": inventories[1],
                       "before_inventory_sha256": try inventoryHash(inventories[0]),
                       "after_inventory_sha256": try inventoryHash(inventories[1])],
                      ["kind": "public_file", "path": "package-identity.json",
                       "before": node(old.nodes["package-identity.json"]), "after": node(new.nodes["package-identity.json"])]],
            "completed_runtime_proof_required": true, "native_signature_checks_required": true,
            "private_policy_rotation_requires_qualified_controller": true,
            "installation_authority": false, "production_ready": false]
        let decoded = try FullImageJSON.object(raw, maximum: 34 * 1024 * 1024)
        var canonical = try FullImageJSON.canonical(expected); canonical.append(10)
        guard try FullImageJSON.same(decoded, expected), raw == canonical else { throw FullImageFailure.source }
        let units: [FullImageSource.Unit] = [
            .tree(.runtimeOwner, try PublicTreeInventory(validatedManifest: before, unit: .runtimeOwner),
                  try PublicTreeInventory(validatedManifest: after, unit: .runtimeOwner)),
            .file(.packageIdentity, old.nodes["package-identity.json"], new.nodes["package-identity.json"])]
        guard var payloadRoots = payloadValue["roots"] as? [String: [String: Any]] else { throw FullImageFailure.source }
        payloadRoots[support] = new.nodes.filter { $0.key.isEmpty || $0.key == "package-identity.json" || below($0.key) }
            .mapValues { node($0) }
        payloadValue["roots"] = payloadRoots
        var payloadRaw = try FullImageJSON.canonical(payloadValue); payloadRaw.append(10)
        let payload = try InstallerPayloadManifest(payloadRaw)
        return Self(pins: pins, before: before, after: after, payload: payload,
            oldPeers: oldPeers, newPeers: newPeers, units: units, changed: changed)
    }
}
