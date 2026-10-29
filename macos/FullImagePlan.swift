// Pure complete-image CA plan loading. No entrypoint, filesystem reads, service
// control or installed adapter. Qualified callers supply independent fixed pins.
import Foundation
import CoreFoundation
import CryptoKit
import Darwin

enum FullImageFailure: Error { case source, predecessor, object, journal, unavailable }

enum FullImageJSON {
    static func hash(_ data: Data) -> String { PublicTreeInventory.digest(data) }
    static func hex(_ value: String, count: Int = 64) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func encode(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed])
    }
    static func object(_ data: Data, maximum: Int) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= maximum, !data.contains(0),
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw FullImageFailure.source }
        // Reject duplicate keys at every depth, including escaped spellings.
        let bytes = [UInt8](data)
        var stack: [(object: Bool, keys: Set<String>, expectsKey: Bool)] = [], cursor = 0
        while cursor < bytes.count {
            switch bytes[cursor] {
            case 34:
                let start = cursor; cursor += 1
                while cursor < bytes.count && bytes[cursor] != 34 { cursor += bytes[cursor] == 92 ? 2 : 1 }
                guard cursor < bytes.count else { throw FullImageFailure.source }; cursor += 1
                if let index = stack.indices.last, stack[index].object && stack[index].expectsKey {
                    var token = Data([91]); token.append(contentsOf: bytes[start..<cursor]); token.append(93)
                    guard let names = try JSONSerialization.jsonObject(with: token) as? [String], names.count == 1,
                          stack[index].keys.insert(names[0]).inserted else { throw FullImageFailure.source }
                    stack[index].expectsKey = false
                }
                continue
            case 123, 91:
                guard stack.count < 32 else { throw FullImageFailure.source }
                stack.append((bytes[cursor] == 123, [], bytes[cursor] == 123))
            case 125, 93:
                guard !stack.isEmpty else { throw FullImageFailure.source }; stack.removeLast()
            case 44:
                if let index = stack.indices.last, stack[index].object { stack[index].expectsKey = true }
            default: break
            }
            cursor += 1
        }
        guard stack.isEmpty else { throw FullImageFailure.source }
        return value
    }
    static func bool(_ value: Any?, _ expected: Bool) -> Bool {
        guard let value = value as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return false }
        return value.boolValue == expected
    }
    // Match Python's sort_keys/ensure_ascii/separators canonical data encoding.
    // UTF-8 key order matches Unicode code-point order; escaped non-BMP scalars
    // are emitted as their JSON UTF-16 surrogate pair, never normalized.
    static func canonical(_ value: Any, depth: Int = 0) throws -> Data {
        guard depth < 40 else { throw FullImageFailure.source }
        func text(_ value: String) -> String {
            var output = "\""
            for scalar in value.unicodeScalars {
                switch scalar.value {
                case 34: output += "\\\""
                case 92: output += "\\\\"
                case 8: output += "\\b"
                case 9: output += "\\t"
                case 10: output += "\\n"
                case 12: output += "\\f"
                case 13: output += "\\r"
                case 32...126: output.unicodeScalars.append(scalar)
                case 0...0xffff: output += String(format: "\\u%04x", scalar.value)
                default:
                    let adjusted = scalar.value - 0x10000
                    output += String(format: "\\u%04x\\u%04x", 0xd800 + (adjusted >> 10), 0xdc00 + (adjusted & 0x3ff))
                }
            }
            return output + "\""
        }
        if value is NSNull { return Data("null".utf8) }
        if let value = value as? String { return Data(text(value).utf8) }
        if let value = value as? NSNumber {
            if CFGetTypeID(value) == CFBooleanGetTypeID() { return Data((value.boolValue ? "true" : "false").utf8) }
            guard value.doubleValue.isFinite, value.doubleValue == Double(value.int64Value) else { throw FullImageFailure.source }
            return Data(String(value.int64Value).utf8)
        }
        if let value = value as? [Any] {
            let children = try value.map { String(decoding: try canonical($0, depth: depth + 1), as: UTF8.self) }
            return Data(("[" + children.joined(separator: ",") + "]").utf8)
        }
        if let value = value as? [String: Any] {
            let keys = value.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            let children = try keys.map { text($0) + ":" + String(decoding: try canonical(value[$0]!, depth: depth + 1), as: UTF8.self) }
            return Data(("{" + children.joined(separator: ",") + "}").utf8)
        }
        throw FullImageFailure.source
    }
    static func same(_ left: Any, _ right: Any) throws -> Bool { try canonical(left) == canonical(right) }
}

// Exactly one already-qualified predecessor, compiled into the new package.
// A caller/journal cannot choose a preceding chain or destination namespace.
struct FullImagePredecessorPins {
    let planSHA256: String
    let originalManifestSHA256: String
    let manifestSHA256: String
    let headSHA256: String
    func validate() throws {
        guard [planSHA256, originalManifestSHA256, manifestSHA256, headSHA256].allSatisfy({ FullImageJSON.hex($0) }),
              originalManifestSHA256 == "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8" else { throw FullImageFailure.predecessor }
    }
    func verifyHead(_ data: Data) throws {
        try validate()
        let value = try FullImageJSON.object(data, maximum: 4096)
        guard FullImageJSON.hash(data) == headSHA256,
              Set(value.keys) == ["schema", "managed_by", "plan_sha256", "base_manifest_sha256", "manifest_sha256", "state", "automatic_reboot_recovery"],
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["managed_by"] as? String == "account-access-component-head-v1",
              value["plan_sha256"] as? String == planSHA256,
              value["base_manifest_sha256"] as? String == originalManifestSHA256,
              value["manifest_sha256"] as? String == manifestSHA256,
              value["state"] as? String == "public_image_verified_gui_unverified",
              FullImageJSON.bool(value["automatic_reboot_recovery"], false) else { throw FullImageFailure.predecessor }
    }
}

// All public file destinations are closed; no namespace or path from a plan
// becomes an operating-system destination without this typed selection.
enum FullImagePlanFileUnit: String, CaseIterable {
    case wheel, packageIdentity, runtimeImage, requirements, componentIdentity, caReceipt
    case pythonPip, pythonPip3, pythonPip312, runtimePip, runtimePip3, runtimePip312
    case runtimePreparation, repairIdentityRemoval, caReplacement
    static let fullImageCases: [Self] = [.wheel, .packageIdentity, .runtimeImage, .requirements,
        .componentIdentity, .caReceipt, .pythonPip, .pythonPip3, .pythonPip312, .runtimePip, .runtimePip3, .runtimePip312]
    var path: String {
        switch self {
        case .wheel: return "wheels/account_access-0.8.0-py3-none-any.whl"
        case .packageIdentity: return "package-identity.json"
        case .runtimeImage: return "runtime-image.json"
        case .requirements: return "package-requirements.txt"
        case .componentIdentity: return "component-identity.json"
        case .caReceipt: return "runtime-ca-refresh.json"
        case .pythonPip: return "python/bin/pip"
        case .pythonPip3: return "python/bin/pip3"
        case .pythonPip312: return "python/bin/pip3.12"
        case .runtimePip: return "runtime/bin/pip"
        case .runtimePip3: return "runtime/bin/pip3"
        case .runtimePip312: return "runtime/bin/pip3.12"
        case .runtimePreparation: return "runtime-preparation.json"
        case .repairIdentityRemoval: return "broker-repair-identity.json"
        case .caReplacement: return "runtime-ca-refresh.json"
        }
    }
    var mode: UInt16 { path.contains("/bin/") ? 0o755 : 0o644 }
    var beforePresent: Bool { self != .caReceipt }
    var afterPresent: Bool { ![Self.componentIdentity, .pythonPip312, .runtimePip312, .repairIdentityRemoval].contains(self) }
}

struct FullImageSourcePins {
    let planSHA256: String
    let targetSourceCommit: String
    let targetManifestSHA256: String
    let caReceiptSHA256: String
    let predecessor: FullImagePredecessorPins
    let predecessorSourceCommit: String
    let targetSourceFiles: [String: String]
    let providerManifestSHA256: String
    let providerSourceBundleSHA256: String
}

// Only independently validated native source types supply this projection.
// It shares storage/journal mechanics, never predecessor or root authority.
protocol PublicImageTransitionSource {
    var planSHA256: String { get }
    var targetSourceCommit: String { get }
    var before: InstallerPayloadManifest { get }
    var after: InstallerPayloadManifest { get }
    var units: [FullImageSource.Unit] { get }
    var directRuntimeDelta: Bool { get }
}

extension PublicImageTransitionSource {
    var directRuntimeDelta: Bool { false }
}

struct FullImageSource: PublicImageTransitionSource {
    enum Unit {
        case tree(PublicTreeUnit, PublicTreeInventory, PublicTreeInventory)
        case file(FullImagePlanFileUnit, InstallerPayloadNode?, InstallerPayloadNode?)
        case directFile(String, UInt16, InstallerPayloadNode?, InstallerPayloadNode?)
        var path: String {
            switch self {
            case .tree(let unit, _, _): return unit.path
            case .file(let unit, _, _): return unit.path
            case .directFile(let path, _, _, _): return path
            }
        }
    }
    let pins: FullImageSourcePins
    var planSHA256: String { pins.planSHA256 }
    var targetSourceCommit: String { pins.targetSourceCommit }
    let before: InstallerPayloadManifest, after: InstallerPayloadManifest
    let oldPeers: [String: ComponentPeerSignature], newPeers: [String: ComponentPeerSignature]
    let designatedRequirements: [String: String]
    let units: [Unit]
    let changed: [String]
    private static let support = InstallerPayloadManifest.support
    private static let trees = PublicTreeUnit.fullImageCases
    private static let files = FullImagePlanFileUnit.fullImageCases
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
    private static func rows(_ tree: InstallerPayloadTree, below prefix: String? = nil) -> [String: Any] {
        var result: [String: Any] = [:]
        for (name, value) in tree.nodes where prefix == nil || below(name, prefix!) { result[name] = node(value) }
        return result
    }
    private static func encodedRows(_ rows: Any) throws -> Data {
        // The plan's inventory digest is Python canonical JSON + one LF.
        var data = try FullImageJSON.canonical(rows); data.append(10); return data
    }
    private static func identity(_ raw: Data, tree: InstallerPayloadTree) throws -> [String: ComponentPeerSignature] {
        let value = try FullImageJSON.object(raw, maximum: 8192)
        guard Set(value.keys) == ["schema", "managed_by", "signatures"],
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["managed_by"] as? String == "account-access-package-identity-v1",
              tree.nodes["package-identity.json"]?.sha256 == FullImageJSON.hash(raw),
              tree.nodes["package-identity.json"]?.size == Int64(raw.count),
              tree.nodes["package-identity.json"]?.mode == 0o644,
              let signatures = value["signatures"] as? [String: Any], Set(signatures.keys) == ["owner", "broker", "bootstrap"] else {
            throw FullImageFailure.source
        }
        var result: [String: ComponentPeerSignature] = [:]
        for (kind, any) in signatures {
            guard let row = any as? [String: Any], Set(row.keys) == ["team", "identifier", "hashes"],
                  row["team"] as? String == "WBULD6N4NQ",
                  row["identifier"] as? String == "com.fainir.accountaccess" + (kind == "owner" ? "" : "." + kind),
                  let hashes = row["hashes"] as? [String], (1...2).contains(hashes.count),
                  hashes == Array(Set(hashes)).sorted(), hashes.allSatisfy({ FullImageJSON.hex($0, count: 40) }) else { throw FullImageFailure.source }
            result[kind] = ComponentPeerSignature(team: "WBULD6N4NQ", identifier: row["identifier"] as! String, hashes: hashes)
        }
        return result
    }
    private static func verifyCA(_ raw: Data, old: InstallerPayloadTree, new: InstallerPayloadTree,
                                 plan: [String: Any], pins: FullImageSourcePins) throws {
        let value = try FullImageJSON.object(raw, maximum: 16384)
        let keys: Set<String> = ["schema", "transform", "source_python_sha256", "refreshed_python_sha256", "official_pip_wheel_sha256", "pip_version", "certifi_version", "ca_sha256", "ca_certificates", "removed_root_certificate_sha256", "source_profile_sha256", "ensurepip_initializer_sha256", "both_active_and_seed_refreshed", "package_code_executed", "system_or_embedded_native_trust_stores_audited"]
        let wheel = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
        let ca = "50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785"
        guard Set(value.keys) == keys, FullImageJSON.hash(raw) == pins.caReceiptSHA256,
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["transform"] as? String == "account-access-frozen-python312-packaging-ca-refresh-v1",
              value["official_pip_wheel_sha256"] as? String == wheel,
              value["pip_version"] as? String == "26.2.2", value["certifi_version"] as? String == "2026.10.19",
              value["ca_sha256"] as? String == ca,
              try InstallerPayloadManifest.integer(value["ca_certificates"], maximum: 500) > 0,
              FullImageJSON.bool(value["both_active_and_seed_refreshed"], true), FullImageJSON.bool(value["package_code_executed"], false),
              FullImageJSON.bool(value["system_or_embedded_native_trust_stores_audited"], false),
              ["source_python_sha256", "refreshed_python_sha256", "ensurepip_initializer_sha256"].allSatisfy({ FullImageJSON.hex(value[$0] as? String ?? "") }),
              value["removed_root_certificate_sha256"] as? [String] == ["86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b", "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"] else { throw FullImageFailure.source }
        let profile = [
            "lib/python3.12/site-packages/pip/__init__.py": "04aa76ceab0f4341e292daae35637f2f8718b183313cc2fb588d1304cb9c0443",
            "lib/python3.12/site-packages/pip/_vendor/vendor.txt": "3df0c9601bfa2e0dca23cc574a4f900a4d7fdad060ab203fab8354350ed93320",
            "lib/python3.12/site-packages/pip/_vendor/certifi/__init__.py": "f96d51ff2f1609a4a44f5b5d8eec47ff34c1658d581fac5081d3759db05a8ce1",
            "lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem": "bbc7e9c01d7551bb8a159b5dedd989b8ee3ce105aff522b68eb1b01bf854cab0",
            "lib/python3.12/ensurepip/__init__.py": "90f6c76cd9ef7ed6daa198bb9ef771139683487f1b061211be7aa511831b2028",
            "lib/python3.12/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl": "c46efd13b6aa8279f33f2864459c8ce587ea6a1a59ee20de055868d8f7688f7f"]
        guard value["source_profile_sha256"] as? [String: String] == profile,
              try FullImageJSON.same(node(new.nodes[FullImagePlanFileUnit.caReceipt.path]), ["kind": "file", "mode": 0o644, "size": raw.count, "sha256": pins.caReceiptSHA256]) else { throw FullImageFailure.source }
        for prefix in ["python", "runtime"] {
            guard profile.allSatisfy({ old.nodes[prefix + "/" + $0.key]?.sha256 == $0.value }),
                  new.nodes[prefix + "/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem"]?.sha256 == ca,
                  new.nodes[prefix + "/lib/python3.12/ensurepip/__init__.py"]?.sha256 == value["ensurepip_initializer_sha256"] as? String,
                  new.nodes[prefix + "/lib/python3.12/ensurepip/_bundled/pip-26.2.2-py3-none-any.whl"]?.sha256 == wheel,
                  new.nodes[prefix + "/lib/python3.12/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl"] == nil,
                  new.nodes[prefix + "/bin/pip3.12"] == nil else { throw FullImageFailure.source }
        }
        let projection: [String: Any] = ["receipt_sha256": pins.caReceiptSHA256, "pip_version": "26.2.2", "certifi_version": "2026.10.19", "official_wheel_sha256": wheel, "source_and_active_prefixes_required": true]
        guard try FullImageJSON.same(plan["closed_CA_profile"]!, projection) else { throw FullImageFailure.source }
    }
    static func load(plan raw: Data, before beforeRaw: Data, after afterRaw: Data,
                     oldIdentity: Data, newIdentity: Data, providerManifest: Data, caReceipt: Data,
                     pins: FullImageSourcePins) throws -> FullImageSource {
        try pins.predecessor.validate()
        guard FullImageJSON.hex(pins.planSHA256), FullImageJSON.hash(raw) == pins.planSHA256,
              FullImageJSON.hex(pins.targetSourceCommit, count: 40), FullImageJSON.hex(pins.predecessorSourceCommit, count: 40),
              FullImageJSON.hex(pins.providerManifestSHA256), FullImageJSON.hex(pins.providerSourceBundleSHA256),
              FullImageJSON.hex(pins.targetManifestSHA256), FullImageJSON.hex(pins.caReceiptSHA256),
              !pins.targetSourceFiles.isEmpty, pins.targetSourceFiles.count <= 1000,
              pins.targetSourceFiles.values.allSatisfy({ FullImageJSON.hex($0) }) else { throw FullImageFailure.source }
        let plan = try FullImageJSON.object(raw, maximum: 2 * InstallerPayloadManifest.maximumManifest + 256 * 1024)
        var canonicalPlan = try FullImageJSON.canonical(plan); canonicalPlan.append(10)
        guard canonicalPlan == raw else { throw FullImageFailure.source }
        let configurationUpgrade = plan["configuration_model_upgrade"] != nil
        var keys: Set<String> = ["schema", "managed_by", "provenance", "old_peers", "new_peers", "provider", "project_wheel_sha256", "changed", "units", "private_format_source_unchanged", "support_and_alias_inode_preservation_required", "native_signature_and_payload_verification_required", "predecessor_receipt_verification_required", "production_ready", "closed_CA_profile", "standalone_provider_matches_active", "native_optional_tree_moves_and_loader_review_required"]
        if configurationUpgrade { keys.insert("configuration_model_upgrade") }
        guard Set(plan.keys) == keys, try InstallerPayloadManifest.integer(plan["schema"], maximum: 1) == 1,
              plan["managed_by"] as? String == "account-access-full-image-ca-plan-proposal-v2",
              FullImageJSON.bool(plan["private_format_source_unchanged"], !configurationUpgrade),
              !configurationUpgrade || plan["configuration_model_upgrade"] as? String == "identity-contact-session-status-v1",
              ["support_and_alias_inode_preservation_required", "native_signature_and_payload_verification_required", "predecessor_receipt_verification_required", "standalone_provider_matches_active", "native_optional_tree_moves_and_loader_review_required"].allSatisfy({ FullImageJSON.bool(plan[$0], true) }),
              FullImageJSON.bool(plan["production_ready"], false) else { throw FullImageFailure.source }
        // The same strict duplicate pass applies to complete manifests, not just
        // the top-level plan. InstallerPayloadManifest validates every node.
        let beforeValue = try FullImageJSON.object(beforeRaw, maximum: InstallerPayloadManifest.maximumManifest)
        let afterValue = try FullImageJSON.object(afterRaw, maximum: InstallerPayloadManifest.maximumManifest)
        guard beforeValue["architecture"] as? String == "arm64", afterValue["architecture"] as? String == "arm64" else { throw FullImageFailure.source }
        let before = try InstallerPayloadManifest(beforeRaw), after = try InstallerPayloadManifest(afterRaw)
        guard before.sha256 == pins.predecessor.manifestSHA256, after.sha256 == pins.targetManifestSHA256,
              let old = before.trees[support], let new = after.trees[support],
              try FullImageJSON.same(rows(before.trees[InstallerPayloadManifest.application]!), rows(after.trees[InstallerPayloadManifest.application]!)),
              try FullImageJSON.same(node(old.nodes[""]), node(new.nodes[""])) else { throw FullImageFailure.source }
        for name in Set(old.nodes.keys).union(new.nodes.keys) where !name.isEmpty {
            let first = name.split(separator: "/")[0].lowercased()
            guard !privateNames.contains(first) else { throw FullImageFailure.source }
        }
        let oldPeers = try identity(oldIdentity, tree: old), newPeers = try identity(newIdentity, tree: new)
        // New code hashes may differ, but identity() validates their fixed
        // Developer ID team and bundle IDs and the target manifest/plan pin
        // them before any runtime policy is derived.
        guard let provenance = plan["provenance"] as? [String: Any],
              Set(provenance.keys) == ["component_source_commit", "target_source_commit", "original_manifest_sha256", "component_plan_sha256", "component_head_sha256", "base_manifest_sha256", "target_manifest_sha256", "target_source_files", "designated_requirements", "provider_manifest_sha256", "provider_source_bundle_sha256"],
              provenance["component_source_commit"] as? String == pins.predecessorSourceCommit,
              provenance["target_source_commit"] as? String == pins.targetSourceCommit,
              provenance["original_manifest_sha256"] as? String == pins.predecessor.originalManifestSHA256,
              provenance["component_plan_sha256"] as? String == pins.predecessor.planSHA256,
              provenance["component_head_sha256"] as? String == pins.predecessor.headSHA256,
              provenance["base_manifest_sha256"] as? String == before.sha256,
              provenance["target_manifest_sha256"] as? String == after.sha256,
              provenance["target_source_files"] as? [String: String] == pins.targetSourceFiles,
              provenance["provider_manifest_sha256"] as? String == pins.providerManifestSHA256,
              provenance["provider_source_bundle_sha256"] as? String == pins.providerSourceBundleSHA256,
              let requirements = provenance["designated_requirements"] as? [String: [String: String]],
              Set(requirements.keys) == ["owner", "broker", "bootstrap"] else { throw FullImageFailure.source }
        let decoder = JSONDecoder()
        guard try decoder.decode([String: ComponentPeerSignature].self, from: FullImageJSON.encode(plan["old_peers"]!)) == oldPeers,
              try decoder.decode([String: ComponentPeerSignature].self, from: FullImageJSON.encode(plan["new_peers"]!)) == newPeers else { throw FullImageFailure.source }
        // Unknown peer members would otherwise be silently ignored by Codable.
        let peerEncoder = JSONEncoder(); peerEncoder.outputFormatting = [.sortedKeys]
        guard try FullImageJSON.same(plan["old_peers"]!, JSONSerialization.jsonObject(with: peerEncoder.encode(oldPeers))),
              try FullImageJSON.same(plan["new_peers"]!, JSONSerialization.jsonObject(with: peerEncoder.encode(newPeers))) else { throw FullImageFailure.source }
        var designated: [String: String] = [:]
        for (name, pair) in requirements {
            guard Set(pair.keys) == ["before", "after"], let before = pair["before"], pair["after"] == before,
                  !before.isEmpty, before.utf8.count <= 8192, !before.utf8.contains(0) else { throw FullImageFailure.source }
            designated[name] = before
        }
        let provider = try FullImageJSON.object(providerManifest, maximum: 16384)
        guard FullImageJSON.hash(providerManifest) == pins.providerManifestSHA256,
              provider["source_bundle_sha256"] as? String == pins.providerSourceBundleSHA256,
              try InstallerPayloadManifest.integer(provider["source_materials"], maximum: 3000) > 0,
              FullImageJSON.bool(provider["native_addons"], false),
              new.nodes["runtime/libexec/bitwarden/runtime-manifest.json"]?.sha256 == pins.providerManifestSHA256 else { throw FullImageFailure.source }
        var providerProjection = provider; providerProjection.removeValue(forKey: "source_materials")
        providerProjection["runtime_manifest_sha256"] = pins.providerManifestSHA256
        guard try FullImageJSON.same(plan["provider"]!, providerProjection) else { throw FullImageFailure.source }
        guard try FullImageJSON.same(
            rows(new, below: PublicTreeUnit.provider.path).reduce(into: [String: Any]()) { $0[String($1.key.dropFirst(PublicTreeUnit.provider.path.count))] = $1.value },
            rows(new, below: PublicTreeUnit.pythonProvider.path).reduce(into: [String: Any]()) { $0[String($1.key.dropFirst(PublicTreeUnit.pythonProvider.path.count))] = $1.value }) else { throw FullImageFailure.source }
        try verifyCA(caReceipt, old: old, new: new, plan: plan, pins: pins)
        let requiredSources: Set<String> = ["macos/AccountAccess.swift", "macos/bitwarden_derivation.py", "macos/bitwarden-overrides.lock.json", "account_access/bitwarden_source.py", "account_access/storage.py", "account_access/models.py", "account_access/worker_enroll.py", "account_access/agent_setup.py"]
        guard requiredSources.isSubset(of: Set(pins.targetSourceFiles.keys)) else { throw FullImageFailure.source }
        for name in ["storage.py", "models.py", "worker_enroll.py", "agent_setup.py"] {
            let path = "runtime/lib/python3.12/site-packages/account_access/" + name
            guard new.nodes[path]?.sha256 == pins.targetSourceFiles["account_access/" + name],
                  new.nodes[path]?.kind == "file" else { throw FullImageFailure.source }
            if name == "models.py" && configurationUpgrade {
                // Exact source bytes and metadata, not an arbitrary migration
                // permission. All other private-format sources stay identical.
                guard try FullImageJSON.same(node(old.nodes[path]), ["kind": "file", "mode": 420, "size": 18921,
                    "sha256": "010c09ec0263e359c12fe0e7fa429698775c5816412448f04d07e96cce54d551"]),
                    try FullImageJSON.same(node(new.nodes[path]), ["kind": "file", "mode": 420, "size": 22350,
                    "sha256": "7a152c833f450f3364d2b297a9561ac6cbed556121892b64027d5a41f83847cf"]) else { throw FullImageFailure.source }
            } else {
                guard try FullImageJSON.same(node(old.nodes[path]), node(new.nodes[path])) else { throw FullImageFailure.source }
            }
        }
        for (name, pin) in pins.targetSourceFiles {
            guard name.range(of: "^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$", options: .regularExpression) != nil else { throw FullImageFailure.source }
            _ = try InstallerPayloadManifest.components(name)
            if name.hasPrefix("account_access/"), name.hasSuffix(".py") {
                guard new.nodes["runtime/lib/python3.12/site-packages/" + name]?.sha256 == pin else { throw FullImageFailure.source }
            }
        }
        for (name, value) in new.nodes where below(name, "runtime/lib/python3.12/site-packages/account_access") {
            guard !name.hasSuffix(".pyc"), !name.hasSuffix(".pyo") else { throw FullImageFailure.source }
            if name.hasSuffix(".py") {
                guard value.kind == "file", pins.targetSourceFiles[String(name.dropFirst("runtime/lib/python3.12/site-packages/".count))] == value.sha256 else { throw FullImageFailure.source }
            }
        }
        let wheel = new.nodes[FullImagePlanFileUnit.wheel.path]
        guard wheel?.kind == "file", try FullImageJSON.same(node(wheel), node(new.nodes["owner.app/Contents/Resources/account_access.whl"])),
              plan["project_wheel_sha256"] as? String == wheel?.sha256 else { throw FullImageFailure.source }
        var changed: [String] = []
        for name in Set(old.nodes.keys).union(new.nodes.keys) where try !FullImageJSON.same(node(old.nodes[name]), node(new.nodes[name])) { changed.append(name) }
        changed.sort()
        guard !changed.isEmpty, plan["changed"] as? [String] == changed, let supplied = plan["units"] as? [[String: Any]] else { throw FullImageFailure.source }
        var units: [Unit] = [], expected: [[String: Any]] = [], covered: [String] = []
        for unit in trees {
            let oldInventory = try PublicTreeInventory(validatedManifest: before, unit: unit)
            let newInventory = try PublicTreeInventory(validatedManifest: after, unit: unit)
            guard unit.accepts(old: oldInventory, new: newInventory) else { throw FullImageFailure.source }
            let owned = changed.filter { below($0, unit.path) }
            if owned.isEmpty { continue }
            let a: Any = oldInventory.isPresent ? rows(old, below: unit.path) : NSNull()
            let b: Any = newInventory.isPresent ? rows(new, below: unit.path) : NSNull()
            expected.append(["kind": "public_tree", "path": unit.path, "before": a, "after": b,
                "before_inventory_sha256": FullImageJSON.hash(try encodedRows(a)), "after_inventory_sha256": FullImageJSON.hash(try encodedRows(b)), "changed": owned])
            units.append(.tree(unit, oldInventory, newInventory))
            covered += owned
        }
        for unit in files.sorted(by: { $0.path < $1.path }) where changed.contains(unit.path) {
            let a = old.nodes[unit.path], b = new.nodes[unit.path]
            guard (a != nil) == unit.beforePresent, (b != nil) == unit.afterPresent,
                  (a == nil || a?.kind == "file"), (b == nil || b?.kind == "file"),
                  a == nil || a?.mode == unit.mode, b == nil || b?.mode == unit.mode else { throw FullImageFailure.source }
            expected.append(["kind": "public_file", "path": unit.path, "before": node(a), "after": node(b), "changed": [unit.path]])
            units.append(.file(unit, a, b)); covered.append(unit.path)
        }
        guard try FullImageJSON.same(supplied, expected), covered.sorted() == changed, Set(covered).count == covered.count else { throw FullImageFailure.source }
        return FullImageSource(pins: pins, before: before, after: after, oldPeers: oldPeers, newPeers: newPeers,
            designatedRequirements: designated, units: units, changed: changed)
    }
}
