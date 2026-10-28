// Pure public-policy derivation for an explicit component transition.
// No account-store reads, enrollment changes, process calls or file operations.
import Foundation
import CoreFoundation
import Darwin

enum ComponentPolicyFailure: Error { case invalid }

struct ComponentPeerSignature: Codable, Equatable {
    let team: String
    let identifier: String
    let hashes: [String]
}

struct ComponentPolicyResult {
    let install: Data
    let host: Data
    let owner: Data
    let ownerUID: uid_t
    let brokerUID: uid_t
}

enum ComponentUpdatePolicies {
    private static let support = "/Library/Application Support/Account Access"
    private static let identifiers = ["owner": "com.fainir.accountaccess",
                                      "broker": "com.fainir.accountaccess.broker",
                                      "bootstrap": "com.fainir.accountaccess.bootstrap"]

    private static func ascii(_ value: String, length: Int, allowed: (UInt8) -> Bool) -> Bool {
        value.utf8.count == length && value.utf8.allSatisfy(allowed)
    }

    private static func hex(_ value: String, length: Int) -> Bool {
        ascii(value, length: length) { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func integer(_ value: Any?, maximum: UInt64 = UInt64(UInt32.max)) throws -> UInt64 {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue >= 0, number.doubleValue <= Double(maximum),
              number.doubleValue == Double(number.uint64Value) else { throw ComponentPolicyFailure.invalid }
        return number.uint64Value
    }

    private static func object(_ data: Data, keys: Set<String>, marker: String) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= 4096,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(value.keys) == keys, value["managed_by"] as? String == marker,
              try integer(value["schema"], maximum: 1) == 1 else { throw ComponentPolicyFailure.invalid }
        try uniqueKeys(data)
        return value
    }

    // JSONSerialization otherwise silently normalizes duplicate members. All
    // accepted policies have one flat object (with optional string arrays), so
    // reject repeated top-level keys, including escaped spellings of a key.
    // Syntax/UTF-8 validity is already established by JSONSerialization above.
    private static func uniqueKeys(_ data: Data) throws {
        let bytes = [UInt8](data)
        var cursor = 0, depth = 0, expectsKey = false
        var keys: Set<String> = []
        while cursor < bytes.count {
            switch bytes[cursor] {
            case 34:
                let start = cursor
                cursor += 1
                while cursor < bytes.count && bytes[cursor] != 34 {
                    cursor += bytes[cursor] == 92 ? 2 : 1
                }
                guard cursor < bytes.count else { throw ComponentPolicyFailure.invalid }
                cursor += 1
                if depth == 1 && expectsKey {
                    var token = Data([91])
                    token.append(contentsOf: bytes[start..<cursor]); token.append(93)
                    guard let names = try JSONSerialization.jsonObject(with: token) as? [String],
                          names.count == 1, keys.insert(names[0]).inserted else { throw ComponentPolicyFailure.invalid }
                    expectsKey = false
                }
                continue
            case 123, 91:
                if depth == 0 { expectsKey = true }
                depth += 1
            case 125, 93: depth -= 1
            case 44:
                if depth == 1 { expectsKey = true }
            default: break
            }
            cursor += 1
        }
    }

    private static func uuid(_ value: Any?) throws -> String {
        guard let text = value as? String, let value = UUID(uuidString: text),
              value.uuidString.lowercased() == text else { throw ComponentPolicyFailure.invalid }
        return text
    }

    private static func peers(_ value: [String: ComponentPeerSignature]) throws -> String {
        guard Set(value.keys) == Set(identifiers.keys), let team = value["owner"]?.team,
              ascii(team, length: 10, allowed: { (48...57).contains($0) || (65...90).contains($0) }) else {
            throw ComponentPolicyFailure.invalid
        }
        for (kind, identity) in value {
            guard identity.identifier == identifiers[kind], identity.team == team,
                  (1...2).contains(identity.hashes.count),
                  identity.hashes == Array(Set(identity.hashes)).sorted(),
                  identity.hashes.allSatisfy({ hex($0, length: 40) }) else { throw ComponentPolicyFailure.invalid }
        }
        return team
    }

    private static func encoded(_ value: [String: Any]) throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
        guard data.count <= 4096 else { throw ComponentPolicyFailure.invalid }
        return data
    }

    static func derive(install: Data, host: Data, owner: Data, worker: Data,
                       oldPeers: [String: ComponentPeerSignature], newPeers: [String: ComponentPeerSignature],
                       oldFingerprint: String, newFingerprint: String, consoleOwner: uid_t) throws -> ComponentPolicyResult {
        let team = try peers(oldPeers)
        guard try peers(newPeers) == team, newPeers["owner"] == oldPeers["owner"], consoleOwner > 0,
              hex(oldFingerprint, length: 64), hex(newFingerprint, length: 64) else {
            throw ComponentPolicyFailure.invalid
        }
        var installValue = try object(install, keys: ["managed_by", "schema", "owner_uid", "broker_uid",
            "broker_name", "vault_id", "enrollment_id", "payload_fingerprint"], marker: "account-access-system-install-v1")
        let broker = try integer(installValue["broker_uid"])
        guard try integer(installValue["owner_uid"]) == UInt64(consoleOwner), broker != UInt64(consoleOwner),
              (UInt64(450)..<500).contains(broker),
              installValue["broker_name"] as? String == "_accountaccess",
              installValue["payload_fingerprint"] as? String == oldFingerprint else { throw ComponentPolicyFailure.invalid }
        let vault = try uuid(installValue["vault_id"])
        _ = try uuid(installValue["enrollment_id"])

        let workerValue = try object(worker, keys: ["managed_by", "schema", "broker_uid", "agent_uid", "root",
            "agent_socket", "owner_socket", "owner_port"], marker: "account-access-worker-v1")
        guard try integer(workerValue["broker_uid"]) == broker,
              try integer(workerValue["agent_uid"]) == UInt64(consoleOwner),
              workerValue["root"] as? String == support + "/vault/data",
              workerValue["agent_socket"] as? String == support + "/run/agent.sock",
              workerValue["owner_socket"] as? String == support + "/control/owner.sock",
              try integer(workerValue["owner_port"], maximum: 65_535) > 0 else { throw ComponentPolicyFailure.invalid }

        var hostValue = try object(host, keys: ["managed_by", "schema", "worker_launcher", "enrollment_policy",
            "bootstrap", "vault_id", "owner_uid", "publisher_team", "owner_identifier", "owner_hashes",
            "bootstrap_identifier", "bootstrap_hashes"], marker: "account-access-system-host-v1")
        guard hostValue["worker_launcher"] as? String == support + "/broker/worker-launch.json",
              hostValue["enrollment_policy"] as? String == support + "/broker/enrollment.json",
              hostValue["bootstrap"] as? String == support + "/bin/AccountAccess-bootstrap",
              try uuid(hostValue["vault_id"]) == vault,
              try integer(hostValue["owner_uid"]) == UInt64(consoleOwner),
              hostValue["publisher_team"] as? String == team,
              hostValue["owner_identifier"] as? String == oldPeers["owner"]!.identifier,
              hostValue["owner_hashes"] as? [String] == oldPeers["owner"]!.hashes,
              hostValue["bootstrap_identifier"] as? String == oldPeers["bootstrap"]!.identifier,
              hostValue["bootstrap_hashes"] as? [String] == oldPeers["bootstrap"]!.hashes else {
            throw ComponentPolicyFailure.invalid
        }
        var ownerValue = try object(owner, keys: ["managed_by", "schema", "owner_uid", "publisher_team",
            "server_identifier", "server_hashes"], marker: "account-access-desktop-owner-v1")
        guard try integer(ownerValue["owner_uid"]) == UInt64(consoleOwner),
              ownerValue["publisher_team"] as? String == team,
              ownerValue["server_identifier"] as? String == oldPeers["broker"]!.identifier,
              ownerValue["server_hashes"] as? [String] == oldPeers["broker"]!.hashes else {
            throw ComponentPolicyFailure.invalid
        }

        installValue["payload_fingerprint"] = newFingerprint
        hostValue["bootstrap_hashes"] = newPeers["bootstrap"]!.hashes
        ownerValue["server_hashes"] = newPeers["broker"]!.hashes
        return try ComponentPolicyResult(install: encoded(installValue), host: encoded(hostValue), owner: encoded(ownerValue),
                                         ownerUID: consoleOwner, brokerUID: uid_t(broker))
    }
}
