import Foundation
import Security
import Darwin

@main enum PublisherPeerChecks {
    static func main() throws {
        guard getuid() != 0, getuid() == geteuid(), CommandLine.arguments.count == 2 else { exit(78) }
        let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        guard data.count <= 16384,
              let entries = try JSONSerialization.jsonObject(with: data) as? [String: [String: Any]],
              Set(entries.keys) == Set(["owner", "broker", "bootstrap", "installerverify"]) else { exit(78) }
        var checks: [String: Bool] = [:]
        for role in entries.keys.sorted() {
            guard let entry = entries[role], let path = entry["path"] as? String,
                  let team = entry["team"] as? String, let identifier = entry["identifier"] as? String,
                  let hashes = entry["hashes"] as? [String] else { exit(78) }
            var code: SecStaticCode?
            guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
                  let code else { exit(78) }
            let variants = [("publisher_and_pinned_hash", team, identifier, hashes, true),
                            ("wrong_team_denied", "ZZZZZZZZZZ", identifier, hashes, false),
                            ("wrong_identifier_denied", team, "com.fainir.accountaccess.untrusted", hashes, false),
                            ("wrong_hash_denied", team, identifier, [String(repeating: "0", count: 40)], false)]
            for (name, actualTeam, actualIdentifier, actualHashes, expected) in variants {
                let peer = try OwnerGatewayPeer(uid: getuid(), team: actualTeam,
                                                identifier: actualIdentifier, codeHashes: actualHashes)
                var requirement: SecRequirement?
                guard SecRequirementCreateWithString(peer.requirement as CFString, [], &requirement) == errSecSuccess,
                      let requirement else { exit(78) }
                let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
                let accepted = SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess
                checks[role + ":" + name] = accepted == expected
            }
        }
        let passed = checks.count == 16 && checks.values.allSatisfy { $0 }
        let result: [String: Any] = ["status": passed ? "PASSED" : "FAILED", "checks": checks,
                                    "private_signins": 0, "production_ready": false,
                                    "dynamic_xpc_or_owner_approval_executed": false,
                                    "scope": "ordinary-user static validation of staged public signed code"]
        let encoded = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        print(String(decoding: encoded, as: UTF8.self))
        if !passed { exit(78) }
    }
}
