// Fictional public full-image policies only. No installed files, accounts or root actions.
import Foundation

private enum PolicyCheckFailure: Error { case assertion }

private struct PolicyFixture {
    static let base = "/Library/Application Support/Account Access"
    static let vault = "12345678-1234-1234-1234-123456789abc"
    static let enrollment = "12345678-1234-1234-1234-123456789def"
    static let oldFingerprint = String(repeating: "a", count: 64)
    static let newFingerprint = String(repeating: "b", count: 64)
    var old = ["owner": ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "com.fainir.accountaccess", hashes: [String(repeating: "1", count: 40)]),
               "broker": ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "com.fainir.accountaccess.broker", hashes: [String(repeating: "2", count: 40)]),
               "bootstrap": ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "com.fainir.accountaccess.bootstrap", hashes: [String(repeating: "3", count: 40)])]
    var new: [String: ComponentPeerSignature]
    var install: [String: Any] = ["managed_by": "account-access-system-install-v1", "schema": 1,
        "owner_uid": 501, "broker_uid": 450, "broker_name": "_accountaccess", "vault_id": vault,
        "enrollment_id": enrollment, "payload_fingerprint": oldFingerprint]
    var worker: [String: Any] = ["managed_by": "account-access-worker-v1", "schema": 1, "broker_uid": 450,
        "agent_uid": 501, "root": base + "/vault/data", "agent_socket": base + "/run/agent.sock",
        "owner_socket": base + "/control/owner.sock", "owner_port": 8765]
    var host: [String: Any] = ["managed_by": "account-access-system-host-v1", "schema": 1,
        "worker_launcher": base + "/broker/worker-launch.json", "enrollment_policy": base + "/broker/enrollment.json",
        "bootstrap": base + "/bin/AccountAccess-bootstrap", "vault_id": vault, "owner_uid": 501,
        "publisher_team": "ABCDEFGHIJ", "owner_identifier": "com.fainir.accountaccess",
        "owner_hashes": [String(repeating: "1", count: 40)],
        "bootstrap_identifier": "com.fainir.accountaccess.bootstrap", "bootstrap_hashes": [String(repeating: "3", count: 40)]]
    var owner: [String: Any] = ["managed_by": "account-access-desktop-owner-v1", "schema": 1, "owner_uid": 501,
        "publisher_team": "ABCDEFGHIJ", "server_identifier": "com.fainir.accountaccess.broker",
        "server_hashes": [String(repeating: "2", count: 40)]]
    init() {
        new = old
        new["owner"] = ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "com.fainir.accountaccess",
            hashes: [String(repeating: "4", count: 40), String(repeating: "5", count: 40)])
    }
    static func data(_ value: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: .sortedKeys)
    }
    func derive(console: UInt32 = 501, fingerprint: String = newFingerprint) throws -> ComponentPolicyResult {
        try FullImageUpdatePolicies.derive(install: Self.data(install), host: Self.data(host), owner: Self.data(owner),
            worker: Self.data(worker), oldPeers: old, newPeers: new, oldFingerprint: Self.oldFingerprint,
            newFingerprint: fingerprint, consoleOwner: console)
    }
}

@main struct FullImageUpdatePolicyChecks {
    static func main() throws {
        var checks = 0
        let fixture = PolicyFixture(), result = try fixture.derive()
        func require(_ value: Bool) throws { guard value else { throw PolicyCheckFailure.assertion }; checks += 1 }
        func object(_ data: Data) throws -> [String: Any] {
            guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw PolicyCheckFailure.assertion }
            return value
        }
        var expectedInstall = fixture.install, expectedHost = fixture.host
        let expectedOwner = fixture.owner
        expectedInstall["payload_fingerprint"] = PolicyFixture.newFingerprint
        expectedHost["owner_hashes"] = fixture.new["owner"]!.hashes
        // The complete records, including both IDs, must survive unchanged
        // except for the two explicitly authorized owner-pin/fingerprint fields.
        try require(NSDictionary(dictionary: try object(result.install)).isEqual(to: expectedInstall))
        try require(NSDictionary(dictionary: try object(result.host)).isEqual(to: expectedHost))
        try require(NSDictionary(dictionary: try object(result.owner)).isEqual(to: expectedOwner))
        try require(result.ownerUID == 501 && result.brokerUID == 450)

        let rejected: [(inout PolicyFixture) -> Void] = [
            { $0.install["schema"] = true },
            { $0.install["broker_uid"] = 450.5 },
            { $0.install["broker_uid"] = 500 },
            { $0.install["owner_uid"] = 502 },
            { $0.install["broker_name"] = "root" },
            { $0.install["payload_fingerprint"] = PolicyFixture.newFingerprint },
            { $0.install["enrollment_id"] = PolicyFixture.enrollment.uppercased() },
            { $0.install["vault_id"] = "invalid" },
            { $0.install["unknown"] = "must not be dropped" },
            { $0.worker["broker_uid"] = 451 },
            { $0.worker["agent_uid"] = 502 },
            { $0.worker["owner_port"] = 0 },
            { $0.worker["owner_port"] = 65_536 },
            { $0.worker["owner_port"] = true },
            { $0.worker["agent_socket"] = PolicyFixture.base + "/run/../run/agent.sock" },
            { $0.worker["owner_socket"] = "/tmp/owner.sock" },
            { $0.worker["root"] = PolicyFixture.base + "/vault/other" },
            { $0.host["vault_id"] = PolicyFixture.enrollment },
            { $0.host["bootstrap"] = "/tmp/bootstrap" },
            { $0.host["owner_hashes"] = [String(repeating: "0", count: 40)] },
            { $0.host["bootstrap_hashes"] = [String(repeating: "0", count: 40)] },
            { $0.host["publisher_team"] = "OTHERTEAM1" },
            { $0.owner["owner_uid"] = false },
            { $0.owner["server_hashes"] = [String(repeating: "0", count: 40)] },
            { $0.owner["server_identifier"] = "other.broker" },
            { $0.new["owner"] = ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "com.fainir.accountaccess", hashes: [String(repeating: "F", count: 40)]) },
            { $0.new["broker"] = ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "com.fainir.accountaccess.broker", hashes: [String(repeating: "6", count: 40)]) },
            { $0.new["broker"] = ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "com.fainir.accountaccess.broker", hashes: [String(repeating: "4", count: 40), String(repeating: "4", count: 40)]) },
            { $0.new["bootstrap"] = ComponentPeerSignature(team: "OTHERTEAM1", identifier: "com.fainir.accountaccess.bootstrap", hashes: [String(repeating: "6", count: 40)]) },
            { $0.old.removeValue(forKey: "bootstrap") },
            { $0.new["extra"] = $0.new["broker"] },
            { $0.new["owner"] = ComponentPeerSignature(team: "OTHERTEAM1", identifier: "com.fainir.accountaccess", hashes: [String(repeating: "4", count: 40)]) },
            { $0.new["owner"] = ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "other.owner", hashes: [String(repeating: "4", count: 40)]) },
            { $0.new["owner"] = ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "com.fainir.accountaccess", hashes: [String(repeating: "4", count: 40), String(repeating: "4", count: 40)]) },
            { $0.new["owner"] = ComponentPeerSignature(team: "ABCDEFGHIJ", identifier: "com.fainir.accountaccess", hashes: [String(repeating: "5", count: 40), String(repeating: "4", count: 40)]) },
            { $0.new.removeValue(forKey: "owner") },
        ]
        for mutate in rejected {
            var changed = fixture
            mutate(&changed)
            do { _ = try changed.derive(); throw PolicyCheckFailure.assertion }
            catch ComponentPolicyFailure.invalid { checks += 1 }
        }
        for console in [UInt32(0), UInt32(502)] {
            do { _ = try fixture.derive(console: console); throw PolicyCheckFailure.assertion }
            catch ComponentPolicyFailure.invalid { checks += 1 }
        }
        do { _ = try fixture.derive(fingerprint: "*"); throw PolicyCheckFailure.assertion }
        catch ComponentPolicyFailure.invalid { checks += 1 }
        var overlapping = fixture
        overlapping.install["owner_uid"] = 450
        overlapping.worker["agent_uid"] = 450
        overlapping.host["owner_uid"] = 450
        overlapping.owner["owner_uid"] = 450
        do { _ = try overlapping.derive(console: 450); throw PolicyCheckFailure.assertion }
        catch ComponentPolicyFailure.invalid { checks += 1 }
        // Reject both direct and escaped duplicate keys even when the final
        // value would satisfy the otherwise valid semantic checks.
        for member in ["\"owner_uid\":501,", "\"owner_\\u0075id\":501,"] {
            let original = try PolicyFixture.data(fixture.install)
            let duplicate = Data(("{" + member).utf8) + original.dropFirst()
            do {
                _ = try FullImageUpdatePolicies.derive(install: duplicate, host: PolicyFixture.data(fixture.host),
                    owner: PolicyFixture.data(fixture.owner), worker: PolicyFixture.data(fixture.worker),
                    oldPeers: fixture.old, newPeers: fixture.new, oldFingerprint: PolicyFixture.oldFingerprint,
                    newFingerprint: PolicyFixture.newFingerprint, consoleOwner: 501)
                throw PolicyCheckFailure.assertion
            } catch ComponentPolicyFailure.invalid { checks += 1 }
        }
        let report: [String: Any] = ["schema": 1, "status": "PASSED", "count": checks,
            "installed_reads": false, "service_actions": false, "production_ready": false,
            "checks": ["exact_install_record_preserved_except_fingerprint": true,
                       "exact_host_policy_preserved_except_owner_hashes": true,
                       "exact_owner_profile_preserved_byte_values": true,
                       "owner_and_broker_uids_preserved": true,
                       "invalid_records_paths_signatures_rejected": true,
                       "foreign_root_or_broker_console_rejected": true,
                       "invalid_fingerprint_rejected": true,
                       "duplicate_plain_or_escaped_key_rejected": true]]
        guard checks == 46 else { throw PolicyCheckFailure.assertion }
        print(String(decoding: try JSONSerialization.data(withJSONObject: report, options: .sortedKeys), as: UTF8.self))
    }
}
