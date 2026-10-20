// Ordinary-user projection checks. No daemon, authdb, Keychain, policy file,
// installed service, owner app or account is accessed by this executable.
import Foundation
import Darwin

@main struct SystemStartupDiagnosticsChecks {
    struct UntrustedFailure: Error, CustomStringConvertible {
        var description: String { fatalError("Diagnostics must never render an arbitrary error") }
    }
    static func main() throws {
        let cases: [(Error, String)] = [
            (RootVaultKeyFailure.daemonRequired, "system_daemon_context_required"),
            (SystemBrokerFailure.policy, "system_broker_invalid_policy"),
            (OwnerPolicyFailure.readback, "owner_policy_readback_invalid"),
            (WorkerLaunchFailure.treeOwner, "worker_runtime_tree_owner_mismatch"),
            (RootListenerFailure.metadata, "broker_socket_activation_metadata_invalid"),
            (RootWorkerProcessFailure.ownershipLost, "worker_process_ownership_lost"),
            (RootWorkerChannelFailure.unavailable, "worker_secret_channel_unavailable"),
            (RootStoreInitializationFailure.invalidReceipt, "store_initializer_receipt_invalid"),
            (RootPublicationFailure.unsafeState, "vault_publication_unsafe_state"),
            (RootMessagesFailure.readerCode, "native_messages_reader_code_rejected"),
            (RootVaultRecordFailure(.references, result: ["private": "fictional-secret"] as CFDictionary), "vault_key_reference_result_invalid"),
            (RootKeychainFailure(operation: .load, status: -12345), "system_keychain_load_failed"),
            (RootKeychainFailure(operation: .enroll, status: -12345), "system_keychain_enroll_failed"),
            (RootKeychainFailure(operation: .remove, status: -12345), "system_keychain_remove_failed"),
            (OwnerGatewayError.invalidPolicy, "owner_gateway_policy_invalid"),
            (OwnerGatewayError.unavailable, "owner_gateway_unavailable"),
            (OwnerGatewayError.invalidResponse, "owner_gateway_response_invalid"),
            (NSError(domain: "fictional-private-path-and-username", code: -12345,
                     userInfo: [NSLocalizedDescriptionKey: "fictional-secret"]), "system_broker_unavailable"),
            (UntrustedFailure(), "system_broker_unavailable")
        ]
        for (error, expected) in cases {
            var emitted: [SystemBrokerStartupDiagnostics.Projection] = []
            SystemBrokerStartupDiagnostics.record(.settings, error: error, emit: { emitted.append($0) })
            precondition(emitted == [.init(phase: "settings", reason: expected)])
            let encoded = try JSONSerialization.data(withJSONObject: ["phase": emitted[0].phase, "reason": emitted[0].reason])
            let text = String(decoding: encoded, as: UTF8.self)
            precondition(!text.contains("fictional") && !text.contains("-12345"))
        }
        print("PASS: startup diagnostics project typed failures once and discard arbitrary errors, record values, paths, identities and OS-provided strings")
        let hostPhases: [RootBrokerStartupPhase] = [.daemonContext, .listeners, .workerSupervisor,
            .messagesCollector, .enrollmentPlan, .gatewayInitialization, .ownerPolicy,
            .enrollmentStart, .workerStart, .gatewayStart]
        for phase in hostPhases {
            let value = SystemBrokerStartupDiagnostics.project(.host(phase), error: RootListenerFailure.invalid)
            precondition(value.phase == phase.rawValue && value.reason == "broker_socket_activation_invalid")
        }
        let outerPhases: [SystemBrokerStartupPhase] = [.daemonContext, .arguments, .settings,
            .brokerDomain, .hostCreation, .hostStart, .ready, .stopping]
        precondition(Set(outerPhases.map { $0.name }).count == outerPhases.count)
        print("PASS: outer and nested startup checkpoints retain a closed phase vocabulary")
        // This is an ordinary-user check: the existing root guard must reject
        // before policy lookup, socket activation, authdb or key access.
        precondition(getuid() != 0 && geteuid() != 0)
        let peer = try OwnerGatewayPeer(uid: getuid(), team: "ABCD123456", identifier: "com.example.fixture",
            codeHashes: [String(repeating: "a", count: 40)])
        var phases: [RootBrokerStartupPhase] = []
        do {
            _ = try RootBrokerHost(policy: "/fictional-policy-never-opened", bootstrap: "/fictional-bootstrap-never-opened",
                bootstrapPeer: peer, vault: "fictional-vault-never-opened", owner: peer, startup: { phases.append($0) })
            preconditionFailure("Diagnostics changed the root-daemon guard")
        } catch RootVaultKeyFailure.daemonRequired {
            precondition(phases == [.daemonContext])
        }
        print("PASS: startup callback reports the original daemon gate without bypassing it or touching any policy or owner state")
    }
}
