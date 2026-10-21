import Foundation
import Darwin

final class DesktopChannelFixture: DesktopOwnerChannel {
    var isAvailable = false
    var acceptsPeer = true
    var acceptsApproval = true
    var requests = 0
    var approvals = 0
    var dropped = false
    var invalidJSON = false
    func prepare(reply: @escaping (Bool) -> Void) { isAvailable = acceptsPeer; reply(acceptsPeer) }
    func authorizeSetup(_ form: Data, reply: @escaping (Bool) -> Void) { approvals += 1; reply(acceptsApproval && form.count == 32) }
    func request(_ route: String, body: Data?, reply: @escaping (Int, Data) -> Void) {
        requests += 1
        if dropped { dropped = false; reply(503, OwnerGatewaySession.failure("owner_channel_unavailable")); return }
        if invalidJSON { reply(200, Data("[]".utf8)); return }
        let payload = route == "owner/vault/enroll" ? "{\"vault_setup\":{\"status\":\"initializing\"}}" : "{\"accounts\":[],\"catalog\":[]}"
        reply(route == "owner/vault/enroll" ? 202 : 200, Data(payload.utf8))
    }
    func invalidate() { isAvailable = false }
}

@main struct DesktopOwnerConnectionChecks {
    static func main() throws {
        var checks: [String: Bool] = [:]
        func fails(_ operation: () throws -> Void) -> Bool {
            do { try operation(); return false } catch { return true }
        }
        var created: [DesktopChannelFixture] = [], approvals = 0, closedApprovals = 0
        var now: TimeInterval = 100
        let connection = DesktopOwnerConnection(makeChannel: {
            let channel = DesktopChannelFixture(); created.append(channel); return channel
        }, acquire: { approvals += 1; return Data(repeating: 0x46, count: 32) }, closeApproval: { closedApprovals += 1 }, clock: { now })
        checks["read_never_requests_os_approval"] = try connection.request("owner/state").0 == 200 && approvals == 0
        checks["enrollment_pending_response_preserved"] = try connection.request("owner/vault/enroll", body: [:]).0 == 202
        checks["setup_lease_reused_for_next_owner_action"] = try connection.request("owner/mailbox/check", body: [:]).0 == 200 && approvals == 1 && created.count == 1
        now += 571
        checks["expired_lease_requires_new_owner_approval"] = try connection.request("owner/source/check", body: [:]).0 == 200 && approvals == 2
        created[0].dropped = true
        let previous = created[0].requests
        checks["lost_write_response_never_replayed"] = try connection.request("owner/credential", body: [:]).0 == 503 && created[0].requests == previous + 1 && created.count == 1
        checks["next_read_reconnects_without_approval"] = try connection.request("owner/state").0 == 200 && created.count == 2 && approvals == 2
        checks["new_channel_does_not_inherit_setup_lease"] = try connection.request("owner/credential", body: [:]).0 == 200 && approvals == 3 && created[1].approvals == 1
        let beforeInvalid = created[1].requests
        checks["unsupported_route_refused_before_transport"] = fails { _ = try connection.request("owner/install", body: [:]) }
            && fails { _ = try connection.request("owner/native-messages/next") }
            && fails { _ = try connection.request("owner/native-messages/respond", body: [:]) }
            && created[1].requests == beforeInvalid && approvals == 3
        checks["caller_enrollment_configuration_refused"] = fails { _ = try connection.request("owner/vault/enroll", body: ["vault_id": "untrusted"]) } && created[1].requests == beforeInvalid
        connection.close()
        let beforeStopApproval = approvals
        checks["pause_never_requests_new_approval"] = try connection.request("owner/stop", body: [:]).0 == 200 && approvals == beforeStopApproval
        checks["authorization_reference_closed"] = closedApprovals >= approvals
        let deniedPeer = DesktopChannelFixture(); deniedPeer.acceptsPeer = false
        var deniedPrompts = 0
        let rejected = DesktopOwnerConnection(makeChannel: { deniedPeer }, acquire: { deniedPrompts += 1; return Data(repeating: 0, count: 32) })
        checks["unverified_peer_gets_no_os_proof_or_setup_body"] = fails { _ = try rejected.request("owner/credential", body: [:]) }
            && deniedPrompts == 0 && deniedPeer.requests == 0 && deniedPeer.approvals == 0
        let deniedSetup = DesktopChannelFixture(); deniedSetup.acceptsApproval = false
        let unapproved = DesktopOwnerConnection(makeChannel: { deniedSetup }, acquire: { Data(repeating: 0, count: 32) })
        checks["denied_os_approval_gets_no_setup_body"] = fails { _ = try unapproved.request("owner/credential", body: [:]) } && deniedSetup.requests == 0 && !deniedSetup.isAvailable
        let malformed = DesktopChannelFixture(); malformed.invalidJSON = true
        let malformedConnection = DesktopOwnerConnection(makeChannel: { malformed }, acquire: { Data() })
        checks["malformed_reply_closes_connection"] = fails { _ = try malformedConnection.request("owner/state") } && !malformed.isAvailable

        var progressEvents: [String] = []
        var progressTime: TimeInterval = 200
        let progressChannel = DesktopChannelFixture()
        let progressConnection = DesktopOwnerConnection(makeChannel: { progressChannel }, acquire: {
            progressEvents.append("acquire")
            return Data(repeating: 0x47, count: 32)
        }, clock: { progressTime })
        func recordProgress(_ phase: DesktopOwnerSetupProgress) {
            switch phase {
            case .requestingApproval: progressEvents.append("requesting")
            case .approvalAccepted: progressEvents.append("accepted")
            }
        }
        _ = try progressConnection.request("owner/state", setupProgress: recordProgress)
        checks["reads_have_no_approval_progress"] = progressEvents.isEmpty && progressChannel.approvals == 0
        _ = try progressConnection.request("owner/import/preview", body: ["csv": "synthetic"], setupProgress: recordProgress)
        checks["approval_progress_brackets_real_acquire_and_authorization"] = progressEvents == ["requesting", "acquire", "accepted"]
            && progressChannel.approvals == 1 && progressChannel.requests == 2
        _ = try progressConnection.request("owner/import/preview", body: ["csv": "synthetic"], setupProgress: recordProgress)
        checks["live_setup_lease_has_no_new_approval_progress"] = progressEvents.count == 3 && progressChannel.approvals == 1
        progressTime += 570
        _ = try progressConnection.request("owner/import/preview", body: ["csv": "synthetic"], setupProgress: recordProgress)
        checks["lease_expiry_reports_new_approval_before_acquire"] = progressEvents == ["requesting", "acquire", "accepted", "requesting", "acquire", "accepted"]
            && progressChannel.approvals == 2
        progressConnection.close()
        let beforePauseProgress = progressEvents
        _ = try progressConnection.request("owner/stop", body: [:], setupProgress: recordProgress)
        checks["restriction_never_reports_mac_approval"] = progressEvents == beforePauseProgress
        let unverifiedProgressChannel = DesktopChannelFixture()
        unverifiedProgressChannel.acceptsPeer = false
        var unverifiedProgress = 0
        let unverifiedProgressConnection = DesktopOwnerConnection(makeChannel: { unverifiedProgressChannel }, acquire: {
            unverifiedProgress += 100
            return Data(repeating: 0x48, count: 32)
        })
        checks["unverified_peer_has_no_approval_progress"] = fails {
            _ = try unverifiedProgressConnection.request("owner/import/preview", body: ["csv": "synthetic"], setupProgress: { _ in
                unverifiedProgress += 1
            })
        } && unverifiedProgress == 0 && unverifiedProgressChannel.requests == 0
        let cancelledChannel = DesktopChannelFixture()
        var cancelledProgress = 0
        let cancelledConnection = DesktopOwnerConnection(makeChannel: { cancelledChannel }, acquire: {
            throw DesktopOwnerFailure.approval
        })
        checks["cancelled_approval_never_reports_accepted_or_sends_body"] = fails {
            _ = try cancelledConnection.request("owner/import/preview", body: ["csv": "synthetic"], setupProgress: { phase in
                switch phase {
                case .requestingApproval: cancelledProgress += 1
                case .approvalAccepted: cancelledProgress += 100
                }
            })
        } && cancelledProgress == 1 && cancelledChannel.requests == 0 && cancelledChannel.approvals == 0

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ac-owner-profile-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("owner.json")
        let value: [String: Any] = ["managed_by": "account-access-desktop-owner-v1", "schema": 1,
            "owner_uid": Int(getuid()), "publisher_team": "fixture", "server_identifier": "com.fainir.accountaccess.broker", "server_hashes": [String(repeating: "a", count: 40)]]
        func write(_ body: [String: Any]) throws {
            try JSONSerialization.data(withJSONObject: body).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        func load(_ components: [String] = ["owner.json"], owner: uid_t = getuid()) throws {
            _ = try DesktopOwnerProfile.fixture(directory: directory, components: components, accountOwner: owner)
        }
        try write(value); try load()
        checks["protected_public_profile_accepted"] = true
        checks["different_owner_profile_refused"] = fails { try load(owner: getuid() + 1) }
        try FileManager.default.setAttributes([.posixPermissions: 0o620], ofItemAtPath: file.path)
        checks["writable_profile_refused"] = fails { try load() }
        try write(value)
        let alias = directory.appendingPathComponent("alias.json")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: file)
        checks["symbolic_profile_refused"] = fails { try load(["alias.json"]) }
        try FileManager.default.removeItem(at: alias)
        try FileManager.default.linkItem(at: file, to: alias)
        checks["hardlinked_profile_refused"] = fails { try load() }
        try FileManager.default.removeItem(at: alias)
        var changed = value; changed["schema"] = true; try write(changed)
        checks["boolean_schema_refused"] = fails { try load() }
        changed = value; changed["owner_uid"] = true; try write(changed)
        checks["boolean_owner_refused"] = fails { try load() }
        changed = value; changed["service"] = "caller.selected"; try write(changed)
        checks["caller_selected_endpoint_refused"] = fails { try load() }
        changed = value; changed["server_identifier"] = "another.app"; try write(changed)
        checks["unrelated_server_profile_refused"] = fails { try load() }
        try Data(repeating: 0x41, count: 4097).write(to: file)
        checks["oversized_profile_refused"] = fails { try load() }
        try write(value)
        try FileManager.default.setAttributes([.posixPermissions: 0o720], ofItemAtPath: directory.path)
        checks["writable_profile_directory_refused"] = fails { try load() }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        checks["relative_traversal_refused"] = fails { try load(["..", "owner.json"]) }
        let acl = try Process.run(URL(fileURLWithPath: "/bin/chmod"), arguments: ["+a", "everyone allow write", file.path])
        acl.waitUntilExit()
        guard acl.terminationStatus == 0 else { throw DesktopOwnerFailure.profile }
        checks["extended_acl_profile_refused"] = fails { try load() }
        checks["unknown_setup_state_requires_repair"] = DesktopVaultScreen(["vault_setup": ["status": "fictional-untrusted-value"]]) == .repair
        checks["incomplete_ready_response_not_account_ready"] = DesktopVaultScreen(["vault_setup": ["status": "ready"]]) == .initializing
        checks["published_worker_state_ready"] = DesktopVaultScreen(["accounts": [], "catalog": []]) == .ready
        checks["empty_state_not_account_ready"] = DesktopVaultScreen([:]) == .repair
        let clientBody = try JSONSerialization.data(withJSONObject: ["token": String(repeating: "F", count: 43)])
        let receiptBody = try JSONSerialization.data(withJSONObject: ["client_id": String(repeating: "a", count: 64), "hosts": ["codex", "claude"]])
        checks["client_enrollment_requires_setup"] = try OwnerGatewayRoute("owner/client/enroll", body: clientBody).requiresSetup
        checks["client_enrollment_rejects_caller_principal"] = fails {
            _ = try OwnerGatewayRoute("owner/client/enroll", body: JSONSerialization.data(withJSONObject: ["token": String(repeating: "F", count: 43), "principal": "admin"]))
        }
        checks["client_enrollment_refuses_malformed_capability"] = fails {
            _ = try OwnerGatewayRoute("owner/client/enroll", body: Data("{\"token\":\"short\"}".utf8))
        }
        checks["client_install_receipt_requires_setup"] = try OwnerGatewayRoute("owner/client/installed", body: receiptBody).requiresSetup
        checks["client_install_receipt_refuses_unknown_host"] = fails {
            _ = try OwnerGatewayRoute("owner/client/installed", body: JSONSerialization.data(withJSONObject: ["client_id": String(repeating: "a", count: 64), "hosts": ["shell"]]))
        }
        final class NoClientBackend: OwnerGatewayBackend {
            var calls = 0
            func request(_ route: OwnerGatewayRoute) throws -> (Int, Data) { calls += 1; return (200, Data("{}".utf8)) }
        }
        let noClientBackend = NoClientBackend()
        let noClientSession = OwnerGatewaySession.fixture(backend: noClientBackend, authorize: { _ in false })
        var clientRejected = false
        noClientSession.request("owner/client/enroll", body: clientBody) { clientRejected = $0 == 403; _ = $1 }
        checks["unapproved_session_cannot_enroll_client"] = clientRejected && noClientBackend.calls == 0
        noClientSession.request("owner/client/installed", body: receiptBody) { clientRejected = $0 == 403; _ = $1 }
        checks["unapproved_session_cannot_confirm_client_install"] = clientRejected && noClientBackend.calls == 0
        noClientSession.close()
        let report: [String: Any] = ["status": checks.values.allSatisfy({ $0 }) ? "PASSED" : "FAILED", "checks": checks,
            "environment": "controlled-demo", "production_ready": false, "private_signins": 0,
            "actual_native_xpc_used": false, "genuine_owner_approval_verified": false]
        print(String(decoding: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), as: UTF8.self))
        if checks.values.contains(false) { exit(1) }
    }
}
