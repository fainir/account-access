// Disposable-CI entrypoints for the production root host and privileged client.
// No installed user, keychain, authorization rule or private account is used.
import Foundation
import Security
import Darwin

enum RootGatewayFixture {
    static func policy() throws -> [String: Any] {
        guard CommandLine.arguments.count >= 3, CommandLine.arguments[1] == "--policy",
              CommandLine.arguments[2].hasPrefix("/Library/PrivilegedHelperTools/account-access-worker-qa-") else {
            throw OwnerGatewayError.invalidPolicy
        }
        let value = try WorkerLaunchPaths.object(CommandLine.arguments[2])
        guard Set(value.keys) == ["fixture", "owner_uid", "owner_hash", "server_hash", "owner_socket", "owner_port", "bootstrap_socket"],
              value["fixture"] as? String == "account-access-root-owner-ci-v1" else { throw OwnerGatewayError.invalidPolicy }
        return value
    }
    static func capability(_ path: String) throws -> String {
        let directory = URL(fileURLWithPath: path).deletingLastPathComponent().path
        _ = try WorkerLaunchPaths.protected(directory)
        var info = stat()
        guard lstat(directory, &info) == 0, info.st_mode & 0o077 == 0,
              lstat(path, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFSOCK,
              info.st_mode & 0o077 == 0 else { throw OwnerGatewayError.invalidPolicy }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw OwnerGatewayError.unavailable }
        defer { Darwin.close(fd) }
        var timeout = timeval(tv_sec: 10, tv_usec: 0)
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
              setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
            throw OwnerGatewayError.unavailable
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString)
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw OwnerGatewayError.invalidPolicy }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes.map { UInt8(bitPattern: $0) }) }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        var uid: uid_t = 0, gid: gid_t = 0
        guard result == 0, getpeereid(fd, &uid, &gid) == 0, uid == 0 else { throw OwnerGatewayError.invalidPolicy }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 44)
        defer { _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }; data.resetBytes(in: 0..<data.count) }
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count == 0 { break }
            guard count > 0, data.count + count <= 43 else { throw OwnerGatewayError.invalidResponse }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard let text = String(data: data, encoding: .utf8),
              text.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else { throw OwnerGatewayError.invalidResponse }
        return text
    }
    static func wait<T>(_ operation: (@escaping (T) -> Void) -> Void) throws -> T {
        let done = DispatchSemaphore(value: 0)
        var result: T?
        operation { result = $0; done.signal() }
        guard done.wait(timeout: .now() + 40) == .success, let result else { throw OwnerGatewayError.unavailable }
        return result
    }
    static func request(_ channel: OwnerGatewayConnection, _ path: String, _ body: [String: Any]? = nil) throws -> (Int, [String: Any]) {
        let payload = try body.map { try JSONSerialization.data(withJSONObject: $0) }
        let result: (Int, Data) = try wait { done in channel.request(path, body: payload) { done(($0, $1)) } }
        guard let value = try JSONSerialization.jsonObject(with: result.1) as? [String: Any] else {
            throw OwnerGatewayError.invalidResponse
        }
        return (result.0, value)
    }
}

#if ACCOUNT_ACCESS_ROOT_GATEWAY_DAEMON
@main struct RootOwnerGatewayDaemonMain {
    static func main() {
        do {
            guard getuid() == 0, geteuid() == 0 else { throw OwnerGatewayError.invalidPolicy }
            var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
            guard setrlimit(RLIMIT_CORE, &noCore) == 0 else { throw OwnerGatewayError.invalidPolicy }
            let value = try RootGatewayFixture.policy()
            let uid = try WorkerLaunchPaths.integer(value["owner_uid"])
            guard let hash = value["owner_hash"] as? String else { throw OwnerGatewayError.invalidPolicy }
            let peer = try OwnerGatewayPeer.fixture(uid: uid, codeHash: hash)
            let token = try RootGatewayFixture.capability(WorkerLaunchPaths.lexical(value["bootstrap_socket"]))
            let backend = try OwnerUnixBackend(path: WorkerLaunchPaths.lexical(value["owner_socket"]), capability: token,
                port: Int(WorkerLaunchPaths.integer(value["owner_port"], maximum: 65535)))
            let host = try OwnerGatewayHost(owner: peer, backend: backend)
            try host.start()
            signal(SIGTERM, SIG_IGN)
            let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
            termination.setEventHandler { host.stop(); exit(0) }
            termination.resume()
            withExtendedLifetime((host, termination)) { RunLoop.current.run() }
        } catch {
            print("{\"status\":\"FAILED\",\"reason\":\"root_owner_gateway_unavailable\"}")
            exit(78)
        }
    }
}
#endif

#if ACCOUNT_ACCESS_ROOT_GATEWAY_CLIENT
@main struct RootOwnerGatewayClientMain {
    static func main() {
        var checks: [String: Bool] = [:]
        do {
            guard getuid() != 0, CommandLine.arguments.count == 4 else { throw OwnerGatewayError.invalidPolicy }
            let value = try RootGatewayFixture.policy()
            guard let hash = value["server_hash"] as? String else { throw OwnerGatewayError.invalidPolicy }
            let peer = try OwnerGatewayPeer.fixture(uid: 0, codeHash: hash)
            let channel = try OwnerGatewayConnection(service: OwnerGatewayHost.serviceName, peer: peer)
            defer { channel.invalidate() }
            let ready: Bool = try RootGatewayFixture.wait { channel.prepare(reply: $0) }
            let mode = CommandLine.arguments[3]
            if mode == "denied" {
                checks["prepare_refused"] = !ready
                let authorized: Bool = try RootGatewayFixture.wait { channel.authorizeSetup(Data(repeating: 0x41, count: 32), reply: $0) }
                checks["failed_prepare_refuses_setup"] = !authorized
                let refused = try RootGatewayFixture.request(channel, "owner/credential", ["account": "demo-api", "credential": ["password": "fictional-only"]])
                checks["failed_prepare_refuses_credential_input"] = refused.0 == 503
            } else if mode == "hold" {
                guard ready else { throw OwnerGatewayError.unavailable }
                print("{\"stage\":\"owner_connection_ready\"}")
                fflush(stdout)
                guard readLine() == "continue" else { throw OwnerGatewayError.invalidResponse }
                let result = try RootGatewayFixture.request(channel, "owner/state")
                checks["stopped_service_channel_refused"] = result.0 == 503
            } else if mode == "coordinator-paused" {
                checks["coordinator_paused_peer_prepared"] = ready
                guard ready else { throw OwnerGatewayError.unavailable }
                let state = try RootGatewayFixture.request(channel, "owner/state")
                checks["coordinator_paused_state_refused"] = state.0 == 503 && state.1["reason"] as? String == "broker_worker_paused"
                let authorized: Bool = try RootGatewayFixture.wait { channel.authorizeSetup(Data(repeating: 0x41, count: 32), reply: $0) }
                checks["coordinator_paused_ungranted_setup_refused"] = !authorized
            } else if mode == "first-enrollment" || mode == "provisioned-install" {
                checks["first_enrollment_root_peer_prepared"] = ready
                guard ready else { throw OwnerGatewayError.unavailable }
                let state = try RootGatewayFixture.request(channel, "owner/state")
                let setup = state.1["vault_setup"] as? [String: Any]
                checks["first_enrollment_state_available_without_vault"] = state.0 == 200
                    && setup?["status"] as? String == "needs_owner"
                    && (state.1["accounts"] as? [Any])?.isEmpty == true
                let health = try RootGatewayFixture.request(channel, "owner/health")
                checks["first_enrollment_health_available"] = health.0 == 200
                    && (health.1["vault_setup"] as? [String: Any])?["status"] as? String == "needs_owner"
                let enroll = try RootGatewayFixture.request(channel, "owner/vault/enroll", [:])
                checks["first_enrollment_without_approval_refused"] = enroll.0 == 403
                let authorized: Bool = try RootGatewayFixture.wait { channel.authorizeSetup(Data(repeating: 0x41, count: 32), reply: $0) }
                checks["first_enrollment_invalid_os_proof_refused"] = !authorized
                checks["first_enrollment_invalid_proof_cannot_create_key"] = try RootGatewayFixture.request(channel, "owner/vault/enroll", [:]).0 == 403
                checks["first_enrollment_caller_configuration_refused"] = try RootGatewayFixture.request(channel, "owner/vault/enroll", ["vault_id": "untrusted"]).0 == 403
                let directory = URL(fileURLWithPath: CommandLine.arguments[2]).deletingLastPathComponent()
                let profileName = mode == "provisioned-install" ? "owner.json" : "desktop-owner.json"
                let profile = try DesktopOwnerProfile.fixture(directory: directory, components: [profileName], fileOwner: 0)
                checks["desktop_profile_reads_protected_root_registration"] = profile.peer.uid == 0
                var prompts = 0
                let desktop = DesktopOwnerConnection(makeChannel: {
                    try OwnerGatewayConnection(service: OwnerGatewayHost.serviceName, peer: profile.peer)
                }, acquire: { prompts += 1; return Data(repeating: 0x41, count: 32) })
                defer { desktop.close() }
                let desktopState = try desktop.request("owner/state")
                checks["desktop_native_read_needs_no_os_approval"] = desktopState.0 == 200 && prompts == 0
                    && (desktopState.1["vault_setup"] as? [String: Any])?["status"] as? String == "needs_owner"
                var approvalRefused = false
                do { _ = try desktop.request("owner/vault/enroll", body: [:]) }
                catch DesktopOwnerFailure.approval { approvalRefused = true }
                checks["desktop_native_invalid_os_proof_blocks_enrollment"] = approvalRefused && prompts == 1

            } else if mode == "coordinator" {
                checks["coordinator_privileged_peer_prepared"] = ready
                guard ready else { throw OwnerGatewayError.unavailable }
                let state = try RootGatewayFixture.request(channel, "owner/state")
                checks["coordinator_encrypted_fixture_store_reached"] = state.0 == 200
                    && (state.1["accounts"] as? [[String: Any]])?.isEmpty == true
                let authorized: Bool = try RootGatewayFixture.wait { channel.authorizeSetup(Data(repeating: 0x41, count: 32), reply: $0) }
                checks["coordinator_ungranted_setup_refused"] = !authorized
                let credential = try RootGatewayFixture.request(channel, "owner/credential", ["account": "fixture", "credential": [:]])
                checks["coordinator_unauthorized_write_refused"] = credential.0 == 403
            } else if mode == "accepted" {
                checks["privileged_root_peer_prepared"] = ready
                guard ready else { throw OwnerGatewayError.unavailable }
                let state = try RootGatewayFixture.request(channel, "owner/state")
                checks["root_backend_reached_isolated_worker"] = state.0 == 200 && state.1["accounts"] is [[String: Any]]
                let authorized: Bool = try RootGatewayFixture.wait { channel.authorizeSetup(Data(repeating: 0x41, count: 32), reply: $0) }
                checks["unconfigured_os_setup_refused"] = !authorized
                let credential = try RootGatewayFixture.request(channel, "owner/credential", ["account": "demo-api", "credential": ["password": "fictional-only"]])
                checks["unauthorized_credential_write_refused"] = credential.0 == 403
                let grant = try RootGatewayFixture.request(channel, "owner/grant", ["account": "demo-api", "principal": "generic", "operations": ["summary"]])
                checks["unauthorized_grant_refused"] = grant.0 == 403
                let revoked = try RootGatewayFixture.request(channel, "owner/revoke", ["account": "demo-api"])
                checks["signed_owner_revocation_reached_worker"] = revoked.0 == 200
            } else { throw OwnerGatewayError.invalidPolicy }
            guard !checks.isEmpty, checks.values.allSatisfy({ $0 }) else { throw OwnerGatewayError.invalidResponse }
            print(String(data: try JSONSerialization.data(withJSONObject: ["status": "PASSED", "checks": checks]), encoding: .utf8)!)
        } catch {
            let report: [String: Any] = ["status": "FAILED", "reason": "root_owner_client_checks_failed",
                "failed_checks": checks.filter { !$0.value }.keys.sorted()]
            print(String(data: (try? JSONSerialization.data(withJSONObject: report)) ?? Data(), encoding: .utf8) ?? "{}")
            exit(1)
        }
    }
}
#endif
