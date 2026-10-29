// Owner-user setup only: no broker key/store access and no capability in output.
import Foundation
import CryptoKit
import Darwin

enum ManagedAgentSetupFailure: Error, Equatable {
    case unavailable, invalidResponse, connectionConflict, connectionRevoked
    case setupAuthorizationRequired, ownerChannelUnavailable, ownerBackendUnavailable
    case serviceRecovering, vaultRepairRequired, connectionResponseRejected
    case agentMigrationReview, agentSetupNeedsRepair, agentSetupUnsupported
    case agentSetupRetryable, agentPermissionsReview, clientConnectionNotConfirmed
}

struct ManagedAgentConnectionFailure: Error {
    enum Stage: String, CaseIterable {
        case prepare, localIdentity, enroll, install, confirm, verify
        var description: String {
            switch self {
            case .prepare: return "preparing the local AI connection"
            case .localIdentity: return "verifying the prepared local connection"
            case .enroll: return "registering the approved connection with the protected store"
            case .install: return "installing the connection for your AI tools"
            case .confirm: return "confirming the installed AI connection"
            case .verify: return "checking the completed connection"
            }
        }
    }
    let stage: Stage
    let failure: ManagedAgentSetupFailure?
    init(stage: Stage, error: Error? = nil) {
        self.stage = stage
        failure = error as? ManagedAgentSetupFailure
    }
    var conflict: Bool { failure == .connectionConflict }
    var revoked: Bool { failure == .connectionRevoked }
    private var detail: String {
        switch failure {
        case .some(.connectionConflict): return "An existing connection conflicts with this setup and needs review."
        case .some(.connectionRevoked): return "This connection was revoked and cannot be re-enabled by retrying setup."
        case .some(.setupAuthorizationRequired): return "The Mac approval was not accepted for this request. Approve the current setup dialog before continuing."
        case .some(.ownerChannelUnavailable): return "The protected owner channel is reconnecting. Check the connection status before retrying."
        case .some(.ownerBackendUnavailable): return "The protected app is not responding. Check its status before retrying."
        case .some(.serviceRecovering): return "The protected service is restarting. Wait until it is ready, then check the connection status."
        case .some(.vaultRepairRequired): return "The protected account store needs repair. Your saved data is preserved."
        case .some(.connectionResponseRejected): return "The protected service refused the connection response. Check the connection status before retrying."
        case .some(.invalidResponse): return "Account Access could not verify the connection response. Check the current connection status before retrying."
        case .some(.unavailable): return "The local AI connection files could not be verified. Repair the existing Account Access setup before continuing."
        case .some(.agentMigrationReview): return "An existing AI-tool connection needs a compatibility review before it can be upgraded. Your existing files are preserved."
        case .some(.agentSetupNeedsRepair): return "The existing AI connection needs repair before it can be upgraded. Your saved accounts and tool preferences are preserved."
        case .some(.agentSetupUnsupported): return "This AI-tool connection cannot be upgraded safely by this version. Your existing files are preserved."
        case .some(.agentSetupRetryable): return "The AI-tool files changed during setup, or another setup is running. Check the connection status before retrying."
        case .some(.agentPermissionsReview): return "macOS file permissions prevent a safe AI-tool update. Your existing files are preserved."
        case .some(.clientConnectionNotConfirmed): return "The protected account store did not confirm the local AI connection. No AI-tool launcher was changed."
        case nil: return "Reopen Account Access to check its current state before retrying."
        }
    }
    var explanation: String {
        // Fixed text only: never interpolate an error, response, path or capability.
        return "The AI connection stopped while \(stage.description). \(detail) Your saved accounts and tool preferences are preserved."
    }
}

final class ManagedAgentSetup {
    private static let base = URL(fileURLWithPath: "/Library/Application Support/Account Access")
    private let helper: (String) throws -> [String: Any]
    private let readToken: () throws -> String

    init() {
        helper = Self.runHelper
        readToken = Self.localToken
    }
    #if ACCOUNT_ACCESS_UI_CHECKS
    init(helper: @escaping (String) throws -> [String: Any], readToken: @escaping () throws -> String) {
        self.helper = helper; self.readToken = readToken
    }
    #endif
    func status() throws -> [String: Any] { try helper("status") }
    static func prepareBrowser() throws -> [String: Any] { try runHelper("browser") }
    static func helperResponse(exitStatus: Int32, data: Data) throws -> [String: Any] {
        guard data.count <= 8192,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ManagedAgentSetupFailure.unavailable
        }
        guard exitStatus != 78 else {
            guard Set(value.keys) == ["status", "reason"],
                  let status = value["status"] as? String,
                  let reason = value["reason"] as? String else {
                throw ManagedAgentSetupFailure.unavailable
            }
            let expected: (String, ManagedAgentSetupFailure)?
            switch reason {
            case "client_migration_requires_review", "client_migration_required",
                 "existing_skill_would_be_overwritten": expected = ("NEEDS_USER", .agentMigrationReview)
            case "client_setup_needs_repair", "client_upgrade_needs_repair": expected = ("NEEDS_USER", .agentSetupNeedsRepair)
            case "client_setup_permissions_need_review": expected = ("NEEDS_USER", .agentPermissionsReview)
            case "client_upgrade_not_supported": expected = ("NEEDS_USER", .agentSetupUnsupported)
            case "client_connection_not_confirmed": expected = ("NEEDS_USER", .clientConnectionNotConfirmed)
            case "client_setup_busy", "client_setup_changed": expected = ("RETRYABLE", .agentSetupRetryable)
            default: expected = nil
            }
            guard let expected, expected.0 == status else { throw ManagedAgentSetupFailure.unavailable }
            throw expected.1
        }
        guard exitStatus == 0 else { throw ManagedAgentSetupFailure.unavailable }
        return value
    }
    func connect(upgrade: Bool = false, request: (String, [String: Any]) throws -> [String: Any]) throws {
        var stage = ManagedAgentConnectionFailure.Stage.prepare
        do {
            let prepared = try helper(upgrade ? "prepare-upgrade" : "prepare")
            guard prepared["status"] as? String == "PREPARED", let expected = prepared["client_id"] as? String else {
                throw ManagedAgentSetupFailure.invalidResponse
            }
            stage = .localIdentity
            let token = try readToken()
            let identity = SHA256.hash(data: Data(token.utf8)).map { String(format: "%02x", $0) }.joined()
            guard token.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil, identity == expected else {
                throw ManagedAgentSetupFailure.invalidResponse
            }
            // Neither response contains a capability. Lost responses are surfaced;
            // only an explicit retry may submit this same idempotent enrollment.
            stage = .enroll
            let enrolled = try request("owner/client/enroll", ["token": token])
            guard enrolled["status"] as? String == "ENROLLED", enrolled["client_id"] as? String == identity,
                  enrolled["principal"] as? String == "generic" else { throw ManagedAgentSetupFailure.invalidResponse }
            stage = .install
            let installed = try helper(upgrade ? "install-upgrade" : "install")
            guard installed["status"] as? String == "INSTALLED", installed["client_id"] as? String == identity,
                  let hosts = installed["hosts"] as? [String], hosts.count <= 2, Set(hosts).count == hosts.count,
                  hosts.allSatisfy({ ["codex", "claude"].contains($0) }) else { throw ManagedAgentSetupFailure.invalidResponse }
            stage = .confirm
            let confirmed = try request("owner/client/installed", ["client_id": identity, "hosts": hosts])
            guard confirmed["status"] as? String == "INSTALLED", confirmed["client_id"] as? String == identity else {
                throw ManagedAgentSetupFailure.invalidResponse
            }
        } catch { throw ManagedAgentConnectionFailure(stage: stage, error: error) }
    }
    private static func home() throws -> URL {
        guard getuid() != 0, getuid() == geteuid(), let entry = getpwuid(getuid()) else {
            throw ManagedAgentSetupFailure.unavailable
        }
        return URL(fileURLWithPath: String(cString: entry.pointee.pw_dir))
    }
    private static func localToken() throws -> String {
        let file = try home().appendingPathComponent("Library/Application Support/Account Access/client-v1/token")
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw ManagedAgentSetupFailure.unavailable }
        defer { Darwin.close(fd) }
        var info = stat(), bytes = [UInt8](repeating: 0, count: 44)
        defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o7777 == 0o600, info.st_nlink == 1, info.st_size == 43,
              read(fd, &bytes, bytes.count) == 43,
              let token = String(bytes: bytes.prefix(43), encoding: .ascii) else { throw ManagedAgentSetupFailure.unavailable }
        return token
    }
    static func helperEnvironment(action: String, ownerHome: URL, inherited: [String: String]) throws -> [String: String] {
        guard ["status", "prepare", "install", "prepare-upgrade", "install-upgrade", "browser"].contains(action) else {
            throw ManagedAgentSetupFailure.unavailable
        }
        var environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": ownerHome.path, "LANG": "en_US.UTF-8"]
        if action != "browser", var namespace = inherited["CODEX_HOME"] {
            guard !namespace.isEmpty, namespace.utf8.count <= 4096,
                  !namespace.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
                  !namespace.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else {
                throw ManagedAgentSetupFailure.unavailable
            }
            if namespace.hasPrefix("~/") { namespace = ownerHome.path + "/" + namespace.dropFirst(2) }
            guard namespace.hasPrefix(ownerHome.path + "/"), namespace != ownerHome.path + "/" else {
                throw ManagedAgentSetupFailure.unavailable
            }
            // The isolated Python helper then verifies every existing component
            // with no-follow, owner/mode/ACL checks before any setup writes.
            environment["CODEX_HOME"] = namespace
        }
        return environment
    }
    private static func runHelper(_ action: String) throws -> [String: Any] {
        let ownerHome = try home()
        let environment = try helperEnvironment(action: action, ownerHome: ownerHome,
                                                inherited: ProcessInfo.processInfo.environment)
        let runtime = base.appendingPathComponent("runtime")
        _ = try WorkerLaunchPaths.protectedTree(runtime.path)
        let python = runtime.appendingPathComponent("bin/python")
        _ = try WorkerLaunchPaths.protected(python.path)
        // Keep the validated virtual-environment path as argv[0]. Executing
        // its resolved base binary would discard the installed package context.
        let process = Process()
        process.executableURL = python
        process.arguments = action == "browser" ? ["-I", "-B", "-m", "account_access.browser_setup"]
            : ["-I", "-B", "-m", "account_access.agent_setup", action]
        process.environment = environment
        process.currentDirectoryURL = base
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let output = Pipe(); process.standardOutput = output
        try process.run()
        let deadline = Date().addingTimeInterval(75)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        guard !process.isRunning else { process.terminate(); throw ManagedAgentSetupFailure.unavailable }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        return try Self.helperResponse(exitStatus: process.terminationStatus, data: data)
    }
}
