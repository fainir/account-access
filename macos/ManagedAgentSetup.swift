// Owner-user setup only: no broker key/store access and no capability in output.
import Foundation
import CryptoKit
import Darwin

enum ManagedAgentSetupFailure: Error { case unavailable, invalidResponse }

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
    func connect(request: (String, [String: Any]) throws -> [String: Any]) throws {
        let prepared = try helper("prepare")
        guard prepared["status"] as? String == "PREPARED", let expected = prepared["client_id"] as? String else {
            throw ManagedAgentSetupFailure.invalidResponse
        }
        let token = try readToken()
        let identity = SHA256.hash(data: Data(token.utf8)).map { String(format: "%02x", $0) }.joined()
        guard token.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil, identity == expected else {
            throw ManagedAgentSetupFailure.invalidResponse
        }
        // Neither response contains a capability. Lost responses are surfaced;
        // only an explicit retry may submit this same idempotent enrollment.
        let enrolled = try request("owner/client/enroll", ["token": token])
        guard enrolled["status"] as? String == "ENROLLED", enrolled["client_id"] as? String == identity,
              enrolled["principal"] as? String == "generic" else { throw ManagedAgentSetupFailure.invalidResponse }
        let installed = try helper("install")
        guard installed["status"] as? String == "INSTALLED", installed["client_id"] as? String == identity,
              let hosts = installed["hosts"] as? [String], hosts.count <= 2, Set(hosts).count == hosts.count,
              hosts.allSatisfy({ ["codex", "claude"].contains($0) }) else { throw ManagedAgentSetupFailure.invalidResponse }
        let confirmed = try request("owner/client/installed", ["client_id": identity, "hosts": hosts])
        guard confirmed["status"] as? String == "INSTALLED", confirmed["client_id"] as? String == identity else {
            throw ManagedAgentSetupFailure.invalidResponse
        }
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
    private static func runHelper(_ action: String) throws -> [String: Any] {
        guard ["status", "prepare", "install", "browser"].contains(action) else { throw ManagedAgentSetupFailure.unavailable }
        let ownerHome = try home()
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
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": ownerHome.path, "LANG": "en_US.UTF-8"]
        process.currentDirectoryURL = base
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let output = Pipe(); process.standardOutput = output
        try process.run()
        let deadline = Date().addingTimeInterval(75)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        guard !process.isRunning else { process.terminate(); throw ManagedAgentSetupFailure.unavailable }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0, data.count <= 8192,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ManagedAgentSetupFailure.unavailable
        }
        return value
    }
}
