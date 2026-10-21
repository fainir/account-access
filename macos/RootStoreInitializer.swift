// Private staged-store creation after the hosting daemon authorizes enrollment.
// This never enrolls/replaces a System key, publishes a stage or grants a client.
import Foundation
import Security
import CryptoKit
import Darwin

enum RootStoreInitializationFailure: String, Error {
    case unsafeCode = "store_initializer_code_rejected"
    case unavailable = "store_initializer_unavailable"
    case invalidReceipt = "store_initializer_receipt_invalid"
    case timeout = "store_initializer_timed_out"
    case ownershipLost = "store_initializer_ownership_lost"
}

// Only a completed initializer can construct this receipt. It contains no key
// or proof bytes and cannot be supplied through an owner/agent request.
struct VerifiedStagedVault {
    let vault: String
    let enrollment: String
    let path: String
    let device: dev_t
    let inode: ino_t
    fileprivate init(plan: MacWorkerEnrollmentPlan, info: stat) {
        vault = plan.vault; enrollment = plan.enrollment; path = plan.stage
        device = info.st_dev; inode = info.st_ino
    }
}

final class RootStoreInitializer {
    private let policy: String
    private let plan: MacWorkerEnrollmentPlan
    private let bootstrap: String
    init(policy: String, bootstrap: String, peer: OwnerGatewayPeer) throws {
        try RootVaultKeyStore.requireDaemon()
        plan = try MacWorkerEnrollmentPlan(policy: policy)
        self.policy = policy
        self.bootstrap = try WorkerLaunchPaths.protected(bootstrap).path
        var code: SecStaticCode?
        var requirement: SecRequirement?
        guard peer.uid == 0, SecStaticCodeCreateWithPath(URL(fileURLWithPath: self.bootstrap) as CFURL, [], &code) == errSecSuccess,
              let code, SecRequirementCreateWithString(peer.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement, SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw RootStoreInitializationFailure.unsafeCode
        }
    }
    private func spawn(_ sources: [Int32]) throws -> pid_t {
        var copies: [Int32] = []
        defer { copies.forEach { Darwin.close($0) } }
        for fd in sources {
            let copy = fcntl(fd, F_DUPFD_CLOEXEC, 10)
            guard copy >= 10 else { throw RootStoreInitializationFailure.unavailable }
            copies.append(copy)
        }
        let values = ["/bin/launchctl", "asuser", String(plan.base.uid), bootstrap, "--enrollment-policy", policy,
                      "--bootstrap-fd", "3", "--receipt-fd", "4"]
        var arguments = values.map { strdup($0) }; arguments.append(nil)
        var environment = plan.base.environment.map { strdup($0) }; environment.append(nil)
        defer { arguments.forEach { free($0) }; environment.forEach { free($0) } }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard !arguments.dropLast().contains(where: { $0 == nil }), !environment.dropLast().contains(where: { $0 == nil }),
              posix_spawn_file_actions_init(&actions) == 0 else { throw RootStoreInitializationFailure.unavailable }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw RootStoreInitializationFailure.unavailable }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else { throw RootStoreInitializationFailure.unavailable }
        for fd in Int32(0)...2 {
            guard posix_spawn_file_actions_addinherit_np(&actions, fd) == 0 else { throw RootStoreInitializationFailure.unavailable }
        }
        for (index, source) in copies.enumerated() {
            guard posix_spawn_file_actions_adddup2(&actions, source, Int32(index + 3)) == 0 else { throw RootStoreInitializationFailure.unavailable }
        }
        var child: pid_t = 0
        let status = arguments.withUnsafeMutableBufferPointer { args in
            environment.withUnsafeMutableBufferPointer { env in
                posix_spawn(&child, "/bin/launchctl", &actions, &attributes, args.baseAddress!, env.baseAddress!)
            }
        }
        guard status == 0, child > 0 else { throw RootStoreInitializationFailure.unavailable }
        return child
    }
    private func read(_ fd: Int32, count: Int, deadline: TimeInterval) throws -> Data {
        var data = Data()
        while data.count < count {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw RootStoreInitializationFailure.timeout }
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&descriptor, 1, Int32(min(1000, (remaining * 1000).rounded(.up))))
            if ready < 0 && errno == EINTR { continue }
            guard ready >= 0 else { throw RootStoreInitializationFailure.unavailable }
            if ready == 0 { continue }
            var buffer = [UInt8](repeating: 0, count: count - data.count)
            let received = Darwin.recv(fd, &buffer, buffer.count, 0)
            if received < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard received > 0 else { throw RootStoreInitializationFailure.invalidReceipt }
            data.append(contentsOf: buffer.prefix(received))
        }
        return data
    }
    @discardableResult
    func initialize(key: RootVaultKey) throws -> VerifiedStagedVault {
        try RootVaultKeyStore.requireDaemon()
        // Recheck emptiness immediately before handing a key to the child.
        _ = try MacWorkerEnrollmentPlan(policy: policy)
        var original = stat()
        guard lstat(plan.stage, &original) == 0 else { throw RootStoreInitializationFailure.unavailable }
        let channel = try RootWorkerChannel(key: key)
        defer { channel.cancel() }
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw RootStoreInitializationFailure.unavailable }
        defer { pair.filter { $0 >= 0 }.forEach { Darwin.close($0) } }
        var enabled: Int32 = 1
        guard fcntl(pair[0], F_SETFD, FD_CLOEXEC) == 0, fcntl(pair[1], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0,
              setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw RootStoreInitializationFailure.unavailable
        }
        var child: pid_t? = try spawn([channel.readDescriptor(), pair[1]])
        defer {
            if let pid = child {
                var status: Int32 = 0
                if waitpid(pid, &status, WNOHANG) == 0 {
                    Darwin.kill(pid, SIGKILL)
                    _ = waitpid(pid, &status, 0)
                }
            }
        }
        Darwin.close(pair[1]); pair[1] = -1
        try channel.transmit()
        let deadline = ProcessInfo.processInfo.systemUptime + 30
        let size = try read(pair[0], count: 4, deadline: deadline).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard (1...1024).contains(size), let value = try JSONSerialization.jsonObject(with: read(pair[0], count: Int(size), deadline: deadline)) as? [String: Any],
              Set(value.keys) == ["status", "vault_id", "enrollment_id", "uid", "gid", "pid", "proof"],
              value["status"] as? String == "INITIALIZED", value["vault_id"] as? String == plan.vault,
              value["enrollment_id"] as? String == plan.enrollment, value["uid"] as? Int == Int(plan.base.uid),
              value["gid"] as? Int == Int(plan.base.gid), value["pid"] as? Int == Int(child!),
              let proof = value["proof"] as? String, proof.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              AccountAccessProcessIdentity(child!, plan.base.uid, plan.base.gid, getpid(), getpgrp()) else {
            throw RootStoreInitializationFailure.invalidReceipt
        }
        var bytes = Data()
        var cursor = proof.startIndex
        while cursor < proof.endIndex {
            let next = proof.index(cursor, offsetBy: 2)
            bytes.append(UInt8(proof[cursor..<next], radix: 16)!)
            cursor = next
        }
        let verified = try channel.withOwnerSecret { secret -> Bool in
            let derived = HMAC<SHA256>.authenticationCode(for: Data("account-access-owner-channel-v1".utf8), using: SymmetricKey(data: Data(secret)))
            let root = URL(fileURLWithPath: plan.stage).resolvingSymlinksInPath().path
            let message = Data(("account-access-vault-enrollment-v1\0" + plan.vault + "\0" + plan.enrollment + "\0" + root).utf8)
            return HMAC<SHA256>.isValidAuthenticationCode(bytes, authenticating: message, using: SymmetricKey(data: Data(derived)))
        }
        guard verified else { throw RootStoreInitializationFailure.invalidReceipt }
        var ack: UInt8 = 49
        guard Darwin.send(pair[0], &ack, 1, 0) == 1 else { throw RootStoreInitializationFailure.unavailable }
        var status: Int32 = 0
        while true {
            let result = waitpid(child!, &status, WNOHANG)
            if result == child! { child = nil; break }
            guard result == 0 else { throw RootStoreInitializationFailure.ownershipLost }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw RootStoreInitializationFailure.timeout }
            Thread.sleep(forTimeInterval: 0.05)
        }
        guard status == 0 else { throw RootStoreInitializationFailure.unavailable }
        var current = stat()
        guard lstat(plan.stage, &current) == 0, current.st_dev == original.st_dev,
              current.st_ino == original.st_ino, current.st_mode & S_IFMT == S_IFDIR,
              current.st_uid == plan.base.uid, current.st_mode & 0o077 == 0 else {
            throw RootStoreInitializationFailure.invalidReceipt
        }
        return VerifiedStagedVault(plan: plan, info: current)
    }
}
