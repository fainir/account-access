// Disposable-CI bridge from a real System key to the production Python reader.
import Foundation
import CryptoKit
import Darwin

#if !ACCOUNT_ACCESS_ROOT_KEY_CHECKS
#error("System-key handoff acceptance is CI-only")
#endif

enum RootKeyHandoffChecks {
    static func service(_ value: [String: Any], identity: String) throws -> [String: Bool] {
        guard let hash = value["bootstrap_hash"] as? String else { throw RootWorkerProcessFailure.unsafeCode }
        let policy = try WorkerLaunchPaths.lexical(value["worker_launcher"])
        let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
        let bootstrap = root.appendingPathComponent("mac-worker-bootstrap").path
        var checks: [String: Bool] = [:]
        let wrong = try OwnerGatewayPeer.fixture(uid: 0, codeHash: String(repeating: "0", count: 40))
        do { _ = try RootWorkerProcess(policy: policy, bootstrap: bootstrap, peer: wrong, vault: identity); throw RootWorkerProcessFailure.unavailable }
        catch RootWorkerProcessFailure.unsafeCode { checks["bootstrap_signature_mismatch_refused"] = true }
        let peer = try OwnerGatewayPeer.fixture(uid: 0, codeHash: hash)
        let plan = try MacWorkerPlan(policy: policy)
        let first = try RootWorkerProcess(policy: policy, bootstrap: bootstrap, peer: peer, vault: identity)
        defer { try? first.stop() }
        let previous = try first.start()
        let before = try previous.request(OwnerGatewayRoute("owner/state", body: nil))
        checks["enrolled_fixture_worker_started"] = before.0 == 200
        guard let pid = first.pid else { throw RootWorkerProcessFailure.unavailable }
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/ps"); process.arguments = ["-p", String(pid), "-o", "uid=,gid="]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
        try process.run(); process.waitUntilExit()
        let text = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        checks["worker_kernel_identity_verified"] = process.terminationStatus == 0 && text.split(whereSeparator: { $0.isWhitespace }).map(String.init) == [String(plan.uid), String(plan.gid)]
        try first.stop()
        checks["worker_graceful_shutdown_verified"] = first.pid == nil && first.lastExitStatus == 0
        if checks["worker_graceful_shutdown_verified"] != true {
            fputs("worker_shutdown_wait_status=\(first.lastExitStatus ?? -1)\n", stderr)
        }
        let second = try RootWorkerProcess(policy: policy, bootstrap: bootstrap, peer: peer, vault: identity)
        defer { try? second.stop() }
        let current = try second.start()
        checks["enrolled_fixture_worker_restarted"] = try current.request(OwnerGatewayRoute("owner/state", body: nil)).0 == 200
        let denied = try previous.request(OwnerGatewayRoute("owner/state", body: nil))
        checks["previous_owner_capability_refused"] = [401, 403].contains(denied.0)
        guard let killed = second.pid, Darwin.kill(killed, SIGKILL) == 0 else { throw RootWorkerProcessFailure.unavailable }
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        var alive = true
        while alive && ProcessInfo.processInfo.systemUptime < deadline {
            Thread.sleep(forTimeInterval: 0.05)
            alive = try second.poll()
        }
        checks["owned_worker_crash_reaped"] = !alive && second.pid == nil && second.lastExitStatus != 0
        try second.stop()
        let recovered = try RootWorkerProcess(policy: policy, bootstrap: bootstrap, peer: peer, vault: identity)
        defer { try? recovered.stop() }
        let restored = try recovered.start()
        checks["crashed_worker_store_recovered"] = try restored.request(OwnerGatewayRoute("owner/state", body: nil)).0 == 200
        try recovered.stop()
        checks["worker_listener_cleanup_verified"] = !FileManager.default.fileExists(atPath: plan.agentSocket)
            && !FileManager.default.fileExists(atPath: plan.ownerSocket)
        let workerPolicy = try WorkerLaunchPaths.object(plan.workerPolicy)
        let state = try WorkerLaunchPaths.lexical(workerPolicy["root"])
        let pause = URL(fileURLWithPath: state).appendingPathComponent("service.paused")
        let pausedFD = open(pause.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard pausedFD >= 0 else { throw RootWorkerProcessFailure.unavailable }
        Darwin.close(pausedFD)
        defer { unlink(pause.path) }
        let paused = try RootWorkerProcess(policy: policy, bootstrap: bootstrap, peer: peer, vault: identity)
        do { _ = try paused.start(); throw RootWorkerProcessFailure.unavailable }
        catch RootWorkerProcessFailure.paused { checks["paused_store_does_not_start_worker"] = paused.pid == nil }
        return checks
    }

    static func receive(_ value: [String: Any], stage: String) throws -> Never {
        guard getuid() == 0, geteuid() == 0, ["create", "reopen"].contains(stage) else { throw RootWorkerChannelFailure.unavailable }
        let plan = try MacWorkerPlan(policy: WorkerLaunchPaths.lexical(value["launcher"]))
        let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
        let script = try WorkerLaunchPaths.protected(root.appendingPathComponent("key-handoff-probe.py").path)
        try MacWorkerBootstrap.checkFD(3, type: S_IFIFO)
        try MacWorkerBootstrap.checkFD(5, type: S_IFSOCK)
        var info = stat()
        guard fstat(4, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_nlink == 1, info.st_size > 28, info.st_size <= 256 else { throw RootWorkerChannelFailure.unavailable }
        try MacWorkerBootstrap.dropIdentity(plan)
        try MacWorkerBootstrap.replaceImage(plan.python,
            arguments: [plan.python, "-I", "-B", script.path, "--policy", plan.workerPolicy, "--store-mode", stage], environment: plan.environment)
    }

    static func frame(_ fd: Int32, count: Int) throws -> Data {
        var value = Data()
        let deadline = ProcessInfo.processInfo.systemUptime + 25
        while value.count < count {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw RootWorkerChannelFailure.unavailable }
            var buffer = [UInt8](repeating: 0, count: count - value.count)
            let received = Darwin.recv(fd, &buffer, buffer.count, 0)
            if received < 0 && errno == EINTR { continue }
            guard received > 0 else { throw RootWorkerChannelFailure.unavailable }
            value.append(contentsOf: buffer.prefix(received))
        }
        return value
    }

    static func spawn(_ sources: [Int32], plan: MacWorkerPlan, policy: String, binary: String, stage: String) throws -> pid_t {
        var copies: [Int32] = []
        defer { copies.forEach { Darwin.close($0) } }
        for source in sources {
            let copy = fcntl(source, F_DUPFD_CLOEXEC, 10)
            guard copy >= 10 else { throw RootWorkerChannelFailure.unavailable }
            copies.append(copy)
        }
        let values = ["/bin/launchctl", "asuser", String(plan.uid), binary, "--policy", policy, "receive", stage]
        var arguments = values.map { strdup($0) }; arguments.append(nil)
        var environment = plan.environment.map { strdup($0) }; environment.append(nil)
        defer { arguments.forEach { free($0) }; environment.forEach { free($0) } }
        guard !arguments.dropLast().contains(where: { $0 == nil }),
              !environment.dropLast().contains(where: { $0 == nil }) else { throw RootWorkerChannelFailure.unavailable }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw RootWorkerChannelFailure.unavailable }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw RootWorkerChannelFailure.unavailable }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
            throw RootWorkerChannelFailure.unavailable
        }
        for fd in Int32(0)...2 {
            guard posix_spawn_file_actions_addinherit_np(&actions, fd) == 0 else { throw RootWorkerChannelFailure.unavailable }
        }
        for (index, source) in copies.enumerated() {
            guard posix_spawn_file_actions_adddup2(&actions, source, Int32(index + 3)) == 0 else {
                throw RootWorkerChannelFailure.unavailable
            }
        }
        var child: pid_t = 0
        let status = arguments.withUnsafeMutableBufferPointer { args in
            environment.withUnsafeMutableBufferPointer { env in
                posix_spawn(&child, "/bin/launchctl", &actions, &attributes, args.baseAddress!, env.baseAddress!)
            }
        }
        guard status == 0, child > 0 else { throw RootWorkerChannelFailure.unavailable }
        return child
    }

    static func run(_ value: [String: Any], policy: String, store: RootVaultKeyStore, identity: String,
                    stage: String) throws -> (checks: [String: Bool], pid: pid_t) {
        let plan = try MacWorkerPlan(policy: WorkerLaunchPaths.lexical(value["launcher"]))
        let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
        let binary = try WorkerLaunchPaths.protected(root.appendingPathComponent("root-key-checks").path)
        _ = try WorkerLaunchPaths.protected(root.appendingPathComponent("key-handoff-probe.py").path)
        let key = try store.load(identity)
        let channel = try RootWorkerChannel(key: key)
        defer { channel.cancel() }
        let encrypted = root.appendingPathComponent("control/key-canary.bin")
        let cipher = open(encrypted.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard cipher >= 0 else { throw RootWorkerChannelFailure.unavailable }
        defer { Darwin.close(cipher) }
        let sealed = try Data(contentsOf: encrypted)
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw RootWorkerChannelFailure.unavailable }
        defer { pair.filter({ $0 >= 0 }).forEach { Darwin.close($0) } }
        var timeout = timeval(tv_sec: 25, tv_usec: 0)
        var enabled: Int32 = 1
        guard fcntl(pair[0], F_SETFD, FD_CLOEXEC) == 0, fcntl(pair[1], F_SETFD, FD_CLOEXEC) == 0,
              setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0,
              setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
            throw RootWorkerChannelFailure.unavailable
        }
        // Deliberately inheritable descriptor outside the allowlist.
        guard fcntl(128, F_GETFD) == -1, errno == EBADF, dup2(cipher, 128) == 128,
              fcntl(128, F_SETFD, 0) == 0 else { throw RootWorkerChannelFailure.unavailable }
        defer { Darwin.close(128) }
        var child: pid_t? = try spawn([channel.readDescriptor(), cipher, pair[1]], plan: plan, policy: policy, binary: binary.path, stage: stage)
        let createdPID = child!
        defer {
            if let pid = child {
                var status: Int32 = 0
                // Reap/check only our child before signaling; never use a stale
                // metadata PID or adopt an unrelated process.
                if waitpid(pid, &status, WNOHANG) == 0 {
                    Darwin.kill(pid, SIGKILL)
                    _ = waitpid(pid, &status, 0)
                }
            }
        }
        Darwin.close(pair[1]); pair[1] = -1
        try channel.transmit()
        let size = try frame(pair[0], count: 4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard (1...512).contains(size),
              let receipt = try JSONSerialization.jsonObject(with: frame(pair[0], count: Int(size))) as? [String: Any],
              Set(receipt.keys) == ["status", "uid", "gid", "pid", "proof", "fd128_closed", "storage_checked", "store_mode"],
              receipt["status"] as? String == "PASSED", receipt["uid"] as? Int == Int(plan.uid),
              receipt["gid"] as? Int == Int(plan.gid), receipt["pid"] as? Int == Int(child!),
              receipt["fd128_closed"] as? Bool == true,
              receipt["storage_checked"] as? Bool == true, receipt["store_mode"] as? String == stage,
              let proof = receipt["proof"] as? String, proof.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw RootWorkerChannelFailure.unavailable
        }
        var receivedProof = Data()
        var cursor = proof.startIndex
        while cursor < proof.endIndex {
            let end = proof.index(cursor, offsetBy: 2)
            receivedProof.append(UInt8(proof[cursor..<end], radix: 16)!)
            cursor = end
        }
        let verified = try channel.withOwnerSecret { bytes -> Bool in
            let derived = HMAC<SHA256>.authenticationCode(for: Data("account-access-owner-channel-v1".utf8), using: SymmetricKey(data: Data(bytes)))
            var message = Data(("account-access-key-handoff-ci-v1" + stage).utf8); message.append(sealed)
            return HMAC<SHA256>.isValidAuthenticationCode(receivedProof, authenticating: message, using: SymmetricKey(data: Data(derived)))
        }
        guard verified else { throw RootWorkerChannelFailure.unavailable }
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-p", String(child!), "-o", "uid=,gid="]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
        try process.run(); process.waitUntilExit()
        let identityText = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard process.terminationStatus == 0, identityText.split(whereSeparator: { $0.isWhitespace }).map(String.init) == [String(plan.uid), String(plan.gid)] else {
            throw RootWorkerChannelFailure.unavailable
        }
        var ack: UInt8 = 49
        guard Darwin.send(pair[0], &ack, 1, 0) == 1 else { throw RootWorkerChannelFailure.unavailable }
        var status: Int32 = 0
        guard waitpid(child!, &status, 0) == child!, status == 0 else { throw RootWorkerChannelFailure.unavailable }
        child = nil
        var checks = ["system_key_decrypted_by_python_reader": true, "owner_entropy_receipt_verified": true,
                      "kernel_dedicated_identity_verified": true, "descriptor_allowlist_verified": true,
                      "exact_envelope_and_eof_verified": true,
                      "encrypted_store_checked": true,
                      "channel_description_redacted": String(reflecting: channel) == "<RootWorkerChannel redacted>"]
        do { try channel.transmit(); throw RootWorkerChannelFailure.unavailable }
        catch RootWorkerChannelFailure.consumed { checks["successful_channel_cannot_replay"] = true }
        let abandoned = try RootWorkerChannel(key: key)
        do { try abandoned.transmit(); throw RootWorkerChannelFailure.consumed }
        catch RootWorkerChannelFailure.unavailable { checks["missing_reader_fails_without_signal_or_fallback"] = true }
        do { try abandoned.transmit(); throw RootWorkerChannelFailure.unavailable }
        catch RootWorkerChannelFailure.consumed { checks["failed_channel_cannot_replay"] = true }
        channel.cancel()
        do { _ = try channel.withOwnerSecret { $0.count }; throw RootWorkerChannelFailure.unavailable }
        catch RootWorkerChannelFailure.consumed { checks["cancelled_channel_refuses_owner_material"] = true }
        return (checks, createdPID)
    }
}
