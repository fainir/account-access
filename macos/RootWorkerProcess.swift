// Own one existing-store worker. No service installation, enrollment, PID
// adoption or automatic restart. The system coordinator owns this lifecycle.
import Foundation
import Security
import Darwin

enum RootWorkerProcessFailure: String, Error {
    case invalidState = "worker_process_invalid_state"
    case unavailable = "worker_process_unavailable"
    case occupied = "worker_socket_already_occupied"
    case unsafeCode = "worker_bootstrap_code_rejected"
    case ownershipLost = "worker_process_ownership_lost"
    case changedSocket = "worker_socket_identity_changed"
    case paused = "worker_store_paused"
}

final class RootWorkerProcess {
    private let plan: MacWorkerPlan
    private let policy: String
    private let bootstrap: String
    private let vault: String
    private let lock = NSRecursiveLock()
    private var child: pid_t?
    private var stopped = false
    private var exitStatus: Int32?
    private var owned: [(path: String, device: dev_t, inode: ino_t)] = []

    init(policy: String, bootstrap: String, peer: OwnerGatewayPeer, vault: String) throws {
        try RootVaultKeyStore.requireDaemon()
        self.plan = try MacWorkerPlan(policy: policy)
        self.policy = policy; self.vault = vault
        self.bootstrap = try WorkerLaunchPaths.protected(bootstrap).path
        var code: SecStaticCode?
        var requirement: SecRequirement?
        guard peer.uid == 0, SecStaticCodeCreateWithPath(URL(fileURLWithPath: self.bootstrap) as CFURL, [], &code) == errSecSuccess,
              let code, SecRequirementCreateWithString(peer.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement, SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw RootWorkerProcessFailure.unsafeCode
        }
    }
    var pid: pid_t? { lock.lock(); defer { lock.unlock() }; return child }
    var lastExitStatus: Int32? { lock.lock(); defer { lock.unlock() }; return exitStatus }

    private func listener(_ path: String, mode: mode_t, group: gid_t) throws -> Int32 {
        var previous = stat()
        guard lstat(path, &previous) == -1, errno == ENOENT else { throw RootWorkerProcessFailure.occupied }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RootWorkerProcessFailure.unavailable }
        var succeeded = false
        defer { if !succeeded { Darwin.close(fd) } }
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size); address.sun_family = sa_family_t(AF_UNIX)
        let bytes = path.utf8CString.map { UInt8(bitPattern: $0) }
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path), fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else {
            throw RootWorkerProcessFailure.unavailable
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let status = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard status == 0 else { throw RootWorkerProcessFailure.unavailable }
        var info = stat()
        guard lstat(path, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFSOCK else {
            throw RootWorkerProcessFailure.unavailable
        }
        owned.append((path, info.st_dev, info.st_ino))
        guard chmod(path, mode) == 0, chown(path, 0, group) == 0, listen(fd, 128) == 0 else {
            throw RootWorkerProcessFailure.unavailable
        }
        succeeded = true
        return fd
    }

    private func spawn(_ descriptors: [Int32]) throws -> pid_t {
        var copies: [Int32] = []
        defer { copies.forEach { Darwin.close($0) } }
        for fd in descriptors {
            let copy = fcntl(fd, F_DUPFD_CLOEXEC, 10)
            guard copy >= 10 else { throw RootWorkerProcessFailure.unavailable }
            copies.append(copy)
        }
        let values = ["/bin/launchctl", "asuser", String(plan.uid), bootstrap, "--policy", policy,
                      "--bootstrap-fd", "3", "--agent-fd", "4", "--owner-fd", "5"]
        var arguments = values.map { strdup($0) }; arguments.append(nil)
        var environment = plan.environment.map { strdup($0) }; environment.append(nil)
        defer { arguments.forEach { free($0) }; environment.forEach { free($0) } }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard !arguments.dropLast().contains(where: { $0 == nil }), !environment.dropLast().contains(where: { $0 == nil }),
              posix_spawn_file_actions_init(&actions) == 0 else { throw RootWorkerProcessFailure.unavailable }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw RootWorkerProcessFailure.unavailable }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else { throw RootWorkerProcessFailure.unavailable }
        for fd in Int32(0)...2 {
            guard posix_spawn_file_actions_addinherit_np(&actions, fd) == 0 else { throw RootWorkerProcessFailure.unavailable }
        }
        for (index, fd) in copies.enumerated() {
            guard posix_spawn_file_actions_adddup2(&actions, fd, Int32(index + 3)) == 0 else { throw RootWorkerProcessFailure.unavailable }
        }
        var result: pid_t = 0
        let status = arguments.withUnsafeMutableBufferPointer { args in
            environment.withUnsafeMutableBufferPointer { env in
                posix_spawn(&result, "/bin/launchctl", &actions, &attributes, args.baseAddress!, env.baseAddress!)
            }
        }
        guard status == 0, result > 0 else { throw RootWorkerProcessFailure.unavailable }
        return result
    }

    func start() throws -> OwnerUnixBackend {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard child == nil, owned.isEmpty, !stopped, let agent = getpwuid(plan.agentUID) else {
            throw RootWorkerProcessFailure.invalidState
        }
        let agentGroup = agent.pointee.pw_gid
        let workerPolicy = try WorkerLaunchPaths.object(plan.workerPolicy)
        let state = try WorkerLaunchPaths.lexical(workerPolicy["root"])
        var pause = stat()
        if lstat(URL(fileURLWithPath: state).appendingPathComponent("service.paused").path, &pause) == 0 {
            throw RootWorkerProcessFailure.paused
        }
        guard errno == ENOENT else { throw RootWorkerProcessFailure.unavailable }
        var descriptors: [Int32] = []
        defer { descriptors.forEach { Darwin.close($0) } }
        do {
            descriptors.append(try listener(plan.agentSocket, mode: 0o660, group: agentGroup))
            descriptors.append(try listener(plan.ownerSocket, mode: 0o600, group: 0))
            let key = try RootVaultKeyStore().load(vault)
            let channel = try RootWorkerChannel(key: key)
            defer { channel.cancel() }
            let capability = try channel.withOwnerSecret { Data($0).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
            let port = Int(try WorkerLaunchPaths.integer(workerPolicy["owner_port"], maximum: 65535))
            let backend = try OwnerUnixBackend(path: plan.ownerSocket, capability: capability, port: port)
            child = try spawn([channel.readDescriptor()] + descriptors)
            try channel.transmit()
            let deadline = ProcessInfo.processInfo.systemUptime + 30
            while ProcessInfo.processInfo.systemUptime < deadline {
                var status: Int32 = 0
                let state = waitpid(child!, &status, WNOHANG)
                if state == child! { child = nil; exitStatus = status; throw RootWorkerProcessFailure.unavailable }
                guard state == 0 else { throw RootWorkerProcessFailure.ownershipLost }
                if let result = try? backend.request(OwnerGatewayRoute("owner/health", body: nil)), result.0 == 200 { return backend }
                Thread.sleep(forTimeInterval: 0.1)
            }
            throw RootWorkerProcessFailure.unavailable
        } catch {
            try stop()
            throw error
        }
    }

    func stop() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        stopped = true
        if let pid = child {
            var status: Int32 = 0
            var result = waitpid(pid, &status, WNOHANG)
            guard result == 0 || result == pid else { throw RootWorkerProcessFailure.ownershipLost }
            if result == 0 {
                // The child remains ours and unreaped; its PID cannot be reused.
                guard Darwin.kill(pid, SIGTERM) == 0 || errno == ESRCH else { throw RootWorkerProcessFailure.unavailable }
                let deadline = ProcessInfo.processInfo.systemUptime + 12
                while result == 0 && ProcessInfo.processInfo.systemUptime < deadline {
                    Thread.sleep(forTimeInterval: 0.05)
                    result = waitpid(pid, &status, WNOHANG)
                }
                if result == 0 {
                    guard Darwin.kill(pid, SIGKILL) == 0 || errno == ESRCH else { throw RootWorkerProcessFailure.unavailable }
                    result = waitpid(pid, &status, 0)
                }
                guard result == pid else { throw RootWorkerProcessFailure.ownershipLost }
            }
            child = nil
            exitStatus = status
        }
        while let item = owned.first {
            var info = stat()
            guard lstat(item.path, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFSOCK,
                  info.st_dev == item.device, info.st_ino == item.inode else { throw RootWorkerProcessFailure.changedSocket }
            guard unlink(item.path) == 0 else { throw RootWorkerProcessFailure.unavailable }
            owned.removeFirst()
        }
    }
    func poll() throws -> Bool {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard let pid = child else { return false }
        var status: Int32 = 0
        let result = waitpid(pid, &status, WNOHANG)
        if result == 0 { return true }
        guard result == pid else { throw RootWorkerProcessFailure.ownershipLost }
        child = nil; exitStatus = status
        return false
    }
    deinit { try? stop() }
}
