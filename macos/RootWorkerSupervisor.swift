// Existing-store lifecycle under a live System daemon. This does not install
// the daemon, enroll a vault or adopt a worker left by a previous daemon.
import Foundation
import Darwin

enum RootWorkerState: String { case idle, running, recovering, paused, failed, stopped }

struct WorkerRestartBudget {
    private(set) var used = 0
    mutating func nextDelay() -> TimeInterval? {
        guard used < 3 else { return nil }
        let delay = TimeInterval(1 << used)
        used += 1
        return delay
    }
    mutating func stable() { used = 0 }
}

final class RootWorkerSupervisor: OwnerGatewayBackend {
    private let policy: String
    private let bootstrap: String
    private let peer: OwnerGatewayPeer
    private let vault: String
    private let listeners: RootActivatedListeners?
    private let pausePath: String
    private let clock: () -> TimeInterval
    private let invalidateOwners: () -> Void
    private let lock = NSRecursiveLock()
    private var worker: RootWorkerProcess?
    private var backend: OwnerUnixBackend?
    private var current: RootWorkerState = .idle
    private var budget = WorkerRestartBudget()
    private var startedAt: TimeInterval = 0
    private var retryAt: TimeInterval = 0

    convenience init(policy: String, bootstrap: String, peer: OwnerGatewayPeer, vault: String,
                     listeners: RootActivatedListeners? = nil, invalidateOwners: @escaping () -> Void) throws {
        try self.init(policy: policy, bootstrap: bootstrap, peer: peer, vault: vault,
                      listeners: listeners, invalidateOwners: invalidateOwners, clock: { ProcessInfo.processInfo.systemUptime })
    }
    private init(policy: String, bootstrap: String, peer: OwnerGatewayPeer, vault: String,
                 listeners: RootActivatedListeners?, invalidateOwners: @escaping () -> Void, clock: @escaping () -> TimeInterval) throws {
        try RootVaultKeyStore.requireDaemon()
        let plan = try MacWorkerPlan(policy: policy)
        let value = try WorkerLaunchPaths.object(plan.workerPolicy)
        let root = try WorkerLaunchPaths.lexical(value["root"])
        self.policy = policy; self.bootstrap = bootstrap; self.peer = peer; self.vault = vault; self.listeners = listeners
        self.pausePath = URL(fileURLWithPath: root).appendingPathComponent("service.paused").path
        self.invalidateOwners = invalidateOwners; self.clock = clock
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS
    static func fixture(policy: String, bootstrap: String, peer: OwnerGatewayPeer, vault: String,
                        invalidateOwners: @escaping () -> Void, clock: @escaping () -> TimeInterval) throws -> RootWorkerSupervisor {
        try RootWorkerSupervisor(policy: policy, bootstrap: bootstrap, peer: peer, vault: vault,
                                 listeners: nil, invalidateOwners: invalidateOwners, clock: clock)
    }
    #endif
    var state: RootWorkerState { lock.lock(); defer { lock.unlock() }; return current }
    var pid: pid_t? { lock.lock(); defer { lock.unlock() }; return worker?.pid }
    var nativeCollectorBackend: OwnerUnixBackend? {
        lock.lock(); defer { lock.unlock() }
        guard getuid() == 0, geteuid() == 0, current == .running else { return nil }
        return backend
    }

    private func isPaused() throws -> Bool {
        var info = stat()
        // Any object, including a dangling symlink, is a stop instruction. The
        // supervisor never follows or removes it to restart automatically.
        if lstat(pausePath, &info) == 0 { return true }
        guard errno == ENOENT else { throw RootWorkerProcessFailure.unavailable }
        return false
    }
    private func discardWorker() throws {
        // Revoke the native sessions and capability before replacing a worker.
        backend = nil
        invalidateOwners()
        try worker?.stop()
        worker = nil
    }
    private func launch() throws {
        if try isPaused() { current = .paused; return }
        let next = try RootWorkerProcess(policy: policy, bootstrap: bootstrap, peer: peer, vault: vault, listeners: listeners)
        worker = next
        let ready = try next.start()
        invalidateOwners()
        backend = ready
        startedAt = clock()
        current = .running
    }
    func start() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard current == .idle else { throw RootWorkerProcessFailure.invalidState }
        do { try launch() }
        catch {
            current = .failed
            try discardWorker()
            throw error
        }
    }
    // Initial enrollment may be paused before the empty store's first worker
    // is ready. Its root-owned enrollment journal holds the durable pause.
    func pauseEnrollment() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard current != .stopped else { throw RootWorkerProcessFailure.invalidState }
        current = .paused
        try discardWorker()
    }
    func resumeEnrollment(_ approval: OwnerEnrollmentApproval) throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard current == .paused, try !isPaused() else { throw RootWorkerProcessFailure.paused }
        current = .idle
        try start()
    }
    // A trusted native scheduler calls tick; requests never restart the worker
    // or replay a write. Only an observed, reaped owned-child exit is retried.
    func tick() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard current == .running || current == .recovering else { return }
        do {
            if try isPaused() {
                current = .paused
                try discardWorker()
                return
            }
            if current == .running {
                guard let worker else { throw RootWorkerProcessFailure.invalidState }
                if try worker.poll() {
                    if clock() - startedAt >= 300 { budget.stable() }
                    return
                }
                try discardWorker()
                guard let delay = budget.nextDelay() else { current = .failed; return }
                retryAt = clock() + delay
                current = .recovering
                return
            }
            if clock() >= retryAt { try launch() }
        } catch {
            current = .failed
            try discardWorker()
            throw error
        }
    }
    func request(_ route: OwnerGatewayRoute) throws -> (Int, Data) {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        if route.path == "/owner/health", current != .stopped {
            return (200, try JSONSerialization.data(withJSONObject: ["status": "ok", "worker_status": current.rawValue]))
        }
        guard current == .running, let backend else {
            let reason = current == .paused ? "broker_worker_paused" :
                (current == .recovering ? "broker_worker_recovering" : "broker_worker_unavailable")
            return (503, OwnerGatewaySession.failure(reason))
        }
        return try backend.request(route) // exactly one attempt, including writes
    }
    func stop() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard current != .stopped else { return }
        current = .stopped
        do { try discardWorker() }
        catch { current = .failed; throw error }
    }
    deinit { try? stop() }
}
