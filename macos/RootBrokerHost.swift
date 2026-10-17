// Native composition for a previously enrolled store. Consumer installation,
// genuine enrollment, source collectors and parent-daemon recovery are separate.
import Foundation

final class RootBrokerHost {
    private final class GatewayReference { weak var host: OwnerGatewayHost? }
    private let worker: RootWorkerSupervisor
    private let gateway: OwnerGatewayHost
    private let queue = DispatchQueue(label: "com.fainir.accountaccess.broker.lifecycle")
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private var started = false
    private var stopped = false

    init(policy: String, bootstrap: String, bootstrapPeer: OwnerGatewayPeer,
         vault: String, owner: OwnerGatewayPeer) throws {
        try RootVaultKeyStore.requireDaemon()
        let reference = GatewayReference()
        let listeners = try RootActivatedListeners(plan: MacWorkerPlan(policy: policy))
        worker = try RootWorkerSupervisor(policy: policy, bootstrap: bootstrap, peer: bootstrapPeer,
            vault: vault, listeners: listeners, invalidateOwners: { reference.host?.invalidateSessions() })
        gateway = try OwnerGatewayHost(owner: owner, backend: worker)
        reference.host = gateway
    }
    var workerPID: pid_t? { worker.pid }
    var state: RootWorkerState { worker.state }
    // Run off the GUI thread. Provisioning must run in this same hosting binary
    // so authd's registrar pin matches the process that verifies owner proofs.
    func start() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard !started, !stopped else { throw RootWorkerProcessFailure.invalidState }
        started = true
        do {
            _ = try OwnerAuthorizationPolicy.installIfAbsent()
            try worker.start()
            try gateway.start()
            let monitor = DispatchSource.makeTimerSource(queue: queue)
            monitor.schedule(deadline: .now() + 0.25, repeating: 0.25)
            monitor.setEventHandler { [weak self] in
                // The supervisor retains its fixed failed status; no error
                // text, code material or retry loop is exported or logged.
                try? self?.worker.tick()
            }
            timer = monitor
            monitor.resume()
        } catch {
            stopped = true
            gateway.stop()
            try worker.stop()
            throw error
        }
    }
    func stop() throws {
        lock.lock(); let wasStopped = stopped; stopped = true
        let monitor = timer; timer = nil; lock.unlock()
        guard !wasStopped else { return }
        monitor?.cancel()
        gateway.stop()
        try worker.stop()
    }
    deinit { try? stop() }
}
