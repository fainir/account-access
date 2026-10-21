// Native composition for existing stores or a fixed first-enrollment plan.
// Consumer installation, source collectors and client issuance are separate.
import Foundation

enum RootBrokerStartupPhase: String {
    case daemonContext = "host_daemon_context"
    case listeners = "socket_listeners"
    case workerSupervisor = "worker_supervisor"
    case messagesCollector = "messages_collector"
    case enrollmentPlan = "enrollment_plan"
    case gatewayInitialization = "owner_gateway_initialization"
    case ownerPolicy = "owner_policy_registration"
    case enrollmentStart = "enrollment_start"
    case workerStart = "worker_start"
    case gatewayStart = "owner_gateway_start"
}

final class RootBrokerHost {
    private final class GatewayReference { weak var host: OwnerGatewayHost? }
    private let worker: RootWorkerSupervisor
    private let gateway: OwnerGatewayHost
    private let enrollment: RootInitialEnrollment?
    private let messages: RootMessagesCollector
    private let startup: (RootBrokerStartupPhase) -> Void
    private let queue = DispatchQueue(label: "com.fainir.accountaccess.broker.lifecycle")
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private var started = false
    private var stopped = false

    convenience init(policy: String, bootstrap: String, bootstrapPeer: OwnerGatewayPeer,
         vault: String, owner: OwnerGatewayPeer, enrollmentPolicy: String? = nil,
         startup: @escaping (RootBrokerStartupPhase) -> Void = { _ in }) throws {
        try self.init(policy: policy, bootstrap: bootstrap, bootstrapPeer: bootstrapPeer,
            vault: vault, owner: owner, enrollmentPolicy: enrollmentPolicy, collector: nil, startup: startup)
    }
    private init(policy: String, bootstrap: String, bootstrapPeer: OwnerGatewayPeer,
         vault: String, owner: OwnerGatewayPeer, enrollmentPolicy: String?, collector: RootMessagesCollector?,
         startup: @escaping (RootBrokerStartupPhase) -> Void = { _ in }) throws {
        self.startup = startup
        startup(.daemonContext)
        try RootVaultKeyStore.requireDaemon()
        let reference = GatewayReference()
        startup(.listeners)
        let listeners = try RootActivatedListeners(plan: MacWorkerPlan(policy: policy))
        startup(.workerSupervisor)
        let managedWorker = try RootWorkerSupervisor(policy: policy, bootstrap: bootstrap, peer: bootstrapPeer,
            vault: vault, listeners: listeners, invalidateOwners: { reference.host?.invalidateSessions() })
        worker = managedWorker
        startup(.messagesCollector)
        messages = try collector ?? RootMessagesCollector(owner: owner)
        startup(.enrollmentPlan)
        let initialSetup = try enrollmentPolicy.map { try RootInitialEnrollment(worker: managedWorker, policy: $0,
            bootstrap: bootstrap, peer: bootstrapPeer, owner: owner.uid, workerPolicy: policy, vault: vault) }
        enrollment = initialSetup
        startup(.gatewayInitialization)
        gateway = try OwnerGatewayHost(owner: owner, backend: initialSetup ?? managedWorker)
        reference.host = gateway
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS
    // Only the fixture database/reader differs. Activation, supervision, key
    // custody, native gateway and collector scheduling use the production host.
    static func fixture(policy: String, bootstrap: String, bootstrapPeer: OwnerGatewayPeer,
                        vault: String, owner: OwnerGatewayPeer, collector: RootMessagesCollector) throws -> RootBrokerHost {
        try RootBrokerHost(policy: policy, bootstrap: bootstrap, bootstrapPeer: bootstrapPeer,
            vault: vault, owner: owner, enrollmentPolicy: nil, collector: collector)
    }
    #endif
    var workerPID: pid_t? { worker.pid }
    var state: RootWorkerState { worker.state }
    var enrollmentState: RootEnrollmentState? { enrollment?.state }
    // Run off the GUI thread. Provisioning must run in this same hosting binary
    // so authd's registrar pin matches the process that verifies owner proofs.
    func start() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard !started, !stopped else { throw RootWorkerProcessFailure.invalidState }
        started = true
        do {
            startup(.ownerPolicy)
            _ = try OwnerAuthorizationPolicy.installIfAbsent()
            if let enrollment { startup(.enrollmentStart); try enrollment.start() }
            else { startup(.workerStart); try worker.start() }
            startup(.gatewayStart)
            try gateway.start()
            let monitor = DispatchSource.makeTimerSource(queue: queue)
            monitor.schedule(deadline: .now() + 0.25, repeating: 0.25)
            monitor.setEventHandler { [weak self] in
                // The supervisor retains its fixed failed status; no error
                // text, code material or retry loop is exported or logged.
                try? self?.worker.tick()
                if let self, let backend = self.worker.nativeCollectorBackend { self.messages.poll(backend) }
            }
            timer = monitor
            monitor.resume()
        } catch {
            stopped = true
            gateway.stop()
            if let enrollment { try enrollment.stop() }
            else { try worker.stop() }
            throw error
        }
    }
    func stop() throws {
        lock.lock(); let wasStopped = stopped; stopped = true
        let monitor = timer; timer = nil; lock.unlock()
        guard !wasStopped else { return }
        monitor?.cancel()
        gateway.stop()
        if let enrollment { try enrollment.stop() }
        else { try worker.stop() }
    }
    deinit { try? stop() }
}
