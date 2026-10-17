// Root service host for the isolated broker's native owner channel. A trusted
// supervisor supplies the already-validated peer policy and private backend;
// this class does not install a service or obtain/store a vault key.
import Foundation
import Darwin

final class OwnerGatewayHost {
    static let serviceName = "com.fainir.accountaccess.broker.owner"
    private let listener: NSXPCListener
    private let delegate: OwnerGatewayListener
    private let lock = NSLock()
    private var started = false
    private var stopped = false

    init(owner: OwnerGatewayPeer, backend: OwnerGatewayBackend) throws {
        guard getuid() == 0, geteuid() == 0, owner.uid != 0 else { throw OwnerGatewayError.invalidPolicy }
        delegate = OwnerGatewayListener(peer: owner) {
            OwnerGatewaySession(backend: backend, verifier: RootOwnerSetupProofVerifier())
        }
        listener = NSXPCListener(machServiceName: Self.serviceName)
        listener.delegate = delegate
    }
    func start() throws {
        lock.lock(); defer { lock.unlock() }
        guard !started, !stopped else { throw OwnerGatewayError.invalidPolicy }
        started = true
        listener.resume()
    }
    func stop() {
        lock.lock(); let alreadyStopped = stopped; stopped = true; lock.unlock()
        if !alreadyStopped { delegate.stop(); listener.invalidate() }
    }
    func invalidateSessions() { delegate.invalidateSessions() }
    deinit { stop() }
}
