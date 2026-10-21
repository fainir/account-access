// Only the disposable CI job may use this entry point. It runs the production
// host with a new fixture System key/store and a separately signed test client.
import Foundation
import Security
import Darwin

#if !ACCOUNT_ACCESS_ROOT_KEY_CHECKS || !ACCOUNT_ACCESS_GATEWAY_CHECKS
#error("Root coordinator acceptance is CI-only")
#endif

enum RootCoordinatorChecks {
    static func removeRule() throws {
        try OwnerAuthorizationPolicy.requireDaemon()
        guard OwnerSetupAuthorization.right == "com.fainir.accountaccess.owner-enrollment.qa" else { throw OwnerPolicyFailure.changed }
        var current: CFDictionary?
        let status = AuthorizationRightGet(OwnerSetupAuthorization.right, &current)
        if status == errAuthorizationDenied, current == nil { return }
        guard OwnerAuthorizationPolicy.trustedDefinition() else { throw OwnerPolicyFailure.changed }
        var reference: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess, let reference else {
            throw OwnerPolicyFailure.unavailable
        }
        defer { AuthorizationFree(reference, [.destroyRights]) }
        guard AuthorizationRightRemove(reference, OwnerSetupAuthorization.right) == errAuthorizationSuccess else {
            throw OwnerPolicyFailure.unavailable
        }
        var value: CFDictionary?
        guard AuthorizationRightGet(OwnerSetupAuthorization.right, &value) == errAuthorizationDenied, value == nil else {
            throw OwnerPolicyFailure.unavailable
        }
    }
    static func run(_ value: [String: Any], identity: String) throws -> Never {
        umask(0o077)
        let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
        let settings = try WorkerLaunchPaths.object(root.appendingPathComponent("root-coordinator.json").path)
        guard Set(settings.keys) == ["fixture", "owner_hash"],
              settings["fixture"] as? String == "account-access-root-coordinator-ci-v1",
              let hash = settings["owner_hash"] as? String, let bootstrapHash = value["bootstrap_hash"] as? String else {
            throw RootListenerFailure.invalid
        }
        let policy = try WorkerLaunchPaths.lexical(value["worker_launcher"])
        let plan = try MacWorkerPlan(policy: policy)
        let host = try RootBrokerHost(policy: policy, bootstrap: root.appendingPathComponent("mac-worker-bootstrap").path,
            bootstrapPeer: OwnerGatewayPeer.fixture(uid: 0, codeHash: bootstrapHash), vault: identity,
            owner: OwnerGatewayPeer.fixture(uid: plan.agentUID, codeHash: hash))
        try host.start()
        guard OwnerAuthorizationPolicy.trustedDefinition() else { throw OwnerPolicyFailure.readback }
        var replay: Int32 = -1
        guard AccountAccessActivateSocket(RootActivatedListeners.agentName, &replay) == EALREADY, replay == -1 else {
            if replay >= 0 { Darwin.close(replay) }
            throw RootListenerFailure.invalid
        }
        let ready = root.appendingPathComponent("root-coordinator-ready.json")
        var previous = Data()
        func publish() throws {
            let child = host.workerPID ?? 0
            let report: [String: Any] = ["status": "READY", "pid": Int(getpid()), "uid": Int(getuid()),
                "group": Int(getpgrp()), "worker_pid": Int(child), "worker_group": child > 0 ? Int(getpgid(child)) : 0,
                "worker_state": host.state.rawValue, "setup_policy_registered": true, "socket_activation_one_shot": true]
            let data = try JSONSerialization.data(withJSONObject: report, options: .sortedKeys)
            if data != previous {
                try data.write(to: ready, options: .atomic)
                previous = data
            }
        }
        try publish()
        let monitor = DispatchSource.makeTimerSource(queue: .main)
        monitor.schedule(deadline: .now() + 0.1, repeating: 0.1)
        monitor.setEventHandler {
            do { try publish() }
            catch { try? host.stop(); exit(78) }
        }
        monitor.resume()
        signal(SIGTERM, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termination.setEventHandler {
            do { try host.stop(); exit(0) }
            catch { exit(78) }
        }
        termination.resume()
        withExtendedLifetime((host, monitor, termination)) { RunLoop.current.run() }
        throw RootListenerFailure.unavailable
    }
}
