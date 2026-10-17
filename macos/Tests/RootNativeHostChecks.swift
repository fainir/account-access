// Actual production host and System-key worker; synthetic source enrollment only.
import Foundation
import Darwin
#if !ACCOUNT_ACCESS_ROOT_KEY_CHECKS || !ACCOUNT_ACCESS_GATEWAY_CHECKS
#error("System-host SMS acceptance is CI-only")
#endif

enum RootNativeHostChecks {
    static func run(_ value: [String: Any], identity: String) throws -> Never {
        let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
        let settings = try WorkerLaunchPaths.object(root.appendingPathComponent("native-host-fixture.json").path)
        guard settings["fixture"] as? String == "account-access-native-system-browser-ci-v1",
              settings["vault_id"] as? String == identity,
              let helperHash = settings["helper_hash"] as? String,
              let ownerHash = settings["owner_hash"] as? String,
              let bootstrapHash = value["bootstrap_hash"] as? String else { throw WorkerLaunchFailure.invalidPolicy }
        let policy = root.appendingPathComponent("native-host-launcher.json").path
        let plan = try MacWorkerPlan(policy: policy)
        let collector = try RootMessagesCollector.fixture(owner: .fixture(uid: plan.agentUID, codeHash: helperHash),
            app: root.appendingPathComponent("native-messages-helper").path,
            arguments: [root.appendingPathComponent("native-host-profile.json").path,
                        root.appendingPathComponent("native-host-owner/messages.sqlite").path])
        let host = try RootBrokerHost.fixture(policy: policy, bootstrap: root.appendingPathComponent("mac-worker-bootstrap").path,
            bootstrapPeer: .fixture(uid: 0, codeHash: bootstrapHash), vault: identity,
            owner: .fixture(uid: plan.agentUID, codeHash: ownerHash), collector: collector)
        try host.start()
        guard host.state == .running, host.workerPID != nil, OwnerAuthorizationPolicy.trustedDefinition() else {
            try? host.stop(); throw RootWorkerProcessFailure.unavailable
        }
        var replay: Int32 = -1
        guard AccountAccessActivateSocket(RootActivatedListeners.agentName, &replay) == EALREADY, replay == -1 else {
            if replay >= 0 { Darwin.close(replay) }
            throw RootListenerFailure.invalid
        }
        let ready = root.appendingPathComponent("native-host-ready.json")
        let data = try JSONSerialization.data(withJSONObject: ["status": "READY", "pid": Int(getpid()),
            "worker_pid": Int(host.workerPID!), "system_key_used": true, "production_composed_host_used": true,
            "socket_activation_one_shot": true])
        try data.write(to: ready, options: .atomic)
        signal(SIGTERM, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termination.setEventHandler {
            do {
                try host.stop()
                guard host.workerPID == nil, host.state == .stopped else { throw RootWorkerProcessFailure.invalidState }
                let receipt = try JSONSerialization.data(withJSONObject: ["status": "STOPPED", "pid": Int(getpid()), "owned_worker_stopped": true])
                try receipt.write(to: root.appendingPathComponent("native-host-stopped.json"), options: .atomic)
                exit(0)
            } catch { exit(78) }
        }
        termination.resume()
        let timeout = DispatchSource.makeTimerSource(queue: .main)
        timeout.schedule(deadline: .now() + 90)
        timeout.setEventHandler { try? host.stop(); exit(78) }
        timeout.resume()
        withExtendedLifetime((host, termination, timeout)) { dispatchMain() }
    }
}
