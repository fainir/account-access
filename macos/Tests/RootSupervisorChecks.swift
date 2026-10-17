// Real System key, production store and actual owned workers in disposable CI.
// Only the monotonic clock is controlled to test backoff without slow sleeps.
import Foundation
import Darwin

#if !ACCOUNT_ACCESS_ROOT_KEY_CHECKS
#error("Root supervisor acceptance is CI-only")
#endif

enum RootSupervisorChecks {
    static func response(_ session: OwnerGatewaySession, _ path: String, body: Data? = nil) -> Int {
        var status = 0
        session.request(path, body: body) { status = $0; _ = $1 }
        return status
    }
    static func run(_ value: [String: Any], identity: String) throws -> [String: Bool] {
        guard let hash = value["bootstrap_hash"] as? String else { throw RootWorkerProcessFailure.unsafeCode }
        let policy = try WorkerLaunchPaths.lexical(value["worker_launcher"])
        let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
        let binary = root.appendingPathComponent("mac-worker-bootstrap").path
        let peer = try OwnerGatewayPeer.fixture(uid: 0, codeHash: hash)
        let plan = try MacWorkerPlan(policy: policy)
        var time: TimeInterval = 100
        var sessions: [OwnerGatewaySession] = []
        var retired = 0
        let supervisor = try RootWorkerSupervisor.fixture(policy: policy, bootstrap: binary, peer: peer, vault: identity,
            invalidateOwners: { sessions.forEach { $0.close() }; sessions.removeAll(); retired += 1 }, clock: { time })
        defer { try? supervisor.stop() }
        var checks: [String: Bool] = [:]
        try supervisor.start()
        checks["existing_store_started"] = supervisor.state == .running && supervisor.pid != nil
        let old = OwnerGatewaySession.fixture(backend: supervisor, authorize: { _ in true })
        sessions.append(old)
        var authorized = false
        old.authorizeSetup(Data(repeating: 0x41, count: 32)) { authorized = $0 }
        checks["synthetic_owner_session_active_before_crash"] = authorized && response(old, "owner/state") == 200
        func crash() throws {
            guard let pid = supervisor.pid, Darwin.kill(pid, SIGKILL) == 0 else { throw RootWorkerProcessFailure.unavailable }
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            while supervisor.state == .running && ProcessInfo.processInfo.systemUptime < deadline {
                try supervisor.tick()
                if supervisor.state == .running { Thread.sleep(forTimeInterval: 0.05) }
            }
        }
        try crash()
        checks["owned_crash_enters_backoff"] = supervisor.state == .recovering && supervisor.pid == nil
        checks["old_owner_session_retired"] = retired >= 2 && response(old, "owner/state") == 403
        let request = try OwnerGatewayRoute("owner/credential", body: Data("{\"account\":\"fixture\",\"credential\":{\"password\":\"fictional\"}}".utf8))
        checks["writes_during_backoff_not_replayed"] = try supervisor.request(request).0 == 503
        time += 0.9; try supervisor.tick()
        checks["backoff_deadline_enforced"] = supervisor.state == .recovering && supervisor.pid == nil
        time += 0.1; try supervisor.tick()
        let reopened = try supervisor.request(OwnerGatewayRoute("owner/state", body: nil))
        checks["crashed_store_reopens_automatically"] = supervisor.state == .running && reopened.0 == 200
        let fresh = OwnerGatewaySession.fixture(backend: supervisor, authorize: { _ in true })
        sessions.append(fresh)
        checks["new_session_requires_own_setup_approval"] = response(fresh, "owner/credential", body: request.body) == 403
        // Three restarts are allowed. A fourth rapid crash stays failed.
        var respected = true
        for delay: TimeInterval in [2, 4] {
            try crash()
            respected = respected && supervisor.state == .recovering && supervisor.pid == nil
            time += delay - 0.1; try supervisor.tick()
            respected = respected && supervisor.state == .recovering && supervisor.pid == nil
            time += 0.1; try supervisor.tick()
            respected = respected && supervisor.state == .running && supervisor.pid != nil
        }
        checks["successive_backoff_deadlines_enforced"] = respected
        try crash()
        checks["restart_budget_exhaustion_stops_loop"] = supervisor.state == .failed && supervisor.pid == nil
        time += 1000; try supervisor.tick()
        checks["failed_state_does_not_restart_on_tick"] = supervisor.state == .failed && supervisor.pid == nil
        try supervisor.stop()
        checks["supervisor_shutdown_cleans_listeners"] = !FileManager.default.fileExists(atPath: plan.agentSocket)
            && !FileManager.default.fileExists(atPath: plan.ownerSocket) && supervisor.state == .stopped
        let workerPolicy = try WorkerLaunchPaths.object(plan.workerPolicy)
        let state = try WorkerLaunchPaths.lexical(workerPolicy["root"])
        let pausePath = URL(fileURLWithPath: state).appendingPathComponent("service.paused").path
        let pausing = try RootWorkerSupervisor.fixture(policy: policy, bootstrap: binary, peer: peer, vault: identity,
            invalidateOwners: {}, clock: { time })
        defer { try? pausing.stop() }
        try pausing.start()
        let fd = open(pausePath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw RootWorkerProcessFailure.unavailable }
        Darwin.close(fd)
        defer { unlink(pausePath) }
        try pausing.tick()
        checks["pause_stops_running_worker"] = pausing.state == .paused && pausing.pid == nil
        time += 1000; try pausing.tick()
        checks["pause_survives_future_ticks"] = pausing.state == .paused && pausing.pid == nil
        try pausing.stop()
        let paused = try RootWorkerSupervisor.fixture(policy: policy, bootstrap: binary, peer: peer, vault: identity,
            invalidateOwners: {}, clock: { time })
        defer { try? paused.stop() }
        try paused.start()
        time += 1000; try paused.tick()
        checks["paused_start_never_launches_worker"] = paused.state == .paused && paused.pid == nil
        let health = try paused.request(OwnerGatewayRoute("owner/health", body: nil))
        let healthValue = try JSONSerialization.jsonObject(with: health.1) as? [String: String]
        checks["paused_native_health_remains_available"] = health.0 == 200 &&
            healthValue?["worker_status"] == "paused"
        checks["paused_owner_reads_do_not_start_worker"] = try paused.request(OwnerGatewayRoute("owner/state", body: nil)).0 == 503 && paused.pid == nil
        try paused.stop()
        guard unlink(pausePath) == 0 else { throw RootWorkerProcessFailure.unavailable }
        let missingID = UUID().uuidString.lowercased()
        let missing = try RootWorkerSupervisor.fixture(policy: policy, bootstrap: binary, peer: peer, vault: missingID,
            invalidateOwners: {}, clock: { time })
        defer { try? missing.stop() }
        do { try missing.start(); throw RootWorkerProcessFailure.unavailable }
        catch RootVaultKeyFailure.missing {
            time += 1000; try missing.tick()
            checks["missing_key_is_terminal_without_enrollment"] = missing.state == .failed && missing.pid == nil
        }
        do { _ = try RootVaultKeyStore().load(missingID); throw RootWorkerProcessFailure.unavailable }
        catch RootVaultKeyFailure.missing { checks["missing_key_not_recreated"] = true }
        return checks
    }
}
