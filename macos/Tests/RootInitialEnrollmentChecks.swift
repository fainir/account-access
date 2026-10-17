// Real fresh System-key creation and production setup components in disposable
// CI. Positive setup approval is synthetic; production-verifier denial is real.
import Foundation
import Darwin

#if !ACCOUNT_ACCESS_ROOT_KEY_CHECKS || !ACCOUNT_ACCESS_GATEWAY_CHECKS
#error("Initial enrollment acceptance is CI-only")
#endif

enum RootInitialEnrollmentChecks {
    static func run(_ value: [String: Any]) throws -> [String: Bool] {
        let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
        guard let hash = value["bootstrap_hash"] as? String else { throw WorkerLaunchFailure.invalidPolicy }
        let policy = root.appendingPathComponent("first-enrollment-launch.json").path
        let launcher = root.appendingPathComponent("first-enrollment-base-launcher.json").path
        let plan = try MacWorkerEnrollmentPlan(policy: policy)
        let binary = root.appendingPathComponent("mac-worker-bootstrap").path
        let peer = try OwnerGatewayPeer.fixture(uid: 0, codeHash: hash)
        let provider = try RootVaultKeyStore()
        var removed = false
        defer { if !removed { try? provider.removeFixture(plan.vault) } }
        func make() throws -> (RootWorkerSupervisor, RootInitialEnrollment) {
            let worker = try RootWorkerSupervisor(policy: launcher, bootstrap: binary, peer: peer,
                vault: plan.vault, invalidateOwners: {})
            let setup = try RootInitialEnrollment(worker: worker, policy: policy, bootstrap: binary,
                peer: peer, owner: plan.base.agentUID, workerPolicy: launcher, vault: plan.vault)
            return (worker, setup)
        }
        func missing() throws -> Bool {
            do { _ = try provider.load(plan.vault); return false }
            catch RootVaultKeyFailure.missing { return true }
        }
        func request(_ session: OwnerGatewaySession, _ name: String, body: Data? = nil) -> (Int, Data) {
            var result = (0, Data())
            session.request(name, body: body) { result = ($0, $1) }
            return result
        }
        func wait(_ setup: RootInitialEnrollment) throws {
            let deadline = ProcessInfo.processInfo.systemUptime + 90
            while setup.workInProgressForChecks && ProcessInfo.processInfo.systemUptime < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            guard !setup.workInProgressForChecks else { throw RootStoreInitializationFailure.timeout }
        }
        let body = Data("{}".utf8)
        var checks: [String: Bool] = [:]
        let (firstWorker, first) = try make()
        defer { try? first.stop() }
        try first.start()
        checks["fresh_start_waits_for_owner_without_worker"] = first.state == .needsOwner && firstWorker.pid == nil
        checks["fresh_start_does_not_create_system_key"] = try missing()
        let session = OwnerGatewaySession(backend: first, verifier: RootOwnerSetupProofVerifier())
        defer { session.close() }
        let state = request(session, "owner/state")
        let decoded = try JSONSerialization.jsonObject(with: state.1) as? [String: Any]
        checks["unenrolled_owner_state_available"] = state.0 == 200 && (decoded?["accounts"] as? [Any])?.isEmpty == true
        checks["unenrolled_health_available"] = request(session, "owner/health").0 == 200
        checks["ordinary_route_cannot_enroll"] = try first.request(OwnerGatewayRoute("owner/vault/enroll", body: body)).0 == 403
        checks["unapproved_session_cannot_enroll"] = request(session, "owner/vault/enroll", body: body).0 == 403
        var accepted = true
        session.authorizeSetup(Data(repeating: 0x00, count: 32)) { accepted = $0 }
        checks["real_setup_verifier_rejects_invalid_owner_proof"] = !accepted
        checks["failed_owner_proof_does_not_create_key"] = try request(session, "owner/vault/enroll", body: body).0 == 403 && missing()
        checks["pause_before_approval_does_not_create_key"] = try request(session, "owner/stop", body: body).0 == 200
            && first.state == .paused && missing()
        try first.stop()
        let (worker, setup) = try make()
        defer { try? setup.stop() }
        try setup.start()
        checks["initial_setup_pause_survives_reopening"] = setup.state == .paused && worker.pid == nil
        checks["paused_start_keeps_system_key_absent"] = try missing()
        let approved = OwnerGatewaySession.fixture(backend: setup, authorize: { $0 == Data(repeating: 0x46, count: 32) })
        defer { approved.close() }
        let entered = DispatchSemaphore(value: 0), proceed = DispatchSemaphore(value: 0)
        setup.fixtureBeforeInitialize = {
            entered.signal()
            guard proceed.wait(timeout: .now() + 20) == .success else { throw RootStoreInitializationFailure.timeout }
        }
        approved.authorizeSetup(Data(repeating: 0x46, count: 32)) { accepted = $0 }
        guard accepted else { throw RootPublicationFailure.notVerified }
        checks["approved_native_enrollment_starts_asynchronously"] = request(approved, "owner/vault/enroll", body: body).0 == 202
        guard entered.wait(timeout: .now() + 30) == .success else { throw RootStoreInitializationFailure.timeout }
        let pausing = OwnerGatewaySession(backend: setup, verifier: RootOwnerSetupProofVerifier())
        defer { pausing.close() }
        checks["pause_during_initialization_stops_progress"] = request(pausing, "owner/stop", body: body).0 == 200
            && setup.state == .paused && worker.pid == nil
        checks["paused_enrollment_cannot_resume_without_approval"] = request(pausing, "owner/vault/enroll", body: body).0 == 403
        guard request(approved, "owner/vault/enroll", body: body).0 == 202 else { throw RootPublicationFailure.notVerified }
        proceed.signal()
        try wait(setup)
        checks["approved_inflight_resume_does_not_duplicate_pipeline"] = setup.state == .ready && setup.completedPipelinesForChecks == 1
        checks["owner_approved_pipeline_reaches_actual_worker"] = setup.state == .ready && worker.state == .running && worker.pid != nil
        checks["new_vault_key_confirmed_in_system_keychain"] = try RootVaultKeyChecks.confirmSystemRecord(provider.load(plan.vault), identity: plan.vault)
        checks["enrolled_owner_state_reaches_published_store"] = request(approved, "owner/state").0 == 200
        checks["completed_enrollment_is_idempotent"] = request(approved, "owner/vault/enroll", body: body).0 == 200
        // An ordinary fixture owner prepares its own client files. Only the
        // authenticated native session can enroll the chosen digest in the worker.
        guard let agent = getpwuid(plan.base.agentUID) else { throw RootPublicationFailure.notVerified }
        let agentGroup = agent.pointee.pw_gid
        let agentHome = root.appendingPathComponent("portable-owner-home")
        try FileManager.default.createDirectory(at: agentHome, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        guard chown(agentHome.path, plan.base.agentUID, agentGroup) == 0 else { throw RootPublicationFailure.notVerified }
        let probe = try WorkerLaunchPaths.protected(root.appendingPathComponent("agent-setup-probe.py").path)
        let python = try WorkerLaunchPaths.protected(root.appendingPathComponent("runtime/bin/python").path)
        func ownerProbe(_ phase: String) throws -> [String: Any] {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            process.arguments = ["-n", "-u", "#" + String(plan.base.agentUID), "-g", "#" + String(agentGroup), "--",
                "/usr/bin/env", "GITHUB_ACTIONS=true", "HOME=" + agentHome.path,
                python.path, "-I", "-B", probe.path, "--prefix", root.path, "--socket", plan.base.agentSocket, phase]
            process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GITHUB_ACTIONS": "true", "HOME": agentHome.path]
            let pipe = Pipe(); process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice; process.standardInput = FileHandle.nullDevice
            try process.run()
            let limit = Date().addingTimeInterval(50)
            while process.isRunning && Date() < limit { Thread.sleep(forTimeInterval: 0.02) }
            guard !process.isRunning else { process.terminate(); throw RootPublicationFailure.notVerified }
            let output = pipe.fileHandleForReading.readDataToEndOfFile()
            guard process.terminationStatus == 0, output.count < 8192,
                  let result = try JSONSerialization.jsonObject(with: output) as? [String: Any] else { throw RootPublicationFailure.notVerified }
            return result
        }
        let prepared = try ownerProbe("prepare")
        guard prepared["status"] as? String == "PREPARED", let clientID = prepared["client_id"] as? String else { throw RootPublicationFailure.notVerified }
        let tokenPath = agentHome.appendingPathComponent("Library/Application Support/Account Access/client-v1/token")
        let token = try String(contentsOf: tokenPath, encoding: .ascii)
        let clientBody = try JSONSerialization.data(withJSONObject: ["token": token])
        checks["unapproved_native_client_enrollment_refused"] = request(pausing, "owner/client/enroll", body: clientBody).0 == 403
        let enrolled = request(approved, "owner/client/enroll", body: clientBody)
        let enrollmentResult = try JSONSerialization.jsonObject(with: enrolled.1) as? [String: Any]
        checks["approved_owner_client_enrollment_reaches_worker"] = enrolled.0 == 200 && enrollmentResult?["client_id"] as? String == clientID
        checks["owner_client_enrollment_is_idempotent"] = request(approved, "owner/client/enroll", body: clientBody).1 == enrolled.1
        checks["client_enrollment_reply_omits_capability"] = !String(decoding: enrolled.1, as: UTF8.self).contains(token)
        let changedClient = try JSONSerialization.data(withJSONObject: ["token": String(repeating: "Z", count: 43)])
        checks["different_client_cannot_replace_existing_enrollment"] = request(approved, "owner/client/enroll", body: changedClient).0 == 403
        let clientInstalled = try ownerProbe("install")
        guard clientInstalled["status"] as? String == "PASSED", let clientChecks = clientInstalled["checks"] as? [String: Bool] else {
            throw RootPublicationFailure.notVerified
        }
        checks.merge(clientChecks) { _, new in new }
        let receipt = try JSONSerialization.data(withJSONObject: ["client_id": clientID, "hosts": ["codex", "claude"]])
        let confirmed = request(approved, "owner/client/installed", body: receipt)
        checks["owner_client_installation_receipt_accepted"] = confirmed.0 == 200

        checks["initialized_pause_keeps_owner_state_available"] = request(pausing, "owner/stop", body: body).0 == 200
            && setup.state == .paused && request(pausing, "owner/state").0 == 200
        checks["initialized_resume_requires_owner_approval"] = request(pausing, "owner/vault/enroll", body: body).0 == 403
        guard request(approved, "owner/vault/enroll", body: body).0 == 202 else { throw RootPublicationFailure.notVerified }
        try wait(setup)
        checks["immediate_initialized_resume_preserves_worker"] = setup.state == .ready && worker.state == .running
            && worker.pid != nil && setup.completedPipelinesForChecks == 2
        try setup.stop()
        let (reopenedWorker, reopened) = try make()
        defer { try? reopened.stop() }
        try reopened.start()
        try wait(reopened)
        checks["authorized_published_setup_reopens_without_new_approval"] = reopened.state == .ready
            && reopenedWorker.state == .running && reopenedWorker.pid != nil
        let reopenedState = try JSONSerialization.jsonObject(with: reopened.request(OwnerGatewayRoute("owner/state", body: nil)).1) as? [String: Any]
        let restoredClient = reopenedState?["managed_client"] as? [String: Any]
        checks["enrolled_client_survives_worker_reopening"] = restoredClient?["status"] as? String == "INSTALLED"
            && restoredClient?["client_id"] as? String == clientID
        try reopened.stop()
        try provider.removeFixture(plan.vault)
        removed = true
        let (brokenWorker, broken) = try make()
        defer { try? broken.stop() }
        try broken.start()
        try wait(broken)
        checks["missing_key_after_publication_requires_repair"] = broken.state == .needsRepair && brokenWorker.pid == nil
        checks["published_vault_key_never_recreated"] = try missing()
        checks["repair_state_keeps_native_owner_reads_available"] = try broken.request(OwnerGatewayRoute("owner/state", body: nil)).0 == 200
        checks["new_fixture_key_removed"] = try missing()
        return checks
    }
}
