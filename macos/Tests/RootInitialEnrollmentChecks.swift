// Real fresh System-key creation and production setup components in disposable
// CI. Positive setup approval is synthetic; production-verifier denial is real.
import Foundation
import Darwin

#if !ACCOUNT_ACCESS_ROOT_KEY_CHECKS || !ACCOUNT_ACCESS_GATEWAY_CHECKS
#error("Initial enrollment acceptance is CI-only")
#endif

enum RootAgentSetupFixtureFailure: String, Error {
    case prepareProcess = "client_prepare_process_failed"
    case installProcess = "client_install_process_failed"
    case response = "client_probe_response_invalid"
    case enrollment = "client_enrollment_response_invalid"
}

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
        let python = root.appendingPathComponent("runtime/bin/python")
        _ = try WorkerLaunchPaths.protected(python.path)
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
            guard process.terminationStatus == 0 else {
                throw phase == "prepare" ? RootAgentSetupFixtureFailure.prepareProcess : RootAgentSetupFixtureFailure.installProcess
            }
            guard output.count < 8192,
                  let result = try JSONSerialization.jsonObject(with: output) as? [String: Any] else { throw RootAgentSetupFixtureFailure.response }
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
        guard enrolled.0 == 200, enrollmentResult?["client_id"] as? String == clientID else { throw RootAgentSetupFixtureFailure.enrollment }
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
        // Only this disposable fixture's own publication metadata is changed.
        // Simulate a mount-device renumbering while retaining both inode values;
        // the production coordinator must refuse before key/worker startup.
        let journalPlan = URL(fileURLWithPath: plan.stage).deletingLastPathComponent()
            .appendingPathComponent(".enrollment-" + plan.enrollment + ".publication/plan.json")
        let originalRecord = try Data(contentsOf: journalPlan)
        let journalVolume = journalPlan.deletingLastPathComponent().appendingPathComponent(RootStoreVolumeBinding.name)
        let originalVolume = try Data(contentsOf: journalVolume)
        // Remove only this fixture's binding to exercise an unbound legacy
        // store. Production never deletes a binding to make a record pass.
        try FileManager.default.removeItem(at: journalVolume)
        var renumbered = try JSONSerialization.jsonObject(with: originalRecord) as! [String: Any]
        for name in ["stagedIdentity", "emptyIdentity"] {
            var identity = renumbered[name] as! [String: Any]
            identity["device"] = (identity["device"] as! NSNumber).int64Value + 1
            renumbered[name] = identity
        }
        try JSONSerialization.data(withJSONObject: renumbered).write(to: journalPlan)
        do {
            defer {
                try! originalRecord.write(to: journalPlan)
                try! originalVolume.write(to: journalVolume, options: .withoutOverwriting)
                precondition(chmod(journalVolume.path, 0o600) == 0)
            }
            let (movedWorker, moved) = try make()
            defer { try? moved.stop() }
            try moved.start()
            checks["changed_publication_device_remains_refused_before_worker"] = moved.state == .needsRepair
                && movedWorker.pid == nil && !moved.workInProgressForChecks
            let reply = try moved.request(OwnerGatewayRoute("owner/state", body: nil))
            let state = try JSONSerialization.jsonObject(with: reply.1) as? [String: Any]
            let setup = state?["vault_setup"] as? [String: Any]
            checks["changed_publication_device_has_closed_diagnostic"] = setup?["diagnostic"] as? [String: String]
                == ["checkpoint": "stage_status", "reason": "vault_publication_device_number_changed"]
        }
        // A valid historical persistent-volume binding permits a changed
        // device number while keeping the publication record bytes unchanged.
        // This fixture simulates the old device value, not a physical remount.
        let historicalRecord = try JSONSerialization.data(withJSONObject: renumbered)
        let parentFD = open(journalPlan.deletingLastPathComponent().deletingLastPathComponent().path,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentFD >= 0 else { throw RootPublicationFailure.unavailable }
        let measured = try RootStoreVolumeBinding.capture(parentFD)
        Darwin.close(parentFD)
        let historical = RootStoreVolumeBinding.Context(device: measured.device + 1,
            parentInode: measured.parentInode, volumeUUID: measured.volumeUUID)
        let historicalBinding = try RootStoreVolumeBinding(record: historicalRecord, context: historical).encoded()
        try historicalRecord.write(to: journalPlan)
        try historicalBinding.write(to: journalVolume)
        do {
            defer { try! originalRecord.write(to: journalPlan); try! originalVolume.write(to: journalVolume) }
            let (boundWorker, bound) = try make()
            defer { try? bound.stop() }
            try bound.start()
            try wait(bound)
            checks["persistent_volume_binding_reopens_simulated_device_change"] = bound.state == .ready
                && boundWorker.state == .running && boundWorker.pid != nil
            checks["persistent_volume_reopen_preserves_original_registration"] = try Data(contentsOf: journalPlan) == historicalRecord
                && Data(contentsOf: journalVolume) == historicalBinding
            try bound.stop()
            var substituted = try JSONSerialization.jsonObject(with: historicalBinding) as! [String: Any]
            substituted["volumeUUID"] = UUID().uuidString.lowercased()
            try JSONSerialization.data(withJSONObject: substituted, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: journalVolume)
            let (foreignWorker, foreign) = try make()
            defer { try? foreign.stop() }
            try foreign.start()
            checks["different_persistent_volume_refused_before_worker"] = foreign.state == .needsRepair
                && foreignWorker.pid == nil && !foreign.workInProgressForChecks
        }
        try provider.removeFixture(plan.vault)
        removed = true
        let (brokenWorker, broken) = try make()
        defer { try? broken.stop() }
        try broken.start()
        try wait(broken)
        checks["missing_key_after_publication_requires_repair"] = broken.state == .needsRepair && brokenWorker.pid == nil
        checks["published_vault_key_never_recreated"] = try missing()
        checks["repair_state_keeps_native_owner_reads_available"] = try broken.request(OwnerGatewayRoute("owner/state", body: nil)).0 == 200
        let missingHealth = try broken.request(OwnerGatewayRoute("owner/health", body: nil))
        let missingState = try JSONSerialization.jsonObject(with: missingHealth.1) as? [String: Any]
        checks["missing_key_has_closed_diagnostic_without_replacement"] =
            (missingState?["vault_setup"] as? [String: Any])?["diagnostic"] as? [String: String]
            == ["checkpoint": "key_access", "reason": "vault_key_missing"]
        checks["new_fixture_key_removed"] = try missing()
        return checks
    }
}
