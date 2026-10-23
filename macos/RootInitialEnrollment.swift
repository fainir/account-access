// First-store orchestration behind the pinned native owner gateway. No service
// installation, migration, source enrollment or agent-client issuance occurs.
import Foundation
import Darwin
import OSLog

enum RootEnrollmentState: String {
    case needsOwner = "needs_owner", initializing, ready, paused, needsRepair = "needs_repair", stopped
}

// Only fixed program categories leave the native daemon. In particular, never
// format an Error, keychain status, path, journal value or account identifier.
enum RootEnrollmentCheckpoint: String, CaseIterable {
    case journalDiscovery = "journal_discovery", journalValidation = "journal_validation"
    case authorization, stageStatus = "stage_status", freshState = "fresh_state"
    case initialization, keyAccess = "key_access", publication, workerStart = "worker_start"
    case pauseRestore = "pause_restore"
}

struct RootEnrollmentDiagnostic: Equatable {
    private static let logger = Logger(subsystem: "com.fainir.accountaccess.broker", category: "store-startup")
    let checkpoint: RootEnrollmentCheckpoint
    let reason: String
    init(_ checkpoint: RootEnrollmentCheckpoint, error: Error) {
        self.checkpoint = checkpoint
        switch error {
        case let value as RootPublicationFailure: reason = value.rawValue
        case let value as RootVaultKeyFailure: reason = value.rawValue
        case let value as RootVaultRecordFailure: reason = value.stage.rawValue
        case let value as RootKeychainFailure:
            switch value.operation {
            case .load: reason = "system_keychain_load_failed"
            case .enroll: reason = "system_keychain_enroll_failed"
            case .remove: reason = "system_keychain_remove_failed"
            }
        case let value as WorkerLaunchFailure: reason = value.rawValue
        case let value as RootWorkerProcessFailure: reason = value.rawValue
        case let value as RootStoreInitializationFailure: reason = value.rawValue
        case let value as RootListenerFailure: reason = value.rawValue
        case let value as RootWorkerChannelFailure: reason = value.rawValue
        default: reason = "store_startup_unavailable"
        }
    }
    var value: [String: String] { ["checkpoint": checkpoint.rawValue, "reason": reason] }
    func record() {
        Self.logger.error("Store startup refused checkpoint=\(checkpoint.rawValue, privacy: .public) reason=\(reason, privacy: .public)")
    }
}

final class RootInitialEnrollment: OwnerVaultEnrollmentBackend {
    private let worker: RootWorkerSupervisor
    private let policy: String
    private let plan: MacWorkerEnrollmentPlan
    private let bootstrap: String
    private let peer: OwnerGatewayPeer
    private let owner: uid_t
    private let queue = DispatchQueue(label: "com.fainir.accountaccess.vault.enrollment")
    private let lock = NSRecursiveLock()
    private var current: RootEnrollmentState = .needsOwner
    private var diagnostic: RootEnrollmentDiagnostic?
    private var publication: RootStorePublication?
    private var inFlight = false
    private var pendingResume: OwnerEnrollmentApproval?
    private var stopped = false
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS
    var fixtureBeforeInitialize: (() throws -> Void)?
    private var completedForChecks = 0
    var workInProgressForChecks: Bool { lock.lock(); defer { lock.unlock() }; return inFlight }
    var completedPipelinesForChecks: Int { lock.lock(); defer { lock.unlock() }; return completedForChecks }
    #endif

    init(worker: RootWorkerSupervisor, policy: String, bootstrap: String, peer: OwnerGatewayPeer,
         owner: uid_t, workerPolicy: String, vault: String) throws {
        try RootVaultKeyStore.requireDaemon()
        self.plan = try MacWorkerEnrollmentPlan(policy: policy, requireEmptyStage: false)
        let expected = try MacWorkerPlan(policy: workerPolicy)
        guard plan.base.workerPolicy == expected.workerPolicy, plan.vault == vault,
              owner == expected.agentUID else { throw WorkerLaunchFailure.invalidPolicy }
        self.worker = worker; self.policy = policy; self.bootstrap = bootstrap; self.peer = peer; self.owner = owner
    }
    var state: RootEnrollmentState { lock.lock(); defer { lock.unlock() }; return current }

    private func fail(_ error: Error, at checkpoint: RootEnrollmentCheckpoint) {
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { return }
        diagnostic = RootEnrollmentDiagnostic(checkpoint, error: error)
        current = .needsRepair
        diagnostic?.record()
    }
    // Call under lock; a ready state never carries a previous failure.
    private func setupValue() -> [String: Any] {
        var result: [String: Any] = ["status": current.rawValue]
        if current == .needsRepair, let diagnostic { result["diagnostic"] = diagnostic.value }
        return result
    }

    private func existingJournal() throws -> Bool {
        let parent = try WorkerLaunchPaths.protected(URL(fileURLWithPath: plan.stage).deletingLastPathComponent().path)
        var info = stat()
        let path = parent.appendingPathComponent(".enrollment-" + plan.enrollment + ".publication").path
        if lstat(path, &info) == -1 {
            guard errno == ENOENT else { throw RootPublicationFailure.unsafeState }
            return false
        }
        guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == 0,
              info.st_mode & 0o7777 == 0o700 else { throw RootPublicationFailure.unsafeState }
        return true
    }
    // Ordinary startup can continue only an enrollment whose owner approval
    // was already durably recorded. Missing keys for initialized data are
    // never replaced; a recorded fresh empty transaction may continue creation.
    func start() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard !stopped, current == .needsOwner else { throw RootWorkerProcessFailure.invalidState }
        var checkpoint = RootEnrollmentCheckpoint.journalDiscovery
        do {
            if try existingJournal() {
                checkpoint = .journalValidation
                let record = try RootStorePublication(policy: policy)
                if try record.isPaused() { current = .paused; return }
                checkpoint = .authorization
                guard try record.isAuthorized(owner: owner) else {
                    guard try record.phase() == .empty else { throw RootPublicationFailure.unsafeState }
                    return
                }
                checkpoint = .stageStatus
                guard try record.phase() != .incomplete else { throw RootPublicationFailure.unsafeState }
                schedule(record, approval: nil)
            } else {
                // Validate fresh state without writing a journal or touching
                // the keychain. Existing data requires migration/repair.
                checkpoint = .freshState
                _ = try MacWorkerEnrollmentPlan(policy: policy)
            }
        } catch {
            fail(error, at: checkpoint)
        }
    }
    private func schedule(_ record: RootStorePublication, approval: OwnerEnrollmentApproval?) {
        publication = record
        inFlight = true
        current = .initializing
        diagnostic = nil
        queue.async { [self] in perform(record, approval: approval) }
    }
    private func interrupted(_ record: RootStorePublication) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        if stopped { return true }
        return try record.isPaused()
    }
    private func perform(_ record: RootStorePublication, approval: OwnerEnrollmentApproval?) {
        defer {
            lock.lock()
            if current != .paused { publication = nil }
            inFlight = false
            #if ACCOUNT_ACCESS_GATEWAY_CHECKS
            completedForChecks += 1
            #endif
            let resume = pendingResume
            pendingResume = nil
            if let resume, !stopped, current == .initializing {
                do {
                    if try !record.isPaused() { schedule(record, approval: resume) }
                    else { current = .paused }
                } catch { fail(error, at: .pauseRestore) }
            }
            lock.unlock()
        }
        var checkpoint = RootEnrollmentCheckpoint.authorization
        do {
            guard try record.isAuthorized(owner: owner) else { throw RootPublicationFailure.notVerified }
            if try interrupted(record) { return }
            checkpoint = .stageStatus
            let phase = try record.phase()
            checkpoint = .keyAccess
            let store = try RootVaultKeyStore()
            if phase == .empty {
                // Verify the fixed native launcher before creating/loading a
                // key. Incomplete or published stores never enter this branch.
                checkpoint = .initialization
                let initializer = try RootStoreInitializer(policy: policy, bootstrap: bootstrap, peer: peer)
                if try interrupted(record) { return }
                checkpoint = .keyAccess
                let key: RootVaultKey
                do { key = try store.load(plan.vault) }
                catch RootVaultKeyFailure.missing { key = try store.enrollNewVault(plan.vault) }
                if try interrupted(record) { return }
                #if ACCOUNT_ACCESS_GATEWAY_CHECKS
                try fixtureBeforeInitialize?()
                if try interrupted(record) { return }
                #endif
                checkpoint = .initialization
                let receipt = try initializer.initialize(key: key)
                // Retain completed initialization even if Pause arrived while
                // the bounded child was working; never leave a reusable stage
                // dependent on an in-memory receipt that is then discarded.
                checkpoint = .publication
                try record.accept(receipt)
            } else if phase != .ready && phase != .published {
                throw RootPublicationFailure.unsafeState
            }
            if try interrupted(record) { return }
            // A missing key for ready/published data is a repair, never a
            // request for a replacement key. Verify availability before swap.
            checkpoint = .keyAccess
            _ = try store.load(plan.vault)
            checkpoint = .publication
            try record.publish()
            if try interrupted(record) { return }
            if try interrupted(record) { return }
            checkpoint = .workerStart
            if worker.state == .paused {
                guard let approval else { throw RootPublicationFailure.notVerified }
                try worker.resumeEnrollment(approval)
            } else if worker.state != .running {
                try worker.start()
            }
            checkpoint = .pauseRestore
            let journalPaused = try record.isPaused()
            lock.lock()
            let paused = journalPaused || current == .paused
            if !stopped && !paused && current == .initializing { current = .ready }
            lock.unlock()
            if paused { try worker.pauseEnrollment() }
        } catch {
            try? worker.pauseEnrollment()
            fail(error, at: checkpoint)
        }
    }
    func enroll(_ approval: OwnerEnrollmentApproval) throws -> (Int, Data) {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { return (503, OwnerGatewaySession.failure("vault_setup_stopped")) }
        if current == .ready { return (200, try response("READY")) }
        if current == .initializing { return (202, try response("INITIALIZING")) }
        guard current == .needsOwner || current == .paused else {
            return (409, OwnerGatewaySession.failure("vault_setup_repair_required"))
        }
        let record = try publication ?? RootStorePublication(policy: policy)
        guard try record.phase() != .incomplete else { throw RootPublicationFailure.unsafeState }
        try record.authorize(approval, owner: owner)
        try record.resume(approval)
        if inFlight {
            pendingResume = approval
            current = .initializing
        } else {
            schedule(record, approval: approval)
        }
        return (202, try response("INITIALIZING"))
    }
    private func response(_ status: String) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["status": status, "vault_setup": setupValue()])
    }
    func request(_ route: OwnerGatewayRoute) throws -> (Int, Data) {
        try RootVaultKeyStore.requireDaemon()
        if route.path == "/owner/vault/enroll" {
            return (403, OwnerGatewaySession.failure("owner_setup_authorization_required"))
        }
        lock.lock()
        let snapshot = current
        let setup = setupValue()
        if route.path == "/owner/stop" && !stopped && current != .needsRepair {
            defer { lock.unlock() }
            guard let body = route.body, let data = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                  data.isEmpty else { return (403, OwnerGatewaySession.failure("invalid_stop_request")) }
            let record = try publication ?? RootStorePublication(policy: policy)
            try record.pause()
            publication = record
            current = .paused
            // Do not hold up the owner channel while a bounded child/startup
            // finishes. The journal blocks further setup progress immediately.
            queue.async { [self, record] in
                lock.lock()
                let shouldPause = !stopped && current == .paused && ((try? record.isPaused()) == true)
                lock.unlock()
                if shouldPause { try? worker.pauseEnrollment() }
            }
            return (200, try response(inFlight ? "PAUSING" : "PAUSED"))
        }
        lock.unlock()
        if route.path == "/owner/health" {
            let workerStatus = snapshot == .ready ? worker.state.rawValue : snapshot.rawValue
            let data = try JSONSerialization.data(withJSONObject: ["status": "ok", "worker_status": workerStatus,
                "vault_setup": setup])
            return (200, data)
        }
        if snapshot == .ready {
            return try worker.request(route)
        }
        if route.path == "/owner/state" {
            let data = try JSONSerialization.data(withJSONObject: ["status": "NEEDS_USER", "accounts": [],
                "vault_setup": setup])
            return (200, data)
        }
        return (503, OwnerGatewaySession.failure("vault_setup_required"))
    }
    func stop() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); stopped = true; current = .stopped; lock.unlock()
        queue.sync {} // Drain the one bounded initialization operation.
        lock.lock(); publication = nil; lock.unlock()
        try worker.stop()
    }
}
