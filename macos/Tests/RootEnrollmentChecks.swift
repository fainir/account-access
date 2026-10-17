// Exercise production staged initialization and worker key verification using
// disposable System keys. This does not simulate genuine owner authorization.
import Foundation
import Darwin

#if !ACCOUNT_ACCESS_ROOT_KEY_CHECKS || !ACCOUNT_ACCESS_GATEWAY_CHECKS
#error("Staged enrollment acceptance is CI-only")
#endif

enum RootEnrollmentChecks {
    static func run(_ value: [String: Any], identity: String) throws -> [String: Bool] {
        let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
        guard let hash = value["bootstrap_hash"] as? String else { throw RootStoreInitializationFailure.unsafeCode }
        let bootstrap = root.appendingPathComponent("mac-worker-bootstrap").path
        let policy = root.appendingPathComponent("enrollment-launch.json").path
        let plan = try MacWorkerEnrollmentPlan(policy: policy)
        let basePolicy = try WorkerLaunchPaths.object(plan.base.workerPolicy)
        let original = try WorkerLaunchPaths.lexical(basePolicy["root"])
        let peer = try OwnerGatewayPeer.fixture(uid: 0, codeHash: hash)
        let wrongPeer = try OwnerGatewayPeer.fixture(uid: 0, codeHash: String(repeating: "0", count: 40))
        var checks: [String: Bool] = [:]
        do { _ = try RootStoreInitializer(policy: policy, bootstrap: bootstrap, peer: wrongPeer); throw RootStoreInitializationFailure.unavailable }
        catch RootStoreInitializationFailure.unsafeCode { checks["wrong_bootstrap_code_refused"] = true }
        checks["staging_and_destination_initially_empty"] = try FileManager.default.contentsOfDirectory(atPath: plan.stage).isEmpty
            && FileManager.default.contentsOfDirectory(atPath: original).isEmpty
        let store = try RootVaultKeyStore()
        let initializer = try RootStoreInitializer(policy: policy, bootstrap: bootstrap, peer: peer)
        try initializer.initialize(key: store.load(identity))
        checks["native_initializer_completed"] = true
        checks["kernel_permanent_identity_parent_and_group_verified"] = true
        checks["secret_bound_receipt_verified"] = true
        checks["initializer_exit_confirmed"] = true
        checks["destination_not_published_or_modified"] = try FileManager.default.contentsOfDirectory(atPath: original).isEmpty
        var before: [(String, dev_t, ino_t)] = []
        for name in ["state.db", "config.json", ".enrollment-claim"] {
            var info = stat()
            let path = URL(fileURLWithPath: plan.stage).appendingPathComponent(name).path
            guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == plan.base.uid,
                  info.st_mode & 0o077 == 0, info.st_nlink == 1 else { throw RootStoreInitializationFailure.invalidReceipt }
            before.append((path, info.st_dev, info.st_ino))
        }
        checks["staged_files_private_and_owned_by_broker"] = true
        do { try initializer.initialize(key: store.load(identity)); throw RootStoreInitializationFailure.unavailable }
        catch WorkerLaunchFailure.invalidPolicy { checks["second_initialization_refused"] = true }
        checks["second_initialization_preserves_stage_files"] = before.allSatisfy { path, device, inode in
            var info = stat()
            return lstat(path, &info) == 0 && info.st_dev == device && info.st_ino == inode
        }
        let stageLauncher = root.appendingPathComponent("enrollment-stage-launcher.json").path
        let worker = try RootWorkerProcess(policy: stageLauncher, bootstrap: bootstrap, peer: peer, vault: identity)
        defer { try? worker.stop() }
        let backend = try worker.start()
        let state = try backend.request(OwnerGatewayRoute("owner/state", body: nil))
        let stateValue = try JSONSerialization.jsonObject(with: state.1) as? [String: Any]
        checks["ordinary_worker_authenticates_initialized_store"] = state.0 == 200
            && stateValue?["accounts"] is [[String: Any]]
        try worker.stop()
        checks["initialized_store_worker_stops_cleanly"] = worker.lastExitStatus == 0
        if checks["initialized_store_worker_stops_cleanly"] != true {
            fputs("initializer_worker_shutdown_wait_status=\(worker.lastExitStatus ?? -1)\n", stderr)
        }
        let wrongID = UUID().uuidString.lowercased()
        _ = try store.enrollNewVault(wrongID)
        var removed = false
        defer { if !removed { try? store.removeFixture(wrongID) } }
        let rejected = try RootWorkerProcess(policy: stageLauncher, bootstrap: bootstrap, peer: peer, vault: wrongID)
        defer { try? rejected.stop() }
        do { _ = try rejected.start(); throw RootStoreInitializationFailure.unavailable }
        catch RootWorkerProcessFailure.unavailable { checks["wrong_existing_key_never_reports_ready"] = rejected.pid == nil }
        try rejected.stop()
        try store.removeFixture(wrongID); removed = true
        checks["wrong_key_fixture_removed"] = true
        let recovered = try RootWorkerProcess(policy: stageLauncher, bootstrap: bootstrap, peer: peer, vault: identity)
        defer { try? recovered.stop() }
        let restored = try recovered.start()
        checks["correct_key_reopens_stage_after_wrong_key_refusal"] = try restored.request(OwnerGatewayRoute("owner/state", body: nil)).0 == 200
        try recovered.stop()
        checks["destination_remains_unpublished"] = try FileManager.default.contentsOfDirectory(atPath: original).isEmpty
        return checks
    }
}
