// Synthetic keychain tests in a disposable root launchd context only. The
// probe uses an explicit System reference to avoid a false user-keychain miss.
import Foundation
import Security
import CryptoKit
import Darwin

@main struct RootVaultKeyChecks {
    // Independently target System rather than relying on the daemon's default
    // search list. This prevents a wrong-keychain miss from becoming denial
    // evidence. The deprecated open call is confined to this CI fixture.
    static func systemQuery(_ identity: String) throws -> [String: Any] {
        guard AccountAccessDisableKeychainInteraction() else { throw RootVaultKeyFailure.unavailable }
        var system: SecKeychain?
        let status = SecKeychainOpen("/Library/Keychains/System.keychain", &system)
        guard status == errSecSuccess, let system else { throw RootKeychainFailure(operation: .load, status: status) }
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: RootVaultKeyStore.service, kSecAttrAccount as String: "vault-" + identity,
                kSecUseDataProtectionKeychain as String: false, kSecAttrSynchronizable as String: false,
                kSecMatchSearchList as String: [system], kSecMatchLimit as String: kSecMatchLimitOne,
                kSecReturnData as String: true]
    }
    static func confirmSystemRecord(_ key: RootVaultKey, identity: String) throws -> Bool {
        let query = try systemQuery(identity)
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw RootKeychainFailure(operation: .load, status: status) }
        guard var value = result as? Data, value.count == 32 else { throw RootVaultRecordFailure(.data, result: result) }
        defer { value.resetBytes(in: 0..<value.count) }
        return try key.withUnsafeKey { Data($0) == value }
    }
    static func main() {
        var report: [String: Any] = ["status": "FAILED", "reason": "root_key_checks_failed"]
        var output: URL?
        var checkpoint = "policy"
        do {
            guard (CommandLine.arguments.count == 4 || (CommandLine.arguments.count == 5 && CommandLine.arguments[3] == "receive")),
                  CommandLine.arguments[1] == "--policy" else {
                throw RootVaultKeyFailure.invalidIdentity
            }
            let path = CommandLine.arguments[2]
            guard path.hasPrefix("/Library/PrivilegedHelperTools/account-access-worker-qa-") else {
                throw RootVaultKeyFailure.invalidIdentity
            }
            let value = try WorkerLaunchPaths.object(path)
            guard Set(value.keys) == ["fixture", "vault_id", "root", "launcher", "worker_launcher", "bootstrap_hash"],
                  value["fixture"] as? String == "account-access-system-key-ci-v1",
                  let identity = value["vault_id"] as? String else { throw RootVaultKeyFailure.invalidIdentity }
            let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
            let mode = CommandLine.arguments[3]
            guard ["create", "reopen", "unprivileged", "remove", "handoff", "supervisor", "receive", "coordinator", "coordinator-cleanup", "initializer", "initial-setup", "initial-setup-cleanup"].contains(mode) else { throw RootVaultKeyFailure.invalidIdentity }
            if mode == "receive" {
                guard CommandLine.arguments.count == 5 else { throw RootVaultKeyFailure.invalidIdentity }
                try RootKeyHandoffChecks.receive(value, stage: CommandLine.arguments[4])
            }
            output = root.appendingPathComponent("key-" + mode + ".json")
            var checks: [String: Bool] = [:]
            let marker = Data("account-access-system-key-canary-v1".utf8)
            let canary = root.appendingPathComponent("control/key-canary.bin")
            if mode == "unprivileged" {
                guard getuid() != 0 else { throw RootVaultKeyFailure.daemonRequired }
                checks["provider_refused"] = (try? RootVaultKeyStore()) == nil
                let query = try systemQuery(identity)
                var result: CFTypeRef?
                let status = SecItemCopyMatching(query as CFDictionary, &result)
                checks["direct_system_item_read_denied"] = [errSecAuthFailed, errSecInteractionNotAllowed].contains(status) && result == nil
                report = ["status": checks.values.allSatisfy({ $0 }) ? "PASSED" : "FAILED", "checks": checks,
                          "pid": Int(getpid()), "uid": Int(getuid()), "probe_status": Int(status)]
                print(String(data: try JSONSerialization.data(withJSONObject: report), encoding: .utf8)!)
                exit(checks.values.allSatisfy({ $0 }) ? 0 : 1)
            }
            guard getuid() == 0, geteuid() == 0 else { throw RootVaultKeyFailure.daemonRequired }
            let store = try RootVaultKeyStore()
            checkpoint = "context"
            checks["system_daemon_context_verified"] = true
            var limit = rlimit()
            checks["provider_disabled_core_dumps"] = getrlimit(RLIMIT_CORE, &limit) == 0 && limit.rlim_cur == 0 && limit.rlim_max == 0
            if mode == "initial-setup" {
                checkpoint = "native_initial_enrollment"
                checks = try RootInitialEnrollmentChecks.run(value)
            } else if mode == "initial-setup-cleanup" {
                let plan = try MacWorkerEnrollmentPlan(policy: root.appendingPathComponent("first-enrollment-launch.json").path, requireEmptyStage: false)
                do { try store.removeFixture(plan.vault) }
                catch let error as RootKeychainFailure where error.status == errSecItemNotFound { }
                checks["initial_setup_fixture_key_removed"] = true
            } else if mode == "initializer" {
                checkpoint = "native_staged_initializer"
                checks = try RootEnrollmentChecks.run(value, identity: identity)
            } else if mode == "coordinator" {
                checkpoint = "native_coordinator"
                try RootCoordinatorChecks.run(value, identity: identity)
            } else if mode == "coordinator-cleanup" {
                checkpoint = "coordinator_policy_cleanup"
                try RootCoordinatorChecks.removeRule()
                checks["coordinator_fixture_rule_removed"] = true
            } else if mode == "supervisor" {
                checkpoint = "native_worker_supervisor"
                checks = try RootSupervisorChecks.run(value, identity: identity)
            } else if mode == "handoff" {
                checkpoint = "native_handoff"
                let created = try RootKeyHandoffChecks.run(value, policy: path, store: store, identity: identity, stage: "create")
                let reopened = try RootKeyHandoffChecks.run(value, policy: path, store: store, identity: identity, stage: "reopen")
                checks = ["separate_receiver_processes_used": created.pid != reopened.pid]
                for (name, value) in created.checks { checks["create_" + name] = value }
                for (name, value) in reopened.checks { checks["reopen_" + name] = value }
                checkpoint = "native_worker_service"
                checks.merge(try RootKeyHandoffChecks.service(value, identity: identity)) { _, new in new }
            } else if mode == "create" {
                checkpoint = "invalid_identity"
                do { _ = try store.load("not-a-vault-uuid"); throw RootVaultKeyFailure.invalidRecord }
                catch RootVaultKeyFailure.invalidIdentity { checks["invalid_vault_identity_rejected"] = true }
                checkpoint = "initial_missing"
                do { _ = try store.load(identity); throw RootVaultKeyFailure.invalidRecord }
                catch RootVaultKeyFailure.missing { checks["missing_key_read_did_not_enroll"] = true }
                checkpoint = "enrollment"
                let key = try store.enrollNewVault(identity)
                checkpoint = "system_location"
                checks["key_confirmed_in_system_keychain"] = try confirmSystemRecord(key, identity: identity)
                checkpoint = "encryption"
                checks["key_description_redacted"] = String(reflecting: key) == "<RootVaultKey redacted>"
                let sealed = try key.withUnsafeKey { try AES.GCM.seal(marker, using: SymmetricKey(data: Data($0))).combined! }
                let fd = open(canary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
                guard fd >= 0 else { throw RootVaultKeyFailure.unavailable }
                let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
                try handle.write(contentsOf: sealed); try handle.synchronize(); try handle.close()
                checks["fresh_key_stored_and_canary_encrypted"] = true
                checkpoint = "duplicate_enrollment"
                do { _ = try store.enrollNewVault(identity); throw RootVaultKeyFailure.invalidRecord }
                catch RootVaultKeyFailure.duplicate { checks["duplicate_enrollment_cannot_replace_key"] = true }
                checkpoint = "other_vault"
                do { _ = try store.load(UUID().uuidString.lowercased()); throw RootVaultKeyFailure.invalidRecord }
                catch RootVaultKeyFailure.missing { checks["other_vault_cannot_read_enrolled_key"] = true }
            } else if mode == "reopen" {
                checkpoint = "restart_recovery"
                let key = try store.load(identity)
                checkpoint = "system_location"
                checks["key_confirmed_in_system_keychain"] = try confirmSystemRecord(key, identity: identity)
                let sealed = try AES.GCM.SealedBox(combined: Data(contentsOf: canary))
                let opened = try key.withUnsafeKey { try AES.GCM.open(sealed, using: SymmetricKey(data: Data($0))) }
                checks["persisted_key_recovered_after_process_restart"] = opened == marker
            } else {
                checkpoint = "fixture_removal"
                do { try store.removeFixture(identity) }
                catch let error as RootKeychainFailure where error.status == errSecItemNotFound { }
                do { _ = try store.load(identity); throw RootVaultKeyFailure.invalidRecord }
                catch RootVaultKeyFailure.missing { checks["fixture_key_removed_and_not_recreated"] = true }
                if FileManager.default.fileExists(atPath: canary.path) { try FileManager.default.removeItem(at: canary) }
            }
            report["failed_checks"] = checks.filter { !$0.value }.keys.sorted()
            guard !checks.isEmpty, checks.values.allSatisfy({ $0 }) else { throw RootVaultKeyFailure.invalidRecord }
            report = ["status": "PASSED", "checks": checks, "pid": Int(getpid()), "uid": Int(getuid())]
        } catch {
            report["reason"] = (error as? RootVaultKeyFailure)?.rawValue ?? "root_key_checks_failed"
            report["checkpoint"] = checkpoint
            if let failure = error as? RootVaultRecordFailure {
                report["reason"] = failure.stage.rawValue
                report["record_shape"] = failure.shape
                report["record_count"] = failure.count
                if let unique = failure.uniqueReferences { report["unique_reference_count"] = unique }
            }
            if let failure = error as? RootKeychainFailure {
                report["reason"] = "system_keychain_unavailable"
                report["keychain_operation"] = failure.operation.rawValue
                report["keychain_status"] = Int(failure.status)
            }
            if let failure = error as? RootWorkerChannelFailure { report["reason"] = failure.rawValue }
            if let failure = error as? RootWorkerProcessFailure { report["reason"] = failure.rawValue }
            if let failure = error as? RootListenerFailure { report["reason"] = failure.rawValue }
            if let failure = error as? OwnerPolicyFailure { report["reason"] = failure.rawValue }
            if let failure = error as? RootStoreInitializationFailure { report["reason"] = failure.rawValue }
            if let failure = error as? RootPublicationFailure { report["reason"] = failure.rawValue }
        }
        if getuid() != 0 {
            print(String(data: (try? JSONSerialization.data(withJSONObject: report)) ?? Data(), encoding: .utf8) ?? "{}")
            exit(1)
        }
        if let output {
            let fd = open(output.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o644)
            if fd >= 0 {
                let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
                try? handle.write(contentsOf: JSONSerialization.data(withJSONObject: report))
                try? handle.synchronize(); try? handle.close()
            }
        }
        exit(report["status"] as? String == "PASSED" ? 0 : 1)
    }
}
