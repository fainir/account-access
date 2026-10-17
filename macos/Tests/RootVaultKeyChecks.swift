// Synthetic keychain tests in a disposable root launchd context only. The
// probe uses an explicit System reference to avoid a false user-keychain miss.
import Foundation
import Security
import CryptoKit
import Darwin

@main struct RootVaultKeyChecks {
    static func main() {
        var report: [String: Any] = ["status": "FAILED", "reason": "root_key_checks_failed"]
        var output: URL?
        do {
            guard CommandLine.arguments.count == 4, CommandLine.arguments[1] == "--policy" else {
                throw RootVaultKeyFailure.invalidIdentity
            }
            let path = CommandLine.arguments[2]
            guard path.hasPrefix("/Library/PrivilegedHelperTools/account-access-worker-qa-") else {
                throw RootVaultKeyFailure.invalidIdentity
            }
            let value = try WorkerLaunchPaths.object(path)
            guard Set(value.keys) == ["fixture", "vault_id", "root"],
                  value["fixture"] as? String == "account-access-system-key-ci-v1",
                  let identity = value["vault_id"] as? String else { throw RootVaultKeyFailure.invalidIdentity }
            let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
            let mode = CommandLine.arguments[3]
            guard ["create", "reopen", "unprivileged", "remove"].contains(mode) else { throw RootVaultKeyFailure.invalidIdentity }
            output = root.appendingPathComponent("key-" + mode + ".json")
            var checks: [String: Bool] = [:]
            let marker = Data("account-access-system-key-canary-v1".utf8)
            let canary = root.appendingPathComponent("control/key-canary.bin")
            if mode == "unprivileged" {
                guard getuid() != 0 else { throw RootVaultKeyFailure.daemonRequired }
                checks["provider_refused"] = (try? RootVaultKeyStore()) == nil
                // Test-only explicit System search; product storage uses
                // SecItem in the verified root system context.
                var system: SecKeychain?
                guard SecKeychainOpen("/Library/Keychains/System.keychain", &system) == errSecSuccess, let system else {
                    throw RootVaultKeyFailure.unavailable
                }
                guard AccountAccessDisableKeychainInteraction() else { throw RootVaultKeyFailure.unavailable }
                let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: RootVaultKeyStore.service, kSecAttrAccount as String: "vault-" + identity,
                    kSecUseDataProtectionKeychain as String: false, kSecAttrSynchronizable as String: false,
                    kSecMatchSearchList as String: [system], kSecMatchLimit as String: kSecMatchLimitOne,
                    kSecReturnData as String: true]
                var result: CFTypeRef?
                let status = SecItemCopyMatching(query as CFDictionary, &result)
                checks["direct_system_item_read_denied"] = [errSecAuthFailed, errSecInteractionNotAllowed, errSecItemNotFound].contains(status) && result == nil
                report = ["status": checks.values.allSatisfy({ $0 }) ? "PASSED" : "FAILED", "checks": checks,
                          "pid": Int(getpid()), "uid": Int(getuid()), "probe_status": Int(status)]
                print(String(data: try JSONSerialization.data(withJSONObject: report), encoding: .utf8)!)
                exit(checks.values.allSatisfy({ $0 }) ? 0 : 1)
            }
            guard getuid() == 0, geteuid() == 0 else { throw RootVaultKeyFailure.daemonRequired }
            var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
            guard setrlimit(RLIMIT_CORE, &noCore) == 0 else { throw RootVaultKeyFailure.unavailable }
            let store = try RootVaultKeyStore()
            checks["system_daemon_context_verified"] = true
            if mode == "create" {
                do { _ = try store.load("not-a-vault-uuid"); throw RootVaultKeyFailure.invalidRecord }
                catch RootVaultKeyFailure.invalidIdentity { checks["invalid_vault_identity_rejected"] = true }
                do { _ = try store.load(identity); throw RootVaultKeyFailure.invalidRecord }
                catch RootVaultKeyFailure.missing { checks["missing_key_read_did_not_enroll"] = true }
                let key = try store.enrollNewVault(identity)
                checks["key_description_redacted"] = String(reflecting: key) == "<RootVaultKey redacted>"
                let sealed = try key.withUnsafeKey { try AES.GCM.seal(marker, using: SymmetricKey(data: Data($0))).combined! }
                let fd = open(canary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
                guard fd >= 0 else { throw RootVaultKeyFailure.unavailable }
                let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
                try handle.write(contentsOf: sealed); try handle.synchronize(); try handle.close()
                checks["fresh_key_stored_and_canary_encrypted"] = true
                do { _ = try store.enrollNewVault(identity); throw RootVaultKeyFailure.invalidRecord }
                catch RootVaultKeyFailure.duplicate { checks["duplicate_enrollment_cannot_replace_key"] = true }
            } else if mode == "reopen" {
                let key = try store.load(identity)
                let sealed = try AES.GCM.SealedBox(combined: Data(contentsOf: canary))
                let opened = try key.withUnsafeKey { try AES.GCM.open(sealed, using: SymmetricKey(data: Data($0))) }
                checks["persisted_key_recovered_after_process_restart"] = opened == marker
            } else {
                do { try store.removeFixture(identity) }
                catch let error as RootKeychainFailure where error.status == errSecItemNotFound { }
                do { _ = try store.load(identity); throw RootVaultKeyFailure.invalidRecord }
                catch RootVaultKeyFailure.missing { checks["fixture_key_removed_and_not_recreated"] = true }
                if FileManager.default.fileExists(atPath: canary.path) { try FileManager.default.removeItem(at: canary) }
            }
            guard !checks.isEmpty, checks.values.allSatisfy({ $0 }) else { throw RootVaultKeyFailure.invalidRecord }
            report = ["status": "PASSED", "checks": checks, "pid": Int(getpid()), "uid": Int(getuid())]
        } catch {
            report["reason"] = (error as? RootVaultKeyFailure)?.rawValue ?? "root_key_checks_failed"
            if let failure = error as? RootKeychainFailure {
                report["reason"] = "system_keychain_unavailable"
                report["keychain_operation"] = failure.operation.rawValue
                report["keychain_status"] = Int(failure.status)
            }
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
