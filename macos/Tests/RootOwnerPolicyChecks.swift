// Disposable VM only. Never compiled into the consumer application.
import Foundation
import Security
import Darwin

#if !ACCOUNT_ACCESS_GATEWAY_CHECKS
#error("Owner policy acceptance requires the separate QA authorization namespace")
#endif

@main struct RootOwnerPolicyChecks {
    static func authorization<T>(_ body: (AuthorizationRef) throws -> T) throws -> T {
        var reference: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess, let reference else {
            throw OwnerPolicyFailure.unavailable
        }
        defer { AuthorizationFree(reference, [.destroyRights]) }
        return try body(reference)
    }
    static func definition() -> [String: Any]? {
        var value: CFDictionary?
        guard AuthorizationRightGet(OwnerSetupAuthorization.right, &value) == errAuthorizationSuccess else { return nil }
        return value as? [String: Any]
    }
    static func setFixture(_ value: [String: Any]) throws {
        try authorization {
            guard AuthorizationRightSet($0, OwnerSetupAuthorization.right, value as CFDictionary, nil, nil, nil) == errAuthorizationSuccess else {
                throw OwnerPolicyFailure.unavailable
            }
        }
    }
    static func removeFixture() throws {
        try authorization {
            guard AuthorizationRightRemove($0, OwnerSetupAuthorization.right) == errAuthorizationSuccess else {
                throw OwnerPolicyFailure.unavailable
            }
        }
        var value: CFDictionary?
        guard AuthorizationRightGet(OwnerSetupAuthorization.right, &value) == errAuthorizationDenied, value == nil else {
            throw OwnerPolicyFailure.unavailable
        }
    }
    static func permissiveProofRefused() throws -> Bool {
        try authorization { reference in
            try OwnerSetupAuthorization.right.withCString { name in
                var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
                return try withUnsafeMutablePointer(to: &item) { pointer in
                    var rights = AuthorizationRights(count: 1, items: pointer)
                    var granted: UnsafeMutablePointer<AuthorizationRights>?
                    let status = AuthorizationCopyRights(reference, &rights, nil, [.extendRights], &granted)
                    defer { if let granted { AuthorizationFreeItemSet(granted) } }
                    guard status == errAuthorizationSuccess, let granted, granted.pointee.count == 1 else {
                        throw OwnerPolicyFailure.unavailable
                    }
                    var form = AuthorizationExternalForm()
                    guard AuthorizationMakeExternalForm(reference, &form) == errAuthorizationSuccess else { throw OwnerPolicyFailure.unavailable }
                    defer { _ = withUnsafeMutableBytes(of: &form) { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
                    // The opaque proof never leaves this native process.
                    var data = withUnsafeBytes(of: &form) { Data($0) }
                    defer { data.resetBytes(in: 0..<data.count) }
                    return !OwnerSetupAuthorization.check(data)
                }
            }
        }
    }
    static func main() {
        var output: URL?
        var owned = false
        var checkpoint = "policy"
        var checks: [String: Bool] = [:]
        var report: [String: Any] = ["status": "FAILED", "reason": "owner_policy_checks_failed"]
        do {
            try OwnerAuthorizationPolicy.requireDaemon()
            var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
            guard setrlimit(RLIMIT_CORE, &noCore) == 0,
                  OwnerSetupAuthorization.right == "com.fainir.accountaccess.owner-enrollment.qa",
                  CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--policy",
                  CommandLine.arguments[2].hasPrefix("/Library/PrivilegedHelperTools/account-access-worker-qa-") else {
                throw OwnerPolicyFailure.daemonRequired
            }
            let policy = try WorkerLaunchPaths.object(CommandLine.arguments[2])
            guard Set(policy.keys) == ["fixture", "root"], policy["fixture"] as? String == "account-access-owner-policy-ci-v1" else {
                throw OwnerPolicyFailure.unavailable
            }
            let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(policy["root"]))
            output = root.appendingPathComponent("owner-policy-report.json")
            checks["system_daemon_context_verified"] = true
            checkpoint = "namespace"
            var existing: CFDictionary?
            guard AuthorizationRightGet(OwnerSetupAuthorization.right, &existing) == errAuthorizationDenied, existing == nil else {
                throw OwnerPolicyFailure.changed
            }
            checks["namespace_initially_absent"] = true
            owned = true
            checkpoint = "install"
            checks["strict_rule_created"] = try OwnerAuthorizationPolicy.installIfAbsent() == .created
            checks["strict_rule_readback_verified"] = OwnerSetupAuthorization.installed()
            checks["matching_rule_preserved"] = try OwnerAuthorizationPolicy.installIfAbsent() == .alreadyInstalled
            checkpoint = "root_shortcut"
            checks["root_shortcut_refused"] = try authorization { !OwnerSetupAuthorization.granted($0, flags: [.extendRights]) }
            checkpoint = "changed_policy"
            try setFixture(["class": "allow"])
            checks["changed_policy_detected"] = !OwnerSetupAuthorization.installed()
            do { _ = try OwnerAuthorizationPolicy.installIfAbsent(); throw OwnerPolicyFailure.unavailable }
            catch OwnerPolicyFailure.changed { checks["changed_policy_refused"] = true }
            checks["changed_policy_preserved"] = definition()?["class"] as? String == "allow"
            checkpoint = "permissive_proof"
            checks["changed_policy_granted_proof_refused"] = try permissiveProofRefused()
            checkpoint = "restore"
            try setFixture(OwnerSetupAuthorization.definition)
            checks["strict_rule_restored"] = OwnerSetupAuthorization.installed()
            checkpoint = "cleanup"
            try removeFixture(); owned = false
            checks["fixture_rule_removed"] = true
            guard !checks.isEmpty, checks.values.allSatisfy({ $0 }) else { throw OwnerPolicyFailure.unavailable }
            report = ["status": "PASSED", "checks": checks, "pid": Int(getpid()), "uid": Int(getuid())]
        } catch {
            report["reason"] = (error as? OwnerPolicyFailure)?.rawValue ?? "owner_policy_checks_failed"
            report["checkpoint"] = checkpoint
            // Schema names of this synthetic rule only, never values/proofs.
            if owned, let value = definition() { report["definition_fields"] = value.keys.sorted() }
        }
        if owned {
            do { try removeFixture() }
            catch { report["cleanup_failed"] = true }
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
