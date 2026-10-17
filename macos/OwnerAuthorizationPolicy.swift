// Called only by the trusted system provisioner after approved service setup.
// Installs policy, never grants a setup authorization or displays owner UI.
import Foundation
import Security
import Darwin

enum OwnerPolicyFailure: String, Error {
    case daemonRequired = "owner_policy_requires_system_daemon"
    case changed = "owner_policy_changed"
    case unavailable = "owner_policy_unavailable"
    case readback = "owner_policy_readback_invalid"
}

enum OwnerPolicyInstallation { case created, alreadyInstalled }

enum OwnerAuthorizationPolicy {
    static func requireDaemon() throws {
        guard getuid() == 0, geteuid() == 0 else { throw OwnerPolicyFailure.daemonRequired }
        var attributes: SessionAttributeBits = []
        guard SessionGetInfo(callerSecuritySession, nil, &attributes) == errSecSuccess,
              attributes.rawValue & 0x0001 != 0 else { throw OwnerPolicyFailure.daemonRequired }
    }

    static func installIfAbsent() throws -> OwnerPolicyInstallation {
        try requireDaemon()
        var existing: CFDictionary?
        let status = AuthorizationRightGet(OwnerSetupAuthorization.right, &existing)
        if status == errAuthorizationSuccess {
            guard let value = existing as? [String: Any], OwnerSetupAuthorization.validDefinition(value) else {
                throw OwnerPolicyFailure.changed
            }
            return .alreadyInstalled
        }
        // AuthorizationDB.h documents this status as "No definition found".
        // Other lookup failures never authorize replacement or an allow rule.
        guard status == errAuthorizationDenied, existing == nil else { throw OwnerPolicyFailure.unavailable }
        var reference: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess, let reference else {
            throw OwnerPolicyFailure.unavailable
        }
        defer { AuthorizationFree(reference, [.destroyRights]) }
        guard AuthorizationRightSet(reference, OwnerSetupAuthorization.right,
                OwnerSetupAuthorization.definition as CFDictionary, "Authorize Account Access setup" as CFString,
                nil, nil) == errAuthorizationSuccess else { throw OwnerPolicyFailure.unavailable }
        guard OwnerSetupAuthorization.installed() else { throw OwnerPolicyFailure.readback }
        return .created
    }
}
