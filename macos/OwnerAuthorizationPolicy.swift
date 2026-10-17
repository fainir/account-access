// Called by the trusted system daemon hosting OwnerGateway, after approved
// service setup. Its own signature owns the rule. Never grants setup authority
// or displays owner UI; an external installer cannot stand in as its registrar.
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
    static func currentRegistrarMatches(_ definition: [String: Any]) -> Bool {
        guard let identifier = definition["identifier"] as? String,
              let text = definition["requirement"] as? String else { return false }
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        var requirement: SecRequirement?
        var expected: CFString?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, [], nil) == errSecSuccess,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSRequirementInformation), &info) == errSecSuccess,
              let values = info as? [String: Any], values[kSecCodeInfoIdentifier as String] as? String == identifier,
              SecCodeCopyDesignatedRequirement(staticCode, [], &requirement) == errSecSuccess, let requirement,
              SecRequirementCopyString(requirement, [], &expected) == errSecSuccess, let expected else { return false }
        return text == expected as String
    }
    static func trustedDefinition() -> Bool {
        var value: CFDictionary?
        guard AuthorizationRightGet(OwnerSetupAuthorization.right, &value) == errAuthorizationSuccess,
              let value = value as? [String: Any] else { return false }
        return OwnerSetupAuthorization.validDefinition(value) && currentRegistrarMatches(value)
    }
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
            guard let value = existing as? [String: Any], OwnerSetupAuthorization.validDefinition(value),
                  currentRegistrarMatches(value) else {
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
        guard trustedDefinition() else { throw OwnerPolicyFailure.readback }
        return .created
    }
}

struct RootOwnerSetupProofVerifier: OwnerSetupProofVerifying {
    func check(_ data: Data) -> Bool {
        guard (try? OwnerAuthorizationPolicy.requireDaemon()) != nil,
              OwnerAuthorizationPolicy.trustedDefinition(), OwnerSetupAuthorization.check(data) else { return false }
        // The registrar's designated requirement is pinned independently of
        // the rule's authentication flags, including after OS verification.
        return OwnerAuthorizationPolicy.trustedDefinition()
    }
}
