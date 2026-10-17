// Durable key custody for a trusted system launchd daemon. Never called from
// the owner app, an agent client, or a sudo process in a user login session.
import Foundation
import Security
import LocalAuthentication
import Darwin

enum RootVaultKeyFailure: String, Error {
    case daemonRequired = "system_daemon_context_required"
    case invalidIdentity = "invalid_vault_identity"
    case missing = "vault_key_missing"
    case duplicate = "vault_key_already_enrolled"
    case invalidRecord = "invalid_vault_key_record"
    case unavailable = "system_keychain_unavailable"
}

struct RootKeychainFailure: Error {
    enum Operation: String { case load, enroll, remove }
    let operation: Operation
    let status: OSStatus
}

final class RootVaultKey: CustomStringConvertible, CustomDebugStringConvertible {
    private var bytes: Data
    fileprivate init(_ value: Data) { bytes = value }
    var description: String { "<RootVaultKey redacted>" }
    var debugDescription: String { description }
    func withUnsafeKey<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) throws -> Result {
        try RootVaultKeyStore.requireDaemon()
        return try bytes.withUnsafeBytes(body)
    }
    deinit { bytes.resetBytes(in: 0..<bytes.count) }
}

final class RootVaultKeyStore {
    #if ACCOUNT_ACCESS_ROOT_KEY_CHECKS
    static let service = "com.fainir.accountaccess.broker.vault-key.qa.v1"
    #else
    static let service = "com.fainir.accountaccess.broker.vault-key.v1"
    #endif
    init() throws { try Self.requireDaemon() }

    static func requireDaemon() throws {
        guard getuid() == 0, geteuid() == 0 else { throw RootVaultKeyFailure.daemonRequired }
        var attributes: SessionAttributeBits = []
        guard SessionGetInfo(callerSecuritySession, nil, &attributes) == errSecSuccess,
              attributes.rawValue & 0x0001 != 0 else { // AuthSession.h: sessionIsRoot
            throw RootVaultKeyFailure.daemonRequired
        }
    }
    private func query(_ identity: String) throws -> [String: Any] {
        try Self.requireDaemon()
        guard let uuid = UUID(uuidString: identity), uuid.uuidString.lowercased() == identity else {
            throw RootVaultKeyFailure.invalidIdentity
        }
        let context = LAContext()
        context.interactionNotAllowed = true
        // TN3137: system-context processes default to the System file-based
        // keychain. No user-login keychain, data-protection group or file-path
        // fallback is selected here. The OS owns its on-disk implementation.
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.service,
                kSecAttrAccount as String: "vault-" + identity,
                kSecAttrSynchronizable as String: false,
                kSecUseDataProtectionKeychain as String: false,
                kSecUseAuthenticationContext as String: context]
    }
    func load(_ identity: String) throws -> RootVaultKey {
        var request = try query(identity)
        request[kSecMatchLimit as String] = kSecMatchLimitAll
        request[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { throw RootVaultKeyFailure.missing }
        guard status == errSecSuccess else { throw RootKeychainFailure(operation: .load, status: status) }
        guard let values = result as? [Data], values.count == 1, values[0].count == 32 else {
            throw RootVaultKeyFailure.invalidRecord
        }
        return RootVaultKey(values[0])
    }
    // Explicit fresh enrollment only. The supervisor must authorize enrollment
    // and confirm there is no existing encrypted state before calling this.
    // Loading/recovering a missing key never calls enrollment automatically.
    func enrollNewVault(_ identity: String) throws -> RootVaultKey {
        var request = try query(identity)
        var bytes = Data(count: 32)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        let random = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard random == errSecSuccess else { throw RootVaultKeyFailure.unavailable }
        request[kSecValueData as String] = bytes
        request[kSecAttrLabel as String] = "Account Access broker vault"
        let status = SecItemAdd(request as CFDictionary, nil)
        if status == errSecDuplicateItem { throw RootVaultKeyFailure.duplicate }
        guard status == errSecSuccess else { throw RootKeychainFailure(operation: .enroll, status: status) }
        let stored = try load(identity)
        guard try stored.withUnsafeKey({ Data($0) == bytes }) else { throw RootVaultKeyFailure.invalidRecord }
        return stored
    }

    #if ACCOUNT_ACCESS_ROOT_KEY_CHECKS
    // No production delete or key-export endpoint. CI removes only its newly
    // allocated UUID in the separate fixture namespace.
    func removeFixture(_ identity: String) throws {
        let status = SecItemDelete(try query(identity) as CFDictionary)
        guard status == errSecSuccess else { throw RootKeychainFailure(operation: .remove, status: status) }
    }
    #endif
}
