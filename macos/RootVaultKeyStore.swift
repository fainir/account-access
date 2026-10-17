// Durable key custody for a trusted system launchd daemon. Never called from
// the owner app, an agent client, or a sudo process in a user login session.
import Foundation
import Security
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

struct RootVaultRecordFailure: Error {
    enum Stage: String {
        case references = "vault_key_reference_result_invalid"
        case data = "vault_key_data_result_invalid"
        case readback = "vault_key_enrollment_readback_invalid"
    }
    let stage: Stage
    // Fixed shape metadata only. Never retain or format a Keychain value.
    let shape: String
    let count: Int
    init(_ stage: Stage, result: CFTypeRef? = nil) {
        self.stage = stage
        if let array = result as? NSArray { shape = "array"; count = array.count }
        else if result is Data { shape = "data"; count = 1 }
        else if result is NSDictionary { shape = "dictionary"; count = 1 }
        else { shape = result == nil ? "absent" : "other"; count = 0 }
    }
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
        // Apply this before the first secret enters this process, including
        // callers that have not yet configured their supervisor lifecycle.
        var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(RLIMIT_CORE, &noCore) == 0 else { throw RootVaultKeyFailure.unavailable }
        guard AccountAccessDisableKeychainInteraction() else { throw RootVaultKeyFailure.unavailable }
    }
    private func query(_ identity: String) throws -> [String: Any] {
        try Self.requireDaemon()
        guard let uuid = UUID(uuidString: identity), uuid.uuidString.lowercased() == identity else {
            throw RootVaultKeyFailure.invalidIdentity
        }
        // TN3137: system-context processes default to the System file-based
        // keychain. No user-login keychain, data-protection group or file-path
        // fallback is selected here. The OS owns its on-disk implementation.
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.service,
                kSecAttrAccount as String: "vault-" + identity,
                kSecAttrSynchronizable as String: false,
                kSecUseDataProtectionKeychain as String: false]
    }
    func load(_ identity: String) throws -> RootVaultKey {
        var request = try query(identity)
        request[kSecMatchLimit as String] = kSecMatchLimitAll
        // The file-based shim rejects MatchLimitAll + password data. Resolve
        // the exact record first without retrieving any password bytes.
        request[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { throw RootVaultKeyFailure.missing }
        guard status == errSecSuccess else { throw RootKeychainFailure(operation: .load, status: status) }
        guard let references = result as? [Data], references.count == 1 else {
            throw RootVaultRecordFailure(.references, result: result)
        }
        request.removeValue(forKey: kSecReturnPersistentRef as String)
        request[kSecValuePersistentRef as String] = references[0]
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        request[kSecReturnData as String] = true
        result = nil
        let read = SecItemCopyMatching(request as CFDictionary, &result)
        if read == errSecItemNotFound { throw RootVaultKeyFailure.missing }
        guard read == errSecSuccess else { throw RootKeychainFailure(operation: .load, status: read) }
        guard let bytes = result as? Data, bytes.count == 32 else { throw RootVaultRecordFailure(.data, result: result) }
        return RootVaultKey(bytes)
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
        guard try stored.withUnsafeKey({ Data($0) == bytes }) else { throw RootVaultRecordFailure(.readback) }
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
