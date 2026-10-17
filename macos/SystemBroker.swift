// Installed system-service entrypoint. No elevation, runtime provisioning,
// caller-selected command, key export or owner-approval bypass.
import Foundation
import Security
import Darwin

enum SystemBrokerFailure: String, Error {
    case arguments = "system_broker_invalid_arguments"
    case policy = "system_broker_invalid_policy"
    case unavailable = "system_broker_unavailable"
}

struct SystemBrokerSettings {
    static let installedPolicy = "/Library/Application Support/Account Access/broker/host.json"
    let workerPolicy: String
    let enrollmentPolicy: String
    let bootstrap: String
    let vault: String
    let owner: OwnerGatewayPeer
    let bootstrapPeer: OwnerGatewayPeer

    init(path: String) throws { try self.init(path: path, fixture: false) }
    private init(path: String, fixture: Bool) throws {
        let value = try WorkerLaunchPaths.object(path)
        guard Set(value.keys) == ["managed_by", "schema", "worker_launcher", "enrollment_policy", "bootstrap", "vault_id",
            "owner_uid", "publisher_team", "owner_identifier", "owner_hashes", "bootstrap_identifier", "bootstrap_hashes"],
              value["managed_by"] as? String == "account-access-system-host-v1",
              try WorkerLaunchPaths.integer(value["schema"]) == 1,
              let identity = value["vault_id"] as? String, let uuid = UUID(uuidString: identity),
              uuid.uuidString.lowercased() == identity,
              let team = value["publisher_team"] as? String,
              let ownerID = value["owner_identifier"] as? String, let ownerHashes = value["owner_hashes"] as? [String],
              let bootstrapID = value["bootstrap_identifier"] as? String,
              let bootstrapHashes = value["bootstrap_hashes"] as? [String] else { throw SystemBrokerFailure.policy }
        workerPolicy = try WorkerLaunchPaths.lexical(value["worker_launcher"])
        enrollmentPolicy = try WorkerLaunchPaths.lexical(value["enrollment_policy"])
        bootstrap = try WorkerLaunchPaths.lexical(value["bootstrap"])
        vault = identity
        let uid = try WorkerLaunchPaths.integer(value["owner_uid"])
        if fixture {
            #if ACCOUNT_ACCESS_GATEWAY_CHECKS && ACCOUNT_ACCESS_ROOT_KEY_CHECKS
            guard path.hasPrefix("/Library/PrivilegedHelperTools/account-access-worker-qa-"),
                  team == "fixture", ownerHashes.count == 1, bootstrapHashes.count == 1 else { throw SystemBrokerFailure.policy }
            owner = try OwnerGatewayPeer.fixture(uid: uid, codeHash: ownerHashes[0])
            bootstrapPeer = try OwnerGatewayPeer.fixture(uid: 0, codeHash: bootstrapHashes[0])
            #else
            throw SystemBrokerFailure.policy
            #endif
        } else {
            owner = try OwnerGatewayPeer(uid: uid, team: team, identifier: ownerID, codeHashes: ownerHashes)
            bootstrapPeer = try OwnerGatewayPeer(uid: 0, team: team, identifier: bootstrapID, codeHashes: bootstrapHashes)
        }
        let plan = try MacWorkerEnrollmentPlan(policy: enrollmentPolicy, requireEmptyStage: false)
        let worker = try MacWorkerPlan(policy: workerPolicy)
        guard plan.vault == vault, plan.base.workerPolicy == worker.workerPolicy,
              uid == worker.agentUID else { throw SystemBrokerFailure.policy }
        _ = try WorkerLaunchPaths.protected(bootstrap)
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS && ACCOUNT_ACCESS_ROOT_KEY_CHECKS
    static func fixture(path: String) throws -> SystemBrokerSettings { try SystemBrokerSettings(path: path, fixture: true) }
    #endif
}

struct SystemBrokerMain {
    static func serve(_ settings: SystemBrokerSettings, fixtureRoot: URL? = nil) throws -> Never {
        let host = try RootBrokerHost(policy: settings.workerPolicy, bootstrap: settings.bootstrap,
            bootstrapPeer: settings.bootstrapPeer, vault: settings.vault, owner: settings.owner,
            enrollmentPolicy: settings.enrollmentPolicy)
        try host.start()
        #if ACCOUNT_ACCESS_GATEWAY_CHECKS && ACCOUNT_ACCESS_ROOT_KEY_CHECKS
        if let fixtureRoot {
            let ready = fixtureRoot.appendingPathComponent("system-broker-ready.json")
            let missing: Bool
            do { _ = try RootVaultKeyStore().load(settings.vault); missing = false }
            catch RootVaultKeyFailure.missing { missing = true }
            let value: [String: Any] = ["status": "READY", "pid": Int(getpid()), "uid": Int(getuid()),
                "group": Int(getpgrp()), "worker_pid": Int(host.workerPID ?? 0),
                "worker_state": host.state.rawValue, "enrollment_state": host.enrollmentState?.rawValue ?? "absent",
                "setup_policy_registered": OwnerAuthorizationPolicy.trustedDefinition(), "fixture_key_absent": missing]
            try JSONSerialization.data(withJSONObject: value, options: .sortedKeys).write(to: ready, options: .atomic)
        }
        #endif
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        let stop: () -> Void = {
            do { try host.stop(); exit(0) }
            catch { exit(78) }
        }
        term.setEventHandler(handler: stop); interrupt.setEventHandler(handler: stop)
        term.resume(); interrupt.resume()
        withExtendedLifetime((host, term, interrupt)) { dispatchMain() }
    }
    static func main() {
        umask(0o077)
        do {
            try RootVaultKeyStore.requireDaemon()
            #if ACCOUNT_ACCESS_GATEWAY_CHECKS && ACCOUNT_ACCESS_ROOT_KEY_CHECKS
            if CommandLine.arguments.count >= 2, CommandLine.arguments[1] == "--fixture-policy" {
                guard [3, 4].contains(CommandLine.arguments.count),
                      CommandLine.arguments[2].hasPrefix("/Library/PrivilegedHelperTools/account-access-worker-qa-"),
                      RootVaultKeyStore.service == "com.fainir.accountaccess.broker.vault-key.qa.v1" else {
                    throw SystemBrokerFailure.arguments
                }
                let path = CommandLine.arguments[2]
                let settings = try SystemBrokerSettings.fixture(path: path)
                if CommandLine.arguments.count == 4 {
                    guard CommandLine.arguments[3] == "--cleanup-fixture-policy" else { throw SystemBrokerFailure.arguments }
                    try cleanupFixturePolicy()
                    let missing: Bool
                    do { _ = try RootVaultKeyStore().load(settings.vault); missing = false }
                    catch RootVaultKeyFailure.missing { missing = true }
                    let result: [String: Any] = ["status": "PASSED", "fixture_right_removed": true, "fixture_key_absent": missing]
                    let output = URL(fileURLWithPath: path).deletingLastPathComponent().appendingPathComponent("system-broker-cleanup.json")
                    try JSONSerialization.data(withJSONObject: result).write(to: output, options: .atomic)
                    return
                }
                try serve(settings, fixtureRoot: URL(fileURLWithPath: path).deletingLastPathComponent())
            }
            #endif
            guard CommandLine.arguments.count == 1 else { throw SystemBrokerFailure.arguments }
            try serve(SystemBrokerSettings(path: SystemBrokerSettings.installedPolicy))
        } catch {
            let reason = (error as? RootVaultKeyFailure)?.rawValue ?? (error as? SystemBrokerFailure)?.rawValue
                ?? (error as? OwnerPolicyFailure)?.rawValue ?? "system_broker_unavailable"
            print("{\"status\":\"FAILED\",\"reason\":\"" + reason + "\"}")
            exit(78)
        }
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS && ACCOUNT_ACCESS_ROOT_KEY_CHECKS
    private static func cleanupFixturePolicy() throws {
        guard OwnerSetupAuthorization.right == "com.fainir.accountaccess.owner-enrollment.qa" else { throw OwnerPolicyFailure.changed }
        var value: CFDictionary?
        let status = AuthorizationRightGet(OwnerSetupAuthorization.right, &value)
        if status == errAuthorizationDenied, value == nil { return }
        guard OwnerAuthorizationPolicy.trustedDefinition() else { throw OwnerPolicyFailure.changed }
        var reference: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess, let reference else { throw OwnerPolicyFailure.unavailable }
        defer { AuthorizationFree(reference, [.destroyRights]) }
        guard AuthorizationRightRemove(reference, OwnerSetupAuthorization.right) == errAuthorizationSuccess else { throw OwnerPolicyFailure.unavailable }
        value = nil
        guard AuthorizationRightGet(OwnerSetupAuthorization.right, &value) == errAuthorizationDenied,
              value == nil else { throw OwnerPolicyFailure.unavailable }
    }
    #endif
}

#if ACCOUNT_ACCESS_SYSTEM_BROKER_MAIN
@main struct AccountAccessSystemBroker { static func main() { SystemBrokerMain.main() } }
#endif
