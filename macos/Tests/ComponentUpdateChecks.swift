// Ordinary synthetic files only. No launchctl, installed paths, owner or vault.
import Foundation
import Darwin

private final class FixtureBarrier: ComponentServiceBarrier {
    var disabled = false
    var enabledWithVerifiedImage = false
    var verifyCoherent: () throws -> Void = {}
    var actions: [String] = []
    func disableAndQuiesce(recovering: Bool) throws { disabled = true; actions.append("disable_quiesce") }
    func requireDisabledAndQuiescent() throws {
        guard disabled else { throw ComponentUpdateFailure.quiescence }
        actions.append("barrier")
    }
    func restoreEnabledJob() throws {
        try verifyCoherent(); enabledWithVerifiedImage = true
        actions.append("enable_coherent"); disabled = false
    }
}

private final class FixtureStore: ComponentTransitionStorage {
    let storage: ComponentFileTransaction
    var operations: [ComponentOperation] { storage.operations }
    var failAfterApply: Int?
    var applications = 0
    var inject: (() throws -> Void)?
    init(_ storage: ComponentFileTransaction) { self.storage = storage }
    func writeEvent(_ event: String, operation: Int) throws { try storage.writeEvent(event, operation: operation) }
    func state(_ operation: ComponentOperation) throws -> ComponentOperationState { try storage.state(operation) }
    func apply(_ operation: ComponentOperation) throws {
        try storage.apply(operation); applications += 1
        if applications == failAfterApply { try inject?(); throw ComponentUpdateFailure.unavailable }
    }
    func reverse(_ operation: ComponentOperation) throws { try storage.reverse(operation) }
    func verifyOldView() throws { try storage.verifyOldView() }
    func verifyRecoverableView() throws { try storage.verifyRecoverableView() }
    func verifyNewView() throws { try storage.verifyNewView() }
}

@main struct ComponentUpdateChecks {
    static func main() throws {
        guard getuid() != 0, getuid() == geteuid(), CommandLine.arguments.count == 1 else { exit(77) }
        var checks = 0
        var passed: [String: Bool] = [:]
        let identity = try ComponentUpdateIdentityChecks.run()
        checks += identity.0
        passed.merge(identity.1) { _, _ in true }
        let disabledHeader = "disabled services = {\n"
        guard try !ComponentCommands.disabled(Data((disabledHeader + "}\n").utf8)),
              try ComponentCommands.disabled(Data((disabledHeader + "\t\"com.fainir.accountaccess.broker\" => true\n}\n").utf8)),
              try !ComponentCommands.disabled(Data((disabledHeader + "\t\"com.fainir.accountaccess.broker\" => false\n}\n").utf8)) else {
            throw ComponentUpdateFailure.context
        }
        checks += 3
        for invalid in ["", disabledHeader + "garbage\n}\n"] {
            do { _ = try ComponentCommands.disabled(Data(invalid.utf8)); throw ComponentUpdateFailure.context }
            catch ComponentUpdateFailure.disabled { checks += 1 }
        }
        passed["disabled_override_requires_closed_output"] = true
        guard try ComponentCommands.disabled(Data(("\n\t" + disabledHeader + "\t\"com.fainir.accountaccess.broker\" => disabled\n\t}\n").utf8)),
              try !ComponentCommands.disabled(Data((disabledHeader + "\t\"com.fainir.accountaccess.broker\" => enabled\n}\n").utf8)),
              try !ComponentCommands.disabled(Data((disabledHeader + "\t\"com.example.one\" => disabled\n\t\"com.example.two\" => enabled\n}\n").utf8)) else {
            throw ComponentUpdateFailure.context
        }
        checks += 3
        for rows in [
            "\"com.fainir.accountaccess.broker\" => unknown\n",
            "\"com.fainir.accountaccess.broker\" => disabled\n\"com.fainir.accountaccess.broker\" => disabled\n",
            "\"com.fainir.accountaccess.broker\" => disabled\n\"com.fainir.accountaccess.broker\" => enabled\n",
            "\"com.example.other\" => enabled\n\"com.example.other\" => disabled\n",
            "\"com.fainir.accountaccess.broker\" => enabled disabled\n",
        ] {
            do { _ = try ComponentCommands.disabled(Data((disabledHeader + rows + "}\n").utf8)); throw ComponentUpdateFailure.context }
            catch ComponentUpdateFailure.disabled { checks += 1 }
        }
        passed["native_disabled_enabled_tokens_and_ambiguity_checked"] = true
        var ownership = ComponentDisableOwnership()
        guard !ownership.permits(disabled: true, recovering: false, persistedIntent: false),
              !ownership.permits(disabled: true, recovering: true, persistedIntent: false) else {
            throw ComponentUpdateFailure.disabled
        }
        try ownership.persistPriorEnabled {}
        guard ownership.permits(disabled: true, recovering: true, persistedIntent: false) else {
            throw ComponentUpdateFailure.disabled
        }
        var failedOwnership = ComponentDisableOwnership()
        do {
            try failedOwnership.persistPriorEnabled { throw ComponentUpdateFailure.journal }
            throw ComponentUpdateFailure.context
        } catch ComponentUpdateFailure.journal {}
        guard !failedOwnership.permits(disabled: true, recovering: true, persistedIntent: false) else {
            throw ComponentUpdateFailure.disabled
        }
        checks += 4
        passed["initial_owner_disabled_refused"] = true
        passed["fresh_attempt_rollback_owned"] = true
        passed["failed_disable_intent_not_owned"] = true
        let missing = Data("Bad request.\nCould not find service \"com.fainir.accountaccess.broker\" in domain for system\n".utf8)
        guard ComponentCommands.definitivelyAbsent(.init(status: 113 << 8, output: missing)),
              !ComponentCommands.definitivelyAbsent(.init(status: 1 << 8, output: missing)),
              !ComponentCommands.definitivelyAbsent(.init(status: 113 << 8, output: Data("other service".utf8))),
              !ComponentCommands.definitivelyAbsent(.init(status: 113 << 8, output: missing + Data("unknown".utf8))) else {
            throw ComponentUpdateFailure.quiescence
        }
        checks += 4
        passed["missing_service_response_exact"] = true
        passed["generic_nonzero_not_absence"] = true
        passed["foreign_service_not_absence"] = true
        passed["extra_output_not_absence"] = true
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("component-update-fixture-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let preparationPath = root.appendingPathComponent("preparation")
            try FileManager.default.createDirectory(at: preparationPath, withIntermediateDirectories: false)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: preparationPath.path)
            let parent = open(preparationPath.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard parent >= 0 else { throw ComponentUpdateFailure.unavailable }
            defer { Darwin.close(parent) }
            try ComponentPreparation.capacity(parent, bytes: 1, owner: getuid(), sameDeviceAs: parent)
            checks += 1
            do {
                try ComponentPreparation.capacity(parent, bytes: Int64.max, owner: getuid(), sameDeviceAs: parent)
                throw ComponentUpdateFailure.context
            } catch ComponentUpdateFailure.unavailable { checks += 1 }
            passed["disk_capacity_checked_on_target_volume"] = true
            let plan = String(repeating: "a", count: 64), modes: [String: mode_t] = ["slot-00": 0o644]
            let orphan = try ComponentPreparation.begin(parent, plan: plan, owner: getuid())
            defer { Darwin.close(orphan.1) }
            _ = try ComponentFiles.writeExclusive(orphan.1, "slot-00", data: Data("partial".utf8), owner: getuid(), mode: 0o600)
            guard try ComponentPreparation.retained(parent, plan: plan, slots: modes, owner: getuid()) == 1 else {
                throw ComponentUpdateFailure.journal
            }
            checks += 1
            let next = try ComponentPreparation.begin(parent, plan: plan, owner: getuid())
            defer { Darwin.close(next.1) }
            _ = try ComponentFiles.writeExclusive(next.1, "slot-00", data: Data("complete".utf8), owner: getuid(), mode: 0o644)
            _ = try ComponentFiles.writeExclusive(next.1, "intent.json", data: Data("{\"complete\":true}".utf8), owner: getuid(), mode: 0o600)
            var before = stat(), published = stat()
            guard fstat(next.1, &before) == 0 else { throw ComponentUpdateFailure.object }
            try ComponentPreparation.publish(parent, name: next.0, directory: next.1, plan: plan, owner: getuid())
            guard fstatat(parent, "transition-" + plan, &published, AT_SYMLINK_NOFOLLOW) == 0,
                  before.st_ino == published.st_ino, before.st_dev == published.st_dev,
                  try InstallerPayloadIO.contents(parent).contains(orphan.0),
                  try ComponentPreparation.retained(parent, plan: plan, slots: modes, owner: getuid()) == 1 else {
                throw ComponentUpdateFailure.journal
            }
            checks += 1
            passed["interrupted_preparation_retained_next_publishes"] = true
            _ = try ComponentFiles.writeExclusive(orphan.1, "unknown", data: Data(), owner: getuid(), mode: 0o600)
            do {
                _ = try ComponentPreparation.retained(parent, plan: plan, slots: modes, owner: getuid())
                throw ComponentUpdateFailure.context
            } catch ComponentUpdateFailure.journal { checks += 1 }
            passed["unknown_preparation_child_refused"] = true
        }
        for scenario in ["success", "after_swap_failure", "recovery_partial", "conflict"] {
            let folder = root.appendingPathComponent(scenario)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
            let backupPath = folder.appendingPathComponent("backup")
            try FileManager.default.createDirectory(at: backupPath, withIntermediateDirectories: false)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: backupPath.path)
            let parent = open(folder.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let backup = open(backupPath.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard parent >= 0, backup >= 0 else { throw ComponentUpdateFailure.unavailable }
            defer { Darwin.close(parent); Darwin.close(backup) }
            let old = Data("old-native-worker".utf8), new = Data("new-native-worker-v2".utf8)
            let previous = try ComponentFiles.writeExclusive(parent, "native", data: old, owner: getuid(), mode: 0o644)
            let staged = try ComponentFiles.writeExclusive(backup, "slot-00", data: new, owner: getuid(), mode: 0o644)
            let head = try ComponentFiles.writeExclusive(backup, "slot-01", data: Data("verified-head".utf8), owner: getuid(), mode: 0o644)
            let operations = [ComponentOperation(target: .image, path: "native", slot: "slot-00", before: previous, after: staged),
                              ComponentOperation(target: .head, path: "head", slot: "slot-01", before: nil, after: head)]
            let verifyOld = {
                guard try ComponentFiles.read(parent, "native", owner: getuid()).0 == old,
                      try ComponentFiles.observe(parent, "head", owner: getuid()) == nil else { throw ComponentUpdateFailure.base }
            }
            let verifyNew = {
                guard try ComponentFiles.read(parent, "native", owner: getuid()).0 == new,
                      try ComponentFiles.observe(parent, "head", owner: getuid()) == nil else { throw ComponentUpdateFailure.object }
            }
            let actual = ComponentFileTransaction(operations: operations, backup: backup, owner: getuid(), target: { operation in
                let copy = dup(parent)
                guard copy >= 0 else { throw ComponentUpdateFailure.unavailable }
                return (copy, operation.path)
            }, verifyOld: verifyOld, verifyRecoverable: {
                let data = try ComponentFiles.read(parent, "native", owner: getuid()).0
                guard data == old || data == new else { throw ComponentUpdateFailure.object }
            }, verifyNew: verifyNew)
            let store = FixtureStore(actual), service = FixtureBarrier()
            if scenario == "success" {
                service.verifyCoherent = {
                    guard try ComponentFiles.read(parent, "native", owner: getuid()).0 == new,
                          try ComponentFiles.observe(parent, "head", owner: getuid()) == head else {
                        throw ComponentUpdateFailure.object
                    }
                }
                let result = try ComponentTransition(storage: store, service: service).run(recovering: false)
                guard case .publishedGUIUnverified = result,
                      try actual.state(operations[0]) == .applied,
                      try actual.state(operations[1]) == .applied,
                      service.enabledWithVerifiedImage else { throw ComponentUpdateFailure.object }
                checks += 4
                passed["coherent_group_before_enable"] = true
                passed["head_after_full_verification"] = true
            } else if scenario == "recovery_partial" {
                try actual.apply(operations[0]) // Simulate crash after swap, before completion event.
                service.verifyCoherent = {
                    guard try ComponentFiles.read(parent, "native", owner: getuid()).0 == new,
                          try ComponentFiles.observe(parent, "head", owner: getuid()) == head else {
                        throw ComponentUpdateFailure.object
                    }
                }
                let result = try ComponentTransition(storage: store, service: service).run(recovering: true)
                guard case .publishedGUIUnverified = result,
                      try actual.state(operations[0]) == .applied,
                      service.enabledWithVerifiedImage else { throw ComponentUpdateFailure.object }
                checks += 3
                passed["partial_swap_recovery_finishes_coherent_group"] = true
            } else {
                store.failAfterApply = 1
                service.verifyCoherent = verifyOld
                if scenario == "conflict" {
                    store.inject = {
                        let replacement = try ComponentFiles.writeExclusive(parent, "concurrent", data: Data("preserve".utf8), owner: getuid(), mode: 0o644)
                        _ = replacement
                        guard renameat(parent, "concurrent", parent, "native") == 0 else { throw ComponentUpdateFailure.object }
                    }
                }
                do {
                    _ = try ComponentTransition(storage: store, service: service).run(recovering: false)
                    throw ComponentUpdateFailure.context
                } catch ComponentUpdateFailure.unavailable where scenario == "after_swap_failure" {
                    try verifyOld()
                    guard service.enabledWithVerifiedImage else { throw ComponentUpdateFailure.object }
                    checks += 2
                    passed["post_swap_failure_rolls_back"] = true
                } catch ComponentUpdateFailure.rollback where scenario == "conflict" {
                    guard service.disabled, !service.enabledWithVerifiedImage,
                          try ComponentFiles.read(parent, "native", owner: getuid()).0 == Data("preserve".utf8),
                          try ComponentFiles.read(backup, "slot-00", owner: getuid()).0 == old else { throw ComponentUpdateFailure.object }
                    checks += 4
                    passed["concurrent_replacement_preserved_disabled"] = true
                }
            }
        }
        let report: [String: Any] = ["schema": 1, "status": "PASSED", "checks": passed,
                                   "ordinary_fixture_assertions": checks,
                                   "installed_reads": false, "service_actions": false]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
    }
}
