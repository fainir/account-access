// Sealed Installer entry point. No path arguments, owner impersonation or
// credential reads. Package postinstall independently pins these helper bytes.
import Foundation
import Darwin

#if ACCOUNT_ACCESS_BROKER_REPAIR_MAIN
enum BrokerRepairProgressCheckpoint {
    case repair(BrokerRepairCheckpoint), predecessor(FullImageInstallCheckpoint)
    var value: String {
        switch self {
        case .repair(let checkpoint): return checkpoint.rawValue
        case .predecessor(let checkpoint): return "predecessor_full_image_" + checkpoint.rawValue
        }
    }
}
enum BrokerRepairProgress {
    static func encoded(_ checkpoint: BrokerRepairProgressCheckpoint, elapsed: Double) -> String? {
        guard elapsed.isFinite, elapsed >= 0, elapsed <= 86400 else { return nil }
        // No strings from an error, record, account or filesystem enter this
        // progress record. Invalid timing suppresses diagnostics, not the repair.
        return "{\"schema\":1,\"status\":\"RUNNING\",\"checkpoint\":\"" + checkpoint.value
            + "\",\"elapsed_seconds\":" + String(Int(elapsed)) + "}"
    }
}
@main struct BrokerRepairMain {
    static func refusal(_ error: Error, checkpoint: BrokerRepairCheckpoint) -> String {
        let migration = error as? StoreVolumeMigrationDiagnostic
        let image = error as? CompletedFullImageDiagnostic
        let component = (image?.failure ?? error) as? CompletedPredecessorDiagnostic
        let failure = migration?.failure ?? component?.failure ?? image?.failure ?? error
        let category = migration.map { "migration_" + $0.checkpoint.rawValue }
            ?? component.map { "predecessor_component_" + $0.checkpoint.rawValue }
            ?? image.map { "predecessor_full_image_" + $0.checkpoint.rawValue } ?? checkpoint.rawValue
        let reason: String
        if let known = failure as? ComponentUpdateFailure { reason = known.rawValue }
        else if let known = failure as? RootStoreVolumeFailure { reason = known.rawValue }
        else if let known = failure as? FullImageFailure {
            switch known {
            case .source: reason = "full_image_source_not_verified"
            case .predecessor: reason = "full_image_predecessor_not_verified"
            case .object: reason = "full_image_object_changed"
            case .journal: reason = "full_image_transition_conflict"
            case .unavailable: reason = "full_image_update_unavailable"
            }
        } else { reason = "broker_repair_not_verified" }
        // Both fields come only from closed enums. Never render Error strings,
        // paths, record contents, filesystem values or account information.
        return "{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"" + reason
            + "\",\"checkpoint\":\"" + category + "\"}"
    }
    static func main() {
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 1 else {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"broker_repair_installer_context_required\"}")
            exit(78)
        }
        var checkpoint = BrokerRepairCheckpoint.context
        let started = ProcessInfo.processInfo.systemUptime
        var lastProgress: String?
        func progress(_ value: BrokerRepairProgressCheckpoint) {
            guard value.value != lastProgress,
                  let line = BrokerRepairProgress.encoded(value, elapsed: ProcessInfo.processInfo.systemUptime - started) else { return }
            lastProgress = value.value
            print(line); fflush(stdout)
        }
        do {
            guard CommandLine.arguments[0].hasPrefix("/"),
                  CommandLine.arguments[0].hasSuffix("/AccountAccess-brokerrepair") else { throw ComponentUpdateFailure.context }
            umask(0o077)
            try ComponentUpdateIdentity.verifySelf(team: "WBULD6N4NQ")
            let path = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
            let resources = try InstallerPayloadIO.directory(path, owner: 0, installerResources: true)
            defer { Darwin.close(resources) }
            let result = try ComponentController.runBrokerRepair(resources: resources, pins: BrokerRepairCompiledPins.value,
                predecessorPins: FullImageUpdateCompiledPins.value,
                checkpoint: { checkpoint = $0; progress(.repair($0)) },
                predecessorCheckpoint: { progress(.predecessor($0)) })
            guard ["UPDATED_GUI_UNVERIFIED", "ALREADY_UPDATED_GUI_UNVERIFIED"].contains(result) else {
                throw ComponentUpdateFailure.unavailable
            }
            print("{\"schema\":1,\"status\":\"" + result + "\",\"checkpoint\":\"" + checkpoint.rawValue
                + "\",\"gui_verified\":false,\"account_qa_verified\":false}")
        } catch {
            print(refusal(error, checkpoint: checkpoint))
            exit(78)
        }
    }
}
#endif
