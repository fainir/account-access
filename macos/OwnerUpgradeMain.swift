// Fixed Installer-only owner successor. No target arguments or setup commands.
import Foundation
import Darwin

#if ACCOUNT_ACCESS_OWNER_UPGRADE_MAIN
@main struct OwnerUpgradeMain {
    private static func reason(_ error: Error) -> String {
        if let diagnostic = error as? CompletedPredecessorDiagnostic { return reason(diagnostic.failure) }
        if let failure = error as? ComponentUpdateFailure { return failure.rawValue }
        if let failure = error as? PublicTreeFailure {
            switch failure {
            case .invalid: return "owner_upgrade_tree_storage_not_verified"
            case .changed: return "owner_upgrade_object_changed"
            case .journal: return "owner_upgrade_tree_journal_not_verified"
            case .barrier: return "owner_upgrade_quiescence_not_verified"
            }
        }
        guard let failure = error as? FullImageFailure else { return "owner_upgrade_unavailable" }
        switch failure {
        case .source: return "owner_upgrade_source_not_verified"
        case .predecessor: return "owner_upgrade_predecessor_not_verified"
        case .object: return "owner_upgrade_object_changed"
        case .journal: return "owner_upgrade_transition_conflict"
        case .unavailable: return "owner_upgrade_unavailable"
        }
    }
    static func main() {
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 1 else {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"owner_upgrade_installer_context_required\"}")
            exit(78)
        }
        var checkpoint = FullImageInstallCheckpoint.context
        do {
            guard CommandLine.arguments[0].hasPrefix("/"),
                  CommandLine.arguments[0].hasSuffix("/AccountAccess-ownerupgrade") else { throw ComponentUpdateFailure.context }
            umask(0o077)
            try ComponentUpdateIdentity.verifySelf(team: "WBULD6N4NQ")
            let resources = try InstallerPayloadIO.directory(
                URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path,
                owner: 0, installerResources: true)
            defer { Darwin.close(resources) }
            let result = try ComponentController.runOwnerUpgrade(resources: resources,
                pins: OwnerUpgradeCompiledPins.value, runtimePins: RuntimeUpgradeCompiledPins.value,
                repairPins: BrokerRepairCompiledPins.value, predecessorPins: FullImageUpdateCompiledPins.value,
                checkpoint: { checkpoint = $0 })
            guard ["UPDATED_GUI_UNVERIFIED", "ALREADY_UPDATED_GUI_UNVERIFIED"].contains(result) else { throw FullImageFailure.unavailable }
            print("{\"schema\":1,\"status\":\"" + result + "\",\"checkpoint\":\"" + checkpoint.rawValue
                + "\",\"gui_verified\":false,\"account_qa_verified\":false}")
        } catch {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"" + reason(error)
                + "\",\"checkpoint\":\"" + checkpoint.rawValue + "\"}")
            exit(78)
        }
    }
}
#endif
