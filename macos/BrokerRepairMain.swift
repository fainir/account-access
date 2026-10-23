// Sealed Installer entry point. No path arguments, owner impersonation or
// credential reads. Package postinstall independently pins these helper bytes.
import Foundation
import Darwin

#if ACCOUNT_ACCESS_BROKER_REPAIR_MAIN
@main struct BrokerRepairMain {
    static func main() {
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 1 else {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"broker_repair_installer_context_required\"}")
            exit(78)
        }
        var checkpoint = BrokerRepairCheckpoint.context
        do {
            guard CommandLine.arguments[0].hasPrefix("/"),
                  CommandLine.arguments[0].hasSuffix("/AccountAccess-brokerrepair") else { throw ComponentUpdateFailure.context }
            umask(0o077)
            try ComponentUpdateIdentity.verifySelf(team: "WBULD6N4NQ")
            let path = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
            let resources = try InstallerPayloadIO.directory(path, owner: 0, installerResources: true)
            defer { Darwin.close(resources) }
            let result = try ComponentController.runBrokerRepair(resources: resources, pins: BrokerRepairCompiledPins.value,
                predecessorPins: FullImageUpdateCompiledPins.value, checkpoint: { checkpoint = $0 })
            guard ["UPDATED_GUI_UNVERIFIED", "ALREADY_UPDATED_GUI_UNVERIFIED"].contains(result) else {
                throw ComponentUpdateFailure.unavailable
            }
            print("{\"schema\":1,\"status\":\"" + result + "\",\"checkpoint\":\"" + checkpoint.rawValue
                + "\",\"gui_verified\":false,\"account_qa_verified\":false}")
        } catch {
            let reason = (error as? ComponentUpdateFailure)?.rawValue ?? "broker_repair_not_verified"
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"" + reason + "\",\"checkpoint\":\"" + checkpoint.rawValue + "\"}")
            exit(78)
        }
    }
}
#endif
