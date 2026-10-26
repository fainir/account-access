// Read-only qualification in the disposable hosted Installer VM. This is not
// shipped in the owner application or used to grant update authority.
import Foundation
import Darwin

@main struct CompletedBrokerRepairProbe {
    static func main() {
        let env = ProcessInfo.processInfo.environment
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 2,
              env["GITHUB_ACTIONS"] == "true", env["CI"] == "true",
              env["RUNNER_ENVIRONMENT"] == "github-hosted", env["RUNNER_OS"] == "macOS",
              env["RUNNER_ARCH"] == "ARM64", env["GITHUB_REPOSITORY"] == "fainir/account-access" else {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"hosted_fixture_required\"}")
            exit(78)
        }
        do {
            let resources = try InstallerPayloadIO.directory(CommandLine.arguments[1], owner: 0, installerResources: true)
            defer { Darwin.close(resources) }
            let proof = try ComponentController.completedBrokerRepair(resources: resources,
                pins: BrokerRepairCompiledPins.value, predecessorPins: FullImageUpdateCompiledPins.value)
            print("{\"schema\":1,\"status\":\"VERIFIED\",\"evidence_sha256\":\"" + proof.sha256 + "\"}")
        } catch {
            let reason: String
            if let known = error as? ComponentUpdateFailure { reason = known.rawValue }
            else if let known = error as? FullImageFailure {
                switch known {
                case .source: reason = "source"
                case .predecessor: reason = "predecessor"
                case .object: reason = "object"
                case .journal: reason = "journal"
                case .unavailable: reason = "unavailable"
                }
            } else { reason = "completed_repair_not_verified" }
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"" + reason + "\"}")
            exit(78)
        }
    }
}
