// Fixed Installer-only full-image entrypoint. There are no target arguments,
// environment-selected roots, credential reads or ordinary-user setup paths.
import Foundation
import Darwin

#if ACCOUNT_ACCESS_FULL_IMAGE_UPDATE_MAIN
@main struct FullImageUpdateMain {
    private static func reason(_ error: Error) -> String {
        if let diagnostic = error as? CompletedPredecessorDiagnostic { return reason(diagnostic.failure) }
        if let failure = error as? ComponentUpdateFailure { return failure.rawValue }
        guard let failure = error as? FullImageFailure else { return "full_image_update_unavailable" }
        switch failure {
        case .source: return "full_image_source_not_verified"
        case .predecessor: return "full_image_predecessor_not_verified"
        case .object: return "full_image_object_changed"
        case .journal: return "full_image_transition_conflict"
        case .unavailable: return "full_image_update_unavailable"
        }
    }
    static func refusal(_ error: Error, checkpoint: FullImageInstallCheckpoint) -> String {
        let category = (error as? CompletedPredecessorDiagnostic).map { "predecessor_" + $0.checkpoint.rawValue }
            ?? checkpoint.rawValue
        return "{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"" + reason(error)
            + "\",\"checkpoint\":\"" + category + "\"}"
    }
    static func main() {
        // Keep the ordinary-user refusal ahead of all filesystem/identity work.
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 1 else {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"full_image_update_context_required\"}")
            exit(78)
        }
        var checkpoint = FullImageInstallCheckpoint.context
        do {
            guard CommandLine.arguments[0].hasPrefix("/"),
                  CommandLine.arguments[0].hasSuffix("/AccountAccess-fullimageupdate") else {
                throw ComponentUpdateFailure.context
            }
            umask(0o077)
            // The existing one-shot update publisher identity remains closed.
            // A package script independently pins these exact helper bytes.
            try ComponentUpdateIdentity.verifySelf(team: "WBULD6N4NQ")
            let resourcePath = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
            let resources = try InstallerPayloadIO.directory(resourcePath, owner: 0, installerResources: true)
            defer { Darwin.close(resources) }
            let result = try ComponentController.runFullImage(resources: resources,
                pins: FullImageUpdateCompiledPins.value, checkpoint: { checkpoint = $0 })
            guard ["UPDATED_GUI_UNVERIFIED", "ALREADY_UPDATED_GUI_UNVERIFIED"].contains(result) else {
                throw FullImageFailure.unavailable
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
