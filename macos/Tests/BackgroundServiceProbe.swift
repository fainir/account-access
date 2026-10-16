import Foundation
import ServiceManagement

// Built only inside a uniquely identified QA app. No production unregister
// command or alternate enrollment path is added to the consumer application.
@main struct BackgroundServiceProbe {
    static func main() throws {
        let layout = try BackgroundRecovery.Layout(bundle: .main)
        guard layout.identifier.hasPrefix("com.fainir.accountaccess.qa.") else { exit(1) }
        let command = CommandLine.arguments.dropFirst().first ?? "status"
        let control = BackgroundRecovery.SystemControl()
        let status: String
        if command == "register" { status = BackgroundRecovery.manage() }
        else if command == "unregister" {
            if control.status != .notRegistered && control.status != .notFound { try control.unregister() }
            status = control.status == .notRegistered || control.status == .notFound ? "not_registered" : "unavailable"
        } else if command == "status" {
            switch control.status {
            case .enabled: status = "enabled"
            case .requiresApproval: status = "requires_approval"
            case .notRegistered, .notFound: status = "not_registered"
            @unknown default: status = "unavailable"
            }
        } else { exit(1) }
        let data = try JSONSerialization.data(withJSONObject: ["status": status, "label": layout.label])
        print(String(decoding: data, as: UTF8.self))
    }
}
