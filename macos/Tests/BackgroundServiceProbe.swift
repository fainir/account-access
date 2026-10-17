import Foundation
import ServiceManagement
import CryptoKit

// Built only inside a uniquely identified QA app. No production unregister
// command or alternate enrollment path is added to the consumer application.
@main struct BackgroundServiceProbe {
    static func main() throws {
        let layout = try BackgroundRecovery.Layout(bundle: .main)
        guard layout.identifier.hasPrefix("com.fainir.accountaccess.qa.") else { exit(1) }
        let command = CommandLine.arguments.dropFirst().first ?? "status"
        if command == "validate" {
            let recordData = try? BackgroundRecovery.readPrivate(layout.runtime.appendingPathComponent("installed-wheel.json"), limit: 1024)
            let record = recordData.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            let path = record?["runtime"] as? String ?? ""
            let python = URL(fileURLWithPath: path).standardizedFileURL
            let launcher = try? BackgroundRecovery.readPrivate(layout.runtime.appendingPathComponent("bin/account-access"), limit: 8192, mode: 0o700)
            let schema = record?["schema"] as? NSNumber
            let checks: [String: Any] = [
                "root_private": (try? BackgroundRecovery.directory(layout.root)) != nil,
                "runtime_private": (try? BackgroundRecovery.directory(layout.runtime)) != nil,
                "record_private": recordData != nil,
                "record_shape": Set(record?.keys.map { $0 } ?? []) == Set(["managed_by", "schema", "wheel_sha256", "runtime", "launcher_sha256"]),
                "managed_by": record?["managed_by"] as? String == "account-access-runtime-v1",
                "schema_kind": schema.map { String(cString: $0.objCType) } ?? "missing",
                "schema_value": schema?.intValue == 2,
                "wheel_pin": record?["wheel_sha256"] as? String == layout.wheelSHA256,
                "runtime_alias_normalized": path != python.path,
                "runtime_in_managed_environments": python.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() == layout.runtime.appendingPathComponent("environments"),
                "runtime_executable": FileManager.default.isExecutableFile(atPath: python.path),
                "environments_private": (try? BackgroundRecovery.directory(layout.runtime.appendingPathComponent("environments"))) != nil,
                "environment_private": (try? BackgroundRecovery.directory(python.deletingLastPathComponent().deletingLastPathComponent())) != nil,
                "bin_not_shared_writable": (try? BackgroundRecovery.directory(python.deletingLastPathComponent(), privateOnly: false)) != nil,
                "launcher_private": launcher != nil,
                "launcher_hash": launcher.map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() == record?["launcher_sha256"] as? String } ?? false,
                "launcher_command": launcher == BackgroundRecovery.activatedLauncher(path: path),
                "payload_matches": BackgroundRecovery.installationMatches(runtime: layout.runtime, expected: layout.wheelSHA256)]
            let valid = (try? BackgroundRecovery.command(layout: layout)) != nil
            let data = try JSONSerialization.data(withJSONObject: ["status": valid ? "valid" : "invalid", "checks": checks])
            print(String(decoding: data, as: UTF8.self))
            return
        }
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
