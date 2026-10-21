// Disposable CI only: compose the production collector with an actual worker.
import Foundation
import Darwin
#if !ACCOUNT_ACCESS_GATEWAY_CHECKS
#error("Synthetic native SMS journey requires CI flags")
#endif
@main struct RootMessagesJourneyMain {
    static func main() {
        do {
            try RootVaultKeyStore.requireDaemon()
            guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--policy" else { throw OwnerGatewayError.invalidPolicy }
            let path = CommandLine.arguments[2]
            let prefix = "/Library/PrivilegedHelperTools/account-access-worker-qa-"
            guard path.hasPrefix(prefix) else { throw OwnerGatewayError.invalidPolicy }
            let root = URL(fileURLWithPath: path).deletingLastPathComponent()
            let value = try WorkerLaunchPaths.object(path)
            guard Set(value.keys) == ["fixture", "owner_uid", "helper_hash", "owner_socket", "owner_port", "bootstrap_socket"],
                  value["fixture"] as? String == "account-access-native-browser-ci-v1",
                  let hash = value["helper_hash"] as? String else { throw OwnerGatewayError.invalidPolicy }
            let owner = try WorkerLaunchPaths.integer(value["owner_uid"])
            let peer = try OwnerGatewayPeer.fixture(uid: owner, codeHash: hash)
            let token = try RootGatewayFixture.capability(WorkerLaunchPaths.lexical(value["bootstrap_socket"]))
            let backend = try OwnerUnixBackend(path: WorkerLaunchPaths.lexical(value["owner_socket"]), capability: token,
                port: Int(WorkerLaunchPaths.integer(value["owner_port"], maximum: 65535)))
            let reader = try RootMessagesCollector.fixture(owner: peer,
                app: root.appendingPathComponent("native-messages-helper").path,
                arguments: [root.appendingPathComponent("native-browser-profile.json").path,
                            root.appendingPathComponent("native-browser-owner/messages.sqlite").path])
            let ready = root.appendingPathComponent("native-browser-ready.json")
            try JSONSerialization.data(withJSONObject: ["status": "READY", "owner_uid": Int(owner)]).write(to: ready, options: .withoutOverwriting)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: ready.path)
            let deadline = ProcessInfo.processInfo.systemUptime + 75
            let stop = root.appendingPathComponent("native-browser-stop")
            while ProcessInfo.processInfo.systemUptime < deadline {
                var info = stat()
                if lstat(stop.path, &info) == 0 {
                    guard info.st_uid == 0, info.st_mode & S_IFMT == S_IFREG,
                          info.st_mode & 0o077 == 0, info.st_nlink == 1 else { throw OwnerGatewayError.invalidPolicy }
                    return
                }
                reader.poll(backend)
                Thread.sleep(forTimeInterval: 0.05)
            }
            throw OwnerGatewayError.unavailable
        } catch {
            // No raw request, response, source data, message or capability.
            print("{\"status\":\"FAILED\",\"reason\":\"native_browser_collector_unavailable\"}")
            exit(78)
        }
    }
}
