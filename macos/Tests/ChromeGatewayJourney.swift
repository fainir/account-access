// Actual stable Chrome launches this fixture Mach-O directly. This entry is
// compiled only into the disposable-CI client, never the installed browser host.
import Foundation
import Darwin

#if !ACCOUNT_ACCESS_GATEWAY_CHECKS || !ACCOUNT_ACCESS_ROOT_GATEWAY_CLIENT
#error("Signed Chrome journey belongs only in the disposable CI client")
#endif

enum ChromeGatewayJourney {
    static func serve() throws -> Never {
        guard getuid() != 0, getuid() == geteuid(), getgid() == getegid(),
              ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",
              Array(CommandLine.arguments.dropFirst()) == [BrowserNativeHost.origin],
              BrowserNativeHost.chromeParentAuthorized() else { throw OwnerGatewayError.invalidPolicy }
        var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(RLIMIT_CORE, &noCore) == 0 else { throw OwnerGatewayError.invalidPolicy }
        let executable = URL(fileURLWithPath: CommandLine.arguments[0])
        let prefix = executable.deletingLastPathComponent()
        guard executable.lastPathComponent == "root-owner-client",
              prefix.deletingLastPathComponent().path == "/Library/PrivilegedHelperTools",
              prefix.lastPathComponent.range(of: "^account-access-worker-qa-[A-Za-z0-9]{8}$",
                  options: .regularExpression) != nil,
              try WorkerLaunchPaths.protected(executable.path).path == executable.path else {
            throw OwnerGatewayError.invalidPolicy
        }
        let value = try WorkerLaunchPaths.object(prefix.appendingPathComponent("browser-host-owner-policy.json").path)
        guard Set(value.keys) == ["fixture", "owner_uid", "owner_hash", "server_hash", "owner_socket", "owner_port", "bootstrap_socket"],
              value["fixture"] as? String == "account-access-root-owner-ci-v1",
              try WorkerLaunchPaths.integer(value["owner_uid"]) == getuid(),
              let hash = value["server_hash"] as? String else { throw OwnerGatewayError.invalidPolicy }
        let peer = try OwnerGatewayPeer.fixture(uid: 0, codeHash: hash)
        let desktop = DesktopOwnerConnection(makeChannel: {
            try OwnerGatewayConnection(service: OwnerGatewayHost.serviceName, peer: peer)
        }, acquire: { throw DesktopOwnerFailure.approval })
        defer { desktop.close() }
        let status = BrowserNativeHost.serve(input: .standardInput, output: .standardOutput,
                                            presentedOrigin: BrowserNativeHost.origin) { body in
            guard BrowserNativeHost.chromeParentAuthorized(),
                  let message = body["message"] as? [String: Any],
                  Set(message.keys) == ["method"], message["method"] as? String == "pending" else {
                throw OwnerGatewayError.invalidPolicy
            }
            let response = try desktop.request("owner/browser-message", body: body)
            guard response.0 == 200, BrowserNativeHost.chromeParentAuthorized() else {
                throw OwnerGatewayError.invalidResponse
            }
            return response.1
        }
        desktop.close()
        exit(status)
    }
}
