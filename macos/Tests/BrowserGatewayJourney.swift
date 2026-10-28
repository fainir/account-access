// Disposable CI only. Exercise the production framing, desktop connection and
// privileged XPC transport; this is not a signed-Chrome-parent fixture.
import Foundation
import Darwin

#if !ACCOUNT_ACCESS_GATEWAY_CHECKS || !ACCOUNT_ACCESS_ROOT_GATEWAY_CLIENT
#error("Browser gateway journey belongs only in the disposable CI client")
#endif

enum BrowserGatewayJourney {
    static func serve(peer: OwnerGatewayPeer) throws -> Never {
        guard getuid() != 0, getuid() == geteuid(),
              ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true" else {
            throw OwnerGatewayError.invalidPolicy
        }
        // No interactive authorization is possible. The real server checks and
        // refuses this invalid external form if a connect message is attempted.
        let desktop = DesktopOwnerConnection(makeChannel: {
            try OwnerGatewayConnection(service: OwnerGatewayHost.serviceName, peer: peer)
        }, acquire: { Data(repeating: 0x41, count: 32) })
        defer { desktop.close() }
        try desktop.prepare()
        let status = BrowserNativeHost.serve(input: .standardInput, output: .standardOutput,
                                            presentedOrigin: BrowserNativeHost.origin) { body in
            try desktop.request("owner/browser-message", body: body).1
        }
        desktop.close()
        exit(status)
    }
}
