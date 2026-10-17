import Foundation
import Darwin

@objc(AccountAccessGatewayProbeV1) protocol OwnerGatewayProbeRPC {
    func run(_ endpoint: NSXPCListenerEndpoint, peerPolicy: Data, mode: String,
             withReply reply: @escaping (Data) -> Void)
    func quit(withReply reply: @escaping () -> Void)
}

#if ACCOUNT_ACCESS_GATEWAY_PROBE
final class OwnerGatewayProbe: NSObject, OwnerGatewayProbeRPC {
    private let lock = NSLock()
    private var held: OwnerGatewayConnection?
    func quit(withReply reply: @escaping () -> Void) {
        reply()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { exit(0) }
    }
    func run(_ endpoint: NSXPCListenerEndpoint, peerPolicy: Data, mode: String,
             withReply reply: @escaping (Data) -> Void) {
        DispatchQueue.global().async {
            var checks: [String: Bool] = ["helper_ran": true]
            var client: OwnerGatewayConnection?
            do {
                if mode == "retired" {
                    self.lock.lock(); let previous = self.held; self.held = nil; self.lock.unlock()
                    guard let previous else { throw OwnerGatewayError.unavailable }
                    defer { previous.invalidate() }
                    let done = DispatchSemaphore(value: 0)
                    var refused = false
                    previous.request("owner/credential", body: Data("{}".utf8)) {
                        refused = [403, 503].contains($0); _ = $1; done.signal()
                    }
                    guard done.wait(timeout: .now() + 40) == .success else { throw OwnerGatewayError.unavailable }
                    let auth = DispatchSemaphore(value: 0)
                    var authorized = true
                    previous.authorizeSetup(Data(repeating: 0x41, count: 32)) { authorized = $0; auth.signal() }
                    guard auth.wait(timeout: .now() + 40) == .success else { throw OwnerGatewayError.unavailable }
                    checks["retired_channel_refuses_setup_input"] = refused && !authorized
                    reply((try? JSONSerialization.data(withJSONObject: ["pid": getpid(), "checks": checks])) ?? Data())
                    return
                }
                let value = try JSONSerialization.jsonObject(with: peerPolicy) as! [String: Any]
                let uid = (value["uid"] as! NSNumber).uint32Value
                let peer: OwnerGatewayPeer
                if let team = value["team"] as? String {
                    peer = try OwnerGatewayPeer(uid: uid, team: team, identifier: value["identifier"] as! String,
                                                codeHashes: [value["hash"] as! String])
                } else { peer = try .fixture(uid: uid, codeHash: value["hash"] as! String) }
                let channel = OwnerGatewayConnection(endpoint: endpoint, peer: peer)
                client = channel
                let ready = DispatchSemaphore(value: 0)
                var prepared = false
                channel.prepare { prepared = $0; ready.signal() }
                guard ready.wait(timeout: .now() + 40) == .success else { throw OwnerGatewayError.unavailable }
                checks["prepared"] = prepared
                if prepared && mode == "hold" {
                    let auth = DispatchSemaphore(value: 0)
                    var authorized = false
                    channel.authorizeSetup(Data(repeating: 0x41, count: 32)) { authorized = $0; auth.signal() }
                    guard auth.wait(timeout: .now() + 40) == .success else { throw OwnerGatewayError.unavailable }
                    checks["held_channel_authorized"] = authorized
                    self.lock.lock(); let previous = self.held; self.held = channel; self.lock.unlock()
                    previous?.invalidate()
                    client = nil // Retain it across the parent's generation change.
                }
                if prepared && mode == "fresh" {
                    let done = DispatchSemaphore(value: 0)
                    var refused = false
                    channel.request("owner/grant", body: Data("{}".utf8)) {
                        refused = $0 == 403; _ = $1; done.signal()
                    }
                    guard done.wait(timeout: .now() + 40) == .success else { throw OwnerGatewayError.unavailable }
                    checks["fresh_channel_needs_setup_authorization"] = refused
                }
                if !prepared {
                    let done = DispatchSemaphore(value: 0)
                    var authorized = true
                    channel.authorizeSetup(Data(repeating: 0x41, count: 32)) { authorized = $0; done.signal() }
                    guard done.wait(timeout: .now() + 5) == .success else { throw OwnerGatewayError.unavailable }
                    checks["failed_prepare_refuses_setup_form"] = !authorized
                    let requestDone = DispatchSemaphore(value: 0)
                    var refused = false
                    let body = try JSONSerialization.data(withJSONObject: ["account": "demo-web", "password": "controlled-demo-password-only"])
                    channel.request("owner/credential", body: body) { refused = $0 == 503 && !$1.isEmpty; requestDone.signal() }
                    guard requestDone.wait(timeout: .now() + 5) == .success else { throw OwnerGatewayError.unavailable }
                    checks["failed_prepare_refuses_credential_request"] = refused
                }
                if prepared && mode == "journey" {
                    func request(_ path: String, _ body: [String: Any]? = nil) throws -> (Int, [String: Any]) {
                        let done = DispatchSemaphore(value: 0)
                        var result: (Int, Data)?
                        channel.request(path, body: try body.map { try JSONSerialization.data(withJSONObject: $0) }) {
                            result = ($0, $1); done.signal()
                        }
                        guard done.wait(timeout: .now() + 40) == .success, let result,
                              let payload = try JSONSerialization.jsonObject(with: result.1) as? [String: Any] else {
                            throw OwnerGatewayError.invalidResponse
                        }
                        return (result.0, payload)
                    }
                    let state = try request("owner/state")
                    checks["signed_owner_state"] = state.0 == 200 && state.1["accounts"] is [[String: Any]]
                    let grant: [String: Any] = ["account": "demo-web", "principal": "gateway-qa", "operations": ["summary"]]
                    let blocked = try request("owner/grant", grant)
                    checks["setup_needs_authorization"] = blocked.0 == 403
                        && blocked.1["reason"] as? String == "owner_setup_authorization_required"
                    let auth = DispatchSemaphore(value: 0)
                    var authorized = false
                    // A deliberately synthetic verifier, compiled into QA only.
                    // This does not test a genuine owner authorization approval.
                    channel.authorizeSetup(Data(repeating: 0x41, count: 32)) { authorized = $0; auth.signal() }
                    guard auth.wait(timeout: .now() + 40) == .success else { throw OwnerGatewayError.unavailable }
                    checks["fixture_setup_authorized"] = authorized
                    let granted = try request("owner/grant", grant)
                    checks["authorized_grant_reached_broker"] = granted.0 == 200
                    let source = try request("owner/source", ["source": "demo-totp", "credential": ["seed": "JBSWY3DPEHPK3PXP"]])
                    checks["authorized_authenticator_setup_reached_broker"] = source.0 == 200
                    let csv = "name,url,username,password\nExample," + (value["login_url"] as! String)
                        + ",demo@example.test,controlled-demo-password-only\n"
                    let preview = try request("owner/import/preview", ["csv": csv])
                    checks["authorized_csv_preview_reached_broker"] = preview.0 == 200 && preview.1["id"] is String
                    let joined = try JSONSerialization.data(withJSONObject: [state.1, granted.1, source.1, preview.1])
                    let text = String(data: joined, encoding: .utf8) ?? ""
                    checks["fixture_password_and_seed_not_returned"] = !text.contains("controlled-demo-password-only")
                        && !text.contains("JBSWY3DPEHPK3PXP")
                    let end = DispatchSemaphore(value: 0)
                    channel.endSetup { end.signal() }
                    guard end.wait(timeout: .now() + 40) == .success else { throw OwnerGatewayError.unavailable }
                    let after = try request("owner/grant", grant)
                    checks["ended_setup_cannot_grant"] = after.0 == 403
                    let revoke = try request("owner/revoke", ["account": "demo-web"])
                    checks["revocation_does_not_need_setup_auth"] = revoke.0 == 200
                    let refreshed = try request("owner/state")
                    checks["state_read_after_revocation"] = refreshed.0 == 200
                    channel.invalidate()
                    let closed = try request("owner/credential", ["account": "demo-web", "credential": [:]])
                    checks["closed_channel_refuses_setup_input"] = closed.0 == 503
                }
            } catch { checks["unexpected_error"] = true }
            client?.invalidate()
            reply((try? JSONSerialization.data(withJSONObject: ["pid": getpid(), "checks": checks])) ?? Data())
        }
    }
}

final class OwnerGatewayProbeDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: OwnerGatewayProbeRPC.self)
        connection.exportedObject = OwnerGatewayProbe()
        connection.resume()
        return true
    }
}

@main struct OwnerGatewayProbeMain {
    static func main() {
        let delegate = OwnerGatewayProbeDelegate()
        let listener = NSXPCListener.service()
        listener.delegate = delegate
        listener.resume()
    }
}
#endif
