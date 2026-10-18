import Foundation
import Network

@main struct MailboxOAuthLoopbackChecks {
    static func main() throws {
        var checks: [String: Bool] = [:]
        let account = "fixture-mail", state = String(repeating: "S", count: 48), port: UInt16 = 52781
        func raw(_ target: String, host: String = "127.0.0.1:52781", method: String = "GET", extra: String = "") -> Data {
            Data("\(method) \(target) HTTP/1.1\r\nHost: \(host)\r\n\(extra)\r\n".utf8)
        }
        let target = "/callback/fixture-mail?code=synthetic-code&state=" + state
        func accepts(_ value: Data) -> Bool {
            MailboxOAuthLoopback.callback(value, port: port, account: account, state: state) != nil
        }
        checks["exact_state_bound_get_accepted"] = accepts(raw(target))
        checks["provider_denial_accepted_as_callback"] = accepts(raw("/callback/fixture-mail?error=access_denied&state=" + state))
        checks["wrong_host_refused"] = !accepts(raw(target, host: "localhost:52781"))
            && !accepts(raw(target, host: "127.0.0.1:52782"))
        checks["wrong_path_and_method_refused"] = !accepts(raw(target.replacingOccurrences(of: "fixture-mail?", with: "other?")))
            && !accepts(raw(target, method: "POST"))
        checks["missing_wrong_and_duplicate_state_refused"] = !accepts(raw("/callback/fixture-mail?code=x"))
            && !accepts(raw(target.replacingOccurrences(of: state, with: "wrong")))
            && !accepts(raw(target + "&state=" + state))
        checks["ambiguous_or_empty_provider_result_refused"] = !accepts(raw(target + "&code=other"))
            && !accepts(raw(target + "&error=access_denied"))
            && !accepts(raw("/callback/fixture-mail?code=&state=" + state))
        checks["duplicate_host_and_http_body_refused"] = !accepts(raw(target, extra: "Host: 127.0.0.1:52781\r\n"))
            && !accepts(raw(target, extra: "Content-Length: 1\r\n"))
            && !accepts(raw(target) + Data("x".utf8))
        checks["chunked_and_fragment_requests_refused"] = !accepts(raw(target, extra: "Transfer-Encoding: chunked\r\n"))
            && !accepts(raw(target + "#fragment"))
        checks["oversized_and_incomplete_headers_refused"] = !accepts(raw(target + String(repeating: "x", count: 8192)))
            && !accepts(Data("GET /callback/fixture-mail HTTP/1.1\r\n".utf8))

        func authorization(_ listener: MailboxOAuthLoopback, host: String = "accounts.google.com") -> String {
            var parts = URLComponents(string: "https://" + host + "/o/oauth2/v2/auth")!
            parts.queryItems = [URLQueryItem(name: "client_id", value: "public-fixture-client"),
                URLQueryItem(name: "state", value: state), URLQueryItem(name: "response_type", value: "code"),
                URLQueryItem(name: "redirect_uri", value: listener.redirectURI),
                URLQueryItem(name: "code_challenge_method", value: "S256"),
                URLQueryItem(name: "code_challenge", value: String(repeating: "A", count: 43))]
            return parts.string!
        }
        let listener = try MailboxOAuthLoopback(account: account)
        defer { listener.close() }
        checks["listener_uses_literal_loopback_random_port"] = listener.redirectURI.hasPrefix("http://127.0.0.1:")
            && listener.redirectURI.hasSuffix("/callback/" + account)
        checks["unrelated_authorization_origin_refused"] = (try? listener.authorize(authorization(listener, host: "accounts.google.com.example.test"))) == nil
        checks["weakened_pkce_or_changed_redirect_refused"] = (try? listener.authorize(authorization(listener).replacingOccurrences(of: "S256", with: "plain"))) == nil
            && (try? listener.authorize(authorization(listener).replacingOccurrences(of: "127.0.0.1", with: "localhost"))) == nil
        _ = try listener.authorize(authorization(listener))
        checks["authorization_can_only_be_armed_once"] = (try? listener.authorize(authorization(listener))) == nil
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        func get(_ value: String) -> (Int?, String) {
            let done = DispatchSemaphore(value: 0)
            var status: Int?, body = ""
            var request = URLRequest(url: URL(string: value)!)
            request.timeoutInterval = 3
            session.dataTask(with: request) { data, response, _ in
                status = (response as? HTTPURLResponse)?.statusCode
                body = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                done.signal()
            }.resume()
            _ = done.wait(timeout: .now() + 5)
            return (status, body)
        }
        let wrong = get(listener.redirectURI + "?code=synthetic-code&state=wrong")
        checks["real_wrong_state_request_does_not_consume_listener"] = wrong.0 == 400 && !wrong.1.contains("synthetic-code")
        let callbackDone = DispatchSemaphore(value: 0)
        var received: String?
        DispatchQueue.global().async {
            received = try? listener.wait(timeout: 5)
            callbackDone.signal()
        }
        let valid = get(listener.redirectURI + "?code=synthetic-code&state=" + state)
        checks["actual_loopback_callback_completes_once_without_echoing_code"] = valid.0 == 200
            && !valid.1.contains("synthetic-code") && callbackDone.wait(timeout: .now() + 5) == .success
            && received == listener.redirectURI + "?code=synthetic-code&state=" + state
        checks["consumed_listener_cannot_be_waited_again"] = (try? listener.wait(timeout: 0.1)) == nil
        listener.close()
        checks["closed_listener_refuses_replay"] = get(listener.redirectURI + "?code=synthetic-code&state=" + state).0 == nil
        let timed = try MailboxOAuthLoopback(account: account)
        _ = try timed.authorize(authorization(timed))
        do { _ = try timed.wait(timeout: 0.05); checks["timeout_closes_listener"] = false }
        catch MailboxOAuthFailure.timedOut { checks["timeout_closes_listener"] = true }
        timed.close()
        let cancelled = try MailboxOAuthLoopback(account: account)
        _ = try cancelled.authorize(authorization(cancelled))
        cancelled.close()
        checks["explicit_cancellation_stops_callback_wait"] = (try? cancelled.wait(timeout: 0.1)) == nil
        func route(_ name: String, _ body: [String: Any]) -> OwnerGatewayRoute? {
            try? OwnerGatewayRoute("owner/mailbox/oauth/" + name, body: JSONSerialization.data(withJSONObject: body))
        }
        let startBody: [String: Any] = ["account": account, "fingerprint": String(repeating: "a", count: 64),
                                        "redirect_uri": "http://127.0.0.1:52781/callback/" + account]
        let finishBody: [String: Any] = ["account": account, "attempt": String(repeating: "b", count: 32),
                                         "callback": "http://127.0.0.1:52781" + target]
        checks["native_begin_and_finish_require_owner_presence"] = route("begin", startBody)?.requiresSetup == true
            && route("finish", finishBody)?.requiresSetup == true
        let checkBody = ["account": account, "fingerprint": String(repeating: "a", count: 64)]
        checks["native_google_identity_check_requires_owner_presence"] = route("check", checkBody)?.requiresSetup == true
        checks["native_google_identity_check_rejects_short_fingerprint"] = route("check", ["account": account, "fingerprint": "short"]) == nil
        checks["native_google_identity_check_rejects_destination_injection"] = route("check", ["account": account, "fingerprint": String(repeating: "a", count: 64), "url": "https://example.test"]) == nil
        checks["native_cancellation_does_not_request_owner_presence"] = route("cancel", ["account": account, "attempt": String(repeating: "b", count: 32)])?.requiresSetup == false
        var changed = startBody; changed["redirect_uri"] = "http://localhost:52781/callback/" + account
        var injected = startBody; injected["authorization_url"] = "https://example.test"
        checks["native_gateway_refuses_destination_injection"] = route("begin", changed) == nil && route("begin", injected) == nil
        changed = finishBody; changed["callback"] = "https://example.test/callback/" + account
        injected = finishBody; injected["attempt"] = "short"
        checks["native_gateway_refuses_foreign_callback_and_bad_attempt"] = route("finish", changed) == nil && route("finish", injected) == nil
        let result: [String: Any] = ["schema": 1, "status": checks.values.allSatisfy({ $0 }) ? "VERIFIED" : "FAILED",
                                   "checks": checks, "private_signins": 0, "google_consent_verified": false]
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys]))
        if !checks.values.allSatisfy({ $0 }) { exit(1) }
    }
}
