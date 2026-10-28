import Foundation
import Darwin

@main struct BrowserNativeHostChecks {
    static func main() throws {
        var checks: [String: Bool] = [:]
        checks["shell_cannot_impersonate_chrome_parent"] = !BrowserNativeHost.chromeParentAuthorized()
            && BrowserNativeHost.run(arguments: [BrowserNativeHost.origin]) == 78
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ac-browser-native-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        func frame(_ value: [String: Any]) throws -> Data {
            let raw = try JSONSerialization.data(withJSONObject: value)
            var count = UInt32(raw.count).littleEndian
            return withUnsafeBytes(of: &count) { Data($0) } + raw
        }
        var requests = 0
        var failRequest = false
        func exchange(_ input: Data, origin: String = BrowserNativeHost.origin) throws -> (Int32, Data) {
            let incoming = directory.appendingPathComponent("in"), outgoing = directory.appendingPathComponent("out")
            try input.write(to: incoming); try Data().write(to: outgoing)
            let read = try FileHandle(forReadingFrom: incoming), write = try FileHandle(forWritingTo: outgoing)
            defer { try? read.close(); try? write.close() }
            let status = BrowserNativeHost.serve(input: read, output: write, presentedOrigin: origin) { _ in
                requests += 1
                if failRequest { throw CocoaError(.fileReadUnknown, userInfo: [NSLocalizedDescriptionKey: "fixture-private-value"]) }
                return ["pending": [], "source_enabled": false]
            }
            return (status, try Data(contentsOf: outgoing))
        }
        let pending = try frame(["id": 7, "body": ["method": "pending"]])
        let reply = try exchange(pending)
        let decoded = try JSONSerialization.jsonObject(with: reply.1.dropFirst(4)) as! [String: Any]
        checks["framed_pending_reaches_fixed_bridge"] = reply.0 == 0 && requests == 1 && decoded["id"] as? Int == 7
        checks["wrong_origin_refused_before_request"] = try exchange(pending, origin: "chrome-extension://other/").0 == 78 && requests == 1
        for (name, bytes) in [("partial_header", Data([1, 0])), ("empty_frame", Data([0, 0, 0, 0])),
                              ("oversized_frame", Data([1, 0, 1, 0])), ("partial_body", pending.dropLast())] {
            checks[name + "_refused"] = try exchange(bytes).0 == 78 && requests == 1
        }
        for (name, body) in [("cookies", ["method": "session-import"]),
                             ("owner_route", ["method": "owner/credential"]),
                             ("arbitrary_path", ["method": "pending", "path": "/tmp/selected"])] {
            let response = try exchange(frame(["id": 8, "body": body]))
            checks[name + "_refused"] = response.0 == 0 && requests == 1 && String(decoding: response.1, as: UTF8.self).contains("unsupported_browser_connection_request")
        }
        let badID = try exchange(frame(["id": true, "body": ["method": "pending"]]))
        checks["boolean_message_id_refused"] = badID.0 == 0 && requests == 1
        failRequest = true
        let failure = try exchange(pending)
        checks["transport_failure_does_not_echo_details"] = failure.0 == 0 && !String(decoding: failure.1, as: UTF8.self).contains("fixture-private-value")

        final class Backend: OwnerGatewayBackend {
            var calls = 0
            func request(_ route: OwnerGatewayRoute) throws -> (Int, Data) {
                calls += 1; return (200, Data("{}".utf8))
            }
        }
        let backend = Backend()
        let session = OwnerGatewaySession.fixture(backend: backend, authorize: { $0 == Data(repeating: 3, count: 32) })
        let poll = try JSONSerialization.data(withJSONObject: ["message": ["method": "pending"]])
        let connect = try JSONSerialization.data(withJSONObject: ["message": ["method": "connect", "account": "fixture", "fingerprint": String(repeating: "a", count: 64)]])
        var status = 0
        session.request("owner/browser-message", body: poll) { status = $0; _ = $1 }
        checks["routine_poll_needs_no_owner_approval"] = status == 200 && backend.calls == 1
        session.request("owner/browser-message", body: connect) { status = $0; _ = $1 }
        checks["connection_without_approval_never_reaches_worker"] = status == 403 && backend.calls == 1
        session.authorizeSetup(Data(repeating: 3, count: 32)) { precondition($0) }
        session.request("owner/browser-message", body: connect) { status = $0; _ = $1 }
        checks["approved_connection_reaches_worker_once"] = status == 200 && backend.calls == 2
        session.endSetup {}
        let message: [String: Any] = ["method": "deliver", "source": "fixture", "window": String(repeating: "b", count: 32),
            "messages": [["id": String(repeating: "c", count: 64), "code": "123456", "observed_at": Date().timeIntervalSince1970]]]
        let delivery = try JSONSerialization.data(withJSONObject: ["message": message])
        session.request("owner/browser-message", body: delivery) { status = $0; _ = $1 }
        checks["routine_delivery_needs_no_new_approval"] = status == 200 && backend.calls == 3
        var malformed = message
        malformed["messages"] = [["id": String(repeating: "c", count: 64), "code": "123456", "observed_at": true]]
        let invalid = try JSONSerialization.data(withJSONObject: ["message": malformed])
        checks["boolean_delivery_time_refused"] = (try? OwnerGatewayRoute("owner/browser-message", body: invalid)) == nil
        session.close()
        session.request("owner/browser-message", body: poll) { status = $0; _ = $1 }
        checks["closed_connection_cannot_poll"] = status == 403 && backend.calls == 3
        let report: [String: Any] = ["status": checks.values.allSatisfy({ $0 }) ? "PASSED" : "FAILED", "checks": checks,
            "environment": "controlled-demo", "production_ready": false, "private_signins": 0,
            "actual_native_xpc_used": false, "genuine_owner_approval_verified": false]
        print(String(decoding: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), as: UTF8.self))
        if checks.values.contains(false) { exit(1) }
    }
}
