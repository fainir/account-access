import Foundation
import Security
import Darwin

final class CheckedOwnerBackend: OwnerGatewayBackend {
    let wrapped: OwnerGatewayBackend
    let capability: String
    private let lock = NSLock()
    private var count = 0
    private var mutations = 0
    private var routes: [String] = []
    private var exposed = false
    var calls: Int { lock.lock(); defer { lock.unlock() }; return count }
    var writes: Int { lock.lock(); defer { lock.unlock() }; return mutations }
    var paths: [String] { lock.lock(); defer { lock.unlock() }; return routes }
    var leaked: Bool { lock.lock(); defer { lock.unlock() }; return exposed }
    init(_ wrapped: OwnerGatewayBackend, capability: String) { self.wrapped = wrapped; self.capability = capability }
    func request(_ route: OwnerGatewayRoute) throws -> (Int, Data) {
        lock.lock(); count += 1; mutations += route.body == nil ? 0 : 1; routes.append(route.path); lock.unlock()
        let result = try wrapped.request(route)
        let text = String(data: result.1, encoding: .utf8) ?? ""
        lock.lock(); exposed = exposed || text.contains(capability); lock.unlock()
        return result
    }
}

enum GatewayChecks {
    static var probePIDs: Set<pid_t> = []
    static func signing(_ url: URL) throws -> [String: Any] {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess else { throw OwnerGatewayError.invalidPolicy }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let value = info as? [String: Any], let hash = value[kSecCodeInfoUnique as String] as? Data,
              let identifier = value[kSecCodeInfoIdentifier as String] as? String else { throw OwnerGatewayError.invalidPolicy }
        var result: [String: Any] = ["uid": getuid(), "hash": hash.map { String(format: "%02x", $0) }.joined(), "identifier": identifier]
        let flags = (value[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        result["hardened_runtime"] = flags & SecCodeSignatureFlags.runtime.rawValue != 0
        if let team = value[kSecCodeInfoTeamIdentifier as String] as? String { result["team"] = team }
        return result
    }
    static func peer(_ value: [String: Any], uid: uid_t? = nil) throws -> OwnerGatewayPeer {
        let uid = uid ?? (value["uid"] as! NSNumber).uint32Value
        if let team = value["team"] as? String {
            return try OwnerGatewayPeer(uid: uid, team: team, identifier: value["identifier"] as! String,
                                        codeHashes: [value["hash"] as! String])
        }
        return try .fixture(uid: uid, codeHash: value["hash"] as! String)
    }

    static func invoke(_ service: String, endpoint: NSXPCListenerEndpoint, policy: [String: Any], mode: String) throws -> [String: Bool] {
        let connection = NSXPCConnection(serviceName: service)
        connection.remoteObjectInterface = NSXPCInterface(with: OwnerGatewayProbeRPC.self)
        connection.resume()
        defer { connection.invalidate() }
        let done = DispatchSemaphore(value: 0)
        var response: Data?
        var failed = false
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in failed = true; done.signal() }) as? OwnerGatewayProbeRPC else {
            throw OwnerGatewayError.unavailable
        }
        proxy.run(endpoint, peerPolicy: try JSONSerialization.data(withJSONObject: policy), mode: mode) {
            response = $0; done.signal()
        }
        guard done.wait(timeout: .now() + 100) == .success, !failed, let response,
              let value = try JSONSerialization.jsonObject(with: response) as? [String: Any],
              let checks = value["checks"] as? [String: Bool] else { throw OwnerGatewayError.invalidResponse }
        if let pid = value["pid"] as? NSNumber, pid.int32Value > 0, pid.int32Value != getpid() {
            probePIDs.insert(pid.int32Value)
        }
        return checks
    }
    static func quit(_ service: String) {
        let connection = NSXPCConnection(serviceName: service)
        connection.remoteObjectInterface = NSXPCInterface(with: OwnerGatewayProbeRPC.self)
        connection.resume()
        let done = DispatchSemaphore(value: 0)
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in done.signal() } as? OwnerGatewayProbeRPC
        proxy?.quit { done.signal() }
        _ = done.wait(timeout: .now() + 5)
        connection.invalidate()
    }

    static func pureChecks() throws -> [String: Bool] {
        let definition = OwnerSetupAuthorization.definition
        var result = ["dedicated_owner_rule_validated": OwnerSetupAuthorization.validDefinition(definition)]
        let peer = try OwnerGatewayPeer(uid: getuid(), team: "WBULD6N4NQ", identifier: "com.fainir.accountaccess",
                                        codeHashes: [String(repeating: "0", count: 40)])
        result["production_peer_requirement_compiles"] = !peer.requirement.isEmpty
        result["code_identity_injection_rejected"] = (try? OwnerGatewayPeer(uid: getuid(), team: "BAD\" or true",
            identifier: "com.fainir.accountaccess", codeHashes: [String(repeating: "0", count: 40)])) == nil
        for (label, field, value) in [("root_shortcut", "allow-root", true as Any),
            ("shared_credentials", "shared", true), ("no_user_auth", "authenticate-user", false),
            ("non_owner_auth", "session-owner", false), ("indefinite_auth", "timeout", 2147483647),
            ("numeric_boolean", "authenticate-user", 1), ("boolean_timeout", "timeout", true),
            ("fractional_timeout", "timeout", 30.1), ("unlimited_tries", "tries", 10000)] {
            var changed = definition; changed[field] = value
            result["reject_" + label] = !OwnerSetupAuthorization.validDefinition(changed)
        }
        var changed = definition; changed["class"] = "allow"
        result["allow_authorization_rule_rejected"] = !OwnerSetupAuthorization.validDefinition(changed)
        result["legacy_long_lived_delegation_rejected"] = !OwnerSetupAuthorization.validDefinition([
            "class": "rule", "rule": [kAuthorizationRuleAuthenticateAsSessionUser]])
        result["short_os_authorization_rejected"] = !OwnerSetupAuthorization.check(Data(repeating: 0, count: 31))
        var reference: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess, let reference else {
            throw OwnerGatewayError.unavailable
        }
        defer { AuthorizationFree(reference, [.destroyRights]) }
        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(reference, &form) == errAuthorizationSuccess else { throw OwnerGatewayError.unavailable }
        let external = withUnsafeBytes(of: &form) { Data($0) }
        var imported: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&form, &imported) == errAuthorizationSuccess, let imported else {
            throw OwnerGatewayError.unavailable
        }
        defer { AuthorizationFree(imported, []) }
        result["os_right_without_approval_denied"] = OwnerSetupAuthorization.right.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                return AuthorizationCopyRights(imported, &rights, nil, [], nil) != errAuthorizationSuccess
            }
        }
        result["unconfigured_or_ungranted_setup_rejected"] = !OwnerSetupAuthorization.check(external)
        let grant = try JSONSerialization.data(withJSONObject: ["account": "demo-web"])
        for (name, route) in [("query_route", "owner/grant?x=1"), ("traversal_route", "owner/../grant"),
            ("external_route", "https://example.test"), ("local_install_route", "owner/install"),
            ("browser_handoff_route", "owner/browser-session/start")] {
            result["reject_" + name] = (try? OwnerGatewayRoute(route, body: grant)) == nil
        }
        for (name, header) in [("duplicate_http_length", "HTTP/1.0 200 OK\r\nContent-Length: 2\r\ncontent-length: 2"),
            ("chunked_http", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2"),
            ("http_redirect", "HTTP/1.1 302 Found\r\nContent-Length: 2"),
            ("oversized_http", "HTTP/1.0 200 OK\r\nContent-Length: 8000001")] {
            result["reject_" + name] = (try? OwnerUnixBackend.responseHeader(Data(header.utf8))) == nil
        }
        let good = try OwnerUnixBackend.responseHeader(Data("HTTP/1.0 200 OK\r\nContent-Length: 2".utf8))
        result["bounded_http_framing"] = good.0 == 200 && good.1 == 2
        final class Echo: OwnerGatewayBackend {
            func request(_ route: OwnerGatewayRoute) throws -> (Int, Data) { (200, Data("{}".utf8)) }
        }
        var now: TimeInterval = 100
        let session = OwnerGatewaySession.fixture(backend: Echo(), authorize: { $0 == Data(repeating: 0x41, count: 32) }, clock: { now })
        var accepted = false
        session.authorizeSetup(Data(repeating: 0x41, count: 32)) { accepted = $0 }
        result["fixture_setup_session_authorizes"] = accepted
        now = 701
        session.request("owner/grant", body: grant) { result["setup_session_expires"] = $0 == 403 && !$1.isEmpty }
        session.close()
        session.authorizeSetup(Data(repeating: 0x41, count: 32)) { result["closed_session_cannot_reauthorize"] = !$0 }
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        let racing = OwnerGatewaySession.fixture(backend: Echo(), authorize: { _ in
            entered.signal(); return release.wait(timeout: .now() + 5) == .success
        })
        final class Outcome: @unchecked Sendable {
            private let lock = NSLock()
            private var value = true
            func save(_ value: Bool) { lock.lock(); self.value = value; lock.unlock() }
            var reopened: Bool { lock.lock(); defer { lock.unlock() }; return value }
        }
        let outcome = Outcome()
        DispatchQueue.global().async {
            racing.authorizeSetup(Data(repeating: 0x41, count: 32)) { outcome.save($0); finished.signal() }
        }
        guard entered.wait(timeout: .now() + 5) == .success else { throw OwnerGatewayError.unavailable }
        racing.close(); release.signal()
        guard finished.wait(timeout: .now() + 5) == .success else { throw OwnerGatewayError.unavailable }
        result["authorization_cannot_survive_disconnect"] = !outcome.reopened
        return result
    }
}

@main struct OwnerGatewayChecksMain {
    static func main() {
        var stage = "initial"
        var trusted = "", denied = ""
        var helpersStopped = false
        func stopHelpers() {
            guard !helpersStopped else { return }
            helpersStopped = true
            if !trusted.isEmpty { GatewayChecks.quit(trusted) }
            if !denied.isEmpty { GatewayChecks.quit(denied) }
        }
        defer { stopHelpers() }
        do {
            let input = FileHandle.standardInput.readDataToEndOfFile()
            guard input.count <= 4096, let values = try JSONSerialization.jsonObject(with: input) as? [String: Any],
                  let path = values["socket"] as? String, let capability = values["capability"] as? String,
                  let trustedID = values["trusted_service"] as? String, let deniedID = values["denied_service"] as? String else {
                throw OwnerGatewayError.invalidPolicy
            }
            trusted = trustedID; denied = deniedID
            stage = "pure_policy"
            var checks = try GatewayChecks.pureChecks()
            stage = "private_unix_backend"
            let backend = CheckedOwnerBackend(try OwnerUnixBackend.fixture(path: path, capability: capability, port: 8765), capability: capability)
            let bundle = Bundle.main.bundleURL
            let trustedURL = bundle.appendingPathComponent("Contents/XPCServices/TrustedProbe.xpc")
            let deniedURL = bundle.appendingPathComponent("Contents/XPCServices/DeniedProbe.xpc")
            stage = "trusted_signature"
            let trustedSignature = try GatewayChecks.signing(trustedURL)
            stage = "denied_signature"
            let deniedSignature = try GatewayChecks.signing(deniedURL)
            checks["test_clients_have_distinct_code_hashes"] = trustedSignature["hash"] as? String != deniedSignature["hash"] as? String
            stage = "host_signature"
            let ownSignature = try GatewayChecks.signing(bundle)
            checks["hardened_test_peers"] = [ownSignature, trustedSignature, deniedSignature]
                .allSatisfy { $0["hardened_runtime"] as? Bool == true }
            var serverPolicy = ownSignature
            serverPolicy["login_url"] = values["login_url"]
            stage = "construct_peer_requirement"
            let delegate = OwnerGatewayListener(peer: try GatewayChecks.peer(trustedSignature), makeSession: {
                .fixture(backend: backend, authorize: { $0 == Data(repeating: 0x41, count: 32) })
            })
            let listener = NSXPCListener.anonymous()
            listener.delegate = delegate
            listener.resume()
            defer { listener.invalidate() }
            stage = "trusted_xpc_journey"
            let journey = try GatewayChecks.invoke(trustedID, endpoint: listener.endpoint, policy: serverPolicy, mode: "journey")
            guard journey["unexpected_error"] != true else { throw OwnerGatewayError.unavailable }
            checks.merge(journey) { _, current in current }
            let before = backend.calls
            stage = "untrusted_xpc_peer"
            let untrusted = try GatewayChecks.invoke(deniedID, endpoint: listener.endpoint, policy: serverPolicy, mode: "denied")
            checks["untrusted_helper_ran"] = untrusted["helper_ran"] == true
            checks["untrusted_code_cannot_reach_gateway"] = untrusted["prepared"] == false && backend.calls == before
            stage = "wrong_server_signature"
            let beforeWrites = backend.writes
            var wrong = serverPolicy; wrong["hash"] = String(repeating: "0", count: 40)
            let spoofed = try GatewayChecks.invoke(trustedID, endpoint: listener.endpoint, policy: wrong, mode: "denied")
            checks["client_rejects_wrong_server_code"] = spoofed["helper_ran"] == true && spoofed["prepared"] == false
                && spoofed["failed_prepare_refuses_setup_form"] == true && spoofed["failed_prepare_refuses_credential_request"] == true
                && backend.writes == beforeWrites && backend.paths.dropFirst(before).allSatisfy { $0 == "/owner/health" }
            stage = "wrong_owner_uid"
            let beforeUID = backend.calls
            let other = OwnerGatewayListener(peer: try GatewayChecks.peer(trustedSignature, uid: getuid() + 1), makeSession: {
                .fixture(backend: backend, authorize: { _ in true })
            })
            let otherListener = NSXPCListener.anonymous(); otherListener.delegate = other; otherListener.resume()
            defer { otherListener.invalidate() }
            let wrongUID = try GatewayChecks.invoke(trustedID, endpoint: otherListener.endpoint, policy: serverPolicy, mode: "denied")
            checks["different_owner_uid_rejected"] = wrongUID["helper_ran"] == true && wrongUID["prepared"] == false && backend.calls == beforeUID
            checks["owner_capability_never_returned"] = !backend.leaked
            checks["actual_python_owner_api_reached"] = backend.calls >= 7
            stopHelpers()
            let deadline = Date().addingTimeInterval(5)
            while Date() < deadline && GatewayChecks.probePIDs.contains(where: { kill($0, 0) == 0 }) {
                Thread.sleep(forTimeInterval: 0.05)
            }
            checks["test_helpers_exited"] = !GatewayChecks.probePIDs.isEmpty
                && GatewayChecks.probePIDs.allSatisfy { kill($0, 0) != 0 && errno == ESRCH }
            guard checks.values.allSatisfy({ $0 }) else {
                print(String(data: try JSONSerialization.data(withJSONObject: ["status": "FAILED", "stage": stage,
                    "failed_checks": checks.filter { !$0.value }.keys.sorted()]), encoding: .utf8)!)
                exit(1)
            }
            let output: [String: Any] = ["status": "PASSED", "environment": "controlled-demo", "platform": "macos",
                "production_ready": false, "private_signins": 0, "checks": checks,
                "publisher_signed_peers": ownSignature["team"] != nil
                    && ownSignature["team"] as? String == trustedSignature["team"] as? String
                    && ownSignature["team"] as? String == deniedSignature["team"] as? String,
                "real_owner_auth_approval_tested": false, "root_service_installed": false]
            print(String(data: try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8)!)
        } catch {
            stopHelpers()
            print("{\"status\":\"FAILED\",\"stage\":\"" + stage + "\",\"production_ready\":false}")
            exit(1)
        }
    }
}
