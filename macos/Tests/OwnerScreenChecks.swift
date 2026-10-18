import AppKit
import Foundation
import CryptoKit

final class VerificationRetryFixture: URLProtocol {
    static var verificationRequests = 0
    static var retriedVisible = false
    static var retried = false
    static var stopped = false
    static var ownerPort = 1
    static var ownerToken = "synthetic-ui-session"
    static var invalidProof = false
    static var loseNextSetupResponse = false
    static var ownerRequests = 0
    static var pauseRequests = 0
    static let instanceKey = Data(repeating: 0xaa, count: 32)
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let payload: [String: Any]
        precondition(request.url?.port == Self.ownerPort)
        precondition(request.value(forHTTPHeaderField: "Authorization") == "Bearer " + Self.ownerToken)
        if request.url?.path == "/owner/ready" {
            let challenge = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
                .queryItems!.first(where: { $0.name == "challenge" })!.value!
            let proof = HMAC<SHA256>.authenticationCode(for: Data(challenge.utf8), using: SymmetricKey(data: Self.instanceKey))
                .map { String(format: "%02x", $0) }.joined()
            payload = ["proof": Self.invalidProof ? "unverified" : proof]
        } else if request.url?.path == "/owner/stop" {
            Self.ownerRequests += 1
            Self.pauseRequests += 1
            payload = ["status": "STOPPED"]
        } else if Self.stopped {
            Self.ownerRequests += 1
            payload = ["connection_jobs": ["first": ["status": "NEEDS_USER", "attention": ["reason": "browser_action_required"]]]]
        } else if request.url?.path == "/owner/verify" {
            Self.ownerRequests += 1
            Self.verificationRequests += 1
            if Self.loseNextSetupResponse {
                Self.loseNextSetupResponse = false
                client?.urlProtocol(self, didFailWithError: URLError(.networkConnectionLost))
                return
            }
            var body = request.httpBody
            if body == nil, let stream = request.httpBodyStream {
                stream.open(); defer { stream.close() }
                var bytes = [UInt8](repeating: 0, count: 1024)
                let count = stream.read(&bytes, maxLength: bytes.count)
                if count > 0 { body = Data(bytes.prefix(count)) }
            }
            let input = body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            Self.retriedVisible = input?["visible"] as? Bool == true && input?["account"] as? String == "fixture"
            Self.retried = true
            payload = ["id": "second"]
        } else {
            Self.ownerRequests += 1
            payload = ["connection_jobs": Self.retried
                ? ["second": ["status": "CONNECTED"]] : ["first": ["status": "RETRYABLE"]]]
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                       headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: try! JSONSerialization.data(withJSONObject: payload))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class NativeOwnerScreenFixture: DesktopOwnerChannel {
    var isAvailable = false
    var enrollments = 0
    var lostNextEnrollment = false
    var clientEnrollments = 0
    let clientToken = String(repeating: "F", count: 43)
    var clientID: String { SHA256.hash(data: Data(clientToken.utf8)).map { String(format: "%02x", $0) }.joined() }
    var state: [String: Any] = ["accounts": [], "catalog": []]
    func prepare(reply: @escaping (Bool) -> Void) { isAvailable = true; reply(true) }
    func authorizeSetup(_ form: Data, reply: @escaping (Bool) -> Void) { reply(form.count == 32) }
    func request(_ route: String, body: Data?, reply: @escaping (Int, Data) -> Void) {
        if route == "owner/vault/enroll" {
            enrollments += 1
            if lostNextEnrollment {
                lostNextEnrollment = false
                reply(503, OwnerGatewaySession.failure("owner_channel_unavailable")); return
            }
            reply(202, Data("{\"vault_setup\":{\"status\":\"initializing\"}}".utf8)); return
        }
        if route == "owner/client/enroll" {
            clientEnrollments += 1
            reply(200, try! JSONSerialization.data(withJSONObject: ["status": "ENROLLED", "client_id": clientID, "principal": "generic"]))
            return
        }
        if route == "owner/client/installed" {
            state["managed_client"] = ["status": "INSTALLED", "client_id": clientID, "principal": "generic"]
            state["principals"] = ["generic"]
            reply(200, try! JSONSerialization.data(withJSONObject: ["status": "INSTALLED", "client_id": clientID, "principal": "generic"]))
            return
        }
        reply(200, try! JSONSerialization.data(withJSONObject: state))
    }
    func invalidate() { isAvailable = false }
}

@main struct OwnerScreenChecks {
    static func main() {
        let legacy = Bundle.main
        var attempts = 0
        precondition((try! OwnerApplicationBundle.select(system: false, main: legacy, installed: {
            attempts += 1; throw DesktopOwnerFailure.profile
        })) == legacy && attempts == 0)
        do {
            _ = try OwnerApplicationBundle.select(system: true, main: legacy, installed: {
                attempts += 1; throw DesktopOwnerFailure.profile
            })
            preconditionFailure("A rejected protected bundle fell back to Bundle.main")
        } catch { precondition(attempts == 1) }
        print("PASS: protected bundle validation cannot fall back to public alias resources")
        _ = NSApplication.shared
        let fixtureRoot = FileManager.default.temporaryDirectory.appendingPathComponent("account-access-native-" + UUID().uuidString)
        try! FileManager.default.createDirectory(at: fixtureRoot, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        setenv("ACCOUNT_ACCESS_DATA_DIR", fixtureRoot.path, 1)
        defer { try? FileManager.default.removeItem(at: fixtureRoot) }
        func saveOwner(port: Int, token: String) {
            let metadata: [String: Any] = ["url": "http://127.0.0.1:\(port)/", "token": token,
                "instance_key": String(repeating: "aa", count: 32)]
            let file = fixtureRoot.appendingPathComponent("desktop.json")
            try! JSONSerialization.data(withJSONObject: metadata).write(to: file, options: .atomic)
            try! FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        saveOwner(port: 1, token: VerificationRetryFixture.ownerToken)
        let export = fixtureRoot.appendingPathComponent("fictional-bitwarden.json")
        let exportText = "{\"encrypted\":false,\"items\":[]}"
        try! Data(exportText.utf8).write(to: export)
        precondition((try! AccountAccess.readPasswordExport(export)) == exportText)
        func rejectedExport(_ file: URL) -> Bool {
            do { _ = try AccountAccess.readPasswordExport(file); return false }
            catch { return true }
        }
        let alias = fixtureRoot.appendingPathComponent("linked.csv")
        try! FileManager.default.createSymbolicLink(at: alias, withDestinationURL: export)
        precondition(rejectedExport(alias))
        let fifo = fixtureRoot.appendingPathComponent("pipe.csv")
        precondition(mkfifo(fifo.path, 0o600) == 0 && rejectedExport(fifo))
        precondition(rejectedExport(fixtureRoot))
        try! Data([0xff, 0xfe, 0xfd]).write(to: export)
        precondition(rejectedExport(export))
        try! Data(repeating: 65, count: 4_000_001).write(to: export)
        precondition(rejectedExport(export))
        print("PASS: password files are bounded regular UTF-8 files; symlinks, pipes, directories and oversized exports are refused")
        let owner = AccountAccess()
        owner.window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 740),
                                styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        owner.base = URL(string: "http://127.0.0.1:1/")!
        owner.token = "synthetic-ui-session"
        owner.accounts = [["account": "fixture", "label": "Fixture account",
                           "route": "browser", "portable_ready": true]]
        owner.showPasswordSync()
        owner.window.contentView!.layoutSubtreeIfNeeded()
        precondition(Set(owner.syncFields.keys) == Set(["endpoint", "vault", "item", "token"]))
        precondition(owner.syncFields["token"] is NSSecureTextField)
        precondition(owner.syncFields["endpoint"]?.isHidden == true)
        precondition(owner.syncProvider.indexOfSelectedItem == 0)
        let sourceFields = ["endpoint": "", "vault": "fixture-vault", "item": "fixture-item", "token": "fixture-token"]
        let serviceConnection = AccountAccess.passwordSyncConnection(provider: 0, fields: sourceFields)!
        precondition(serviceConnection["provider"] == "onepassword-service-account" && serviceConnection["endpoint"] == nil)
        precondition(AccountAccess.passwordSyncConnection(provider: 1, fields: sourceFields) == nil)
        owner.syncFields["token"]?.stringValue = "fixture-token-to-clear"
        owner.syncProvider.selectItem(at: 1)
        owner.syncProviderChanged()
        precondition(owner.syncFields["endpoint"]?.isHidden == false && owner.syncFields["token"]?.stringValue == "")
        owner.window.contentView!.layoutSubtreeIfNeeded()
        for field in owner.syncFields.values {
            precondition(field.superview === owner.stack)
            precondition(field.frame.width > 400 && field.frame.height > 0)
        }
        precondition(owner.stack.arrangedSubviews.contains {
            ($0 as? NSButton)?.title == "Connect automatic updates"
        })
        owner.window.setContentSize(NSSize(width: 880, height: 650))
        owner.window.contentView!.layoutSubtreeIfNeeded()
        for field in owner.syncFields.values {
            precondition(field.frame.width <= owner.stack.frame.width + 1)
        }
        print("PASS: service-account sync needs no Connect server; provider switching clears tokens; fields fit the narrow window")
        owner.accounts = [["account": "fixture", "label": "Fixture account", "route": "browser",
                           "portable_ready": true, "connected": false]]
        owner.sources = [["id": "fixture-factor", "kind": "totp"]]
        owner.showImportSummary(["fixture"], issues: [("fixture", "Verification must be connected.")])
        owner.window.contentView!.layoutSubtreeIfNeeded()
        func descendants(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(descendants) }
        var views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Saved · Sign-in needs attention"))
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Verification must be connected."))
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Show sign-in problem"))
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Review verification methods"))
        precondition(!views.contains { $0 is NSSecureTextField })
        owner.showImportSummary(["fixture"], issues: [])
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Saved · Sign-in needs attention"))
        owner.accounts[0]["connected"] = true
        owner.showImportSummary(["fixture"], issues: [])
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Connected"))
        precondition(!views.compactMap { ($0 as? NSButton)?.title }.contains("Show sign-in problem"))
        print("PASS: import summary distinguishes saved credentials from verified sign-in and exposes repair without blank credential fields")
        owner.accounts = [["account": "fixture", "label": "Fixture account", "route": "browser",
                           "portable_ready": true, "connected": false,
                           "challenges": [["kind": "unknown"]]]]
        owner.navigationFailures = [["account": "fixture", "reason": "redirect:destination:configured_path_1:query"]]
        owner.ready()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains(owner.navigationFailureMessage("redirect:destination:configured_path_1:query")))
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Show technical details"))
        precondition(!views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("redirect:destination:configured_path_1:query"))
        print("PASS: stopped sign-ins show a plain-language failure and an optional owner-only technical detail action")
        let previousAccounts = owner.accounts
        owner.accounts[0]["challenges"] = [["kind": "captcha"]]
        owner.navigationFailures = [["account": "fixture", "reason": "request:http_403:configured_path_0:no_query"]]
        owner.ready()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains(owner.verificationMessage(["reason": "browser_captcha_required"])))
        precondition(!views.compactMap { ($0 as? NSButton)?.title }.contains("Show technical details"))
        owner.accounts = previousAccounts
        print("PASS: browser security checks have a specific explanation without a misleading transport error")
        precondition(AccountAccess.authenticatorQRText(["otpauth://totp/Example?secret=FICTIONAL"]) != nil)
        precondition(AccountAccess.authenticatorQRText(["otpauth-migration://offline?data=FICTIONAL"]) != nil)
        precondition(AccountAccess.authenticatorQRText(["https://example.com"]) == nil)
        precondition(AccountAccess.authenticatorQRText(["otpauth://totp/A", "otpauth://totp/B"]) == nil)
        precondition(AccountAccess.authenticatorQRTexts(["otpauth-migration://offline?data=PART1", "otpauth-migration://offline?data=PART2"])?.count == 2)
        precondition(AccountAccess.authenticatorQRTexts(["otpauth://totp/A", "otpauth-migration://offline?data=PART2"]) == nil)
        precondition(AccountAccess.authenticatorQRTexts(Array(repeating: "otpauth-migration://offline?data=PART", count: 17)) == nil)
        precondition(AccountAccess.authenticatorQRTexts(Array(repeating: "otpauth-migration://offline?data=" + String(repeating: "A", count: 31000), count: 2)) == nil)
        owner.sources = [["id": "fixture-factor", "kind": "totp", "accounts": ["fixture"]]]
        owner.showFactors()
        views = descendants(owner.stack)
        precondition(owner.factorFields["seed"] is NSSecureTextField)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Import authenticator QR images"))
        print("PASS: authenticator setup masks keys and accepts bounded complete transfer image selections")
        owner.sources = [["id": "fixture-mail", "kind": "imap", "accounts": ["fixture"], "enrolled": true]]
        owner.showFactors()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Setup saved"))
        precondition(!views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("● Connected"))
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Check email connection"))
        owner.sources[0]["connection_check"] = ["status": "VERIFIED"]
        owner.showFactors()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("● Mailbox connection checked"))
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains { $0.contains("sign-in is still needed to verify code delivery") })
        print("PASS: saved mailbox credentials and a checked connection cannot claim completed website code delivery")
        owner.sources = []
        owner.smsSetups = []
        owner.showFactors()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Connect Gmail or email"))
        precondition(!views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("You're all set"))
        owner.showEmailSetup()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Use an app password"))
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains(where: { $0.contains("publisher's registered Gmail connection") }))
        owner.mailboxOAuth = [["account": "fixture-gmail", "label": "Gmail", "fingerprint": String(repeating: "a", count: 64),
                              "publisher_configured": true, "connected": false,
                              "sources": [["recipient": "owner@example.test"]]]]
        owner.showEmailSetup()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Connect with Google"))
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains(where: { $0.contains("Google grants mailbox read access") }))
        owner.mailboxOAuth[0]["connected"] = true
        owner.mailboxOAuth[0]["renewable_access_saved"] = true
        owner.showEmailSetup()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains(where: { $0.contains("Renewable Google access is saved") }))
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Reconnect with Google"))
        for reason in ["connection_revoked", "provider_grant_revoked_or_expired", "refresh_outcome_uncertain",
                       "mailbox_oauth_renewal_unavailable", "mailbox_scope_missing", "mailbox_scope_not_allowed", "fictional-private-reason"] {
            owner.mailboxOAuth[0]["connected"] = false
            owner.mailboxOAuth[0]["renewable_access_saved"] = false
            owner.mailboxOAuth[0]["connection_state"] = "needs_attention"
            owner.mailboxOAuth[0]["reason"] = reason
            owner.showEmailSetup()
            views = descendants(owner.stack)
            let texts = views.compactMap { ($0 as? NSTextField)?.stringValue }
            precondition(texts.contains(where: { $0.contains("Google connection needs attention") }))
            precondition(!texts.contains(where: { $0.contains("Renewable Google access is saved") || $0.contains("fictional-private-reason") }))
            precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Reconnect with Google"))
        }
        owner.mailboxOAuth[0]["connected"] = true
        owner.mailboxOAuth[0].removeValue(forKey: "renewable_access_saved")
        owner.mailboxOAuth[0].removeValue(forKey: "connection_state")
        owner.showEmailSetup()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains(where: { $0.contains("Google connection needs attention") }))
        print("PASS: unusable or nonrenewable Google grants require reconnection without claiming saved access or exposing arbitrary reasons")
        owner.mailboxOAuth = []
        owner.showMailboxPasswordSetup()
        precondition(owner.mailboxFields["password"] is NSSecureTextField)
        precondition(owner.mailboxFields["host"]?.stringValue == "imap.gmail.com")
        precondition(owner.mailboxFields["port"]?.stringValue == "993")
        precondition(owner.mailboxFields["host"]?.isEnabled == false)
        precondition(owner.mailboxFields["host"]?.isHidden == true && owner.mailboxFields["port"]?.isHidden == true)
        owner.mailboxKind.selectItem(at: 1)
        owner.mailboxKindChanged()
        precondition(owner.mailboxFields["host"]?.isEnabled == true && owner.mailboxFields["host"]?.stringValue == "")
        precondition(owner.mailboxFields["host"]?.isHidden == false)
        print("PASS: Gmail setup is available before any website source and masks its app password; other providers require explicit TLS settings")
        let mailboxID = "mailbox-" + String(repeating: "a", count: 24)
        owner.mailboxes = [["id": mailboxID, "label": "Example email", "username": "owner@example.test",
                            "host": "imap.example.test", "port": 993, "connection_check": ["status": "VERIFIED"]]]
        owner.sources = [["id": "fixture-mail", "kind": "imap", "accounts": ["fixture"],
                          "mail_server": "imap.example.test", "mail_port": 993, "recipient": "owner@example.test"]]
        owner.showFactors()
        precondition(owner.factorMailboxMenu?.selectedItem?.representedObject as? String == mailboxID)
        precondition(owner.factorFields.values.allSatisfy { !$0.isEnabled && $0.isHidden && $0.stringValue.isEmpty })
        owner.sources[0]["recipient"] = "different@example.test"
        owner.showFactors()
        precondition(owner.factorMailboxMenu == nil)
        precondition(owner.factorFields.values.allSatisfy { $0.isEnabled })
        owner.mailboxes = []
        print("PASS: a checked matching mailbox is reusable without another password entry; another recipient is never offered")
        owner.browserUpdates = [["account": "fixture", "fingerprint": "fictional"]]
        owner.ready()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Update sign-in connection"))
        print("PASS: reviewed sign-in repairs are available without entering the password again")
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [VerificationRetryFixture.self]
        owner.session = URLSession(configuration: sessionConfig)
        // Simulate the endpoint/capability rotation after a service crash. The
        // real request method must verify the new owner before using it, while
        // leaving an unsaved native credential form intact.
        owner.showMailboxPasswordSetup()
        owner.mailboxFields["password"]!.stringValue = "fictional-unsaved-value"
        let unsavedField = owner.mailboxFields["password"]!
        VerificationRetryFixture.ownerPort = 2
        VerificationRetryFixture.ownerToken = "synthetic-restarted-session"
        saveOwner(port: 2, token: VerificationRetryFixture.ownerToken)
        _ = try! owner.request("owner/state")
        precondition(owner.base.port == 2 && owner.token == VerificationRetryFixture.ownerToken)
        precondition(owner.mailboxFields["password"] === unsavedField && unsavedField.stringValue == "fictional-unsaved-value")
        print("PASS: native requests verify a restarted local service without rebuilding or clearing an unsaved form")
        let callsBeforeInvalidProof = VerificationRetryFixture.ownerRequests
        VerificationRetryFixture.invalidProof = true
        do {
            _ = try owner.request("owner/verify", body: ["account": "fixture"])
            preconditionFailure("Unverified owner accepted setup data")
        } catch { }
        precondition(VerificationRetryFixture.ownerRequests == callsBeforeInvalidProof)
        precondition(unsavedField.stringValue == "fictional-unsaved-value")
        VerificationRetryFixture.invalidProof = false
        print("PASS: failed owner identity verification sends no setup request and preserves the unsaved form")
        let callsBeforeLostResponse = VerificationRetryFixture.ownerRequests
        VerificationRetryFixture.loseNextSetupResponse = true
        do {
            _ = try owner.request("owner/verify", body: ["account": "fixture"])
            preconditionFailure("Lost setup response unexpectedly succeeded")
        } catch { }
        precondition(VerificationRetryFixture.ownerRequests == callsBeforeLostResponse + 1)
        precondition(unsavedField.stringValue == "fictional-unsaved-value")
        print("PASS: a lost setup response is surfaced without replaying the request or clearing an idle form")
        let checksBefore = VerificationRetryFixture.verificationRequests
        for kind in ["captcha", "passkey", "device", "admin", "action", "recovery", "unknown"] {
            owner.accounts[0]["challenges"] = [["kind": kind]]
            precondition(owner.verificationRetryBlock("fixture") != nil)
            precondition(owner.verifyLinkedAccounts(["fixture"]).count == 1)
        }
        precondition(VerificationRetryFixture.verificationRequests == checksBefore)
        owner.accounts[0]["challenges"] = [["kind": "email"]]
        precondition(owner.verificationRetryBlock("fixture") == nil)
        owner.accounts[0]["challenges"] = []
        print("PASS: saving verification setup cannot retry blocked website checks or presence challenges")
        owner.status = NSTextField(labelWithString: "Checking")
        _ = try! owner.waitForConnection(["id": "first"], account: "fixture", timeout: 10, visible: true)
        precondition(VerificationRetryFixture.retriedVisible)
        print("PASS: owner-visible troubleshooting stays visible after a transient retry")
        VerificationRetryFixture.stopped = true
        let stopped = try! owner.waitForConnection(["id": "first"], account: "fixture", timeout: 10, visible: true)
        let stoppedJobs = stopped["connection_jobs"] as! [String: [String: Any]]
        precondition(stoppedJobs["first"]?["status"] as? String == "NEEDS_USER")
        VerificationRetryFixture.stopped = false
        print("PASS: finishing a stopped review returns the failed account state without claiming connection")
        owner.sources = []
        owner.smsSetups = [["account": "fixture", "fingerprint": "fictional"]]
        owner.showFactors()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Connect iPhone SMS"))
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Set up Google Messages"))
        precondition(!views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("You're all set"))
        print("PASS: an offered SMS method has a setup action before any SMS source exists")
        precondition(AccountAccess.smsTimeoutMessage(deliveryStarted: false, incoming: 0, unreadable: 0).contains("did not reach a confirmed SMS request"))
        precondition(AccountAccess.smsTimeoutMessage(deliveryStarted: true, incoming: 0, unreadable: 0).contains("delivery was not confirmed"))
        precondition(owner.verificationMessage(["reason": "browser_state_unrecognized"]).contains("does not recognize"))
        precondition(owner.verificationMessage(["reason": "browser_passkey_required"]).contains("requires owner approval"))
        precondition(owner.verificationMessage(["reason": "browser_recovery_required"]).contains("opened account recovery"))
        let browserCheck = owner.verificationMessage(["reason": "browser_captcha_required"])
        precondition(browserCheck.contains("cannot complete automatically") && browserCheck.contains("password is preserved"))
        print("PASS: pre-request failures cannot claim SMS delivery was tested; owner attention distinguishes unknown pages and required presence")
        let mailboxLimit = owner.verificationMessage(["kind": "email", "reason": "mailbox_result_limit"])
        precondition(mailboxLimit.contains("instead of guessing") && !mailboxLimit.contains("SMS"))
        precondition(owner.verificationMessage(["reason": "mailbox_scope_missing"]).contains("Reconnect that mailbox"))
        precondition(owner.verificationMessage(["reason": "phone_not_paired"]).contains("Pair your Android phone"))
        precondition(owner.verificationMessage(["kind": "sms", "reason": "verification_source_not_connected"]).contains("No SMS delivery was tested"))
        print("PASS: email and unpaired-phone failures explain their repair without claiming an SMS test")
        let detail = AccountAccess.verificationDetailText([
            "page": "origin_0:/sessions/two-factor/sms",
            "forms": [["route": "origin_0:/sessions/two-factor", "method": "POST"],
                      ["route": "https://example.com/?secret=fictional", "method": "GET"]],
            "fields": ["sms_totp": true, "password": "fictional-secret"],
            "controls": ["sms": ["count": 1, "visible": false]],
            "progress": ["method": "sms", "sms_code_filled": true, "code": "fictional-secret",
                         "code_request": ["page": "origin_0:/sessions/two-factor/sms", "http_status": 302,
                                          "transport": "document", "ajax": true, "auto": false,
                                          "redirect": "https://example.com/?secret=fictional", "code": "fictional-secret"]],
            "assets": ["https://github.githubassets.com/assets/sessions-test.js", "https://example.com/?secret=fictional"],
            "arbitrary": "fictional-secret"])
        precondition(detail.contains("origin_0:/sessions/two-factor/sms"))
        precondition(detail.contains("Form: POST origin_0:/sessions/two-factor"))
        precondition(detail.contains("Code fields present: sms_totp"))
        precondition(detail.contains("sms controls: 1 hidden"))
        precondition(detail.contains("Selected method: sms") && detail.contains("Login stage: sms_code_filled"))
        precondition(detail.contains("Code request HTTP: 302") && detail.contains("Code request transport: document"))
        precondition(detail.contains("Code request ajax: true") && !detail.contains("Code request redirect:"))
        precondition(detail.contains("Asset: https://github.githubassets.com/assets/sessions-test.js"))
        precondition(!detail.contains("fictional") && !detail.contains("example.com"))
        precondition(AccountAccess.verificationDetailText(["page": "origin_0:/sessions/private-value"]).isEmpty)
        let afterSMS = owner.verificationMessage(["reason": "browser_action_required", "diagnostics": ["progress": ["sms_code_filled": true]]])
        precondition(afterSMS.contains("SMS code was received") && !afterSMS.contains("No SMS"))
        print("PASS: verification detail view excludes arbitrary data and admits only closed routes and known control names")
        owner.browserSessionAccounts = [["account": "fixture", "label": "GitHub fixture", "fingerprint": "fictional", "username_hint": "fixture-owner"]]
        owner.ready()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Use signed-in Chrome"))
        let chrome = NSButton()
        chrome.identifier = NSUserInterfaceItemIdentifier("fixture")
        owner.showBrowserSession(chrome)
        views = descendants(owner.stack)
        precondition(owner.browserSessionUsername.stringValue == "fixture-owner")
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Prepare Chrome connection"))
        precondition(!views.contains { $0 is NSSecureTextField })
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains { $0.contains("checks the signed-in username") && $0.contains("temporary cookie") })
        print("PASS: Chrome session setup shows expected username and temporary cookie access before preparing; it never asks for a password")
        owner.browserSessionAccounts = []
        owner.ready()
        views = descendants(owner.stack)
        precondition(!views.compactMap { ($0 as? NSButton)?.title }.contains("Use signed-in Chrome"))
        print("PASS: unsupported or unapproved accounts have no Chrome session-transfer action")
        precondition(AccountAccess.browserSessionFailureMessage("browser_login_required").contains("did not accept"))
        precondition(AccountAccess.browserSessionFailureMessage("browser_state_unrecognized").contains("connector needs review"))
        precondition(AccountAccess.browserSessionFailureMessage("invalid_browser_session_state").contains("unsupported session format"))
        precondition(!AccountAccess.browserSessionFailureMessage("fictional-private-cookie").contains("fictional-private-cookie"))
        print("PASS: Chrome failures explain known repair cases without displaying arbitrary backend data")
        owner.backgroundRecovery = ["status": "RETRYING", "reason": "fictional-private-exception"]
        owner.ready()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Background recovery is retrying"))
        precondition(!views.compactMap { ($0 as? NSTextField)?.stringValue }.contains { $0.contains("fictional-private-exception") })
        owner.backgroundRecovery = ["status": "STOPPED"]
        owner.ready()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Background recovery stopped"))
        owner.backgroundRecovery = ["status": "RUNNING"]
        owner.ready()
        views = descendants(owner.stack)
        precondition(!views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Background recovery is retrying"))
        print("PASS: background recovery health shows fixed retry/stopped messages and clears after recovery without exception details")
        owner.accounts = [["account": "example", "label": "Public example", "environment": "public-example", "connected": true, "portable_ready": true],
                          ["account": "service", "label": "Service", "environment": "live", "connected": false, "portable_ready": true]]
        owner.ready()
        views = descendants(owner.stack)
        let exampleText = views.compactMap { ($0 as? NSTextField)?.stringValue }
        precondition(exampleText.contains("0 ready · 1 service connections"))
        precondition(exampleText.contains("1 ready · 1 example connections"))
        precondition(exampleText.contains("Example connected"))
        precondition(owner.requestText.contains("example accounts"))
        owner.accounts[1]["connected"] = true
        precondition(owner.requestText.contains("connected services") && !owner.requestText.contains("example accounts"))
        owner.accounts[1]["challenges"] = [["kind": "unknown"]]
        precondition(owner.requestText.contains("example accounts"))
        owner.showImportSummary(["example"], issues: [])
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Example connected"))
        owner.accounts = []
        precondition(owner.requestText.contains("what needs attention"))
        print("PASS: public examples have separate readiness counts, explicit statuses and example-only prompts; unverified imports never claim Connected")
        owner.backgroundServiceStatus = "requires_approval"
        owner.ready()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Open Login Items"))
        owner.backgroundServiceStatus = "enabled"
        owner.ready()
        views = descendants(owner.stack)
        precondition(!views.compactMap { ($0 as? NSButton)?.title }.contains("Open Login Items"))
        print("PASS: macOS background approval has a specific settings action and does not claim the current service is unavailable")
        owner.showMailboxPasswordSetup()
        owner.mailboxFields["password"]!.stringValue = "fictional-unsaved-value"
        owner.pauseAccess()
        let pauseDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < pauseDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(!owner.busy && VerificationRetryFixture.pauseRequests == 1)
        precondition(owner.token.isEmpty && owner.base == nil && owner.mailboxFields["password"]!.stringValue.isEmpty)
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Resume Account Access"))
        print("PASS: native Pause sends one stop request, clears local setup secrets and offers explicit Resume")
        let packaged = AccountAccess()
        packaged.requiresSystemInstallation = true
        precondition(packaged.systemOwnerConfigured)
        let legacyRequestsBefore = VerificationRetryFixture.ownerRequests
        do { _ = try packaged.nativeOwner(); preconditionFailure("Missing protected registration accepted") }
        catch {
            precondition(packaged.systemOwnerSelected && packaged.systemOwner == nil)
            precondition(packaged.token.isEmpty && packaged.base == nil)
            precondition(VerificationRetryFixture.ownerRequests == legacyRequestsBefore)
        }
        print("PASS: protected package refuses missing registration without starting legacy credential storage")
        owner.fixtureSystemOwnerSelected = true
        let nativeChannel = NativeOwnerScreenFixture()
        var nativePrompts = 0
        owner.systemOwner = DesktopOwnerConnection(makeChannel: { nativeChannel }, acquire: {
            nativePrompts += 1; return Data(repeating: 0x46, count: 32)
        })
        owner.presentSystemState(["vault_setup": ["status": "needs_owner"]])
        views = descendants(owner.window.contentView!)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Set up Account Access"))
        precondition(!views.compactMap { ($0 as? NSButton)?.title }.contains("Import passwords"))
        precondition(!views.contains { $0 is NSSecureTextField } && nativePrompts == 0)
        owner.presentSystemState(["vault_setup": ["status": "paused"]])
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Resume Account Access"))
        owner.presentSystemState(["vault_setup": ["status": "fictional-private-error"]])
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Check again"))
        precondition(!views.compactMap { ($0 as? NSTextField)?.stringValue }.contains { $0.contains("fictional-private-error") })
        print("PASS: isolated first setup and durable pause have explicit owner actions; repair never exposes raw errors or offers reset")
        try! FileManager.default.removeItem(at: fixtureRoot.appendingPathComponent("desktop.json"))
        owner.enrollSystemVault()
        let nativeDeadline = Date().addingTimeInterval(8)
        while (!owner.systemOwnerReady || owner.busy) && Date() < nativeDeadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        precondition(owner.systemOwnerReady && !owner.busy && nativePrompts == 1 && nativeChannel.enrollments == 1)
        precondition(owner.base == nil && owner.token.isEmpty)
        print("PASS: native setup accepts pending enrollment and automatically reads worker state without the legacy capability file")
        nativeChannel.lostNextEnrollment = true
        owner.enrollSystemVault()
        let lostDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < lostDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(nativeChannel.enrollments == 2 && !owner.busy)
        owner.reopen()
        let readDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < readDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(owner.systemOwnerReady && !owner.busy && nativeChannel.enrollments == 2 && nativePrompts == 1)
        print("PASS: lost native enrollment response is never replayed; reopening reconnects with a read and no new OS prompt")
        var localClientInstalled = false
        var preparedClients = 0
        owner.managedAgents = ManagedAgentSetup(helper: { action in
            if action == "prepare" { preparedClients += 1; return ["status": "PREPARED", "client_id": nativeChannel.clientID] }
            if action == "install" { localClientInstalled = true; return ["status": "INSTALLED", "client_id": nativeChannel.clientID, "hosts": ["codex", "claude"]] }
            return ["status": localClientInstalled ? "INSTALLED" : "NOT_INSTALLED", "client_id": nativeChannel.clientID]
        }, readToken: { nativeChannel.clientToken })
        nativeChannel.state["local_host_actions"] = false
        nativeChannel.state["managed_client"] = ["status": "NOT_CONNECTED"]
        owner.systemOwnerReady = false
        owner.presentSystemState(nativeChannel.state)
        let checkDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < checkDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Connect automatically"))
        precondition(preparedClients == 0 && nativeChannel.clientEnrollments == 0 && !owner.systemOwnerReady)
        owner.connectSystemAgents()
        let clientDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < clientDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(owner.systemOwnerReady && localClientInstalled && preparedClients == 1 && nativeChannel.clientEnrollments == 1)
        let promptsAfterConnection = nativePrompts
        owner.reopen()
        let reopenDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < reopenDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(owner.systemOwnerReady && preparedClients == 1 && nativeChannel.clientEnrollments == 1 && nativePrompts == promptsAfterConnection)
        print("PASS: a fresh isolated account view waits for portable client setup; both hosts connect without a selector, and reopening verifies without another enrollment or approval")
        var mismatchedRequests = 0
        let mismatched = ManagedAgentSetup(helper: { _ in ["status": "PREPARED", "client_id": String(repeating: "0", count: 64)] }, readToken: { nativeChannel.clientToken })
        do {
            try mismatched.connect { _, _ in mismatchedRequests += 1; return [:] }
            preconditionFailure("Mismatched local capability must not be enrolled")
        } catch { precondition(mismatchedRequests == 0) }
        print("PASS: changed local capability identity is refused before any native enrollment request")


    }
}
