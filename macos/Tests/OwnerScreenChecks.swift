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

final class OwnerApprovalWindowFixture: NSWindow {
    var approvalFrontRequests = 0
    override func makeKeyAndOrderFront(_ sender: Any?) { approvalFrontRequests += 1 }
}

final class NativeOwnerScreenFixture: DesktopOwnerChannel {
    var isAvailable = false
    var enrollments = 0
    var lostNextEnrollment = false
    var clientEnrollments = 0
    private let deviceEmailLock = NSLock()
    private var deviceEmailRequestLog: [String] = []
    var deviceEmailRequests: [String] { deviceEmailLock.withLock { deviceEmailRequestLog } }
    private let verificationRequestLock = NSLock()
    private var verificationRequests = 0
    var verificationRequestCount: Int { verificationRequestLock.withLock { verificationRequests } }
    var deviceEmailApplyFailure = false
    var deviceEmailPreview: [String: Any] = [:]
    var googleRequests: [String] = []
    private let sourceRequestLock = NSLock()
    private var sourceRequestLog: [[String: Any]] = []
    var sourceRequests: [[String: Any]] { sourceRequestLock.withLock { sourceRequestLog } }
    private let mailboxLock = NSLock()
    private var mailboxPosts = 0
    private var mailboxReply: ((Int, Data) -> Void)?
    var mailboxPostCount: Int { mailboxLock.withLock { mailboxPosts } }
    var mailboxResponsePending: Bool { mailboxLock.withLock { mailboxReply != nil } }
    func rejectMailboxResponse() {
        let reply = mailboxLock.withLock { () -> ((Int, Data) -> Void)? in
            defer { mailboxReply = nil }
            return mailboxReply
        }
        reply?(401, OwnerGatewaySession.failure("mailbox_connection_failed"))
    }
    let clientToken = String(repeating: "F", count: 43)
    var clientID: String { SHA256.hash(data: Data(clientToken.utf8)).map { String(format: "%02x", $0) }.joined() }
    var state: [String: Any] = ["accounts": [], "catalog": []]
    func prepare(reply: @escaping (Bool) -> Void) { isAvailable = true; reply(true) }
    func authorizeSetup(_ form: Data, reply: @escaping (Bool) -> Void) { reply(form.count == 32) }
    func request(_ route: String, body: Data?, reply: @escaping (Int, Data) -> Void) {
        if route == "owner/verify" { verificationRequestLock.withLock { verificationRequests += 1 } }
        if route == "owner/source" {
            let request = body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
            sourceRequestLock.withLock { sourceRequestLog.append(request) }
            reply(200, Data("{\"status\":\"ENROLLED\"}".utf8)); return
        }
        if route == "owner/source/check" {
            reply(200, Data("{\"status\":\"VERIFIED\"}".utf8)); return
        }
        if ["owner/mailbox/connect", "owner/mailbox/password"].contains(route) {
            mailboxLock.withLock {
                mailboxPosts += 1
                precondition(mailboxReply == nil)
                mailboxReply = reply
            }
            return
        }
        if route.hasPrefix("owner/mailbox/oauth/") {
            googleRequests.append(route)
            if route.hasSuffix("/check") {
                let item = ["id": "gmail-mailbox-" + String(repeating: "a", count: 24),
                    "recipient": "fictional@example.test", "label": "Google mailbox", "kind": "gmail"]
                var connections = state["mailbox_oauth"] as? [[String: Any]] ?? []
                if !connections.isEmpty {
                    connections[0]["reusable_mailbox"] = item
                    connections[0]["mailbox_identity_verified"] = true
                }
                state["mailbox_oauth"] = connections
                reply(200, try! JSONSerialization.data(withJSONObject: ["status": "VERIFIED", "mailbox_identity_verified": true])); return
            }
        }
        if route.hasPrefix("owner/device-email/") {
            deviceEmailLock.withLock { deviceEmailRequestLog.append(route) }
            if route.hasSuffix("/preview") {
                reply(200, try! JSONSerialization.data(withJSONObject: deviceEmailPreview)); return
            }
            if route.hasSuffix("/apply") && deviceEmailApplyFailure {
                reply(409, OwnerGatewaySession.failure("device_email_setup_changed")); return
            }
            if route.hasSuffix("/apply") || route.hasSuffix("/remove") {
                var setups = state["device_email_setups"] as? [[String: Any]] ?? []
                if !setups.isEmpty { setups[0]["connected"] = route.hasSuffix("/apply") }
                state["device_email_setups"] = setups
            }
            reply(200, Data("{\"status\":\"ENROLLED\"}".utf8)); return
        }
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
        setbuf(stdout, nil)
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
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.httpCookieStorage = nil
        sessionConfig.urlCredentialStorage = nil
        sessionConfig.urlCache = nil
        sessionConfig.connectionProxyDictionary = [:]
        sessionConfig.protocolClasses = [VerificationRetryFixture.self]
        let fixtureSession = URLSession(configuration: sessionConfig)
        let helperLock = NSLock()
        var unexpectedHelperCalls = 0
        let blockedHelpers = ManagedAgentSetup(helper: { _ in
            helperLock.withLock { unexpectedHelperCalls += 1 }
            throw ManagedAgentSetupFailure.unavailable
        }, readToken: {
            helperLock.withLock { unexpectedHelperCalls += 1 }
            throw ManagedAgentSetupFailure.unavailable
        })
        var fixtureProfileReads = 0
        let missingFixtureProfile: () throws -> DesktopOwnerProfile = {
            fixtureProfileReads += 1
            throw DesktopOwnerFailure.profile
        }
        let owner = AccountAccess(fixtureRoot: fixtureRoot, session: fixtureSession,
                                  managedAgents: blockedHelpers, ownerProfile: missingFixtureProfile)
        precondition(owner.root == fixtureRoot && owner.runtime == fixtureRoot.appendingPathComponent("runtime"))
        precondition(!owner.requiresSystemInstallation && !owner.systemOwnerConfigured && fixtureProfileReads == 0)
        owner.window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 740),
                                styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        owner.base = URL(string: "http://127.0.0.1:1/")!
        owner.token = "synthetic-ui-session"
        owner.accounts = [["account": "fixture", "label": "Fixture account", "route": "browser",
                           "portable_ready": true, "connected": true,
                           "saved_login_available": true, "saved_login_exportable": true,
                           "operations": []]]
        owner.ready()
        var accountActions = descendants(owner.stack).compactMap { $0 as? NSButton }
        precondition(accountActions.contains { $0.title == "Export saved login…" && $0.action == #selector(AccountAccess.exportSavedLogin) })
        precondition(accountActions.contains { $0.title == "Forget saved login" && $0.action == #selector(AccountAccess.forgetSavedLogin) })
        owner.window.setContentSize(NSSize(width: 880, height: 650))
        owner.window.contentView!.layoutSubtreeIfNeeded()
        for control in accountActions where ["Export saved login…", "Forget saved login"].contains(control.title) {
            precondition(control.frame.width > 0 && control.frame.height > 0)
        }
        owner.accounts[0]["saved_login_exportable"] = false
        owner.ready()
        accountActions = descendants(owner.stack).compactMap { $0 as? NSButton }
        precondition(!accountActions.contains { $0.title == "Export saved login…" })
        precondition(accountActions.contains { $0.title == "Forget saved login" })
        let exportSentinel = fixtureRoot.appendingPathComponent("export-sentinel.txt")
        let selectedExport = fixtureRoot.appendingPathComponent("saved-login.csv")
        try! Data("keep this file".utf8).write(to: exportSentinel)
        try! FileManager.default.createSymbolicLink(at: selectedExport, withDestinationURL: exportSentinel)
        try! AccountAccess.writePrivateExport(Data("url,username,password\r\nhttps://fixture.test,owner,synthetic\r\n".utf8), to: selectedExport)
        var exportedInfo = stat()
        precondition(lstat(selectedExport.path, &exportedInfo) == 0
            && exportedInfo.st_mode & S_IFMT == S_IFREG
            && exportedInfo.st_mode & 0o077 == 0
            && (try? String(contentsOf: selectedExport, encoding: .utf8))?.contains("synthetic") == true
            && (try? String(contentsOf: exportSentinel, encoding: .utf8)) == "keep this file")
        print("PASS: account login export is explicit, destination writes replace links safely, and files are owner-only")
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
        let generation = String(repeating: "a", count: 32)
        precondition(AccountAccess.passwordSyncReconnectConnection(token: "fixture-replacement", generation: generation) == ["token": "fixture-replacement", "generation": generation])
        for invalid in ["", "wrong", String(repeating: "A", count: 32), generation + "\n"] {
            precondition(AccountAccess.passwordSyncReconnectConnection(token: "fixture-replacement", generation: invalid) == nil)
        }
        for invalid in ["", "value\n", String(repeating: "x", count: 8193)] {
            precondition(AccountAccess.passwordSyncReconnectConnection(token: invalid, generation: generation) == nil)
        }
        owner.passwordSync = [["account": "fixture", "provider": "1Password service account", "status": "BLOCKED", "generation": generation]]
        owner.showPasswordSync()
        let replace = NSButton()
        replace.identifier = NSUserInterfaceItemIdentifier("fixture")
        owner.syncFields["token"]?.stringValue = "old-unsaved-token"
        owner.showReconnectPasswordSync(replace)
        precondition(Set(owner.syncFields.keys) == Set(["token"]))
        precondition(owner.syncFields["token"] is NSSecureTextField && owner.syncFields["token"]?.stringValue == "")
        precondition(owner.syncReconnectAccount == "fixture" && owner.syncReconnectGeneration == generation)
        owner.syncFields["token"]?.stringValue = "replacement-to-cancel"
        let discarded = owner.syncFields["token"]!
        owner.showPasswordSync()
        precondition(discarded.stringValue == "" && owner.syncReconnectAccount == nil && owner.syncReconnectGeneration == nil)
        owner.passwordSync = []
        print("PASS: token replacement needs only a masked new token and current generation; cancellation clears the secret without changing the source")

        let bitwardenID = String(repeating: "b", count: 32)
        let bitwardenItem = "12345678-1234-1234-1234-123456789abc"
        let bitwardenFields = ["client_id": "user." + bitwardenItem, "client_secret": "synthetic-api-secret",
                               "master_password": "  synthetic unicode 🔐 master  "]
        precondition(AccountAccess.bitwardenEnrollment(region: "us", fields: bitwardenFields, consent: false) == nil)
        let enrollment = AccountAccess.bitwardenEnrollment(region: "eu", fields: bitwardenFields, consent: true)!
        precondition(enrollment["master_password"] as? String == bitwardenFields["master_password"])
        precondition(enrollment["consent_vault_access"] as? Bool == true)
        for (key, invalid) in [("client_id", "user." + bitwardenItem.uppercased()), ("client_secret", "secret\n"),
                               ("master_password", "bad\0password"), ("master_password", String(repeating: "x", count: 4097))] {
            var fields = bitwardenFields; fields[key] = invalid
            precondition(AccountAccess.bitwardenEnrollment(region: "us", fields: fields, consent: true) == nil)
        }
        precondition(AccountAccess.bitwardenEnrollment(region: "self-hosted", fields: bitwardenFields, consent: true) == nil)
        precondition(AccountAccess.bitwardenItemConnection(id: bitwardenID, generation: generation, item: bitwardenItem)?["item"] == bitwardenItem)
        precondition(AccountAccess.bitwardenItemConnection(id: bitwardenID, generation: generation + "\n", item: bitwardenItem) == nil)
        owner.bitwardenAvailable = true
        owner.showBitwardenConnect()
        precondition(Set(owner.bitwardenFields.keys) == Set(["client_id", "client_secret", "master_password"]))
        precondition(owner.bitwardenFields.values.allSatisfy { $0 is NSSecureTextField })
        precondition(owner.bitwardenConsent.state == .off)
        for (key, field) in owner.bitwardenFields { field.stringValue = bitwardenFields[key]! }
        owner.bitwardenConsent.state = .on
        let discardedBitwardenFields = Array(owner.bitwardenFields.values)
        owner.showPasswordSync()
        precondition(discardedBitwardenFields.allSatisfy { $0.stringValue.isEmpty })
        precondition(owner.bitwardenConsent.state == .off)
        print("PASS: Bitwarden requires explicit vault consent, masks setup credentials, preserves master-password text and clears cancelled secrets")

        func syncDescendants(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(syncDescendants) }
        owner.bitwardenConnections = [["id": bitwardenID, "generation": generation, "email": "synthetic@example.test", "region": "eu", "provider": "Bitwarden"]]
        owner.accounts = [["account": "fixture", "label": "Imported fixture", "route": "browser", "portable_ready": true,
                           "password_sync_suggestion": ["provider": "bitwarden", "item": bitwardenItem]],
                          ["account": "other", "label": "Advanced fixture", "route": "browser", "portable_ready": true]]
        owner.passwordSync = [["account": "fixture", "provider": "Bitwarden", "status": "SYNCED", "generation": generation]]
        owner.showPasswordSync()
        precondition(owner.bitwardenItem.stringValue == bitwardenItem && owner.bitwardenItem.isHidden && !owner.bitwardenItem.isEditable)
        precondition(!syncDescendants(owner.stack).compactMap { ($0 as? NSButton)?.title }.contains("Replace token"))
        owner.bitwardenAccounts.selectItem(at: 1)
        owner.bitwardenAccountChanged()
        precondition(!owner.bitwardenItem.isHidden && owner.bitwardenItem.isEditable && owner.bitwardenItem.stringValue.isEmpty)
        owner.bitwardenAvailable = false
        owner.showPasswordSync()
        precondition(!syncDescendants(owner.stack).compactMap { ($0 as? NSButton)?.title }.contains("Connect Bitwarden"))
        owner.bitwardenConnections = []
        owner.passwordSync = []
        print("PASS: imported Bitwarden item IDs need no reentry; manual IDs stay advanced, replacement tokens are absent and unavailable runtime hides enrollment")

        owner.accounts = [["account": "fixture", "label": "Fixture account", "route": "browser", "environment": "live",
                           "portable_ready": true, "connected": false]]
        owner.sources = [["id": "fixture-factor", "kind": "totp"]]
        owner.showImportSummary(["fixture"], issues: [("fixture", "Verification must be connected.")])
        owner.window.contentView!.layoutSubtreeIfNeeded()
        func descendants(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(descendants) }
        var views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Saved · Sign-in needs attention"))
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Verification must be connected."))
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Review sign-in help"))
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Review verification methods"))
        precondition(!views.contains { $0 is NSSecureTextField })
        owner.showImportSummary(["fixture"], issues: [])
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Saved · Sign-in needs attention"))
        owner.accounts[0]["connected"] = true
        owner.showImportSummary(["fixture"], issues: [])
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Connected"))
        precondition(!views.compactMap { ($0 as? NSButton)?.title }.contains("Review sign-in help"))
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
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains(where: { $0.contains("Google access is saved") }))
        precondition(!views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Google mailbox checked"))
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Check Google connection"))
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
            precondition(!texts.contains(where: { $0.contains("Google access is saved") || $0.contains("Google mailbox checked") || $0.contains("fictional-private-reason") }))
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
        let savedCatalog = owner.catalog
        let savedAccounts = owner.accounts
        owner.accounts = []
        owner.catalog = [
            ["id": "identity-fixture", "label": "Fictional identity login", "login_method": "identity_phone_sms",
             "operations": [["name": "status", "description": "Confirm the signed-in session"]]],
            ["id": "password-fixture", "label": "Fictional password login",
             "operations": [["name": "status", "description": "Confirm the signed-in session"]]]
        ]
        owner.connections()
        precondition(owner.username is NSSecureTextField && owner.password != nil)
        precondition(owner.loginIdentityLabel?.stringValue == "Identity number")
        precondition(owner.loginSecretLabel?.stringValue == "Phone number for login SMS")
        owner.username.stringValue = "fictional-identity"
        owner.password.stringValue = "fictional-phone"
        let identityEntry = owner.services.selectedItem!.representedObject as! [String: Any]
        precondition(AccountAccess.loginCredential(entry: identityEntry, identity: owner.username.stringValue,
            secret: owner.password.stringValue) == ["identity": "fictional-identity", "phone": "fictional-phone"])
        owner.services.selectItem(at: 1)
        owner.serviceChanged()
        precondition(!(owner.username is NSSecureTextField) && owner.username.stringValue.isEmpty && owner.password.stringValue.isEmpty)
        precondition(owner.loginIdentityLabel?.stringValue == "Email or username" && owner.loginSecretLabel?.stringValue == "Password")
        precondition(AccountAccess.loginCredential(entry: [:], identity: "fictional-user", secret: "fictional-password")
            == ["username": "fictional-user", "password": "fictional-password"])
        owner.catalog = savedCatalog
        owner.accounts = savedAccounts
        print("PASS: identity and phone enrollment uses distinct masked fields; changing login kind clears values and restores password labels")
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
        precondition(browserCheck.contains("cannot complete automatically") && browserCheck.contains("sign-in details are preserved"))
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
        let fieldKeys = ["password", "one_time_code", "numeric_input", "email_input"]
        let markerKeys = ["login", "sms", "email", "totp", "device", "passkey", "captcha", "admin", "action", "recovery", "unknown", "method"]
        let firstStop: [String: Any] = ["schema": 1, "page": "origin_0:/?/device",
            "forms": [["method": "POST", "visible": true, "reviewed_action": false, "controls": 3]],
            "fields": Dictionary(uniqueKeysWithValues: fieldKeys.map { ($0, $0 == "one_time_code") }),
            "field_counts": Dictionary(uniqueKeysWithValues: fieldKeys.map { ($0, $0 == "one_time_code" ? 1 : 0) }),
            "visible_field_counts": Dictionary(uniqueKeysWithValues: fieldKeys.map { ($0, $0 == "one_time_code" ? 1 : 0) }),
            "markers": Dictionary(uniqueKeysWithValues: markerKeys.map { ($0, false) }),
            "progress": ["password_submit_attempted": true]]
        let firstStopText = AccountAccess.verificationDetailText(firstStop)
        precondition(firstStopText.contains("first stopped sign-in") && firstStopText.contains("One-time-code fields: 1 visible / 1 observed"))
        precondition(firstStopText.contains("does not match a configured static login route") && !firstStopText.contains("Selected method:"))
        for invalid in [true, 1.0, "1"] as [Any] {
            var malformed = firstStop; malformed["schema"] = invalid
            precondition(AccountAccess.verificationDetailText(malformed).isEmpty)
        }
        var malformed = firstStop
        malformed["fields"] = ["password": "fictional-password", "one_time_code": "fictional-code", "csrf": "fictional-csrf"]
        precondition(AccountAccess.verificationDetailText(malformed).isEmpty)
        malformed = firstStop; malformed["page"] = "https://example.test/secret?token=fictional-token"
        precondition(AccountAccess.verificationDetailText(malformed).isEmpty)
        malformed = firstStop; malformed["forms"] = [["method": "POST", "visible": true, "reviewed_action": false, "controls": 3, "action": "fictional-token"]]
        precondition(AccountAccess.verificationDetailText(malformed).isEmpty)
        malformed = firstStop; malformed["field_counts"] = ["password": true, "one_time_code": 1, "numeric_input": 0, "email_input": 0]
        precondition(AccountAccess.verificationDetailText(malformed).isEmpty)
        malformed = firstStop; malformed["progress"] = ["password_submit_attempted": 1]
        precondition(AccountAccess.verificationDetailText(malformed).isEmpty)
        let diagnosticOwner = AccountAccess(fixtureRoot: fixtureRoot, session: fixtureSession,
                                            managedAgents: blockedHelpers, ownerProfile: missingFixtureProfile)
        diagnosticOwner.accept(["accounts": [["account": "fixture", "challenges": [["id": "pending", "diagnostics": firstStop]]]],
            "connection_jobs": ["older": ["account": "fixture", "attention": ["diagnostics": ["page": "origin_0:/login"]]]]])
        precondition(diagnosticOwner.verificationDetails["fixture"] == firstStopText)
        diagnosticOwner.accept(["accounts": [["account": "fixture", "challenges": []]]])
        precondition(diagnosticOwner.verificationDetails.isEmpty)
        print("PASS: first stopped-page details reject secret-bearing or malformed data, preserve unknown methods and disappear with the current challenge")
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
        owner.serviceEnvironment = "controlled-demo"
        owner.accounts = [["account": "legacy-example", "label": "Legacy fixture", "connected": true, "portable_ready": true]]
        let legacyAuthenticator = ["kind": "totp", "accounts": ["legacy-example"]] as [String: Any]
        precondition(AccountAccess.verificationEnvironment(legacyAuthenticator, accounts: owner.accounts,
                                                           fallback: owner.serviceEnvironment) == "controlled-demo")
        precondition(owner.requestText.contains("example accounts"))
        owner.ready()
        views = descendants(owner.stack)
        let inheritedExampleText = views.compactMap { ($0 as? NSTextField)?.stringValue }
        precondition(inheritedExampleText.contains("1 ready · 1 example connections"))
        precondition(inheritedExampleText.contains("Example connected"))
        precondition(inheritedExampleText.contains("Example connection. These results do not validate access to a personal account."))
        owner.agents = ["codex"]
        owner.automaticSessions = ["codex": ["enabled": true]]
        owner.ready()
        views = descendants(owner.stack)
        let demoAgentText = views.compactMap { ($0 as? NSTextField)?.stringValue }
        precondition(demoAgentText.contains("Demo connection only"))
        precondition(demoAgentText.contains("Example only"))
        precondition(!demoAgentText.contains("Ready in every new session"))
        owner.serviceEnvironment = "mixed"
        precondition(AccountAccess.effectiveEnvironment(owner.accounts[0], fallback: owner.serviceEnvironment) == "unclassified")
        precondition(AccountAccess.verificationEnvironment(legacyAuthenticator, accounts: owner.accounts,
                                                           fallback: owner.serviceEnvironment) == "unclassified")
        precondition(!owner.requestText.contains("connected services") && !owner.requestText.contains("example accounts"))
        owner.ready()
        views = descendants(owner.stack)
        let unclassifiedText = views.compactMap { ($0 as? NSTextField)?.stringValue }
        precondition(unclassifiedText.contains("1 connections · source unverified"))
        precondition(unclassifiedText.contains("Source unverified"))
        precondition(unclassifiedText.contains("The service source could not be verified. This connection does not establish personal-account access."))
        precondition(unclassifiedText.contains("AI connection source unverified"))
        precondition(!unclassifiedText.contains("Ready in every new session"))
        owner.serviceEnvironment = "live"
        owner.accounts = [["account": "personal-service", "label": "Personal service", "environment": "live",
                           "connected": true, "portable_ready": true]]
        owner.ready()
        views = descendants(owner.stack)
        let liveAgentText = views.compactMap { ($0 as? NSTextField)?.stringValue }
        precondition(liveAgentText.contains("Ready in every new session"))
        precondition(liveAgentText.contains("Automatic"))
        owner.accounts = []
        precondition(owner.requestText.contains("what needs attention"))
        print("PASS: examples and legacy demo responses stay labeled; AI setup reports demo-only, unverified, and live readiness truthfully")
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
        let packaged = AccountAccess(fixtureRoot: fixtureRoot, session: fixtureSession,
                                     managedAgents: blockedHelpers, ownerProfile: missingFixtureProfile)
        packaged.requiresSystemInstallation = true
        precondition(packaged.systemOwnerConfigured)
        let legacyRequestsBefore = VerificationRetryFixture.ownerRequests
        do { _ = try packaged.nativeOwner(); preconditionFailure("Missing protected registration accepted") }
        catch {
            precondition(packaged.systemOwnerSelected && packaged.systemOwner == nil)
            precondition(packaged.token.isEmpty && packaged.base == nil)
            precondition(VerificationRetryFixture.ownerRequests == legacyRequestsBefore)
            precondition(fixtureProfileReads == 1)
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
        owner.presentSystemState(["vault_setup": ["status": "needs_repair", "diagnostic": [
            "checkpoint": "stage_status", "reason": "vault_publication_device_number_changed"]]])
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains { $0.contains("disk reference changed") })
        precondition(views.compactMap { ($0 as? NSButton)?.title } == ["Check again"])
        owner.presentSystemState(["vault_setup": ["status": "needs_repair", "diagnostic": [
            "checkpoint": "stage_status", "reason": "fictional-private-error"]]])
        views = descendants(owner.stack)
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
        let gmailMailboxID = "gmail-mailbox-" + String(repeating: "b", count: 24)
        let gmailContext = String(repeating: "c", count: 64)
        let gmailRevision = String(repeating: "d", count: 64)
        let gmailBlockedAccount: [String: Any] = ["account": "fixture", "label": "Fixture account", "challenges": [["kind": "unknown"]]]
        let gmailMailboxOption: [String: Any] = ["id": gmailMailboxID, "label": "Saved Google", "kind": "gmail", "recipient": "owner@example.test"]
        let gmailSource: [String: Any] = ["id": "ordinary-email", "kind": "gmail", "accounts": ["fixture"],
            "sender": "login@example.test", "recipient": "owner@example.test", "subject": "Sign in",
            "setup_context": gmailContext, "setup_revision": gmailRevision,
            "mailbox_options": [gmailMailboxOption]]
        nativeChannel.state["accounts"] = [gmailBlockedAccount]
        nativeChannel.state["code_sources"] = [gmailSource]
        owner.accept(nativeChannel.state)
        owner.showFactors()
        precondition(owner.factorMailboxMenu?.selectedItem?.representedObject as? String == gmailMailboxID)
        precondition(owner.factorMailboxMenu?.numberOfItems == 1)
        precondition(owner.factorFields.isEmpty)
        precondition(descendants(owner.stack).compactMap { ($0 as? NSTextField)?.stringValue }
            .contains { $0.contains("login@example.test") && $0.contains("owner@example.test") && $0.contains("Sign in") })
        let verificationBeforeGmailBinding = nativeChannel.verificationRequestCount
        owner.saveFactor()
        owner.saveFactor()
        let gmailBindingDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < gmailBindingDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(!owner.busy && nativeChannel.sourceRequests.count == 1)
        let gmailBinding = nativeChannel.sourceRequests[0]
        precondition(gmailBinding["source"] as? String == "ordinary-email")
        precondition(gmailBinding["credential"] as? [String: String] == ["mailbox": gmailMailboxID, "setup_context": gmailContext, "setup_revision": gmailRevision])
        precondition(nativeChannel.verificationRequestCount == verificationBeforeGmailBinding)
        owner.accept(nativeChannel.state)
        owner.sources[0].removeValue(forKey: "setup_revision")
        owner.showFactors()
        precondition(descendants(owner.stack).compactMap { $0 as? NSButton }
            .first { $0.title == "Connect verification" }?.isEnabled == false)
        owner.saveFactor()
        precondition(!owner.busy && nativeChannel.sourceRequests.count == 1)
        precondition(owner.status.stringValue.contains("email setup changed"))
        nativeChannel.state["accounts"] = []
        nativeChannel.state["code_sources"] = []
        owner.accept(nativeChannel.state)
        print("PASS: checked Gmail reuse submits one exact review without secrets, consent or retrying a blocked website; missing revision stops locally")
        var mismatchedRequests = 0
        let mismatched = ManagedAgentSetup(helper: { _ in ["status": "PREPARED", "client_id": String(repeating: "0", count: 64)] }, readToken: { nativeChannel.clientToken })
        do {
            try mismatched.connect { _, _ in mismatchedRequests += 1; return [:] }
            preconditionFailure("Mismatched local capability must not be enrolled")
        } catch { precondition(mismatchedRequests == 0) }
        print("PASS: changed local capability identity is refused before any native enrollment request")

        // Every failure stops at its actual stage; arbitrary underlying data is
        // never reflected in the user-visible explanation and no step retries.
        let privateFailureText = "fictional-capability-and-private-path-must-stay-local"
        for failedStage in ManagedAgentConnectionFailure.Stage.allCases where failedStage != .verify {
            for malformed in [false, true] {
                var reached: [ManagedAgentConnectionFailure.Stage] = []
                func visit(_ stage: ManagedAgentConnectionFailure.Stage) throws -> Bool {
                    reached.append(stage)
                    if stage == failedStage && !malformed {
                        throw NSError(domain: privateFailureText, code: 1,
                                      userInfo: [NSLocalizedDescriptionKey: privateFailureText])
                    }
                    return stage == failedStage
                }
                let setup = ManagedAgentSetup(helper: { action in
                    let stage: ManagedAgentConnectionFailure.Stage = action == "prepare-upgrade" ? .prepare : .install
                    precondition(action == "prepare-upgrade" || action == "install-upgrade")
                    if try visit(stage) { return ["status": privateFailureText] }
                    return stage == .prepare
                        ? ["status": "PREPARED", "client_id": nativeChannel.clientID]
                        : ["status": "INSTALLED", "client_id": nativeChannel.clientID, "hosts": ["codex", "claude"]]
                }, readToken: {
                    if try visit(.localIdentity) { return privateFailureText }
                    return nativeChannel.clientToken
                })
                do {
                    try setup.connect(upgrade: true) { route, _ in
                        let stage: ManagedAgentConnectionFailure.Stage = route == "owner/client/enroll" ? .enroll : .confirm
                        precondition(route == "owner/client/enroll" || route == "owner/client/installed")
                        if try visit(stage) { return ["status": privateFailureText] }
                        return ["status": stage == .enroll ? "ENROLLED" : "INSTALLED",
                                "client_id": nativeChannel.clientID, "principal": "generic"]
                    }
                    preconditionFailure("Failed connection step was accepted")
                } catch let failure as ManagedAgentConnectionFailure {
                    precondition(failure.stage == failedStage && !failure.conflict && !failure.revoked)
                    precondition(failure.explanation.contains(failedStage.description))
                    precondition(!failure.explanation.contains(privateFailureText))
                    precondition(!failure.explanation.contains(nativeChannel.clientToken))
                    let stages = ManagedAgentConnectionFailure.Stage.allCases
                    precondition(reached == Array(stages.prefix(through: stages.firstIndex(of: failedStage)!)))
                } catch { preconditionFailure("Failure was not reduced to a closed stage") }
            }
        }
        for (reason, revoked) in [("client_connection_conflict", false), ("portable_client_revoked", true)] {
            do {
                _ = try owner.checkedOwnerResponse(409, ["reason": reason, "detail": privateFailureText])
                preconditionFailure("Connection rejection was accepted")
            } catch {
                let failure = ManagedAgentConnectionFailure(stage: .enroll, error: error)
                precondition(failure.revoked == revoked && failure.conflict != revoked)
                precondition(!failure.explanation.contains(privateFailureText))
            }
        }
        let managedSetupFailures: [(String, ManagedAgentSetupFailure, String)] = [
            ("owner_setup_authorization_required", .setupAuthorizationRequired, "Approve the current setup dialog"),
            ("owner_channel_unavailable", .ownerChannelUnavailable, "protected owner channel is reconnecting"),
            ("owner_backend_unavailable", .ownerBackendUnavailable, "protected app is not responding"),
            ("broker_worker_recovering", .serviceRecovering, "protected service is restarting"),
            ("vault_setup_repair_required", .vaultRepairRequired, "account store needs repair"),
            ("unrecognized_private_reason", .connectionResponseRejected, "refused the connection response"),
        ]
        for (reason, expectedFailure, expectedMessage) in managedSetupFailures {
            do {
                _ = try owner.checkedOwnerResponse(503, ["reason": reason, "detail": privateFailureText], managedClientSetup: true)
                preconditionFailure("Managed-client setup failure was accepted")
            } catch {
                let failure = ManagedAgentConnectionFailure(stage: .enroll, error: error)
                precondition(failure.failure == expectedFailure)
                precondition(failure.explanation.localizedCaseInsensitiveContains(expectedMessage))
                precondition(!failure.explanation.contains(privateFailureText))
                precondition(!failure.explanation.contains(reason))
            }
        }
        let verificationFailure = ManagedAgentConnectionFailure(stage: .verify)
        precondition(verificationFailure.explanation.contains("checking the completed connection"))
        print("PASS: connection failures identify their exact closed stage, stop without replay, and hide arbitrary errors, responses and capabilities; conflicts and revocations require review")

        let customNamespace = "~/Library/Application Support/Codex Work"
        let ownerHome = fixtureRoot.appendingPathComponent("home")
        for action in ["status", "prepare", "install", "prepare-upgrade", "install-upgrade"] {
            let environment = try! ManagedAgentSetup.helperEnvironment(action: action, ownerHome: ownerHome,
                inherited: ["CODEX_HOME": customNamespace, "OPENAI_API_KEY": "fictional", "PYTHONPATH": "/untrusted", "DYLD_INSERT_LIBRARIES": "/untrusted"])
            precondition(environment["CODEX_HOME"] == ownerHome.path + "/Library/Application Support/Codex Work")
            precondition(Set(environment.keys) == ["PATH", "HOME", "LANG", "CODEX_HOME"])
        }
        precondition(try! ManagedAgentSetup.helperEnvironment(action: "browser", ownerHome: ownerHome,
            inherited: ["CODEX_HOME": customNamespace])["CODEX_HOME"] == nil)
        for value in ["", "relative", "/tmp/elsewhere", "~/../other", "~/a\nother", String(repeating: "a", count: 4097)] {
            do {
                _ = try ManagedAgentSetup.helperEnvironment(action: "prepare", ownerHome: ownerHome, inherited: ["CODEX_HOME": value])
                preconditionFailure("Invalid Codex namespace accepted")
            } catch {}
        }
        print("PASS: all agent setup actions preserve only a bounded owner-home Codex namespace; browser setup and unrelated credential or runtime variables stay excluded")

        nativeChannel.state["managed_client"] = ["status": "NOT_CONNECTED"]
        for malformed in [false, true] {
            var discoveryActions: [String] = []
            let previousEnrollments = nativeChannel.clientEnrollments
            owner.managedAgents = ManagedAgentSetup(helper: { action in
                discoveryActions.append(action)
                if malformed { return ["status": "PRIVATE_UNKNOWN_STATUS"] }
                throw ManagedAgentSetupFailure.unavailable
            }, readToken: { preconditionFailure("Failed discovery cannot read a capability") })
            owner.systemOwnerReady = false
            owner.connectAgentsAfterSetup = true
            owner.presentSystemState(nativeChannel.state)
            let discoveryDeadline = Date().addingTimeInterval(5)
            while owner.busy && Date() < discoveryDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
            let discoveryViews = descendants(owner.stack)
            let labels = discoveryViews.compactMap { ($0 as? NSTextField)?.stringValue }.joined(separator: " ")
            let buttons = discoveryViews.compactMap { ($0 as? NSButton)?.title }
            precondition(discoveryActions == ["status"] && nativeChannel.clientEnrollments == previousEnrollments)
            precondition(!owner.connectAgentsAfterSetup && !owner.systemOwnerReady)
            precondition(labels.contains("The existing AI connection could not be verified") && !labels.contains("PRIVATE_UNKNOWN_STATUS"))
            precondition(!buttons.contains("Connect automatically") && !buttons.contains("Upgrade AI connection"))
        }
        print("PASS: failed or unknown client discovery cannot become fresh setup, read a capability or silently enroll")

        var upgradeActions: [String] = []
        var upgraded = false
        owner.managedAgents = ManagedAgentSetup(helper: { action in
            upgradeActions.append(action)
            if action == "status" { return upgraded ? ["status": "INSTALLED", "client_id": nativeChannel.clientID] : ["status": "MIGRATION_REQUIRED", "legacy_connections": 2] }
            if action == "prepare-upgrade" { return ["status": "PREPARED", "client_id": nativeChannel.clientID] }
            if action == "install-upgrade" { upgraded = true; return ["status": "INSTALLED", "client_id": nativeChannel.clientID, "hosts": ["codex", "claude"]] }
            preconditionFailure("An upgrade used the ordinary installer")
        }, readToken: { nativeChannel.clientToken })
        nativeChannel.state["managed_client"] = ["status": "NOT_CONNECTED"]
        owner.systemOwnerReady = false
        owner.connectAgentsAfterSetup = true
        owner.presentSystemState(nativeChannel.state)
        let migrationDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < migrationDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(owner.systemAgentUpgradeNeeded && !upgraded && upgradeActions == ["status"])
        precondition(descendants(owner.stack).compactMap { ($0 as? NSButton)?.title }.contains("Upgrade AI connection"))
        let priorEnrollments = nativeChannel.clientEnrollments
        owner.connectSystemAgents()
        let upgradeDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < upgradeDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(upgraded && owner.systemOwnerReady && !owner.systemAgentUpgradeNeeded)
        precondition(upgradeActions == ["status", "prepare-upgrade", "install-upgrade"] && nativeChannel.clientEnrollments == priorEnrollments + 1)
        print("PASS: a recognized preview connection offers an explicit upgrade, waits for the owner, then connects both agents through the new approved capability")

        nativeChannel.state["mailbox_oauth"] = [["account": "mail", "fingerprint": String(repeating: "a", count: 64),
            "publisher_configured": true, "connected": true, "renewable_access_saved": true, "sources": []]]
        owner.accept(nativeChannel.state)
        owner.showFactors()
        let googleCheck = descendants(owner.stack).compactMap { $0 as? NSButton }.first { $0.title == "Check Google connection" }!
        owner.checkGmailOAuth(googleCheck)
        let googleDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < googleDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(nativeChannel.googleRequests == ["owner/mailbox/oauth/check"])
        precondition(owner.mailboxOAuth.first?["mailbox_identity_verified"] as? Bool == true)
        precondition(descendants(owner.stack).compactMap { ($0 as? NSTextField)?.stringValue }.contains("Google mailbox checked"))
        print("PASS: saved Google access checks its reusable mailbox address without another consent flow or mailbox password")

        // Reject the actual native mailbox POST. Only nonsecret form context
        // may return; a new password and explicit submit are always required.
        let awaitMailboxReply = {
            let deadline = Date().addingTimeInterval(5)
            while !nativeChannel.mailboxResponsePending && Date() < deadline {
                RunLoop.current.run(until: Date().addingTimeInterval(0.02))
            }
            precondition(nativeChannel.mailboxResponsePending)
        }
        let finishMailboxReply = {
            nativeChannel.rejectMailboxResponse()
            let deadline = Date().addingTimeInterval(5)
            while owner.busy && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
            precondition(!owner.busy)
        }
        let initialMailboxPosts = nativeChannel.mailboxPostCount
        for provider in [0, 1] {
            owner.showMailboxPasswordSetup()
            owner.mailboxKind.selectItem(at: provider)
            owner.mailboxKindChanged()
            owner.mailboxFields["username"]!.stringValue = "fictional@example.test"
            if provider == 1 {
                owner.mailboxFields["host"]!.stringValue = "imap.example.test"
                owner.mailboxFields["port"]!.stringValue = "1993"
            }
            let expectedHost = owner.mailboxFields["host"]!.stringValue
            let expectedPort = owner.mailboxFields["port"]!.stringValue
            owner.mailboxFields["password"]!.stringValue = "fictional-rejected-app-password"
            let submittedPassword = owner.mailboxFields["password"]!
            owner.saveMailbox()
            precondition(submittedPassword.stringValue.isEmpty)
            awaitMailboxReply()
            finishMailboxReply()
            print("CHECK: rejected native mailbox retry preserved address: \(owner.mailboxFields["username"]?.stringValue == "fictional@example.test"); password blank: \(owner.mailboxFields["password"]?.stringValue.isEmpty == true)")
            precondition(owner.mailboxKind.indexOfSelectedItem == provider)
            precondition(owner.mailboxFields["username"]!.stringValue == "fictional@example.test")
            precondition(owner.mailboxFields["host"]!.stringValue == expectedHost)
            precondition(owner.mailboxFields["port"]!.stringValue == expectedPort)
            precondition(owner.mailboxFields["password"] is NSSecureTextField && owner.mailboxFields["password"]!.stringValue.isEmpty)
            precondition(descendants(owner.stack).compactMap { ($0 as? NSTextField)?.stringValue }.contains { $0.contains("email server did not accept") })
            precondition(!nativeChannel.mailboxResponsePending)
            let unsentRetryPassword = owner.mailboxFields["password"]!
            unsentRetryPassword.stringValue = "fictional-unsent-retry-password"
            owner.showFactors()
            precondition(unsentRetryPassword.stringValue.isEmpty)
        }
        precondition(nativeChannel.mailboxPostCount == initialMailboxPosts + 2)
        let editingID = "mailbox-" + String(repeating: "a", count: 24)
        owner.editMailboxPassword({ let button = NSButton(); button.identifier = NSUserInterfaceItemIdentifier(editingID); return button }())
        owner.mailboxFields["password"]!.stringValue = "fictional-rejected-replacement"
        owner.saveMailbox()
        awaitMailboxReply()
        let postsWhilePending = nativeChannel.mailboxPostCount
        owner.saveMailbox()
        owner.pauseAccess()
        precondition(owner.busy && nativeChannel.mailboxPostCount == postsWhilePending)
        finishMailboxReply()
        precondition(owner.editingMailbox == editingID && owner.mailboxFields["password"]!.stringValue.isEmpty)
        owner.mailboxFields["password"]!.stringValue = "fictional-explicit-retry"
        owner.saveMailbox()
        awaitMailboxReply()
        let activeMailboxScreen = owner.stack
        owner.busy = false
        owner.showFactors()
        let destinationScreen = owner.stack
        precondition(activeMailboxScreen !== destinationScreen)
        nativeChannel.rejectMailboxResponse()
        let staleMailboxDeadline = Date().addingTimeInterval(0.2)
        while Date() < staleMailboxDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(owner.stack === destinationScreen && !owner.busy)
        precondition(nativeChannel.mailboxPostCount == initialMailboxPosts + 4 && !nativeChannel.mailboxResponsePending)
        print("PASS: rejected native mailbox setup retains only nonsecret context, clears passwords, requires explicit retry and cannot replace a navigated screen")
        owner.sources = []
        for kind in ["sms", "device-email"] {
            owner.smsSetups = kind == "sms" ? [["account": "fixture"]] : []
            owner.deviceEmailSetups = kind == "device-email" ? [["account": "fixture"]] : []
            owner.showImportSummary(["fixture"], issues: [("fixture", "Verification must be connected.")])
            precondition(descendants(owner.stack).compactMap { ($0 as? NSButton)?.title }.contains("Review verification methods"))
        }
        owner.smsSetups = []
        owner.deviceEmailSetups = []
        print("PASS: import completion offers verification for SMS-only and device-email-only setup")

        let fingerprint = String(repeating: "a", count: 64)
        let deviceMailboxID = "mailbox-" + String(repeating: "b", count: 24)
        let previewID = String(repeating: "c", count: 32)
        for (route, payload, needsSetup) in [
            ("owner/device-email/preview", ["account": "personal-pypi", "fingerprint": fingerprint, "mailbox": deviceMailboxID], true),
            ("owner/device-email/preview", ["account": "personal-pypi", "fingerprint": fingerprint, "mailbox": "gmail-mailbox-" + String(repeating: "a", count: 24)], true),
            ("owner/device-email/apply", ["id": previewID], true),
            ("owner/device-email/discard", ["id": previewID], false),
            ("owner/device-email/remove", ["account": "personal-pypi", "fingerprint": fingerprint], false)
        ] {
            let rule = try! OwnerGatewayRoute(route, body: JSONSerialization.data(withJSONObject: payload))
            precondition(rule.requiresSetup == needsSetup)
        }
        for payload in [["account": "personal-pypi", "fingerprint": fingerprint, "mailbox": "https://mail.example.test"],
                        ["account": "personal-pypi", "fingerprint": fingerprint, "mailbox": deviceMailboxID, "template": "unreviewed"]] {
            do {
                _ = try OwnerGatewayRoute("owner/device-email/preview", body: JSONSerialization.data(withJSONObject: payload))
                preconditionFailure("Unreviewed device email route accepted")
            } catch {}
        }
        print("PASS: device-email preview/apply require fresh setup; exact discard/removal are restrictive and arbitrary filters or mailbox URLs are refused")

        let deviceSetup: [String: Any] = ["account": "personal-pypi", "label": "PyPI", "fingerprint": fingerprint,
            "connected": false, "mailboxes": [["id": deviceMailboxID, "label": "Saved Gmail", "recipient": "fictional@example.test", "kind": "imap"]]]
        nativeChannel.deviceEmailPreview = ["id": previewID, "expires": Date().timeIntervalSince1970 + 120,
            "account": "personal-pypi", "label": "PyPI", "recipient": "fictional@example.test", "mailbox_label": "Saved Gmail",
            "operations": [["name": "status", "description": "Confirm your signed-in PyPI username"]]]
        nativeChannel.state = ["accounts": [], "catalog": [], "device_email_setups": [deviceSetup]]
        owner.accept(nativeChannel.state)
        owner.showFactors()
        views = descendants(owner.stack)
        precondition(owner.deviceEmailMailboxMenus["personal-pypi"]?.numberOfItems == 1)
        precondition(!views.contains { $0 is NSSecureTextField })
        let reviewButton = views.compactMap { $0 as? NSButton }.first { $0.title == "Review email connection" }!
        owner.previewDeviceEmail(reviewButton)
        let previewDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < previewDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(owner.deviceEmailReview?["id"] as? String == previewID)
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains { $0.contains("existing approved reads are retained") })
        owner.cancelDeviceEmail()
        let discardDeadline = Date().addingTimeInterval(3)
        while !nativeChannel.deviceEmailRequests.contains("owner/device-email/discard") && Date() < discardDeadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        precondition(owner.deviceEmailReview == nil && !nativeChannel.deviceEmailRequests.contains("owner/device-email/apply"))
        print("PASS: native PyPI device email reuses a checked mailbox without secret reentry, shows a review and cancels without applying")

        owner.presentDeviceEmailReview(nativeChannel.deviceEmailPreview, expectedAccount: "personal-pypi")
        owner.applyDeviceEmail(); owner.applyDeviceEmail()
        let applyDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < applyDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        precondition(nativeChannel.deviceEmailRequests.filter { $0 == "owner/device-email/apply" }.count == 1)
        precondition(owner.deviceEmailReview == nil)
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Setup saved · delivery unverified"))
        print("PASS: native device-email confirmation sends one apply and reports saved setup without claiming delivery")

        func requireDeviceEmail(_ condition: @autoclosure () -> Bool, _ checkpoint: String) {
            guard condition() else {
                fputs("FAIL: native-device-email-checkpoint " + checkpoint + "\n", stderr)
                exit(1)
            }
        }
        nativeChannel.deviceEmailApplyFailure = true
        owner.presentDeviceEmailReview(nativeChannel.deviceEmailPreview, expectedAccount: "personal-pypi")
        owner.applyDeviceEmail()
        let staleDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < staleDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        requireDeviceEmail(owner.deviceEmailReview == nil, "stale_review_consumed")
        let applyCount = nativeChannel.deviceEmailRequests.filter { $0 == "owner/device-email/apply" }.count
        owner.applyDeviceEmail()
        requireDeviceEmail(nativeChannel.deviceEmailRequests.filter { $0 == "owner/device-email/apply" }.count == applyCount, "stale_apply_not_replayed")
        var expiredReview = nativeChannel.deviceEmailPreview
        expiredReview["expires"] = Date().timeIntervalSince1970 - 1
        owner.deviceEmailReview = expiredReview
        owner.applyDeviceEmail()
        let expiryExplanation = "This email review expired. Choose the connected mailbox again in Verification."
        let expiryDeadline = Date().addingTimeInterval(5)
        while !descendants(owner.stack).compactMap({ ($0 as? NSTextField)?.stringValue }).contains(expiryExplanation)
                && Date() < expiryDeadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        requireDeviceEmail(owner.deviceEmailReview == nil, "expired_review_consumed")
        requireDeviceEmail(nativeChannel.deviceEmailRequests.filter { $0 == "owner/device-email/apply" }.count == applyCount, "expired_apply_not_sent")
        requireDeviceEmail(descendants(owner.stack).compactMap { ($0 as? NSTextField)?.stringValue }.contains { $0.contains("review expired") }, "expired_message_rendered")
        owner.presentDeviceEmailReview(nativeChannel.deviceEmailPreview, expectedAccount: "personal-pypi")
        owner.showReady()
        requireDeviceEmail(owner.deviceEmailReview == nil, "navigation_review_cleared")
        let deviceNavigationDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < deviceNavigationDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        owner.deviceEmailSetups = [["account": "personal-pypi", "label": "PyPI", "fingerprint": fingerprint, "connected": false, "mailboxes": []]]
        owner.showFactors()
        views = descendants(owner.stack)
        requireDeviceEmail(views.compactMap { ($0 as? NSButton)?.title }.contains("Connect a mailbox"), "missing_mailbox_setup_offered")
        requireDeviceEmail(!views.compactMap { ($0 as? NSButton)?.title }.contains("Review email connection"), "missing_mailbox_review_absent")
        owner.deviceEmailSetups[0]["configured"] = true
        owner.showFactors()
        views = descendants(owner.stack)
        requireDeviceEmail(views.compactMap { ($0 as? NSButton)?.title }.contains("Disconnect device email"), "configured_disconnect_offered")
        requireDeviceEmail(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Email connection needs attention"), "configured_attention_shown")
        owner.presentDeviceEmailReview(nativeChannel.deviceEmailPreview, expectedAccount: "personal-pypi")
        owner.pauseAccess()
        requireDeviceEmail(owner.deviceEmailReview == nil, "pause_review_cleared")
        let devicePauseDeadline = Date().addingTimeInterval(5)
        while owner.busy && Date() < devicePauseDeadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        requireDeviceEmail(nativeChannel.deviceEmailRequests.filter { $0 == "owner/device-email/apply" }.count == applyCount, "pause_apply_not_replayed")
        print("PASS: stale native device-email apply is not replayed; navigation/pause clear review and missing mailboxes offer setup or restrictive disconnect")

        func requireLocalUX(_ condition: @autoclosure () -> Bool, _ checkpoint: String) {
            guard condition() else {
                fputs("FAIL: native-local-ux-checkpoint " + checkpoint + "\n", stderr)
                exit(1)
            }
        }
        owner.accounts = [["account": "fixture", "label": "Fixture account", "route": "browser",
                           "portable_ready": true, "connected": false, "challenges": [["kind": "unknown"]]]]
        owner.agents = ["claude", "codex"]
        owner.ready()
        views = descendants(owner.stack)
        requireLocalUX(views.compactMap { ($0 as? NSButton)?.title }.contains("Use Claude Code"), "claude_action_label")
        requireLocalUX(!views.compactMap { ($0 as? NSButton)?.title }.contains("Open Claude Code"), "desktop_action_absent")
        requireLocalUX(views.compactMap { ($0 as? NSButton)?.title }.contains("Open Codex"), "codex_action_label")
        let help = views.compactMap { $0 as? NSButton }.first { $0.title == "Review sign-in help" }
        requireLocalUX(help?.action == #selector(AccountAccess.inspectSavedSignIn), "help_action_present")
        let verificationRequestsBeforeHelp = nativeChannel.verificationRequestCount
        owner.inspectSavedSignIn(help!)
        views = descendants(owner.stack)
        requireLocalUX(!owner.busy && nativeChannel.verificationRequestCount == verificationRequestsBeforeHelp, "help_no_verification_request")
        requireLocalUX(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("This version cannot open a website sign-in window for you. Review the saved connection and its verification methods here."), "visible_handoff_unavailable")
        requireLocalUX(views.compactMap { ($0 as? NSButton)?.title }.contains("Review account connection"), "connection_navigation_present")
        requireLocalUX(views.compactMap { ($0 as? NSButton)?.title }.contains("Review verification methods"), "verification_navigation_present")
        let claudeButton = NSButton()
        claudeButton.identifier = NSUserInterfaceItemIdentifier("claude")
        owner.openAgent(claudeButton)
        views = descendants(owner.stack)
        requireLocalUX(views.compactMap { ($0 as? NSButton)?.title }.contains("Open Terminal"), "terminal_action_label")
        requireLocalUX(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains { $0.contains("Opening Terminal alone does not start Claude Code.") }, "terminal_launch_honest")
        requireLocalUX(!owner.busy && nativeChannel.verificationRequestCount == verificationRequestsBeforeHelp, "claude_no_verification_request")
        owner.openPreferredAgent()
        views = descendants(owner.stack)
        requireLocalUX(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Use Claude Code"), "preferred_agent_help")
        requireLocalUX(!owner.busy && nativeChannel.verificationRequestCount == verificationRequestsBeforeHelp, "preferred_agent_no_verification_request")
        print("PASS: Claude Code actions show honest local guidance; unsupported visible sign-in help makes no verification request")
        let feedbackOwner = AccountAccess(fixtureRoot: fixtureRoot, session: fixtureSession,
                                          managedAgents: blockedHelpers, ownerProfile: missingFixtureProfile)
        let feedbackWindow = OwnerApprovalWindowFixture(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 740),
                                                        styleMask: [.titled], backing: .buffered, defer: false)
        feedbackOwner.window = feedbackWindow
        func drainApprovalFeedback(_ checkpoint: String) {
            var drained = false
            DispatchQueue.main.async { drained = true }
            let deadline = Date().addingTimeInterval(5)
            while !drained && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
            requireLocalUX(drained, checkpoint)
        }
        feedbackOwner.busy = true
        feedbackOwner.page("Original setup", "Synthetic approval progress")
        feedbackOwner.progress()
        let originalFeedback = feedbackOwner.ownerSetupContext.snapshot()
        feedbackOwner.ownerApprovalProgress(.requestingApproval, identifier: UUID(), context: originalFeedback)
        // The first event has been queued, but no progress label has been bound.
        feedbackOwner.page("Replacement page", "The original request no longer owns this page")
        feedbackOwner.progress()
        let replacementStatus: NSTextField = feedbackOwner.status
        drainApprovalFeedback("approval_first_event_drained")
        requireLocalUX(replacementStatus.stringValue == "Preparing…" && feedbackWindow.approvalFrontRequests == 0
                       && feedbackOwner.systemApprovalProgress?.id == nil, "approval_first_event_page_replacement_ignored")
        let beforeNewOperation = feedbackOwner.ownerSetupContext.snapshot()
        feedbackOwner.ownerApprovalProgress(.requestingApproval, identifier: UUID(), context: beforeNewOperation)
        feedbackOwner.busy = false
        feedbackOwner.busy = true
        drainApprovalFeedback("approval_new_operation_drained")
        requireLocalUX(replacementStatus.stringValue == "Preparing…" && feedbackWindow.approvalFrontRequests == 0,
                       "approval_same_page_new_operation_ignored")
        let beforeWindowChange = feedbackOwner.ownerSetupContext.snapshot()
        feedbackOwner.ownerApprovalProgress(.requestingApproval, identifier: UUID(), context: beforeWindowChange)
        let replacementWindow = OwnerApprovalWindowFixture(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 740),
                                                           styleMask: [.titled], backing: .buffered, defer: false)
        feedbackOwner.window = replacementWindow
        drainApprovalFeedback("approval_new_window_drained")
        requireLocalUX(replacementStatus.stringValue == "Preparing…" && feedbackWindow.approvalFrontRequests == 0
                       && replacementWindow.approvalFrontRequests == 0, "approval_window_replacement_ignored")
        feedbackOwner.page("Current setup", "Synthetic approval progress")
        feedbackOwner.progress()
        let liveFeedback = feedbackOwner.ownerSetupContext.snapshot(), liveFeedbackID = UUID()
        feedbackOwner.ownerApprovalProgress(.requestingApproval, identifier: liveFeedbackID, context: liveFeedback)
        drainApprovalFeedback("approval_live_begin_drained")
        requireLocalUX(feedbackOwner.status.stringValue == "Find the separate macOS dialog “Authorize Account Access setup” and approve with Touch ID or your Mac login password. If no dialog appears, wait up to two minutes; the request stops without sending account setup data."
                       && replacementWindow.approvalFrontRequests == 1, "approval_live_begin_rendered_once")
        feedbackOwner.ownerApprovalProgress(.approvalAccepted, identifier: liveFeedbackID, context: liveFeedback)
        feedbackOwner.page("A later page", "The accepted event must not change this page")
        feedbackOwner.progress()
        drainApprovalFeedback("approval_stale_accepted_drained")
        requireLocalUX(feedbackOwner.status.stringValue == "Preparing…" && replacementWindow.approvalFrontRequests == 1,
                       "approval_accepted_page_replacement_ignored")
        let finalFeedback = feedbackOwner.ownerSetupContext.snapshot(), finalFeedbackID = UUID()
        feedbackOwner.ownerApprovalProgress(.requestingApproval, identifier: finalFeedbackID, context: finalFeedback)
        feedbackOwner.ownerApprovalProgress(.approvalAccepted, identifier: finalFeedbackID, context: finalFeedback)
        drainApprovalFeedback("approval_live_pair_drained")
        requireLocalUX(feedbackOwner.status.stringValue == "Mac approval accepted. Continuing setup…"
                       && replacementWindow.approvalFrontRequests == 2 && feedbackOwner.systemApprovalProgress?.id == nil,
                       "approval_live_pair_completes_without_extra_front")
        feedbackOwner.busy = false
        print("PASS: approval feedback ignores delayed first/accepted events after page, window or operation changes and fronts only its current setup")
        requireLocalUX(fixtureProfileReads == 1 && helperLock.withLock { unexpectedHelperCalls == 0 }, "fixture_dependencies_only")
        print("PASS: UI fixtures use only temporary roots, synthetic owner profiles, fake helpers and intercepted URL requests")


    }
}
