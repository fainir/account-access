import AppKit
import Foundation

final class VerificationRetryFixture: URLProtocol {
    static var retriedVisible = false
    static var retried = false
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let payload: [String: Any]
        if request.url?.path == "/owner/verify" {
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

@main struct OwnerScreenChecks {
    static func main() {
        _ = NSApplication.shared
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
        print("PASS: all four sync fields and connect action render; token is masked; fields fit the narrow window")
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
        precondition(AccountAccess.authenticatorQRText(["otpauth://totp/Example?secret=FICTIONAL"]) != nil)
        precondition(AccountAccess.authenticatorQRText(["otpauth-migration://offline?data=FICTIONAL"]) != nil)
        precondition(AccountAccess.authenticatorQRText(["https://example.com"]) == nil)
        precondition(AccountAccess.authenticatorQRText(["otpauth://totp/A", "otpauth://totp/B"]) == nil)
        owner.sources = [["id": "fixture-factor", "kind": "totp", "accounts": ["fixture"]]]
        owner.showFactors()
        views = descendants(owner.stack)
        precondition(owner.factorFields["seed"] is NSSecureTextField)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Import authenticator QR image"))
        print("PASS: authenticator setup masks keys and accepts only a single setup or transfer QR")
        owner.browserUpdates = [["account": "fixture", "fingerprint": "fictional"]]
        owner.ready()
        views = descendants(owner.stack)
        precondition(views.compactMap { ($0 as? NSButton)?.title }.contains("Update sign-in connection"))
        print("PASS: reviewed sign-in repairs are available without entering the password again")
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [VerificationRetryFixture.self]
        owner.session = URLSession(configuration: sessionConfig)
        owner.status = NSTextField(labelWithString: "Checking")
        _ = try! owner.waitForConnection(["id": "first"], account: "fixture", timeout: 10, visible: true)
        precondition(VerificationRetryFixture.retriedVisible)
        print("PASS: owner-visible troubleshooting stays visible after a transient retry")
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
        print("PASS: pre-request failures cannot claim SMS delivery was tested; owner attention distinguishes unknown pages and required presence")
    }
}
