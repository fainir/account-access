import AppKit
import Foundation

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
    }
}
