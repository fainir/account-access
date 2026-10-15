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
    }
}
