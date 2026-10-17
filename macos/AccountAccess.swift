import AppKit
import CryptoKit
import Foundation
import Security
import UniformTypeIdentifiers
import CoreImage
import ServiceManagement

final class FlippedView: NSView { override var isFlipped: Bool { true } }

final class SurfaceView: NSView {
    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true
        layer?.cornerRadius = 14
        layer?.borderWidth = 1
        updateColors()
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func viewDidChangeEffectiveAppearance() { super.viewDidChangeEffectiveAppearance(); updateColors() }
    func updateColors() {
        layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.5).cgColor
    }
}

final class LocalRequests: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

// A real native installer and owner interface. No terminal or web view is used.
// All connections and permissions go through the existing authenticated owner API.
final class AccountAccess: NSObject, NSApplicationDelegate, NSTextFieldDelegate {
    let files = FileManager.default
    let root: URL = {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let canonical = home.appendingPathComponent(".local/share/account-access")
        let legacy = home.appendingPathComponent("Library/Application Support/AccountAccess")
        let fallback = !FileManager.default.fileExists(atPath: canonical.appendingPathComponent("config.json").path) && FileManager.default.fileExists(atPath: legacy.appendingPathComponent("config.json").path) ? legacy : canonical
        return URL(fileURLWithPath: ProcessInfo.processInfo.environment["ACCOUNT_ACCESS_DATA_DIR"] ?? (Bundle.main.object(forInfoDictionaryKey: "AccountAccessDataDirectory") as? String) ?? fallback.path)
    }()
    lazy var runtime = URL(fileURLWithPath: ProcessInfo.processInfo.environment["ACCOUNT_ACCESS_INSTALL_DIR"] ?? (Bundle.main.object(forInfoDictionaryKey: "AccountAccessInstallDirectory") as? String) ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/share/account-access/runtime").path)
    var window: NSWindow!
    var stack: NSStackView!
    var status: NSTextField!
    var button: NSButton!
    var spinner: NSProgressIndicator!
    var services: NSPopUpButton!
    var username: NSTextField!
    var password: NSSecureTextField!
    var permission: NSButton!
    var connectAction: NSButton?
    var savedSignInAction: NSButton?
    var catalog: [[String: Any]] = []
    var accounts: [[String: Any]] = []
    var agents = ["claude"]
    var principals: [String] = []
    var sources: [[String: Any]] = []
    var mailboxes: [[String: Any]] = []
    var mailboxFields: [String: NSTextField] = [:]
    var mailboxServerViews: [NSView] = []
    var mailboxKind: NSPopUpButton!
    var factorMailboxMenu: NSPopUpButton?
    var factorEntryViews: [NSView] = []
    var editingMailbox: String?
    var passwordSync: [[String: Any]] = []
    var navigationFailures: [[String: Any]] = []
    var browserUpdates: [[String: Any]] = []
    var smsSetups: [[String: Any]] = []
    var browserSessionAccounts: [[String: Any]] = []
    var browserSessionChoice: [String: Any]?
    var browserSessionWatch: String?
    var browserSessionUsername: NSTextField!
    var smsProgress: Progress?
    var smsDiagnostics: String?
    var verificationDetails: [String: String] = [:]
    var syncAccounts: NSPopUpButton!
    var syncFields: [String: NSTextField] = [:]
    var automaticSessions: [String: [String: Any]] = [:]
    var section = "accounts"
    var selectedAccount: String?
    let accent = NSColor(calibratedRed: 0.36, green: 0.31, blue: 0.87, alpha: 1)
    var importID = ""
    var importRows: [(String, NSButton, NSPopUpButton, Bool)] = []
    var importFile: URL?
    var deleteExport: NSButton!
    var importAuthenticators: NSButton!
    var factorMenu: NSPopUpButton!
    var factorFields: [String: NSTextField] = [:]
    var base: URL!
    var token = ""
    let ownerConnectionLock = NSRecursiveLock()
    var systemOwner: DesktopOwnerConnection?
    var systemOwnerSelected = false
    var requiresSystemInstallation = Bundle.main.object(forInfoDictionaryKey: "AccountAccessSystemInstallationRequired") as? Bool == true
    var systemOwnerReady = false
    var systemSetupGeneration = 0
    var managedAgents = ManagedAgentSetup()
    var systemAgentClientID: String?
    var connectAgentsAfterSetup = false
    #if ACCOUNT_ACCESS_UI_CHECKS
    var fixtureSystemOwnerSelected = false
    #endif
    var systemOwnerConfigured: Bool {
        #if ACCOUNT_ACCESS_UI_CHECKS
        if fixtureSystemOwnerSelected { return true }
        #endif
        return requiresSystemInstallation || systemOwnerSelected || DesktopOwnerProfile.isInstalled
    }
    func nativeOwner() throws -> DesktopOwnerConnection? {
        guard systemOwnerConfigured else { return nil }
        systemOwnerSelected = true // Never fall back after selecting a protected registration.
        if let systemOwner { return systemOwner }
        do {
            let connection = try DesktopOwnerConnection(profile: DesktopOwnerProfile())
            systemOwner = connection
            return connection
        } catch { throw Failure.message("The protected installation could not be verified. Check the Account Access installation before connecting an account.") }
    }
    var busy = false
    var backgroundRecovery: [String: Any] = [:]
    var backgroundServiceStatus = "unknown"
    var failedAccount: String?
    let localRequests = LocalRequests()
    static func isExample(_ account: [String: Any]) -> Bool {
        ["controlled-demo", "public-example"].contains(account["environment"] as? String ?? "")
    }
    static func isReady(_ account: [String: Any]) -> Bool {
        account["connected"] as? Bool == true && account["portable_ready"] as? Bool != false
            && (account["challenges"] as? [[String: Any]] ?? []).isEmpty
    }
    var preferredAgent: String { agents.contains("claude") ? "Claude Code" : agents.contains("codex") ? "Codex" : "your AI tool" }
    var requestText: String {
        if accounts.contains(where: { !Self.isExample($0) && Self.isReady($0) }) {
            return "Summarize the approved information from my connected services and save the results as one task."
        }
        if accounts.contains(where: { Self.isExample($0) && Self.isReady($0) }) {
            return "Try my connected example accounts and save the results as one task. Label the results as examples."
        }
        return "Check which of my configured services are available and tell me what needs attention."
    }
    lazy var session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        config.urlCache = nil
        config.connectionProxyDictionary = [:]
        config.timeoutIntervalForRequest = 30
        return URLSession(configuration: config, delegate: localRequests, delegateQueue: nil)
    }()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        let menu = NSMenu()
        let item = NSMenuItem()
        let appMenu = NSMenu()
        let repair = appMenu.addItem(withTitle: "Repair installation…", action: #selector(install), keyEquivalent: "")
        repair.target = self
        let pause = appMenu.addItem(withTitle: "Pause Account Access", action: #selector(pauseAccess), keyEquivalent: "")
        pause.target = self
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Quit Account Access", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.submenu = appMenu
        menu.addItem(item)
        NSApp.mainMenu = menu
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 740),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Account Access"
        window.minSize = NSSize(width: 880, height: 650)
        window.titlebarAppearsTransparent = true
        window.isReleasedWhenClosed = false
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if systemOwnerConfigured { openSystemOwner(); return }
        if files.fileExists(atPath: root.appendingPathComponent("desktop.json").path),
           files.isExecutableFile(atPath: runtime.appendingPathComponent("bin/account-access").path), installedPayloadMatches() {
            let metadata = try? Data(contentsOf: root.appendingPathComponent("desktop.json"))
            let info = metadata.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            if info?["version"] as? String == Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String {
                reopen()
            } else { welcome() }
        } else { welcome() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard let window else { return true }
        window.makeKeyAndOrderFront(nil)
        sender.activate(ignoringOtherApps: true)
        return true
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if busy {
            let alert = NSAlert()
            alert.messageText = "Please let the current step finish"
            alert.informativeText = "The installer or account connection is still working."
            alert.runModal()
            return .terminateCancel
        }
        return .terminateNow
    }

    func page(_ title: String, _ subtitle: String) {
        let shell = NSView()
        window.contentView = shell
        let haveOwner = systemOwnerReady || (!systemOwnerConfigured && base != nil && !token.isEmpty)
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        shell.addSubview(scroll)
        if haveOwner {
            let sidebar = NSStackView()
            sidebar.orientation = .vertical
            sidebar.alignment = .leading
            sidebar.spacing = 14
            sidebar.translatesAutoresizingMaskIntoConstraints = false
            shell.addSubview(sidebar)
            sidebar.addArrangedSubview(makeLabel("Account Access", 20, .labelColor, .semibold))
            sidebar.addArrangedSubview(makeLabel("Your AI. Your accounts.", 13, .secondaryLabelColor))
            let navigation: [(String, String, Selector, String)] = [
                ("Accounts", "rectangle.grid.2x2", #selector(showReady), "accounts"),
                ("Verification", "checkmark.shield", #selector(showFactors), "verification"),
                ("Import passwords", "arrow.down.doc", #selector(importPasswords), "import"),
                ("Password sync", "arrow.triangle.2.circlepath", #selector(showPasswordSync), "sync"),
                ("Add account", "plus", #selector(backToConnections), "add")]
            for (name, image, selector, key) in navigation {
                let control = NSButton(title: name, target: self, action: selector)
                control.image = NSImage(systemSymbolName: image, accessibilityDescription: nil)
                control.imagePosition = .imageLeading
                control.bezelStyle = .rounded
                control.isBordered = false
                control.font = .systemFont(ofSize: 14, weight: key == section ? .semibold : .regular)
                control.contentTintColor = key == section ? accent : .secondaryLabelColor
                control.wantsLayer = true
                control.layer?.cornerRadius = 9
                control.layer?.backgroundColor = key == section ? accent.withAlphaComponent(0.1).cgColor : NSColor.clear.cgColor
                control.isEnabled = !busy
                sidebar.addArrangedSubview(control)
                control.widthAnchor.constraint(equalToConstant: 180).isActive = true
                control.heightAnchor.constraint(equalToConstant: 36).isActive = true
            }
            sidebar.addArrangedSubview(makeLabel("Saved on this Mac\nYou approve what your AI can read.", 13, .secondaryLabelColor))
            NSLayoutConstraint.activate([
                sidebar.leadingAnchor.constraint(equalTo: shell.leadingAnchor, constant: 22),
                sidebar.topAnchor.constraint(equalTo: shell.topAnchor, constant: 38),
                sidebar.widthAnchor.constraint(equalToConstant: 180)])
        }
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: shell.leadingAnchor, constant: haveOwner ? 220 : 0),
            scroll.trailingAnchor.constraint(equalTo: shell.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: shell.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: shell.bottomAnchor)])
        let view = FlippedView()
        view.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = view
        stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 40),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -40),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 38),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -38),
            view.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor)])
        label("ACCOUNT ACCESS", 12, accent, .semibold)
        label(title, 30, .labelColor, .semibold)
        label(subtitle, 17, .secondaryLabelColor)
    }

    func makeLabel(_ text: String, _ size: CGFloat = 16, _ color: NSColor = .labelColor,
                   _ weight: NSFont.Weight = .regular) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: text)
        field.font = .systemFont(ofSize: size, weight: weight)
        field.textColor = color
        field.isSelectable = false
        return field
    }

    @discardableResult func label(_ text: String, _ size: CGFloat = 16,
                                 _ color: NSColor = .labelColor,
                                 _ weight: NSFont.Weight = .regular) -> NSTextField {
        let field = makeLabel(text, size, color, weight)
        stack.addArrangedSubview(field)
        field.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        return field
    }

    @discardableResult func card(_ title: String, _ detail: String, status: String? = nil,
                                good: Bool = true) -> NSStackView {
        let surface = SurfaceView()
        surface.translatesAutoresizingMaskIntoConstraints = false
        let body = NSStackView()
        body.orientation = .vertical
        body.alignment = .leading
        body.spacing = 9
        body.translatesAutoresizingMaskIntoConstraints = false
        surface.addSubview(body)
        let heading = NSStackView()
        heading.orientation = .horizontal
        heading.addArrangedSubview(makeLabel(title, 18, .labelColor, .semibold))
        if let status { heading.addArrangedSubview(makeLabel(status, 13, good ? .systemGreen : .systemOrange, .medium)) }
        body.addArrangedSubview(heading)
        let description = makeLabel(detail, 14, .secondaryLabelColor)
        body.addArrangedSubview(description)
        description.widthAnchor.constraint(equalTo: body.widthAnchor).isActive = true
        stack.addArrangedSubview(surface)
        NSLayoutConstraint.activate([
            surface.widthAnchor.constraint(equalTo: stack.widthAnchor),
            body.leadingAnchor.constraint(equalTo: surface.leadingAnchor, constant: 20),
            body.trailingAnchor.constraint(equalTo: surface.trailingAnchor, constant: -20),
            body.topAnchor.constraint(equalTo: surface.topAnchor, constant: 18),
            body.bottomAnchor.constraint(equalTo: surface.bottomAnchor, constant: -18)])
        return body
    }

    @discardableResult func action(_ title: String, _ selector: Selector) -> NSButton {
        let control = NSButton(title: title, target: self, action: selector)
        control.bezelStyle = .rounded
        control.controlSize = .large
        control.font = .systemFont(ofSize: 14, weight: .medium)
        control.heightAnchor.constraint(greaterThanOrEqualToConstant: 36).isActive = true
        stack.addArrangedSubview(control)
        return control
    }

    @discardableResult func primary(_ title: String, _ selector: Selector) -> NSButton {
        let control = action(title, selector)
        control.bezelColor = accent
        control.contentTintColor = .white
        control.font = .systemFont(ofSize: 15, weight: .semibold)
        return control
    }

    func progress() {
        spinner = NSProgressIndicator()
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.startAnimation(nil)
        stack.addArrangedSubview(spinner)
        status = label("Preparing…", 17)
    }

    func welcome() {
        let updating = files.isExecutableFile(atPath: runtime.appendingPathComponent("bin/account-access").path)
        page(updating ? "A simpler way to use your accounts" : "Your AI can handle the sign-in", "Connect once. Ask naturally. Account Access takes care of supported sign-ins.")
        card("1  Install", "Your existing AI tools are connected automatically.")
        card("2  Connect your accounts", "Import saved passwords and approve the information your AI can read.")
        card("3  Keep using your AI", "Ask in ordinary language. No special command in each session.")
        button = primary(updating ? "Update Account Access" : "Install Account Access", #selector(install))
        label("macOS · Installs in your user folder · No administrator password needed", 13, .secondaryLabelColor)
    }

    @objc func install() {
        if systemOwnerConfigured { openSystemOwner(); return }
        guard !busy else { return }
        busy = true
        page("Installing Account Access", "The app prepares everything needed for secure website access.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.saveApplication()
                guard let script = Bundle.main.url(forResource: "install", withExtension: "sh") else {
                    throw Failure.message("The installer is incomplete. Download it again from the official release.")
                }
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/bin/sh")
                process.arguments = [script.path]
                var environment = ProcessInfo.processInfo.environment
                environment["ACCOUNT_ACCESS_NO_OPEN"] = "1"
                environment["ACCOUNT_ACCESS_DATA_DIR"] = self.root.path
                environment["ACCOUNT_ACCESS_INSTALL_DIR"] = self.runtime.path
                guard let expectedHash = Bundle.main.object(forInfoDictionaryKey: "AccountAccessWheelSHA256") as? String,
                      expectedHash.count == 64 else {
                    throw Failure.message("The installer is missing its signed package checksum. Download the complete app from the official release.")
                }
                environment["ACCOUNT_ACCESS_EXPECTED_WHEEL_SHA256"] = expectedHash
                // The package is part of the signed app. Ignore inherited paths;
                // the bootstrap also checks it against the signed checksum.
                environment.removeValue(forKey: "ACCOUNT_ACCESS_BUNDLED_WHEEL")
                if let wheel = Bundle.main.url(forResource: "account_access", withExtension: "whl") {
                    environment["ACCOUNT_ACCESS_BUNDLED_WHEEL"] = wheel.path
                }
                process.environment = environment
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = pipe
                process.standardInput = FileHandle.nullDevice
                try process.run()
                var pending = Data()
                while true {
                    let data = pipe.fileHandleForReading.availableData
                    if data.isEmpty { break }
                    pending.append(data)
                    while let end = pending.firstIndex(of: 10) {
                        let line = String(decoding: pending[..<end], as: UTF8.self)
                        pending.removeSubrange(...end)
                        let steps = ["1/4": "Preparing the installer…", "2/4": "Downloading and verifying Account Access…",
                                     "3/4": "Installing the secure local app…", "4/4": "Preparing website access…"]
                        if let step = steps.first(where: { line.hasPrefix($0.key) }) {
                            DispatchQueue.main.async { self.status.stringValue = step.value }
                        }
                    }
                }
                process.waitUntilExit()
                guard process.terminationStatus == 0 else {
                    throw Failure.message("Installation could not finish. Check your internet connection, then try again. No account credentials were changed.")
                }
                try self.loadOwner()
                let backgroundStatus = self.prepareBackgroundRecovery()
                _ = try self.request("owner/install", body: [:])
                let state = try self.request("owner/state")
                DispatchQueue.main.async {
                    self.busy = false
                    self.backgroundServiceStatus = backgroundStatus
                    self.accept(state)
                    if self.accounts.contains(where: { $0["connected"] as? Bool == true }) {
                        self.ready()
                    } else { self.connections() }
                }
            } catch { self.fail(error, retry: #selector(self.install)) }
        }
    }

    @objc func reopen() {
        if systemOwnerConfigured { openSystemOwner(); return }
        if !installedPayloadMatches() { install(); return }
        busy = true
        page("Opening Account Access", "Reconnecting to your secure local app…")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.saveApplication()
                let process = Process()
                process.executableURL = self.runtime.appendingPathComponent("bin/account-access")
                process.arguments = ["--root", self.root.path, "start", "--no-open"]
                process.standardInput = FileHandle.nullDevice
                process.standardOutput = FileHandle.nullDevice
                process.standardError = FileHandle.nullDevice
                try process.run()
                process.waitUntilExit()
                guard process.terminationStatus == 0 else {
                    throw Failure.message("The local app could not start. Try again.")
                }
                try self.loadOwner()
                let backgroundStatus = self.prepareBackgroundRecovery()
                _ = try self.request("owner/install", body: [:])
                let state = try self.request("owner/state")
                DispatchQueue.main.async {
                    self.busy = false
                    self.backgroundServiceStatus = backgroundStatus
                    self.accept(state)
                    if self.accounts.contains(where: { $0["connected"] as? Bool == true }) {
                        self.ready()
                    } else { self.connections() }
                }
            } catch { self.fail(error, retry: #selector(self.reopen)) }
        }
    }

    func saveApplication() throws {
        let directory = files.homeDirectoryForCurrentUser.appendingPathComponent("Applications")
        try files.createDirectory(at: directory, withIntermediateDirectories: true)
        let target = directory.appendingPathComponent("Account Access.app")
        let source = Bundle.main.bundleURL
        if source.standardizedFileURL == target.standardizedFileURL { return }
        if files.fileExists(atPath: target.path) {
            let attributes = try files.attributesOfItem(atPath: target.path)
            guard attributes[.type] as? FileAttributeType == .typeDirectory,
                  let previous = Bundle(url: target),
                  previous.bundleIdentifier == "com.fainir.accountaccess" else {
                throw Failure.message("Another file already uses the Account Access app name. Your existing file has been preserved.")
            }
        }
        // Replacing an app bundle does not replace an already-running process.
        // Ask prior owner UIs to close normally; their busy-step guards can
        // refuse. The independent local account service remains running.
        let peers = NSRunningApplication.runningApplications(withBundleIdentifier: "com.fainir.accountaccess")
            .filter { $0.processIdentifier != getpid() }
        for peer in peers where !peer.isTerminated { _ = peer.terminate() }
        func stillRunning(_ peer: NSRunningApplication) -> Bool {
            guard let current = NSRunningApplication(processIdentifier: peer.processIdentifier) else { return false }
            return !current.isTerminated && current.bundleIdentifier == "com.fainir.accountaccess"
        }
        let closeDeadline = Date().addingTimeInterval(15)
        while peers.contains(where: stillRunning) && Date() < closeDeadline {
            Thread.sleep(forTimeInterval: 0.1)
        }
        guard !peers.contains(where: stillRunning) else {
            throw Failure.message("The previous Account Access window is still open. Finish its current step and quit it, then retry this update. Your accounts are preserved.")
        }
        let temporary = directory.appendingPathComponent(".account-access-" + UUID().uuidString + ".app")
        try files.copyItem(at: source, to: temporary)
        defer { try? files.removeItem(at: temporary) }
        if files.fileExists(atPath: target.path) {
            _ = try files.replaceItemAt(target, withItemAt: temporary)
        } else {
            try files.moveItem(at: temporary, to: target)
        }
    }

    enum Failure: Error { case message(String) }

    func installedPayloadMatches() -> Bool {
        guard let expected = Bundle.main.object(forInfoDictionaryKey: "AccountAccessWheelSHA256") as? String else { return false }
        return BackgroundRecovery.installationMatches(runtime: runtime, expected: expected)
    }

    func prepareBackgroundRecovery() -> String {
        // ServiceManagement must be called by the saved app, rather than the
        // original download that the installer copied into Applications.
        do {
            let layout = try BackgroundRecovery.Layout(bundle: .main)
            guard layout.root.standardizedFileURL == root.standardizedFileURL,
                  layout.runtime.standardizedFileURL == runtime.standardizedFileURL else { return "custom_configuration" }
            let saved = files.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Account Access.app/Contents/MacOS/AccountAccess")
            let process = Process()
            process.executableURL = saved
            process.arguments = ["--background-enable"]
            process.standardInput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            let output = Pipe()
            process.standardOutput = output
            var environment = ProcessInfo.processInfo.environment
            for key in ["ACCOUNT_ACCESS_DATA_DIR", "ACCOUNT_ACCESS_INSTALL_DIR", "PYTHONPATH", "PYTHONHOME"] { environment.removeValue(forKey: key) }
            process.environment = environment
            try process.run()
            let deadline = Date().addingTimeInterval(20)
            while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
            if process.isRunning { process.terminate(); return "unavailable" }
            let data = output.fileHandleForReading.readDataToEndOfFile()
            guard process.terminationStatus == 0, data.count <= 4096,
                  let result = try JSONSerialization.jsonObject(with: data) as? [String: String],
                  let status = result["status"], ["enabled", "requires_approval", "unavailable"].contains(status) else { return "unavailable" }
            return status
        } catch { return "unavailable" }
    }

    @objc func openBackgroundSettings() { SMAppService.openSystemSettingsLoginItems() }

    @objc func pauseAccess() {
        guard !busy else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/stop", body: [:])
                DispatchQueue.main.async {
                    self.busy = false
                    self.systemSetupGeneration += 1
                    self.systemOwner?.close()
                    self.systemOwnerReady = false
                    self.token = ""
                    self.base = nil
                    for field in self.mailboxFields.values where field is NSSecureTextField { field.stringValue = "" }
                    for field in self.factorFields.values where field is NSSecureTextField { field.stringValue = "" }
                    for field in self.syncFields.values where field is NSSecureTextField { field.stringValue = "" }
                    self.password?.stringValue = ""
                    self.page("Account Access is paused", "Saved connections are preserved. Background recovery stays paused after login until you resume it.")
                    self.primary("Resume Account Access", #selector(self.reopen))
                }
            } catch { self.fail(error, retry: #selector(self.reopen)) }
        }
    }

    func loadOwner() throws {
        ownerConnectionLock.lock()
        defer { ownerConnectionLock.unlock() }
        if let native = try nativeOwner() { try native.prepare(); return }
        let metadata = root.appendingPathComponent("desktop.json")
        let attributes = try files.attributesOfItem(atPath: metadata.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              let info = try JSONSerialization.jsonObject(with: Data(contentsOf: metadata)) as? [String: Any],
              let url = info["url"] as? String, let parts = URLComponents(string: url),
              parts.scheme == "http", parts.host == "127.0.0.1", parts.port != nil,
              parts.path == "/", parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil,
              let endpoint = parts.url,
              let bearer = info["token"] as? String, !bearer.isEmpty,
              let hex = info["instance_key"] as? String, hex.count == 64 else {
            throw Failure.message("The secure local app could not be verified. Reopen Account Access and try again.")
        }
        var key = Data()
        for offset in stride(from: 0, to: hex.count, by: 2) {
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: 2)
            guard let byte = UInt8(hex[start..<end], radix: 16) else {
                throw Failure.message("The local app identity is invalid.")
            }
            key.append(byte)
        }
        var random = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
            throw Failure.message("A secure connection could not be prepared.")
        }
        let challenge = random.map { String(format: "%02x", $0) }.joined()
        base = endpoint
        token = bearer
        let proof = try request("owner/ready?challenge=" + challenge)["proof"] as? String
        let expected = HMAC<SHA256>.authenticationCode(for: Data(challenge.utf8), using: SymmetricKey(data: key))
            .map { String(format: "%02x", $0) }.joined()
        guard proof == expected else {
            token = ""
            throw Failure.message("The secure local app could not be verified.")
        }
    }

    func request(_ route: String, body: [String: Any]? = nil) throws -> [String: Any] {
        ownerConnectionLock.lock()
        defer { ownerConnectionLock.unlock() }
        if let native = try nativeOwner() {
            do {
                let response = try native.request(route, body: body)
                return try checkedOwnerResponse(response.0, response.1, pending: route == "owner/vault/enroll")
            } catch DesktopOwnerFailure.approval {
                throw Failure.message("Setup was not approved. Your saved connections are preserved. Try the setup action again when you are ready to approve it on this Mac.")
            } catch is DesktopOwnerFailure {
                throw Failure.message("The protected app did not respond. Check setup progress before trying the action again. Your saved connections are preserved.")
            } catch is OwnerGatewayError {
                throw Failure.message("This action is not available through the protected connection yet. Your saved connections are preserved.")
            }
        }
        // A supervised restart changes the port and capability. Verify the
        // current registration before sending any setup data. This does not
        // replay an operation whose response was lost or rebuild its form.
        if !route.hasPrefix("owner/ready?") { try loadOwner() }
        guard let url = URL(string: route, relativeTo: base)?.absoluteURL,
              url.scheme == "http", url.host == "127.0.0.1", url.port == base.port,
              url.user == nil, url.password == nil else {
            throw Failure.message("The local request is invalid.")
        }
        var message = URLRequest(url: url)
        message.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        if let body = body {
            message.httpMethod = "POST"
            message.setValue(base.absoluteString.dropLast().description, forHTTPHeaderField: "Origin")
            message.setValue("application/json", forHTTPHeaderField: "Content-Type")
            message.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        let done = DispatchSemaphore(value: 0)
        var result: Result<[String: Any], Error> = .failure(Failure.message("The local app did not respond."))
        session.dataTask(with: message) { data, response, error in
            defer { done.signal() }
            do {
                if let error = error { throw error }
                guard let response = response as? HTTPURLResponse, let data = data,
                      let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw Failure.message("The local app could not complete this step. Your existing connections are preserved.")
                }
                result = .success(try self.checkedOwnerResponse(response.statusCode, payload))
            } catch { result = .failure(error) }
        }.resume()
        guard done.wait(timeout: .now() + 35) == .success else {
            throw Failure.message("The local app took too long to respond. Try again.")
        }
        return try result.get()
    }

    func checkedOwnerResponse(_ code: Int, _ payload: [String: Any], pending: Bool = false) throws -> [String: Any] {
        if code == 200 || (pending && code == 202) { return payload }
        let reasons = [
            "owner_setup_authorization_required": "Approve this setup action on your Mac to continue.",
            "owner_channel_unavailable": "The protected app reconnected. Check setup progress before trying this action again.",
            "owner_backend_unavailable": "The protected app is temporarily unavailable. Check progress before retrying this action.",
            "broker_worker_recovering": "The protected app is recovering. Check again shortly; your action was not repeated.",
            "vault_setup_repair_required": "The protected account store needs repair. Your saved data is preserved.",
            "password_sync_identity_mismatch": "This password-manager item belongs to a different username. Select the item for the account you imported.",
            "password_source_item_changed": "This item must be an active login for the approved website, with one username and password.",
            "password_source_access_removed": "The password source rejected access. Check its read-only token and the selected vault and item.",
            "password_source_unavailable": "The password source is temporarily unavailable. Try again when it is online.",
            "mailbox_connection_failed": "The email server did not accept this connection. Check the email address and application password in Verification. No website sign-in was started.",
            "mailbox_temporarily_unavailable": "The mailbox is temporarily unreachable. Your saved setup is preserved; Account Access can retry without another login approval.",
            "mailbox_tls_verification_failed": "The mailbox's secure connection could not be verified. Check the server settings; Account Access will not use an unverified connection.",
            "mailbox_not_connected": "Connect this email account in Verification first. No website sign-in was started.",
            "mailbox_identity_mismatch": "The connected Gmail account does not match the mailbox approved for these login messages. Connect the correct Gmail account.",
            "mailbox_uid_tracking_unavailable": "This mail server did not provide the message tracking needed to exclude old codes. No website sign-in was started.",
            "invalid_mailbox_setup": "Check the email address, mail server and application password. Other email providers require their TLS IMAP server and port.",
            "mailbox_already_connected": "This mailbox is already saved. Use Update app password or Check connection on its card.",
            "mailbox_source_mismatch": "Choose the mailbox for the email address and mail server already approved for this website.",
            "mailbox_scope_missing": "Reconnect the configured Gmail account with permission to read login messages.",
            "account_not_connected": "Connect the configured Gmail account through Manage permissions first.",
            "provider_rejected_access": "The email provider rejected this connection. Reconnect the mailbox in Verification.",
            "network_unavailable": "The email provider could not be reached. Your saved setup is preserved; try Check email connection when it is online.",
            "invalid_authenticator_export": "This image is not a supported Authenticator transfer QR. Choose a complete export or the website's original setup QR.",
            "authenticator_multiple_batches": "This export spans multiple QR codes. In Google Authenticator, export only the account you want to connect and choose its QR image.",
            "unsupported_authenticator_settings": "This authenticator uses settings that are not supported yet. Six-digit SHA-1 TOTP is required.",
            "authenticator_preview_expired": "The import preview expired. Choose the QR image again.",
            "authenticator_selection_changed": "The connected account changed during the preview. Choose the QR image again and review the account.",
            "password_sync_requires_https_origin": "Enter only the HTTPS server address, without a path or query.",
            "invalid_password_sync_link": "Check the connection details. Vault and item IDs must be the exact 26-character IDs from 1Password."
        ]
        throw Failure.message(reasons[payload["reason"] as? String ?? ""] ?? "The local app could not complete this step. Your existing connections are preserved.")
    }

    func openSystemOwner() {
        guard !busy else { return }
        systemAgentClientID = nil
        connectAgentsAfterSetup = false
        systemSetupGeneration += 1
        let generation = systemSetupGeneration
        busy = true
        page("Opening Account Access", "Connecting to your protected local app…")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let state = try self.request("owner/state")
                DispatchQueue.main.async {
                    guard generation == self.systemSetupGeneration else { return }
                    self.busy = false
                    self.presentSystemState(state)
                }
            } catch { self.fail(error, retry: #selector(self.reopen)) }
        }
    }

    func presentSystemState(_ state: [String: Any]) {
        systemSetupGeneration += 1
        systemOwnerReady = false
        switch DesktopVaultScreen(state) {
        case .ready:
            if state["local_host_actions"] as? Bool == false {
                let client = state["managed_client"] as? [String: Any] ?? [:]
                guard client["status"] as? String == "INSTALLED", let identity = client["client_id"] as? String,
                      identity.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
                      identity == systemAgentClientID else {
                    checkSystemAgentSetup(state)
                    return
                }
            }
            systemOwnerReady = true
            accept(state)
            if accounts.contains(where: { $0["connected"] as? Bool == true }) { ready() }
            else { connections() }
        case .needsOwner:
            page("Set up your private account store", "Connect once. Your AI can use approved accounts without seeing their passwords or login codes.")
            card("Protected on this Mac", "The account store runs separately from your AI tools. macOS asks you to approve setup before any credentials are saved.")
            primary("Set up Account Access", #selector(enrollSystemVault))
        case .paused:
            page("Account Access is paused", "Saved connections are preserved. Approve Resume on this Mac to let your AI use them again.")
            primary("Resume Account Access", #selector(enrollSystemVault))
        case .initializing:
            page("Preparing your private account store", "Account Access is finishing setup. You can leave this window open; it will continue automatically.")
            progress()
            status.stringValue = "Preparing secure storage…"
            action("Check progress", #selector(reopen))
            pollSystemSetup(generation: systemSetupGeneration, remaining: 60)
        case .repair:
            page("Your installation needs attention", "The protected account store could not be opened safely. Your saved data is preserved. Check the installation before connecting more accounts.")
            action("Check again", #selector(reopen))
        }
    }

    @objc func enrollSystemVault() {
        guard !busy else { return }
        connectAgentsAfterSetup = true
        systemSetupGeneration += 1
        busy = true
        page("Approve setup on this Mac", "Use the macOS approval window to continue. Your AI tools never receive this approval or your credentials.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let state = try self.request("owner/vault/enroll", body: [:])
                DispatchQueue.main.async {
                    self.busy = false
                    if state["vault_setup"] != nil { self.presentSystemState(state) }
                    else { self.openSystemOwner() }
                }
            } catch { self.fail(error, retry: #selector(self.reopen)) }
        }
    }

    func showSystemAgentSetup() {
        page("Connect your AI tools", "One shared connection works with your existing agents. You do not need to choose a tool or type a command in each session.")
        card("Use your AI as usual", "Account Access adds its skill and automatic session instructions for supported tools. Your existing preferences are preserved.")
        primary("Connect automatically", #selector(connectSystemAgents))
    }

    func checkSystemAgentSetup(_ state: [String: Any]) {
        if connectAgentsAfterSetup { connectSystemAgents(); return }
        busy = true
        page("Checking your AI connection", "Verifying the installed portable skill…")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            let local = try? self.managedAgents.status()
            DispatchQueue.main.async {
                self.busy = false
                let server = state["managed_client"] as? [String: Any] ?? [:]
                if local?["status"] as? String == "INSTALLED", server["status"] as? String == "INSTALLED",
                   let identity = local?["client_id"] as? String, identity == server["client_id"] as? String {
                    self.systemAgentClientID = identity
                    self.presentSystemState(state)
                } else { self.showSystemAgentSetup() }
            }
        }
    }

    @objc func connectSystemAgents() {
        guard !busy else { return }
        connectAgentsAfterSetup = false
        systemSetupGeneration += 1
        busy = true
        page("Connecting your AI tools", "Preparing one private connection and automatic skill discovery. macOS may ask you to approve this setup action.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.managedAgents.connect { route, body in try self.request(route, body: body) }
                let state = try self.request("owner/state")
                guard let client = state["managed_client"] as? [String: Any], client["status"] as? String == "INSTALLED",
                      let identity = client["client_id"] as? String else { throw ManagedAgentSetupFailure.invalidResponse }
                DispatchQueue.main.async {
                    self.busy = false
                    self.systemAgentClientID = identity
                    self.presentSystemState(state)
                }
            } catch {
                self.fail(Failure.message("Automatic AI setup could not finish. Your saved accounts and existing tool preferences are preserved. Check the protected installation, then reopen Account Access. A previous installation may need migration before it can be replaced."), retry: #selector(self.reopen))
            }
        }
    }

    func pollSystemSetup(generation: Int, remaining: Int) {
        guard remaining > 0 else {
            status.stringValue = "Setup is taking longer. Choose Check progress to reconnect."
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            guard let self, generation == self.systemSetupGeneration, !self.busy else { return }
            DispatchQueue.global(qos: .utility).async {
                let state = try? self.request("owner/state") // Reconnect and read only; never replay enrollment.
                DispatchQueue.main.async {
                    guard generation == self.systemSetupGeneration, !self.busy else { return }
                    if let state, DesktopVaultScreen(state) != .initializing { self.presentSystemState(state) }
                    else { self.pollSystemSetup(generation: generation, remaining: remaining - 1) }
                }
            }
        }
    }

    func accept(_ state: [String: Any]) {
        backgroundRecovery = state["background_recovery"] as? [String: Any] ?? [:]
        navigationFailures = state["navigation_failures"] as? [[String: Any]] ?? []
        browserUpdates = state["browser_updates"] as? [[String: Any]] ?? []
        smsSetups = state["sms_setups"] as? [[String: Any]] ?? []
        browserSessionAccounts = state["browser_session_accounts"] as? [[String: Any]] ?? []
        passwordSync = state["password_sync"] as? [[String: Any]] ?? []
        catalog = state["catalog"] as? [[String: Any]] ?? []
        accounts = state["accounts"] as? [[String: Any]] ?? []
        sources = state["code_sources"] as? [[String: Any]] ?? []
        mailboxes = state["mailboxes"] as? [[String: Any]] ?? []
        principals = state["principals"] as? [String] ?? []
        agents = state["integrations"] as? [String] ?? principals
        automaticSessions = state["automatic_sessions"] as? [String: [String: Any]] ?? [:]
        verificationDetails = [:]
        let jobs = state["connection_jobs"] as? [String: [String: Any]] ?? [:]
        for job in jobs.values.sorted(by: { ($0["status"] as? String == "RUNNING") && ($1["status"] as? String != "RUNNING") }) {
            guard let account = job["account"] as? String, verificationDetails[account] == nil,
                  let attention = job["attention"] as? [String: Any] else { continue }
            let detail = Self.verificationDetailText(attention["diagnostics"] as? [String: Any] ?? [:])
            if !detail.isEmpty { verificationDetails[account] = detail }
        }
    }

    static func verificationDetailText(_ diagnostic: [String: Any]) -> String {
        // Only a closed route vocabulary and structural booleans reach this owner view.
        let words = Set("account account_verifications accounts app auth authenticate authentication callback challenge check compromised_password device email error flow github login mobile new notification oauth otp password password_reset profile recovery required reset security session sessions settings setup sms sso sudo totp two-factor two_factor trusted-device trusted_device verification verified-device verified_device verify webauthn".split(separator: " ").map(String.init))
        func route(_ raw: Any?) -> String? {
            guard let value = raw as? String, value.count <= 240,
                  let separator = value.range(of: ":/") else { return nil }
            let host = String(value[..<separator.lowerBound])
            guard host == "external" || host.range(of: "^origin_[0-9]{1,3}$", options: .regularExpression) != nil else { return nil }
            let parts = value[separator.upperBound...].split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count <= 9, parts.allSatisfy({ $0.isEmpty || $0 == "?" || words.contains(String($0)) }) else { return nil }
            return value
        }
        var lines: [String] = []
        if let page = route(diagnostic["page"]) { lines.append("Page: " + page) }
        for form in (diagnostic["forms"] as? [[String: Any]] ?? []).prefix(8) {
            guard let destination = route(form["route"]), let method = form["method"] as? String,
                  ["GET", "POST", "other"].contains(method) else { continue }
            lines.append("Form: " + method + " " + destination)
        }
        if let fields = diagnostic["fields"] as? [String: Any] {
            let present = ["sms_totp", "app_totp", "otp_id", "otp_name", "one_time_code", "recovery_code"].filter { (fields[$0] as? NSNumber)?.boolValue == true }
            lines.append("Code fields present: " + (present.isEmpty ? "none" : present.joined(separator: ", ")))
        }
        if let controls = diagnostic["controls"] as? [String: [String: Any]] {
            for name in ["sms", "totp", "toggle"] {
                guard let control = controls[name], let count = control["count"] as? Int,
                      (0...8).contains(count), let visible = control["visible"] as? Bool else { continue }
                lines.append(name + " controls: " + String(count) + (visible ? " visible" : " hidden"))
            }
        }
        if let notices = diagnostic["notices"] as? [String: Any] {
            for name in ["delivery_failed", "rate_limited", "unavailable", "invalid_request"] {
                if notices[name] as? Bool == true { lines.append("Provider notice: " + name) }
            }
        }
        if let progress = diagnostic["progress"] as? [String: Any] {
            if let method = progress["method"] as? String, ["sms", "email", "totp"].contains(method) {
                lines.append("Selected method: " + method)
            }
            for phase in ["password_submit_attempted", "sms_requested", "email_requested", "sms_code_filled", "email_code_filled", "totp_code_filled", "sms_submit_attempted", "email_submit_attempted", "totp_submit_attempted"] {
                if progress[phase] as? Bool == true { lines.append("Login stage: " + phase) }
            }
            if let request = progress["code_request"] as? [String: Any] {
                if let page = route(request["page"]) { lines.append("Code request page: " + page) }
                if let status = request["http_status"] as? Int, (100...599).contains(status) {
                    lines.append("Code request HTTP: " + String(status))
                }
                if let transport = request["transport"] as? String, ["document", "xhr", "fetch", "other"].contains(transport) {
                    lines.append("Code request transport: " + transport)
                }
                if let destination = route(request["redirect"]) { lines.append("Code request redirect: " + destination) }
                for flag in ["ajax", "auto"] {
                    if let value = request[flag] as? Bool { lines.append("Code request " + flag + ": " + String(value)) }
                }
                if let button = request["button"] as? String, ["recovery", "cancel", "send", "confirm", "continue", "other"].contains(button) {
                    lines.append("Code request button: " + button)
                }
                for field in (request["fields"] as? [[String: Any]] ?? []).prefix(32) {
                    guard let type = field["type"] as? String,
                          ["hidden", "text", "tel", "number", "checkbox", "radio", "select-one", "submit", "button", "other"].contains(type) else { continue }
                    let flags = ["required", "checked", "invalid"].filter { field[$0] as? Bool == true }
                    lines.append("Code request field: " + type + (flags.isEmpty ? "" : " (" + flags.joined(separator: ", ") + ")"))
                }
            }
        }
        for asset in (diagnostic["assets"] as? [String] ?? []).prefix(150) {
            if asset.count <= 240 && asset.range(of: "^https://github\\.githubassets\\.com/assets/[A-Za-z0-9_.-]+\\.(js|css)$", options: .regularExpression) != nil {
                lines.append("Asset: " + asset)
            }
        }
        return lines.joined(separator: "\n")
    }

    func chooseAgents() {
        page("Connecting your existing AI tools", "The portable skill and CLI work with compatible agents. Installed tools are detected automatically.")
        progress()
        installAgents()
    }

    @objc func installAgents() {
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/install", body: [:])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.connections() }
            } catch { self.fail(error, retry: #selector(self.reopen)) }
        }
    }

    func connections() {
        connectAction = nil
        savedSignInAction = nil
        section = "add"
        let connected = accounts.filter { $0["connected"] as? Bool == true && $0["portable_ready"] as? Bool != false }
        page("Connect an account", "Choose a supported account and approve its reads. You only do this once.")
        primary("Import saved passwords", #selector(importPasswords))
        let available = catalog.filter { entry in
            entry["id"] as? String == selectedAccount || !connected.contains { $0["account"] as? String == entry["id"] as? String }
        }
        if available.isEmpty {
            card("All supported accounts are connected", "Your approved accounts are ready to use. Additional websites need a supported connection before Account Access can sign in.")
            action("Back to my accounts", #selector(showReady))
            return
        }
        services = NSPopUpButton()
        for entry in available {
            services.addItem(withTitle: entry["label"] as? String ?? "Account")
            services.lastItem?.representedObject = entry
        }
        services.target = self
        services.action = #selector(serviceChanged)
        services.font = .systemFont(ofSize: 17)
        stack.addArrangedSubview(services)
        label("Email or username", 14, .secondaryLabelColor)
        username = NSTextField()
        username.placeholderString = "Email or username"
        username.font = .systemFont(ofSize: 18)
        username.delegate = self
        username.heightAnchor.constraint(equalToConstant: 40).isActive = true
        stack.addArrangedSubview(username)
        username.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        label("Password", 14, .secondaryLabelColor)
        password = NSSecureTextField()
        password.placeholderString = "Password"
        password.font = .systemFont(ofSize: 18)
        password.delegate = self
        password.heightAnchor.constraint(equalToConstant: 40).isActive = true
        stack.addArrangedSubview(password)
        password.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        permission = NSButton(checkboxWithTitle: "", target: nil, action: nil)
        permission.font = .systemFont(ofSize: 16)
        permission.target = self
        permission.action = #selector(connectionInputChanged)
        (permission.cell as? NSButtonCell)?.wraps = true
        stack.addArrangedSubview(permission)
        permission.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        if let selectedAccount, let index = available.firstIndex(where: { $0["id"] as? String == selectedAccount }) {
            services.selectItem(at: index)
        }
        selectedAccount = nil
        serviceChanged()
        button = primary("Connect account", #selector(connect))
        connectAction = button
        if available.contains(where: { entry in accounts.contains { $0["account"] as? String == entry["id"] as? String } }) {
            savedSignInAction = action("Use saved sign-in", #selector(retrySaved))
        }
        if !connected.isEmpty { action("Start using my connected accounts", #selector(showReady)) }
        label("Namecheap has a limited sign-in check. Email, authenticator or security-key steps still need provider validation. SauceDemo and The Internet are public testing examples. Other websites require reviewed connectors.", 13, .secondaryLabelColor)
        connectionInputChanged()
    }

    @objc func serviceChanged() {
        let entry = services.selectedItem?.representedObject as? [String: Any] ?? [:]
        let operations = entry["operations"] as? [[String: Any]] ?? []
        permission.title = "Allow your AI to: " + operations.compactMap { $0["description"] as? String }.joined(separator: "; ")
        permission.state = .off
        username.stringValue = ""
        password.stringValue = ""
        connectionInputChanged()
    }

    func controlTextDidChange(_ notification: Notification) { connectionInputChanged() }

    @objc func connectionInputChanged() {
        guard let permission, let username, let password else { return }
        connectAction?.isEnabled = permission.state == .on && !username.stringValue.isEmpty && !password.stringValue.isEmpty
        let selected = services?.selectedItem?.representedObject as? [String: Any]
        savedSignInAction?.isEnabled = permission.state == .on && accounts.contains { $0["account"] as? String == selected?["id"] as? String }
    }

    @objc func connect() {
        guard permission.state == .on, !username.stringValue.isEmpty, !password.stringValue.isEmpty,
              let entry = services.selectedItem?.representedObject as? [String: Any],
              let service = entry["id"] as? String else { return }
        let body: [String: Any] = ["service": service, "username": username.stringValue,
                                   "password": password.stringValue, "agents": ["generic"]]
        let existing = accounts.contains { $0["account"] as? String == service }
        failedAccount = service
        password.stringValue = ""
        busy = true
        page("Connecting your account", "Checking the saved login and the read you approved…")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let job: [String: Any]
                if existing {
                    _ = try self.request("owner/credential", body: ["account": service,
                        "username": body["username"]!, "password": body["password"]!])
                    let names = (entry["operations"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
                    _ = try self.request("owner/grant", body: ["account": service, "principal": "generic", "operations": names])
                    job = try self.request("owner/verify", body: ["account": service])
                } else {
                    job = try self.request("owner/add", body: body)
                }
                let state = try self.waitForConnection(job, account: service)
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.connections() }
            } catch { self.fail(error, retry: #selector(self.retryConnection)) }
        }
    }

    func verificationMessage(_ attention: [String: Any]) -> String {
        let diagnostic = attention["diagnostics"] as? [String: Any] ?? [:]
        let progress = diagnostic["progress"] as? [String: Any] ?? [:]
        let isSMS = attention["kind"] as? String == "sms"
            || (diagnostic["page"] as? String ?? "").contains("/two-factor/sms")
        let delivery = progress["sms_code_filled"] as? Bool == true
            ? "A fresh matching SMS code was received locally. Your saved password is preserved."
            : progress["sms_requested"] as? Bool == true
                ? "The website accepted the SMS request, but delivery is unconfirmed. Your saved password is preserved."
                : isSMS ? "No SMS delivery was tested. Your saved password is preserved."
                    : "Your saved password is preserved."
        switch attention["reason"] as? String ?? "" {
        case "browser_captcha_required":
            return "The website requires a browser security check that this connector cannot complete automatically. Your saved password is preserved."
        case "browser_recovery_required":
            return "The website opened account recovery. Use an available sign-in method in its window. " + delivery
        case "browser_passkey_required", "browser_device_required", "browser_admin_required", "browser_action_required":
            return "The website requires owner approval before continuing. " + delivery
        case "browser_state_unrecognized":
            return "The website returned a sign-in page this connector does not recognize. " + delivery
        case "browser_login_required":
            return "The website returned to password entry. " + delivery
        case "verification_method_unavailable", "verification_source_not_connected", "authenticator_not_enrolled":
            return "The website needs an available verification method connected. " + delivery
        case "verification_code_request_rejected", "verification_code_request_not_submitted":
            return "The website did not confirm the reviewed SMS request. " + delivery
        case "mailbox_result_limit":
            return "Too many recent emails match this sign-in. Account Access stopped instead of guessing a code. Review the mailbox and try again. " + delivery
        case "sms_gateway_result_limit":
            return "Too many messages match this SMS gateway connection. Account Access stopped instead of choosing from an incomplete list. " + delivery
        case "mailbox_scope_missing":
            return "The email connection is missing permission to read login messages. Reconnect that mailbox in Verification. " + delivery
        case "phone_not_paired":
            return "Pair your Android phone in Verification before checking this sign-in. " + delivery
        default:
            return "Sign-in stopped. " + delivery + " Review this website's sign-in connection."
        }
    }

    static func smsTimeoutMessage(deliveryStarted: Bool, incoming: Int, unreadable: Int) -> String {
        if !deliveryStarted {
            return "The sign-in did not reach a confirmed SMS request. No SMS delivery was tested and no filter was enabled. Your saved password is preserved."
        }
        if unreadable > 0 {
            return "New texts arrived, but some messages could not be decoded. No SMS filter was enabled. Update Account Access before trying again."
        }
        if incoming > 0 {
            return "New texts arrived, but none matched a supported GitHub login message. No SMS filter was enabled."
        }
        return "The website opened SMS code entry, but delivery was not confirmed. No new text reached Messages on this Mac. No SMS filter was enabled."
    }

    func waitForConnection(_ initial: [String: Any], account: String, timeout: TimeInterval = 150, visible: Bool = false) throws -> [String: Any] {
        guard var id = initial["id"] as? String else { throw Failure.message("The connection could not start.") }
        let deadline = Date().addingTimeInterval(timeout)
        var shownDetails = ""
        var shownReviewID = ""
        while Date() < deadline {
            let state = try request("owner/state")
            let jobs = state["connection_jobs"] as? [String: [String: Any]] ?? [:]
            if visible, let attention = jobs[id]?["attention"] as? [String: Any] {
                let explanation = verificationMessage(attention)
                let detail = Self.verificationDetailText(attention["diagnostics"] as? [String: Any] ?? [:])
                let addDetail = !detail.isEmpty && shownDetails != detail
                shownDetails = detail
                let reviewID = id
                let addFinish = shownReviewID != reviewID
                shownReviewID = reviewID
                DispatchQueue.main.async {
                    self.status.stringValue = explanation
                    if addDetail {
                        self.verificationDetails[account] = detail
                        let inspect = NSButton(title: "Show verification details", target: self, action: #selector(self.showVerificationDetails))
                        inspect.identifier = NSUserInterfaceItemIdentifier(detail)
                        self.stack.addArrangedSubview(inspect)
                    }
                    if addFinish {
                        let finish = NSButton(title: "Finish review", target: self, action: #selector(self.finishSignInReview))
                        finish.identifier = NSUserInterfaceItemIdentifier(reviewID)
                        self.stack.addArrangedSubview(finish)
                    }
                }
            }
            if let result = jobs[id], let outcome = result["status"] as? String, outcome != "RUNNING" {
                if outcome == "CONNECTED" { return state }
                if outcome == "RETRYABLE" {
                    Thread.sleep(forTimeInterval: 3)
                    let retry = try request("owner/verify", body: ["account": account, "visible": visible])
                    guard let next = retry["id"] as? String else { break }
                    id = next
                    DispatchQueue.main.async { self.status.stringValue = "The website is taking longer. Retrying safely…" }
                    continue
                }
                if visible, outcome == "NEEDS_USER", result["attention"] != nil {
                    // Return to the account card with its failed status and
                    // diagnostics after review; this never marks it connected.
                    return state
                }
                let reason = result["reason"] as? String ?? ""
                if reason == "browser_captcha_required" {
                    throw Failure.message("The website requires a browser security check that this connector cannot complete automatically. Your saved password is preserved; this sign-in remains unverified.")
                }
                if ["mailbox_result_limit", "mailbox_scope_missing", "phone_not_paired"].contains(reason) {
                    throw Failure.message(verificationMessage(["reason": reason]))
                }
                if reason == "mac_messages_permission_required" {
                    throw Failure.message("macOS has not allowed access to Messages. Enable iPhone text forwarding and grant the Account Access app Full Disk Access in Privacy settings, then retry this saved sign-in.")
                }
                if reason.contains("verification_method_unavailable") {
                    throw Failure.message("This website did not offer a connected verification method. Connect a method that is available on its sign-in page. Your imported password is already saved.")
                }
                if reason.contains("authenticator") || reason.contains("mailbox") || reason.contains("code_not_received") || reason.contains("verification_source") {
                    throw Failure.message("This login needs its verification method connected. Open Verification methods to enroll the authenticator, reconnect email, or check phone access. Your imported password is already saved.")
                }
                throw Failure.message("This account needs a sign-in check. Open Accounts to review this account or try its saved sign-in again. Your other connections are preserved.")
            }
            Thread.sleep(forTimeInterval: 0.8)
        }
        throw Failure.message("The website took too long to connect. Your saved configuration is preserved.")
    }

    @objc func retrySaved() {
        guard permission.state == .on, let entry = services.selectedItem?.representedObject as? [String: Any],
              let account = entry["id"] as? String else { return }
        failedAccount = account
        let names = (entry["operations"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/grant", body: ["account": account, "principal": "generic", "operations": names])
                DispatchQueue.main.async { self.busy = false; self.retryConnection() }
            } catch { self.fail(error, retry: #selector(self.backToConnections)) }
        }
    }

    @objc func retryConnection() {
        guard let account = failedAccount else { reopen(); return }
        busy = true
        page("Checking your saved sign-in", "Account Access will retry temporary failures while keeping login attempts limited.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let job = try self.request("owner/verify", body: ["account": account])
                let state = try self.waitForConnection(job, account: account)
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.connections() }
            } catch { self.fail(error, retry: #selector(self.retryConnection)) }
        }
    }

    @objc func showReady() {
        guard !busy else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.ready() }
            } catch { self.fail(error, retry: #selector(self.reopen)) }
        }
    }

    @objc func importPasswords() {
        section = "import"
        page("Import saved passwords", "Bring your supported logins from the password manager you already use.")
        card("1  Export your passwords", "In Chrome, open Password Manager, then Settings and Export passwords. Apple Passwords, Bitwarden and compatible 1Password CSV exports also work.")
        card("2  Choose the export", "Select the CSV file on this Mac. You'll review matching supported accounts before anything is saved.")
        card("3  Approve your accounts", "Choose the logins and reads you want to allow. Passwords are encrypted locally. You can move the export to Trash after importing.")
        primary("Choose password file", #selector(choosePasswordFile))
        card("Keeping passwords current", "Chrome and CSV exports are snapshots. Import a fresh export when those passwords change. A configured 1Password Connect source can update already-approved passwords automatically.")
        action("Connect a live password source", #selector(showPasswordSync))
        action("Back to my accounts", #selector(showReady))
    }

    @objc func choosePasswordFile() {
        let picker = NSOpenPanel()
        picker.allowedContentTypes = [.commaSeparatedText]
        picker.allowsMultipleSelection = false
        picker.message = "Select the password CSV exported by Chrome, Apple Passwords, Bitwarden, or 1Password. Only selected supported logins will be saved."
        guard picker.runModal() == .OK, let file = picker.url else { return }
        do {
            let attributes = try files.attributesOfItem(atPath: file.path)
            guard (attributes[.size] as? NSNumber)?.intValue ?? 4_000_001 <= 4_000_000 else {
                throw Failure.message("The password export is too large. Export fewer accounts and try again.")
            }
            let csv = try String(contentsOf: file, encoding: .utf8)
            busy = true
            page("Reviewing your saved logins", "Passwords stay in the local service and never appear in your AI chat.")
            progress()
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let preview = try self.request("owner/import/preview", body: ["csv": csv])
                    DispatchQueue.main.async { self.busy = false; self.importFile = file; self.reviewImport(preview) }
                } catch { self.fail(error, retry: #selector(self.importPasswords)) }
            }
        } catch { fail(error, retry: #selector(importPasswords)) }
    }

    func reviewImport(_ preview: [String: Any]) {
        section = "import"
        importID = preview["id"] as? String ?? ""
        importRows = []
        page("Choose the logins to import", "Check an account and approve its listed reads. Existing saved logins for selected accounts will be replaced.")
        for row in preview["rows"] as? [[String: Any]] ?? [] {
            let matches = row["matches"] as? [[String: Any]] ?? []
            guard !matches.isEmpty, let id = row["id"] as? String else { continue }
            let check = NSButton(checkboxWithTitle: (row["username"] as? String ?? "Login") + " · " + (row["website"] as? String ?? ""), target: nil, action: nil)
            check.font = .systemFont(ofSize: 16)
            stack.addArrangedSubview(check)
            let select = NSPopUpButton()
            for match in matches {
                let reads = (match["operations"] as? [[String: Any]] ?? []).compactMap { $0["description"] as? String }
                select.addItem(withTitle: (match["label"] as? String ?? "Account") + " — Allow: " + reads.joined(separator: "; "))
                select.lastItem?.representedObject = match
            }
            stack.addArrangedSubview(select)
            importRows.append((id, check, select, row["has_authenticator"] as? Bool == true))
        }
        label("Unsupported logins: " + String(preview["unsupported"] as? Int ?? 0) + ". These will not be saved; importing cannot add a website connector.", 14, .secondaryLabelColor)
        deleteExport = NSButton(checkboxWithTitle: "Move the plaintext export file to Trash after importing", target: nil, action: nil)
        deleteExport.state = .on
        stack.addArrangedSubview(deleteExport)
        importAuthenticators = NSButton(checkboxWithTitle: "Also enroll included authenticator keys for supported login recovery", target: nil, action: nil)
        if importRows.contains(where: { $0.3 }) { stack.addArrangedSubview(importAuthenticators) }
        primary("Import selected accounts", #selector(applyImport))
        action("Back", #selector(backToConnections))
    }

    @objc func applyImport() {
        let selections: [[String: Any]] = importRows.compactMap { id, check, menu, hasAuthenticator in
            guard check.state == .on, let entry = menu.selectedItem?.representedObject as? [String: Any], let account = entry["id"] as? String else { return nil }
            let ops = (entry["operations"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
            return ["row": id, "account": account, "operations": ops,
                    "include_authenticator": hasAuthenticator && importAuthenticators.state == .on && entry["authenticator_supported"] as? Bool == true]
        }
        guard !selections.isEmpty else { return }
        let remove = deleteExport.state == .on
        let file = importFile
        busy = true
        page("Importing your selected accounts", "Saving encrypted logins and checking the approved reads…")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try self.request("owner/import/apply", body: ["id": self.importID, "selections": selections])
                if remove, let file { try self.files.trashItem(at: file, resultingItemURL: nil) }
                var issues: [(String, String)] = []
                for job in result["jobs"] as? [[String: Any]] ?? [] {
                    if let account = job["account"] as? String {
                        do { _ = try self.waitForConnection(job, account: account) }
                        catch Failure.message(let message) { issues.append((account, message)) }
                        catch { issues.append((account, "The sign-in check could not finish. Your imported password is saved.")) }
                    }
                }
                let state = try self.request("owner/state")
                let imported = selections.compactMap { $0["account"] as? String }
                DispatchQueue.main.async {
                    self.busy = false; self.importFile = nil; self.importRows = []
                    self.accept(state); self.showImportSummary(imported, issues: issues)
                }
            } catch { self.fail(error, retry: #selector(self.importPasswords)) }
        }
    }

    func showImportSummary(_ imported: [String], issues: [(String, String)], verification: Bool = false) {
        section = verification ? "verification" : "import"
        page(verification ? "Verification saved" : "Passwords imported", "Your selected " + (verification ? "verification method is" : "logins are") + " encrypted locally. Review the sign-in checks below.")
        for account in imported {
            let issue = issues.first { $0.0 == account }?.1
            let saved = accounts.first { $0["account"] as? String == account } ?? [:]
            let name = saved["label"] as? String ?? account
            let ready = issue == nil && Self.isReady(saved)
            let explanation = ready ? (Self.isExample(saved) ? "Example sign-in verified. These results do not validate a personal account." : "Sign-in verified. This approved account is ready for your AI.") : "Your login is saved. Review the sign-in status before using this connection."
            let body = card(name, issue ?? explanation,
                            status: ready ? (Self.isExample(saved) ? "Example connected" : "Connected") : "Saved · Sign-in needs attention", good: ready)
            if !ready {
                let inspect = NSButton(title: "Show sign-in problem", target: self, action: #selector(inspectSavedSignIn))
                inspect.identifier = NSUserInterfaceItemIdentifier(account)
                body.addArrangedSubview(inspect)
            }
        }
        if !issues.isEmpty && !sources.isEmpty { action("Review verification methods", #selector(showFactors)) }
        primary("Go to my accounts", #selector(showReady))
    }

    @objc func inspectSavedSignIn(_ sender: NSButton) {
        guard let account = sender.identifier?.rawValue else { return }
        busy = true
        page("Checking your saved sign-in", "The website opens on this Mac. If the sign-in stops, its page stays open for up to five minutes so you can review the problem. Close that browser window when finished. Your permissions stay the same.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let job = try self.request("owner/verify", body: ["account": account, "visible": true])
                let state = try self.waitForConnection(job, account: account, timeout: 360, visible: true)
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.ready() }
            } catch { self.fail(error, retry: #selector(self.showReady)) }
        }
    }

    @objc func showBrowserSession(_ sender: NSButton) {
        guard let account = sender.identifier?.rawValue,
              let choice = browserSessionAccounts.first(where: { $0["account"] as? String == account }) else { return }
        browserSessionChoice = choice
        page("Use your signed-in Chrome account", "Connect an existing GitHub sign-in once, then let your AI reuse it for your approved reads.")
        card(choice["label"] as? String ?? "GitHub", "Your GitHub session cookies will be copied directly into this Mac's encrypted store. Account Access checks the signed-in username before saving. Cookies stay out of AI chat. Chrome will ask for temporary cookie and GitHub site access; the cookie permission can also cover sites already granted to this helper. The helper reads only GitHub cookies for this transfer and removes the temporary permissions afterward.")
        label("Expected GitHub username", 14, .secondaryLabelColor)
        browserSessionUsername = NSTextField(string: choice["username_hint"] as? String ?? "")
        browserSessionUsername.placeholderString = "Your GitHub username, not your email address"
        browserSessionUsername.setAccessibilityLabel("Expected GitHub username")
        stack.addArrangedSubview(browserSessionUsername)
        browserSessionUsername.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        primary("Prepare Chrome connection", #selector(startBrowserSession))
        action("Back to my accounts", #selector(showReady))
    }

    @objc func startBrowserSession() {
        guard let choice = browserSessionChoice, let account = choice["account"] as? String,
              let fingerprint = choice["fingerprint"] as? String else { return }
        let expected = browserSessionUsername.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard expected.range(of: "^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$", options: .regularExpression) != nil else {
            status.stringValue = "Enter the GitHub username shown on your signed-in account."
            return
        }
        busy = true
        page("Preparing your Chrome connection", "Setting up a five-minute request for this approved account.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            var observedRequest: String?
            do {
                let result = try self.request("owner/browser-session/start", body: ["account": account, "fingerprint": fingerprint, "username": expected])
                guard let id = result["id"] as? String, let path = result["extension_path"] as? String,
                      path == self.root.appendingPathComponent("GoogleMessagesExtension").path else {
                    throw Failure.message("The browser connection could not be prepared.")
                }
                observedRequest = id
                DispatchQueue.main.async {
                    self.busy = false
                    self.browserSessionWatch = id
                    self.page("Connect your open GitHub tab", "Open the Account Access browser helper on your signed-in GitHub tab, choose this account, and click Connect this GitHub sign-in. This page updates automatically after verification.")
                    self.card("One-time helper update", "If the helper is already installed, open Chrome Extensions and click Reload for Account Access. Otherwise choose Load unpacked and select the open GoogleMessagesExtension folder. The helper is now named Account Access — Browser Connections.")
                    self.label("Expected GitHub username: " + expected, 15, .secondaryLabelColor)
                    self.action("Open Chrome Extensions", #selector(self.openChromeExtensions))
                    self.action("Open GitHub in Chrome", #selector(self.openGitHubInChrome))
                    self.action("Cancel this connection", #selector(self.cancelBrowserSession))
                    NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: path)
                }
                let deadline = Date().addingTimeInterval(300)
                while Date() < deadline {
                    Thread.sleep(forTimeInterval: 0.8)
                    let state = try self.request("owner/state")
                    guard let pending = (state["browser_session_requests"] as? [[String: Any]])?.first(where: { $0["id"] as? String == id }) else { break }
                    let outcome = pending["status"] as? String ?? ""
                    if outcome == "CONNECTED" {
                        DispatchQueue.main.async {
                            guard self.browserSessionWatch == id else { return }
                            self.browserSessionWatch = nil; self.accept(state); self.ready()
                        }
                        return
                    }
                    if !["AWAITING_BROWSER", "VERIFYING"].contains(outcome) {
                        let reason = pending["reason"] as? String ?? ""
                        throw Failure.message(Self.browserSessionFailureMessage(reason))
                    }
                }
                DispatchQueue.main.async {
                    guard self.browserSessionWatch == id else { return }
                    self.browserSessionWatch = nil
                    self.fail(Failure.message("This browser connection expired or was cancelled. Your existing connections are preserved."), retry: #selector(self.showReady))
                }
            } catch {
                let failedRequest = observedRequest
                DispatchQueue.main.async {
                    guard failedRequest.map({ self.browserSessionWatch == $0 }) ?? self.busy else { return }
                    self.browserSessionWatch = nil
                    self.fail(error, retry: #selector(self.showReady))
                }
            }
        }
    }

    static func browserSessionFailureMessage(_ reason: String) -> String {
        let detail: String
        switch reason {
        case "browser_session_identity_mismatch": detail = "Chrome is signed in to a different GitHub username. Start again with the correct tab and username."
        case "browser_login_required": detail = "GitHub did not accept the copied sign-in. Sign in normally in Chrome before connecting again."
        case "browser_state_unrecognized": detail = "GitHub's signed-in page did not match the reviewed connection. Its connector needs review."
        case "invalid_browser_session_state": detail = "Chrome returned an unsupported session format."
        case "browser_session_verification_failed": detail = "The local verification browser could not finish."
        case "browser_session_cancelled", "browser_session_request_expired_or_changed": detail = "This browser connection expired, was cancelled, or its approved permissions changed."
        case "browser_action_required": detail = "GitHub requires a separate account action. Complete its genuine owner flow."
        default: detail = "This Chrome session could not be verified. Start a new connection after reviewing your GitHub tab."
        }
        return detail + " Your previous connection is preserved."
    }

    @objc func openGitHubInChrome() {
        NSWorkspace.shared.open([URL(string: "https://github.com/settings/profile")!],
            withApplicationAt: URL(fileURLWithPath: "/Applications/Google Chrome.app"),
            configuration: NSWorkspace.OpenConfiguration())
    }

    @objc func cancelBrowserSession() {
        guard let id = browserSessionWatch, let account = browserSessionChoice?["account"] as? String else { return }
        browserSessionWatch = nil
        DispatchQueue.global(qos: .userInitiated).async {
            _ = try? self.request("owner/browser-session/cancel", body: ["account": account, "id": id])
            DispatchQueue.main.async { self.showReady() }
        }
    }

    @objc func showVerificationDetails(_ sender: NSButton) {
        guard let detail = sender.identifier?.rawValue else { return }
        let alert = NSAlert()
        alert.messageText = "Verification controls"
        alert.informativeText = detail
        alert.addButton(withTitle: "Close")
        alert.runModal()
    }

    @objc func finishSignInReview(_ sender: NSButton) {
        guard let id = sender.identifier?.rawValue else { return }
        sender.isEnabled = false
        DispatchQueue.global(qos: .userInitiated).async {
            _ = try? self.request("owner/verify/finish-review", body: ["id": id])
        }
    }

    @objc func backToConnections() { connections() }

    @objc func showPasswordSync() {
        section = "sync"
        page("Keep passwords up to date", "Approved logins stay automatic when your connected password source changes.")
        card("Chrome and other CSV imports", "An export is a one-time snapshot. Chrome does not offer this app a public password-sync API. Re-import after a password change; this app never leaves a plaintext export running in the background.")
        for link in passwordSync {
            let account = link["account"] as? String ?? ""
            let name = accounts.first { $0["account"] as? String == account }?["label"] as? String ?? account
            let body = card(name, "1Password Connect · checks every five minutes while the service is running. Only the password can update; account identity and permissions stay fixed.", status: link["status"] as? String ?? "", good: link["status"] as? String == "SYNCED")
            let disconnect = NSButton(title: "Disconnect and remove saved login", target: self, action: #selector(disconnectPasswordSync))
            disconnect.identifier = NSUserInterfaceItemIdentifier(account)
            body.addArrangedSubview(disconnect)
        }
        card("Connect 1Password", "Requires an existing 1Password Connect server and a read-only token for a dedicated vault. Your administrator supplies the connection details once. Tokens stay in the encrypted local vault.")
        syncAccounts = NSPopUpButton()
        for account in accounts where account["route"] as? String == "browser" && account["portable_ready"] as? Bool == true {
            syncAccounts.addItem(withTitle: account["label"] as? String ?? "Account")
            syncAccounts.lastItem?.representedObject = account["account"]
        }
        guard syncAccounts.numberOfItems > 0 else {
            label("Import and approve an account first.")
            action("Import passwords", #selector(importPasswords))
            return
        }
        stack.addArrangedSubview(syncAccounts)
        syncFields = [:]
        for (key, title) in [("endpoint", "Connect server HTTPS address"), ("vault", "Vault ID"), ("item", "Login item ID"), ("token", "Read-only Connect token")] {
            label(title, 14, .secondaryLabelColor)
            let field: NSTextField = key == "token" ? NSSecureTextField() : NSTextField()
            field.placeholderString = title
            field.setAccessibilityLabel(title)
            stack.addArrangedSubview(field)
            field.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
            syncFields[key] = field
        }
        primary("Connect automatic updates", #selector(connectPasswordSync))
    }

    @objc func connectPasswordSync() {
        guard let account = syncAccounts.selectedItem?.representedObject as? String else { return }
        let connection = syncFields.mapValues { $0.stringValue }
        guard connection.values.allSatisfy({ !$0.isEmpty }) else { return }
        syncFields.values.forEach { $0.stringValue = "" }
        busy = true
        page("Connecting your password source", "Checking the selected account and website. Your approved reads stay the same.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/password-sync", body: ["account": account, "connection": connection])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showPasswordSync() }
            } catch { self.fail(error, retry: #selector(self.showPasswordSync)) }
        }
    }

    @objc func disconnectPasswordSync(_ sender: NSButton) {
        guard let account = sender.identifier?.rawValue else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/password-sync/disconnect", body: ["account": account])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showPasswordSync() }
            } catch { self.fail(error, retry: #selector(self.showPasswordSync)) }
        }
    }

    @objc func showFactors() {
        section = "verification"
        page("Verification", "Connect email, SMS or an authenticator once. Login codes stay out of your AI chat.")
        for mailbox in mailboxes {
            guard let id = mailbox["id"] as? String else { continue }
            let check = mailbox["connection_check"] as? [String: Any] ?? [:]
            let checked = check["status"] as? String == "VERIFIED"
            let panel = card((mailbox["label"] as? String ?? "Email") + " · " + (mailbox["username"] as? String ?? ""),
                             checked ? "Email access passed its last check. Connect a supported website to use its login codes."
                             : "Setup is saved. Check the address and app password, then check this connection.",
                             status: checked ? "Mailbox connection checked" : "Setup saved", good: checked)
            for (title, selector) in [("Check connection", #selector(checkSavedMailbox(_:))),
                                      ("Update app password", #selector(editMailboxPassword(_:))),
                                      ("Disconnect mailbox", #selector(disconnectMailbox(_:)))] {
                let button = NSButton(title: title, target: self, action: selector)
                button.identifier = NSUserInterfaceItemIdentifier(id)
                panel.addArrangedSubview(button)
            }
        }
        action("Connect Gmail or email", #selector(showEmailSetup))
        if sources.isEmpty && smsSetups.isEmpty {
            card("Connect a website", "You can save your mailbox now. Website verification methods appear after you connect a supported account.", status: "One-time setup", good: false)
            action("Back", #selector(backToConnections))
            return
        }
        for setup in smsSetups {
            guard let account = setup["account"] as? String else { continue }
            let name = accounts.first { $0["account"] as? String == account }?["label"] as? String ?? "GitHub"
            let panel = card("iPhone SMS · " + name, "Connect the login messages already forwarded to this Mac. Account Access detects the sender during one sign-in and asks you to review it.", status: "One-time setup", good: false)
            let start = NSButton(title: "Connect iPhone SMS", target: self, action: #selector(startSMSSetup))
            start.identifier = NSUserInterfaceItemIdentifier(account)
            panel.addArrangedSubview(start)
        }
        if !smsSetups.isEmpty || sources.contains(where: { $0["kind"] as? String == "google_messages" }) {
            let panel = card("Android SMS · Google Messages", "Use the Google Messages tab already paired to your phone. A browser connection passes only fresh GitHub login codes to this Mac during an active sign-in.", status: "One-time browser connection", good: false)
            panel.addArrangedSubview(NSButton(title: "Set up Google Messages", target: self, action: #selector(prepareGoogleMessages)))
        }
        if sources.isEmpty { action("Back", #selector(backToConnections)); return }
        factorMenu = NSPopUpButton()
        for source in sources {
            let linked = (source["accounts"] as? [String] ?? []).map { id in accounts.first { $0["account"] as? String == id }?["label"] as? String ?? id }
            let label = factorName(source["kind"] as? String ?? "") + " · " + linked.joined(separator: ", ")
            factorMenu.addItem(withTitle: label)
            factorMenu.lastItem?.representedObject = source
        }
        factorMenu.target = self
        factorMenu.action = #selector(factorChanged)
        stack.addArrangedSubview(factorMenu)
        factorChanged()
    }

    @objc func showEmailSetup() {
        editingMailbox = nil
        page("Connect your email", "Save your mailbox once. Only supported websites with approved login-message filters can use it.")
        mailboxKind = NSPopUpButton()
        mailboxKind.addItems(withTitles: ["Gmail", "Other email · TLS IMAP"])
        mailboxKind.target = self
        mailboxKind.action = #selector(mailboxKindChanged)
        stack.addArrangedSubview(mailboxKind)
        mailboxFields = [:]
        mailboxServerViews = []
        for (name, title) in [("username", "Email address"), ("password", "Application password"),
                              ("host", "IMAP server"), ("port", "TLS port")] {
            label(title, 14)
            if ["host", "port"].contains(name), let title = stack.arrangedSubviews.last { mailboxServerViews.append(title) }
            let field: NSTextField = name == "password" ? NSSecureTextField() : NSTextField()
            field.placeholderString = title
            field.heightAnchor.constraint(equalToConstant: 38).isActive = true
            stack.addArrangedSubview(field)
            field.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
            mailboxFields[name] = field
            if ["host", "port"].contains(name) { mailboxServerViews.append(field) }
        }
        mailboxKindChanged()
        label("Create a Google app password for Account Access with 2-Step Verification enabled. If Google does not offer app passwords for your account, this connection is not supported yet.", 13, .secondaryLabelColor)
        action("Open Google App passwords", #selector(openGoogleAppPasswords))
        label("Your app password grants mailbox access and is encrypted on this Mac. Account Access uses read-only checks and matching login messages for approved sign-ins. Website code delivery is checked separately.", 13, .secondaryLabelColor)
        primary("Connect mailbox", #selector(saveMailbox))
        action("Back", #selector(showFactors))
    }

    @objc func mailboxKindChanged() {
        let gmail = mailboxKind.indexOfSelectedItem == 0
        mailboxFields["host"]?.isEnabled = !gmail
        mailboxFields["port"]?.isEnabled = !gmail
        mailboxFields["host"]?.stringValue = gmail ? "imap.gmail.com" : ""
        mailboxFields["port"]?.stringValue = "993"
        for view in mailboxServerViews { view.isHidden = gmail }
    }

    @objc func openGoogleAppPasswords() {
        NSWorkspace.shared.open(URL(string: "https://myaccount.google.com/apppasswords")!)
    }

    @objc func saveMailbox() {
        let data: [String: Any]
        if let id = editingMailbox {
            data = ["id": id, "password": mailboxFields["password"]?.stringValue ?? ""]
        } else {
            data = ["label": mailboxKind.indexOfSelectedItem == 0 ? "Gmail" : "Email",
                    "host": mailboxFields["host"]?.stringValue ?? "",
                    "port": Int(mailboxFields["port"]?.stringValue ?? "") ?? 0,
                    "username": mailboxFields["username"]?.stringValue ?? "",
                    "password": mailboxFields["password"]?.stringValue ?? ""]
        }
        let route = editingMailbox == nil ? "owner/mailbox/connect" : "owner/mailbox/password"
        for field in mailboxFields.values { field.stringValue = "" }
        mailboxRequest(route, data)
    }

    func mailboxRequest(_ route: String, _ body: [String: Any]) {
        busy = true
        page("Checking your mailbox", "Checking encrypted email access without fetching messages or starting a website sign-in.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request(route, body: body)
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showFactors() }
            } catch { self.fail(error, retry: #selector(self.backToConnections)) }
        }
    }

    @objc func checkSavedMailbox(_ sender: NSButton) {
        guard let id = sender.identifier?.rawValue else { return }
        mailboxRequest("owner/mailbox/check", ["id": id])
    }

    @objc func editMailboxPassword(_ sender: NSButton) {
        guard let id = sender.identifier?.rawValue else { return }
        editingMailbox = id
        page("Update email access", "Replace the saved application password. The email address and mail server stay fixed.")
        let field = NSSecureTextField()
        field.placeholderString = "Application password"
        field.heightAnchor.constraint(equalToConstant: 38).isActive = true
        stack.addArrangedSubview(field)
        field.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        mailboxFields = ["password": field]
        primary("Save and check", #selector(saveMailbox))
        action("Back", #selector(showFactors))
    }

    @objc func disconnectMailbox(_ sender: NSButton) {
        guard let id = sender.identifier?.rawValue else { return }
        let alert = NSAlert()
        alert.messageText = "Disconnect this mailbox?"
        alert.informativeText = "The saved mailbox password is removed locally. Websites using it will pause when they next need an email code. Other account permissions stay the same."
        alert.addButton(withTitle: "Disconnect")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        mailboxRequest("owner/mailbox/remove", ["id": id])
    }

    func factorName(_ kind: String) -> String {
        return ["totp": "Authenticator", "imap": "Email", "gmail": "Gmail", "twilio": "SMS gateway",
                "mac_messages": "iPhone Messages", "phone_relay": "Android phone", "google_messages": "Google Messages"][kind] ?? "Verification"
    }

    @objc func prepareGoogleMessages() {
        let review = NSAlert()
        review.messageText = "Prepare the Google Messages connection?"
        review.informativeText = "This installs a local bridge for the Account Access SMS-only Chrome extension. Chrome will separately ask for access to messages.google.com. During a pending GitHub sign-in, it matches the exact login text and passes fresh codes locally. GitHub rotates sender numbers, so sender identity is not independently verified. Your AI receives no codes or message contents."
        review.addButton(withTitle: "Prepare browser connection"); review.addButton(withTitle: "Cancel")
        guard review.runModal() == .alertFirstButtonReturn else { return }
        busy = true
        page("Preparing Google Messages", "Setting up the local SMS bridge. No browser permission has been granted yet.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try self.request("owner/google-messages/prepare", body: [:])
                guard let path = result["extension_path"] as? String,
                      path == self.root.appendingPathComponent("GoogleMessagesExtension").path else {
                    throw Failure.message("The browser connection could not be prepared.")
                }
                DispatchQueue.main.async {
                    self.busy = false
                    self.page("Add the SMS browser connection", "This preview uses a local Chrome extension. The folder is open in Finder. In Chrome Extensions, enable Developer mode, choose Load unpacked and select GoogleMessagesExtension. Open Account Access — Browser Connections in Chrome, select your reviewed GitHub account, and click Connect GitHub login texts.")
                    self.label("Keep one paired Google Messages conversations tab open. Your usual Chrome session stays on this computer.", 15, .secondaryLabelColor)
                    self.action("Open Chrome Extensions", #selector(self.openChromeExtensions))
                    self.action("Back to verification", #selector(self.showFactors))
                    NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: path)
                }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    @objc func openChromeExtensions() {
        NSWorkspace.shared.open([URL(string: "chrome://extensions")!],
            withApplicationAt: URL(fileURLWithPath: "/Applications/Google Chrome.app"),
            configuration: NSWorkspace.OpenConfiguration())
    }

    @objc func cancelSMSSetup() { smsProgress?.cancel() }

    @objc func showSMSDiagnostics() {
        let alert = NSAlert()
        alert.messageText = "Sign-in delivery details"
        alert.informativeText = smsDiagnostics ?? "The website has not returned structural delivery details yet. No credentials or message contents are included."
        alert.addButton(withTitle: "Close")
        alert.runModal()
    }

    @objc func startSMSSetup(_ sender: NSButton) {
        guard !busy, let account = sender.identifier?.rawValue,
              let setup = smsSetups.first(where: { $0["account"] as? String == account }),
              let fingerprint = setup["fingerprint"] as? String else { return }
        guard MessagesReader.hasAccess(), let path = MessagesReader.messagesPath() else {
            let alert = NSAlert()
            alert.messageText = "Allow Messages access first"
            alert.informativeText = "In Full Disk Access, turn on Account Access and approve the macOS prompt. Return here and try connecting SMS again."
            alert.addButton(withTitle: "Open privacy settings"); alert.addButton(withTitle: "Cancel")
            if alert.runModal() == .alertFirstButtonReturn { openMessagePrivacy() }
            return
        }
        let review = NSAlert()
        review.messageText = "Connect GitHub login SMS?"
        review.informativeText = "Account Access will use your saved GitHub sign-in and request one login SMS. During this setup it checks at most 20 fresh incoming texts for a recognized GitHub login message. You'll review the sender before enabling its exact filter. Codes stay outside your AI chat. Your approved website reads stay the same."
        review.addButton(withTitle: "Start SMS setup"); review.addButton(withTitle: "Cancel")
        guard review.runModal() == .alertFirstButtonReturn else { return }
        guard let afterRow = MessagesReader.incomingBaseline(path: path) else {
            fail(Failure.message("Messages could not prepare a fresh delivery window. No website sign-in was started."), retry: #selector(showFactors))
            return
        }
        busy = true
        smsDiagnostics = nil
        let waiting = Progress(totalUnitCount: 110)
        smsProgress = waiting
        page("Connecting your login SMS", "Requesting one GitHub login SMS and checking its delivery on this Mac. You do not need to copy a code.")
        progress()
        let cancel = action("Cancel SMS setup", #selector(cancelSMSSetup))
        cancel.isEnabled = true
        let details = action("Show sign-in details", #selector(showSMSDiagnostics))
        details.isEnabled = true
        DispatchQueue.global(qos: .userInitiated).async {
            var id: String?
            do {
                let started = try self.request("owner/sms/setup-start", body: ["account": account, "fingerprint": fingerprint])
                guard let jobID = started["id"] as? String else { throw Failure.message("SMS setup could not start.") }
                id = jobID
                var deadline = Date().addingTimeInterval(120)
                var deliveryStarted = false
                var incoming = 0
                var unreadable = 0
                while Date() < deadline && !waiting.isCancelled {
                    let state = try self.request("owner/state")
                    let job = (state["connection_jobs"] as? [String: [String: Any]])?[jobID] ?? [:]
                    if let delivery = job["code_requested"] as? [String: Any], delivery["kind"] as? String == "sms",
                       let httpStatus = delivery["http_status"] as? Int, (200..<400).contains(httpStatus),
                       let at = delivery["at"] as? Double {
                        if !deliveryStarted {
                            deliveryStarted = true
                            deadline = Date().addingTimeInterval(110)
                        }
                        if let details = delivery["diagnostics"] as? [String: Any],
                           let bytes = try? JSONSerialization.data(withJSONObject: details, options: [.prettyPrinted, .sortedKeys]),
                           let text = String(data: bytes, encoding: .utf8) {
                            DispatchQueue.main.async { self.smsDiagnostics = text }
                        }
                        let preview = MessagesReader.previewGitHubSMS(path: path, started: at, afterRow: afterRow)
                        incoming = Int(preview["incoming"] ?? "0") ?? 0
                        unreadable = Int(preview["unreadable"] ?? "0") ?? 0
                        if preview["status"] == "WAITING" {
                            let message = unreadable > 0 ? "Some incoming messages could not be read."
                                : incoming > 0 ? "New messages arrived; waiting for the GitHub login text…"
                                : "The website opened SMS code entry. Waiting for a new GitHub text in Messages on this Mac…"
                            DispatchQueue.main.async { self.status.stringValue = message }
                        }
                        if preview["status"] == "FOUND" {
                            DispatchQueue.main.async {
                                self.busy = false; self.smsProgress = nil; self.accept(state)
                                self.confirmSMSSetup(jobID, account: account, preview: preview)
                            }
                            return
                        }
                        if preview["status"] == "NEEDS_USER" {
                            throw Failure.message(preview["reason"] == "ambiguous_login_code"
                                ? "More than one GitHub login SMS arrived. No filter was connected. Wait for those attempts to finish before trying again."
                                : "Messages access or this setup window is unavailable. Check Mac privacy settings and try again.")
                        }
                    } else if let attention = job["attention"] as? [String: Any] {
                        if let details = attention["diagnostics"] as? [String: Any],
                           let bytes = try? JSONSerialization.data(withJSONObject: details, options: [.prettyPrinted, .sortedKeys]),
                           let text = String(data: bytes, encoding: .utf8) {
                            DispatchQueue.main.async { self.smsDiagnostics = text }
                        }
                        throw Failure.message(self.verificationMessage(attention))
                    } else if let outcome = job["status"] as? String, outcome != "RUNNING" {
                        throw Failure.message(job["reason"] as? String == "login_retry_cooldown"
                            ? "The website's sign-in cooldown is active. Wait one minute and connect SMS again."
                            : "The website did not accept its reviewed SMS request. No delivery was confirmed. Your saved password is preserved.")
                    }
                    Thread.sleep(forTimeInterval: 1)
                }
                let explanation = Self.smsTimeoutMessage(deliveryStarted: deliveryStarted, incoming: incoming, unreadable: unreadable)
                throw Failure.message(waiting.isCancelled ? "SMS setup was cancelled. No SMS filter was enabled." : explanation)
            } catch {
                if let id { _ = try? self.request("owner/sms/setup-discard", body: ["id": id]) }
                let state = try? self.request("owner/state")
                DispatchQueue.main.async { if let state { self.accept(state) }; self.smsProgress = nil }
                self.fail(error, retry: #selector(self.showFactors))
                DispatchQueue.main.async {
                    if self.smsDiagnostics != nil { self.action("Show sign-in details", #selector(self.showSMSDiagnostics)) }
                }
            }
        }
    }

    func confirmSMSSetup(_ id: String, account: String, preview: [String: String]) {
        guard let sender = preview["sender"], let template = preview["template"] else { return }
        let review = NSAlert()
        review.messageText = "GitHub login SMS found"
        review.informativeText = "Enable this sender ending in “" + String(sender.suffix(4)) + "” for GitHub login codes? Later sign-ins will check only fresh incoming messages from that exact sender and matching this login template. Your approved reads stay the same.\n\nLogin message pattern:\n" + template
        review.addButton(withTitle: "Connect SMS"); review.addButton(withTitle: "Cancel")
        let accepted = review.runModal() == .alertFirstButtonReturn
        busy = true
        page(accepted ? "Checking automatic SMS sign-in" : "Cancelling SMS setup", accepted
             ? "Your SMS filter is saved locally. Checking the website sign-in without copying a code. A short website cooldown may apply."
             : "No SMS filter will be enabled.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                if accepted {
                    _ = try self.request("owner/sms/setup-apply", body: ["id": id, "sender": sender, "template": template])
                    let issues = self.verifyLinkedAccounts([account])
                    let state = try self.request("owner/state")
                    DispatchQueue.main.async { self.busy = false; self.accept(state); self.showImportSummary([account], issues: issues, verification: true) }
                } else {
                    _ = try self.request("owner/sms/setup-discard", body: ["id": id])
                    let state = try self.request("owner/state")
                    DispatchQueue.main.async { self.busy = false; self.accept(state); self.showFactors() }
                }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    @objc func factorChanged() {
        // Rebuild below the picker to avoid keeping old secret fields around.
        while let last = stack.arrangedSubviews.last, last !== factorMenu {
            stack.removeArrangedSubview(last); last.removeFromSuperview()
        }
        factorFields = [:]
        factorEntryViews = []
        factorMailboxMenu = nil
        let source = factorMenu.selectedItem?.representedObject as? [String: Any] ?? [:]
        let kind = source["kind"] as? String ?? ""
        let email = ["imap", "gmail"].contains(kind)
        let connectionCheck = source["connection_check"] as? [String: Any] ?? [:]
        let checked = connectionCheck["status"] as? String == "VERIFIED"
        label(source["enrolled"] as? Bool == true
              ? (email && checked ? "● Mailbox connection checked" : "Setup saved") : "One-time setup", 14,
              email && checked ? .systemGreen : .secondaryLabelColor)
        if email && source["enrolled"] as? Bool == true {
            label(checked ? "Email access passed its last check. A website sign-in is still needed to verify code delivery."
                  : "Saving these details does not verify email access or code delivery.", 14, .secondaryLabelColor)
            action("Check email connection", #selector(checkEmailConnection))
        }
        if kind == "google_messages" {
            label("Keep one paired Google Messages conversations tab open in Chrome. Only new matching GitHub login texts during a pending sign-in are eligible. Cached texts, changed pages and ambiguous codes stop safely.", 15, .secondaryLabelColor)
            action("Set up Google Messages", #selector(prepareGoogleMessages))
            if source["enrolled"] as? Bool == true { action("Disable this verification method", #selector(disableFactor)) }
            action("Back", #selector(backToConnections))
            return
        }
        let fields: [(String, String)] = kind == "totp" ? [("seed", "Authenticator setup key or otpauth link")] :
            kind == "imap" ? ((source["mailbox_account"] as? String) != nil ? [("username", "Mailbox email address")] : [("username", "Mailbox email address"), ("password", "Mailbox application password")]) :
            kind == "twilio" ? [("sid", "SMS gateway account ID"), ("auth_token", "SMS gateway token")] : []
        if kind == "imap" && source["mailbox_account"] as? String == nil {
            let matching = mailboxes.filter {
                ($0["host"] as? String)?.lowercased() == (source["mail_server"] as? String)?.lowercased()
                && $0["port"] as? Int == source["mail_port"] as? Int
                && ($0["username"] as? String)?.lowercased() == (source["recipient"] as? String)?.lowercased()
            }
            if !matching.isEmpty {
                label("Use a connected mailbox or enter separate details", 14)
                let menu = NSPopUpButton()
                menu.addItem(withTitle: "Enter mailbox details")
                for mailbox in matching {
                    menu.addItem(withTitle: mailbox["username"] as? String ?? "Email")
                    menu.lastItem?.representedObject = mailbox["id"]
                    let checked = (mailbox["connection_check"] as? [String: Any])?["status"] as? String == "VERIFIED"
                    if mailbox["id"] as? String == source["linked_mailbox"] as? String
                        || (matching.count == 1 && checked && source["enrolled"] as? Bool != true) { menu.select(menu.lastItem) }
                }
                menu.target = self
                menu.action = #selector(factorMailboxChanged)
                factorMailboxMenu = menu
                stack.addArrangedSubview(menu)
            }
        }
        for (name, hint) in fields {
            label(hint, 15)
            if let title = stack.arrangedSubviews.last { factorEntryViews.append(title) }
            let input: NSTextField = name == "username" ? NSTextField() : NSSecureTextField()
            input.placeholderString = hint
            input.font = .systemFont(ofSize: 17)
            input.heightAnchor.constraint(equalToConstant: 40).isActive = true
            stack.addArrangedSubview(input)
            input.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
            factorFields[name] = input
            factorEntryViews.append(input)
        }
        factorMailboxChanged()
        if kind == "totp" {
            label("Use the website's setup key, or Google Authenticator → Transfer codes → Export codes. Unlock your phone and export the account you want to connect. Choose its QR image below and review the account before importing. Your phone keeps generating codes.", 14, .secondaryLabelColor)
            label("Importing copies the authenticator key to this Mac for unattended login. The key stays encrypted locally. A push, passkey or fingerprint approval still needs you.", 14, .secondaryLabelColor)
            action("Import authenticator QR image", #selector(readAuthenticatorQR))
        } else if kind == "imap" {
            label("Mail server: " + (source["mail_server"] as? String ?? "configured provider"), 14, .secondaryLabelColor)
            label("Uses encrypted IMAP access to the configured mailbox. Gmail may require an application password. Microsoft mail can use a configured OAuth connection.", 14, .secondaryLabelColor)
        } else if kind == "mac_messages" {
            label("Your iPhone must forward SMS to Messages on this Mac. Add Account Access to Full Disk Access in macOS privacy settings. macOS grants broad file access; this app’s reader checks only fresh incoming messages from this account’s configured sender and returns matching login codes to the service.", 15, .secondaryLabelColor)
            action("Open Mac privacy settings", #selector(openMessagePrivacy))
        } else if kind == "phone_relay" {
            label("Pair the Android companion on the same private Wi-Fi. It forwards matching login notifications through a certificate-pinned encrypted connection.", 15, .secondaryLabelColor)
            action("Pair Android phone", #selector(pairPhone))
        } else if kind == "gmail" {
            label("Connect the configured Gmail account through its provider consent screen in Manage permissions. The resolver reads only matching current login messages, but Gmail consent grants mailbox read access.", 15, .secondaryLabelColor)
        }
        primary(source["enrolled"] as? Bool == true ? "Save changes" : "Connect verification", #selector(saveFactor))
        if source["enrolled"] as? Bool == true { action("Disable this verification method", #selector(disableFactor)) }
        action("Back", #selector(backToConnections))
    }

    @objc func factorMailboxChanged() {
        let linked = factorMailboxMenu?.selectedItem?.representedObject as? String != nil
        for view in factorEntryViews { view.isHidden = linked }
        for field in factorFields.values {
            field.isEnabled = !linked
            if linked { field.stringValue = "" }
        }
    }

    @objc func readAuthenticatorQR() {
        let picker = NSOpenPanel()
        picker.allowedContentTypes = [.png, .jpeg]
        guard picker.runModal() == .OK, let url = picker.url else { return }
        guard let image = CIImage(contentsOf: url),
              let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]),
              let text = Self.authenticatorQRText(detector.features(in: image).compactMap { ($0 as? CIQRCodeFeature)?.messageString }) else {
            let alert = NSAlert()
            alert.messageText = "Choose one authenticator QR"
            alert.informativeText = "The image must contain exactly one website setup QR or Google Authenticator transfer QR. No account was changed."
            alert.runModal()
            return
        }
        if text.hasPrefix("otpauth://totp/") { factorFields["seed"]?.stringValue = text; return }
        guard let source = factorMenu.selectedItem?.representedObject as? [String: Any], let id = source["id"] as? String else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let preview = try self.request("owner/authenticator/preview", body: ["source": id, "uri": text])
                DispatchQueue.main.async { self.busy = false; self.chooseAuthenticator(preview, source: source) }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    static func authenticatorQRText(_ messages: [String]) -> String? {
        guard messages.count == 1, let text = messages.first, text.utf8.count <= 32000,
              text.hasPrefix("otpauth://totp/") || text.hasPrefix("otpauth-migration://offline?") else { return nil }
        return text
    }

    func chooseAuthenticator(_ preview: [String: Any], source: [String: Any]) {
        guard let ident = preview["id"] as? String, let entries = preview["accounts"] as? [[String: Any]], !entries.isEmpty else { return }
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 420, height: 30))
        for entry in entries {
            picker.addItem(withTitle: entry["label"] as? String ?? "Authenticator account")
            picker.lastItem?.representedObject = entry["index"]
        }
        let linked = (source["accounts"] as? [String] ?? []).map { id in accounts.first { $0["account"] as? String == id }?["label"] as? String ?? id }.joined(separator: ", ")
        let alert = NSAlert()
        alert.messageText = "Choose the matching authenticator"
        alert.informativeText = "Connect only the selected key to " + linked + ". Check that the website and account match. Other keys in this QR will be discarded."
        alert.accessoryView = picker
        alert.addButton(withTitle: "Import selected authenticator")
        alert.addButton(withTitle: "Cancel")
        let accepted = alert.runModal() == .alertFirstButtonReturn
        let index = picker.selectedItem?.representedObject as? Int ?? -1
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                if accepted {
                    _ = try self.request("owner/authenticator/apply", body: ["id": ident, "index": index])
                } else {
                    _ = try self.request("owner/authenticator/discard", body: ["id": ident])
                }
                let linked = source["accounts"] as? [String] ?? []
                let issues = accepted ? self.verifyLinkedAccounts(linked) : []
                let state = try self.request("owner/state")
                DispatchQueue.main.async {
                    self.busy = false; self.accept(state)
                    if accepted { self.showImportSummary(linked, issues: issues, verification: true) }
                    else { self.showFactors() }
                }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    @objc func openMessagePrivacy() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") { NSWorkspace.shared.open(url) }
    }

    @objc func saveFactor() {
        guard let source = factorMenu.selectedItem?.representedObject as? [String: Any], let id = source["id"] as? String else { return }
        let kind = source["kind"] as? String ?? ""
        if kind == "mac_messages" && !MessagesReader.hasAccess() {
            let alert = NSAlert()
            alert.messageText = "Allow Messages access first"
            alert.informativeText = "Open Full Disk Access, turn on Account Access, and approve the macOS prompt with Touch ID or your Mac login password. Return here and connect verification again. No website sign-in has been started."
            alert.addButton(withTitle: "Open privacy settings")
            alert.addButton(withTitle: "Cancel")
            if alert.runModal() == .alertFirstButtonReturn { openMessagePrivacy() }
            return
        }
        var credential: [String: Any] = factorFields.mapValues { $0.stringValue }
        if let mailbox = factorMailboxMenu?.selectedItem?.representedObject as? String {
            credential = ["mailbox": mailbox]
        }
        if kind == "mac_messages" { credential = ["enabled": true] }
        let linked = source["accounts"] as? [String] ?? []
        for field in factorFields.values { field.stringValue = "" }
        busy = true
        page("Saving your verification method", "The secret is encrypted locally. Checking your connected accounts…")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/source", body: ["source": id, "credential": credential])
                if ["imap", "gmail"].contains(kind) {
                    _ = try self.request("owner/source/check", body: ["source": id])
                }
                let issues = self.verifyLinkedAccounts(linked)
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showImportSummary(linked, issues: issues, verification: true) }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    func verifyLinkedAccounts(_ linked: [String]) -> [(String, String)] {
        var issues: [(String, String)] = []
        for account in linked {
            if let explanation = verificationRetryBlock(account) {
                issues.append((account, explanation))
                continue
            }
            do {
                let job = try request("owner/verify", body: ["account": account])
                _ = try waitForConnection(job, account: account)
            } catch Failure.message(let message) { issues.append((account, message)) }
            catch { issues.append((account, "The verification method is saved. The website sign-in still needs attention.")) }
        }
        return issues
    }

    func verificationRetryBlock(_ account: String) -> String? {
        let current = accounts.first { $0["account"] as? String == account }
        let challenges = current?["challenges"] as? [[String: Any]] ?? []
        for challenge in challenges {
            let kind = challenge["kind"] as? String ?? ""
            if ["captcha", "passkey", "device", "admin", "action", "recovery", "unknown"].contains(kind) {
                return verificationMessage(["reason": "browser_" + (kind == "unknown" ? "state_unrecognized" : kind + "_required")])
            }
        }
        return nil
    }

    @objc func checkEmailConnection() {
        guard let source = factorMenu.selectedItem?.representedObject as? [String: Any],
              let id = source["id"] as? String else { return }
        busy = true
        page("Checking email access", "Checking your saved mailbox connection without fetching messages or starting a website sign-in.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/source/check", body: ["source": id])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showFactors() }
            } catch { self.fail(error, retry: #selector(self.backToConnections)) }
        }
    }

    @objc func disableFactor() {
        guard let source = factorMenu.selectedItem?.representedObject as? [String: Any], let id = source["id"] as? String else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/source/revoke", body: ["source": id])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showFactors() }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    @objc func pairPhone() {
        guard let source = factorMenu.selectedItem?.representedObject as? [String: Any], let id = source["id"] as? String else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try self.request("owner/phone/pair", body: ["source": id])
                let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
                DispatchQueue.main.async {
                    self.busy = false
                    self.page("Pair your Android phone", "Scan this pairing QR with the Account Access companion. Keep both devices on the same private Wi-Fi.")
                    if let filter = CIFilter(name: "CIQRCodeGenerator") {
                        filter.setValue(data, forKey: "inputMessage")
                        if let output = filter.outputImage {
                            let image = NSImage(size: NSSize(width: 300, height: 300))
                            let representation = NSCIImageRep(ciImage: output)
                            image.addRepresentation(representation)
                            let view = NSImageView()
                            view.image = image
                            view.widthAnchor.constraint(equalToConstant: 300).isActive = true
                            view.heightAnchor.constraint(equalToConstant: 300).isActive = true
                            self.stack.addArrangedSubview(view)
                        }
                    }
                    let paste = NSButton(title: "Copy pairing for the companion", target: nil, action: nil)
                    paste.target = self
                    paste.action = #selector(self.copyPhonePairing)
                    paste.identifier = NSUserInterfaceItemIdentifier(String(data: data, encoding: .utf8) ?? "")
                    self.stack.addArrangedSubview(paste)
                    self.action("Back", #selector(self.backToConnections))
                }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    @objc func copyPhonePairing(_ sender: NSButton) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(sender.identifier?.rawValue ?? "", forType: .string)
    }

    func ready() {
        section = "accounts"
        page("Your accounts", "Keep using your AI. Account Access handles the supported sign-ins and approved reads.")
        if backgroundServiceStatus == "requires_approval" {
            let notice = card("Allow background recovery", "macOS has disabled this background item. Allow Account Access in Login Items to restore automatic recovery after login or a crash.", status: "Needs approval", good: false)
            let settings = NSButton(title: "Open Login Items", target: self, action: #selector(openBackgroundSettings))
            notice.addArrangedSubview(settings)
        } else if backgroundServiceStatus == "unavailable" {
            card("Background recovery needs attention", "The macOS background service could not be prepared. Your current account service can still handle approved requests. Use Repair installation to check it.", status: "Needs attention", good: false)
        }
        if backgroundRecovery["status"] as? String == "RETRYING" {
            card("Background recovery is retrying", "Background recovery hit an internal problem and is retrying automatically. Your saved connections and completed task steps are preserved.", status: "Retrying", good: false)
        } else if backgroundRecovery["status"] as? String == "STOPPED" {
            card("Background recovery stopped", "Use Repair installation in the app menu to restart it. Your saved connections are preserved.", status: "Stopped", good: false)
        }
        let serviceAccounts = accounts.filter { !Self.isExample($0) }
        let examples = accounts.filter(Self.isExample)
        let connected = serviceAccounts.filter(Self.isReady)
        let detected = agents.filter { ["codex", "claude"].contains($0) }
        let automatic = !detected.isEmpty && detected.allSatisfy { automaticSessions[$0]?["enabled"] as? Bool == true }
        let tools = detected.map { $0 == "claude" ? "Claude Code" : "Codex" }.joined(separator: " + ")
        let setup = card(automatic ? "Ready in every new session" : "Connect your AI tools",
                         automatic ? "Ask normally in " + tools + ". No special command required." : "Finish automatic setup so your AI can use connected accounts in new sessions.",
                         status: automatic ? "Automatic" : "Setup needed", good: automatic)
        if !automatic {
            let fix = NSButton(title: "Finish automatic setup", target: self, action: #selector(installAgents))
            setup.addArrangedSubview(fix)
        }
        if !detected.isEmpty { primary("Open " + preferredAgent, #selector(openClaude)) }
        label(String(connected.count) + " ready · " + String(serviceAccounts.count) + " service connections", 14, .secondaryLabelColor)
        if !examples.isEmpty {
            label(String(examples.filter(Self.isReady).count) + " ready · " + String(examples.count) + " example connections", 14, .secondaryLabelColor)
        }
        for account in accounts {
            let allowed = account["portable_ready"] as? Bool != false
            let active = account["connected"] as? Bool == true
            let pending = !(account["challenges"] as? [[String: Any]] ?? []).isEmpty
            let status = !allowed ? "Approval needed" : pending || !active ? "Sign-in needs attention" : Self.isExample(account) ? "Example connected" : "Connected"
            let reads = (account[allowed ? "approved_operations" : "operations"] as? [[String: Any]] ?? []).compactMap { $0["description"] as? String }.joined(separator: "; ")
            let body = card(account["label"] as? String ?? "Account", (allowed ? "Approved reads: " : "Available reads: ") + reads, status: status, good: allowed && active && !pending)
            if Self.isExample(account) {
                let note = NSTextField(wrappingLabelWithString: "Example connection. These results do not validate access to a personal account.")
                note.font = .systemFont(ofSize: 14)
                body.addArrangedSubview(note)
            }
            let browserCheck = (account["challenges"] as? [[String: Any]] ?? []).contains { $0["kind"] as? String == "captcha" }
            if browserCheck {
                let message = NSTextField(wrappingLabelWithString: verificationMessage(["reason": "browser_captcha_required"]))
                message.font = .systemFont(ofSize: 14)
                body.addArrangedSubview(message)
            }
            if allowed && browserSessionAccounts.contains(where: { $0["account"] as? String == account["account"] as? String }) {
                let chrome = NSButton(title: "Use signed-in Chrome", target: self, action: #selector(showBrowserSession))
                chrome.identifier = NSUserInterfaceItemIdentifier(account["account"] as? String ?? "")
                body.addArrangedSubview(chrome)
            }
            if (pending || !active), let id = account["account"] as? String, let detail = verificationDetails[id] {
                let inspect = NSButton(title: "Show verification details", target: self, action: #selector(showVerificationDetails))
                inspect.identifier = NSUserInterfaceItemIdentifier(detail)
                body.addArrangedSubview(inspect)
            }
            if pending && !browserCheck, let failure = navigationFailures.first(where: { $0["account"] as? String == account["account"] as? String }),
               let reason = failure["reason"] as? String {
                let route = failure["route"] as? String ?? ""
                let explanation = route.hasSuffix("/two-factor/webauthn")
                    ? "The website sent this sign-in to its security-key or passkey step. Approve it on your device, or connect a supported authenticator method."
                    : navigationFailureMessage(reason)
                let message = NSTextField(wrappingLabelWithString: explanation)
                message.font = .systemFont(ofSize: 14)
                body.addArrangedSubview(message)
                let details = NSButton(title: "Show technical details", target: self, action: #selector(showNavigationDetails))
                let hint = failure["route"] as? String
                details.identifier = NSUserInterfaceItemIdentifier(reason + (hint.map { "\nRoute: " + $0 } ?? ""))
                body.addArrangedSubview(details)
            }
            if !allowed || !active || pending {
                if smsSetups.contains(where: { $0["account"] as? String == account["account"] as? String }) {
                    let sms = NSButton(title: "Connect iPhone SMS", target: self, action: #selector(startSMSSetup))
                    sms.identifier = NSUserInterfaceItemIdentifier(account["account"] as? String ?? "")
                    body.addArrangedSubview(sms)
                }
                if browserUpdates.contains(where: { $0["account"] as? String == account["account"] as? String }) {
                    let update = NSButton(title: "Update sign-in connection", target: self, action: #selector(updateBrowserConnection))
                    update.identifier = NSUserInterfaceItemIdentifier(account["account"] as? String ?? "")
                    body.addArrangedSubview(update)
                }
                let repair = NSButton(title: allowed ? "Reconnect" : "Review access", target: self, action: #selector(reviewAccount))
                repair.identifier = NSUserInterfaceItemIdentifier(account["account"] as? String ?? "")
                body.addArrangedSubview(repair)
                if allowed && pending {
                    let inspect = NSButton(title: "Show sign-in problem", target: self, action: #selector(inspectSavedSignIn))
                    inspect.identifier = NSUserInterfaceItemIdentifier(account["account"] as? String ?? "")
                    body.addArrangedSubview(inspect)
                }
            }
        }
        let example = card("Try asking your AI", requestText)
        let row = NSStackView()
        let copy = NSButton(title: "Copy example", target: self, action: #selector(copyRequest))
        row.addArrangedSubview(copy)
        for agent in detected {
            let open = NSButton(title: "Open " + (agent == "claude" ? "Claude Code" : "Codex"), target: self, action: #selector(openAgent))
            open.identifier = NSUserInterfaceItemIdentifier(agent)
            row.addArrangedSubview(open)
        }
        example.addArrangedSubview(row)
        label("Passwords are encrypted locally and stay out of AI chat. Only approved accounts and reads are available. Login codes are bound to the pending sign-in.", 13, .secondaryLabelColor)
    }

    @objc func reviewAccount(_ sender: NSButton) { selectedAccount = sender.identifier?.rawValue; connections() }

    @objc func updateBrowserConnection(_ sender: NSButton) {
        guard let account = sender.identifier?.rawValue,
              let update = browserUpdates.first(where: { $0["account"] as? String == account }),
              let fingerprint = update["fingerprint"] as? String else { return }
        let alert = NSAlert()
        alert.messageText = "Update this website's sign-in connection?"
        alert.informativeText = "Use GitHub's current public profile heading for an existing heading-only read. Follow exact versioned scripts and styles declared by GitHub's HTTPS login response, with anonymous downloads from GitHub's asset host. Other destinations, queries, asset POSTs and page-driven discovery stay blocked. The recovery page can be viewed for diagnosis; a recovery-code field stops automatic sign-in. Approved account reads and connected verification sources stay the same."
        alert.addButton(withTitle: "Update connection")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/browser-update", body: ["account": account, "fingerprint": fingerprint])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.ready() }
            } catch { self.fail(error, retry: #selector(self.showReady)) }
        }
    }

    func navigationFailureMessage(_ reason: String) -> String {
        let fields = reason.components(separatedBy: ":")
        guard fields.count == 4 else { return "The sign-in check could not finish." }
        switch fields[1] {
        case "destination": return "The website sent this sign-in outside its reviewed login flow. Your saved password is preserved."
        case "method": return "The website requested a sign-in action that this connection does not permit."
        case "transport": return "The sign-in request could not reach the website."
        case "response_size": return "The website returned a response larger than this connection permits."
        case "redirect_limit", "missing_location": return "The website's sign-in redirects could not finish."
        default: return fields[1].hasPrefix("http_") ? "The website returned an error while signing in (HTTP " + String(fields[1].dropFirst(5)) + ")." : "The sign-in check could not finish."
        }
    }

    @objc func showNavigationDetails(_ sender: NSButton) {
        let alert = NSAlert()
        alert.messageText = "Sign-in check details"
        alert.informativeText = (sender.identifier?.rawValue ?? "No detail available") + "\n\nRoute words come from a fixed public vocabulary; ? replaces all other segments. No hostname, query value, password, code or page contents are recorded."
        alert.addButton(withTitle: "Done")
        alert.runModal()
    }

    @objc func openAgent(_ sender: NSButton) {
        let identifier = sender.identifier?.rawValue == "claude" ? "com.anthropic.claudefordesktop" : "com.openai.codex"
        if let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: identifier) {
            NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration())
        }
    }

    @objc func copyRequest() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(requestText, forType: .string)
    }

    @objc func openClaude() {
        let identifier = agents.contains("claude") ? "com.anthropic.claudefordesktop" : "com.openai.codex"
        guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: identifier) else {
            let alert = NSAlert()
            alert.messageText = "Install " + preferredAgent + " first"
            alert.informativeText = "Account Access works with your existing AI tool installation."
            alert.runModal()
            return
        }
        NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration())
    }

    func fail(_ error: Error, retry: Selector) {
        let explanation: String
        if case Failure.message(let message) = error { explanation = message }
        else { explanation = "This step could not finish. Check your connection and try again. Your saved accounts are preserved." }
        DispatchQueue.main.async {
            self.busy = false
            self.page("This step needs attention", explanation)
            self.action("Try again", retry)
                    if !self.sources.isEmpty { self.action("Review verification methods", #selector(self.showFactors)) }
        }
    }
}

#if !ACCOUNT_ACCESS_UI_CHECKS
@main struct AccountAccessMain {
    static func main() {
        if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--background-enable" {
            let payload = ["status": BackgroundRecovery.manage()]
            let data = try! JSONSerialization.data(withJSONObject: payload)
            print(String(decoding: data, as: UTF8.self))
            return
        }
        if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--read-login-code" {
            MessagesReader.run()
            return
        }
        let app = NSApplication.shared
        let delegate = AccountAccess()
        app.delegate = delegate
        #if ACCOUNT_ACCESS_LAUNCH_CHECKS
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            guard let owner = NSApplication.shared.delegate as? AccountAccess,
                  let window = owner.window, window.isVisible else {
                fputs("FAIL: the optimized app lost its delegate or startup window\n", stderr)
                exit(1)
            }
            window.orderOut(nil)
            _ = owner.applicationShouldHandleReopen(NSApplication.shared, hasVisibleWindows: false)
            guard window.isVisible else {
                fputs("FAIL: reopening did not restore the owner window\n", stderr)
                exit(1)
            }
            print("PASS: optimized entrypoint retains its owner delegate and restores the window on reopen")
            NSApplication.shared.terminate(nil)
        }
        #endif
        // NSApplication's delegate is weak. Keep the owner alive for the whole
        // event loop, including after asynchronous startup callbacks finish.
        withExtendedLifetime(delegate) { app.run() }
    }
}
#endif
