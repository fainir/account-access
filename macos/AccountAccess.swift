import AppKit
import CryptoKit
import Foundation
import CoreFoundation
import Security
import UniformTypeIdentifiers
import CoreImage
import CoreBluetooth
import ServiceManagement
import Darwin

// Advertise only a fresh public discovery UUID while the owner displays this QR.
// Login messages still use the QR's certificate-pinned HTTPS endpoint.
final class PhonePairingAdvertiser: NSObject, CBPeripheralManagerDelegate {
    let service: UUID
    let update: (String) -> Void
    private var manager: CBPeripheralManager!
    private var expiry: Timer?
    private var stopped = false

    init(service: UUID, update: @escaping (String) -> Void) {
        self.service = service
        self.update = update
        super.init()
        manager = CBPeripheralManager(delegate: self, queue: .main)
        expiry = Timer.scheduledTimer(withTimeInterval: 300, repeats: false) { [weak self] _ in
            guard let self else { return }
            self.stop()
            self.update("Bluetooth discovery expired. Go back and create a new pairing QR.")
        }
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard !stopped else { return }
        switch peripheral.state {
        case .poweredOn:
            peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [CBUUID(nsuuid: service)]])
            update("Preparing Bluetooth discovery for your phone…")
        case .poweredOff:
            update("Turn on Bluetooth on this Mac and your phone to connect Android 15 or newer.")
        case .unauthorized:
            update("Allow Account Access Bluetooth access in System Settings to connect Android 15 or newer.")
        case .unsupported:
            update("This Mac cannot advertise Bluetooth devices. Android 15 or newer cannot complete this pairing.")
        default:
            update("Waiting for Bluetooth. Keep this pairing screen open.")
        }
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        guard !stopped else { return }
        update(error == nil
            ? "Computer discoverable. On your phone, choose Connect computer with Android and confirm the matching device."
            : "Bluetooth discovery could not start. Go back and try pairing again.")
    }

    func stop() {
        stopped = true
        expiry?.invalidate()
        expiry = nil
        manager?.stopAdvertising()
    }

    deinit { expiry?.invalidate(); manager?.stopAdvertising() }
}

// The public /Applications entry is a convenience alias in a shared directory.
// Bind system resources once to the protected bundle, independently of how
// Launch Services populated Bundle.main when following that alias.
enum OwnerApplicationBundle {
    static let canonical = URL(fileURLWithPath: "/Library/Application Support/Account Access/owner.app")
    static let systemRequired: Bool = {
        if Bundle.main.object(forInfoDictionaryKey: "AccountAccessSystemInstallationRequired") as? Bool == true
            || DesktopOwnerProfile.isInstalled { return true }
        var info = stat()
        if lstat(canonical.path, &info) == 0 { return true }
        return errno != ENOENT
    }()
    static let selection: Result<Bundle, Error> = Result {
        try select(system: systemRequired, main: .main, installed: validatedInstalled)
    }
    static func current() throws -> Bundle { try selection.get() }
    static func select(system: Bool, main: Bundle, installed: () throws -> Bundle) throws -> Bundle {
        system ? try installed() : main
    }
    private static func validatedInstalled() throws -> Bundle {
        _ = try WorkerLaunchPaths.protectedTree(canonical.path)
        let executable = canonical.appendingPathComponent("Contents/MacOS/AccountAccess")
        guard try WorkerLaunchPaths.protected(executable.path) == executable else { throw DesktopOwnerFailure.profile }
        var bytes = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(getpid(), &bytes, UInt32(bytes.count)) > 0,
              URL(fileURLWithPath: String(cString: bytes)).resolvingSymlinksInPath() == executable,
              let bundle = Bundle(url: canonical), bundle.bundleIdentifier == "com.fainir.accountaccess",
              bundle.executableURL == executable,
              bundle.object(forInfoDictionaryKey: "AccountAccessSystemInstallationRequired") as? Bool == true else {
            throw DesktopOwnerFailure.profile
        }
        var code: SecStaticCode?, running: SecCode?, runningStatic: SecStaticCode?
        var staticInfo: CFDictionary?, runningInfo: CFDictionary?
        guard SecStaticCodeCreateWithPath(canonical as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess,
              SecCodeCopySelf([], &running) == errSecSuccess, let running,
              SecCodeCopyStaticCode(running, [], &runningStatic) == errSecSuccess, let runningStatic,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &staticInfo) == errSecSuccess,
              SecCodeCopySigningInformation(runningStatic, SecCSFlags(rawValue: kSecCSSigningInformation), &runningInfo) == errSecSuccess,
              let expected = staticInfo as? [String: Any], let actual = runningInfo as? [String: Any],
              let team = expected[kSecCodeInfoTeamIdentifier as String] as? String,
              let hash = expected[kSecCodeInfoUnique as String] as? Data,
              actual[kSecCodeInfoUnique as String] as? Data == hash,
              team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else { throw DesktopOwnerFailure.profile }
        let requirement = try OwnerGatewayPeer(uid: getuid(), team: team,
            identifier: "com.fainir.accountaccess", codeHashes: [hash.map { String(format: "%02x", $0) }.joined()]).requirement
        var parsed: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &parsed) == errSecSuccess, let parsed,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), parsed) == errSecSuccess,
              SecCodeCheckValidity(running, SecCSFlags(rawValue: kSecCSStrictValidate), parsed) == errSecSuccess else {
            throw DesktopOwnerFailure.profile
        }
        return bundle
    }
}

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
    let root: URL
    private let runtimeOverride: URL?
    private let installedOwnerProfile: () -> Bool
    private let loadOwnerProfile: () throws -> DesktopOwnerProfile

    private static func defaultRoot() -> URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let canonical = home.appendingPathComponent(".local/share/account-access")
        let legacy = home.appendingPathComponent("Library/Application Support/AccountAccess")
        let fallback = !FileManager.default.fileExists(atPath: canonical.appendingPathComponent("config.json").path) && FileManager.default.fileExists(atPath: legacy.appendingPathComponent("config.json").path) ? legacy : canonical
        return URL(fileURLWithPath: ProcessInfo.processInfo.environment["ACCOUNT_ACCESS_DATA_DIR"] ?? ((try? OwnerApplicationBundle.current())?.object(forInfoDictionaryKey: "AccountAccessDataDirectory") as? String) ?? fallback.path)
    }
    lazy var runtime = runtimeOverride ?? URL(fileURLWithPath: ProcessInfo.processInfo.environment["ACCOUNT_ACCESS_INSTALL_DIR"] ?? ((try? OwnerApplicationBundle.current())?.object(forInfoDictionaryKey: "AccountAccessInstallDirectory") as? String) ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/share/account-access/runtime").path)
    let ownerSetupContext = DesktopOwnerSetupContext()
    var window: NSWindow! { didSet { ownerSetupContext.invalidate() } }
    var stack: NSStackView!
    var status: NSTextField!
    var button: NSButton!
    var spinner: NSProgressIndicator!
    var services: NSPopUpButton!
    var username: NSTextField!
    var password: NSSecureTextField!
    var loginIdentityLabel: NSTextField?
    var loginSecretLabel: NSTextField?
    var permission: NSButton!
    var connectAction: NSButton?
    var savedSignInAction: NSButton?
    var catalog: [[String: Any]] = []
    var accounts: [[String: Any]] = []
    var agents = ["claude"]
    var principals: [String] = []
    var sources: [[String: Any]] = []
    var mailboxes: [[String: Any]] = []
    var mailboxOAuth: [[String: Any]] = []
    var deviceEmailSetups: [[String: Any]] = []
    var deviceEmailMailboxMenus: [String: NSPopUpButton] = [:]
    var deviceEmailReview: [String: Any]?
    var deviceEmailGeneration = 0
    var activeMailboxOAuth: MailboxOAuthLoopback?
    var mailboxOAuthCancelled = false
    var mailboxOAuthFinishing = false
    var mailboxOAuthAttempt: [String: String]?
    var mailboxFields: [String: NSTextField] = [:]
    var mailboxServerViews: [NSView] = []
    var mailboxKind: NSPopUpButton!
    var factorMailboxMenu: NSPopUpButton?
    var factorEntryViews: [NSView] = []
    var editingMailbox: String?
    enum MailboxRetryContext {
        case connect(provider: Int, username: String, host: String, port: String)
        case update(id: String)
    }
    var passwordSync: [[String: Any]] = []
    var bitwardenConnections: [[String: Any]] = []
    var bitwardenAvailable = false
    var bitwardenFields: [String: NSTextField] = [:]
    var bitwardenRegion: NSPopUpButton!
    var bitwardenConsent: NSButton!
    var bitwardenAccounts: NSPopUpButton!
    var bitwardenSources: NSPopUpButton!
    var bitwardenItem: NSTextField!
    var bitwardenItemLabel: NSTextField?
    var bitwardenItemNote: NSTextField?
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
    var syncProvider: NSPopUpButton!
    var syncFields: [String: NSTextField] = [:]
    var syncEndpointViews: [NSView] = []
    var syncTokenLabel: NSTextField?
    var syncReconnectAccount: String?
    var syncReconnectGeneration: String?
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
    var phonePairingAdvertiser: PhonePairingAdvertiser?
    private var phonePairingPayload: String?
    var base: URL!
    var token = ""
    let ownerConnectionLock = NSRecursiveLock()
    var systemOwner: DesktopOwnerConnection?
    var systemOwnerSelected = false
    var requiresSystemInstallation: Bool
    var systemOwnerReady = false
    var systemSetupGeneration = 0
    var systemApprovalProgress: (id: UUID, label: NSTextField)?
    var managedAgents = ManagedAgentSetup()
    var systemAgentClientID: String?
    var systemAgentUpgradeNeeded = false
    var connectAgentsAfterSetup = false
    #if ACCOUNT_ACCESS_UI_CHECKS
    var fixtureSystemOwnerSelected = false
    #endif

    override init() {
        root = Self.defaultRoot()
        runtimeOverride = nil
        requiresSystemInstallation = OwnerApplicationBundle.systemRequired
        installedOwnerProfile = { DesktopOwnerProfile.isInstalled }
        loadOwnerProfile = { try DesktopOwnerProfile() }
        super.init()
    }

    #if ACCOUNT_ACCESS_UI_CHECKS
    // Compile-time fixture dependency injection. No production default is
    // evaluated, even while stored properties are initialized.
    init(fixtureRoot: URL, session: URLSession, managedAgents: ManagedAgentSetup,
         ownerProfile: @escaping () throws -> DesktopOwnerProfile) {
        root = fixtureRoot
        runtimeOverride = fixtureRoot.appendingPathComponent("runtime")
        requiresSystemInstallation = false
        installedOwnerProfile = { false }
        loadOwnerProfile = ownerProfile
        super.init()
        self.session = session
        self.managedAgents = managedAgents
    }
    #endif

    var systemOwnerConfigured: Bool {
        #if ACCOUNT_ACCESS_UI_CHECKS
        if fixtureSystemOwnerSelected { return true }
        #endif
        return requiresSystemInstallation || systemOwnerSelected || installedOwnerProfile()
    }
    func nativeOwner() throws -> DesktopOwnerConnection? {
        guard systemOwnerConfigured else { return nil }
        systemOwnerSelected = true // Never fall back after selecting a protected registration.
        if let systemOwner { return systemOwner }
        do {
            let connection = try DesktopOwnerConnection(profile: loadOwnerProfile())
            systemOwner = connection
            return connection
        } catch { throw Failure.message("The protected installation could not be verified. Check the Account Access installation before connecting an account.") }
    }
    var busy = false { didSet { if busy != oldValue { ownerSetupContext.invalidate() } } }
    var backgroundRecovery: [String: Any] = [:]
    var backgroundServiceStatus = "unknown"
    var serviceEnvironment = "unclassified"
    var failedAccount: String?
    let localRequests = LocalRequests()
    static func effectiveEnvironment(_ account: [String: Any], fallback: String? = nil) -> String {
        let candidate = account["environment"] as? String ?? fallback ?? "unclassified"
        return ["live", "controlled-demo", "public-example"].contains(candidate) ? candidate : "unclassified"
    }
    static func isExample(_ account: [String: Any], fallback: String? = nil) -> Bool {
        ["controlled-demo", "public-example"].contains(effectiveEnvironment(account, fallback: fallback))
    }
    static func isLive(_ account: [String: Any], fallback: String? = nil) -> Bool {
        effectiveEnvironment(account, fallback: fallback) == "live"
    }
    static func verificationEnvironment(_ source: [String: Any], accounts: [[String: Any]], fallback: String? = nil) -> String {
        let linked = source["accounts"] as? [String] ?? []
        guard !linked.isEmpty else {
            if let fallback, ["live", "controlled-demo", "public-example"].contains(fallback) { return fallback }
            return "unclassified"
        }
        var environments: [String] = []
        for id in linked {
            guard let account = accounts.first(where: { $0["account"] as? String == id }) else { return "unclassified" }
            environments.append(effectiveEnvironment(account, fallback: fallback))
        }
        guard let first = environments.first, first != "unclassified", environments.allSatisfy({ $0 == first }) else {
            return "unclassified"
        }
        return first
    }
    static func isReady(_ account: [String: Any]) -> Bool {
        account["connected"] as? Bool == true && account["portable_ready"] as? Bool != false
            && (account["challenges"] as? [[String: Any]] ?? []).isEmpty
    }
    var preferredAgent: String { agents.contains("claude") ? "Claude Code" : agents.contains("codex") ? "Codex" : "your AI tool" }
    var requestText: String {
        if accounts.contains(where: { Self.isLive($0, fallback: serviceEnvironment) && Self.isReady($0) }) {
            return "Summarize the approved information from my connected services and save the results as one task."
        }
        if accounts.contains(where: { Self.isExample($0, fallback: serviceEnvironment) && Self.isReady($0) }) {
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
            if info?["version"] as? String == (try? OwnerApplicationBundle.current())?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String {
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
        clearDeviceEmailReview()
        return .terminateNow
    }

    func page(_ title: String, _ subtitle: String, preservingDeviceEmailReview: Bool = false) {
        phonePairingAdvertiser?.stop()
        phonePairingAdvertiser = nil
        phonePairingPayload = nil
        ownerSetupContext.invalidate()
        systemApprovalProgress = nil
        if !preservingDeviceEmailReview { clearDeviceEmailReview() }
        clearBitwardenFields()
        for field in mailboxFields.values where field is NSSecureTextField { field.stringValue = "" }
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
                guard let script = try OwnerApplicationBundle.current().url(forResource: "install", withExtension: "sh") else {
                    throw Failure.message("The installer is incomplete. Download it again from the official release.")
                }
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/bin/sh")
                process.arguments = [script.path]
                var environment = ProcessInfo.processInfo.environment
                environment["ACCOUNT_ACCESS_NO_OPEN"] = "1"
                environment["ACCOUNT_ACCESS_DATA_DIR"] = self.root.path
                environment["ACCOUNT_ACCESS_INSTALL_DIR"] = self.runtime.path
                guard let expectedHash = try OwnerApplicationBundle.current().object(forInfoDictionaryKey: "AccountAccessWheelSHA256") as? String,
                      expectedHash.count == 64 else {
                    throw Failure.message("The installer is missing its signed package checksum. Download the complete app from the official release.")
                }
                environment["ACCOUNT_ACCESS_EXPECTED_WHEEL_SHA256"] = expectedHash
                // The package is part of the signed app. Ignore inherited paths;
                // the bootstrap also checks it against the signed checksum.
                environment.removeValue(forKey: "ACCOUNT_ACCESS_BUNDLED_WHEEL")
                if let wheel = try OwnerApplicationBundle.current().url(forResource: "account_access", withExtension: "whl") {
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
        let source = try OwnerApplicationBundle.current().bundleURL
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
        guard let expected = (try? OwnerApplicationBundle.current())?.object(forInfoDictionaryKey: "AccountAccessWheelSHA256") as? String else { return false }
        return BackgroundRecovery.installationMatches(runtime: runtime, expected: expected)
    }

    func prepareBackgroundRecovery() -> String {
        // ServiceManagement must be called by the saved app, rather than the
        // original download that the installer copied into Applications.
        do {
            let layout = try BackgroundRecovery.Layout(bundle: OwnerApplicationBundle.current())
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
        clearDeviceEmailReview()
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
                    self.clearBitwardenFields()
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

    func ownerApprovalProgress(_ phase: DesktopOwnerSetupProgress, identifier: UUID,
                               context: DesktopOwnerSetupContext.Snapshot) {
        // Never wait synchronously for the UI while holding transport locks.
        DispatchQueue.main.async { [weak self] in
            guard let self, self.ownerSetupContext.isCurrent(context), self.busy,
                  let window = self.window else { return }
            switch phase {
            case .requestingApproval:
                let progressLabel: NSTextField
                if let status = self.status, status.window === window { progressLabel = status }
                else {
                    progressLabel = self.label("macOS approval requested…", 17)
                    self.status = progressLabel
                }
                self.systemApprovalProgress = (identifier, progressLabel)
                progressLabel.stringValue = "Find the separate macOS dialog “Authorize Account Access setup” and approve with Touch ID or your Mac login password. If no dialog appears, wait up to two minutes; the request stops without sending account setup data."
                window.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
            case .approvalAccepted:
                guard let progress = self.systemApprovalProgress, progress.id == identifier,
                      progress.label.window === window else { return }
                progress.label.stringValue = "Mac approval accepted. Continuing setup…"
                self.systemApprovalProgress = nil
            }
        }
    }

    func request(_ route: String, body: [String: Any]? = nil) throws -> [String: Any] {
        let approvalContext = ownerSetupContext.snapshot() // Before any transport lock or queued feedback.
        ownerConnectionLock.lock()
        defer { ownerConnectionLock.unlock() }
        let bitwardenRequest = route.hasPrefix("owner/bitwarden/") || (body?["connection"] as? [String: Any])?["provider"] as? String == "bitwarden"
        if let native = try nativeOwner() {
            do {
                let approvalProgressID = UUID()
                let response = try native.request(route, body: body, setupProgress: { phase in
                    self.ownerApprovalProgress(phase, identifier: approvalProgressID, context: approvalContext)
                })
                return try checkedOwnerResponse(response.0, response.1, pending: route == "owner/vault/enroll", bitwarden: bitwardenRequest)
            } catch DesktopOwnerFailure.approval {
                throw Failure.message("Setup was not approved. Your saved connections are preserved. Try the setup action again when you are ready to approve it on this Mac.")
            } catch DesktopOwnerFailure.approvalTimedOut {
                throw Failure.message("The macOS approval dialog did not finish within two minutes. If it is still open, finish or cancel it on this Mac before trying again. No account setup data was sent.")
            } catch DesktopOwnerFailure.approvalPending {
                throw Failure.message("A previous macOS approval dialog is still open. Finish or cancel it on this Mac before trying again. No account setup data was sent.")
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
        if route == "owner/bitwarden/connect" { message.timeoutInterval = 70 }
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
                result = .success(try self.checkedOwnerResponse(response.statusCode, payload, bitwarden: bitwardenRequest))
            } catch { result = .failure(error) }
        }.resume()
        guard done.wait(timeout: .now() + (route == "owner/bitwarden/connect" ? 75 : 35)) == .success else {
            throw Failure.message("The local app took too long to respond. Try again.")
        }
        return try result.get()
    }

    func checkedOwnerResponse(_ code: Int, _ payload: [String: Any], pending: Bool = false, bitwarden: Bool = false) throws -> [String: Any] {
        if code == 200 || (pending && code == 202) { return payload }
        if payload["reason"] as? String == "client_connection_conflict" { throw ManagedAgentSetupFailure.connectionConflict }
        if payload["reason"] as? String == "portable_client_revoked" { throw ManagedAgentSetupFailure.connectionRevoked }
        if bitwarden && payload["reason"] as? String == "password_source_access_removed" {
            throw Failure.message("Bitwarden did not accept this connection. Check the personal API key, region and master password, or reconnect if access was revoked.")
        }
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
            "password_source_runtime_unavailable": "Repair or update Account Access to restore the password-manager connection.",
            "bitwarden_connection_invalid": "Check the Bitwarden server region, personal API key and master password. Enter them only here.",
            "bitwarden_vault_consent_required": "Review and allow local Bitwarden vault access before connecting.",
            "bitwarden_protected_worker_required": "Bitwarden sync requires the protected Account Access installation. Update or repair the app first.",
            "bitwarden_connection_not_found": "This Bitwarden connection was removed. Connect it again in Password sync.",
            "bitwarden_connection_changed": "This Bitwarden connection changed. Reopen Password sync before linking or disconnecting it.",
            "mailbox_connection_failed": "The email server did not accept this connection. Check the email address and application password in Verification. No website sign-in was started.",
            "mailbox_temporarily_unavailable": "The mailbox is temporarily unreachable. Your saved setup is preserved; Account Access can retry without another login approval.",
            "mailbox_tls_verification_failed": "The mailbox's secure connection could not be verified. Check the server settings; Account Access will not use an unverified connection.",
            "mailbox_not_connected": "Connect this email account in Verification first. No website sign-in was started.",
            "mailbox_identity_mismatch": "The connected Gmail account does not match the mailbox approved for these login messages. Connect the correct Gmail account.",
            "mailbox_identity_check_required": "Check your saved Google connection in Verification, then review the website's email connection. You do not need to enter an app password.",
            "mailbox_connection_retry_required": "Google access is saved. Try Check Google connection again; Account Access can renew it without another consent prompt.",
            "mailbox_uid_tracking_unavailable": "This mail server did not provide the message tracking needed to exclude old codes. No website sign-in was started.",
            "invalid_mailbox_setup": "Check the email address, mail server and application password. Other email providers require their TLS IMAP server and port.",
            "mailbox_already_connected": "This mailbox is already saved. Use Update app password or Check connection on its card.",
            "mailbox_source_mismatch": "Choose the mailbox for the email address and mail server already approved for this website.",
            "mailbox_binding_changed": "This website or mailbox connection changed. Reopen Verification and choose the checked mailbox again.",
            "invalid_mailbox_binding": "Reopen Verification and choose a checked mailbox for this website.",
            "mailbox_binding_unsupported": "This website's email connection needs a supported connector before it can use a saved mailbox.",
            "mailbox_scope_missing": "Reconnect the configured Gmail account with permission to read login messages.",
            "mailbox_scope_not_allowed": "Google returned broader access than this Gmail connection permits. The publisher must check its Google application; your existing connection is preserved.",
            "mailbox_oauth_renewal_unavailable": "Google did not provide renewable access. Reconnect Google once so approved email-code logins can continue after access expires.",
            "password_export_encrypted": "Choose an unencrypted Bitwarden JSON export. Account Access cannot open password-protected exports. Keep the export on this Mac and remove it after importing.",
            "password_file_too_large": "The password export is too large. Export fewer accounts and try again.",
            "invalid_password_export": "The password file could not be read. Export a fresh UTF-8 CSV or unencrypted Bitwarden JSON file and try again.",
            "unsupported_password_export": "Choose a supported password CSV or unencrypted Bitwarden JSON export.",
            "import_connector_changed": "This account's connection changed after the import review. Choose the password file again and review the current account permissions.",
            "import_authenticator_changed": "This account's authenticator changed after the import review. Choose the password file again before replacing its authenticator key.",
            "pypi_manual_setup_unavailable": "Manual PyPI setup is unavailable in this pilot. Use the reviewed automatic route; your saved login is preserved.",
            "login_challenge_changed": "The website's verification route changed. Account Access stopped before another attempt; the connector needs review.",
            "device_email_setup_changed": "This account changed during the review. Open Verification and review its current email connection again.",
            "device_email_mailbox_changed": "This mailbox changed during the review. Check its connection, then choose it again.",
            "device_email_mailbox_unavailable": "Connect and check a mailbox first, then choose it for PyPI device emails.",
            "device_email_setup_expired": "This review expired. Choose the connected mailbox again to create a fresh review.",
            "device_email_setup_incomplete": "The connection result could not be confirmed. Open Verification to check its current state before trying again.",
            "invalid_device_email_setup": "Choose this account's connected mailbox again in Verification.",
            "device_email_setup_limit": "There are too many pending email reviews. Cancel an earlier review or wait briefly, then try again.",
            "account_not_connected": "Connect the configured Gmail account through Manage permissions first.",
            "provider_rejected_access": "The email provider rejected this connection. Reconnect the mailbox in Verification.",
            "network_unavailable": "The email provider could not be reached. Your saved setup is preserved; try Check email connection when it is online.",
            "invalid_authenticator_export": "This image is not a supported Authenticator transfer QR. Choose a complete export or the website's original setup QR.",
            "authenticator_export_incomplete": "Choose all QR images from the same Google Authenticator export together. No account was changed.",
            "authenticator_export_mismatch": "These QR images are duplicated or come from different exports. Choose each image from one complete export.",
            "unsupported_authenticator_settings": "This authenticator uses settings that are not supported yet. Six-digit SHA-1 TOTP is required.",
            "authenticator_preview_expired": "The import preview expired. Choose the QR image again.",
            "authenticator_selection_changed": "The connected account changed during the preview. Choose the QR image again and review the account.",
            "password_sync_requires_https_origin": "Enter only the HTTPS server address, without a path or query.",
            "invalid_password_sync_link": "Check the password source details and replacement token. Reopen Password sync if this form is out of date.",
            "password_sync_not_connected": "This password source was removed. Refresh Password sync before connecting it again.",
            "password_sync_connection_changed": "This connection changed while the form was open. Reopen Password sync and use its current Replace token action."
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
            if let detail = DesktopVaultRepair.detail(state) { card("Startup check", detail) }
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
        if systemAgentUpgradeNeeded {
            card("Upgrade your existing connection", "Your earlier Account Access skill was found. Upgrade connects it to the protected account store and keeps your personal instructions and tool preferences. Your earlier credentials and permissions are not copied.")
        }
        primary(systemAgentUpgradeNeeded ? "Upgrade AI connection" : "Connect automatically", #selector(connectSystemAgents))
    }

    func checkSystemAgentSetup(_ state: [String: Any]) {
        busy = true
        page("Checking your AI connection", "Verifying the installed portable skill…")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            let local: [String: Any]
            do {
                local = try self.managedAgents.status()
                guard let status = local["status"] as? String,
                      ["INSTALLED", "NOT_INSTALLED", "MIGRATION_REQUIRED"].contains(status) else {
                    throw ManagedAgentSetupFailure.invalidResponse
                }
            } catch {
                DispatchQueue.main.async {
                    self.connectAgentsAfterSetup = false
                    self.systemAgentUpgradeNeeded = false
                }
                self.fail(Failure.message("The existing AI connection could not be verified. It needs review before setup can continue. Your saved accounts and tool preferences are preserved."), retry: #selector(self.reopen))
                return
            }
            DispatchQueue.main.async {
                self.busy = false
                self.systemAgentUpgradeNeeded = local["status"] as? String == "MIGRATION_REQUIRED"
                let server = state["managed_client"] as? [String: Any] ?? [:]
                if local["status"] as? String == "INSTALLED", server["status"] as? String == "INSTALLED",
                   let identity = local["client_id"] as? String, identity == server["client_id"] as? String {
                    self.systemAgentClientID = identity
                    self.presentSystemState(state)
                } else if self.connectAgentsAfterSetup && !self.systemAgentUpgradeNeeded {
                    self.connectSystemAgents()
                } else {
                    self.connectAgentsAfterSetup = false
                    self.showSystemAgentSetup()
                }
            }
        }
    }

    @objc func connectSystemAgents() {
        guard !busy else { return }
        connectAgentsAfterSetup = false
        let upgrade = systemAgentUpgradeNeeded
        systemSetupGeneration += 1
        busy = true
        page("Connecting your AI tools", "Preparing one private connection and automatic skill discovery. macOS may ask you to approve this setup action.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            var connectionFinished = false
            do {
                try self.managedAgents.connect(upgrade: upgrade) { route, body in try self.request(route, body: body) }
                connectionFinished = true
                let state = try self.request("owner/state")
                guard let client = state["managed_client"] as? [String: Any], client["status"] as? String == "INSTALLED",
                      let identity = client["client_id"] as? String else { throw ManagedAgentSetupFailure.invalidResponse }
                DispatchQueue.main.async {
                    self.busy = false
                    self.systemAgentClientID = identity
                    self.systemAgentUpgradeNeeded = false
                    self.presentSystemState(state)
                }
            } catch {
                let failure = error as? ManagedAgentConnectionFailure
                    ?? ManagedAgentConnectionFailure(stage: connectionFinished ? .verify : .prepare, error: error)
                self.fail(Failure.message(failure.explanation), retry: #selector(self.reopen))
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
        serviceEnvironment = state["environment"] as? String ?? "unclassified"
        backgroundRecovery = state["background_recovery"] as? [String: Any] ?? [:]
        navigationFailures = state["navigation_failures"] as? [[String: Any]] ?? []
        browserUpdates = state["browser_updates"] as? [[String: Any]] ?? []
        smsSetups = state["sms_setups"] as? [[String: Any]] ?? []
        browserSessionAccounts = state["browser_session_accounts"] as? [[String: Any]] ?? []
        passwordSync = state["password_sync"] as? [[String: Any]] ?? []
        bitwardenConnections = state["bitwarden_connections"] as? [[String: Any]] ?? []
        bitwardenAvailable = state["bitwarden_available"] as? Bool ?? false
        catalog = state["catalog"] as? [[String: Any]] ?? []
        accounts = state["accounts"] as? [[String: Any]] ?? []
        sources = (state["code_sources"] as? [[String: Any]] ?? []).filter {
            $0["message_purpose"] as? String != "pypi-device-confirmation"
        }
        mailboxes = state["mailboxes"] as? [[String: Any]] ?? []
        mailboxOAuth = state["mailbox_oauth"] as? [[String: Any]] ?? []
        deviceEmailSetups = state["device_email_setups"] as? [[String: Any]] ?? []
        principals = state["principals"] as? [String] ?? []
        agents = state["integrations"] as? [String] ?? principals
        automaticSessions = state["automatic_sessions"] as? [String: [String: Any]] ?? [:]
        verificationDetails = [:]
        for account in accounts {
            guard let handle = account["account"] as? String else { continue }
            for challenge in account["challenges"] as? [[String: Any]] ?? [] {
                let detail = Self.verificationDetailText(challenge["diagnostics"] as? [String: Any] ?? [:])
                if !detail.isEmpty { verificationDetails[handle] = detail; break }
            }
        }
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
        if diagnostic["schema"] != nil {
            return structuralVerificationDetailText(diagnostic, route: route)
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

    static func structuralVerificationDetailText(_ diagnostic: [String: Any], route: (Any?) -> String?) -> String {
        func integer(_ value: Any?, maximum: Int) -> Int? {
            guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                  ["c", "C", "s", "S", "i", "I", "l", "L", "q", "Q"].contains(String(cString: number.objCType)),
                  number.doubleValue >= 0, number.doubleValue <= Double(maximum) else { return nil }
            return number.intValue
        }
        func boolean(_ value: Any?) -> Bool? {
            guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
            return number.boolValue
        }
        let fields = ["password", "one_time_code", "numeric_input", "email_input"]
        let markers = Set(["login", "sms", "email", "totp", "device", "passkey", "captcha", "admin", "action", "recovery", "unknown", "method"])
        let phases = ["password_submit_attempted", "identity_submit_attempted", "sms_requested", "email_requested", "sms_code_filled", "email_code_filled", "totp_code_filled", "sms_submit_attempted", "email_submit_attempted", "totp_submit_attempted"]
        guard Set(diagnostic.keys) == Set(["schema", "page", "forms", "fields", "field_counts", "visible_field_counts", "markers", "progress"]),
              integer(diagnostic["schema"], maximum: 1) == 1, let page = route(diagnostic["page"]),
              let forms = diagnostic["forms"] as? [[String: Any]], forms.count <= 8,
              let present = diagnostic["fields"] as? [String: Any], Set(present.keys) == Set(fields),
              let counts = diagnostic["field_counts"] as? [String: Any], Set(counts.keys) == Set(fields),
              let visible = diagnostic["visible_field_counts"] as? [String: Any], Set(visible.keys) == Set(fields),
              let matches = diagnostic["markers"] as? [String: Any], Set(matches.keys) == markers,
              matches.values.allSatisfy({ boolean($0) != nil }),
              let progress = diagnostic["progress"] as? [String: Any],
              Set(progress.keys).isSubset(of: Set(phases + ["method"])) else { return "" }
        var lines = ["Details from the first stopped sign-in", "Page: " + page]
        for form in forms {
            guard Set(form.keys) == Set(["method", "visible", "reviewed_action", "controls"]),
                  let method = form["method"] as? String, ["GET", "POST", "other"].contains(method),
                  let shown = boolean(form["visible"]), let reviewed = boolean(form["reviewed_action"]),
                  let controls = integer(form["controls"], maximum: 32) else { return "" }
            lines.append("Form: " + method + (shown ? " visible" : " hidden") + "; controls: " + String(controls))
            lines.append(reviewed ? "Form destination matches a configured static login route" : "Form destination does not match a configured static login route")
        }
        let labels = ["Password fields", "One-time-code fields", "Numeric input fields", "Email input fields"]
        for (index, field) in fields.enumerated() {
            guard let total = integer(counts[field], maximum: 8),
                  let shown = integer(visible[field], maximum: 8), shown <= total,
                  boolean(present[field]) == (shown > 0) else { return "" }
            lines.append(labels[index] + ": " + String(shown) + " visible / " + String(total) + " observed")
        }
        for marker in markers.sorted() where boolean(matches[marker]) == true {
            lines.append("Configured sign-in marker: " + marker)
        }
        for (key, value) in progress {
            if key == "method" {
                guard let method = value as? String, ["email", "sms", "totp"].contains(method) else { return "" }
            } else if boolean(value) == nil { return "" }
        }
        if let method = progress["method"] as? String { lines.append("Selected method: " + method) }
        for phase in phases where boolean(progress[phase]) == true { lines.append("Login stage: " + phase) }
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
        loginIdentityLabel = label("Email or username", 14, .secondaryLabelColor)
        username = NSTextField()
        username.placeholderString = "Email or username"
        username.font = .systemFont(ofSize: 18)
        username.delegate = self
        username.heightAnchor.constraint(equalToConstant: 40).isActive = true
        stack.addArrangedSubview(username)
        username.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        loginSecretLabel = label("Password", 14, .secondaryLabelColor)
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
        let identityPhone = entry["login_method"] as? String == "identity_phone_sms"
        if (username is NSSecureTextField) != identityPhone,
           let index = stack.arrangedSubviews.firstIndex(of: username) {
            let replacement: NSTextField = identityPhone ? NSSecureTextField() : NSTextField()
            replacement.font = username.font
            replacement.delegate = self
            stack.removeArrangedSubview(username)
            username.removeFromSuperview()
            username.stringValue = ""
            username = replacement
            stack.insertArrangedSubview(replacement, at: index)
            replacement.heightAnchor.constraint(equalToConstant: 40).isActive = true
            replacement.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        loginIdentityLabel?.stringValue = identityPhone ? "Identity number" : "Email or username"
        loginSecretLabel?.stringValue = identityPhone ? "Phone number for login SMS" : "Password"
        username.placeholderString = identityPhone ? "Identity number" : "Email or username"
        password.placeholderString = identityPhone ? "Phone number" : "Password"
        let operations = entry["operations"] as? [[String: Any]] ?? []
        permission.title = "Allow your AI to: " + operations.compactMap { $0["description"] as? String }.joined(separator: "; ")
        permission.state = .off
        username.stringValue = ""
        password.stringValue = ""
        connectionInputChanged()
    }

    static func loginCredential(entry: [String: Any], identity: String, secret: String) -> [String: String] {
        if entry["login_method"] as? String == "identity_phone_sms" {
            return ["identity": identity, "phone": secret]
        }
        return ["username": identity, "password": secret]
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
        let credential = Self.loginCredential(entry: entry, identity: username.stringValue, secret: password.stringValue)
        var body: [String: Any] = credential
        body["service"] = service
        body["agents"] = ["generic"]
        let existing = accounts.contains { $0["account"] as? String == service }
        failedAccount = service
        username.stringValue = ""
        password.stringValue = ""
        busy = true
        page("Connecting your account", "Checking the saved login and the read you approved…")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let job: [String: Any]
                if existing {
                    var edit: [String: Any] = credential
                    edit["account"] = service
                    _ = try self.request("owner/credential", body: edit)
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
            ? "A fresh matching SMS code was received locally. Your saved sign-in details are preserved."
            : progress["sms_requested"] as? Bool == true
                ? "The website accepted the SMS request, but delivery is unconfirmed. Your saved sign-in details are preserved."
                : isSMS ? "No SMS delivery was tested. Your saved sign-in details are preserved."
                    : "Your saved sign-in details are preserved."
        switch attention["reason"] as? String ?? "" {
        case "browser_captcha_required":
            return "The website requires a browser security check that this connector cannot complete automatically. Your saved sign-in details are preserved."
        case "browser_recovery_required":
            return "The website opened account recovery. Use an available sign-in method in its window. " + delivery
        case "browser_passkey_required", "browser_device_required", "browser_admin_required", "browser_action_required":
            return "The website requires owner approval before continuing. " + delivery
        case "browser_state_unrecognized":
            return "The website returned a sign-in page this connector does not recognize. " + delivery
        case "login_challenge_changed":
            return "The website's verification route changed. Account Access stopped before another attempt; the connector needs review. " + delivery
        case "pypi_manual_setup_unavailable":
            return "PyPI manual setup is unavailable. Connect its authenticator and checked device-email mailbox in Verification, then retry the approved read. " + delivery
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
            return "The sign-in did not reach a confirmed SMS request. No SMS delivery was tested and no filter was enabled. Your saved sign-in details are preserved."
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
                    throw Failure.message("The website requires a browser security check that this connector cannot complete automatically. Your saved sign-in details are preserved; this sign-in remains unverified.")
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
        clearDeviceEmailReview()
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.ready() }
            } catch { self.fail(error, retry: #selector(self.reopen)) }
        }
    }

    @objc func importPasswords() {
        clearDeviceEmailReview()
        section = "import"
        page("Import saved passwords", "Bring your supported logins from the password manager you already use.")
        card("1  Export your passwords", "In Chrome, open Password Manager, then Settings and Export passwords. Apple Passwords, Bitwarden and compatible 1Password CSV exports also work. Bitwarden can also export an unencrypted JSON file.")
        card("2  Choose the export", "Select the CSV or Bitwarden JSON file on this Mac. You'll review matching supported accounts before anything is saved.")
        card("3  Approve your accounts", "Choose the logins and reads you want to allow. Passwords are encrypted locally. You can move the export to Trash after importing.")
        primary("Choose password file", #selector(choosePasswordFile))
        card("Keeping passwords current", "CSV and JSON exports are snapshots. Connect Bitwarden or a configured 1Password source to keep approved passwords current automatically. Other imported passwords need a fresh export after changes.")
        action("Connect a live password source", #selector(showPasswordSync))
        action("Back to my accounts", #selector(showReady))
    }

    @objc func choosePasswordFile() {
        let picker = NSOpenPanel()
        picker.allowedContentTypes = [.commaSeparatedText, .json]
        picker.allowsMultipleSelection = false
        picker.message = "Select a password CSV or unencrypted Bitwarden JSON export. Only selected supported logins will be saved."
        guard picker.runModal() == .OK, let file = picker.url else { return }
        do {
            let csv = try Self.readPasswordExport(file)
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

    static func readPasswordExport(_ file: URL) throws -> String {
        let limit = 4_000_000
        let invalid = Failure.message("Choose the original CSV or Bitwarden JSON export file. It must be a readable UTF-8 file on this Mac.")
        let tooLarge = Failure.message("The password export is too large. Export fewer accounts and try again.")
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw invalid }
        defer { Darwin.close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG else { throw invalid }
        guard before.st_size <= limit else { throw tooLarge }
        guard before.st_size > 0 else { throw invalid }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = Darwin.read(fd, &buffer, min(buffer.count, limit + 1 - data.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw invalid }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
            guard data.count <= limit else { throw tooLarge }
        }
        var after = stat()
        guard fstat(fd, &after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, after.st_size == data.count,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              let contents = String(data: data, encoding: .utf8) else { throw invalid }
        return contents
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
            let example = Self.isExample(saved, fallback: serviceEnvironment)
            let live = Self.isLive(saved, fallback: serviceEnvironment)
            let explanation = ready ? (example ? "Example sign-in verified. These results do not validate a personal account."
                : live ? "Sign-in verified. This approved account is ready for your AI."
                : "The sign-in result is saved, but its source could not be verified. It does not establish personal-account access.")
                : "Your login is saved. Review the sign-in status before using this connection."
            let body = card(name, issue ?? explanation,
                            status: ready ? (example ? "Example connected" : live ? "Connected" : "Source unverified")
                                : "Saved · Sign-in needs attention", good: ready && (example || live))
            if !ready {
                let inspect = NSButton(title: "Review sign-in help", target: self, action: #selector(inspectSavedSignIn))
                inspect.identifier = NSUserInterfaceItemIdentifier(account)
                body.addArrangedSubview(inspect)
            }
        }
        if !issues.isEmpty && (!sources.isEmpty || !smsSetups.isEmpty || !deviceEmailSetups.isEmpty) { action("Review verification methods", #selector(showFactors)) }
        primary("Go to my accounts", #selector(showReady))
    }

    @objc func inspectSavedSignIn(_ sender: NSButton) {
        guard !busy, let account = sender.identifier?.rawValue,
              accounts.contains(where: { $0["account"] as? String == account }) else { return }
        section = "accounts"
        page("Sign-in help", "This version cannot open a website sign-in window for you. Review the saved connection and its verification methods here.")
        card("Your saved connection", "Review account connection shows the existing reconnect and access options. Connect any missing verification method before retrying the supported sign-in check.")
        let review = primary("Review account connection", #selector(reviewAccount))
        review.identifier = NSUserInterfaceItemIdentifier(account)
        action("Review verification methods", #selector(showFactors))
        action("Back to my accounts", #selector(showReady))
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
        syncFields.values.forEach { $0.stringValue = "" }
        clearBitwardenFields()
        syncReconnectAccount = nil
        syncReconnectGeneration = nil
        section = "sync"
        page("Keep passwords up to date", "Approved logins stay automatic when your connected password source changes.")
        card("Chrome and password file imports", "CSV and JSON exports are one-time snapshots. Chrome does not offer this app a public password-sync API. Re-import after a password change; this app never leaves a plaintext export running in the background.")
        for link in passwordSync {
            let account = link["account"] as? String ?? ""
            let name = accounts.first { $0["account"] as? String == account }?["label"] as? String ?? account
            let provider = link["provider"] as? String ?? "1Password"
            let body = card(name, provider + " · checks every five minutes while the service is running. Only the password can update; account identity and permissions stay fixed.", status: link["status"] as? String ?? "", good: link["status"] as? String == "SYNCED")
            if provider == "Bitwarden" {
                body.addArrangedSubview(NSTextField(wrappingLabelWithString: "Reconnect Bitwarden below if its vault access changes. A replacement token cannot repair this connection."))
            } else if let generation = link["generation"] as? String,
               Self.passwordSyncReconnectConnection(token: "shape-check", generation: generation) != nil {
                let replace = NSButton(title: "Replace token", target: self, action: #selector(showReconnectPasswordSync))
                replace.identifier = NSUserInterfaceItemIdentifier(account)
                body.addArrangedSubview(replace)
            } else {
                body.addArrangedSubview(NSTextField(wrappingLabelWithString: "A check is in progress. Reopen Password sync before replacing its token."))
            }
            let disconnect = NSButton(title: "Disconnect and remove saved login", target: self, action: #selector(disconnectPasswordSync))
            disconnect.identifier = NSUserInterfaceItemIdentifier(account)
            body.addArrangedSubview(disconnect)
        }
        showBitwardenSyncCards()
        card("Connect 1Password", "Use a service account with read-only access to a dedicated vault, or an existing Connect server. Choose the exact login item for an account you already imported. Tokens stay encrypted locally; the app cannot add accounts or permissions through sync.")
        syncAccounts = NSPopUpButton()
        for account in accounts where account["route"] as? String == "browser" && account["portable_ready"] as? Bool == true && account["login_method"] as? String != "identity_phone_sms" {
            syncAccounts.addItem(withTitle: account["label"] as? String ?? "Account")
            syncAccounts.lastItem?.representedObject = account["account"]
        }
        guard syncAccounts.numberOfItems > 0 else {
            label("Import and approve an account first.")
            action("Import passwords", #selector(importPasswords))
            return
        }
        stack.addArrangedSubview(syncAccounts)
        syncProvider = NSPopUpButton()
        syncProvider.addItems(withTitles: ["1Password service account", "1Password Connect server"])
        syncProvider.setAccessibilityLabel("Password source connection")
        syncProvider.target = self
        syncProvider.action = #selector(syncProviderChanged)
        stack.addArrangedSubview(syncProvider)
        syncFields = [:]
        syncEndpointViews = []
        for (key, title) in [("endpoint", "Connect server HTTPS address"), ("vault", "Vault ID"), ("item", "Login item ID"), ("token", "Read-only Connect token")] {
            label(title, 14, .secondaryLabelColor)
            if key == "endpoint", let view = stack.arrangedSubviews.last { syncEndpointViews.append(view) }
            if key == "token" { syncTokenLabel = stack.arrangedSubviews.last as? NSTextField }
            let field: NSTextField = key == "token" ? NSSecureTextField() : NSTextField()
            field.placeholderString = title
            field.setAccessibilityLabel(title)
            stack.addArrangedSubview(field)
            field.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
            syncFields[key] = field
            if key == "endpoint" { syncEndpointViews.append(field) }
        }
        syncProviderChanged()
        primary("Connect automatic updates", #selector(connectPasswordSync))
    }

    static func passwordSyncReconnectConnection(token: String, generation: String) -> [String: String]? {
        guard !token.isEmpty, token.utf8.count <= 8192, !token.contains("\r"), !token.contains("\n"),
              generation.utf8.count == 32,
              generation.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else { return nil }
        return ["token": token, "generation": generation]
    }

    func clearBitwardenFields() {
        bitwardenFields.values.forEach { $0.stringValue = "" }
        bitwardenConsent?.state = .off
    }

    static func canonicalBitwardenUUID(_ value: String) -> Bool {
        value.utf8.count == 36 && value.range(of: "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", options: .regularExpression) != nil
    }

    static func bitwardenIdentity(id: String, generation: String) -> [String: String]? {
        guard [id, generation].allSatisfy({ $0.utf8.count == 32 && $0.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil }) else { return nil }
        return ["id": id, "generation": generation]
    }

    static func bitwardenEnrollment(region: String, fields: [String: String], consent: Bool) -> [String: Any]? {
        guard consent, ["us", "eu"].contains(region), Set(fields.keys) == ["client_id", "client_secret", "master_password"],
              let client = fields["client_id"], client.hasPrefix("user."), client.utf8.count == 41,
              canonicalBitwardenUUID(String(client.dropFirst(5))),
              let secret = fields["client_secret"], (1...8192).contains(secret.utf8.count),
              !secret.contains("\0"), !secret.contains("\r"), !secret.contains("\n"),
              let master = fields["master_password"], (1...4096).contains(master.utf8.count), !master.contains("\0") else { return nil }
        return ["region": region, "client_id": client, "client_secret": secret, "master_password": master, "consent_vault_access": true]
    }

    static func bitwardenItemConnection(id: String, generation: String, item: String) -> [String: String]? {
        guard bitwardenIdentity(id: id, generation: generation) != nil, canonicalBitwardenUUID(item) else { return nil }
        return ["provider": "bitwarden", "connection": id, "connection_generation": generation, "item": item]
    }

    func showBitwardenSyncCards() {
        for connection in bitwardenConnections {
            guard let id = connection["id"] as? String, let generation = connection["generation"] as? String,
                  Self.bitwardenIdentity(id: id, generation: generation) != nil else { continue }
            let email = connection["email"] as? String ?? "Bitwarden account"
            let region = connection["region"] as? String == "eu" ? "Europe" : "United States"
            let connectionStatus = connection["status"] as? String ?? "CONNECTED"
            let body = card("Bitwarden · " + email, region + " server. This connection keeps its own encrypted vault session. Locking another Bitwarden app does not disconnect it.", status: connectionStatus, good: connectionStatus == "CONNECTED")
            let remove = NSButton(title: "Disconnect Bitwarden vault", target: self, action: #selector(disconnectBitwarden))
            remove.identifier = NSUserInterfaceItemIdentifier(id)
            body.addArrangedSubview(remove)
        }
        guard bitwardenAvailable else {
            card("Bitwarden live sync", "Update or repair Account Access to install its protected Bitwarden component. File import still works; live connection setup becomes available after repair.")
            return
        }
        card("Connect Bitwarden once", "Bitwarden JSON imports are snapshots. Connect your vault once to keep selected, already-approved passwords current automatically. Your master password is used only to unlock setup and is never saved.")
        action("Connect Bitwarden", #selector(showBitwardenConnect))
        let choices = accounts.filter { $0["route"] as? String == "browser" && $0["portable_ready"] as? Bool == true && $0["login_method"] as? String != "identity_phone_sms" }
        let connectedVaults = bitwardenConnections.filter { ($0["status"] as? String ?? "CONNECTED") == "CONNECTED" }
        guard !connectedVaults.isEmpty, !choices.isEmpty else {
            label("Import and approve a supported login, then select it here after connecting Bitwarden.", 14, .secondaryLabelColor)
            return
        }
        label("Keep an approved login current with Bitwarden", 17)
        bitwardenAccounts = NSPopUpButton()
        bitwardenAccounts.setAccessibilityLabel("Approved account for Bitwarden sync")
        for account in choices {
            bitwardenAccounts.addItem(withTitle: account["label"] as? String ?? "Account")
            bitwardenAccounts.lastItem?.representedObject = account["account"]
        }
        bitwardenAccounts.target = self
        bitwardenAccounts.action = #selector(bitwardenAccountChanged)
        stack.addArrangedSubview(bitwardenAccounts)
        bitwardenSources = NSPopUpButton()
        bitwardenSources.setAccessibilityLabel("Connected Bitwarden vault")
        for connection in connectedVaults {
            guard let id = connection["id"] as? String, let generation = connection["generation"] as? String,
                  let identity = Self.bitwardenIdentity(id: id, generation: generation) else { continue }
            bitwardenSources.addItem(withTitle: (connection["email"] as? String ?? "Bitwarden account") + " · " + (connection["region"] as? String ?? ""))
            bitwardenSources.lastItem?.representedObject = identity
        }
        stack.addArrangedSubview(bitwardenSources)
        bitwardenItemNote = label("", 14, .secondaryLabelColor)
        bitwardenItemLabel = label("Bitwarden login item ID (advanced)", 14, .secondaryLabelColor)
        bitwardenItem = NSTextField()
        bitwardenItem.placeholderString = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        bitwardenItem.setAccessibilityLabel("Bitwarden login item ID (advanced)")
        stack.addArrangedSubview(bitwardenItem)
        bitwardenItem.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        bitwardenAccountChanged()
        action("Connect Bitwarden automatic updates", #selector(linkBitwardenItem))
    }

    @objc func bitwardenAccountChanged() {
        let account = bitwardenAccounts?.selectedItem?.representedObject as? String
        let suggestion = accounts.first { $0["account"] as? String == account }?["password_sync_suggestion"] as? [String: String]
        let item = suggestion?["provider"] == "bitwarden" ? suggestion?["item"] : nil
        let imported = item.map(Self.canonicalBitwardenUUID) == true
        bitwardenItem?.stringValue = imported ? item! : ""
        bitwardenItem?.isHidden = imported
        bitwardenItem?.isEditable = !imported
        bitwardenItemLabel?.isHidden = imported
        bitwardenItemNote?.stringValue = imported ? "Uses the exact Bitwarden login selected during password import. Only its password can update." : "Advanced: enter this login's exact item ID from Bitwarden. Account Access checks its website and username before linking it."
    }

    @objc func showBitwardenConnect() {
        guard bitwardenAvailable else { showPasswordSync(); return }
        page("Connect Bitwarden once", "Your approved login passwords can then update without routine prompts.")
        card("One-time setup", "In the Bitwarden web vault, open Settings → Security → Keys, then View API key. Choose the same server region you use in Bitwarden. Your master password is used for this setup only and is never saved.")
        action("Open Bitwarden setup instructions", #selector(openBitwardenInstructions))
        label("Bitwarden server", 14, .secondaryLabelColor)
        bitwardenRegion = NSPopUpButton()
        bitwardenRegion.addItems(withTitles: ["United States · bitwarden.com", "Europe · bitwarden.eu"])
        bitwardenRegion.setAccessibilityLabel("Bitwarden server region")
        stack.addArrangedSubview(bitwardenRegion)
        bitwardenFields = [:]
        for (key, title) in [("client_id", "Personal API client ID"), ("client_secret", "Personal API client secret"), ("master_password", "Bitwarden master password")] {
            label(title, 14, .secondaryLabelColor)
            let field = NSSecureTextField()
            field.placeholderString = title
            field.setAccessibilityLabel(title)
            stack.addArrangedSubview(field)
            field.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
            bitwardenFields[key] = field
        }
        card("Review vault access", "Bitwarden's session can decrypt your whole vault. Account Access keeps that session encrypted locally and fetches only exact items you link to approved logins. Disconnecting below removes this connection and its saved linked passwords and sessions. No vault list, password or key is sent to your AI.")
        bitwardenConsent = NSButton(checkboxWithTitle: "Allow Account Access to decrypt my Bitwarden vault locally", target: nil, action: nil)
        bitwardenConsent.setAccessibilityLabel("Allow local Bitwarden vault decryption")
        bitwardenConsent.state = .off
        stack.addArrangedSubview(bitwardenConsent)
        primary("Connect Bitwarden vault", #selector(connectBitwarden))
        action("Cancel Bitwarden setup", #selector(showPasswordSync))
    }

    @objc func openBitwardenInstructions() { NSWorkspace.shared.open(URL(string: "https://bitwarden.com/help/personal-api-key/")!) }

    @objc func connectBitwarden() {
        guard bitwardenAvailable, let body = Self.bitwardenEnrollment(region: bitwardenRegion.indexOfSelectedItem == 1 ? "eu" : "us",
            fields: bitwardenFields.mapValues { $0.stringValue }, consent: bitwardenConsent.state == .on) else {
            status.stringValue = "Enter your personal API details and master password, then review local vault access."
            return
        }
        clearBitwardenFields()
        busy = true
        page("Connecting Bitwarden", "Checking your vault connection. The master password is not saved; this can take up to a minute.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/bitwarden/connect", body: body)
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showPasswordSync() }
            } catch { self.fail(error, retry: #selector(self.showPasswordSync)) }
        }
    }

    @objc func linkBitwardenItem() {
        guard let account = bitwardenAccounts?.selectedItem?.representedObject as? String,
              let identity = bitwardenSources?.selectedItem?.representedObject as? [String: String],
              let connection = Self.bitwardenItemConnection(id: identity["id"] ?? "", generation: identity["generation"] ?? "", item: bitwardenItem?.stringValue ?? "") else {
            status.stringValue = "Choose the current Bitwarden connection and this login's exact item."
            return
        }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/password-sync", body: ["account": account, "connection": connection])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showPasswordSync() }
            } catch { self.fail(error, retry: #selector(self.showPasswordSync)) }
        }
    }

    @objc func disconnectBitwarden(_ sender: NSButton) {
        guard let id = sender.identifier?.rawValue,
              let connection = bitwardenConnections.first(where: { $0["id"] as? String == id }),
              let generation = connection["generation"] as? String,
              let identity = Self.bitwardenIdentity(id: id, generation: generation) else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/bitwarden/disconnect", body: identity)
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showPasswordSync() }
            } catch { self.fail(error, retry: #selector(self.showPasswordSync)) }
        }
    }

    @objc func showReconnectPasswordSync(_ sender: NSButton) {
        guard let account = sender.identifier?.rawValue,
              let link = passwordSync.first(where: { $0["account"] as? String == account }),
              link["provider"] as? String != "Bitwarden",
              let generation = link["generation"] as? String,
              Self.passwordSyncReconnectConnection(token: "shape-check", generation: generation) != nil else {
            status.stringValue = "Reopen Password sync after the current check finishes."
            return
        }
        syncFields.values.forEach { $0.stringValue = "" }
        syncReconnectAccount = account
        syncReconnectGeneration = generation
        let name = accounts.first { $0["account"] as? String == account }?["label"] as? String ?? account
        page("Replace password source token", "Update automatic password access for " + name + ".")
        card("Same approved login", "The website, username and exact password-manager item stay the same. If the replacement cannot be verified, the existing connection is preserved.")
        label("Replacement read-only token", 14, .secondaryLabelColor)
        let secret = NSSecureTextField()
        secret.placeholderString = "Replacement read-only token"
        secret.setAccessibilityLabel("Replacement read-only token")
        stack.addArrangedSubview(secret)
        secret.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        syncFields = ["token": secret]
        primary("Check and replace token", #selector(reconnectPasswordSync))
        action("Cancel token replacement", #selector(showPasswordSync))
    }

    @objc func reconnectPasswordSync() {
        guard let account = syncReconnectAccount, let generation = syncReconnectGeneration,
              let connection = Self.passwordSyncReconnectConnection(token: syncFields["token"]?.stringValue ?? "", generation: generation) else {
            status.stringValue = "Enter the replacement read-only token."
            return
        }
        syncFields.values.forEach { $0.stringValue = "" }
        syncReconnectAccount = nil
        syncReconnectGeneration = nil
        busy = true
        page("Checking the replacement token", "Verifying the same approved login. Existing access is preserved if this check fails.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/password-sync/reconnect", body: ["account": account, "connection": connection])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showPasswordSync() }
            } catch { self.fail(error, retry: #selector(self.showPasswordSync)) }
        }
    }

    @objc func syncProviderChanged() {
        let serviceAccount = syncProvider.indexOfSelectedItem == 0
        for view in syncEndpointViews { view.isHidden = serviceAccount }
        syncFields["endpoint"]?.isEnabled = !serviceAccount
        syncFields["endpoint"]?.stringValue = ""
        syncFields["token"]?.stringValue = ""
        let title = serviceAccount ? "Service-account token for a read-only vault" : "Read-only Connect token"
        syncTokenLabel?.stringValue = title
        syncFields["token"]?.placeholderString = title
        syncFields["token"]?.setAccessibilityLabel(title)
    }

    static func passwordSyncConnection(provider: Int, fields: [String: String]) -> [String: String]? {
        guard provider == 0 || provider == 1 else { return nil }
        var connection = fields.filter { provider == 1 || $0.key != "endpoint" }
        guard Set(connection.keys) == (provider == 0 ? Set(["vault", "item", "token"]) : Set(["endpoint", "vault", "item", "token"])),
              connection.values.allSatisfy({ !$0.isEmpty }) else { return nil }
        if provider == 0 { connection["provider"] = "onepassword-service-account" }
        return connection
    }

    @objc func connectPasswordSync() {
        guard let account = syncAccounts.selectedItem?.representedObject as? String,
              let connection = Self.passwordSyncConnection(provider: syncProvider.indexOfSelectedItem,
                                                           fields: syncFields.mapValues { $0.stringValue }) else {
            status.stringValue = "Enter the selected password source's token, vault and login item details."
            return
        }
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
        showGmailOAuthCards()
        for mailbox in mailboxes {
            guard let id = mailbox["id"] as? String else { continue }
            let check = mailbox["connection_check"] as? [String: Any] ?? [:]
            let checked = check["status"] as? String == "VERIFIED"
            let example = serviceEnvironment == "controlled-demo" || mailbox["host"] as? String == "127.0.0.1"
            let panel = card((mailbox["label"] as? String ?? "Email") + " · " + (mailbox["username"] as? String ?? ""),
                             checked ? "Email access passed its last check. Connect a supported website to use its login codes."
                             : "Setup is saved. Check the address and app password, then check this connection.",
                             status: example ? "Example mailbox" : checked ? "Mailbox connection checked" : "Setup saved",
                             good: checked && !example)
            if example {
                panel.addArrangedSubview(NSTextField(wrappingLabelWithString: "Controlled test mailbox. This is not a real email connection."))
            }
            for (title, selector) in [("Check connection", #selector(checkSavedMailbox(_:))),
                                      ("Update app password", #selector(editMailboxPassword(_:))),
                                      ("Disconnect mailbox", #selector(disconnectMailbox(_:)))] {
                let button = NSButton(title: title, target: self, action: selector)
                button.identifier = NSUserInterfaceItemIdentifier(id)
                panel.addArrangedSubview(button)
            }
        }
        action("Connect Gmail or email", #selector(showEmailSetup))
        showDeviceEmailCards()
        if sources.isEmpty && smsSetups.isEmpty && deviceEmailSetups.isEmpty {
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
            let environment = Self.verificationEnvironment(source, accounts: accounts, fallback: serviceEnvironment)
            let suffix = ["controlled-demo", "public-example"].contains(environment) ? " · Example"
                : environment == "unclassified" ? " · Source unverified" : ""
            let label = factorName(source["kind"] as? String ?? "") + " · " + linked.joined(separator: ", ") + suffix
            factorMenu.addItem(withTitle: label)
            factorMenu.lastItem?.representedObject = source
        }
        factorMenu.target = self
        factorMenu.action = #selector(factorChanged)
        stack.addArrangedSubview(factorMenu)
        factorChanged()
    }

    func discardDeviceEmailID(_ id: String) {
        DispatchQueue.global(qos: .utility).async {
            _ = try? self.request("owner/device-email/discard", body: ["id": id])
        }
    }

    func clearDeviceEmailReview() {
        deviceEmailGeneration += 1
        let id = deviceEmailReview?["id"] as? String
        deviceEmailReview = nil
        if let id { discardDeviceEmailID(id) }
    }

    func showDeviceEmailCards() {
        deviceEmailMailboxMenus = [:]
        for setup in deviceEmailSetups {
            guard let account = setup["account"] as? String else { continue }
            let connected = setup["connected"] as? Bool == true
            let configured = setup["configured"] as? Bool ?? connected
            let source = accounts.first { $0["account"] as? String == account } ?? [:]
            let example = Self.isExample(source, fallback: serviceEnvironment)
            let panel = card((setup["label"] as? String ?? "PyPI") + " · Device confirmation email",
                connected ? "Email connection saved. Fresh matching PyPI device emails are handled locally during sign-in. Delivery is checked during an actual login."
                : "Use a mailbox you already connected and checked. Account Access can handle fresh PyPI device-confirmation emails without asking you to copy a link.",
                status: example ? "Example setup · delivery unverified"
                    : connected ? "Setup saved · delivery unverified" : configured ? "Email connection needs attention" : "One-time setup", good: false)
            if example {
                panel.addArrangedSubview(NSTextField(wrappingLabelWithString: "Example email setup. This does not verify delivery to a personal mailbox."))
            }
            if configured {
                let disconnect = NSButton(title: "Disconnect device email", target: self, action: #selector(disconnectDeviceEmail))
                disconnect.identifier = NSUserInterfaceItemIdentifier(account)
                panel.addArrangedSubview(disconnect)
                if connected { continue }
            }
            let candidates = setup["mailboxes"] as? [[String: Any]] ?? []
            if candidates.isEmpty {
                panel.addArrangedSubview(makeLabel("Connect and check an email mailbox first. A checked Google connection or TLS IMAP mailbox can be used without entering its password again.", 14, .secondaryLabelColor))
                panel.addArrangedSubview(NSButton(title: "Connect a mailbox", target: self, action: #selector(showEmailSetup)))
                continue
            }
            let menu = NSPopUpButton()
            menu.setAccessibilityLabel("Connected mailbox for " + (setup["label"] as? String ?? "PyPI") + " device emails")
            for mailbox in candidates {
                guard let id = mailbox["id"] as? String else { continue }
                menu.addItem(withTitle: (mailbox["label"] as? String ?? "Email") + " · " + (mailbox["recipient"] as? String ?? ""))
                menu.lastItem?.representedObject = id
            }
            deviceEmailMailboxMenus[account] = menu
            panel.addArrangedSubview(menu)
            let review = NSButton(title: "Review email connection", target: self, action: #selector(previewDeviceEmail))
            review.identifier = NSUserInterfaceItemIdentifier(account)
            panel.addArrangedSubview(review)
        }
    }

    @objc func previewDeviceEmail(_ sender: NSButton) {
        guard !busy, let account = sender.identifier?.rawValue,
              let setup = deviceEmailSetups.first(where: { $0["account"] as? String == account }),
              let fingerprint = setup["fingerprint"] as? String,
              let mailbox = deviceEmailMailboxMenus[account]?.selectedItem?.representedObject as? String else { return }
        busy = true
        page("Review your email connection", "Checking the selected account and saved mailbox. No website sign-in or email read is started.")
        progress()
        let generation = deviceEmailGeneration
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let review = try self.request("owner/device-email/preview", body: ["account": account, "fingerprint": fingerprint, "mailbox": mailbox])
                DispatchQueue.main.async {
                    self.busy = false
                    guard generation == self.deviceEmailGeneration else {
                        if let id = review["id"] as? String { self.discardDeviceEmailID(id) }
                        return
                    }
                    self.presentDeviceEmailReview(review, expectedAccount: account)
                }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    func presentDeviceEmailReview(_ review: [String: Any], expectedAccount: String) {
        guard let id = review["id"] as? String, id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
              review["account"] as? String == expectedAccount,
              let expires = review["expires"] as? Double, expires > Date().timeIntervalSince1970,
              let recipient = review["recipient"] as? String, let mailbox = review["mailbox_label"] as? String,
              let operations = review["operations"] as? [[String: Any]], operations.count <= 32 else {
            if let id = review["id"] as? String { discardDeviceEmailID(id) }
            fail(Failure.message("This email review is unavailable or expired. Choose the mailbox again in Verification."), retry: #selector(showFactors))
            return
        }
        deviceEmailReview = review
        page("Confirm device email", "Use " + mailbox + " · " + recipient + " for " + (review["label"] as? String ?? "PyPI") + ".", preservingDeviceEmailReview: true)
        card("Fresh matching sign-in emails", "Account Access reads only matching PyPI device-confirmation emails locally during a supported login. No password, code or link is sent to your AI. Your existing approved reads are retained.")
        for operation in operations {
            if let description = operation["description"] as? String { label("Approved read: " + description, 14) }
        }
        label("Saving this setup does not verify email delivery or sign in to PyPI.", 14, .secondaryLabelColor)
        primary("Confirm email connection", #selector(applyDeviceEmail))
        action("Cancel email connection", #selector(cancelDeviceEmail))
    }

    @objc func cancelDeviceEmail() { clearDeviceEmailReview(); showFactors() }

    @objc func applyDeviceEmail() {
        guard !busy, let review = deviceEmailReview, let id = review["id"] as? String else { return }
        guard let expires = review["expires"] as? Double, expires > Date().timeIntervalSince1970 else {
            clearDeviceEmailReview()
            fail(Failure.message("This email review expired. Choose the connected mailbox again in Verification."), retry: #selector(showFactors))
            return
        }
        // Consume the local button capability before dispatch; a lost response
        // is resolved by reading state, never by automatically repeating apply.
        deviceEmailReview = nil
        busy = true
        page("Connecting device email", "Saving your reviewed mailbox connection. Existing approved reads are retained.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/device-email/apply", body: ["id": id])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showFactors() }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    @objc func disconnectDeviceEmail(_ sender: NSButton) {
        guard !busy, let account = sender.identifier?.rawValue,
              let setup = deviceEmailSetups.first(where: { $0["account"] as? String == account }),
              let fingerprint = setup["fingerprint"] as? String else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/device-email/remove", body: ["account": account, "fingerprint": fingerprint])
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.showFactors() }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    @objc func showEmailSetup() {
        page("Connect your email", "Connect Google in your browser once, or use an application password when your provider supports it.")
        showGmailOAuthCards()
        if mailboxOAuth.isEmpty {
            label("Sign in with Google needs the publisher's registered Gmail connection. This preview does not include one. Gmail app passwords are available only for accounts where Google permits them.", 14, .secondaryLabelColor)
        }
        primary("Use an app password", #selector(showMailboxPasswordSetup))
        action("Back", #selector(showFactors))
    }

    static func mailboxOAuthRepairMessage(_ reason: String) -> String {
        switch reason {
        case "mailbox_scope_not_allowed":
            return "Google returned broader access than this connection permits. The publisher must check its Google application before you reconnect."
        case "refresh_outcome_uncertain":
            return "Google access renewal was interrupted. Reconnect once to restore automatic email-code access."
        case "connection_revoked", "provider_grant_revoked_or_expired":
            return "The saved Google permission is no longer usable. Reconnect once to restore automatic email-code access."
        case "mailbox_scope_missing":
            return "Reconnect Google with the mailbox read permission needed for your approved login messages."
        default:
            return "Renewable Google access is not saved. Reconnect once so approved email-code logins can continue after access expires."
        }
    }

    func showGmailOAuthCards() {
        for mailbox in mailboxOAuth {
            guard let account = mailbox["account"] as? String else { continue }
            let ready = mailbox["publisher_configured"] as? Bool == true
            let needsAttention = mailbox["connection_state"] as? String == "needs_attention"
                || (mailbox["connected"] as? Bool == true && mailbox["renewable_access_saved"] as? Bool != true)
            let connected = mailbox["connected"] as? Bool == true
                && mailbox["renewable_access_saved"] as? Bool == true && !needsAttention
            let recipients = (mailbox["sources"] as? [[String: Any]] ?? []).compactMap { $0["recipient"] as? String }
            let reusable = mailbox["reusable_mailbox"] as? [String: Any]
            let identityChecked = connected && mailbox["mailbox_identity_verified"] as? Bool == true && reusable != nil
            let addresses = reusable?["recipient"] as? String ?? Array(Set(recipients)).sorted().joined(separator: ", ")
            let panel = card(addresses.isEmpty ? "Gmail" : "Gmail · " + addresses,
                             "Connect in Google's own browser page. Google grants mailbox read access; Account Access uses matching login messages for your configured websites. Website permissions stay the same."
                             + (identityChecked ? " Your Google mailbox address is checked. Choose it for a supported website's email verification without an app password. Code delivery is checked during sign-in."
                                : connected ? " Google access is saved. Check its address to make this mailbox available for supported website verification; you do not need to enter an app password or reconnect Google." : "")
                             + (needsAttention ? " " + Self.mailboxOAuthRepairMessage(mailbox["reason"] as? String ?? "") : ""),
                             status: ready ? (identityChecked ? "Google mailbox checked" : connected ? "Google access saved · address unchecked" : needsAttention ? "Google connection needs attention" : "One-time Google connection") : "Publisher setup needed", good: ready && identityChecked)
            if mailbox["environment"] as? String == "controlled-demo" {
                let example = NSTextField(wrappingLabelWithString: "Controlled provider fixture. This is not a real Gmail connection.")
                panel.addArrangedSubview(example)
            }
            if ready {
                if connected {
                    let check = NSButton(title: "Check Google connection", target: self, action: #selector(checkGmailOAuth(_:)))
                    check.identifier = NSUserInterfaceItemIdentifier(account)
                    panel.addArrangedSubview(check)
                }
                let connect = NSButton(title: connected || needsAttention ? "Reconnect with Google" : "Connect with Google", target: self, action: #selector(connectGmailOAuth(_:)))
                connect.identifier = NSUserInterfaceItemIdentifier(account)
                panel.addArrangedSubview(connect)
            } else {
                panel.addArrangedSubview(NSTextField(wrappingLabelWithString: "The publisher must finish configuring its Google application before browser sign-in is available. Never enter your normal Google password here."))
            }
        }
    }

    @objc func checkGmailOAuth(_ sender: NSButton) {
        guard !busy, let account = sender.identifier?.rawValue,
              let configured = mailboxOAuth.first(where: { $0["account"] as? String == account }),
              let fingerprint = configured["fingerprint"] as? String else { return }
        busy = true
        page("Checking your Google mailbox", "Confirming the connected address. No messages are fetched and no website sign-in is started.")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let checked = try self.request("owner/mailbox/oauth/check", body: ["account": account, "fingerprint": fingerprint])
                guard checked["status"] as? String == "VERIFIED" else { throw Failure.message("The Google mailbox address could not be checked. Your saved connection is preserved. Try Check Google connection again.") }
                let state = try self.request("owner/state")
                DispatchQueue.main.async {
                    self.busy = false; self.accept(state); self.showFactors()
                    self.status.stringValue = "Google mailbox checked. Choose it for a supported website's email verification. Code delivery is checked during sign-in."
                }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    @objc func connectGmailOAuth(_ sender: NSButton) {
        guard let account = sender.identifier?.rawValue,
              let configured = mailboxOAuth.first(where: { $0["account"] as? String == account }),
              let fingerprint = configured["fingerprint"] as? String,
              configured["publisher_configured"] as? Bool == true else { return }
        busy = true
        mailboxOAuthCancelled = false
        mailboxOAuthFinishing = false
        mailboxOAuthAttempt = nil
        page("Connect Gmail in your browser", "Choose the approved Google account and review Google's mailbox read permission. Return here after consent. You do not need to copy a code or password.")
        progress()
        let cancel = action("Cancel Google connection", #selector(cancelGmailOAuth))
        cancel.isEnabled = true
        DispatchQueue.global(qos: .userInitiated).async {
            var listener: MailboxOAuthLoopback?
            do {
                let callback = try MailboxOAuthLoopback(account: account)
                listener = callback
                defer { callback.close() }
                DispatchQueue.main.sync {
                    self.activeMailboxOAuth = callback
                    if self.mailboxOAuthCancelled { callback.close() }
                }
                let started = try self.request("owner/mailbox/oauth/begin", body: ["account": account, "fingerprint": fingerprint, "redirect_uri": callback.redirectURI])
                guard let id = started["attempt"] as? String, let authorization = started["authorization_url"] as? String else {
                    throw Failure.message("Google connection could not start. Try again from Verification.")
                }
                DispatchQueue.main.sync { self.mailboxOAuthAttempt = ["account": account, "attempt": id] }
                let url = try callback.authorize(authorization)
                var opened = false
                var cancelled = false
                DispatchQueue.main.sync {
                    cancelled = self.mailboxOAuthCancelled
                    if !cancelled { opened = NSWorkspace.shared.open(url) }
                }
                if cancelled { throw MailboxOAuthFailure.cancelled }
                guard opened else { throw Failure.message("Open your default browser, then try connecting Gmail again.") }
                let received = try callback.wait()
                // The main queue orders the user's cancellation against the
                // transition to saving the accepted provider response. Once
                // saving starts the UI cannot claim that it was cancelled.
                DispatchQueue.main.sync {
                    cancelled = self.mailboxOAuthCancelled
                    if !cancelled {
                        self.mailboxOAuthFinishing = true
                        self.mailboxOAuthAttempt = nil
                        cancel.isEnabled = false
                        self.status.stringValue = "Saving your Google connection…"
                    }
                }
                if cancelled { throw MailboxOAuthFailure.cancelled }
                _ = try self.request("owner/mailbox/oauth/finish", body: ["account": account, "attempt": id, "callback": received])
                callback.close()
                let checked = try? self.request("owner/mailbox/oauth/check", body: ["account": account, "fingerprint": fingerprint])
                let addressChecked = checked?["status"] as? String == "VERIFIED"
                let state = try self.request("owner/state")
                DispatchQueue.main.async {
                    self.activeMailboxOAuth = nil; self.busy = false; self.accept(state); self.showFactors()
                    self.status.stringValue = addressChecked
                        ? "Google mailbox connected and checked. Choose it for a supported website's email verification. Code delivery is checked during sign-in."
                        : "Google access is saved. The address check could not finish; use Check Google connection to retry without entering a password or repeating consent."
                }
            } catch {
                listener?.close()
                var abandoned: [String: String]?
                DispatchQueue.main.sync {
                    abandoned = self.mailboxOAuthAttempt
                    self.mailboxOAuthAttempt = nil
                    self.activeMailboxOAuth = nil
                }
                if let abandoned { _ = try? self.request("owner/mailbox/oauth/cancel", body: abandoned) }
                if let failure = error as? MailboxOAuthFailure {
                    let message: String
                    switch failure {
                    case .cancelled: message = "Google connection cancelled. Your existing connections are preserved."
                    case .timedOut: message = "Google connection timed out. Try again from Verification when you are ready."
                    case .invalidAuthorization: message = "The configured Google connection could not be verified. The publisher must check its Gmail setup."
                    case .unavailable: message = "The local browser callback could not start. Try connecting Gmail again."
                    }
                    self.fail(Failure.message(message), retry: #selector(self.showFactors))
                } else { self.fail(error, retry: #selector(self.showFactors)) }
            }
        }
    }

    @objc func cancelGmailOAuth() {
        guard !mailboxOAuthFinishing else { return }
        mailboxOAuthCancelled = true
        activeMailboxOAuth?.close()
        if let attempt = mailboxOAuthAttempt {
            mailboxOAuthAttempt = nil
            DispatchQueue.global(qos: .userInitiated).async {
                _ = try? self.request("owner/mailbox/oauth/cancel", body: attempt)
            }
        }
    }

    @objc func showMailboxPasswordSetup() {
        section = "verification"
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
        label("For Gmail, create a Google app password for Account Access with 2-Step Verification enabled. If Google does not offer app passwords, use the configured Google browser connection in Verification.", 13, .secondaryLabelColor)
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
        guard !busy else { return }
        let data: [String: Any]
        let retryContext: MailboxRetryContext
        if let id = editingMailbox {
            data = ["id": id, "password": mailboxFields["password"]?.stringValue ?? ""]
            retryContext = .update(id: id)
        } else {
            let username = mailboxFields["username"]?.stringValue ?? ""
            let host = mailboxFields["host"]?.stringValue ?? ""
            let port = mailboxFields["port"]?.stringValue ?? ""
            data = ["label": mailboxKind.indexOfSelectedItem == 0 ? "Gmail" : "Email",
                    "host": host, "port": Int(port) ?? 0, "username": username,
                    "password": mailboxFields["password"]?.stringValue ?? ""]
            retryContext = .connect(provider: mailboxKind.indexOfSelectedItem, username: username, host: host, port: port)
        }
        let route = editingMailbox == nil ? "owner/mailbox/connect" : "owner/mailbox/password"
        for field in mailboxFields.values { field.stringValue = "" }
        mailboxRequest(route, data, retryContext: retryContext)
    }

    func mailboxRequest(_ route: String, _ body: [String: Any], retryContext: MailboxRetryContext? = nil) {
        guard !busy else { return }
        busy = true
        page("Checking your mailbox", "Checking encrypted email access without fetching messages or starting a website sign-in.")
        progress()
        let requestScreen = stack
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request(route, body: body)
                let state = try self.request("owner/state")
                DispatchQueue.main.async {
                    guard self.busy, self.stack === requestScreen else { return }
                    self.busy = false; self.accept(state); self.showFactors()
                }
            } catch {
                DispatchQueue.main.async {
                    guard self.busy, self.stack === requestScreen else { return }
                    self.busy = false
                    let explanation: String
                    if case Failure.message(let message) = error { explanation = message }
                    else { explanation = "The mailbox connection could not finish. Check your settings and enter the application password again." }
                    guard let retryContext else {
                        self.page("This step needs attention", explanation)
                        self.action("Review email connections", #selector(self.showFactors))
                        return
                    }
                    switch retryContext {
                    case let .connect(provider, username, host, port):
                        self.showMailboxPasswordSetup()
                        self.mailboxKind.selectItem(at: provider)
                        self.mailboxKindChanged()
                        self.mailboxFields["username"]?.stringValue = username
                        self.mailboxFields["host"]?.stringValue = host
                        self.mailboxFields["port"]?.stringValue = port
                    case let .update(id): self.showMailboxPasswordEdit(id)
                    }
                    self.mailboxFields["password"]?.stringValue = ""
                    self.label(explanation, 14, .systemRed)
                    self.window.makeFirstResponder(self.mailboxFields["password"])
                }
            }
        }
    }

    @objc func checkSavedMailbox(_ sender: NSButton) {
        guard let id = sender.identifier?.rawValue else { return }
        mailboxRequest("owner/mailbox/check", ["id": id])
    }

    @objc func editMailboxPassword(_ sender: NSButton) {
        guard let id = sender.identifier?.rawValue else { return }
        showMailboxPasswordEdit(id)
    }

    func showMailboxPasswordEdit(_ id: String) {
        section = "verification"
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
                let result = try self.systemOwnerConfigured ? ManagedAgentSetup.prepareBrowser()
                    : self.request("owner/google-messages/prepare", body: [:])
                guard let path = result["extension_path"] as? String,
                      path == (self.systemOwnerConfigured
                        ? "/Library/Application Support/Account Access/owner.app/Contents/Resources/GoogleMessagesExtension"
                        : self.root.appendingPathComponent("GoogleMessagesExtension").path) else {
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
                            : "The website did not accept its reviewed SMS request. No delivery was confirmed. Your saved sign-in details are preserved.")
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
        let sourceEnvironment = Self.verificationEnvironment(source, accounts: accounts, fallback: serviceEnvironment)
        if ["controlled-demo", "public-example"].contains(sourceEnvironment) {
            label("Example verification source. This does not verify real email, SMS or authenticator access.", 14, .secondaryLabelColor)
        } else if sourceEnvironment == "unclassified" {
            label("Verification source could not be linked to a verified service. This does not establish personal-account access.", 14, .secondaryLabelColor)
        }
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
        if kind == "gmail", let matching = source["mailbox_options"] as? [[String: Any]], !matching.isEmpty {
            label("Use a connected Gmail mailbox", 14)
            let menu = NSPopUpButton()
            menu.setAccessibilityLabel("Use a connected Gmail mailbox")
            for mailbox in matching {
                guard mailbox["kind"] as? String == "gmail", let id = mailbox["id"] as? String,
                      let recipient = mailbox["recipient"] as? String else { continue }
                menu.addItem(withTitle: (mailbox["label"] as? String ?? "Gmail") + " · " + recipient)
                menu.lastItem?.representedObject = id
                if id == source["linked_mailbox"] as? String
                    || (matching.count == 1 && source["enrolled"] as? Bool != true) { menu.select(menu.lastItem) }
            }
            menu.target = self
            menu.action = #selector(factorMailboxChanged)
            factorMailboxMenu = menu
            stack.addArrangedSubview(menu)
        }
        if email, let sender = source["sender"] as? String, let recipient = source["recipient"] as? String,
           let subject = source["subject"] as? String {
            label("Only login messages from " + sender + " to " + recipient + " with subject “" + subject + "”.", 14, .secondaryLabelColor)
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
            label("Use the website's setup key, or Google Authenticator → Transfer codes → Export codes. Unlock your phone and export your accounts. Select all QR images from that export together, then choose the matching account. Your phone keeps generating codes.", 14, .secondaryLabelColor)
            label("Importing copies the authenticator key to this Mac for unattended login. The key stays encrypted locally. A push, passkey or fingerprint approval still needs you.", 14, .secondaryLabelColor)
            action("Import authenticator QR images", #selector(readAuthenticatorQR))
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
            label("Choose a connected, checked Gmail mailbox to avoid signing in again. Only this website's configured login messages are used. If no mailbox is offered, connect and check the configured Google account above first.", 15, .secondaryLabelColor)
        }
        let connect = primary(source["enrolled"] as? Bool == true ? "Save changes" : "Connect verification", #selector(saveFactor))
        if kind == "gmail" {
            connect.isEnabled = factorMailboxMenu?.selectedItem?.representedObject as? String != nil
                && source["setup_context"] as? String != nil && source["setup_revision"] as? String != nil
        }
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
        picker.allowsMultipleSelection = true
        picker.message = "Select the website setup QR, or all images from one Google Authenticator export."
        guard picker.runModal() == .OK else { return }
        let urls = picker.urls
        var messages: [String] = []
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        var valid = !urls.isEmpty && urls.count <= 16 && detector != nil
        for url in urls where valid {
            guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize,
                  size <= 10_000_000, let image = CIImage(contentsOf: url),
                  image.extent.width > 0, image.extent.height > 0,
                  image.extent.width * image.extent.height <= 32_000_000 else { valid = false; break }
            let found = detector!.features(in: image).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
            if found.isEmpty { valid = false; break }
            messages.append(contentsOf: found)
        }
        guard valid, let texts = Self.authenticatorQRTexts(messages) else {
            let alert = NSAlert()
            alert.messageText = "Choose authenticator QR images"
            alert.informativeText = "Choose one website setup QR, or all QR images from one Google Authenticator export (up to 16). Every image must contain an authenticator QR. No account was changed."
            alert.runModal()
            return
        }
        if texts.count == 1, let text = texts.first, text.hasPrefix("otpauth://totp/") {
            factorFields["seed"]?.stringValue = text; return
        }
        guard let source = factorMenu.selectedItem?.representedObject as? [String: Any], let id = source["id"] as? String else { return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let preview = try self.request("owner/authenticator/preview", body: ["source": id, "uris": texts])
                DispatchQueue.main.async { self.busy = false; self.chooseAuthenticator(preview, source: source) }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    static func authenticatorQRText(_ messages: [String]) -> String? {
        guard messages.count == 1, let text = messages.first, text.utf8.count <= 32000,
              text.hasPrefix("otpauth://totp/") || text.hasPrefix("otpauth-migration://offline?") else { return nil }
        return text
    }

    static func authenticatorQRTexts(_ messages: [String]) -> [String]? {
        guard (1...16).contains(messages.count), messages.reduce(0, { $0 + $1.utf8.count }) <= 60000 else { return nil }
        if messages.count == 1 { return authenticatorQRText(messages).map { [$0] } }
        guard messages.allSatisfy({ $0.utf8.count <= 32000 && $0.hasPrefix("otpauth-migration://offline?") }) else { return nil }
        return messages
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
        alert.informativeText = "Connect only the selected key to " + linked + ". Check that the website and account match. Other keys in this export will be discarded."
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
        guard !busy, let source = factorMenu.selectedItem?.representedObject as? [String: Any], let id = source["id"] as? String else { return }
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
        if kind == "gmail" {
            guard let mailbox = factorMailboxMenu?.selectedItem?.representedObject as? String,
                  let context = source["setup_context"] as? String,
                  let revision = source["setup_revision"] as? String else {
                status.stringValue = "The email setup changed. Reopen Verification and choose the checked mailbox again."
                return
            }
            credential = ["mailbox": mailbox, "setup_context": context, "setup_revision": revision]
        } else if let mailbox = factorMailboxMenu?.selectedItem?.representedObject as? String {
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
                var result = try self.request("owner/phone/pair", body: ["source": id])
                let discovery = UUID()
                result["bluetooth_service_uuid"] = discovery.uuidString.lowercased()
                let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
                DispatchQueue.main.async {
                    self.busy = false
                    self.page("Pair your Android phone", "Scan this QR with the Account Access companion. Keep both devices on the same private Wi-Fi. Android 15 or newer also needs Bluetooth discovery and Android's device confirmation; keep this screen open while connecting.")
                    self.phonePairingPayload = String(data: data, encoding: .utf8)
                    let discoveryStatus = self.makeLabel("Preparing Bluetooth discovery…", 14, .secondaryLabelColor)
                    self.stack.addArrangedSubview(discoveryStatus)
                    self.phonePairingAdvertiser = PhonePairingAdvertiser(service: discovery) { [weak discoveryStatus] message in
                        discoveryStatus?.stringValue = message
                    }
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
                    paste.identifier = NSUserInterfaceItemIdentifier("copy-phone-pairing")
                    self.stack.addArrangedSubview(paste)
                    self.action("Back", #selector(self.backToConnections))
                }
            } catch { self.fail(error, retry: #selector(self.showFactors)) }
        }
    }

    @objc func copyPhonePairing(_ sender: NSButton) {
        guard let pairing = phonePairingPayload else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(pairing, forType: .string)
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
        let serviceAccounts = accounts.filter { Self.isLive($0, fallback: serviceEnvironment) }
        let examples = accounts.filter { Self.isExample($0, fallback: serviceEnvironment) }
        let unclassified = accounts.filter { Self.effectiveEnvironment($0, fallback: serviceEnvironment) == "unclassified" }
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
        if !detected.isEmpty { primary(agents.contains("claude") ? "Use Claude Code" : "Open Codex", #selector(openPreferredAgent)) }
        label(String(connected.count) + " ready · " + String(serviceAccounts.count) + " service connections", 14, .secondaryLabelColor)
        if !examples.isEmpty {
            label(String(examples.filter(Self.isReady).count) + " ready · " + String(examples.count) + " example connections", 14, .secondaryLabelColor)
        }
        if !unclassified.isEmpty {
            label(String(unclassified.count) + " connections · source unverified", 14, .secondaryLabelColor)
        }
        for account in accounts {
            let allowed = account["portable_ready"] as? Bool != false
            let active = account["connected"] as? Bool == true
            let pending = !(account["challenges"] as? [[String: Any]] ?? []).isEmpty
            let context = Self.effectiveEnvironment(account, fallback: serviceEnvironment)
            let example = Self.isExample(account, fallback: serviceEnvironment)
            let status = !allowed ? "Approval needed" : pending || !active ? "Sign-in needs attention"
                : example ? "Example connected" : context == "live" ? "Connected" : "Source unverified"
            let reads = (account[allowed ? "approved_operations" : "operations"] as? [[String: Any]] ?? []).compactMap { $0["description"] as? String }.joined(separator: "; ")
            let body = card(account["label"] as? String ?? "Account", (allowed ? "Approved reads: " : "Available reads: ") + reads,
                            status: status, good: allowed && active && !pending && context != "unclassified")
            if example {
                let note = NSTextField(wrappingLabelWithString: "Example connection. These results do not validate access to a personal account.")
                note.font = .systemFont(ofSize: 14)
                body.addArrangedSubview(note)
            } else if context == "unclassified" {
                let note = NSTextField(wrappingLabelWithString: "The service source could not be verified. This connection does not establish personal-account access.")
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
                    let inspect = NSButton(title: "Review sign-in help", target: self, action: #selector(inspectSavedSignIn))
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
            let open = NSButton(title: agent == "claude" ? "Use Claude Code" : "Open Codex", target: self, action: #selector(openAgent))
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
        case "destination": return "The website sent this sign-in outside its reviewed login flow. Your saved sign-in details are preserved."
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
        guard let agent = sender.identifier?.rawValue, ["claude", "codex"].contains(agent) else { return }
        useAgent(agent)
    }

    func useAgent(_ agent: String) {
        if agent == "claude" {
            page("Use Claude Code", "Open your usual Claude Code terminal or editor and start a new session. Once automatic setup is complete, the installed Account Access skill is available in new sessions.")
            card("Ask normally", "Describe your task in Claude Code. No Account Access command or slash command is needed. Your approved accounts and reads determine what it can do.")
            card("Already have a session open?", "Start a new session after setup so Claude Code loads the installed guidance. Opening Terminal alone does not start Claude Code.")
            action("Open Terminal", #selector(openTerminal))
            action("Back to my accounts", #selector(showReady))
            return
        }
        guard agent == "codex" else { return }
        guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.openai.codex") else {
            page("Open Codex", "Open your existing Codex installation, or install it before using this connection.")
            action("Back to my accounts", #selector(showReady))
            return
        }
        NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration())
    }

    @objc func openTerminal() {
        guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else {
            page("Open your terminal", "Open your usual terminal or editor to use your existing Claude Code installation.")
            action("Back to my accounts", #selector(showReady))
            return
        }
        NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration())
    }

    @objc func copyRequest() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(requestText, forType: .string)
    }

    @objc func openPreferredAgent() {
        if agents.contains("claude") { useAgent("claude") }
        else if agents.contains("codex") { useAgent("codex") }
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
        let appBundle: Bundle
        do { appBundle = try OwnerApplicationBundle.current() }
        catch {
            fputs("Account Access could not verify its protected app. Reinstall the signed package.\n", stderr)
            exit(78)
        }
        if CommandLine.arguments.count >= 2 && CommandLine.arguments[1] == "--browser-native-host" {
            exit(BrowserNativeHost.run(arguments: Array(CommandLine.arguments.dropFirst(2))))
        }
        if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--system-read-login-code" {
            SystemMessagesReader.run()
            return
        }
        if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--background-enable" {
            let payload = ["status": BackgroundRecovery.manage(bundle: appBundle)]
            let data = try! JSONSerialization.data(withJSONObject: payload)
            print(String(decoding: data, as: UTF8.self))
            return
        }
        if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--read-login-code" {
            guard !OwnerApplicationBundle.systemRequired
                && !DesktopOwnerProfile.isInstalled else {
                print("{\"status\":\"NEEDS_USER\",\"reason\":\"owner_authorization_required\"}")
                return
            }
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
