import AppKit
import CryptoKit
import Foundation
import Security
import UniformTypeIdentifiers
import CoreImage

final class FlippedView: NSView { override var isFlipped: Bool { true } }

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
final class AccountAccess: NSObject, NSApplicationDelegate {
    let files = FileManager.default
    let root = URL(fileURLWithPath: ProcessInfo.processInfo.environment["ACCOUNT_ACCESS_DATA_DIR"] ??
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/share/account-access").path)
    lazy var runtime = URL(fileURLWithPath: ProcessInfo.processInfo.environment["ACCOUNT_ACCESS_INSTALL_DIR"] ?? root.appendingPathComponent("runtime").path)
    var window: NSWindow!
    var stack: NSStackView!
    var status: NSTextField!
    var button: NSButton!
    var spinner: NSProgressIndicator!
    var services: NSPopUpButton!
    var username: NSTextField!
    var password: NSSecureTextField!
    var permission: NSButton!
    var catalog: [[String: Any]] = []
    var accounts: [[String: Any]] = []
    var agents = ["claude"]
    var sources: [[String: Any]] = []
    var importID = ""
    var importRows: [(String, NSButton, NSPopUpButton)] = []
    var importFile: URL?
    var deleteExport: NSButton!
    var factorMenu: NSPopUpButton!
    var factorFields: [String: NSTextField] = [:]
    var base: URL!
    var token = ""
    var busy = false
    var failedAccount: String?
    let localRequests = LocalRequests()
    let prompt = "/account-access Find the cheapest product in my personal and work shopping accounts, and read my membership welcome message. Refresh the data and save one task. Keep the answer short. Use my three example connections."
    var preferredAgent: String { agents.contains("claude") ? "Claude Code" : agents.contains("codex") ? "Codex" : "your AI tool" }
    var requestText: String {
        let connected = Set(accounts.filter { $0["connected"] as? Bool == true }.compactMap { $0["account"] as? String })
        let text = connected == Set(["personal-store", "work-store", "member-portal"])
            ? prompt : "/account-access Read one permitted operation from each connected account. Give me a short summary of each and save progress as a task."
        return agents.contains("claude") ? text : text.replacingOccurrences(of: "/account-access", with: "$account-access")
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
        appMenu.addItem(withTitle: "Quit Account Access", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.submenu = appMenu
        menu.addItem(item)
        NSApp.mainMenu = menu
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 880, height: 660),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Account Access"
        window.isReleasedWhenClosed = false
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if files.fileExists(atPath: root.appendingPathComponent("desktop.json").path),
           files.isExecutableFile(atPath: runtime.appendingPathComponent("bin/account-access").path) {
            reopen()
        } else { welcome() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
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
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        window.contentView = scroll
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
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 50),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -50),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 38),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -38),
            view.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            view.heightAnchor.constraint(greaterThanOrEqualTo: scroll.contentView.heightAnchor)
        ])
        label("ACCOUNT ACCESS", 13, .secondaryLabelColor)
        label(title, 31, .labelColor, .bold)
        label(subtitle, 17, .secondaryLabelColor)
    }

    @discardableResult func label(_ text: String, _ size: CGFloat = 16,
                                 _ color: NSColor = .labelColor,
                                 _ weight: NSFont.Weight = .regular) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: text)
        field.font = .systemFont(ofSize: size, weight: weight)
        field.textColor = color
        field.isSelectable = false
        stack.addArrangedSubview(field)
        field.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        return field
    }

    @discardableResult func action(_ title: String, _ selector: Selector) -> NSButton {
        let control = NSButton(title: title, target: self, action: selector)
        control.bezelStyle = .rounded
        control.controlSize = .large
        control.font = .systemFont(ofSize: 17, weight: .medium)
        stack.addArrangedSubview(control)
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
        page("Let your AI handle the sign-in", "Install once, connect your accounts, and give your AI a request.")
        label("1   Install the local app\n\n2   Import or connect your accounts\n\n3   Ask your existing AI tool", 19)
        label("Saved credentials stay in your encrypted local vault. Your AI receives the permitted results.", 16, .secondaryLabelColor)
        button = action("Install Account Access", #selector(install))
        label("macOS · Installs in your user folder · No administrator password needed", 13, .secondaryLabelColor)
    }

    @objc func install() {
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
                _ = try self.request("owner/install", body: [:])
                let state = try self.request("owner/state")
                DispatchQueue.main.async {
                    self.busy = false
                    self.accept(state)
                    self.connections()
                }
            } catch { self.fail(error, retry: #selector(self.install)) }
        }
    }

    @objc func reopen() {
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
                _ = try self.request("owner/install", body: [:])
                let state = try self.request("owner/state")
                DispatchQueue.main.async {
                    self.busy = false
                    self.accept(state)
                    self.connections()
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

    func loadOwner() throws {
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
                guard let response = response as? HTTPURLResponse, response.statusCode == 200,
                      let data = data,
                      let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw Failure.message("The local app could not complete this step. Your existing connections are preserved.")
                }
                result = .success(payload)
            } catch { result = .failure(error) }
        }.resume()
        guard done.wait(timeout: .now() + 35) == .success else {
            throw Failure.message("The local app took too long to respond. Try again.")
        }
        return try result.get()
    }

    func accept(_ state: [String: Any]) {
        catalog = state["catalog"] as? [[String: Any]] ?? []
        accounts = state["accounts"] as? [[String: Any]] ?? []
        sources = state["code_sources"] as? [[String: Any]] ?? []
        agents = state["principals"] as? [String] ?? []
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
        let connected = accounts.filter { $0["connected"] as? Bool == true }
        page("Connect your accounts once", "Your AI can perform only the reads you approve here.")
        label("Portable skill + CLI ready. Detected tools: " + agents.filter { $0 != "generic" }.joined(separator: ", "), 14, .secondaryLabelColor)
        action("Import saved passwords", #selector(importPasswords))
        action("Verification methods", #selector(showFactors))
        if !connected.isEmpty {
            label(connected.map { "✓  " + ($0["label"] as? String ?? "Account") }.joined(separator: "\n"), 17, .systemGreen)
        }
        let available = catalog.filter { entry in
            !connected.contains { $0["account"] as? String == entry["id"] as? String }
        }
        if available.isEmpty { ready(); return }
        services = NSPopUpButton()
        for entry in available {
            services.addItem(withTitle: entry["label"] as? String ?? "Account")
            services.lastItem?.representedObject = entry
        }
        services.target = self
        services.action = #selector(serviceChanged)
        services.font = .systemFont(ofSize: 17)
        stack.addArrangedSubview(services)
        username = NSTextField()
        username.placeholderString = "Email or username"
        username.font = .systemFont(ofSize: 18)
        username.heightAnchor.constraint(equalToConstant: 34).isActive = true
        stack.addArrangedSubview(username)
        username.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        password = NSSecureTextField()
        password.placeholderString = "Password"
        password.font = .systemFont(ofSize: 18)
        password.heightAnchor.constraint(equalToConstant: 34).isActive = true
        stack.addArrangedSubview(password)
        password.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        permission = NSButton(checkboxWithTitle: "", target: nil, action: nil)
        permission.font = .systemFont(ofSize: 16)
        stack.addArrangedSubview(permission)
        serviceChanged()
        button = action("Connect account", #selector(connect))
        if available.contains(where: { entry in accounts.contains { $0["account"] as? String == entry["id"] as? String } }) {
            action("Retry selected account’s saved sign-in", #selector(retrySaved))
        }
        if !connected.isEmpty { action("Start using my connected accounts", #selector(showReady)) }
        label("Included examples use public testing sites: SauceDemo and The Internet. Other websites require reviewed connectors.", 13, .secondaryLabelColor)
    }

    @objc func serviceChanged() {
        let entry = services.selectedItem?.representedObject as? [String: Any] ?? [:]
        let operations = entry["operations"] as? [[String: Any]] ?? []
        permission.title = "Allow: " + (operations.first?["description"] as? String ?? "the selected read")
        permission.state = .off
        username.stringValue = ""
        password.stringValue = ""
    }

    @objc func connect() {
        guard permission.state == .on, !username.stringValue.isEmpty, !password.stringValue.isEmpty,
              let entry = services.selectedItem?.representedObject as? [String: Any],
              let service = entry["id"] as? String else { return }
        let body: [String: Any] = ["service": service, "username": username.stringValue,
                                   "password": password.stringValue]
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
                    for agent in self.agents {
                        _ = try self.request("owner/grant", body: ["account": service, "principal": agent, "operations": names])
                    }
                    job = try self.request("owner/verify", body: ["account": service])
                } else {
                    job = try self.request("owner/add", body: body)
                }
                let state = try self.waitForConnection(job, account: service)
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.connections() }
            } catch { self.fail(error, retry: #selector(self.retryConnection)) }
        }
    }

    func waitForConnection(_ initial: [String: Any], account: String) throws -> [String: Any] {
        guard var id = initial["id"] as? String else { throw Failure.message("The connection could not start.") }
        let deadline = Date().addingTimeInterval(150)
        while Date() < deadline {
            let state = try request("owner/state")
            let jobs = state["connection_jobs"] as? [String: [String: Any]] ?? [:]
            if let result = jobs[id], let outcome = result["status"] as? String, outcome != "RUNNING" {
                if outcome == "CONNECTED" { return state }
                if outcome == "RETRYABLE" {
                    Thread.sleep(forTimeInterval: 3)
                    let retry = try request("owner/verify", body: ["account": account])
                    guard let next = retry["id"] as? String else { break }
                    id = next
                    DispatchQueue.main.async { self.status.stringValue = "The website is taking longer. Retrying safely…" }
                    continue
                }
                let reason = result["reason"] as? String ?? ""
                if reason == "mac_messages_permission_required" {
                    throw Failure.message("macOS has not allowed access to Messages. Enable iPhone text forwarding and grant the local Account Access runtime access in Privacy settings, then retry this saved sign-in.")
                }
                if reason.contains("authenticator") || reason.contains("mailbox") || reason.contains("code_not_received") || reason.contains("verification_source") {
                    throw Failure.message("This login needs its verification method connected. Open Verification methods to enroll the authenticator, reconnect email, or check phone access. Your imported password is already saved.")
                }
                throw Failure.message("This account needs a sign-in check. Your other connections are preserved. Reopen the app to review the selected account or try its saved sign-in again.")
            }
            Thread.sleep(forTimeInterval: 0.8)
        }
        throw Failure.message("The website took too long to connect. Your saved configuration is preserved.")
    }

    @objc func retrySaved() {
        failedAccount = (services.selectedItem?.representedObject as? [String: Any])?["id"] as? String
        retryConnection()
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

    @objc func showReady() { ready() }

    @objc func importPasswords() {
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
            importRows.append((id, check, select))
        }
        label("Unsupported logins: " + String(preview["unsupported"] as? Int ?? 0) + ". These will not be saved; importing cannot add a website connector.", 14, .secondaryLabelColor)
        deleteExport = NSButton(checkboxWithTitle: "Move the plaintext export file to Trash after importing", target: nil, action: nil)
        stack.addArrangedSubview(deleteExport)
        action("Import selected accounts", #selector(applyImport))
        action("Back", #selector(backToConnections))
    }

    @objc func applyImport() {
        let selections: [[String: Any]] = importRows.compactMap { id, check, menu in
            guard check.state == .on, let entry = menu.selectedItem?.representedObject as? [String: Any], let account = entry["id"] as? String else { return nil }
            let ops = (entry["operations"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
            return ["row": id, "account": account, "operations": ops]
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
                var state = try self.request("owner/state")
                for job in result["jobs"] as? [[String: Any]] ?? [] {
                    if let account = job["account"] as? String {
                        // Missing verification enrollment can be repaired in the next screen.
                        do { state = try self.waitForConnection(job, account: account) } catch { }
                    }
                }
                DispatchQueue.main.async { self.busy = false; self.importFile = nil; self.importRows = []; self.accept(state); self.connections() }
            } catch { self.fail(error, retry: #selector(self.importPasswords)) }
        }
    }

    @objc func backToConnections() { connections() }

    @objc func showFactors() {
        page("Set up verification once", "Account Access uses verification only for the approved login. Passwords and codes stay out of your AI chat.")
        if sources.isEmpty {
            label("Your configured accounts do not require a verification method. A reviewed connector must identify the login-code challenge before automatic code handling can be enabled.", 17)
            action("Back", #selector(backToConnections))
            return
        }
        factorMenu = NSPopUpButton()
        for source in sources {
            let label = (source["accounts"] as? [String] ?? []).joined(separator: ", ") + " · " + (source["kind"] as? String ?? "Verification")
            factorMenu.addItem(withTitle: label)
            factorMenu.lastItem?.representedObject = source
        }
        factorMenu.target = self
        factorMenu.action = #selector(factorChanged)
        stack.addArrangedSubview(factorMenu)
        factorChanged()
    }

    @objc func factorChanged() {
        // Rebuild below the picker to avoid keeping old secret fields around.
        while let last = stack.arrangedSubviews.last, last !== factorMenu {
            stack.removeArrangedSubview(last); last.removeFromSuperview()
        }
        factorFields = [:]
        let source = factorMenu.selectedItem?.representedObject as? [String: Any] ?? [:]
        let kind = source["kind"] as? String ?? ""
        let fields: [(String, String)] = kind == "totp" ? [("seed", "Authenticator setup key or otpauth link")] :
            kind == "imap" ? ((source["mailbox_account"] as? String) != nil ? [("username", "Mailbox email address")] : [("username", "Mailbox email address"), ("password", "Mailbox application password")]) :
            kind == "twilio" ? [("sid", "SMS gateway account ID"), ("auth_token", "SMS gateway token")] : []
        for (name, hint) in fields {
            label(hint, 15)
            let input: NSTextField = name == "username" ? NSTextField() : NSSecureTextField()
            input.placeholderString = hint
            input.font = .systemFont(ofSize: 17)
            input.heightAnchor.constraint(equalToConstant: 34).isActive = true
            stack.addArrangedSubview(input)
            input.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
            factorFields[name] = input
        }
        if kind == "totp" {
            label("Enroll a setup key you explicitly allow for login recovery. An authenticator push or fingerprint approval still needs you.", 14, .secondaryLabelColor)
            action("Read a setup QR image", #selector(readAuthenticatorQR))
        } else if kind == "imap" {
            label("Mail server: " + (source["mail_server"] as? String ?? "configured provider"), 14, .secondaryLabelColor)
            label("Uses encrypted IMAP access to the configured mailbox. Gmail may require an application password. Microsoft mail can use a configured OAuth connection.", 14, .secondaryLabelColor)
        } else if kind == "mac_messages" {
            label("Your iPhone must forward SMS to Messages on this Mac. Allow the Account Access runtime to access Messages when macOS requests it. Only fresh incoming messages from this account’s configured sender are checked.", 15, .secondaryLabelColor)
            action("Open Mac privacy settings", #selector(openMessagePrivacy))
        } else if kind == "phone_relay" {
            label("Pair the Android companion on the same private Wi-Fi. It forwards matching login notifications through a certificate-pinned encrypted connection.", 15, .secondaryLabelColor)
            action("Pair Android phone", #selector(pairPhone))
        } else if kind == "gmail" {
            label("Connect the configured Gmail account through its provider consent screen in Manage permissions. The resolver reads only matching current login messages, but Gmail consent grants mailbox read access.", 15, .secondaryLabelColor)
        }
        action("Enable this verification method", #selector(saveFactor))
        action("Back", #selector(backToConnections))
    }

    @objc func readAuthenticatorQR() {
        let picker = NSOpenPanel()
        picker.allowedContentTypes = [.png, .jpeg]
        guard picker.runModal() == .OK, let url = picker.url, let image = CIImage(contentsOf: url),
              let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]),
              let qr = detector.features(in: image).compactMap({ $0 as? CIQRCodeFeature }).first,
              let text = qr.messageString, text.hasPrefix("otpauth://totp/") else { return }
        factorFields["seed"]?.stringValue = text
    }

    @objc func openMessagePrivacy() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") { NSWorkspace.shared.open(url) }
    }

    @objc func saveFactor() {
        guard let source = factorMenu.selectedItem?.representedObject as? [String: Any], let id = source["id"] as? String else { return }
        let kind = source["kind"] as? String ?? ""
        var credential: [String: Any] = factorFields.mapValues { $0.stringValue }
        if kind == "mac_messages" { credential = ["enabled": true] }
        let linked = source["accounts"] as? [String] ?? []
        for field in factorFields.values { field.stringValue = "" }
        busy = true
        page("Saving your verification method", "The secret is encrypted locally. Checking your connected accounts…")
        progress()
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.request("owner/source", body: ["source": id, "credential": credential])
                for account in linked {
                    if let job = try? self.request("owner/verify", body: ["account": account]) {
                        _ = try? self.waitForConnection(job, account: account)
                    }
                }
                let state = try self.request("owner/state")
                DispatchQueue.main.async { self.busy = false; self.accept(state); self.connections() }
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
        page("Your connected accounts are ready", "Ask for the work. Account Access handles the approved sign-ins and reads.")
        let connected = accounts.filter { $0["connected"] as? Bool == true }
        label(connected.map { "✓  " + ($0["label"] as? String ?? "Account") }.joined(separator: "\n"), 18, .systemGreen)
        label("Try this in a fresh " + preferredAgent + " chat:", 17, .secondaryLabelColor)
        let text = label(requestText, 17)
        text.isSelectable = true
        action("Copy request", #selector(copyRequest))
        action("Open " + preferredAgent, #selector(openClaude))
        action("Import saved passwords", #selector(importPasswords))
        action("Verification methods", #selector(showFactors))
        action("Manage accounts and verification", #selector(backToConnections))
        label("The local service keeps running when you close this window. Reopen Account Access from your user Applications folder after a restart.", 14, .secondaryLabelColor)
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

let app = NSApplication.shared
let delegate = AccountAccess()
app.delegate = delegate
app.run()
