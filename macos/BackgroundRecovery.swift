import Foundation
import CryptoKit
import ServiceManagement
import Darwin

enum BackgroundRecovery {
    static let plistName = "com.fainir.accountaccess.background.plist"
    static let helperName = "AccountAccessBackground"
    enum Failure: Error { case invalidSetup, managementFailed }

    struct Layout {
        let bundle: URL
        let identifier: String
        let root: URL
        let runtime: URL
        let version: String
        var label: String { identifier + ".background" }
        var helper: URL { bundle.appendingPathComponent("Contents/MacOS/" + helperName) }
        var plist: URL { bundle.appendingPathComponent("Contents/Library/LaunchAgents/" + plistName) }

        init(bundle: Bundle) throws {
            guard let id = bundle.bundleIdentifier,
                  id == "com.fainir.accountaccess" || id.range(of: "^com\\.fainir\\.accountaccess\\.qa\\.[a-z0-9]+$", options: .regularExpression) != nil,
                  let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
                  (bundle.object(forInfoDictionaryKey: "AccountAccessBackgroundFormat") as? NSNumber)?.intValue == 1 else {
                throw Failure.invalidSetup
            }
            let files = FileManager.default
            let home = files.homeDirectoryForCurrentUser
            let canonical = home.appendingPathComponent(".local/share/account-access")
            let legacy = home.appendingPathComponent("Library/Application Support/AccountAccess")
            let fallback = !files.fileExists(atPath: canonical.appendingPathComponent("config.json").path)
                && files.fileExists(atPath: legacy.appendingPathComponent("config.json").path) ? legacy : canonical
            func path(_ key: String, _ fallback: URL) throws -> URL {
                guard let value = bundle.object(forInfoDictionaryKey: key) as? String else { return fallback }
                guard value.hasPrefix("/"), !value.contains("\0") else { throw Failure.invalidSetup }
                return URL(fileURLWithPath: value).standardizedFileURL
            }
            self.bundle = bundle.bundleURL
            self.identifier = id
            self.version = version
            self.root = try path("AccountAccessDataDirectory", fallback)
            self.runtime = try path("AccountAccessInstallDirectory", home.appendingPathComponent(".local/share/account-access/runtime"))
        }
    }

    static func directory(_ url: URL, privateOnly: Bool = true) throws {
        let info = try FileManager.default.attributesOfItem(atPath: url.path)
        guard info[.type] as? FileAttributeType == .typeDirectory,
              (info[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              let mode = (info[.posixPermissions] as? NSNumber)?.intValue,
              mode & (privateOnly ? 0o077 : 0o022) == 0 else { throw Failure.invalidSetup }
    }

    static func readPrivate(_ url: URL, limit: Int = 4096) throws -> Data {
        let info = try FileManager.default.attributesOfItem(atPath: url.path)
        guard info[.type] as? FileAttributeType == .typeRegular,
              (info[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              (info[.referenceCount] as? NSNumber)?.intValue == 1,
              (info[.posixPermissions] as? NSNumber)?.intValue == 0o600,
              let length = (info[.size] as? NSNumber)?.intValue, length <= limit else { throw Failure.invalidSetup }
        let data = try Data(contentsOf: url)
        guard data.count <= limit else { throw Failure.invalidSetup }
        return data
    }

    static func writePrivate(_ data: Data, to url: URL) throws {
        if FileManager.default.fileExists(atPath: url.path) {
            _ = try readPrivate(url)
        }
        var name = Array(url.deletingLastPathComponent().appendingPathComponent(".background-XXXXXX").path.utf8CString)
        let fd = mkstemp(&name)
        guard fd >= 0 else { throw Failure.invalidSetup }
        let temporary = String(cString: name)
        defer { unlink(temporary) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        guard rename(temporary, url.path) == 0 else { throw Failure.invalidSetup }
    }

    static func command(layout: Layout) throws -> [String]? {
        let files = FileManager.default
        try directory(layout.root)
        if (try? files.attributesOfItem(atPath: layout.root.appendingPathComponent("service.paused").path)) != nil {
            return nil
        }
        let registration = layout.root.appendingPathComponent("supervisor.json")
        if !files.fileExists(atPath: registration.path) { return nil }
        guard let info = try JSONSerialization.jsonObject(with: readPrivate(registration)) as? [String: String],
              Set(info.keys) == Set(["generation", "runtime", "version"]),
              let generation = info["generation"], generation.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              info["version"] == layout.version, let executable = info["runtime"], executable.hasPrefix("/") else {
            throw Failure.invalidSetup
        }
        let python = URL(fileURLWithPath: executable).standardizedFileURL
        let bin = python.deletingLastPathComponent()
        let environment = bin.deletingLastPathComponent()
        guard environment.deletingLastPathComponent() == layout.runtime.appendingPathComponent("environments"),
              bin.lastPathComponent == "bin",
              python.lastPathComponent.range(of: "^python(?:3(?:\\.[0-9]+)?)?$", options: .regularExpression) != nil,
              files.isExecutableFile(atPath: python.path) else { throw Failure.invalidSetup }
        try directory(layout.runtime)
        try directory(layout.runtime.appendingPathComponent("environments"))
        try directory(environment)
        try directory(bin, privateOnly: false)
        return [python.path, "-I", "-m", "account_access.cli", "--root", layout.root.path,
                "desktop-guardian", "--generation", generation]
    }

    static func kickstart(label: String) throws {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["kickstart", "gui/\(getuid())/" + label]
        task.standardInput = FileHandle.nullDevice
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        try task.run()
        let deadline = Date().addingTimeInterval(5)
        while task.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        if task.isRunning { task.terminate(); throw Failure.managementFailed }
        guard task.terminationStatus == 0 else { throw Failure.managementFailed }
    }

    protocol Control {
        var status: SMAppService.Status { get }
        func register() throws
        func unregister() throws
    }

    final class SystemControl: Control {
        let service = SMAppService.agent(plistName: BackgroundRecovery.plistName)
        var status: SMAppService.Status { service.status }
        func register() throws { try service.register() }
        func unregister() throws {
            let done = DispatchSemaphore(value: 0)
            var failure: Error?
            service.unregister { error in failure = error; done.signal() }
            guard done.wait(timeout: .now() + 10) == .success, failure == nil else { throw Failure.managementFailed }
        }
    }

    static func ensure(control: Control, revision: String, previous: String?,
                       kickstart: () throws -> Void, save: () throws -> Void) -> String {
        // A revoked/disabled item is an owner decision. Never unregister it or
        // use launchctl enable/bootstrap as a fallback for missing approval.
        if control.status == .requiresApproval { return "requires_approval" }
        do {
            if control.status == .enabled && previous != revision {
                try control.unregister()
            }
            if control.status == .notRegistered || control.status == .notFound {
                try control.register()
            }
            if control.status == .requiresApproval { return "requires_approval" }
            guard control.status == .enabled else { return "unavailable" }
            try kickstart()
            try save()
            return "enabled"
        } catch { return control.status == .requiresApproval ? "requires_approval" : "unavailable" }
    }

    static func manage(bundle: Bundle = .main) -> String {
        do {
            let layout = try Layout(bundle: bundle)
            try directory(layout.root)
            guard FileManager.default.isExecutableFile(atPath: layout.helper.path),
                  let data = try PropertyListSerialization.propertyList(from: Data(contentsOf: layout.plist), options: [], format: nil) as? [String: Any],
                  NSDictionary(dictionary: data).isEqual(to: [
                    "Label": layout.label, "BundleProgram": "Contents/MacOS/" + helperName,
                    "RunAtLoad": true, "KeepAlive": ["SuccessfulExit": false],
                    "ThrottleInterval": 10, "ProcessType": "Background"]) else { throw Failure.invalidSetup }
            let revision = SHA256.hash(data: try Data(contentsOf: layout.helper) + Data(contentsOf: layout.plist))
                .map { String(format: "%02x", $0) }.joined()
            let marker = layout.root.appendingPathComponent("background-registered.sha256")
            let previous = (try? readPrivate(marker)).flatMap { String(data: $0, encoding: .utf8) }
            return ensure(control: SystemControl(), revision: revision, previous: previous,
                          kickstart: { try kickstart(label: layout.label) },
                          save: { try writePrivate(Data(revision.utf8), to: marker) })
        } catch { return "unavailable" }
    }
}
