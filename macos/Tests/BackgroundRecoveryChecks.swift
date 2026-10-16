import Foundation
import ServiceManagement
import CryptoKit

final class BackgroundControlFixture: BackgroundRecovery.Control {
    var status: SMAppService.Status
    var registrationStatus = SMAppService.Status.enabled
    var calls: [String] = []
    var rejected = false
    init(_ status: SMAppService.Status) { self.status = status }
    func register() throws {
        calls.append("register")
        if rejected { throw BackgroundRecovery.Failure.managementFailed }
        status = registrationStatus
    }
    func unregister() throws { calls.append("unregister"); status = .notRegistered }
}

@main struct BackgroundRecoveryChecks {
    static func main() throws {
        let files = FileManager.default
        let temporary = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("account-access-background-" + UUID().uuidString)
        let app = temporary.appendingPathComponent("Fixture.app")
        let root = temporary.appendingPathComponent("data")
        let runtime = temporary.appendingPathComponent("runtime's folder")
        let environment = runtime.appendingPathComponent("environments/account-access-fixture")
        let bin = environment.appendingPathComponent("bin")
        for path in [temporary, app.appendingPathComponent("Contents"), root, runtime,
                     runtime.appendingPathComponent("environments"), environment, bin] {
            try files.createDirectory(at: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        defer { try? files.removeItem(at: temporary) }
        let info: [String: Any] = ["CFBundleIdentifier": "com.fainir.accountaccess.qa.fixture",
            "CFBundleShortVersionString": "0.8.0", "CFBundleExecutable": "Fixture",
            "AccountAccessBackgroundFormat": 1, "AccountAccessDataDirectory": root.path,
            "AccountAccessWheelSHA256": String(repeating: "b", count: 64),
            "AccountAccessInstallDirectory": runtime.path]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
            .write(to: app.appendingPathComponent("Contents/Info.plist"))
        let layout = try BackgroundRecovery.Layout(bundle: Bundle(url: app)!)
        let installed = runtime.appendingPathComponent("installed-wheel.json")
        let python = bin.appendingPathComponent("python")
        precondition(files.createFile(atPath: python.path, contents: Data("fixture".utf8), attributes: [.posixPermissions: 0o700]))
        let launcher = runtime.appendingPathComponent("bin/account-access")
        try files.createDirectory(at: launcher.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let launcherBytes = BackgroundRecovery.activatedLauncher(python: python)
        precondition(String(data: launcherBytes, encoding: .utf8)!.contains("runtime'\"'\"'s folder"))
        precondition(files.createFile(atPath: launcher.path, contents: launcherBytes, attributes: [.posixPermissions: 0o700]))
        let launcherHash = SHA256.hash(data: launcherBytes).map { String(format: "%02x", $0) }.joined()
        func saveInstalled(_ change: [String: Any] = [:]) throws {
            var data: [String: Any] = ["managed_by": "account-access-runtime-v1", "schema": 2,
                "wheel_sha256": String(repeating: "b", count: 64), "runtime": python.path,
                "launcher_sha256": launcherHash]
            data.merge(change) { _, new in new }
            try BackgroundRecovery.writePrivate(JSONSerialization.data(withJSONObject: data), to: installed)
        }
        try saveInstalled()
        let registration = root.appendingPathComponent("supervisor.json")
        let generation = String(repeating: "a", count: 64)
        func save(_ change: [String: String] = [:]) throws {
            var data = ["generation": generation, "version": "0.8.0", "runtime": python.path]
            data.merge(change) { _, new in new }
            try BackgroundRecovery.writePrivate(JSONSerialization.data(withJSONObject: data), to: registration)
        }
        try save()
        let command = try BackgroundRecovery.command(layout: layout)!
        precondition(command == [python.path, "-I", "-m", "account_access.cli", "--root", layout.root.path,
                                 "desktop-guardian", "--generation", generation])
        print("PASS: helper selects only the approved managed runtime and isolated guardian command")
        precondition(BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "b", count: 64)))
        precondition(!BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "c", count: 64)))
        let installedRecord = try BackgroundRecovery.readPrivate(installed)
        try saveInstalled(["wheel_sha256": String(repeating: "c", count: 64)])
        do { _ = try BackgroundRecovery.command(layout: layout); preconditionFailure("Stale same-version runtime was accepted") }
        catch { }
        try BackgroundRecovery.writePrivate(installedRecord, to: installed)
        try files.setAttributes([.posixPermissions: 0o644], ofItemAtPath: installed.path)
        precondition(!BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "b", count: 64)))
        try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: installed.path)
        print("PASS: same-version stale or unsafe runtime records cannot satisfy the signed app's payload pin")
        let alternateEnvironment = runtime.appendingPathComponent("environments/account-access-uncommitted")
        let alternateBin = alternateEnvironment.appendingPathComponent("bin")
        try files.createDirectory(at: alternateBin, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let alternatePython = alternateBin.appendingPathComponent("python")
        precondition(files.createFile(atPath: alternatePython.path, contents: Data("uncommitted fixture".utf8), attributes: [.posixPermissions: 0o700]))
        try save(["runtime": alternatePython.path])
        do { _ = try BackgroundRecovery.command(layout: layout); preconditionFailure("An uncommitted environment borrowed the active wheel pin") }
        catch { }
        try save()
        print("PASS: an uncommitted managed environment cannot borrow the activated runtime's payload record")
        try saveInstalled(["runtime": alternatePython.path])
        precondition(!BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "b", count: 64)))
        try saveInstalled()
        try launcherBytes.advanced(by: 1).write(to: launcher)
        try files.setAttributes([.posixPermissions: 0o700], ofItemAtPath: launcher.path)
        precondition(!BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "b", count: 64)))
        try launcherBytes.write(to: launcher)
        try files.setAttributes([.posixPermissions: 0o700], ofItemAtPath: launcher.path)
        try BackgroundRecovery.writePrivate(JSONSerialization.data(withJSONObject: [
            "managed_by": "account-access-runtime-v1", "schema": 1,
            "wheel_sha256": String(repeating: "b", count: 64)]), to: installed)
        precondition(!BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "b", count: 64)))
        try saveInstalled(["schema": 2.5])
        precondition(!BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "b", count: 64)))
        try saveInstalled()
        print("PASS: changed launcher bytes and legacy or invalid payload schemas require repair before reopening")
        let pause = root.appendingPathComponent("service.paused")
        try BackgroundRecovery.writePrivate(Data("paused".utf8), to: pause)
        let pausedCommand = try BackgroundRecovery.command(layout: layout)
        precondition(pausedCommand == nil)
        try files.removeItem(at: pause)
        for change in [["generation": "invalid"], ["version": "old"], ["runtime": "/usr/bin/python3"],
                       ["runtime": bin.path + "/../bin/python"], ["extra": "unrecognized"]] {
            try save(change)
            do { _ = try BackgroundRecovery.command(layout: layout); preconditionFailure("Invalid setup was accepted") }
            catch { }
        }
        try save()
        try files.setAttributes([.posixPermissions: 0o644], ofItemAtPath: registration.path)
        do { _ = try BackgroundRecovery.command(layout: layout); preconditionFailure("Public registration was accepted") }
        catch { }
        try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: registration.path)
        let outside = temporary.appendingPathComponent("outside")
        try files.moveItem(at: registration, to: outside)
        try files.createSymbolicLink(at: registration, withDestinationURL: outside)
        do { _ = try BackgroundRecovery.command(layout: layout); preconditionFailure("Linked registration was accepted") }
        catch { }
        precondition(files.fileExists(atPath: outside.path))
        print("PASS: pause, changed runtime/version, malformed and unsafe registration stop before runtime execution")

        func ensure(_ control: BackgroundControlFixture, previous: String? = "current",
                    failKickstart: Bool = false) -> (String, Int, Int) {
            var kicks = 0, saves = 0
            let status = BackgroundRecovery.ensure(control: control, revision: "current", previous: previous,
                kickstart: { kicks += 1; if failKickstart { throw BackgroundRecovery.Failure.managementFailed } },
                save: { saves += 1 })
            return (status, kicks, saves)
        }
        let denied = BackgroundControlFixture(.requiresApproval)
        let deniedResult = ensure(denied, previous: "old")
        precondition(deniedResult == ("requires_approval", 0, 0) && denied.calls.isEmpty)
        let newlyDenied = BackgroundControlFixture(.notRegistered)
        newlyDenied.registrationStatus = .requiresApproval
        let newResult = ensure(newlyDenied)
        precondition(newResult == ("requires_approval", 0, 0) && newlyDenied.calls == ["register"])
        print("PASS: disabled or newly approval-required items are never unregistered, kickstarted or force-enabled")
        let enabled = BackgroundControlFixture(.enabled)
        precondition(ensure(enabled) == ("enabled", 1, 1) && enabled.calls.isEmpty)
        let changed = BackgroundControlFixture(.enabled)
        precondition(ensure(changed, previous: "old") == ("enabled", 1, 1) && changed.calls == ["unregister", "register"])
        let first = BackgroundControlFixture(.notRegistered)
        precondition(ensure(first) == ("enabled", 1, 1) && first.calls == ["register"])
        print("PASS: first registration, ordinary resume and changed-helper re-registration follow their separate lifecycle paths")
        let failed = BackgroundControlFixture(.notRegistered)
        failed.rejected = true
        precondition(ensure(failed) == ("unavailable", 0, 0) && failed.calls == ["register"])
        let stopped = BackgroundControlFixture(.enabled)
        precondition(ensure(stopped, failKickstart: true) == ("unavailable", 1, 0) && stopped.calls.isEmpty)
        print("PASS: registration and launch failures remain unavailable without weaker installation or approval fallbacks")
    }
}
