import Foundation
import ServiceManagement

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
        let temporary = files.temporaryDirectory.appendingPathComponent("account-access-background-" + UUID().uuidString)
        let app = temporary.appendingPathComponent("Fixture.app")
        let root = temporary.appendingPathComponent("data")
        let runtime = temporary.appendingPathComponent("runtime")
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
        try BackgroundRecovery.writePrivate(JSONSerialization.data(withJSONObject: [
            "managed_by": "account-access-runtime-v1", "schema": 1,
            "wheel_sha256": String(repeating: "b", count: 64)]), to: installed)
        let python = bin.appendingPathComponent("python")
        precondition(files.createFile(atPath: python.path, contents: Data("fixture".utf8), attributes: [.posixPermissions: 0o700]))
        let registration = root.appendingPathComponent("supervisor.json")
        let generation = String(repeating: "a", count: 64)
        func save(_ change: [String: String] = [:]) throws {
            var data = ["generation": generation, "version": "0.8.0", "runtime": python.path]
            data.merge(change) { _, new in new }
            try BackgroundRecovery.writePrivate(JSONSerialization.data(withJSONObject: data), to: registration)
        }
        try save()
        let command = try BackgroundRecovery.command(layout: layout)!
        precondition(command == [python.path, "-I", "-m", "account_access.cli", "--root", root.path,
                                 "desktop-guardian", "--generation", generation])
        print("PASS: helper selects only the approved managed runtime and isolated guardian command")
        precondition(BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "b", count: 64)))
        precondition(!BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "c", count: 64)))
        let installedRecord = try BackgroundRecovery.readPrivate(installed)
        try BackgroundRecovery.writePrivate(JSONSerialization.data(withJSONObject: [
            "managed_by": "account-access-runtime-v1", "schema": 1,
            "wheel_sha256": String(repeating: "c", count: 64)]), to: installed)
        do { _ = try BackgroundRecovery.command(layout: layout); preconditionFailure("Stale same-version runtime was accepted") }
        catch { }
        try BackgroundRecovery.writePrivate(installedRecord, to: installed)
        try files.setAttributes([.posixPermissions: 0o644], ofItemAtPath: installed.path)
        precondition(!BackgroundRecovery.installationMatches(runtime: runtime, expected: String(repeating: "b", count: 64)))
        try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: installed.path)
        print("PASS: same-version stale or unsafe runtime records cannot satisfy the signed app's payload pin")
        let pause = root.appendingPathComponent("service.paused")
        try BackgroundRecovery.writePrivate(Data("paused".utf8), to: pause)
        let pausedCommand = try BackgroundRecovery.command(layout: layout)
        precondition(pausedCommand == nil)
        try files.removeItem(at: pause)
        for change in [["generation": "invalid"], ["version": "old"], ["runtime": "/usr/bin/python3"], ["extra": "unrecognized"]] {
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
