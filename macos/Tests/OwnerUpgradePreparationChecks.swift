// Ordinary owned-temporary-tree regression for the publication boundary.
// No installed reads, service actions, account data or executable payloads.
import Foundation
import Darwin

private enum OwnerPreparationFixtureFailure: Error { case failed(Int) }

enum OwnerUpgradePreparationChecks {
    private(set) static var checkpoint = "start"
    static func run() throws -> Int {
        guard getuid() != 0, getuid() == geteuid() else { throw OwnerPreparationFixtureFailure.failed(#line) }
        var count = 0
        func check(_ value: Bool, line: Int = #line) throws {
            guard value else { throw OwnerPreparationFixtureFailure.failed(line) }; count += 1
        }
        func refuses(_ body: () throws -> Void) throws {
            var rejected = false; do { try body() } catch { rejected = true }; try check(rejected)
        }
        var template = Array("/private/tmp/account-access-owner-preparation-XXXXXX".utf8CString)
        let path = try template.withUnsafeMutableBufferPointer { bytes -> String in
            guard let made = mkdtemp(bytes.baseAddress!) else { throw OwnerPreparationFixtureFailure.failed(#line) }
            return String(cString: made)
        }
        let root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0, fchown(root, uid_t.max, getgid()) == 0 else { throw OwnerPreparationFixtureFailure.failed(#line) }
        let rootPin = try PublicTreeDirectoryIdentity.observe(root, owner: getuid(), group: getgid())
        defer {
            Darwin.close(root)
            var current = stat()
            if lstat(path, &current) == 0 && PublicTreeDirectoryIdentity(current) == rootPin {
                try? FileManager.default.removeItem(atPath: path)
            }
        }
        func directory(_ parent: Int32, _ name: String, _ mode: mode_t) throws -> Int32 {
            guard mkdirat(parent, name, mode) == 0 else { throw OwnerPreparationFixtureFailure.failed(#line) }
            let child = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard child >= 0, fchmod(child, mode) == 0, fchown(child, uid_t.max, getgid()) == 0 else {
                throw OwnerPreparationFixtureFailure.failed(#line)
            }
            return child
        }
        func inventory(_ data: Data) throws -> PublicTreeInventory {
            let dir: [String: Any] = ["kind": "directory", "mode": 0o755]
            let rows: [String: [String: Any]] = ["": dir, "owner.app": dir, "owner.app/Contents": dir,
                "owner.app/Contents/MacOS": dir, "owner.app/Contents/MacOS/AccountAccess": ["kind": "file",
                    "mode": 0o644, "size": data.count, "sha256": FullImageJSON.hash(data)]]
            let value: [String: Any] = ["schema": 1, "managed_by": "account-access-install-payload-v1",
                "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
                "roots": [InstallerPayloadManifest.support: rows, InstallerPayloadManifest.application:
                    ["": ["kind": "symlink", "target": InstallerPayloadManifest.applicationTarget]]]]
            return try PublicTreeInventory(manifest: FullImageJSON.encode(value), unit: .runtimeOwner)
        }
        func tree(_ parent: Int32, _ name: String, _ data: Data) throws {
            let a = try directory(parent, name, 0o755); defer { Darwin.close(a) }
            let b = try directory(a, "Contents", 0o755); defer { Darwin.close(b) }
            let c = try directory(b, "MacOS", 0o755); defer { Darwin.close(c) }
            _ = try ComponentFiles.writeExclusive(c, "AccountAccess", data: data, owner: getuid(), mode: 0o644)
        }
        let target = try directory(root, "target", 0o755); defer { Darwin.close(target) }
        let preparing = try directory(root, "preparing", 0o700); defer { Darwin.close(preparing) }
        let retained = try directory(preparing, "retained", 0o700); defer { Darwin.close(retained) }
        let journal = try directory(preparing, "journal", 0o700); defer { Darwin.close(journal) }
        let oldData = Data("fictional-old-not-executed".utf8), newData = Data("fictional-new-not-executed".utf8)
        let old = try inventory(oldData), new = try inventory(newData), unit = PublicTreeUnit.runtimeOwner
        try tree(target, unit.name, oldData); try tree(retained, unit.slot, newData)
        let anchor = try PublicTreeTrustedAnchor.acceptVerifiedDescriptor(root, expected: rootPin)
        func attachment(_ fd: Int32, _ names: [String], _ role: PublicTreeParentRole) throws -> PublicTreeAttachment {
            var steps: [PublicTreeAncestorStep] = [], current = dup(root)
            guard current >= 0 else { throw OwnerPreparationFixtureFailure.failed(#line) }
            defer { Darwin.close(current) }
            for name in names {
                let child = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw OwnerPreparationFixtureFailure.failed(#line) }
                steps.append(PublicTreeAncestorStep(name: try PublicTreeAncestorName(name),
                    identity: try PublicTreeDirectoryIdentity.observe(child, owner: getuid(), group: getgid())))
                Darwin.close(current); current = child
            }
            return try PublicTreeAttachment.bind(anchor: anchor, steps: steps, role: role,
                parentFD: fd, owner: getuid(), group: getgid())
        }
        let targetRoute = try attachment(target, ["target"], .target(unit))
        checkpoint = "capture"
        let operation = try PublicTreeStorage.capture(unit: unit, targetParent: target, retainedParent: retained,
            targetAttachment: targetRoute, retainedAttachment: attachment(retained, ["preparing", "retained"], .retained(unit)),
            old: old, new: new, owner: getuid(), group: getgid(), planSHA256: String(repeating: "a", count: 64))
        func observed(_ prefix: String) throws -> PublicTreeStorage {
            try PublicTreeStorage.open(operation: operation, unit: unit, targetParent: target, retainedParent: retained,
                journalParent: journal, targetAttachment: targetRoute,
                retainedAttachment: attachment(retained, [prefix, "retained"], .retained(unit)),
                journalAttachment: attachment(journal, [prefix, "journal"], .journal(unit)), old: old, new: new,
                owner: getuid(), group: getgid(), requireQuiescent: { throw PublicTreeFailure.barrier }, createIfMissing: false)
        }
        // Reproduce the previous failure without allowing the observer to write.
        checkpoint = "empty_read_only"
        var exactFailure = false
        do { _ = try observed("preparing") } catch PublicTreeFailure.journal { exactFailure = true }
        try check(exactFailure)
        try check(try InstallerPayloadIO.contents(journal).isEmpty)
        checkpoint = "prepare_local_journal"
        try OwnerUpgradeLocalJournal.prepare(journal, operation: operation, owner: getuid(), group: getgid())
        let sealed = try ComponentFiles.read(journal, "intent.json", owner: getuid(), mode: 0o600)
        try check(try InstallerPayloadIO.contents(journal) == ["intent.json"])
        try refuses { try OwnerUpgradeLocalJournal.prepare(journal, operation: operation, owner: getuid(), group: getgid()) }
        try check(try ComponentFiles.read(journal, "intent.json", owner: getuid(), mode: 0o600).1 == sealed.1)
        let evidence: Data
        do {
            checkpoint = "prepared_read_only"
            let readOnly = try observed("preparing")
            try check(try readOnly.state() == .staged)
            try check(try readOnly.originalObservation() == operation.before)
            evidence = try readOnly.journalEvidence()
        }
        try check(try ComponentFiles.read(journal, "intent.json", owner: getuid(), mode: 0o600).1 == sealed.1)
        checkpoint = "publish"
        try check(renameat(root, "preparing", root, "transition") == 0)
        let published = try observed("transition")
        try check(try published.state() == .staged)
        try check(try published.originalObservation() == operation.before)
        try check(try published.journalEvidence() == evidence)
        checkpoint = "foreign_journal"
        _ = try ComponentFiles.writeExclusive(journal, "foreign.json", data: Data("foreign".utf8), owner: getuid(), mode: 0o600)
        try refuses { _ = try observed("transition") }
        try check(try ComponentFiles.read(journal, "intent.json", owner: getuid(), mode: 0o600).1 == sealed.1)
        try check(unlinkat(journal, "foreign.json", 0) == 0)
        try check(try observed("transition").state() == .staged)
        try check(try observed("transition").originalObservation() == operation.before)
        checkpoint = "invalid_preparation"
        let bad = try directory(root, "bad", 0o700); defer { Darwin.close(bad) }
        let foreignOperation = PublicTreeOperation(schema: 2, unit: PublicTreeUnit.owner.rawValue,
            planSHA256: operation.planSHA256, beforeManifestSHA256: operation.beforeManifestSHA256,
            afterManifestSHA256: operation.afterManifestSHA256, before: operation.before, after: operation.after)
        try refuses { try OwnerUpgradeLocalJournal.prepare(bad, operation: foreignOperation, owner: getuid(), group: getgid()) }
        try check(try InstallerPayloadIO.contents(bad).isEmpty)
        let badMode = try directory(root, "bad-mode", 0o755); defer { Darwin.close(badMode) }
        try refuses { try OwnerUpgradeLocalJournal.prepare(badMode, operation: operation, owner: getuid(), group: getgid()) }
        try check(try InstallerPayloadIO.contents(badMode).isEmpty)
        guard count == 21 else { throw OwnerPreparationFixtureFailure.failed(#line) }
        checkpoint = "complete"
        return count
    }
}
