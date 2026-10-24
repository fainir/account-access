// Ordinary exclusive temporary roots; no installed metadata or service access.
import Foundation
import Darwin

private enum RuntimeUpgradeNamespaceFailure: Error { case rejected(Int, Int32) }

enum RuntimeUpgradeNamespaceChecks {
    static func run() throws -> Int {
        guard getuid() != 0, getuid() == geteuid() else { throw RuntimeUpgradeNamespaceFailure.rejected(#line, errno) }
        var checks = 0
        func check(_ yes: Bool) throws { guard yes else { throw RuntimeUpgradeNamespaceFailure.rejected(#line, errno) }; checks += 1 }
        func refuses(_ body: () throws -> Void) throws {
            var refused = false; do { try body() } catch { refused = true }; try check(refused)
        }
        try refuses { _ = try FullImageNamespaceDirectory.installed(-1, kind: .runtimeUpgrade) }
        try refuses { _ = try FullImageInstalledRoutes.installed(kind: .runtimeUpgrade) }
        var template = Array("/private/tmp/account-access-runtime-namespace-XXXXXX".utf8CString)
        // mkdtemp returns the input buffer. Copy the name while Swift still
        // guarantees that buffer's lifetime, including under optimization.
        let path = try template.withUnsafeMutableBufferPointer { buffer -> String in
            guard let made = mkdtemp(buffer.baseAddress!) else { throw RuntimeUpgradeNamespaceFailure.rejected(#line, errno) }
            return String(cString: made)
        }
        let root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw RuntimeUpgradeNamespaceFailure.rejected(#line, errno) }
        defer { Darwin.close(root) }
        let rootPin = try InstallerPayloadIO.check(root, owner: getuid(), directory: true)
        func directory(_ parent: Int32, _ name: String) throws -> Int32 {
            guard mkdirat(parent, name, 0o755) == 0 else { throw RuntimeUpgradeNamespaceFailure.rejected(#line, errno) }
            let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0, fchmod(fd, 0o755) == 0, fchown(fd, uid_t.max, getgid()) == 0 else { throw RuntimeUpgradeNamespaceFailure.rejected(#line, errno) }
            return fd
        }
        let library = try directory(root, "Library"); defer { Darwin.close(library) }
        let support = try directory(library, "Application Support"); defer { Darwin.close(support) }
        try refuses { _ = try FullImageNamespaceDirectory.fixture(support, owner: getuid(), group: getgid(),
            create: false, kind: .runtimeUpgrade) }
        try check(try InstallerPayloadIO.contents(support).isEmpty)
        let old = try FullImageNamespaceDirectory.fixture(support, owner: getuid(), group: getgid())
        defer { Darwin.close(old) }
        let oldHead = try ComponentFiles.writeExclusive(old, "head.json", data: Data("old-head".utf8), owner: getuid(), mode: 0o644)
        let next = try FullImageNamespaceDirectory.fixture(support, owner: getuid(), group: getgid(), kind: .runtimeUpgrade)
        defer { Darwin.close(next) }
        let newHead = try ComponentFiles.writeExclusive(next, "head.json", data: Data("new-head".utf8), owner: getuid(), mode: 0o644)
        let legacyRoutes = try FullImageInstalledRoutes.fixture(root: root, owner: getuid())
        let runtimeRoutes = try FullImageInstalledRoutes.fixture(root: root, owner: getuid(), kind: .runtimeUpgrade)
        for (routes, expected) in [(legacyRoutes, oldHead), (runtimeRoutes, newHead)] {
            let (parent, name) = try routes.resolve(.head); defer { Darwin.close(parent) }
            try check(name == "head.json")
            try check(try ComponentFiles.observe(parent, name, owner: getuid()) == expected)
            try routes.verify()
        }
        try check(try legacyRoutes.namespace().identity.inode != runtimeRoutes.namespace().identity.inode)
        let reopened = try FullImageNamespaceDirectory.fixture(support, owner: getuid(), group: getgid(), create: false, kind: .runtimeUpgrade)
        defer { Darwin.close(reopened) }
        try check(try InstallerPayloadIO.check(reopened, owner: getuid(), directory: true).st_ino == runtimeRoutes.namespace().identity.inode)
        let bad = try directory(support, "bad-parent"); defer { Darwin.close(bad) }
        guard symlinkat("../" + PublicImageNamespace.fullImage.name, bad, PublicImageNamespace.runtimeUpgrade.name) == 0 else {
            throw RuntimeUpgradeNamespaceFailure.rejected(#line, errno)
        }
        try refuses { _ = try FullImageNamespaceDirectory.fixture(bad, owner: getuid(), group: getgid(), kind: .runtimeUpgrade) }
        try check(try ComponentFiles.observe(old, "head.json", owner: getuid()) == oldHead)
        try check(try ComponentFiles.observe(next, "head.json", owner: getuid()) == newHead)
        var current = stat()
        guard lstat(path, &current) == 0,
              PublicTreeDirectoryIdentity(rootPin) == PublicTreeDirectoryIdentity(current) else { throw RuntimeUpgradeNamespaceFailure.rejected(#line, errno) }
        // Only this invocation's known files, links and empty folders are removed.
        guard unlinkat(bad, PublicImageNamespace.runtimeUpgrade.name, 0) == 0,
              unlinkat(support, "bad-parent", AT_REMOVEDIR) == 0,
              unlinkat(old, "head.json", 0) == 0, unlinkat(next, "head.json", 0) == 0,
              unlinkat(support, PublicImageNamespace.fullImage.name, AT_REMOVEDIR) == 0,
              unlinkat(support, PublicImageNamespace.runtimeUpgrade.name, AT_REMOVEDIR) == 0,
              unlinkat(library, "Application Support", AT_REMOVEDIR) == 0,
              unlinkat(root, "Library", AT_REMOVEDIR) == 0, rmdir(path) == 0 else { throw RuntimeUpgradeNamespaceFailure.rejected(#line, errno) }
        return checks
    }
}
