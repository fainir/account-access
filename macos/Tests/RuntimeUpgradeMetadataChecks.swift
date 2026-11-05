// Metadata-only fixtures beneath an exclusively created ordinary-user folder.
// File bytes are fictional and never executed or treated as payload evidence.
import Foundation
import Darwin

private enum RuntimeUpgradeMetadataFailure: Error { case rejected(Int, Int32) }

enum RuntimeUpgradeMetadataChecks {
    static func run(source: RuntimeUpgradeSource) throws -> Int {
        guard getuid() != 0, getuid() == geteuid() else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
        var groups = [gid_t](repeating: 0, count: 256)
        let count = getgroups(Int32(groups.count), &groups)
        guard count > 0, let legacy = groups.prefix(Int(count)).first(where: { $0 != getgid() }) else {
            throw FullImageFailure.unavailable
        }
        let published = getgid(), unit = PublicTreeUnit.runtimeRoot
        let inventory = try PublicTreeInventory(validatedManifest: source.before, unit: unit)
        guard let tree = inventory.tree, tree.nodes.count < 1000,
              tree.nodes.values.allSatisfy({ ["file", "directory"].contains($0.kind) }) else { throw FullImageFailure.source }
        var template = Array("/private/tmp/account-access-runtime-groups-XXXXXX".utf8CString)
        let path = try template.withUnsafeMutableBufferPointer { buffer -> String in
            guard let made = mkdtemp(buffer.baseAddress!) else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
            return String(cString: made)
        }
        let root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0, fchmod(root, 0o755) == 0, fchown(root, uid_t.max, legacy) == 0 else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
        defer { Darwin.close(root) }
        let identity = PublicTreeDirectoryIdentity(try InstallerPayloadIO.check(root, owner: getuid(), directory: true))
        for (name, node) in tree.nodes.sorted(by: { $0.key.count < $1.key.count }) where !name.isEmpty {
            _ = try InstallerPayloadManifest.components(name)
            if node.kind == "directory" {
                guard mkdirat(root, name, 0o700) == 0 else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
            }
            let flags = node.kind == "directory" ? (O_RDONLY | O_DIRECTORY) : (O_WRONLY | O_CREAT | O_EXCL)
            let fd = openat(root, name, flags | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
            defer { Darwin.close(fd) }
            guard fchmod(fd, mode_t(node.mode!)) == 0,
                  fchown(fd, uid_t.max, unit.precedingGroup(name, legacy: legacy, published: published)) == 0 else {
                throw RuntimeUpgradeMetadataFailure.rejected(#line, errno)
            }
        }
        var checks = 0
        func check(_ yes: Bool) throws { guard yes else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }; checks += 1 }
        func inspect() throws {
            try PublicTreeIO.metadata(root, inventory: inventory, owner: getuid(), group: legacy, priorReleaseGroup: published)
        }
        func refuses(_ body: () throws -> Void) throws {
            var refused = false; do { try body() } catch { refused = true }; try check(refused)
        }
        try inspect(); try check(true)
        try refuses { try PublicTreeIO.metadata(root, inventory: inventory, owner: getuid(), group: legacy) }
        for (name, correct, wrong) in [("fixture", legacy, published),
            ("lib/python3.12/site-packages/account_access/agent_setup.py", published, legacy),
            ("lib/python3.12/encodings/__pycache__/aliases.cpython-312.pyc", published, legacy)] {
            let fd = openat(root, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }; defer { Darwin.close(fd) }
            guard fchown(fd, uid_t.max, wrong) == 0 else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
            try refuses { try inspect() }
            guard fchown(fd, uid_t.max, correct) == 0 else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
            try inspect(); try check(true)
        }
        try check(PublicTreeUnit.runtimeOwner.precedingGroup("", legacy: legacy, published: published) == published)
        try check(PublicTreeUnit.pythonRoot.precedingGroup("bin/pip", legacy: legacy, published: published) == published)
        try check(PublicTreeUnit.pythonRoot.precedingGroup("bin/other", legacy: legacy, published: published) == legacy)
        try check(PublicTreeUnit.wheels.precedingGroup("account_access-0.8.0-py3-none-any.whl", legacy: legacy, published: published) == published)
        try check(PublicTreeUnit.binRoot.precedingGroup("AccountAccess-broker", legacy: legacy, published: published) == legacy)
        try check(PublicTreeUnit.binRoot.precedingGroup("AccountAccess-installerverify", legacy: legacy, published: published) == legacy)
        var current = stat()
        guard lstat(path, &current) == 0, PublicTreeDirectoryIdentity(current) == identity else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
        for (name, node) in tree.nodes.sorted(by: { $0.key.count > $1.key.count }) where !name.isEmpty {
            guard unlinkat(root, name, node.kind == "directory" ? AT_REMOVEDIR : 0) == 0 else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
        }
        guard rmdir(path) == 0 else { throw RuntimeUpgradeMetadataFailure.rejected(#line, errno) }
        return checks
    }
}
