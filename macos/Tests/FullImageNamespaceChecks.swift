// Namespace-only follow-up: exclusive invocation-owned temporary roots, no
// installed metadata, service, process, package or account operations.
import Foundation
import Darwin

private enum NamespaceFixtureFailure: Error { case failed }
@main struct FullImageNamespaceChecks {
    static var count = 0
    static func expect(_ value: Bool) throws { guard value else { throw NamespaceFixtureFailure.failed }; count += 1 }
    static func refuses(_ body: () throws -> Void) throws {
        var failed = false; do { try body() } catch { failed = true }; try expect(failed)
    }
    static func directory(_ parent: Int32, _ name: String) throws -> Int32 {
        guard mkdirat(parent, name, 0o700) == 0 else { throw NamespaceFixtureFailure.failed }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0, fchmod(fd, 0o700) == 0, fchown(fd, uid_t.max, getgid()) == 0 else { throw NamespaceFixtureFailure.failed }; return fd
    }
    static func info(_ fd: Int32) throws -> stat { try InstallerPayloadIO.check(fd, owner: getuid(), directory: true) }
    static func open(_ parent: Int32) throws -> Int32 { try FullImageNamespaceDirectory.fixture(parent, owner: getuid(), group: getgid()) }
    static func acl(_ fd: Int32) throws {
        var value: acl_t? = acl_init(1); guard value != nil else { throw NamespaceFixtureFailure.failed }
        defer { if let value { acl_free(UnsafeMutableRawPointer(value)) } }
        var entry: acl_entry_t?, permissions: acl_permset_t?, principal = UUID().uuid
        guard acl_create_entry(&value, &entry) == 0, let value, let entry,
              acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0,
              withUnsafeBytes(of: &principal, { acl_set_qualifier(entry, $0.baseAddress!) }) == 0,
              acl_get_permset(entry, &permissions) == 0, let permissions,
              acl_clear_perms(permissions) == 0, acl_add_perm(permissions, ACL_READ_DATA) == 0,
              acl_set_permset(entry, permissions) == 0, acl_valid(value) == 0,
              acl_set_fd(fd, value) == 0 else { throw NamespaceFixtureFailure.failed }
    }
    static func repairChecks(_ root: Int32, otherGroup: gid_t?) throws {
        let name = "Account Access Broker Repair"
        func openRepair(_ parent: Int32, create: Bool = true) throws -> Int32 {
            try FullImageNamespaceDirectory.fixtureBrokerRepair(parent, owner: getuid(), group: getgid(), create: create)
        }
        try refuses { _ = try FullImageNamespaceDirectory.installedBrokerRepair(-1) }
        try refuses { _ = try FullImageNamespaceDirectory.fixtureBrokerRepair(-1, owner: getuid() + 1, group: getgid()) }
        do {
            let parent = try directory(root, "repair-fresh"); defer { Darwin.close(parent) }
            try refuses { _ = try openRepair(parent, create: false) }
            try expect(try InstallerPayloadIO.contents(parent).isEmpty)
            let created = try openRepair(parent); defer { Darwin.close(created) }
            let before = try info(created), parentBefore = try info(parent)
            try expect(before.st_gid == getgid() && before.st_mode & 0o7777 == 0o700)
            try expect(try InstallerPayloadIO.contents(parent) == [name])
            let existing = try openRepair(parent, create: false); defer { Darwin.close(existing) }
            try expect(InstallerPayloadIO.same(before, try info(existing)) && InstallerPayloadIO.same(parentBefore, try info(parent)))
        }
        do {
            let parent = try directory(root, "repair-symlink"); defer { Darwin.close(parent) }
            let foreign = try directory(parent, "foreign"); defer { Darwin.close(foreign) }
            let before = try info(foreign)
            guard symlinkat("foreign", parent, name) == 0 else { throw NamespaceFixtureFailure.failed }
            try refuses { _ = try openRepair(parent) }
            try expect(InstallerPayloadIO.same(before, try info(foreign)))
        }
        do {
            let parent = try directory(root, "repair-acl"); defer { Darwin.close(parent) }
            let existing = try directory(parent, name); defer { Darwin.close(existing) }
            try acl(existing)
            var before = stat(), after = stat()
            guard fstat(existing, &before) == 0 else { throw NamespaceFixtureFailure.failed }
            try refuses { _ = try openRepair(parent) }
            guard fstat(existing, &after) == 0 else { throw NamespaceFixtureFailure.failed }
            try expect(InstallerPayloadIO.same(before, after) && before.st_gid == after.st_gid)
        }
        if let other = otherGroup {
            let parent = try directory(root, "repair-inherited-group"); defer { Darwin.close(parent) }
            guard fchown(parent, uid_t.max, other) == 0 else { throw NamespaceFixtureFailure.failed }
            let created = try openRepair(parent); defer { Darwin.close(created) }
            try expect(try info(created).st_gid == getgid())
            try expect(try info(parent).st_gid == other)
            let wrongParent = try directory(root, "repair-existing-wrong-group"); defer { Darwin.close(wrongParent) }
            let wrong = try directory(wrongParent, name); defer { Darwin.close(wrong) }
            guard fchown(wrong, uid_t.max, other) == 0 else { throw NamespaceFixtureFailure.failed }
            let before = try info(wrong), parentBefore = try info(wrongParent)
            try refuses { _ = try openRepair(wrongParent) }
            try expect(InstallerPayloadIO.same(before, try info(wrong)) && (try info(wrong)).st_gid == other)
            try expect(InstallerPayloadIO.same(parentBefore, try info(wrongParent)))
        }
    }
    static func main() {
        guard getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 1 else { exit(77) }
        umask(0o077)
        do {
            var raw = Array("/private/tmp/account-access-namespace-XXXXXX".utf8CString)
            let ownPath = try raw.withUnsafeMutableBufferPointer { value -> String in
                guard let result = mkdtemp(value.baseAddress!) else { throw NamespaceFixtureFailure.failed }; return String(cString: result)
            }
            let root = Darwin.open(ownPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0, fchmod(root, 0o700) == 0, fchown(root, uid_t.max, getgid()) == 0 else { throw NamespaceFixtureFailure.failed }
            defer { Darwin.close(root) }
            let rootPin = PublicTreeDirectoryIdentity(try info(root))
            let name = "Account Access Full Images"
            try refuses { _ = try FullImageNamespaceDirectory.installed(-1) }
            try refuses { _ = try FullImageNamespaceDirectory.fixture(-1, owner: getuid() + 1, group: getgid()) }
            do {
                let parent = try directory(root, "read-only"); defer { Darwin.close(parent) }
                try refuses { _ = try FullImageNamespaceDirectory.fixture(parent, owner: getuid(), group: getgid(), create: false) }
                try expect(try InstallerPayloadIO.contents(parent).isEmpty)
                let existing = try open(parent); defer { Darwin.close(existing) }
                let before = try info(existing), parentBefore = try info(parent)
                let observed = try FullImageNamespaceDirectory.fixture(parent, owner: getuid(), group: getgid(), create: false)
                defer { Darwin.close(observed) }
                try expect(InstallerPayloadIO.same(before, try info(observed))
                    && InstallerPayloadIO.same(parentBefore, try info(parent)))
            }
            do {
                let resources = try directory(root, "resources"); defer { Darwin.close(resources) }
                for name in ["FullImagePlan.json", "BaseManifest.json", "TargetManifest.json", "BaseIdentity.json",
                    "TargetIdentity.json", "ProviderManifest.json", "RuntimeCAReceipt.json", "Predecessor", "TargetImage",
                    "AccountAccess-fullimageupdate", "postinstall"] {
                    _ = try ComponentFiles.writeExclusive(resources, name, data: Data(), owner: getuid(), mode: 0o644)
                }
                try ComponentController.fixtureFullImageResourceSet(resources); count += 1
                _ = try ComponentFiles.writeExclusive(resources, "unreviewed-extra", data: Data(), owner: getuid(), mode: 0o644)
                try refuses { try ComponentController.fixtureFullImageResourceSet(resources) }
                guard unlinkat(resources, "unreviewed-extra", 0) == 0, unlinkat(resources, "postinstall", 0) == 0 else { throw NamespaceFixtureFailure.failed }
                try refuses { try ComponentController.fixtureFullImageResourceSet(resources) }
            }
            do {
                let parent = try directory(root, "fresh"); defer { Darwin.close(parent) }
                let created = try open(parent); defer { Darwin.close(created) }
                let before = try info(created)
                try expect(before.st_gid == getgid() && before.st_mode & 0o7777 == 0o700)
                try PublicTreeIO.noACL(created); count += 1
                var path = stat()
                try expect(fstatat(parent, name, &path, AT_SYMLINK_NOFOLLOW) == 0 && InstallerPayloadIO.same(before, path))
                let parentBefore = try info(parent)
                let existing = try open(parent); defer { Darwin.close(existing) }
                let after = try info(created)
                try expect(try info(existing).st_ino == before.st_ino)
                try expect(InstallerPayloadIO.same(before, after) && after.st_gid == before.st_gid)
                try expect(InstallerPayloadIO.same(parentBefore, try info(parent)))
            }
            do {
                let parent = try directory(root, "symlink"); defer { Darwin.close(parent) }
                let foreign = try directory(parent, "foreign"); defer { Darwin.close(foreign) }
                let before = try info(foreign)
                guard symlinkat("foreign", parent, name) == 0 else { throw NamespaceFixtureFailure.failed }
                try refuses { _ = try open(parent) }
                try expect(InstallerPayloadIO.same(before, try info(foreign)))
            }
            do {
                let parent = try directory(root, "acl"); defer { Darwin.close(parent) }
                let namespace = try directory(parent, name); defer { Darwin.close(namespace) }
                try acl(namespace)
                var before = stat(), after = stat()
                guard fstat(namespace, &before) == 0 else { throw NamespaceFixtureFailure.failed }
                try refuses { _ = try open(parent) }
                guard fstat(namespace, &after) == 0 else { throw NamespaceFixtureFailure.failed }
                try expect(InstallerPayloadIO.same(before, after) && before.st_gid == after.st_gid)
            }
            let groupCount = getgroups(0, nil)
            guard groupCount >= 0, groupCount <= 256 else { throw NamespaceFixtureFailure.failed }
            var groups = [gid_t](repeating: 0, count: Int(groupCount))
            guard getgroups(groupCount, &groups) == groupCount else { throw NamespaceFixtureFailure.failed }
            var supplemental = "UNAVAILABLE_NO_DISTINCT_GROUP"
            if let other = groups.first(where: { $0 != getgid() }) {
                let parent = try directory(root, "inherited-group"); defer { Darwin.close(parent) }
                guard fchown(parent, uid_t.max, other) == 0 else { throw NamespaceFixtureFailure.failed }
                guard mkdirat(parent, "inheritance-probe", 0o700) == 0 else { throw NamespaceFixtureFailure.failed }
                let probe = openat(parent, "inheritance-probe", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard probe >= 0 else { throw NamespaceFixtureFailure.failed }; defer { Darwin.close(probe) }
                let inherited = try info(probe).st_gid == other
                let created = try open(parent); defer { Darwin.close(created) }
                try expect(try info(created).st_gid == getgid())
                try expect(try info(parent).st_gid == other)
                let wrongParent = try directory(root, "existing-wrong-group"); defer { Darwin.close(wrongParent) }
                let wrong = try directory(wrongParent, name); defer { Darwin.close(wrong) }
                guard fchown(wrong, uid_t.max, other) == 0 else { throw NamespaceFixtureFailure.failed }
                let before = try info(wrong), parentBefore = try info(wrongParent)
                try refuses { _ = try open(wrongParent) }
                let after = try info(wrong)
                try expect(InstallerPayloadIO.same(before, after) && after.st_gid == other)
                try expect(InstallerPayloadIO.same(parentBefore, try info(wrongParent)))
                supplemental = inherited ? "PASSED_INHERITED_DIFFERENT_GROUP_CORRECTED_ONLY_ON_NEW_INODE" : "PASSED_DIFFERENT_GROUP_CHECKS_OS_DID_NOT_INHERIT"
                try expect(inherited) // This macOS qualification specifically proves inherited-GID correction.
            }
            try repairChecks(root, otherGroup: groups.first(where: { $0 != getgid() }))
            var final = stat()
            guard lstat(ownPath, &final) == 0, PublicTreeDirectoryIdentity(final) == rootPin else { throw NamespaceFixtureFailure.failed }
            try FileManager.default.removeItem(atPath: ownPath) // Exclusive invocation-owned tree only.
            print("{\"status\":\"PASSED\",\"checks\":\(count),\"supplemental_group_case\":\"\(supplemental)\",\"installed_reads\":false,\"root_execution\":false,\"service_actions\":false,\"production_ready\":false}")
        } catch { fputs("FULL_IMAGE_NAMESPACE_FIXTURE_FAILED\n", stderr); exit(1) }
    }
}
