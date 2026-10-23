// Candidate fixed installed adapter helpers. No entrypoint; production callers
// are root-gated in the same-file ComponentController companion. Ordinary tests
// may only supply their invocation-owned temporary root through the gated seam.
import Foundation
import CryptoKit
import Darwin

enum FullImageNamespaceDirectory {
    private static let name = "Account Access Full Images"
    private static func open(_ parent: Int32, owner: uid_t, group: gid_t, create: Bool) throws -> Int32 {
        let ancestor = try InstallerPayloadIO.check(parent, owner: owner, directory: true)
        try PublicTreeIO.noACL(parent)
        let created: Bool
        if !create { created = false }
        else if mkdirat(parent, name, 0o700) == 0 { created = true }
        else { guard errno == EEXIST else { throw FullImageFailure.journal }; created = false }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw FullImageFailure.journal }
        var adopted = false; defer { if !adopted { Darwin.close(fd) } }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        try PublicTreeIO.noACL(fd)
        var path = stat()
        guard before.st_mode & 0o7777 == 0o700, before.st_nlink > 0,
              fstatat(parent, name, &path, AT_SYMLINK_NOFOLLOW) == 0, path.st_gid == before.st_gid,
              InstallerPayloadIO.same(before, path) else { throw FullImageFailure.journal }
        if created {
            // Only this successful exclusive mkdir authorizes normalization.
            // Existing wrong-group roots are rejected below without a write.
            guard fchown(fd, owner, group) == 0, fchmod(fd, 0o700) == 0,
                  fsync(fd) == 0, fsync(parent) == 0 else { throw FullImageFailure.journal }
        }
        let after = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        try PublicTreeIO.noACL(fd); try PublicTreeIO.noACL(parent)
        let parentAfter = try InstallerPayloadIO.check(parent, owner: owner, directory: true)
        guard after.st_gid == group, after.st_mode & 0o7777 == 0o700,
              after.st_dev == before.st_dev, after.st_ino == before.st_ino, after.st_nlink > 0,
              PublicTreeDirectoryIdentity(ancestor) == PublicTreeDirectoryIdentity(parentAfter),
              fstatat(parent, name, &path, AT_SYMLINK_NOFOLLOW) == 0, path.st_gid == group,
              InstallerPayloadIO.same(after, path) else { throw FullImageFailure.journal }
        adopted = true; return fd
    }
    static func installed(_ parent: Int32, create: Bool = true) throws -> Int32 {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        return try open(parent, owner: 0, group: 0, create: create)
    }
#if ACCOUNT_ACCESS_FULL_IMAGE_INSTALLED_CHECKS
    static func fixture(_ parent: Int32, owner: uid_t, group: gid_t, create: Bool = true) throws -> Int32 {
        guard getuid() != 0, geteuid() == getuid(), owner == getuid(), group == getgid() else { throw ComponentUpdateFailure.context }
        return try open(parent, owner: owner, group: group, create: create)
    }
#endif
}

final class FullImageFDCanonicalPath {
    private let fd: Int32, owner: uid_t
    private let canonical: String, identity: PublicTreeDirectoryIdentity
    private let qualify: (String) throws -> Void
    private static func path(_ fd: Int32) throws -> String {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(fd, F_GETPATH, &buffer) == 0 else { throw FullImageFailure.source }
        let value = String(cString: buffer)
        guard value.hasPrefix("/"), !value.utf8.contains(0) else { throw FullImageFailure.source }
        _ = try InstallerPayloadManifest.components(String(value.dropFirst())); return value
    }
    private init(_ supplied: Int32, owner: uid_t, qualify: @escaping (String) throws -> Void) throws {
        let fd = fcntl(supplied, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw FullImageFailure.source }
        var adopted = false; defer { if !adopted { Darwin.close(fd) } }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        let path = try Self.path(fd)
        try qualify(path)
        let reopened = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard reopened >= 0 else { throw FullImageFailure.source }; defer { Darwin.close(reopened) }
        let current = try InstallerPayloadIO.check(reopened, owner: owner, directory: true)
        guard InstallerPayloadIO.same(before, current), try Self.path(fd) == path else { throw FullImageFailure.source }
        self.fd = fd; self.owner = owner; canonical = path; identity = PublicTreeDirectoryIdentity(before); self.qualify = qualify
        adopted = true
    }
    deinit { Darwin.close(fd) }
    static func installed(_ fd: Int32) throws -> FullImageFDCanonicalPath {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        return try FullImageFDCanonicalPath(fd, owner: 0, qualify: { path in
            // Reuse the existing exact Installer /private/tmp sticky-parent
            // exception; all package children still require protected root FDs.
            let canonical = try InstallerPayloadIO.directory(path, owner: 0, installerResources: true)
            Darwin.close(canonical)
        })
    }
    private func verify() throws {
        guard try Self.path(fd) == canonical else { throw FullImageFailure.source }
        try qualify(canonical)
        let current = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else { throw FullImageFailure.source }; defer { Darwin.close(current) }
        let held = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        let path = try InstallerPayloadIO.check(current, owner: owner, directory: true)
        guard PublicTreeDirectoryIdentity(held) == identity, InstallerPayloadIO.same(held, path),
              try Self.path(fd) == canonical else { throw FullImageFailure.source }
    }
    func checked(_ body: (String) throws -> Void) throws {
        try verify(); try body(canonical); try verify()
    }
#if ACCOUNT_ACCESS_FULL_IMAGE_INSTALLED_CHECKS
    static func fixture(_ fd: Int32, owner: uid_t) throws -> FullImageFDCanonicalPath {
        guard getuid() != 0, owner == getuid(), geteuid() == owner else { throw ComponentUpdateFailure.context }
        return try FullImageFDCanonicalPath(fd, owner: owner, qualify: { path in
            guard path.hasPrefix("/private/tmp/account-access-installed-adapter-") else { throw FullImageFailure.source }
            var info = stat()
            guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == owner,
                  info.st_mode & 0o022 == 0 else { throw FullImageFailure.source }
        })
    }
#endif
}

final class FullImageAttachedDirectory {
    let fd: Int32
    let identity: PublicTreeDirectoryIdentity
    private let anchor: PublicTreeTrustedAnchor
    private let steps: [PublicTreeAncestorStep]
    private let owner: uid_t, group: gid_t
    init(root: Int32, anchor: PublicTreeTrustedAnchor, absolute: String, owner: uid_t) throws {
        guard absolute.hasPrefix("/") else { throw FullImageFailure.object }
        let parts = try InstallerPayloadManifest.components(String(absolute.dropFirst()))
        guard !parts.isEmpty else { throw FullImageFailure.object }
        var current = fcntl(root, F_DUPFD_CLOEXEC, 0), route: [PublicTreeAncestorStep] = []
        guard current >= 0 else { throw FullImageFailure.object }
        var adopted = false
        defer { if !adopted { Darwin.close(current) } }
        for part in parts {
            var path = stat()
            guard fstatat(current, part, &path, AT_SYMLINK_NOFOLLOW) == 0 else { throw FullImageFailure.object }
            let child = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard child >= 0 else { throw FullImageFailure.object }
            do {
                let info = try InstallerPayloadIO.check(child, owner: owner, directory: true)
                let pin = try PublicTreeDirectoryIdentity.observe(child, owner: owner, group: info.st_gid)
                guard InstallerPayloadIO.same(path, info), [mode_t(0o755), 0o700].contains(pin.mode) else { throw FullImageFailure.object }
                route.append(PublicTreeAncestorStep(name: try PublicTreeAncestorName(part), identity: pin))
            } catch { Darwin.close(child); throw error }
            Darwin.close(current); current = child
        }
        let leaf = route.last!.identity
        let role: PublicTreeParentRole = leaf.mode == 0o755 ? .target(.owner) : .journal(.owner)
        _ = try PublicTreeAttachment.bind(anchor: anchor, steps: route, role: role,
            parentFD: current, owner: owner, group: leaf.group)
        self.fd = current; identity = leaf; self.anchor = anchor; steps = route
        self.owner = owner; group = leaf.group
        adopted = true
    }
    deinit { Darwin.close(fd) }
    func attachment(_ role: PublicTreeParentRole) throws -> PublicTreeAttachment {
        try PublicTreeAttachment.bind(anchor: anchor, steps: steps, role: role, parentFD: fd, owner: owner, group: group)
    }
    func verify(_ candidate: Int32) throws {
        let role: PublicTreeParentRole = identity.mode == 0o755 ? .target(.owner) : .journal(.owner)
        try attachment(role).verify(candidate, role: role, owner: owner, group: group, mode: identity.mode)
    }
    func duplicate() throws -> Int32 {
        try verify(fd)
        let result = fcntl(fd, F_DUPFD_CLOEXEC, 0)
        guard result >= 0 else { throw FullImageFailure.object }; return result
    }
}

// This object never accepts destination strings from a manifest/journal. Every
// production route is selected below from the closed native unit enums.
final class FullImageInstalledRoutes {
    private let root: Int32, anchor: PublicTreeTrustedAnchor
    private let owner: uid_t
    private var held: [String: FullImageAttachedDirectory] = [:]
    private init(root supplied: Int32, owner: uid_t) throws {
        let copy = fcntl(supplied, F_DUPFD_CLOEXEC, 0)
        guard copy >= 0 else { throw FullImageFailure.object }
        var adopted = false; defer { if !adopted { Darwin.close(copy) } }
        let info = try InstallerPayloadIO.check(copy, owner: owner, directory: true)
        let identity = try PublicTreeDirectoryIdentity.observe(copy, owner: owner, group: info.st_gid)
        guard identity.mode == 0o755 || identity.mode == 0o700 else { throw FullImageFailure.object }
        root = copy; self.owner = owner
        anchor = try PublicTreeTrustedAnchor.acceptVerifiedDescriptor(copy, expected: identity)
        adopted = true
    }
    deinit { Darwin.close(root) }
    static func installed() throws -> FullImageInstalledRoutes {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        let fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw FullImageFailure.object }; defer { Darwin.close(fd) }
        return try FullImageInstalledRoutes(root: fd, owner: 0)
    }
    private func directory(_ path: String) throws -> FullImageAttachedDirectory {
        if let existing = held[path] { try existing.verify(existing.fd); return existing }
        let value = try FullImageAttachedDirectory(root: root, anchor: anchor, absolute: path, owner: owner)
        held[path] = value; return value
    }
    func support() throws -> FullImageAttachedDirectory { try directory(InstallerPayloadManifest.support) }
    func namespace() throws -> FullImageAttachedDirectory { try directory(FullImageFixedNamespace.namespace) }
    func transition(plan: String) throws -> FullImageAttachedDirectory { try directory(FullImageFixedNamespace.transition(plan)) }
    func files(plan: String) throws -> FullImageAttachedDirectory { try directory(FullImageFixedNamespace.transition(plan) + "/files") }
    func globalJournal(plan: String) throws -> FullImageAttachedDirectory { try directory(FullImageFixedNamespace.transition(plan) + "/global") }
    func retained(_ unit: PublicTreeUnit, plan: String) throws -> FullImageAttachedDirectory {
        try directory(FullImageFixedNamespace.transition(plan) + "/trees/" + unit.rawValue + "/retained")
    }
    func treeJournal(_ unit: PublicTreeUnit, plan: String) throws -> FullImageAttachedDirectory {
        try directory(FullImageFixedNamespace.transition(plan) + "/trees/" + unit.rawValue + "/journal")
    }
    func preparing(_ name: String, plan: String, unit: PublicTreeUnit? = nil) throws -> FullImageAttachedDirectory {
        let prefix = ".preparing-" + plan + "-"
        guard FullImageJSON.hex(plan), name.hasPrefix(prefix),
              let uuid = UUID(uuidString: String(name.dropFirst(prefix.count))),
              uuid.uuidString.lowercased() == String(name.dropFirst(prefix.count)) else { throw FullImageFailure.journal }
        let suffix = unit.map { "/trees/" + $0.rawValue + "/retained" } ?? "/global"
        return try FullImageAttachedDirectory(root: root, anchor: anchor,
            absolute: FullImageFixedNamespace.namespace + "/" + name + suffix, owner: owner)
    }
    func treeParent(_ unit: PublicTreeUnit) throws -> FullImageAttachedDirectory {
        let parent = unit.path.split(separator: "/").dropLast().joined(separator: "/")
        return try directory(InstallerPayloadManifest.support + (parent.isEmpty ? "" : "/" + parent))
    }
    func fileParent(_ unit: FullImageFileUnit) throws -> FullImageAttachedDirectory {
        if unit == .head { return try namespace() }
        let parent = unit.path.split(separator: "/").dropLast().joined(separator: "/")
        return try directory(InstallerPayloadManifest.support + (parent.isEmpty ? "" : "/" + parent))
    }
    func resolve(_ unit: FullImageFileUnit) throws -> (Int32, String) {
        (try fileParent(unit).duplicate(), String(unit.path.split(separator: "/").last!))
    }
    func verify() throws { for route in held.values { try route.verify(route.fd) } }
    // Do not cache a route to a preparation name that will be published under a
    // different name. Construct installed routes only after exclusive publish.
#if ACCOUNT_ACCESS_FULL_IMAGE_INSTALLED_CHECKS
    static func fixture(root: Int32, owner: uid_t) throws -> FullImageInstalledRoutes {
        guard getuid() != 0, owner == getuid(), geteuid() == owner else { throw ComponentUpdateFailure.context }
        return try FullImageInstalledRoutes(root: root, owner: owner)
    }
#endif
}

enum FullImagePolicyFingerprint {
    // Exact Python json.dumps(sort_keys=True) formatting used by the existing
    // system provisioner/component builder, for this closed string-only shape.
    private static func python(_ value: Any) throws -> String {
        if let value = value as? String { return String(decoding: try FullImageJSON.canonical(value), as: UTF8.self) }
        if let value = value as? [Any] { return "[" + (try value.map { try python($0) }).joined(separator: ", ") + "]" }
        if let value = value as? [String: Any] {
            let keys = value.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            return "{" + (try keys.map { try python($0) + ": " + python(value[$0]!) }).joined(separator: ", ") + "}"
        }
        throw FullImageFailure.source
    }
    static func value(_ peers: [String: ComponentPeerSignature]) throws -> String {
        guard Set(peers.keys) == ["owner", "broker", "bootstrap"] else { throw FullImageFailure.source }
        var signatures: [String: Any] = [:]
        for (name, peer) in peers {
            guard peer.team == "WBULD6N4NQ", peer.identifier == "com.fainir.accountaccess" + (name == "owner" ? "" : "." + name),
                  (1...2).contains(peer.hashes.count), peer.hashes == Array(Set(peer.hashes)).sorted(),
                  peer.hashes.allSatisfy({ FullImageJSON.hex($0, count: 40) }) else { throw FullImageFailure.source }
            signatures[name] = ["team": peer.team, "identifier": peer.identifier, "hashes": peer.hashes]
        }
        let base = InstallerPayloadManifest.support
        let layout = ["runtime": base + "/runtime", "browsers": base + "/browsers", "owner_app": base + "/owner.app",
            "broker": base + "/bin/AccountAccess-broker", "bootstrap": base + "/bin/AccountAccess-bootstrap",
            "broker_name": "_accountaccess", "label": "com.fainir.accountaccess.broker"]
        return FullImageJSON.hash(Data(try python(["signatures": signatures, "layout": layout]).utf8))
    }
}

enum FullImagePreparationInspector {
    // Orphans have no authority. Inspect metadata only without following links,
    // bound their aggregate size/count and retain them for diagnosis/retry.
    private static func inspect(_ fd: Int32, owner: uid_t, group: gid_t, nodes: inout Int, bytes: inout Int64) throws {
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        try PublicTreeIO.noACL(fd)
        guard before.st_gid == group, [mode_t(0o700), 0o755].contains(before.st_mode & 0o7777) else { throw FullImageFailure.journal }
        for name in try InstallerPayloadIO.contents(fd) {
            try ComponentFiles.name(name); nodes += 1
            guard nodes <= InstallerPayloadManifest.maximumEntries + 1024 else { throw FullImageFailure.journal }
            var info = stat(), after = stat()
            guard fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_uid == owner,
                  info.st_gid == group, info.st_mode & 0o6000 == 0 else { throw FullImageFailure.journal }
            if info.st_mode & S_IFMT == S_IFLNK {
                guard info.st_nlink == 1, info.st_size >= 0, info.st_size <= 4096 else { throw FullImageFailure.journal }
                let link = openat(fd, name, O_RDONLY | O_SYMLINK | O_NONBLOCK | O_CLOEXEC)
                guard link >= 0 else { throw FullImageFailure.journal }
                do { try PublicTreeIO.noLinkACL(link) } catch { Darwin.close(link); throw error }; Darwin.close(link)
            } else {
                let directory = info.st_mode & S_IFMT == S_IFDIR
                let child = openat(fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (directory ? O_DIRECTORY : 0))
                guard child >= 0 else { throw FullImageFailure.journal }
                do {
                    let current = try InstallerPayloadIO.check(child, owner: owner, directory: directory)
                    guard InstallerPayloadIO.same(info, current) else { throw FullImageFailure.journal }
                    try PublicTreeIO.noACL(child)
                    if directory { try inspect(child, owner: owner, group: group, nodes: &nodes, bytes: &bytes) }
                    else {
                        guard [mode_t(0o600), 0o644, 0o755].contains(current.st_mode & 0o7777),
                              current.st_size >= 0, current.st_size <= InstallerPayloadManifest.maximumFile else { throw FullImageFailure.journal }
                        let addition = bytes.addingReportingOverflow(current.st_size)
                        guard !addition.overflow, addition.partialValue <= InstallerPayloadManifest.maximumTotal else { throw FullImageFailure.journal }
                        bytes = addition.partialValue
                    }
                } catch { Darwin.close(child); throw error }; Darwin.close(child)
            }
            guard fstatat(fd, name, &after, AT_SYMLINK_NOFOLLOW) == 0, InstallerPayloadIO.same(info, after) else { throw FullImageFailure.journal }
        }
        guard InstallerPayloadIO.same(before, try InstallerPayloadIO.check(fd, owner: owner, directory: true)) else { throw FullImageFailure.journal }
    }
    static func retained(_ namespace: Int32, plan: String, owner: uid_t, group: gid_t) throws -> Int {
        guard FullImageJSON.hex(plan) else { throw FullImageFailure.journal }
        let before = try InstallerPayloadIO.check(namespace, owner: owner, directory: true)
        guard before.st_gid == group, before.st_mode & 0o7777 == 0o700 else { throw FullImageFailure.journal }
        let prefix = ".preparing-" + plan + "-"
        var count = 0, nodes = 0, bytes: Int64 = 0
        for name in try InstallerPayloadIO.contents(namespace) {
            if name == "transition-" + plan || name == "head.json" { continue }
            guard name.hasPrefix(prefix), let uuid = UUID(uuidString: String(name.dropFirst(prefix.count))),
                  uuid.uuidString.lowercased() == String(name.dropFirst(prefix.count)) else { throw FullImageFailure.journal }
            count += 1; guard count <= 8 else { throw FullImageFailure.journal }
            var before = stat(), after = stat()
            guard fstatat(namespace, name, &before, AT_SYMLINK_NOFOLLOW) == 0 else { throw FullImageFailure.journal }
            let fd = openat(namespace, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw FullImageFailure.journal }
            do {
                guard InstallerPayloadIO.same(before, try InstallerPayloadIO.check(fd, owner: owner, directory: true)) else { throw FullImageFailure.journal }
                try inspect(fd, owner: owner, group: group, nodes: &nodes, bytes: &bytes)
            } catch { Darwin.close(fd); throw error }; Darwin.close(fd)
            guard fstatat(namespace, name, &after, AT_SYMLINK_NOFOLLOW) == 0, InstallerPayloadIO.same(before, after) else { throw FullImageFailure.journal }
        }
        guard InstallerPayloadIO.same(before, try InstallerPayloadIO.check(namespace, owner: owner, directory: true)) else { throw FullImageFailure.journal }
        return count
    }
}

enum FullImagePublicStager {
    static func bytes(_ node: InstallerPayloadNode?) throws -> Int64 {
        guard let node else { return 0 }
        guard node.kind == "file", let size = node.size, size >= 0, size <= InstallerPayloadManifest.maximumFile else { throw FullImageFailure.source }
        return size
    }
    static func reserve(_ source: FullImageSource) throws -> Int64 {
        var total: Int64 = 2 * 1024 * 1024
        for unit in source.units {
            let nodes: [InstallerPayloadNode]
            switch unit {
            case .file(_, _, let after): nodes = after.map { [$0] } ?? []
            case .tree(_, _, let after): nodes = after.tree.map { Array($0.nodes.values).filter { $0.kind == "file" } } ?? []
            }
            for node in nodes {
                let added = total.addingReportingOverflow(try bytes(node))
                guard !added.overflow, added.partialValue <= InstallerPayloadManifest.maximumTotal else { throw FullImageFailure.unavailable }
                total = added.partialValue
            }
        }
        return total
    }
    static func copyFile(from source: Int32, name: String, to destination: Int32, slot: String,
                         node: InstallerPayloadNode, owner: uid_t, group: gid_t) throws {
        try ComponentFiles.name(name); try ComponentFiles.name(slot)
        guard node.kind == "file", let mode = node.mode, let size = node.size,
              size >= 0, size <= InstallerPayloadManifest.maximumFile else { throw FullImageFailure.source }
        let input = openat(source, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard input >= 0 else { throw FullImageFailure.object }; defer { Darwin.close(input) }
        let before = try InstallerPayloadIO.check(input, owner: owner, directory: false)
        try PublicTreeIO.noACL(input)
        guard before.st_gid == group, before.st_mode & 0o7777 == mode, before.st_size == size else { throw FullImageFailure.object }
        var path = stat()
        guard fstatat(source, name, &path, AT_SYMLINK_NOFOLLOW) == 0, InstallerPayloadIO.same(path, before) else { throw FullImageFailure.object }
        let output = openat(destination, slot, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard output >= 0 else { throw FullImageFailure.object }; defer { Darwin.close(output) }
        var count: Int64 = 0, hasher = SHA256(), buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        while true {
            let amount = Darwin.read(input, &buffer, buffer.count)
            if amount < 0 && errno == EINTR { continue }
            guard amount >= 0, count + Int64(amount) <= size else { throw FullImageFailure.object }
            if amount == 0 { break }
            count += Int64(amount); hasher.update(data: buffer.prefix(amount))
            try buffer.withUnsafeBytes { raw in
                var offset = 0
                while offset < amount {
                    let written = Darwin.write(output, raw.baseAddress!.advanced(by: offset), amount - offset)
                    if written < 0 && errno == EINTR { continue }
                    guard written > 0 else { throw FullImageFailure.unavailable }; offset += written
                }
            }
        }
        guard count == size, hasher.finalize().map({ String(format: "%02x", $0) }).joined() == node.sha256,
              InstallerPayloadIO.same(before, try InstallerPayloadIO.check(input, owner: owner, directory: false)),
              fstatat(source, name, &path, AT_SYMLINK_NOFOLLOW) == 0, InstallerPayloadIO.same(before, path),
              fchmod(output, mode) == 0, fsync(output) == 0, fsync(destination) == 0,
              lseek(output, 0, SEEK_SET) == 0 else { throw FullImageFailure.object }
        let made = try InstallerPayloadIO.check(output, owner: owner, directory: false)
        try PublicTreeIO.noACL(output)
        guard made.st_gid == group else { throw FullImageFailure.object }
        try InstallerPayloadIO.verifyFile(output, node: node, owner: owner)
    }
    static func copyTree(from source: Int32, to destination: Int32, inventory: PublicTreeInventory,
                         owner: uid_t, group: gid_t, relative: String = "") throws {
        guard let tree = inventory.tree else { throw FullImageFailure.source }
        let before = try InstallerPayloadIO.check(source, owner: owner, directory: true)
        guard before.st_gid == group, before.st_mode & 0o7777 == tree.nodes[relative]?.mode,
              try InstallerPayloadIO.contents(source) == (tree.children[relative] ?? []),
              try InstallerPayloadIO.contents(destination).isEmpty else { throw FullImageFailure.object }
        try PublicTreeIO.noACL(source); try PublicTreeIO.noACL(destination)
        for name in (tree.children[relative] ?? []).sorted() {
            let path = relative.isEmpty ? name : relative + "/" + name
            let node = tree.nodes[path]!
            if node.kind == "file" {
                try copyFile(from: source, name: name, to: destination, slot: name, node: node, owner: owner, group: group)
            } else if node.kind == "directory" {
                guard mkdirat(destination, name, 0o700) == 0 else { throw FullImageFailure.object }
                let input = openat(source, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                let output = openat(destination, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard input >= 0, output >= 0 else { if input >= 0 { Darwin.close(input) }; if output >= 0 { Darwin.close(output) }; throw FullImageFailure.object }
                do {
                    try copyTree(from: input, to: output, inventory: inventory, owner: owner, group: group, relative: path)
                    guard fchmod(output, node.mode!) == 0, fsync(output) == 0 else { throw FullImageFailure.object }
                } catch { Darwin.close(input); Darwin.close(output); throw error }
                Darwin.close(input); Darwin.close(output)
            } else {
                var info = stat(), after = stat(), buffer = [CChar](repeating: 0, count: 4097)
                guard fstatat(source, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
                      info.st_mode & S_IFMT == S_IFLNK, info.st_uid == owner, info.st_gid == group, info.st_nlink == 1 else { throw FullImageFailure.object }
                let input = openat(source, name, O_RDONLY | O_SYMLINK | O_NONBLOCK | O_CLOEXEC)
                guard input >= 0 else { throw FullImageFailure.object }
                do { try PublicTreeIO.noLinkACL(input) } catch { Darwin.close(input); throw error }; Darwin.close(input)
                let count = readlinkat(source, name, &buffer, buffer.count)
                guard count > 0, count <= 4096,
                      Data(buffer.prefix(count).map { UInt8(bitPattern: $0) }) == Data(node.target!.utf8),
                      fstatat(source, name, &after, AT_SYMLINK_NOFOLLOW) == 0, InstallerPayloadIO.same(info, after),
                      symlinkat(node.target!, destination, name) == 0 else { throw FullImageFailure.object }
            }
        }
        guard fsync(destination) == 0,
              InstallerPayloadIO.same(before, try InstallerPayloadIO.check(source, owner: owner, directory: true)) else { throw FullImageFailure.object }
    }
}

enum FullImagePublicView {
    // A complete projection, rather than a broad skip list: each qualified unit
    // contributes exactly its staged or applied side; every other public node
    // remains the immutable predecessor node. Missing removal sides stay absent.
    static func projection(source: FullImageSource, states: [ComponentOperationState]) throws -> InstallerPayloadTree {
        guard states.count == source.units.count, !states.contains(.conflict),
              let base = source.before.trees[InstallerPayloadManifest.support] else { throw FullImageFailure.object }
        var nodes = base.nodes
        for (index, unit) in source.units.enumerated() {
            switch unit {
            case .file(let file, let before, let after):
                nodes[file.path] = states[index] == .applied ? after : before
            case .tree(let tree, let before, let after):
                let prefix = tree.path
                for path in Array(nodes.keys) where path == prefix || path.hasPrefix(prefix + "/") { nodes.removeValue(forKey: path) }
                if let side = (states[index] == .applied ? after : before).tree {
                    for (path, node) in side.nodes { nodes[path.isEmpty ? prefix : prefix + "/" + path] = node }
                }
            }
        }
        var children: [String: Set<String>] = [:]
        for path in nodes.keys where !path.isEmpty {
            let parts = try InstallerPayloadManifest.components(path)
            children[parts.dropLast().joined(separator: "/"), default: []].insert(parts.last!)
        }
        return InstallerPayloadTree(nodes: nodes, children: children)
    }
    static func verify(source: FullImageSource, states: [ComponentOperationState], support: Int32, owner: uid_t) throws {
        let projected = try projection(source: source, states: states)
        // Same exact opaque private branches as InstallerPayloadIO.verifyImage;
        // they are separately governed by existing policy/identity helpers.
        _ = try InstallerPayloadIO.verify(support, tree: projected, owner: owner,
            rootExtras: ["broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"])
    }
}
