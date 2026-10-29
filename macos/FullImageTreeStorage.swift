// In-development directory-storage primitive; not installed or updater-ready.
// No installed-path lookup, service control, owner-policy access or controller.
import Foundation
import CryptoKit
import Darwin

enum PublicTreeFailure: Error { case invalid, changed, journal, barrier }
enum PublicTreeUnit: String, CaseIterable {
    case owner, project, distInfo, pythonProvider, provider
    case pythonPip, pythonOldPipInfo, pythonPipInfo, pythonEnsurePip
    case runtimePip, runtimeOldPipInfo, runtimePipInfo, runtimeEnsurePip
    case runtimeOwner, pythonRoot, runtimeRoot, browsers, wheels, binRoot
    // The first complete-image release has a separate closed set. Adding a
    // successor tree must never expand that release's accepted plan.
    static let fullImageCases: [Self] = [.owner, .project, .distInfo, .pythonProvider, .provider,
        .pythonPip, .pythonOldPipInfo, .pythonPipInfo, .pythonEnsurePip,
        .runtimePip, .runtimeOldPipInfo, .runtimePipInfo, .runtimeEnsurePip]
    // The runtime successor has a separate typed set. In particular, adding
    // `bin` here must not expand the first complete-image release contract.
    static let runtimeUpgradeCases: [Self] = [.runtimeOwner, .pythonRoot, .runtimeRoot, .browsers, .wheels, .binRoot]
    var path: String {
        switch self {
        case .owner, .runtimeOwner: return "owner.app"
        case .project: return "runtime/lib/python3.12/site-packages/account_access"
        case .distInfo: return "runtime/lib/python3.12/site-packages/account_access-0.8.0.dist-info"
        case .pythonProvider: return "python/libexec/bitwarden"
        case .provider: return "runtime/libexec/bitwarden"
        case .pythonPip: return "python/lib/python3.12/site-packages/pip"
        case .pythonOldPipInfo: return "python/lib/python3.12/site-packages/pip-26.2.1.dist-info"
        case .pythonPipInfo: return "python/lib/python3.12/site-packages/pip-26.2.2.dist-info"
        case .pythonEnsurePip: return "python/lib/python3.12/ensurepip"
        case .runtimePip: return "runtime/lib/python3.12/site-packages/pip"
        case .runtimeOldPipInfo: return "runtime/lib/python3.12/site-packages/pip-26.2.1.dist-info"
        case .runtimePipInfo: return "runtime/lib/python3.12/site-packages/pip-26.2.2.dist-info"
        case .runtimeEnsurePip: return "runtime/lib/python3.12/ensurepip"
        case .pythonRoot: return "python"
        case .runtimeRoot: return "runtime"
        case .browsers: return "browsers"
        case .wheels: return "wheels"
        case .binRoot: return "bin"
        }
    }
    var beforePresent: Bool { ![Self.pythonPipInfo, .runtimePipInfo].contains(self) }
    var afterPresent: Bool { ![Self.pythonOldPipInfo, .runtimeOldPipInfo].contains(self) }
    var runtimeUpgrade: Bool { Self.runtimeUpgradeCases.contains(self) }
    // Package85 and the preceding cache repair published these exact nodes as
    // root:wheel; other nodes kept the original support group's metadata. This closed
    // mapping validates each old node without changing it or allowing any GID.
    func precedingGroup(_ relative: String, legacy: gid_t, published: gid_t) -> gid_t {
        guard runtimeUpgrade else { return legacy }
        let absolute = path + (relative.isEmpty ? "" : "/" + relative)
        for unit in Self.fullImageCases where unit.afterPresent {
            if absolute == unit.path || absolute.hasPrefix(unit.path + "/") { return published }
        }
        let files: Set<String> = ["wheels/account_access-0.8.0-py3-none-any.whl",
            "python/bin/pip", "python/bin/pip3", "runtime/bin/pip", "runtime/bin/pip3",
            "runtime/lib/python3.12/encodings/__pycache__/__init__.cpython-312.pyc",
            "runtime/lib/python3.12/encodings/__pycache__/aliases.cpython-312.pyc",
            "runtime/lib/python3.12/encodings/__pycache__/utf_8.cpython-312.pyc"]
        return files.contains(absolute) ? published : legacy
    }
    func accepts(old: PublicTreeInventory, new: PublicTreeInventory) -> Bool {
        old.unit == self && new.unit == self && old.isPresent == beforePresent && new.isPresent == afterPresent
    }
    var name: String { String(path.split(separator: "/").last!) }
    var slot: String { "slot-" + rawValue }
}

struct PublicTreeInventory {
    let unit: PublicTreeUnit
    let tree: InstallerPayloadTree?
    let manifestSHA256: String
    let inventorySHA256: String?
    var isPresent: Bool { tree != nil }
    init(manifest: Data, unit: PublicTreeUnit) throws {
        try self.init(validatedManifest: InstallerPayloadManifest(manifest), unit: unit)
    }
    // Reuse the already strict immutable manifest loaded by the plan parser;
    // this does not introduce a second unvalidated JSON or path authority.
    init(validatedManifest parsed: InstallerPayloadManifest, unit: PublicTreeUnit) throws {
        let source = parsed.trees[InstallerPayloadManifest.support]!
        var nodes: [String: InstallerPayloadNode] = [:], children: [String: Set<String>] = [:]
        var rows: [String: [String: Any]] = [:]
        for (path, node) in source.nodes where path == unit.path || path.hasPrefix(unit.path + "/") {
            let name = path == unit.path ? "" : String(path.dropFirst(unit.path.count + 1))
            nodes[name] = node
            if !name.isEmpty {
                let parts = try InstallerPayloadManifest.components(name)
                children[parts.dropLast().joined(separator: "/"), default: []].insert(parts.last!)
            }
            if node.kind == "file" { rows[name] = ["kind": node.kind, "mode": node.mode!, "size": node.size!, "sha256": node.sha256!] }
            else if node.kind == "directory" { rows[name] = ["kind": node.kind, "mode": node.mode!] }
            else { rows[name] = ["kind": node.kind, "target": node.target!] }
        }
        self.unit = unit; manifestSHA256 = parsed.sha256
        if nodes.isEmpty {
            let parent = unit.path.split(separator: "/").dropLast().joined(separator: "/")
            guard unit.beforePresent != unit.afterPresent,
                  source.nodes[parent]?.kind == "directory", source.nodes[parent]?.mode == 0o755 else { throw PublicTreeFailure.invalid }
            tree = nil; inventorySHA256 = nil
        } else {
            guard nodes[""]?.kind == "directory", nodes[""]?.mode == 0o755 else { throw PublicTreeFailure.invalid }
            tree = InstallerPayloadTree(nodes: nodes, children: children)
            inventorySHA256 = Self.digest(try JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys, .withoutEscapingSlashes]))
        }
    }
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}

struct PublicTreePin: Codable, Equatable {
    let device: Int32
    let inode: UInt64
    let owner: UInt32
    let group: UInt32
    let mode: UInt16
    let inventorySHA256: String
}
struct PublicTreeOperation: Codable, Equatable {
    let schema: Int
    let unit: String
    let planSHA256: String
    let beforeManifestSHA256: String
    let afterManifestSHA256: String
    let before: PublicTreePin?
    let after: PublicTreePin?
    private enum Keys: String, CodingKey, CaseIterable {
        case schema, unit, planSHA256, beforeManifestSHA256, afterManifestSHA256, before, after
    }
    private struct AnyKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    init(schema: Int, unit: String, planSHA256: String, beforeManifestSHA256: String,
         afterManifestSHA256: String, before: PublicTreePin?, after: PublicTreePin?) {
        self.schema = schema; self.unit = unit; self.planSHA256 = planSHA256
        self.beforeManifestSHA256 = beforeManifestSHA256; self.afterManifestSHA256 = afterManifestSHA256
        self.before = before; self.after = after
    }
    init(from decoder: Decoder) throws {
        let all = try decoder.container(keyedBy: AnyKey.self)
        guard Set(all.allKeys.map(\.stringValue)) == Set(Keys.allCases.map(\.rawValue)) else { throw PublicTreeFailure.invalid }
        let values = try decoder.container(keyedBy: Keys.self)
        schema = try values.decode(Int.self, forKey: .schema)
        unit = try values.decode(String.self, forKey: .unit)
        planSHA256 = try values.decode(String.self, forKey: .planSHA256)
        beforeManifestSHA256 = try values.decode(String.self, forKey: .beforeManifestSHA256)
        afterManifestSHA256 = try values.decode(String.self, forKey: .afterManifestSHA256)
        before = try values.decodeIfPresent(PublicTreePin.self, forKey: .before)
        after = try values.decodeIfPresent(PublicTreePin.self, forKey: .after)
    }
    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: Keys.self)
        try values.encode(schema, forKey: .schema); try values.encode(unit, forKey: .unit)
        try values.encode(planSHA256, forKey: .planSHA256)
        try values.encode(beforeManifestSHA256, forKey: .beforeManifestSHA256)
        try values.encode(afterManifestSHA256, forKey: .afterManifestSHA256)
        if let before { try values.encode(before, forKey: .before) } else { try values.encodeNil(forKey: .before) }
        if let after { try values.encode(after, forKey: .after) } else { try values.encodeNil(forKey: .after) }
    }
}

enum PublicTreeIO {
    struct FastObject: Equatable {
        let device: Int32, inode: UInt64, type: UInt16, permissions: UInt16
        let owner: UInt32, group: UInt32, links: UInt64, size: Int64
        let mtimeSec: Int64, mtimeNsec: Int64, ctimeSec: Int64, ctimeNsec: Int64
        let linkTarget: String?

        init(_ info: stat, linkTarget: String? = nil, rootDirectory: Bool = false) {
            device = info.st_dev; inode = UInt64(info.st_ino)
            type = UInt16(info.st_mode & S_IFMT); permissions = UInt16(info.st_mode & 0o7777)
            owner = info.st_uid; group = info.st_gid; links = UInt64(info.st_nlink); size = Int64(info.st_size)
            mtimeSec = Int64(info.st_mtimespec.tv_sec); mtimeNsec = Int64(info.st_mtimespec.tv_nsec)
            // renameatx_np changes a moved directory's ctime on some APFS
            // versions. Its inode and mtime remain stable across the swap.
            ctimeSec = rootDirectory ? 0 : Int64(info.st_ctimespec.tv_sec)
            ctimeNsec = rootDirectory ? 0 : Int64(info.st_ctimespec.tv_nsec)
            self.linkTarget = linkTarget
        }
    }

    static func noACL(_ fd: Int32) throws {
        errno = 0
        guard let acl = acl_get_fd(fd) else {
            guard errno == ENOENT else { throw PublicTreeFailure.invalid }; return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) != 0, errno == EINVAL else { throw PublicTreeFailure.invalid }
    }
    static func noLinkACL(_ fd: Int32) throws {
        errno = 0
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            // ENOTSUP, EBADF and other errors refuse; there is no skip/follow fallback.
            guard errno == ENOENT else { throw PublicTreeFailure.invalid }; return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) != 0, errno == EINVAL else {
            throw PublicTreeFailure.invalid
        }
    }
    static func metadata(_ fd: Int32, inventory: PublicTreeInventory, owner: uid_t, group: gid_t, name: String = "", priorReleaseGroup: gid_t? = nil) throws {
        guard let tree = inventory.tree, priorReleaseGroup == nil || inventory.unit.runtimeUpgrade else { throw PublicTreeFailure.invalid }
        func expectedGroup(_ path: String) -> gid_t {
            priorReleaseGroup.map { inventory.unit.precedingGroup(path, legacy: group, published: $0) } ?? group
        }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        try noACL(fd)
        guard before.st_gid == expectedGroup(name), before.st_mode & 0o7777 == tree.nodes[name]?.mode,
              before.st_nlink > 0,
              try InstallerPayloadIO.contents(fd) == (tree.children[name] ?? []) else { throw PublicTreeFailure.changed }
        for child in (tree.children[name] ?? []).sorted() {
            let relative = name.isEmpty ? child : name + "/" + child
            let node = tree.nodes[relative]!
            var info = stat()
            guard fstatat(fd, child, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_uid == owner,
                  info.st_gid == expectedGroup(relative), info.st_dev == before.st_dev,
                  info.st_mode & 0o6000 == 0 else { throw PublicTreeFailure.changed }
            if node.kind == "symlink" {
                guard info.st_mode & S_IFMT == S_IFLNK, info.st_nlink == 1 else { throw PublicTreeFailure.changed }
                // O_SYMLINK opens this link itself; child is one validated component.
                let link = openat(fd, child, O_RDONLY | O_SYMLINK | O_CLOEXEC | O_NONBLOCK)
                guard link >= 0 else { throw PublicTreeFailure.changed }
                do {
                    var held = stat(), current = stat()
                    guard fstat(link, &held) == 0, held.st_mode & S_IFMT == S_IFLNK,
                          held.st_gid == expectedGroup(relative), InstallerPayloadIO.same(info, held) else { throw PublicTreeFailure.changed }
                    try noLinkACL(link)
                    guard fstat(link, &current) == 0, current.st_gid == expectedGroup(relative),
                          InstallerPayloadIO.same(held, current) else { throw PublicTreeFailure.changed }
                } catch { Darwin.close(link); throw error }
                Darwin.close(link)
            } else {
                let opened = openat(fd, child, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (node.kind == "directory" ? O_DIRECTORY : 0))
                guard opened >= 0 else { throw PublicTreeFailure.changed }
                do {
                    let observed = try InstallerPayloadIO.check(opened, owner: owner, directory: node.kind == "directory")
                    try noACL(opened)
                    guard observed.st_gid == expectedGroup(relative), InstallerPayloadIO.same(info, observed) else { throw PublicTreeFailure.changed }
                    if node.kind == "directory" { try metadata(opened, inventory: inventory, owner: owner, group: group, name: relative, priorReleaseGroup: priorReleaseGroup) }
                } catch { Darwin.close(opened); throw error }
                Darwin.close(opened)
            }
            var after = stat()
            guard fstatat(fd, child, &after, AT_SYMLINK_NOFOLLOW) == 0, after.st_gid == expectedGroup(relative),
                  InstallerPayloadIO.same(info, after) else {
                throw PublicTreeFailure.changed
            }
        }
        let current = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        guard current.st_gid == expectedGroup(name), InstallerPayloadIO.same(before, current) else {
            throw PublicTreeFailure.changed
        }
    }
    static func observe(_ parent: Int32, name: String, inventory: PublicTreeInventory, owner: uid_t, group: gid_t, attachment: PublicTreeAttachment, priorReleaseGroup: gid_t? = nil) throws -> PublicTreePin {
        let rootGroup = priorReleaseGroup.map { inventory.unit.precedingGroup("", legacy: group, published: $0) } ?? group
        guard attachment.role.mayObserve(inventory.unit), let tree = inventory.tree,
              let inventorySHA256 = inventory.inventorySHA256 else { throw PublicTreeFailure.invalid }
        try attachment.verify(parent, role: attachment.role, owner: owner, group: attachment.parentGroup, mode: attachment.role.mode)
        guard try InstallerPayloadManifest.components(name).count == 1 else { throw PublicTreeFailure.invalid }
        var path = stat()
        guard fstatat(parent, name, &path, AT_SYMLINK_NOFOLLOW) == 0, path.st_mode & S_IFMT == S_IFDIR else { throw PublicTreeFailure.changed }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw PublicTreeFailure.changed }
        defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true,
            expectedGroup: rootGroup, strictACL: true)
        guard path.st_gid == rootGroup, InstallerPayloadIO.same(path, before) else { throw PublicTreeFailure.changed }
        _ = try InstallerPayloadIO.verify(fd, tree: tree, owner: owner, expectedGroup: { relative in
            priorReleaseGroup.map { inventory.unit.precedingGroup(relative, legacy: group, published: $0) } ?? group
        })
        var after = stat()
        let current = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        guard fstatat(parent, name, &after, AT_SYMLINK_NOFOLLOW) == 0,
              after.st_gid == rootGroup, current.st_gid == rootGroup,
              InstallerPayloadIO.same(before, after), InstallerPayloadIO.same(before, current) else {
            throw PublicTreeFailure.changed
        }
        try attachment.verify(parent, role: attachment.role, owner: owner, group: attachment.parentGroup, mode: attachment.role.mode)
        return PublicTreePin(device: before.st_dev, inode: UInt64(before.st_ino), owner: owner, group: rootGroup,
            mode: UInt16(before.st_mode & 0o7777), inventorySHA256: inventorySHA256)
    }
    static func observeOptional(_ parent: Int32, name: String, inventory: PublicTreeInventory,
        owner: uid_t, group: gid_t, attachment: PublicTreeAttachment, priorReleaseGroup: gid_t? = nil) throws -> PublicTreePin? {
        if inventory.isPresent { return try observe(parent, name: name, inventory: inventory, owner: owner, group: group, attachment: attachment, priorReleaseGroup: priorReleaseGroup) }
        guard attachment.role.mayObserve(inventory.unit), try InstallerPayloadManifest.components(name).count == 1 else { throw PublicTreeFailure.invalid }
        try attachment.verify(parent, role: attachment.role, owner: owner, group: attachment.parentGroup, mode: attachment.role.mode)
        var info = stat()
        errno = 0
        guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw PublicTreeFailure.changed }
        try attachment.verify(parent, role: attachment.role, owner: owner, group: attachment.parentGroup, mode: attachment.role.mode)
        errno = 0
        guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw PublicTreeFailure.changed }
        return nil
    }

    // A content hash is established by observeOptional before this snapshot is
    // trusted. Later, while the service and owner app are quiesced, this checks
    // every path, directory entry, inode, permission, size and change time
    // without rereading file contents. It is process-local and never survives
    // an interrupted update; recovery starts with the full content verifier.
    static func fastSnapshot(_ parent: Int32, name: String, inventory: PublicTreeInventory,
        owner: uid_t, group: gid_t, attachment: PublicTreeAttachment,
        priorReleaseGroup: gid_t? = nil) throws -> [String: FastObject]? {
        guard attachment.role.mayObserve(inventory.unit), try InstallerPayloadManifest.components(name).count == 1 else {
            throw PublicTreeFailure.invalid
        }
        try attachment.verify(parent, role: attachment.role, owner: owner,
            group: attachment.parentGroup, mode: attachment.role.mode)
        guard let tree = inventory.tree else {
            var info = stat(); errno = 0
            guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else {
                throw PublicTreeFailure.changed
            }
            try attachment.verify(parent, role: attachment.role, owner: owner,
                group: attachment.parentGroup, mode: attachment.role.mode)
            return nil
        }
        func expectedGroup(_ relative: String) -> gid_t {
            priorReleaseGroup.map { inventory.unit.precedingGroup(relative, legacy: group, published: $0) } ?? group
        }
        var rootInfo = stat()
        guard fstatat(parent, name, &rootInfo, AT_SYMLINK_NOFOLLOW) == 0,
              rootInfo.st_mode & S_IFMT == S_IFDIR,
              rootInfo.st_uid == owner, rootInfo.st_gid == expectedGroup(""),
              rootInfo.st_mode & 0o7777 == tree.nodes[""]?.mode,
              rootInfo.st_nlink > 0 else { throw PublicTreeFailure.changed }
        let root = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw PublicTreeFailure.changed }
        defer { Darwin.close(root) }
        let openedRoot = try InstallerPayloadIO.check(root, owner: owner, directory: true)
        guard openedRoot.st_gid == expectedGroup(""), InstallerPayloadIO.same(rootInfo, openedRoot) else {
            throw PublicTreeFailure.changed
        }
        var result: [String: FastObject] = [:]
        func scan(_ fd: Int32, _ relative: String, _ depth: Int) throws {
            guard depth <= 64, let node = tree.nodes[relative], node.kind == "directory" else {
                throw PublicTreeFailure.changed
            }
            let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
            try noACL(fd)
            guard before.st_gid == expectedGroup(relative), before.st_mode & 0o7777 == node.mode,
                  before.st_nlink > 0,
                  try InstallerPayloadIO.contents(fd) == (tree.children[relative] ?? []) else {
                throw PublicTreeFailure.changed
            }
            result[relative] = FastObject(before, rootDirectory: relative.isEmpty)
            for child in (tree.children[relative] ?? []).sorted() {
                let path = relative.isEmpty ? child : relative + "/" + child
                guard let expected = tree.nodes[path] else { throw PublicTreeFailure.changed }
                var item = stat()
                guard fstatat(fd, child, &item, AT_SYMLINK_NOFOLLOW) == 0,
                      item.st_uid == owner, item.st_gid == expectedGroup(path),
                      item.st_dev == before.st_dev, item.st_mode & 0o6000 == 0 else {
                    throw PublicTreeFailure.changed
                }
                var target: String?
                switch expected.kind {
                case "directory":
                    guard item.st_mode & S_IFMT == S_IFDIR, item.st_mode & 0o7777 == expected.mode,
                          item.st_nlink > 0 else { throw PublicTreeFailure.changed }
                    let childFD = openat(fd, child, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    guard childFD >= 0 else { throw PublicTreeFailure.changed }
                    do {
                        let opened = try InstallerPayloadIO.check(childFD, owner: owner, directory: true)
                        guard opened.st_gid == expectedGroup(path), InstallerPayloadIO.same(item, opened) else {
                            throw PublicTreeFailure.changed
                        }
                        try scan(childFD, path, depth + 1)
                    } catch { Darwin.close(childFD); throw error }
                    Darwin.close(childFD)
                case "file":
                    guard item.st_mode & S_IFMT == S_IFREG, item.st_nlink == 1,
                          item.st_mode & 0o7777 == expected.mode, item.st_size == expected.size else {
                        throw PublicTreeFailure.changed
                    }
                    result[path] = FastObject(item)
                case "symlink":
                    guard item.st_mode & S_IFMT == S_IFLNK, item.st_nlink == 1 else { throw PublicTreeFailure.changed }
                    var bytes = [CChar](repeating: 0, count: 4097)
                    let count = readlinkat(fd, child, &bytes, bytes.count)
                    guard count > 0, count <= 4096,
                          Data(bytes.prefix(count).map { UInt8(bitPattern: $0) }) == Data(expected.target!.utf8),
                          let value = String(bytes: bytes.prefix(count).map { UInt8(bitPattern: $0) }, encoding: .utf8) else {
                        throw PublicTreeFailure.changed
                    }
                    target = value
                    result[path] = FastObject(item, linkTarget: target)
                default: throw PublicTreeFailure.changed
                }
                var after = stat()
                guard fstatat(fd, child, &after, AT_SYMLINK_NOFOLLOW) == 0,
                      InstallerPayloadIO.same(item, after) else { throw PublicTreeFailure.changed }
            }
            let after = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
            guard after.st_gid == expectedGroup(relative), InstallerPayloadIO.same(before, after) else {
                throw PublicTreeFailure.changed
            }
        }
        try scan(root, "", 0)
        var finalPath = stat(), finalFD = stat()
        guard fstat(root, &finalFD) == 0, fstatat(parent, name, &finalPath, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(rootInfo, finalPath), InstallerPayloadIO.same(rootInfo, finalFD) else {
            throw PublicTreeFailure.changed
        }
        try attachment.verify(parent, role: attachment.role, owner: owner,
            group: attachment.parentGroup, mode: attachment.role.mode)
        return result
    }

}

final class PublicTreeStorage {
    enum State: Equatable { case staged, applied }
    enum Phase: Equatable { case afterIntent, beforeRename, afterRename, afterAcknowledgment }
    private enum Event: String, CaseIterable { case applyIntent, applied, rollbackIntent, rolledBack }
    private struct Parent {
        let attachment: PublicTreeAttachment
        let role: PublicTreeParentRole
        let fd: Int32
        let device: Int32
        let inode: UInt64
        let group: gid_t
        let mode: mode_t
    }
    private struct Record: Equatable {
        let data: Data
        let device: Int32
        let inode: UInt64
        let mtimeSec: Int64, mtimeNsec: Int64, ctimeSec: Int64, ctimeNsec: Int64
    }
    let operation: PublicTreeOperation
    private let unit: PublicTreeUnit
    private let old: PublicTreeInventory, new: PublicTreeInventory
    private let target: Parent, retained: Parent, journal: Parent
    private let owner: uid_t, group: gid_t, beforeGroup: gid_t
    private let requireQuiescent: () throws -> Void
    private let fault: (Phase) throws -> Void
    private var history: [Record] = []
    private var intentRecord: Record?
    private let observationDevice: Int32?
    private var fastSnapshots: [UInt64: [String: PublicTreeIO.FastObject]]?
    private var fastStateEnabled = false
    // A fixed successor can qualify the original published tree in its own
    // retained slot. This mode is read-only and never chooses a filesystem path.
    private let completedProjection: (() throws -> PublicTreePin?)?

    private init(operation: PublicTreeOperation, unit: PublicTreeUnit, old: PublicTreeInventory, new: PublicTreeInventory,
        target: Parent, retained: Parent, journal: Parent, owner: uid_t, group: gid_t, beforeGroup: gid_t,
        requireQuiescent: @escaping () throws -> Void, fault: @escaping (Phase) throws -> Void,
        observationDevice: Int32?, completedProjection: (() throws -> PublicTreePin?)?) {
        self.operation = operation; self.unit = unit; self.old = old; self.new = new
        self.target = target; self.retained = retained; self.journal = journal
        self.owner = owner; self.group = group; self.beforeGroup = beforeGroup
        self.requireQuiescent = requireQuiescent; self.fault = fault
        self.observationDevice = observationDevice
        self.completedProjection = completedProjection
    }
    deinit { Darwin.close(target.fd); Darwin.close(retained.fd); Darwin.close(journal.fd) }
    private static func encode<Value: Encodable>(_ value: Value) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    private static func parent(_ supplied: Int32, attachment: PublicTreeAttachment, role: PublicTreeParentRole, owner: uid_t, mode: mode_t) throws -> Parent {
        let group = attachment.parentGroup
        try attachment.verify(supplied, role: role, owner: owner, group: group, mode: mode)
        let fd = dup(supplied)
        guard fd >= 0 else { throw PublicTreeFailure.invalid }
        do {
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw PublicTreeFailure.invalid }
            let info = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
            try PublicTreeIO.noACL(fd)
            guard info.st_gid == group, info.st_nlink > 0, info.st_mode & 0o7777 == mode else { throw PublicTreeFailure.invalid }
            return Parent(attachment: attachment, role: role, fd: fd, device: info.st_dev, inode: UInt64(info.st_ino), group: group, mode: mode)
        } catch { Darwin.close(fd); throw error }
    }
    // beforeGroup is separately qualified legacy-image authority, never a GID
    // selected from the operation record. Nil preserves the uniform fixture API.
    // Parent groups always come from their immutable canonical attachments.
    static func capture(unit: PublicTreeUnit, targetParent: Int32, retainedParent: Int32,
        targetAttachment: PublicTreeAttachment, retainedAttachment: PublicTreeAttachment,
        old: PublicTreeInventory, new: PublicTreeInventory, owner: uid_t, group: gid_t,
        beforeGroup: gid_t? = nil, planSHA256: String) throws -> PublicTreeOperation {
        let beforeGroup = beforeGroup ?? group
        guard unit.accepts(old: old, new: new), planSHA256.count == 64,
              planSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw PublicTreeFailure.invalid }
        for (fd, mode, attachment, role) in [(targetParent, mode_t(0o755), targetAttachment, PublicTreeParentRole.target(unit)),
                                             (retainedParent, mode_t(0o700), retainedAttachment, PublicTreeParentRole.retained(unit))] {
            try attachment.verify(fd, role: role, owner: owner, group: attachment.parentGroup, mode: mode)
            let info = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
            try PublicTreeIO.noACL(fd)
            guard info.st_gid == attachment.parentGroup, info.st_nlink > 0, info.st_mode & 0o7777 == mode else { throw PublicTreeFailure.invalid }
        }
        let before = try PublicTreeIO.observeOptional(targetParent, name: unit.name, inventory: old, owner: owner, group: beforeGroup, attachment: targetAttachment, priorReleaseGroup: unit.runtimeUpgrade ? group : nil)
        let after = try PublicTreeIO.observeOptional(retainedParent, name: unit.slot, inventory: new, owner: owner, group: group, attachment: retainedAttachment)
        try targetAttachment.verify(targetParent, role: .target(unit), owner: owner, group: targetAttachment.parentGroup, mode: 0o755)
        try retainedAttachment.verify(retainedParent, role: .retained(unit), owner: owner, group: retainedAttachment.parentGroup, mode: 0o700)
        var targetInfo = stat(), retainedInfo = stat()
        guard fstat(targetParent, &targetInfo) == 0, fstat(retainedParent, &retainedInfo) == 0,
              targetInfo.st_dev == retainedInfo.st_dev, targetInfo.st_ino != retainedInfo.st_ino else { throw PublicTreeFailure.invalid }
        if let before, let after {
            guard before.device == after.device, before.inode != after.inode,
                  before.inventorySHA256 != after.inventorySHA256 else { throw PublicTreeFailure.invalid }
        }
        return PublicTreeOperation(schema: 2, unit: unit.rawValue, planSHA256: planSHA256,
            beforeManifestSHA256: old.manifestSHA256, afterManifestSHA256: new.manifestSHA256, before: before, after: after)
    }
    static func open(operation: PublicTreeOperation, unit: PublicTreeUnit, targetParent: Int32, retainedParent: Int32,
        journalParent: Int32, targetAttachment: PublicTreeAttachment, retainedAttachment: PublicTreeAttachment,
        journalAttachment: PublicTreeAttachment, old: PublicTreeInventory, new: PublicTreeInventory, owner: uid_t, group: gid_t,
        beforeGroup: gid_t? = nil,
        requireQuiescent: @escaping () throws -> Void, createIfMissing: Bool = true,
        observationDevice: Int32? = nil,
        completedProjection: (() throws -> PublicTreePin?)? = nil,
        fault: @escaping (Phase) throws -> Void = { _ in }) throws -> PublicTreeStorage {
        let beforeGroup = beforeGroup ?? group
        guard observationDevice == nil || (!createIfMissing && observationDevice! >= 0) else { throw PublicTreeFailure.invalid }
        guard completedProjection == nil || !createIfMissing else { throw PublicTreeFailure.invalid }
        guard operation.schema == 2, operation.unit == unit.rawValue, unit.accepts(old: old, new: new),
              operation.planSHA256.utf8.count == 64,
              operation.planSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              operation.beforeManifestSHA256 == old.manifestSHA256, operation.afterManifestSHA256 == new.manifestSHA256,
              (operation.before != nil) == old.isPresent, (operation.after != nil) == new.isPresent else { throw PublicTreeFailure.invalid }
        for (pin, inventory, contentGroup) in [(operation.before, old, unit.precedingGroup("", legacy: beforeGroup, published: group)), (operation.after, new, group)] {
            if let pin {
                guard pin.inventorySHA256 == inventory.inventorySHA256, pin.owner == owner, pin.group == contentGroup,
                      pin.mode == 0o755, pin.inode > 0 else { throw PublicTreeFailure.invalid }
            }
        }
        if let before = operation.before, let after = operation.after {
            guard before.inode != after.inode, before.inventorySHA256 != after.inventorySHA256 else { throw PublicTreeFailure.invalid }
        }
        var opened: [Int32] = [], adopted = false
        defer { if !adopted { opened.forEach { Darwin.close($0) } } }
        let target = try parent(targetParent, attachment: targetAttachment, role: .target(unit), owner: owner, mode: 0o755); opened.append(target.fd)
        let retained = try parent(retainedParent, attachment: retainedAttachment, role: .retained(unit), owner: owner, mode: 0o700); opened.append(retained.fd)
        let journal = try parent(journalParent, attachment: journalAttachment, role: .journal(unit), owner: owner, mode: 0o700); opened.append(journal.fd)
        guard Set([target.inode, retained.inode, journal.inode]).count == 3,
              target.device == retained.device, retained.device == journal.device,
              [operation.before, operation.after].compactMap({ $0 }).allSatisfy({ $0.device == (observationDevice ?? target.device) }) else { throw PublicTreeFailure.invalid }
        let value = PublicTreeStorage(operation: operation, unit: unit, old: old, new: new, target: target,
            retained: retained, journal: journal, owner: owner, group: group, beforeGroup: beforeGroup,
            requireQuiescent: requireQuiescent, fault: fault, observationDevice: observationDevice,
            completedProjection: completedProjection)
        adopted = true
        try value.prepareJournal(createIfMissing: createIfMissing)
        _ = try value.state()
        return value
    }
    private func parents() throws {
        for parent in [target, retained, journal] {
            try parent.attachment.verify(parent.fd, role: parent.role, owner: owner, group: parent.group, mode: parent.mode)
            let info = try InstallerPayloadIO.check(parent.fd, owner: owner, directory: true)
            try PublicTreeIO.noACL(parent.fd)
            guard info.st_dev == parent.device, UInt64(info.st_ino) == parent.inode,
                  info.st_gid == parent.group, info.st_nlink > 0, info.st_mode & 0o7777 == parent.mode else { throw PublicTreeFailure.changed }
        }
    }
    private func read(_ name: String) throws -> Record {
        try parents()
        let fd = openat(journal.fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw PublicTreeFailure.journal }
        defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        try PublicTreeIO.noACL(fd)
        guard before.st_gid == journal.group, before.st_mode & 0o7777 == 0o600 else { throw PublicTreeFailure.journal }
        let data = try InstallerPayloadIO.read(fd, maximum: 4096, owner: owner)
        var info = stat()
        let current = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        guard fstatat(journal.fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_gid == journal.group, current.st_gid == journal.group,
              InstallerPayloadIO.same(before, info), InstallerPayloadIO.same(before, current) else { throw PublicTreeFailure.journal }
        try parents()
        return Record(data: data, device: before.st_dev, inode: UInt64(before.st_ino), mtimeSec: Int64(before.st_mtimespec.tv_sec),
            mtimeNsec: Int64(before.st_mtimespec.tv_nsec), ctimeSec: Int64(before.st_ctimespec.tv_sec), ctimeNsec: Int64(before.st_ctimespec.tv_nsec))
    }
    private func write(_ name: String, data: Data) throws -> Record {
        guard observationDevice == nil, completedProjection == nil else { throw PublicTreeFailure.journal }
        try parents()
        guard data.count <= 4096 else { throw PublicTreeFailure.journal }
        let fd = openat(journal.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw PublicTreeFailure.journal }
        defer { Darwin.close(fd) }
        let created = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        try PublicTreeIO.noACL(fd)
        guard created.st_gid == journal.group, fchmod(fd, 0o600) == 0 else { throw PublicTreeFailure.journal }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw PublicTreeFailure.journal }; offset += count
            }
        }
        guard fsync(fd) == 0, fsync(journal.fd) == 0 else { throw PublicTreeFailure.journal }
        try parents()
        return try read(name)
    }
    private func eventData(_ kind: Event, sequence: Int) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["schema": 1, "sequence": sequence, "event": kind.rawValue,
            "unit": unit.rawValue, "plan_sha256": operation.planSHA256], options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private func event(_ record: Record, sequence: Int) throws -> Event {
        guard let value = try Event.allCases.first(where: { try eventData($0, sequence: sequence) == record.data }) else {
            throw PublicTreeFailure.journal
        }
        return value
    }
    private func follows(_ next: Event, _ previous: Event?) -> Bool {
        switch previous {
        case nil: return next == .applyIntent
        case .applyIntent: return [.applyIntent, .applied, .rollbackIntent].contains(next)
        case .applied: return next == .rollbackIntent
        case .rollbackIntent: return [.rollbackIntent, .rolledBack, .applyIntent].contains(next)
        case .rolledBack: return next == .applyIntent
        }
    }
    private func loadHistory() throws -> [Record] {
        try parents()
        let names = try InstallerPayloadIO.contents(journal.fd)
        guard names.contains("intent.json"), names.count <= 257 else { throw PublicTreeFailure.journal }
        var result: [Record] = [], previous: Event?
        for index in 0..<(names.count - 1) {
            let name = String(format: "event-%04d.json", index)
            guard names.contains(name) else { throw PublicTreeFailure.journal }
            let record = try read(name)
            let kind = try event(record, sequence: index)
            guard follows(kind, previous) else { throw PublicTreeFailure.journal }
            result.append(record)
            previous = kind
        }
        try parents()
        return result
    }
    private func prepareJournal(createIfMissing: Bool) throws {
        try parents()
        let names = try InstallerPayloadIO.contents(journal.fd), expected = try Self.encode(operation)
        if names.isEmpty {
            guard createIfMissing else { throw PublicTreeFailure.journal }
            intentRecord = try write("intent.json", data: expected)
        }
        else { intentRecord = try read("intent.json") }
        guard intentRecord?.data == expected else { throw PublicTreeFailure.journal }
        history = try loadHistory()
    }
    private func journalUnchanged() throws {
        guard try read("intent.json") == intentRecord, try loadHistory() == history else { throw PublicTreeFailure.journal }
    }
    private func append(_ kind: Event) throws {
        try parents(); try journalUnchanged()
        guard history.count < 256 else { throw PublicTreeFailure.journal }
        let previous = try history.last.map { try event($0, sequence: history.count - 1) }
        guard follows(kind, previous) else { throw PublicTreeFailure.journal }
        let name = String(format: "event-%04d.json", history.count)
        history.append(try write(name, data: eventData(kind, sequence: history.count)))
    }
    func state() throws -> State {
        if fastStateEnabled { return try fastState() }
        try parents(); try journalUnchanged()
        let previous = try history.last.map { try event($0, sequence: history.count - 1) }
        func identity(_ parent: Parent, _ name: String, _ pin: PublicTreePin?) throws -> Bool {
            var info = stat(); errno = 0
            if fstatat(parent.fd, name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
                guard errno == ENOENT else { throw PublicTreeFailure.changed }
                return pin == nil
            }
            guard let pin else { return false }
            return info.st_mode & S_IFMT == S_IFDIR && info.st_dev == (observationDevice == nil ? pin.device : target.device)
                && UInt64(info.st_ino) == pin.inode
        }
        func expected(_ pin: PublicTreePin?) -> PublicTreePin? {
            guard let pin, observationDevice != nil else { return pin }
            return PublicTreePin(device: target.device, inode: pin.inode, owner: pin.owner,
                group: pin.group, mode: pin.mode, inventorySHA256: pin.inventorySHA256)
        }
        if let completedProjection {
            guard previous != nil, previous != .rolledBack,
                  try completedProjection() == expected(operation.after),
                  try identity(retained, unit.slot, operation.before),
                  try PublicTreeIO.observeOptional(retained.fd, name: unit.slot, inventory: old,
                    owner: owner, group: beforeGroup, attachment: retained.attachment,
                    priorReleaseGroup: unit.runtimeUpgrade ? group : nil) == expected(operation.before) else {
                throw PublicTreeFailure.changed
            }
            try parents(); try journalUnchanged()
            return .applied
        }
        if try identity(target, unit.name, operation.before), try identity(retained, unit.slot, operation.after) {
            guard previous != .applied,
                  try PublicTreeIO.observeOptional(target.fd, name: unit.name, inventory: old, owner: owner, group: beforeGroup, attachment: target.attachment, priorReleaseGroup: unit.runtimeUpgrade ? group : nil) == expected(operation.before),
                  try PublicTreeIO.observeOptional(retained.fd, name: unit.slot, inventory: new, owner: owner, group: group, attachment: retained.attachment) == expected(operation.after) else { throw PublicTreeFailure.changed }
            try rememberFastSnapshots(.staged)
            try parents()
            return .staged
        }
        guard previous != nil, previous != .rolledBack,
              try identity(target, unit.name, operation.after), try identity(retained, unit.slot, operation.before),
              try PublicTreeIO.observeOptional(target.fd, name: unit.name, inventory: new, owner: owner, group: group, attachment: target.attachment) == expected(operation.after),
              try PublicTreeIO.observeOptional(retained.fd, name: unit.slot, inventory: old, owner: owner, group: beforeGroup, attachment: retained.attachment, priorReleaseGroup: unit.runtimeUpgrade ? group : nil) == expected(operation.before) else { throw PublicTreeFailure.changed }
        try rememberFastSnapshots(.applied)
        try parents()
        return .applied
    }

    // ComponentTransition calls this only after its service barrier has
    // disabled the broker and confirmed both it and the owner app quiescent.
    // The snapshot is process-local; a new helper must re-hash everything.
    func enableQuiescedFastState() throws {
        guard completedProjection == nil, fastSnapshots != nil, !fastStateEnabled else {
            throw PublicTreeFailure.barrier
        }
        try requireQuiescent()
        _ = try fastState()
        fastStateEnabled = true
    }

    // Read-only completed-predecessor proofs hold maintenance leases and give
    // every tree a barrier closure that always refuses writes. After the first
    // content-hash pass, later proof checks can compare the metadata snapshot.
    func enableVerifiedReadOnlyFastState() throws {
        guard !fastStateEnabled else { throw PublicTreeFailure.barrier }
        // A projected tree is already guarded by the typed completed-projection
        // callback. Keep its original full verifier for this specialized path.
        guard completedProjection == nil else { return }
        guard fastSnapshots != nil else { throw PublicTreeFailure.barrier }
        _ = try fastState()
        fastStateEnabled = true
    }

    private func rememberFastSnapshots(_ state: State) throws {
        guard fastSnapshots == nil, completedProjection == nil else { return }
        var snapshots: [UInt64: [String: PublicTreeIO.FastObject]] = [:]
        func remember(_ pin: PublicTreePin?, _ inventory: PublicTreeInventory,
                      _ parent: Parent, _ name: String, _ contentGroup: gid_t, _ prior: gid_t?) throws {
            guard let pin else { return }
            guard let snapshot = try PublicTreeIO.fastSnapshot(parent.fd, name: name, inventory: inventory,
                    owner: owner, group: contentGroup, attachment: parent.attachment, priorReleaseGroup: prior),
                  snapshot[""]?.inode == pin.inode,
                  snapshots.updateValue(snapshot, forKey: pin.inode) == nil else { throw PublicTreeFailure.changed }
        }
        if state == .staged {
            try remember(operation.before, old, target, unit.name, beforeGroup,
                         unit.runtimeUpgrade ? group : nil)
            try remember(operation.after, new, retained, unit.slot, group, nil)
        } else {
            try remember(operation.after, new, target, unit.name, group, nil)
            try remember(operation.before, old, retained, unit.slot, beforeGroup,
                         unit.runtimeUpgrade ? group : nil)
        }
        fastSnapshots = snapshots
    }

    private func fastState() throws -> State {
        guard let fastSnapshots else { throw PublicTreeFailure.barrier }
        try parents(); try journalUnchanged()
        func pinPresent(_ parent: Parent, _ name: String, _ pin: PublicTreePin?) throws -> Bool {
            var info = stat(); errno = 0
            if fstatat(parent.fd, name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
                guard errno == ENOENT else { throw PublicTreeFailure.changed }
                return pin == nil
            }
            guard let pin, info.st_mode & S_IFMT == S_IFDIR,
                  info.st_dev == (observationDevice == nil ? pin.device : target.device),
                  UInt64(info.st_ino) == pin.inode else { return false }
            return true
        }
        let targetBefore = try pinPresent(target, unit.name, operation.before)
        let targetAfter = try pinPresent(target, unit.name, operation.after)
        let retainedBefore = try pinPresent(retained, unit.slot, operation.before)
        let retainedAfter = try pinPresent(retained, unit.slot, operation.after)
        let current: State
        if targetBefore && retainedAfter { current = .staged }
        else if targetAfter && retainedBefore { current = .applied }
        else { throw PublicTreeFailure.changed }
        let previous = try history.last.map { try event($0, sequence: history.count - 1) }
        if current == .staged {
            guard previous != .applied else { throw PublicTreeFailure.changed }
        } else {
            guard previous != nil, previous != .rolledBack else { throw PublicTreeFailure.changed }
        }
        func compare(_ parent: Parent, _ name: String, _ inventory: PublicTreeInventory,
                     _ pin: PublicTreePin?, _ contentGroup: gid_t, _ prior: gid_t?) throws {
            let observed = try PublicTreeIO.fastSnapshot(parent.fd, name: name, inventory: inventory,
                owner: owner, group: contentGroup, attachment: parent.attachment, priorReleaseGroup: prior)
            guard observed == pin.flatMap({ fastSnapshots[$0.inode] }) else { throw PublicTreeFailure.changed }
        }
        if current == .staged {
            try compare(target, unit.name, old, operation.before, beforeGroup,
                        unit.runtimeUpgrade ? group : nil)
            try compare(retained, unit.slot, new, operation.after, group, nil)
        } else {
            try compare(target, unit.name, new, operation.after, group, nil)
            try compare(retained, unit.slot, old, operation.before, beforeGroup,
                        unit.runtimeUpgrade ? group : nil)
        }
        return current
    }

    // The caller still has to qualify the completed global transition. This
    // evidence merely binds its valid local history and applied view. Recovery
    // can finish globally after an exchange whose local acknowledgment was lost.
    func completedEvidence() throws -> Data {
        guard !history.isEmpty, try state() == .applied else { throw PublicTreeFailure.journal }
        let raw = try journalEvidence()
        guard try state() == .applied else { throw PublicTreeFailure.changed }
        return raw
    }

    // History-only recheck for a caller that already owns a completed proof.
    // This method makes no claim about the current or retained tree contents.
    func journalEvidence() throws -> Data {
        try parents(); try journalUnchanged()
        guard let intentRecord else { throw PublicTreeFailure.journal }
        let value: [String: Any] = ["schema": 1,
            "intent_sha256": PublicTreeInventory.digest(intentRecord.data),
            "event_sha256": history.map { PublicTreeInventory.digest($0.data) }]
        let raw = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
        try journalUnchanged()
        try parents()
        return raw
    }

    // Used only by a separately validated successor to supply its original
    // before tree. Both views, parent attachments and the journal are checked.
    func originalObservation() throws -> PublicTreePin? {
        guard completedProjection == nil, observationDevice == nil else { throw PublicTreeFailure.invalid }
        let current = try state()
        let parent = current == .staged ? target : retained
        let name = current == .staged ? unit.name : unit.slot
        let result = try PublicTreeIO.observeOptional(parent.fd, name: name, inventory: old,
            owner: owner, group: beforeGroup, attachment: parent.attachment,
            priorReleaseGroup: unit.runtimeUpgrade ? group : nil)
        guard result == operation.before, try state() == current else { throw PublicTreeFailure.changed }
        return result
    }

    func apply() throws { try exchange(forward: true) }
    func reverse() throws { try exchange(forward: false) }
    private func exchange(forward: Bool) throws {
        guard observationDevice == nil, completedProjection == nil else { throw PublicTreeFailure.journal }
        try requireQuiescent()
        let wanted: State = forward ? .staged : .applied
        if try state() != wanted { return }
        try append(forward ? .applyIntent : .rollbackIntent)
        try fault(.afterIntent); try requireQuiescent()
        guard try state() == wanted else { throw PublicTreeFailure.changed }
        try fault(.beforeRename); try requireQuiescent()
        guard try state() == wanted else { throw PublicTreeFailure.changed }
        try parents()
        let renamed: Int32
        if operation.before != nil && operation.after != nil {
            renamed = renameatx_np(retained.fd, unit.slot, target.fd, unit.name, UInt32(RENAME_SWAP))
        } else if (operation.before == nil) == forward {
            renamed = renameatx_np(retained.fd, unit.slot, target.fd, unit.name, UInt32(RENAME_EXCL))
        } else {
            renamed = renameatx_np(target.fd, unit.name, retained.fd, unit.slot, UInt32(RENAME_EXCL))
        }
        guard renamed == 0, fsync(retained.fd) == 0, fsync(target.fd) == 0 else { throw PublicTreeFailure.changed }
        try parents()
        try fault(.afterRename); try requireQuiescent()
        guard try state() != wanted else { throw PublicTreeFailure.changed }
        try append(forward ? .applied : .rolledBack)
        try fault(.afterAcknowledgment)
    }
}
