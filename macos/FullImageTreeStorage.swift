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
    case runtimeOwner, pythonRoot, runtimeRoot, browsers, wheels
    // The first complete-image release has a separate closed set. Adding a
    // successor tree must never expand that release's accepted plan.
    static let fullImageCases: [Self] = [.owner, .project, .distInfo, .pythonProvider, .provider,
        .pythonPip, .pythonOldPipInfo, .pythonPipInfo, .pythonEnsurePip,
        .runtimePip, .runtimeOldPipInfo, .runtimePipInfo, .runtimeEnsurePip]
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
        }
    }
    var beforePresent: Bool { ![Self.pythonPipInfo, .runtimePipInfo].contains(self) }
    var afterPresent: Bool { ![Self.pythonOldPipInfo, .runtimeOldPipInfo].contains(self) }
    var runtimeUpgrade: Bool { [.runtimeOwner, .pythonRoot, .runtimeRoot, .browsers, .wheels].contains(self) }
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
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        guard path.st_gid == rootGroup, InstallerPayloadIO.same(path, before), before.st_gid == rootGroup else { throw PublicTreeFailure.changed }
        try metadata(fd, inventory: inventory, owner: owner, group: group, priorReleaseGroup: priorReleaseGroup)
        _ = try InstallerPayloadIO.verify(fd, tree: tree, owner: owner)
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

    private init(operation: PublicTreeOperation, unit: PublicTreeUnit, old: PublicTreeInventory, new: PublicTreeInventory,
        target: Parent, retained: Parent, journal: Parent, owner: uid_t, group: gid_t, beforeGroup: gid_t,
        requireQuiescent: @escaping () throws -> Void, fault: @escaping (Phase) throws -> Void,
        observationDevice: Int32?) {
        self.operation = operation; self.unit = unit; self.old = old; self.new = new
        self.target = target; self.retained = retained; self.journal = journal
        self.owner = owner; self.group = group; self.beforeGroup = beforeGroup
        self.requireQuiescent = requireQuiescent; self.fault = fault
        self.observationDevice = observationDevice
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
        fault: @escaping (Phase) throws -> Void = { _ in }) throws -> PublicTreeStorage {
        let beforeGroup = beforeGroup ?? group
        guard observationDevice == nil || (!createIfMissing && observationDevice! >= 0) else { throw PublicTreeFailure.invalid }
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
            requireQuiescent: requireQuiescent, fault: fault, observationDevice: observationDevice)
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
        guard observationDevice == nil else { throw PublicTreeFailure.journal }
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
        if try identity(target, unit.name, operation.before), try identity(retained, unit.slot, operation.after) {
            guard previous != .applied,
                  try PublicTreeIO.observeOptional(target.fd, name: unit.name, inventory: old, owner: owner, group: beforeGroup, attachment: target.attachment, priorReleaseGroup: unit.runtimeUpgrade ? group : nil) == expected(operation.before),
                  try PublicTreeIO.observeOptional(retained.fd, name: unit.slot, inventory: new, owner: owner, group: group, attachment: retained.attachment) == expected(operation.after) else { throw PublicTreeFailure.changed }
            try parents()
            return .staged
        }
        guard previous != nil, previous != .rolledBack,
              try identity(target, unit.name, operation.after), try identity(retained, unit.slot, operation.before),
              try PublicTreeIO.observeOptional(target.fd, name: unit.name, inventory: new, owner: owner, group: group, attachment: target.attachment) == expected(operation.after),
              try PublicTreeIO.observeOptional(retained.fd, name: unit.slot, inventory: old, owner: owner, group: beforeGroup, attachment: retained.attachment, priorReleaseGroup: unit.runtimeUpgrade ? group : nil) == expected(operation.before) else { throw PublicTreeFailure.changed }
        try parents()
        return .applied
    }

    func apply() throws { try exchange(forward: true) }
    func reverse() throws { try exchange(forward: false) }
    private func exchange(forward: Bool) throws {
        guard observationDevice == nil else { throw PublicTreeFailure.journal }
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
