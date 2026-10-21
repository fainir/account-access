// In-development directory-storage primitive; not installed or updater-ready.
// No installed-path lookup, service control, owner-policy access or controller.
import Foundation
import CryptoKit
import Darwin

enum PublicTreeFailure: Error { case invalid, changed, journal, barrier }
enum PublicTreeUnit: String, CaseIterable {
    case owner, project, distInfo, provider
    var path: String {
        switch self {
        case .owner: return "owner.app"
        case .project: return "runtime/lib/python3.12/site-packages/account_access"
        case .distInfo: return "runtime/lib/python3.12/site-packages/account_access-0.8.0.dist-info"
        case .provider: return "runtime/libexec/bitwarden"
        }
    }
    var name: String { String(path.split(separator: "/").last!) }
    var slot: String { "slot-" + rawValue }
}

struct PublicTreeInventory {
    let unit: PublicTreeUnit
    let tree: InstallerPayloadTree
    let manifestSHA256: String
    let inventorySHA256: String
    init(manifest: Data, unit: PublicTreeUnit) throws {
        let parsed = try InstallerPayloadManifest(manifest)
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
        guard nodes[""]?.kind == "directory", nodes[""]?.mode == 0o755 else { throw PublicTreeFailure.invalid }
        self.unit = unit; tree = InstallerPayloadTree(nodes: nodes, children: children)
        manifestSHA256 = parsed.sha256
        inventorySHA256 = Self.digest(try JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys, .withoutEscapingSlashes]))
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
    let before: PublicTreePin
    let after: PublicTreePin
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
    static func metadata(_ fd: Int32, inventory: PublicTreeInventory, owner: uid_t, group: gid_t, name: String = "") throws {
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        try noACL(fd)
        guard before.st_gid == group, before.st_mode & 0o7777 == inventory.tree.nodes[name]?.mode,
              before.st_nlink > 0,
              try InstallerPayloadIO.contents(fd) == (inventory.tree.children[name] ?? []) else { throw PublicTreeFailure.changed }
        for child in (inventory.tree.children[name] ?? []).sorted() {
            let relative = name.isEmpty ? child : name + "/" + child
            let node = inventory.tree.nodes[relative]!
            var info = stat()
            guard fstatat(fd, child, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_uid == owner,
                  info.st_gid == group, info.st_dev == before.st_dev,
                  info.st_mode & 0o6000 == 0 else { throw PublicTreeFailure.changed }
            if node.kind == "symlink" {
                guard info.st_mode & S_IFMT == S_IFLNK, info.st_nlink == 1 else { throw PublicTreeFailure.changed }
                // O_SYMLINK opens this link itself; child is one validated component.
                let link = openat(fd, child, O_RDONLY | O_SYMLINK | O_CLOEXEC | O_NONBLOCK)
                guard link >= 0 else { throw PublicTreeFailure.changed }
                do {
                    var held = stat(), current = stat()
                    guard fstat(link, &held) == 0, held.st_mode & S_IFMT == S_IFLNK,
                          held.st_gid == group, InstallerPayloadIO.same(info, held) else { throw PublicTreeFailure.changed }
                    try noLinkACL(link)
                    guard fstat(link, &current) == 0, current.st_gid == group,
                          InstallerPayloadIO.same(held, current) else { throw PublicTreeFailure.changed }
                } catch { Darwin.close(link); throw error }
                Darwin.close(link)
            } else {
                let opened = openat(fd, child, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (node.kind == "directory" ? O_DIRECTORY : 0))
                guard opened >= 0 else { throw PublicTreeFailure.changed }
                do {
                    let observed = try InstallerPayloadIO.check(opened, owner: owner, directory: node.kind == "directory")
                    try noACL(opened)
                    guard observed.st_gid == group, InstallerPayloadIO.same(info, observed) else { throw PublicTreeFailure.changed }
                    if node.kind == "directory" { try metadata(opened, inventory: inventory, owner: owner, group: group, name: relative) }
                } catch { Darwin.close(opened); throw error }
                Darwin.close(opened)
            }
            var after = stat()
            guard fstatat(fd, child, &after, AT_SYMLINK_NOFOLLOW) == 0, after.st_gid == group,
                  InstallerPayloadIO.same(info, after) else {
                throw PublicTreeFailure.changed
            }
        }
        let current = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        guard current.st_gid == group, InstallerPayloadIO.same(before, current) else {
            throw PublicTreeFailure.changed
        }
    }
    static func observe(_ parent: Int32, name: String, inventory: PublicTreeInventory, owner: uid_t, group: gid_t, attachment: PublicTreeAttachment) throws -> PublicTreePin {
        guard attachment.role.mayObserve(inventory.unit) else { throw PublicTreeFailure.invalid }
        try attachment.verify(parent, role: attachment.role, owner: owner, group: group, mode: attachment.role.mode)
        guard try InstallerPayloadManifest.components(name).count == 1 else { throw PublicTreeFailure.invalid }
        var path = stat()
        guard fstatat(parent, name, &path, AT_SYMLINK_NOFOLLOW) == 0, path.st_mode & S_IFMT == S_IFDIR else { throw PublicTreeFailure.changed }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw PublicTreeFailure.changed }
        defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        guard path.st_gid == group, InstallerPayloadIO.same(path, before), before.st_gid == group else { throw PublicTreeFailure.changed }
        try metadata(fd, inventory: inventory, owner: owner, group: group)
        _ = try InstallerPayloadIO.verify(fd, tree: inventory.tree, owner: owner)
        var after = stat()
        let current = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        guard fstatat(parent, name, &after, AT_SYMLINK_NOFOLLOW) == 0,
              after.st_gid == group, current.st_gid == group,
              InstallerPayloadIO.same(before, after), InstallerPayloadIO.same(before, current) else {
            throw PublicTreeFailure.changed
        }
        try attachment.verify(parent, role: attachment.role, owner: owner, group: group, mode: attachment.role.mode)
        return PublicTreePin(device: before.st_dev, inode: UInt64(before.st_ino), owner: owner, group: group,
            mode: UInt16(before.st_mode & 0o7777), inventorySHA256: inventory.inventorySHA256)
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
    private let owner: uid_t, group: gid_t
    private let requireQuiescent: () throws -> Void
    private let fault: (Phase) throws -> Void
    private var history: [Record] = []
    private var intentRecord: Record?

    private init(operation: PublicTreeOperation, unit: PublicTreeUnit, old: PublicTreeInventory, new: PublicTreeInventory,
        target: Parent, retained: Parent, journal: Parent, owner: uid_t, group: gid_t,
        requireQuiescent: @escaping () throws -> Void, fault: @escaping (Phase) throws -> Void) {
        self.operation = operation; self.unit = unit; self.old = old; self.new = new
        self.target = target; self.retained = retained; self.journal = journal
        self.owner = owner; self.group = group; self.requireQuiescent = requireQuiescent; self.fault = fault
    }
    deinit { Darwin.close(target.fd); Darwin.close(retained.fd); Darwin.close(journal.fd) }
    private static func encode<Value: Encodable>(_ value: Value) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    private static func parent(_ supplied: Int32, attachment: PublicTreeAttachment, role: PublicTreeParentRole, owner: uid_t, group: gid_t, mode: mode_t) throws -> Parent {
        try attachment.verify(supplied, role: role, owner: owner, group: group, mode: mode)
        let fd = dup(supplied)
        guard fd >= 0 else { throw PublicTreeFailure.invalid }
        do {
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw PublicTreeFailure.invalid }
            let info = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
            try PublicTreeIO.noACL(fd)
            guard info.st_gid == group, info.st_nlink > 0, info.st_mode & 0o7777 == mode else { throw PublicTreeFailure.invalid }
            return Parent(attachment: attachment, role: role, fd: fd, device: info.st_dev, inode: UInt64(info.st_ino), mode: mode)
        } catch { Darwin.close(fd); throw error }
    }
    static func capture(unit: PublicTreeUnit, targetParent: Int32, retainedParent: Int32,
        targetAttachment: PublicTreeAttachment, retainedAttachment: PublicTreeAttachment,
        old: PublicTreeInventory, new: PublicTreeInventory, owner: uid_t, group: gid_t, planSHA256: String) throws -> PublicTreeOperation {
        guard old.unit == unit, new.unit == unit, planSHA256.count == 64,
              planSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw PublicTreeFailure.invalid }
        for (fd, mode, attachment, role) in [(targetParent, mode_t(0o755), targetAttachment, PublicTreeParentRole.target(unit)),
                                             (retainedParent, mode_t(0o700), retainedAttachment, PublicTreeParentRole.retained(unit))] {
            try attachment.verify(fd, role: role, owner: owner, group: group, mode: mode)
            let info = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
            try PublicTreeIO.noACL(fd)
            guard info.st_gid == group, info.st_nlink > 0, info.st_mode & 0o7777 == mode else { throw PublicTreeFailure.invalid }
        }
        let before = try PublicTreeIO.observe(targetParent, name: unit.name, inventory: old, owner: owner, group: group, attachment: targetAttachment)
        let after = try PublicTreeIO.observe(retainedParent, name: unit.slot, inventory: new, owner: owner, group: group, attachment: retainedAttachment)
        try targetAttachment.verify(targetParent, role: .target(unit), owner: owner, group: group, mode: 0o755)
        try retainedAttachment.verify(retainedParent, role: .retained(unit), owner: owner, group: group, mode: 0o700)
        guard before.device == after.device, before.inode != after.inode,
              before.inventorySHA256 != after.inventorySHA256 else { throw PublicTreeFailure.invalid }
        return PublicTreeOperation(schema: 1, unit: unit.rawValue, planSHA256: planSHA256,
            beforeManifestSHA256: old.manifestSHA256, afterManifestSHA256: new.manifestSHA256, before: before, after: after)
    }
    static func open(operation: PublicTreeOperation, unit: PublicTreeUnit, targetParent: Int32, retainedParent: Int32,
        journalParent: Int32, targetAttachment: PublicTreeAttachment, retainedAttachment: PublicTreeAttachment,
        journalAttachment: PublicTreeAttachment, old: PublicTreeInventory, new: PublicTreeInventory, owner: uid_t, group: gid_t,
        requireQuiescent: @escaping () throws -> Void, fault: @escaping (Phase) throws -> Void = { _ in }) throws -> PublicTreeStorage {
        guard operation.schema == 1, operation.unit == unit.rawValue, old.unit == unit, new.unit == unit,
              operation.planSHA256.utf8.count == 64,
              operation.planSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              operation.beforeManifestSHA256 == old.manifestSHA256, operation.afterManifestSHA256 == new.manifestSHA256,
              operation.before.inventorySHA256 == old.inventorySHA256, operation.after.inventorySHA256 == new.inventorySHA256,
              operation.before.owner == owner, operation.after.owner == owner,
              operation.before.group == group, operation.after.group == group,
              operation.before.mode == 0o755, operation.after.mode == 0o755,
              operation.before.inode != operation.after.inode,
              operation.before.inventorySHA256 != operation.after.inventorySHA256 else { throw PublicTreeFailure.invalid }
        var opened: [Int32] = [], adopted = false
        defer { if !adopted { opened.forEach { Darwin.close($0) } } }
        let target = try parent(targetParent, attachment: targetAttachment, role: .target(unit), owner: owner, group: group, mode: 0o755); opened.append(target.fd)
        let retained = try parent(retainedParent, attachment: retainedAttachment, role: .retained(unit), owner: owner, group: group, mode: 0o700); opened.append(retained.fd)
        let journal = try parent(journalParent, attachment: journalAttachment, role: .journal(unit), owner: owner, group: group, mode: 0o700); opened.append(journal.fd)
        guard Set([target.inode, retained.inode, journal.inode]).count == 3,
              target.device == retained.device, retained.device == journal.device,
              operation.before.device == target.device, operation.after.device == target.device else { throw PublicTreeFailure.invalid }
        let value = PublicTreeStorage(operation: operation, unit: unit, old: old, new: new, target: target,
            retained: retained, journal: journal, owner: owner, group: group, requireQuiescent: requireQuiescent, fault: fault)
        adopted = true
        try value.prepareJournal()
        _ = try value.state()
        return value
    }
    private func parents() throws {
        for parent in [target, retained, journal] {
            try parent.attachment.verify(parent.fd, role: parent.role, owner: owner, group: group, mode: parent.mode)
            let info = try InstallerPayloadIO.check(parent.fd, owner: owner, directory: true)
            try PublicTreeIO.noACL(parent.fd)
            guard info.st_dev == parent.device, UInt64(info.st_ino) == parent.inode,
                  info.st_gid == group, info.st_nlink > 0, info.st_mode & 0o7777 == parent.mode else { throw PublicTreeFailure.changed }
        }
    }
    private func read(_ name: String) throws -> Record {
        try parents()
        let fd = openat(journal.fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw PublicTreeFailure.journal }
        defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        try PublicTreeIO.noACL(fd)
        guard before.st_gid == group, before.st_mode & 0o7777 == 0o600 else { throw PublicTreeFailure.journal }
        let data = try InstallerPayloadIO.read(fd, maximum: 4096, owner: owner)
        var info = stat()
        let current = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        guard fstatat(journal.fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_gid == group, current.st_gid == group,
              InstallerPayloadIO.same(before, info), InstallerPayloadIO.same(before, current) else { throw PublicTreeFailure.journal }
        try parents()
        return Record(data: data, device: before.st_dev, inode: UInt64(before.st_ino), mtimeSec: Int64(before.st_mtimespec.tv_sec),
            mtimeNsec: Int64(before.st_mtimespec.tv_nsec), ctimeSec: Int64(before.st_ctimespec.tv_sec), ctimeNsec: Int64(before.st_ctimespec.tv_nsec))
    }
    private func write(_ name: String, data: Data) throws -> Record {
        try parents()
        guard data.count <= 4096 else { throw PublicTreeFailure.journal }
        let fd = openat(journal.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw PublicTreeFailure.journal }
        defer { Darwin.close(fd) }
        let created = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        try PublicTreeIO.noACL(fd)
        guard created.st_gid == group, fchmod(fd, 0o600) == 0 else { throw PublicTreeFailure.journal }
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
    private func prepareJournal() throws {
        try parents()
        let names = try InstallerPayloadIO.contents(journal.fd), expected = try Self.encode(operation)
        if names.isEmpty { intentRecord = try write("intent.json", data: expected) }
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
        var a = stat(), b = stat()
        guard fstatat(target.fd, unit.name, &a, AT_SYMLINK_NOFOLLOW) == 0,
              fstatat(retained.fd, unit.slot, &b, AT_SYMLINK_NOFOLLOW) == 0 else { throw PublicTreeFailure.changed }
        if a.st_dev == operation.before.device, UInt64(a.st_ino) == operation.before.inode,
           b.st_dev == operation.after.device, UInt64(b.st_ino) == operation.after.inode {
            guard previous != .applied,
                  try PublicTreeIO.observe(target.fd, name: unit.name, inventory: old, owner: owner, group: group, attachment: target.attachment) == operation.before,
                  try PublicTreeIO.observe(retained.fd, name: unit.slot, inventory: new, owner: owner, group: group, attachment: retained.attachment) == operation.after else { throw PublicTreeFailure.changed }
            try parents()
            return .staged
        }
        guard previous != nil, previous != .rolledBack,
              a.st_dev == operation.after.device, UInt64(a.st_ino) == operation.after.inode,
              b.st_dev == operation.before.device, UInt64(b.st_ino) == operation.before.inode,
              try PublicTreeIO.observe(target.fd, name: unit.name, inventory: new, owner: owner, group: group, attachment: target.attachment) == operation.after,
              try PublicTreeIO.observe(retained.fd, name: unit.slot, inventory: old, owner: owner, group: group, attachment: retained.attachment) == operation.before else { throw PublicTreeFailure.changed }
        try parents()
        return .applied
    }
    func apply() throws { try exchange(forward: true) }
    func reverse() throws { try exchange(forward: false) }
    private func exchange(forward: Bool) throws {
        try requireQuiescent()
        let wanted: State = forward ? .staged : .applied
        if try state() != wanted { return }
        try append(forward ? .applyIntent : .rollbackIntent)
        try fault(.afterIntent); try requireQuiescent()
        guard try state() == wanted else { throw PublicTreeFailure.changed }
        try fault(.beforeRename); try requireQuiescent()
        guard try state() == wanted else { throw PublicTreeFailure.changed }
        try parents()
        guard renameatx_np(retained.fd, unit.slot, target.fd, unit.name, UInt32(RENAME_SWAP)) == 0,
              fsync(retained.fd) == 0, fsync(target.fd) == 0 else { throw PublicTreeFailure.changed }
        try parents()
        try fault(.afterRename); try requireQuiescent()
        guard try state() != wanted else { throw PublicTreeFailure.changed }
        try append(forward ? .applied : .rolledBack)
        try fault(.afterAcknowledgment)
    }
}
