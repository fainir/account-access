// In-development verified-attachment primitive; no installed operation.
// The caller must qualify the trusted anchor and every immutable route pin.
import Foundation
import Darwin

struct PublicTreeDirectoryIdentity: Equatable {
    let device: Int32
    let inode: UInt64
    let owner: uid_t
    let group: gid_t
    let mode: mode_t
    init(_ info: stat) {
        device = info.st_dev; inode = UInt64(info.st_ino)
        owner = info.st_uid; group = info.st_gid; mode = info.st_mode & 0o7777
    }
    // This reads metadata, not trust authority. Production must obtain the
    // expected value from its qualified fixed-root loader; fixtures use new FDs.
    static func observe(_ fd: Int32, owner: uid_t, group: gid_t) throws -> Self {
        let info = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        try PublicTreeIO.noACL(fd)
        guard info.st_gid == group, info.st_nlink > 0 else { throw PublicTreeFailure.changed }
        return Self(info)
    }
    fileprivate func check(_ fd: Int32) throws -> stat {
        let info = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        try PublicTreeIO.noACL(fd)
        guard info.st_nlink > 0, Self(info) == self else { throw PublicTreeFailure.changed }
        return info
    }
}

struct PublicTreeAncestorName: Equatable {
    let value: String
    init(_ value: String) throws {
        guard try InstallerPayloadManifest.components(value).count == 1,
              value.utf8.count <= 255 else { throw PublicTreeFailure.invalid }
        self.value = value
    }
}
struct PublicTreeAncestorStep: Equatable {
    let name: PublicTreeAncestorName
    let identity: PublicTreeDirectoryIdentity
}
enum PublicTreeParentRole: Equatable {
    case target(PublicTreeUnit), retained(PublicTreeUnit), journal(PublicTreeUnit)
    var mode: mode_t {
        switch self { case .target: return 0o755; case .retained, .journal: return 0o700 }
    }
    func mayObserve(_ unit: PublicTreeUnit) -> Bool { self == .target(unit) || self == .retained(unit) }
}

final class PublicTreeTrustedAnchor {
    fileprivate let fd: Int32
    fileprivate let identity: PublicTreeDirectoryIdentity
    private init(fd: Int32, identity: PublicTreeDirectoryIdentity) { self.fd = fd; self.identity = identity }
    deinit { Darwin.close(fd) }
    // Qualification of the anchor's canonical attachment is an external
    // precondition. A descriptor alone cannot prove ancestors above itself.
    static func acceptVerifiedDescriptor(_ supplied: Int32, expected: PublicTreeDirectoryIdentity) throws -> PublicTreeTrustedAnchor {
        let fd = fcntl(supplied, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw PublicTreeFailure.invalid }
        do {
            _ = try expected.check(fd)
            return PublicTreeTrustedAnchor(fd: fd, identity: expected)
        } catch { Darwin.close(fd); throw error }
    }
}

final class PublicTreeAttachment {
    let role: PublicTreeParentRole
    private let anchor: PublicTreeTrustedAnchor
    private let steps: [PublicTreeAncestorStep]
    private let leaf: PublicTreeDirectoryIdentity
    // The caller qualified this exact canonical directory identity at bind.
    // Its group is independent of any old/new tree moved beneath it.
    var parentGroup: gid_t { leaf.group }
    private init(anchor: PublicTreeTrustedAnchor, steps: [PublicTreeAncestorStep], role: PublicTreeParentRole) {
        self.anchor = anchor; self.steps = steps; self.role = role
        leaf = steps.last?.identity ?? anchor.identity
    }
    static func bind(anchor: PublicTreeTrustedAnchor, steps: [PublicTreeAncestorStep], role: PublicTreeParentRole,
                     parentFD: Int32, owner: uid_t, group: gid_t) throws -> PublicTreeAttachment {
        guard steps.count <= 128, steps.map({ $0.name.value.utf8.count + 1 }).reduce(0, +) <= 4096 else {
            throw PublicTreeFailure.invalid
        }
        let value = PublicTreeAttachment(anchor: anchor, steps: steps, role: role)
        try value.verify(parentFD, role: role, owner: owner, group: group, mode: role.mode)
        return value
    }
    func verify(_ parentFD: Int32, role expectedRole: PublicTreeParentRole, owner: uid_t, group: gid_t, mode: mode_t) throws {
        guard role == expectedRole, leaf.owner == owner, leaf.group == group,
              leaf.mode == mode, mode == role.mode else { throw PublicTreeFailure.invalid }
        let first = fcntl(anchor.fd, F_DUPFD_CLOEXEC, 0)
        guard first >= 0 else { throw PublicTreeFailure.invalid }
        var held = [first]
        var before: [stat] = [], pathBefore: [stat] = []
        defer { held.forEach { Darwin.close($0) } }
        before.append(try anchor.identity.check(first))
        for step in steps {
            let parent = held.last!
            var path = stat()
            guard fstatat(parent, step.name.value, &path, AT_SYMLINK_NOFOLLOW) == 0,
                  path.st_mode & S_IFMT == S_IFDIR,
                  PublicTreeDirectoryIdentity(path) == step.identity else { throw PublicTreeFailure.changed }
            let child = openat(parent, step.name.value, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard child >= 0 else { throw PublicTreeFailure.changed }
            held.append(child)
            let info = try step.identity.check(child)
            guard info.st_gid == path.st_gid, InstallerPayloadIO.same(path, info) else { throw PublicTreeFailure.changed }
            pathBefore.append(path); before.append(info)
        }
        let parentBefore = try leaf.check(parentFD)
        guard PublicTreeDirectoryIdentity(parentBefore) == PublicTreeDirectoryIdentity(before.last!) else {
            throw PublicTreeFailure.changed
        }
        // Keep every intermediate FD open until every route edge has been
        // checked again. Persistent pins omit times; each walk is time-stable.
        for (index, step) in steps.enumerated() {
            var path = stat()
            guard fstatat(held[index], step.name.value, &path, AT_SYMLINK_NOFOLLOW) == 0,
                  path.st_gid == pathBefore[index].st_gid,
                  InstallerPayloadIO.same(pathBefore[index], path) else { throw PublicTreeFailure.changed }
        }
        for (index, fd) in held.enumerated() {
            let expected = index == 0 ? anchor.identity : steps[index - 1].identity
            let current = try expected.check(fd)
            guard current.st_gid == before[index].st_gid, InstallerPayloadIO.same(before[index], current) else {
                throw PublicTreeFailure.changed
            }
        }
        let parentAfter = try leaf.check(parentFD)
        guard parentAfter.st_gid == parentBefore.st_gid, InstallerPayloadIO.same(parentBefore, parentAfter) else {
            throw PublicTreeFailure.changed
        }
    }
}
