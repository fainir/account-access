// Atomic publication of one immutable metadata binding. The caller holds the
// enrollment lock and revalidates its attached journal and authority at each
// checkpoint. A crash can leave only a matching bounded pending prefix, which
// the same authorized operation can finish without replacing any existing file.
import Foundation
import Darwin

enum RootStoreVolumePublication {
    static let pendingName = "pending-volume-v1.json"
    enum Phase { case created, partial, synced, published }

    static func publish(directory: Int32, data: Data, verify: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw RootStoreVolumeFailure.unavailable }
        try publish(directory: directory, data: data, owner: 0, verify: verify, fault: { _ in })
    }
    private static func check(_ fd: Int32, owner: uid_t, directory: Bool) throws -> stat {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == owner,
              info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o7777 == (directory ? 0o700 : 0o600),
              info.st_nlink > 0, directory || (info.st_nlink == 1 && info.st_size >= 0 && info.st_size <= 512) else {
            throw RootStoreVolumeFailure.invalid
        }
        errno = 0
        if let acl = acl_get_fd(fd) {
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            errno = 0
            guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == -1, errno == EINVAL else {
                throw RootStoreVolumeFailure.invalid
            }
        } else if errno != ENOENT { throw RootStoreVolumeFailure.invalid }
        return info
    }
    private static func same(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_uid == rhs.st_uid
            && lhs.st_gid == rhs.st_gid && lhs.st_mode == rhs.st_mode && lhs.st_nlink == rhs.st_nlink
            && lhs.st_size == rhs.st_size && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }
    private static func read(_ parent: Int32, name: String, fd: Int32, owner: uid_t) throws -> Data {
        let before = try check(fd, owner: owner, directory: false)
        guard lseek(fd, 0, SEEK_SET) == 0 else { throw RootStoreVolumeFailure.unavailable }
        var bytes = [UInt8](repeating: 0, count: 513), result = Data(), path = stat()
        while result.count <= 512 {
            let count = Darwin.read(fd, &bytes, bytes.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw RootStoreVolumeFailure.unavailable }
            if count == 0 { break }
            result.append(contentsOf: bytes.prefix(count))
        }
        guard result.count == before.st_size,
              same(before, try check(fd, owner: owner, directory: false)),
              fstatat(parent, name, &path, AT_SYMLINK_NOFOLLOW) == 0, same(before, path) else {
            throw RootStoreVolumeFailure.changed
        }
        return result
    }
    private static func publish(directory: Int32, data: Data, owner: uid_t,
                                verify: () throws -> Void, fault: (Phase) throws -> Void) throws {
        guard !data.isEmpty, data.count <= 512 else { throw RootStoreVolumeFailure.invalid }
        _ = try check(directory, owner: owner, directory: true)
        try verify()
        let existing = openat(directory, RootStoreVolumeBinding.name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if existing >= 0 {
            defer { Darwin.close(existing) }
            guard try read(directory, name: RootStoreVolumeBinding.name, fd: existing, owner: owner) == data else {
                throw RootStoreVolumeFailure.changed
            }
            var pending = stat()
            guard fstatat(directory, pendingName, &pending, AT_SYMLINK_NOFOLLOW) == -1, errno == ENOENT else {
                throw RootStoreVolumeFailure.changed
            }
            try verify(); return
        }
        guard errno == ENOENT else { throw RootStoreVolumeFailure.invalid }
        var fd = openat(directory, pendingName, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        let created = fd >= 0
        if fd < 0, errno == EEXIST { fd = openat(directory, pendingName, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK) }
        guard fd >= 0 else { throw RootStoreVolumeFailure.unavailable }; defer { Darwin.close(fd) }
        let prefix = try read(directory, name: pendingName, fd: fd, owner: owner)
        guard data.starts(with: prefix) else { throw RootStoreVolumeFailure.changed }
        if created { try fault(.created) }
        try verify()
        try data.withUnsafeBytes { bytes in
            var offset = prefix.count
            while offset < bytes.count {
                // Small bounded writes make the interruption seam exercise a
                // real prefix; ordinary production retry uses the same path.
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), min(64, bytes.count - offset))
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw RootStoreVolumeFailure.unavailable }
                offset += count
                if offset < bytes.count { try fault(.partial) }
            }
        }
        guard fsync(fd) == 0, try read(directory, name: pendingName, fd: fd, owner: owner) == data else {
            throw RootStoreVolumeFailure.unavailable
        }
        try fault(.synced); try verify()
        guard renameatx_np(directory, pendingName, directory, RootStoreVolumeBinding.name, UInt32(RENAME_EXCL)) == 0,
              fsync(directory) == 0 else { throw RootStoreVolumeFailure.unavailable }
        try fault(.published); try verify()
        guard try read(directory, name: RootStoreVolumeBinding.name, fd: fd, owner: owner) == data else {
            throw RootStoreVolumeFailure.changed
        }
    }
#if ACCOUNT_ACCESS_STORE_VOLUME_CHECKS
    static func fixture(directory: Int32, data: Data, verify: () throws -> Void = {},
                        fault: (Phase) throws -> Void = { _ in }) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw RootStoreVolumeFailure.unavailable }
        try publish(directory: directory, data: data, owner: getuid(), verify: verify, fault: fault)
    }
#endif
}
