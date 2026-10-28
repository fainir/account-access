// The system job owns the socket namespace across daemon generations. This
// class only activates/duplicates its inherited listeners; it never binds,
// adopts a PID, removes a path or falls back to creating replacement sockets.
import Foundation
import Darwin

enum RootListenerFailure: String, Error {
    case unavailable = "broker_socket_activation_unavailable"
    case invalid = "broker_socket_activation_invalid"
    case busy = "broker_socket_activation_in_use"
    case context = "broker_socket_activation_context_invalid"
    case metadata = "broker_socket_activation_metadata_invalid"
    case changed = "broker_socket_activation_identity_changed"
}

final class RootActivatedListeners {
    static let agentName = "AccountAccessAgent"
    static let ownerName = "AccountAccessOwner"
    private struct Entry {
        let fd: Int32
        let path: String
        let group: gid_t
        let mode: mode_t
        let device: dev_t
        let inode: ino_t
        let descriptor: WorkerListenerBindings.Descriptor
        let binding: WorkerListenerBindings.Record
    }
    struct Lease {
        let descriptors: [Int32]
        let bindings: WorkerListenerBindings
        fileprivate init(descriptors: [Int32], bindings: WorkerListenerBindings) {
            self.descriptors = descriptors; self.bindings = bindings
        }
    }
    private let entries: [Entry]
    private let brokerUID: uid_t
    private let agentUID: uid_t
    private let lock = NSLock()
    private var claimed = false

    private static func activate(_ name: String) throws -> Int32 {
        var fd: Int32 = -1
        guard AccountAccessActivateSocket(name, &fd) == 0, fd >= 3 else { throw RootListenerFailure.unavailable }
        return fd
    }
    private static func metadata(_ fd: Int32, path: String, group: gid_t, mode: mode_t,
                                 descriptor: WorkerListenerBindings.Descriptor) throws -> stat {
        _ = try WorkerLaunchPaths.protected(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        try MacWorkerBootstrap.checkFD(fd, type: S_IFSOCK)
        guard try WorkerListenerBindings.descriptor(fd) == descriptor else { throw RootListenerFailure.changed }
        try WorkerLaunchPaths.rejectGrantACL(path)
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK,
              info.st_uid == 0, info.st_gid == group, info.st_mode & 0o7777 == mode, info.st_nlink == 1 else {
            throw RootListenerFailure.metadata
        }
        try MacWorkerBootstrap.requireListening(fd)
        return info
    }
    private static func configure(_ fd: Int32, path: String, group: gid_t, mode: mode_t,
                                  descriptor: WorkerListenerBindings.Descriptor) throws {
        // launchd's initial filesystem mode can reflect its creation mask.
        // Only the owning job may normalize its freshly activated root socket.
        // Acquiring it for a later worker never repairs changed metadata.
        _ = try WorkerLaunchPaths.protected(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        // Named activation is the role authority. Modern launchd can rename
        // its socket vnode while getsockname retains the original bind name.
        // Preserve the actual descriptor identity; never adopt an arbitrary FD.
        try MacWorkerBootstrap.checkFD(fd, type: S_IFSOCK)
        guard try WorkerListenerBindings.descriptor(fd) == descriptor else { throw RootListenerFailure.changed }
        try WorkerLaunchPaths.rejectGrantACL(path)
        var before = stat(), after = stat()
        guard lstat(path, &before) == 0, before.st_mode & S_IFMT == S_IFSOCK, before.st_uid == 0,
              chown(path, 0, group) == 0, chmod(path, mode) == 0,
              lstat(path, &after) == 0, after.st_uid == 0, after.st_mode & S_IFMT == S_IFSOCK,
              after.st_dev == before.st_dev, after.st_ino == before.st_ino else {
            throw RootListenerFailure.metadata
        }
    }
    init(plan: MacWorkerPlan) throws {
        try RootVaultKeyStore.requireDaemon()
        // Parent crash cleanup belongs to this launchd job's process group.
        guard getppid() == 1, getpgrp() == getpid(), let user = getpwuid(plan.agentUID) else {
            throw RootListenerFailure.context
        }
        let group = user.pointee.pw_gid
        var acquired: [Entry] = []
        do {
            for (role, name, path, group, mode) in [(UInt8(1), Self.agentName, plan.agentSocket, group, mode_t(0o660)),
                                              (UInt8(2), Self.ownerName, plan.ownerSocket, gid_t(0), mode_t(0o600))] {
                let fd = try Self.activate(name)
                do {
                    try MacWorkerBootstrap.checkFD(fd, type: S_IFSOCK)
                    let socket = try WorkerListenerBindings.descriptor(fd)
                    try Self.configure(fd, path: path, group: group, mode: mode, descriptor: socket)
                    let info = try Self.metadata(fd, path: path, group: group, mode: mode, descriptor: socket)
                    // The launchd source tag is minted only here, immediately
                    // following this private exact-name activation call.
                    let binding = WorkerListenerBindings.Record(role: role, source: 1,
                        descriptorDevice: socket.device, descriptorInode: socket.inode,
                        pathDevice: Int64(info.st_dev), pathInode: UInt64(info.st_ino),
                        pathDigest: WorkerListenerBindings.digest(path), addressDigest: WorkerListenerBindings.digest(socket.address))
                    acquired.append(Entry(fd: fd, path: path, group: group, mode: mode, device: info.st_dev,
                                          inode: info.st_ino, descriptor: socket, binding: binding))
                } catch { Darwin.close(fd); throw error }
            }
        } catch { acquired.forEach { Darwin.close($0.fd) }; throw error }
        entries = acquired; brokerUID = plan.uid; agentUID = plan.agentUID
    }
    func acquire(for plan: MacWorkerPlan) throws -> Lease {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard !claimed else { throw RootListenerFailure.busy }
        guard getppid() == 1, getpgrp() == getpid(), plan.uid == brokerUID, plan.agentUID == agentUID,
              entries.map({ $0.path }) == [plan.agentSocket, plan.ownerSocket] else { throw RootListenerFailure.invalid }
        var copies: [Int32] = []
        do {
            for entry in entries {
                let info = try Self.metadata(entry.fd, path: entry.path, group: entry.group, mode: entry.mode,
                                             descriptor: entry.descriptor)
                guard info.st_dev == entry.device, info.st_ino == entry.inode else { throw RootListenerFailure.changed }
                let copy = fcntl(entry.fd, F_DUPFD_CLOEXEC, 10)
                guard copy >= 10 else { throw RootListenerFailure.unavailable }
                copies.append(copy)
            }
        } catch { copies.forEach { Darwin.close($0) }; throw error }
        let bindings: WorkerListenerBindings
        do { bindings = try WorkerListenerBindings(records: entries.map({ $0.binding })) }
        catch { copies.forEach { Darwin.close($0) }; throw error }
        claimed = true
        return Lease(descriptors: copies, bindings: bindings)
    }
    func release() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard claimed else { throw RootListenerFailure.invalid }
        claimed = false
    }
    deinit { entries.forEach { Darwin.close($0.fd) } }
}
