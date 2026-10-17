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
    private static func metadata(_ fd: Int32, path: String, group: gid_t, mode: mode_t) throws -> stat {
        _ = try WorkerLaunchPaths.protected(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        try MacWorkerBootstrap.checkFD(fd, type: S_IFSOCK, socketPath: path)
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK,
              info.st_uid == 0, info.st_gid == group, info.st_mode & 0o7777 == mode else {
            throw RootListenerFailure.metadata
        }
        try MacWorkerBootstrap.requireListening(fd)
        return info
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
            for (name, path, group, mode) in [(Self.agentName, plan.agentSocket, group, mode_t(0o660)),
                                              (Self.ownerName, plan.ownerSocket, gid_t(0), mode_t(0o600))] {
                let fd = try Self.activate(name)
                do {
                    let info = try Self.metadata(fd, path: path, group: group, mode: mode)
                    acquired.append(Entry(fd: fd, path: path, group: group, mode: mode, device: info.st_dev, inode: info.st_ino))
                } catch { Darwin.close(fd); throw error }
            }
        } catch { acquired.forEach { Darwin.close($0.fd) }; throw error }
        entries = acquired; brokerUID = plan.uid; agentUID = plan.agentUID
    }
    func acquire(for plan: MacWorkerPlan) throws -> [Int32] {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard !claimed else { throw RootListenerFailure.busy }
        guard getppid() == 1, getpgrp() == getpid(), plan.uid == brokerUID, plan.agentUID == agentUID,
              entries.map({ $0.path }) == [plan.agentSocket, plan.ownerSocket] else { throw RootListenerFailure.invalid }
        var copies: [Int32] = []
        do {
            for entry in entries {
                let info = try Self.metadata(entry.fd, path: entry.path, group: entry.group, mode: entry.mode)
                guard info.st_dev == entry.device, info.st_ino == entry.inode else { throw RootListenerFailure.changed }
                let copy = fcntl(entry.fd, F_DUPFD_CLOEXEC, 10)
                guard copy >= 10 else { throw RootListenerFailure.unavailable }
                copies.append(copy)
            }
        } catch { copies.forEach { Darwin.close($0) }; throw error }
        claimed = true
        return copies
    }
    func release() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard claimed else { throw RootListenerFailure.invalid }
        claimed = false
    }
    deinit { entries.forEach { Darwin.close($0.fd) } }
}
