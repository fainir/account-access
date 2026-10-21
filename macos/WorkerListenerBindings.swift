// Public metadata for the root-created worker handoff. The root supervisor is
// the authority: neither socket stat ownership nor a pipe's stat uid proves
// who passed a descriptor. No secret bytes are parsed or placed in arguments.
import Foundation
import CryptoKit
import Darwin

struct WorkerListenerBindings {
    static let metadataSize = 216
    static let frameSize = 280
    private static let magic = Data("AALSN002".utf8)

    struct Descriptor: Equatable {
        let device: Int64
        let inode: UInt64
        let address: String
    }
    struct Record: Equatable {
        let role: UInt8
        let source: UInt8
        let descriptorDevice: Int64
        let descriptorInode: UInt64
        let pathDevice: Int64
        let pathInode: UInt64
        let pathDigest: Data
        let addressDigest: Data
    }
    let metadata: Data
    let records: [Record]

    static func digest(_ value: String) -> Data { Data(SHA256.hash(data: Data(value.utf8))) }

    static func descriptor(_ fd: Int32) throws -> Descriptor {
        var info = stat(), address = sockaddr_un(), kind: Int32 = 0
        var length = socklen_t(MemoryLayout<sockaddr_un>.size)
        var kindLength = socklen_t(MemoryLayout<Int32>.size)
        let status = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard fd >= 3, fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK,
              status == 0, address.sun_family == sa_family_t(AF_UNIX),
              length >= 3, length <= MemoryLayout<sockaddr_un>.size,
              getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &kindLength) == 0,
              kindLength == MemoryLayout<Int32>.size, kind == SOCK_STREAM else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        let name = withUnsafeBytes(of: address.sun_path) { raw -> String? in
            let bytes = raw.prefix(Int(length) - 2)
            let nameBytes = bytes.prefix(while: { $0 != 0 })
            guard !nameBytes.isEmpty, nameBytes.count < raw.count else { return nil }
            return String(bytes: nameBytes, encoding: .utf8)
        }
        guard let name, name.hasPrefix("/"), !name.utf8.contains(0), info.st_ino != 0 else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        return Descriptor(device: Int64(info.st_dev), inode: UInt64(info.st_ino), address: name)
    }

    private static func pathInfo(_ path: String, group: gid_t, mode: mode_t, uid: uid_t = 0,
                                 protectParent: Bool = true) throws -> stat {
        if protectParent {
            _ = try WorkerLaunchPaths.protected(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        }
        try WorkerLaunchPaths.rejectGrantACL(path)
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK, info.st_uid == uid,
              info.st_gid == group, info.st_mode & 0o7777 == mode, info.st_nlink == 1, info.st_ino != 0 else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        return info
    }

    // Only the native bind path uses this factory. Launchd provenance is minted
    // inside RootActivatedListeners immediately after its exact named API call.
    static func direct(fd: Int32, role: UInt8, path: String, group: gid_t, mode: mode_t) throws -> Record {
        try MacWorkerBootstrap.checkFD(fd, type: S_IFSOCK, socketPath: path)
        let socket = try descriptor(fd)
        let node = try pathInfo(path, group: group, mode: mode)
        try MacWorkerBootstrap.requireListening(fd)
        return Record(role: role, source: 0, descriptorDevice: socket.device, descriptorInode: socket.inode,
                      pathDevice: Int64(node.st_dev), pathInode: UInt64(node.st_ino),
                      pathDigest: digest(path), addressDigest: digest(socket.address))
    }

    init(records: [Record]) throws {
        guard records.count == 2, records.allSatisfy({ $0.pathDigest.count == 32 && $0.addressDigest.count == 32 }) else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        var value = Self.magic
        Self.append(2, bytes: 2, to: &value)
        value.append(contentsOf: [2, 0])
        Self.append(UInt64(Self.frameSize), bytes: 4, to: &value)
        for record in records {
            value.append(contentsOf: [record.role, record.source, 0, 0])
            Self.append(UInt64(bitPattern: record.descriptorDevice), bytes: 8, to: &value)
            Self.append(record.descriptorInode, bytes: 8, to: &value)
            Self.append(UInt64(bitPattern: record.pathDevice), bytes: 8, to: &value)
            Self.append(record.pathInode, bytes: 8, to: &value)
            value.append(record.pathDigest); value.append(record.addressDigest)
        }
        try self.init(metadata: value)
    }

    init(metadata value: Data) throws {
        // Normalize Data slice indices before the fixed-offset parser.
        let metadata = Data(value)
        guard metadata.count == Self.metadataSize, metadata.prefix(8) == Self.magic,
              Self.integer(metadata, at: 8, bytes: 2) == 2, metadata[10] == 2, metadata[11] == 0,
              Self.integer(metadata, at: 12, bytes: 4) == Self.frameSize else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        var parsed: [Record] = []
        for index in 0..<2 {
            let start = 16 + index * 100
            guard metadata[start] == index + 1, [0, 1].contains(metadata[start + 1]),
                  Self.integer(metadata, at: start + 2, bytes: 2) == 0 else {
                throw WorkerLaunchFailure.invalidDescriptors
            }
            let record = Record(role: metadata[start], source: metadata[start + 1],
                descriptorDevice: Int64(bitPattern: Self.integer(metadata, at: start + 4, bytes: 8)),
                descriptorInode: Self.integer(metadata, at: start + 12, bytes: 8),
                pathDevice: Int64(bitPattern: Self.integer(metadata, at: start + 20, bytes: 8)),
                pathInode: Self.integer(metadata, at: start + 28, bytes: 8),
                pathDigest: metadata.subdata(in: (start + 36)..<(start + 68)),
                addressDigest: metadata.subdata(in: (start + 68)..<(start + 100)))
            guard record.descriptorInode != 0, record.pathInode != 0,
                  record.source == 1 || record.pathDigest == record.addressDigest else {
                throw WorkerLaunchFailure.invalidDescriptors
            }
            parsed.append(record)
        }
        guard parsed[0].descriptorDevice != parsed[1].descriptorDevice || parsed[0].descriptorInode != parsed[1].descriptorInode,
              parsed[0].pathDigest != parsed[1].pathDigest,
              parsed[0].addressDigest != parsed[1].addressDigest,
              parsed[0].pathDevice != parsed[1].pathDevice || parsed[0].pathInode != parsed[1].pathInode else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        self.metadata = metadata; records = parsed
    }

    private static func append(_ value: UInt64, bytes: Int, to data: inout Data) {
        for offset in (0..<bytes).reversed() { data.append(UInt8(truncatingIfNeeded: value >> (offset * 8))) }
    }
    private static func integer(_ value: Data, at offset: Int, bytes: Int) -> UInt64 {
        value[offset..<(offset + bytes)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    private func validateRecord(_ record: Record, fd: Int32, path: String, group: gid_t, mode: mode_t,
                                uid: uid_t = 0, protectParent: Bool = true) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == uid else { throw WorkerLaunchFailure.invalidDescriptors }
        let socket = try Self.descriptor(fd)
        guard socket.device == record.descriptorDevice, socket.inode == record.descriptorInode,
              Self.digest(path) == record.pathDigest, Self.digest(socket.address) == record.addressDigest,
              record.source == 1 || socket.address == path else { throw WorkerLaunchFailure.invalidDescriptors }
        let node = try Self.pathInfo(path, group: group, mode: mode, uid: uid, protectParent: protectParent)
        guard Int64(node.st_dev) == record.pathDevice, UInt64(node.st_ino) == record.pathInode else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        try MacWorkerBootstrap.requireListening(fd)
    }

    func validate(agentFD: Int32, ownerFD: Int32, plan: MacWorkerPlan) throws {
        guard agentFD != ownerFD, let user = getpwuid(plan.agentUID) else { throw WorkerLaunchFailure.invalidDescriptors }
        let group = user.pointee.pw_gid
        try validateRecord(records[0], fd: agentFD, path: plan.agentSocket, group: group, mode: 0o660)
        try validateRecord(records[1], fd: ownerFD, path: plan.ownerSocket, group: 0, mode: 0o600)
    }

    // Read only the metadata prefix. The untouched 64-byte secret suffix and
    // EOF are consumed by Python after permanent identity drop. A legacy worker
    // envelope, malformed prefix, early EOF or timeout never triggers fallback.
    static func consume(_ fd: Int32, timeout: TimeInterval = 3) throws -> WorkerListenerBindings {
        try MacWorkerBootstrap.checkFD(fd, type: S_IFIFO)
        return try consumeChecked(fd, timeout: timeout)
    }
    private static func consumeChecked(_ fd: Int32, timeout: TimeInterval) throws -> WorkerListenerBindings {
        guard timeout > 0, timeout <= 10 else { throw WorkerLaunchFailure.invalidDescriptors }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw WorkerLaunchFailure.invalidDescriptors }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var value = Data()
        while value.count < metadataSize {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw WorkerLaunchFailure.invalidDescriptors }
            var event = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&event, 1, Int32(max(1, min(remaining * 1000, 10_000))))
            if ready < 0 && errno == EINTR { continue }
            guard ready > 0, event.revents & Int16(POLLIN | POLLHUP) != 0,
                  event.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw WorkerLaunchFailure.invalidDescriptors }
            var bytes = [UInt8](repeating: 0, count: metadataSize - value.count)
            let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if count < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard count > 0 else { throw WorkerLaunchFailure.invalidDescriptors }
            value.append(contentsOf: bytes.prefix(count))
        }
        return try WorkerListenerBindings(metadata: value)
    }
    var hex: String { metadata.map { String(format: "%02x", $0) }.joined() }

    #if ACCOUNT_ACCESS_LISTENER_BINDING_CHECKS
    // Ordinary-user fixtures exercise real descriptor substitution and path
    // replacement without weakening any production uid/parent validation.
    static func fixtureRecord(fd: Int32, role: UInt8, path: String, source: UInt8 = 0) throws -> Record {
        let socket = try descriptor(fd)
        guard source == 1 || socket.address == path else { throw WorkerLaunchFailure.invalidDescriptors }
        let node = try pathInfo(path, group: getgid(), mode: 0o600, uid: getuid(), protectParent: false)
        return Record(role: role, source: source, descriptorDevice: socket.device, descriptorInode: socket.inode,
                      pathDevice: Int64(node.st_dev), pathInode: UInt64(node.st_ino),
                      pathDigest: digest(path), addressDigest: digest(socket.address))
    }
    func fixtureValidate(agentFD: Int32, ownerFD: Int32, paths: [String]) throws {
        guard paths.count == 2, agentFD != ownerFD else { throw WorkerLaunchFailure.invalidDescriptors }
        try validateRecord(records[0], fd: agentFD, path: paths[0], group: getgid(), mode: 0o600, uid: getuid(), protectParent: false)
        try validateRecord(records[1], fd: ownerFD, path: paths[1], group: getgid(), mode: 0o600, uid: getuid(), protectParent: false)
    }
    static func fixtureConsume(_ fd: Int32, timeout: TimeInterval = 3) throws -> WorkerListenerBindings {
        var info = stat()
        guard fd >= 3, fstat(fd, &info) == 0, info.st_uid == getuid(),
              info.st_mode & S_IFMT == S_IFIFO, info.st_dev == 0, info.st_nlink == 0 else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        return try consumeChecked(fd, timeout: timeout)
    }
    #endif
}
