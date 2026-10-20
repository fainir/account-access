// Root-native, one-shot bootstrap for the isolated worker. A trusted supervisor
// inherits only the read descriptor into a validated child, then transmits.
import Foundation
import Security
import Darwin

enum RootWorkerChannelFailure: String, Error {
    case unavailable = "worker_secret_channel_unavailable"
    case consumed = "worker_secret_channel_already_consumed"
}

final class RootWorkerChannel: CustomStringConvertible, CustomDebugStringConvertible {
    private var key: RootVaultKey?
    private var owner = Data(count: 32)
    private var reader: Int32 = -1
    private var writer: Int32 = -1
    private let listenerBindings: Data?
    private var pending = true
    private var closed = false
    private let lock = NSLock()
    var description: String { "<RootWorkerChannel redacted>" }
    var debugDescription: String { description }

    init(key: RootVaultKey, listenerBindings: WorkerListenerBindings? = nil) throws {
        try RootVaultKeyStore.requireDaemon()
        self.key = key
        self.listenerBindings = listenerBindings?.metadata
        let status = owner.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw RootWorkerChannelFailure.unavailable }
        var pair: [Int32] = [-1, -1]
        guard pipe(&pair) == 0 else { throw RootWorkerChannelFailure.unavailable }
        reader = pair[0]; writer = pair[1]
        guard fcntl(reader, F_SETFD, FD_CLOEXEC) == 0, fcntl(writer, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(writer, F_SETFL, O_NONBLOCK) == 0, fcntl(writer, F_SETNOSIGPIPE, 1) == 0 else {
            closeDescriptors()
            throw RootWorkerChannelFailure.unavailable
        }
    }
    func readDescriptor() throws -> Int32 {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard pending, reader >= 0 else { throw RootWorkerChannelFailure.consumed }
        return reader // Borrowed for explicit child inheritance, not caller ownership.
    }
    func withOwnerSecret<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) throws -> Result {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard !closed else { throw RootWorkerChannelFailure.consumed }
        return try owner.withUnsafeBytes(body)
    }
    func transmit() throws {
        try RootVaultKeyStore.requireDaemon()
        lock.lock(); defer { lock.unlock() }
        guard pending, let key, writer >= 0 else { throw RootWorkerChannelFailure.consumed }
        pending = false // Any attempted send consumes the channel, including failure.
        var sent = false
        defer {
            closeDescriptors(); self.key = nil
            if !sent { closed = true; owner.resetBytes(in: 0..<owner.count) }
        }
        Darwin.close(reader); reader = -1
        let expected = listenerBindings == nil ? 64 : WorkerListenerBindings.frameSize
        var payload = Data()
        payload.reserveCapacity(expected)
        defer { payload.resetBytes(in: 0..<payload.count) }
        if let listenerBindings { payload.append(listenerBindings) }
        try key.withUnsafeKey { payload.append(contentsOf: $0) }
        payload.append(owner)
        guard payload.count == expected, fpathconf(writer, _PC_PIPE_BUF) >= expected else {
            throw RootWorkerChannelFailure.unavailable
        }
        let deadline = ProcessInfo.processInfo.systemUptime + 1
        // A fresh nonblocking pipe has room for this sub-PIPE_BUF atomic write.
        // No partial write or uncertain attempt is retried with a new envelope.
        try payload.withUnsafeBytes { bytes in
            while ProcessInfo.processInfo.systemUptime < deadline {
                let count = Darwin.write(writer, bytes.baseAddress, bytes.count)
                if count < 0 && errno == EINTR { continue }
                guard count == expected else { throw RootWorkerChannelFailure.unavailable }
                return
            }
            throw RootWorkerChannelFailure.unavailable
        }
        sent = true
    }
    func cancel() {
        lock.lock(); defer { lock.unlock() }
        pending = false; closed = true; closeDescriptors(); key = nil
        owner.resetBytes(in: 0..<owner.count)
    }
    private func closeDescriptors() {
        if reader >= 0 { Darwin.close(reader); reader = -1 }
        if writer >= 0 { Darwin.close(writer); writer = -1 }
    }
    deinit { closeDescriptors(); owner.resetBytes(in: 0..<owner.count) }
}
