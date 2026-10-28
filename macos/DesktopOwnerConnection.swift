// Desktop transport for the isolated system service. The public profile contains
// code identity only; credentials and OS approval travel over the pinned XPC peer.
import Foundation
import Security
import Darwin

enum DesktopOwnerFailure: Error { case profile, unavailable, approval, approvalTimedOut, approvalPending, response }
enum DesktopOwnerSetupProgress { case requestingApproval, approvalAccepted }

// AuthorizationCopyRights can wait on a system-owned dialog and has no
// cancellation API. Bound the UI operation independently, and make sure a
// grant returned after the owner has already seen a timeout is discarded.
private final class DesktopOwnerSetupAuthorizationRequest {
    private let lock = NSLock()
    private let done = DispatchSemaphore(value: 0)
    private var result: Result<Data, Error>?
    private var abandoned = false

    func acquire(timeout: TimeInterval, operation: @escaping () throws -> Data,
                 completed: @escaping () -> Void, discardLateResult: @escaping () -> Void) throws -> Data {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let value = Result { try operation() }
            lock.lock()
            if abandoned {
                lock.unlock()
                if case .success(var form) = value { form.resetBytes(in: 0..<form.count) }
                discardLateResult()
                completed()
                return
            }
            result = value
            lock.unlock()
            completed()
            done.signal()
        }

        if done.wait(timeout: .now() + timeout) == .success {
            lock.lock()
            let completedResult = result
            result = nil
            lock.unlock()
            guard let completedResult else { throw DesktopOwnerFailure.approval }
            return try completedResult.get()
        }

        lock.lock()
        // A completion can race the timeout. Prefer a result that was
        // published before we mark the request abandoned.
        if let completedResult = result {
            result = nil
            lock.unlock()
            return try completedResult.get()
        }
        abandoned = true
        lock.unlock()
        throw DesktopOwnerFailure.approvalTimedOut
    }
}

// Do not stack system authorization dialogs if one AuthorizationCopyRights
// call outlives the UI timeout. The gate clears only when that OS call returns.
private final class DesktopOwnerSetupAuthorizationGate {
    private let lock = NSLock()
    private var pending = false
    func begin() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !pending else { return false }
        pending = true
        return true
    }
    func complete() {
        lock.lock(); defer { lock.unlock() }
        pending = false
    }
    var isPending: Bool {
        lock.lock(); defer { lock.unlock() }
        return pending
    }
}

// UI feedback identity only. It grants no owner or channel authority, and its
// snapshot can be read by a worker without reading any AppKit state.
final class DesktopOwnerSetupContext {
    struct Snapshot: Equatable { fileprivate let generation: UUID }
    private let lock = NSLock()
    private var generation = UUID()
    func invalidate() {
        lock.lock(); defer { lock.unlock() }
        generation = UUID()
    }
    func snapshot() -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        return Snapshot(generation: generation)
    }
    func isCurrent(_ snapshot: Snapshot) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return snapshot.generation == generation
    }
}

struct DesktopOwnerProfile {
    static let installedPath = "/Library/Application Support/Account Access/owner.json"
    let peer: OwnerGatewayPeer
    static var isInstalled: Bool {
        var info = stat()
        if lstat(installedPath, &info) == 0 { return true }
        return errno != ENOENT // An unreadable registration must not select the legacy transport.
    }
    init() throws {
        let root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard root >= 0 else { throw DesktopOwnerFailure.profile }
        defer { Darwin.close(root) }
        let data = try Self.read(at: root, components: ["Library", "Application Support", "Account Access", "owner.json"], owner: 0)
        peer = try Self.parse(data, owner: getuid(), fixture: false)
    }
    private static func check(_ fd: Int32, owner: uid_t, directory: Bool) throws -> stat {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == owner,
              info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o7022 == 0 else { throw DesktopOwnerFailure.profile }
        // Refuse extended ACLs rather than assuming mode bits describe access.
        errno = 0
        if let acl = acl_get_fd(fd) {
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            // Darwin returns zero for an entry and -1/EINVAL for an empty ACL.
            errno = 0
            guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == -1, errno == EINVAL else {
                throw DesktopOwnerFailure.profile
            }
        } else if errno != ENOENT { throw DesktopOwnerFailure.profile }
        if !directory {
            guard info.st_nlink == 1, (1...4096).contains(info.st_size) else { throw DesktopOwnerFailure.profile }
        }
        return info
    }
    private static func read(at parent: Int32, components: [String], owner: uid_t) throws -> Data {
        _ = try check(parent, owner: owner, directory: true)
        var directory = dup(parent)
        guard directory >= 0 else { throw DesktopOwnerFailure.profile }
        defer { Darwin.close(directory) }
        for component in components.dropLast() {
            let next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw DesktopOwnerFailure.profile }
            do { _ = try check(next, owner: owner, directory: true) }
            catch { Darwin.close(next); throw error }
            Darwin.close(directory); directory = next
        }
        guard let name = components.last else { throw DesktopOwnerFailure.profile }
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw DesktopOwnerFailure.profile }
        defer { Darwin.close(fd) }
        let before = try check(fd, owner: owner, directory: false)
        var data = Data(), buffer = [UInt8](repeating: 0, count: 4097)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count == -1 && errno == EINTR { continue }
            guard count >= 0, data.count + count <= 4096 else { throw DesktopOwnerFailure.profile }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        let after = try check(fd, owner: owner, directory: false)
        guard before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, Int(after.st_size) == data.count,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else { throw DesktopOwnerFailure.profile }
        return data
    }
    private static func parse(_ data: Data, owner: uid_t, fixture: Bool) throws -> OwnerGatewayPeer {
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(value.keys) == ["managed_by", "schema", "owner_uid", "publisher_team", "server_identifier", "server_hashes"],
              value["managed_by"] as? String == "account-access-desktop-owner-v1",
              let schema = value["schema"] as? NSNumber, CFGetTypeID(schema) != CFBooleanGetTypeID(), schema == 1,
              let uid = value["owner_uid"] as? NSNumber, CFGetTypeID(uid) != CFBooleanGetTypeID(),
              owner != 0, uid.doubleValue == Double(owner),
              let team = value["publisher_team"] as? String,
              value["server_identifier"] as? String == "com.fainir.accountaccess.broker",
              let hashes = value["server_hashes"] as? [String] else { throw DesktopOwnerFailure.profile }
        #if ACCOUNT_ACCESS_GATEWAY_CHECKS || ACCOUNT_ACCESS_UI_CHECKS
        if fixture {
            guard team == "fixture", hashes.count == 1 else { throw DesktopOwnerFailure.profile }
            return try OwnerGatewayPeer.fixture(uid: 0, codeHash: hashes[0])
        }
        #endif
        return try OwnerGatewayPeer(uid: 0, team: team, identifier: "com.fainir.accountaccess.broker", codeHashes: hashes)
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS || ACCOUNT_ACCESS_UI_CHECKS
    private init(peer: OwnerGatewayPeer) { self.peer = peer }
    static func fixture(directory: URL, components: [String], fileOwner: uid_t = getuid(), accountOwner: uid_t = getuid()) throws -> DesktopOwnerProfile {
        guard !components.isEmpty, components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("/") && !$0.utf8.contains(0) }) else {
            throw DesktopOwnerFailure.profile
        }
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw DesktopOwnerFailure.profile }
        defer { Darwin.close(fd) }
        return try DesktopOwnerProfile(peer: parse(read(at: fd, components: components, owner: fileOwner), owner: accountOwner, fixture: true))
    }
    static func fixture(peer: OwnerGatewayPeer) -> DesktopOwnerProfile { DesktopOwnerProfile(peer: peer) }
    #endif
}

protocol DesktopOwnerChannel: AnyObject {
    var isAvailable: Bool { get }
    func prepare(reply: @escaping (Bool) -> Void)
    func authorizeSetup(_ form: Data, reply: @escaping (Bool) -> Void)
    func request(_ route: String, body: Data?, reply: @escaping (Int, Data) -> Void)
    func invalidate()
}
extension OwnerGatewayConnection: DesktopOwnerChannel {}

private final class DesktopOwnerReply<Value> {
    private let lock = NSLock()
    private var result: Value?
    private var closed = false
    private let done = DispatchSemaphore(value: 0)
    func finish(_ value: Value) {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return }
        result = value; closed = true; done.signal()
    }
    func wait(timeout: TimeInterval = 40) throws -> Value {
        let completed = done.wait(timeout: .now() + timeout) == .success
        lock.lock(); defer { lock.unlock() }
        closed = true
        guard completed, let result else { throw DesktopOwnerFailure.unavailable }
        return result
    }
}

final class DesktopOwnerConnection {
    private let lock = NSRecursiveLock()
    private let makeChannel: () throws -> DesktopOwnerChannel
    private let acquire: () throws -> Data
    private let closeApproval: () -> Void
    private let approvalTimeout: TimeInterval
    private let authorizationGate = DesktopOwnerSetupAuthorizationGate()
    private let clock: () -> TimeInterval
    private var channel: DesktopOwnerChannel?
    private var setupUntil: TimeInterval = 0
    private let approval: OwnerSetupApproval?

    init(profile: DesktopOwnerProfile) {
        let approval = OwnerSetupApproval()
        self.approval = approval
        makeChannel = { try OwnerGatewayConnection(service: "com.fainir.accountaccess.broker.owner", peer: profile.peer) }
        acquire = approval.acquire; closeApproval = approval.close
        approvalTimeout = 120
        clock = { ProcessInfo.processInfo.systemUptime }
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS || ACCOUNT_ACCESS_UI_CHECKS
    init(makeChannel: @escaping () throws -> DesktopOwnerChannel, acquire: @escaping () throws -> Data,
         closeApproval: @escaping () -> Void = {}, clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         approvalTimeout: TimeInterval = 120) {
        approval = nil; self.makeChannel = makeChannel; self.acquire = acquire
        self.closeApproval = closeApproval; self.clock = clock; self.approvalTimeout = approvalTimeout
    }
    #endif
    private func preparedChannel() throws -> DesktopOwnerChannel {
        if let channel, channel.isAvailable { return channel }
        close()
        let next = try makeChannel()
        channel = next
        let reply = DesktopOwnerReply<Bool>()
        next.prepare(reply: reply.finish)
        guard try reply.wait() else { close(); throw DesktopOwnerFailure.unavailable }
        return next
    }
    func prepare() throws {
        lock.lock(); defer { lock.unlock() }
        _ = try preparedChannel()
    }
    // Reads never prompt. Setup writes originate from an explicit owner action.
    // A dropped response is returned to the UI; no operation is replayed.
    func request(_ route: String, body: [String: Any]? = nil,
                 setupProgress: (DesktopOwnerSetupProgress) -> Void = { _ in }) throws -> (Int, [String: Any]) {
        lock.lock(); defer { lock.unlock() }
        let bytes = try body.map { try JSONSerialization.data(withJSONObject: $0) }
        let validated = try OwnerGatewayRoute(route, body: bytes)
        let active = try preparedChannel()
        if validated.requiresSetup && clock() >= setupUntil {
            setupProgress(.requestingApproval)
            guard authorizationGate.begin() else { throw DesktopOwnerFailure.approvalPending }
            var form: Data
            do {
                form = try DesktopOwnerSetupAuthorizationRequest().acquire(timeout: approvalTimeout,
                    operation: acquire, completed: { self.authorizationGate.complete() },
                    discardLateResult: closeApproval)
            } catch DesktopOwnerFailure.approvalTimedOut {
                throw DesktopOwnerFailure.approvalTimedOut
            } catch {
                authorizationGate.complete()
                closeApproval()
                throw error
            }
            defer { form.resetBytes(in: 0..<form.count); closeApproval() }
            guard form.count == 32 else { close(); throw DesktopOwnerFailure.approval }
            let authorized = DesktopOwnerReply<Bool>()
            active.authorizeSetup(form, reply: authorized.finish)
            guard try authorized.wait() else { close(); throw DesktopOwnerFailure.approval }
            setupUntil = clock() + 570 // Shorter than the server's fixed ten-minute lease.
            setupProgress(.approvalAccepted)
        }
        let reply = DesktopOwnerReply<(Int, Data)>()
        active.request(route, body: bytes) { reply.finish(($0, $1)) }
        let response: (Int, Data)
        do { response = try reply.wait(timeout: validated.path == "/owner/bitwarden/connect" ? 75 : 40) }
        catch { close(); throw error }
        guard response.1.count <= 8_000_000, let payload = try JSONSerialization.jsonObject(with: response.1) as? [String: Any] else {
            close(); throw DesktopOwnerFailure.response
        }
        if response.0 == 503 { close() }
        if response.0 == 403 { setupUntil = 0 }
        return (response.0, payload)
    }
    func close() {
        lock.lock(); defer { lock.unlock() }
        channel?.invalidate(); channel = nil; setupUntil = 0
        // OwnerSetupApproval.close() waits for AuthorizationCopyRights' lock.
        // A timed-out system prompt is cleaned by its late-completion path.
        if !authorizationGate.isPending { closeApproval() }
    }
    deinit { close() }
}

enum DesktopVaultScreen: Equatable {
    case needsOwner, initializing, ready, paused, repair
    init(_ state: [String: Any]) {
        if let setup = state["vault_setup"] as? [String: Any] {
            switch setup["status"] as? String {
            case "needs_owner": self = .needsOwner
            case "initializing": self = .initializing
            case "paused": self = .paused
            case "ready": self = .initializing // Enrollment reply; fetch the full worker state next.
            default: self = .repair
            }
        } else if state["accounts"] is [[String: Any]], state["catalog"] is [[String: Any]] {
            self = .ready
        } else { self = .repair }
    }
}

enum DesktopVaultRepair {
    static func detail(_ state: [String: Any]) -> String? {
        guard let setup = state["vault_setup"] as? [String: Any], setup["status"] as? String == "needs_repair",
              let diagnostic = setup["diagnostic"] as? [String: String],
              Set(diagnostic.keys) == ["checkpoint", "reason"] else { return nil }
        // Render fixed explanations only, never a daemon-supplied string.
        switch (diagnostic["checkpoint"], diagnostic["reason"]) {
        case ("stage_status", "vault_publication_device_number_changed"):
            return "The saved store's disk reference changed. The existing store needs its location revalidated before it can reopen."
        case ("stage_status", "vault_publication_directory_identity_mismatch"):
            return "The saved store's directory does not match its original registration. Its existing data has not been replaced."
        case ("key_access", "vault_key_missing"):
            return "The encryption key for this existing store is unavailable. Account Access has not created a replacement key."
        case ("key_access", "system_keychain_load_failed"):
            return "macOS could not provide access to the existing encryption key."
        case ("worker_start", "worker_process_unavailable"):
            return "The protected account service did not finish starting."
        default: return nil
        }
    }
}
