// Native owner-only transport for the separately managed broker. This component
// does not install a privileged service or migrate an existing owner's vault.
import Foundation
import Security
import Darwin

@objc(AccountAccessOwnerGatewayV1) protocol OwnerGatewayRPC {
    func authorizeSetup(_ externalForm: Data, withReply reply: @escaping (Bool) -> Void)
    func request(_ route: String, body: Data?, withReply reply: @escaping (Int, Data) -> Void)
    func endSetup(withReply reply: @escaping () -> Void)
}

enum OwnerGatewayError: Error { case invalidPolicy, unavailable, invalidResponse }

struct OwnerGatewayPeer {
    let uid: uid_t
    let requirement: String

    init(uid: uid_t, team: String, identifier: String, codeHashes: [String]) throws {
        guard team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
              identifier.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]{1,199}$", options: .regularExpression) != nil,
              !codeHashes.isEmpty, codeHashes.count <= 8,
              codeHashes.allSatisfy({ $0.range(of: "^[a-fA-F0-9]{40}$", options: .regularExpression) != nil }) else {
            throw OwnerGatewayError.invalidPolicy
        }
        let hashes = codeHashes.map { "cdhash H\"" + $0.lowercased() + "\"" }.joined(separator: " or ")
        let text = "anchor apple generic and identifier \"" + identifier +
            "\" and certificate leaf[subject.OU] = \"" + team + "\" and (" + hashes +
            ") and !(entitlement[\"com.apple.security.get-task-allow\"] exists)"
        try Self.validate(text)
        self.uid = uid
        self.requirement = text
    }

    private static func validate(_ text: String) throws {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              requirement != nil else { throw OwnerGatewayError.invalidPolicy }
    }

    #if ACCOUNT_ACCESS_GATEWAY_CHECKS
    // Ad-hoc CI fixtures exercise kernel CDHash enforcement, not publisher trust.
    static func fixture(uid: uid_t, codeHash: String) throws -> OwnerGatewayPeer {
        guard codeHash.range(of: "^[a-fA-F0-9]{40}$", options: .regularExpression) != nil else {
            throw OwnerGatewayError.invalidPolicy
        }
        let text = "cdhash H\"" + codeHash + "\""
        try validate(text)
        return OwnerGatewayPeer(uid: uid, requirement: text)
    }
    private init(uid: uid_t, requirement: String) { self.uid = uid; self.requirement = requirement }
    #endif
}

enum OwnerSetupAuthorization {
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS
    static let right = "com.fainir.accountaccess.owner-enrollment.qa"
    #else
    static let right = "com.fainir.accountaccess.owner-enrollment.v1"
    #endif
    // Provisioning must install this exact rule before enabling the UI.
    // No caller-supplied right, default unknown-right rule or allow rule is used.
    // The canned session-owner delegation has a very long credential lifetime.
    // Use a fresh, unshared authorization and only a short IPC handoff window.
    static let definition: [String: Any] = ["class": "user", "session-owner": true,
        "authenticate-user": true, "allow-root": false, "shared": false, "timeout": 30, "tries": 3]

    static func validDefinition(_ value: [String: Any]) -> Bool {
        // authd emits registrar identity and localized prompt metadata. These
        // do not replace authentication settings. The root host separately
        // pins the registrar before accepting any setup proof.
        let metadata: Set<String> = ["comment", "created", "modified", "version", "description",
                                     "default-prompt", "identifier", "requirement"]
        if value["identifier"] != nil || value["requirement"] != nil {
            guard let identifier = value["identifier"] as? String,
                  identifier.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]{1,199}$", options: .regularExpression) != nil,
                  let text = value["requirement"] as? String, text.utf8.count <= 8192 else { return false }
            var requirement: SecRequirement?
            guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, requirement != nil else { return false }
        }
        if let prompt = value["default-prompt"] {
            guard let localized = prompt as? [String: String], localized.count <= 32,
                  localized.allSatisfy({ $0.key.utf8.count <= 128 && $0.value.utf8.count <= 4096 }) else { return false }
        }
        let security = value.filter { !metadata.contains($0.key) }
        guard Set(security.keys) == Set(definition.keys), security["class"] as? String == "user" else { return false }
        for name in ["session-owner", "authenticate-user", "allow-root", "shared"] {
            guard let number = security[name] as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID(),
                  number.boolValue == (definition[name] as! Bool) else { return false }
        }
        for name in ["timeout", "tries"] {
            guard let number = security[name] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                  number.doubleValue == Double(definition[name] as! Int) else { return false }
        }
        return true
    }

    static func installed() -> Bool {
        var value: CFDictionary?
        guard AuthorizationRightGet(right, &value) == errAuthorizationSuccess,
              let value = value as? [String: Any] else { return false }
        return validDefinition(value)
    }

    static func check(_ data: Data) -> Bool {
        guard data.count == MemoryLayout<AuthorizationExternalForm>.size, installed() else { return false }
        var form = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &form) { data.copyBytes(to: $0) }
        defer { _ = withUnsafeMutableBytes(of: &form) { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        var reference: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&form, &reference) == errAuthorizationSuccess,
              let reference else { return false }
        defer { AuthorizationFree(reference, []) }
        // The service never prompts, extends rights or accepts partial
        // authorization. Only the signed UI may ask the owner first.
        return granted(reference, flags: [])
    }

    static func granted(_ reference: AuthorizationRef, flags: AuthorizationFlags) -> Bool {
        // Never let an undefined right inherit the host's default policy, even
        // if another internal caller uses this lower-level helper directly.
        guard installed() else { return false }
        return right.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                var returned: UnsafeMutablePointer<AuthorizationRights>?
                let status = AuthorizationCopyRights(reference, &rights, nil, flags, &returned)
                defer { if let returned { AuthorizationFreeItemSet(returned) } }
                guard status == errAuthorizationSuccess, let returned, returned.pointee.count == 1,
                      let items = returned.pointee.items,
                      String(cString: items.pointee.name) == right, items.pointee.flags == 0 else { return false }
                return true
            }
        }
    }
}

final class OwnerSetupApproval {
    private var reference: AuthorizationRef?
    private let lock = NSRecursiveLock()

    // Call only in response to an explicit owner setup action, off the UI thread.
    // This method is not used during agent account operations.
    func acquire() throws -> Data {
        lock.lock(); defer { lock.unlock() }
        close()
        guard OwnerSetupAuthorization.installed() else { throw OwnerGatewayError.unavailable }
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess else {
            throw OwnerGatewayError.unavailable
        }
        guard let reference else { throw OwnerGatewayError.unavailable }
        let accepted = OwnerSetupAuthorization.granted(reference, flags: [.interactionAllowed, .extendRights])
        guard accepted else { throw OwnerGatewayError.unavailable }
        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(reference, &form) == errAuthorizationSuccess else {
            throw OwnerGatewayError.unavailable
        }
        defer { _ = withUnsafeMutableBytes(of: &form) { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        return withUnsafeBytes(of: &form) { Data($0) }
    }

    func close() {
        lock.lock(); defer { lock.unlock() }
        if let reference { AuthorizationFree(reference, [.destroyRights]) }
        reference = nil
    }
    deinit { close() }
}

struct OwnerGatewayRoute {
    let path: String
    let body: Data?
    let requiresSetup: Bool

    static let writes: Set<String> = [
        "owner/credential", "owner/grant", "owner/revoke", "owner/add", "owner/verify",
        "owner/import/preview", "owner/import/apply", "owner/authenticator/preview",
        "owner/authenticator/apply", "owner/authenticator/discard", "owner/source",
        "owner/source/check", "owner/source/revoke", "owner/mailbox/connect", "owner/mailbox/check",
        "owner/mailbox/password", "owner/mailbox/remove", "owner/password-sync",
        "owner/password-sync/disconnect", "owner/phone/pair", "owner/stop", "owner/vault/enroll"
    ]
    static let restrictions: Set<String> = ["owner/stop", "owner/revoke", "owner/source/revoke",
        "owner/mailbox/remove", "owner/password-sync/disconnect", "owner/authenticator/discard"]

    init(_ route: String, body: Data?) throws {
        if body == nil {
            guard ["owner/state", "owner/health"].contains(route) else { throw OwnerGatewayError.invalidPolicy }
        } else {
            guard Self.writes.contains(route), let body,
                  body.count <= (route == "owner/import/preview" ? 8_000_000 : 65536),
                  let value = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                throw OwnerGatewayError.invalidPolicy
            }
            if route == "owner/verify", (value["visible"] as? Bool) == true {
                throw OwnerGatewayError.invalidPolicy // Requires a future trusted host handoff.
            }
            if route == "owner/vault/enroll", !value.isEmpty { throw OwnerGatewayError.invalidPolicy }
        }
        self.path = "/" + route
        self.body = body
        self.requiresSetup = body != nil && !Self.restrictions.contains(route)
    }
}

protocol OwnerGatewayBackend {
    func request(_ route: OwnerGatewayRoute) throws -> (Int, Data)
}

// Only a live, authenticated setup session can create this native authority.
// It has no serialized representation, secret bytes or caller-selected policy.
struct OwnerEnrollmentApproval { fileprivate init() {} }
protocol OwnerVaultEnrollmentBackend: OwnerGatewayBackend {
    func enroll(_ approval: OwnerEnrollmentApproval) throws -> (Int, Data)
}

protocol OwnerSetupProofVerifying {
    func check(_ data: Data) -> Bool
}

final class OwnerGatewaySession: NSObject, OwnerGatewayRPC {
    private let backend: OwnerGatewayBackend
    private let authorize: (Data) -> Bool
    private let clock: () -> TimeInterval
    private let lock = NSLock()
    private var expires: TimeInterval = 0
    private var generation = 0
    private var closed = false
    private var busy = false

    convenience init(backend: OwnerGatewayBackend) {
        self.init(backend: backend, authorize: OwnerSetupAuthorization.check,
                  clock: { ProcessInfo.processInfo.systemUptime })
    }
    convenience init(backend: OwnerGatewayBackend, verifier: OwnerSetupProofVerifying) {
        self.init(backend: backend, authorize: verifier.check,
                  clock: { ProcessInfo.processInfo.systemUptime })
    }
    private init(backend: OwnerGatewayBackend, authorize: @escaping (Data) -> Bool,
                 clock: @escaping () -> TimeInterval) {
        self.backend = backend; self.authorize = authorize; self.clock = clock
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS
    static func fixture(backend: OwnerGatewayBackend, authorize: @escaping (Data) -> Bool,
                        clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) -> OwnerGatewaySession {
        OwnerGatewaySession(backend: backend, authorize: authorize, clock: clock)
    }
    #endif

    func close() { lock.lock(); closed = true; expires = 0; generation += 1; lock.unlock() }
    func endSetup(withReply reply: @escaping () -> Void) {
        lock.lock(); expires = 0; generation += 1; lock.unlock(); reply()
    }
    func authorizeSetup(_ externalForm: Data, withReply reply: @escaping (Bool) -> Void) {
        lock.lock()
        guard !closed else { lock.unlock(); reply(false); return }
        generation += 1
        let attempt = generation
        expires = 0
        lock.unlock()
        let accepted = externalForm.count == 32 && authorize(externalForm)
        lock.lock()
        let current = !closed && generation == attempt && accepted
        if current { expires = clock() + 600 }
        lock.unlock()
        reply(current)
    }

    static func failure(_ reason: String) -> Data {
        // Reasons are fixed literals selected by this implementation.
        (try? JSONSerialization.data(withJSONObject: ["status": "NEEDS_USER", "reason": reason])) ?? Data()
    }

    func request(_ route: String, body: Data?, withReply reply: @escaping (Int, Data) -> Void) {
        guard let route = try? OwnerGatewayRoute(route, body: body) else {
            reply(403, Self.failure("trusted_owner_route_required")); return
        }
        lock.lock()
        guard !closed else { lock.unlock(); reply(403, Self.failure("owner_session_closed")); return }
        guard !busy else { lock.unlock(); reply(409, Self.failure("owner_request_in_progress")); return }
        guard !route.requiresSetup || clock() < expires else {
            lock.unlock(); reply(403, Self.failure("owner_setup_authorization_required")); return
        }
        busy = true
        lock.unlock()
        let result: (Int, Data)
        do {
            let response: (Int, Data)
            if route.path == "/owner/vault/enroll" {
                guard let enrollment = backend as? OwnerVaultEnrollmentBackend else {
                    throw OwnerGatewayError.invalidPolicy
                }
                response = try enrollment.enroll(OwnerEnrollmentApproval())
            } else {
                response = try backend.request(route)
            }
            let (status, data) = response
            guard (200...299).contains(status) || (400...599).contains(status), data.count <= 8_000_000,
                  (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else {
                throw OwnerGatewayError.invalidResponse
            }
            result = (status, data)
        } catch {
            // Never include an exception, body, socket path or capability.
            result = (503, Self.failure("owner_backend_unavailable"))
        }
        lock.lock(); busy = false; lock.unlock()
        reply(result.0, result.1)
    }
}

final class OwnerGatewayListener: NSObject, NSXPCListenerDelegate {
    private let peer: OwnerGatewayPeer
    private let makeSession: () -> OwnerGatewaySession
    private let lock = NSLock()
    private var stopped = false
    private var generation = 0
    private var connections: [UUID: (NSXPCConnection, OwnerGatewaySession)] = [:]
    init(peer: OwnerGatewayPeer, makeSession: @escaping () -> OwnerGatewaySession) {
        self.peer = peer; self.makeSession = makeSession
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier == peer.uid else { return false }
        lock.lock(); let attempt = generation; let open = !stopped; lock.unlock()
        guard open else { return false }
        connection.setCodeSigningRequirement(peer.requirement)
        let session = makeSession()
        let identifier = UUID()
        connection.exportedInterface = NSXPCInterface(with: OwnerGatewayRPC.self)
        connection.exportedObject = session
        connection.invalidationHandler = { [weak self, weak session] in
            session?.close()
            guard let self else { return }
            self.lock.lock(); self.connections.removeValue(forKey: identifier); self.lock.unlock()
        }
        connection.interruptionHandler = { [weak session] in session?.close() }
        lock.lock()
        guard !stopped, generation == attempt, connections.count < 16 else {
            lock.unlock(); session.close(); return false
        }
        connections[identifier] = (connection, session)
        lock.unlock()
        connection.resume()
        return true
    }
    func stop() {
        lock.lock(); stopped = true
        lock.unlock()
        invalidateSessions()
    }
    func invalidateSessions() {
        lock.lock()
        generation += 1
        let active = Array(connections.values)
        connections.removeAll(); lock.unlock()
        for (connection, session) in active { session.close(); connection.invalidate() }
    }
    deinit { stop() }
}

// Production construction uses the system bootstrap namespace and a root peer;
// there is no loopback, owner-file capability or alternate transport fallback.
private final class OwnerGatewayReply<Value> {
    private let lock = NSLock()
    private var finished = false
    private let reply: (Value) -> Void
    init(_ reply: @escaping (Value) -> Void) { self.reply = reply }
    func finish(_ value: Value, before: () -> Void = {}) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        lock.unlock()
        before()
        reply(value)
    }
}

final class OwnerGatewayConnection {
    private let connection: NSXPCConnection
    private let peer: OwnerGatewayPeer
    private let lock = NSLock()
    private var ready = false
    private var closed = false

    init(service: String, peer: OwnerGatewayPeer) throws {
        guard peer.uid == 0, service == "com.fainir.accountaccess.broker.owner" else {
            throw OwnerGatewayError.invalidPolicy
        }
        self.connection = NSXPCConnection(machServiceName: service, options: [.privileged])
        self.peer = peer
        configure()
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS
    init(endpoint: NSXPCListenerEndpoint, peer: OwnerGatewayPeer) {
        self.connection = NSXPCConnection(listenerEndpoint: endpoint)
        self.peer = peer
        configure()
    }
    #endif
    private func configure() {
        connection.remoteObjectInterface = NSXPCInterface(with: OwnerGatewayRPC.self)
        connection.setCodeSigningRequirement(peer.requirement)
        connection.interruptionHandler = { [weak self] in self?.invalidate() }
        connection.invalidationHandler = { [weak self] in self?.invalidate() }
        connection.resume()
    }
    private func proxy(error: @escaping () -> Void) -> OwnerGatewayRPC? {
        connection.remoteObjectProxyWithErrorHandler { _ in error() } as? OwnerGatewayRPC
    }
    private var peerIdentityMatches: Bool { connection.effectiveUserIdentifier == peer.uid }
    private var isReady: Bool { lock.lock(); defer { lock.unlock() }; return ready }
    // The initial health request contains no enrollment data. Verify the peer's
    // kernel identity before releasing an external authorization or credentials.
    func prepare(reply: @escaping (Bool) -> Void) {
        let completion = OwnerGatewayReply(reply)
        let failed = { [weak self] in completion.finish(false, before: { self?.invalidate() }) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 35, execute: failed)
        guard let proxy = proxy(error: failed) else { failed(); return }
        proxy.request("owner/health", body: nil) { [weak self] status, data in
            guard let self else { failed(); return }
            var accepted = self.peerIdentityMatches && status == 200 && data.count <= 65536
                && ((try? JSONSerialization.jsonObject(with: data)) is [String: Any])
            self.lock.lock(); accepted = accepted && !self.closed; self.lock.unlock()
            completion.finish(accepted, before: {
                self.lock.lock(); self.ready = accepted && !self.closed; self.lock.unlock()
                if !accepted { self.invalidate() }
            })
        }
    }
    func authorizeSetup(_ form: Data, reply: @escaping (Bool) -> Void) {
        let completion = OwnerGatewayReply(reply)
        let failed = { completion.finish(false) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 35, execute: failed)
        guard isReady, form.count == 32, let proxy = proxy(error: failed) else { failed(); return }
        proxy.authorizeSetup(form) { [weak self] accepted in completion.finish(accepted && self?.peerIdentityMatches == true) }
    }
    func request(_ route: String, body: Data?, reply: @escaping (Int, Data) -> Void) {
        let completion = OwnerGatewayReply<(Int, Data)> { reply($0.0, $0.1) }
        let failed = { completion.finish((503, OwnerGatewaySession.failure("owner_channel_unavailable"))) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 35, execute: failed)
        guard isReady else { failed(); return }
        guard (try? OwnerGatewayRoute(route, body: body)) != nil else {
            completion.finish((403, OwnerGatewaySession.failure("trusted_owner_route_required")))
            return
        }
        guard let proxy = proxy(error: failed) else { failed(); return }
        proxy.request(route, body: body) { [weak self] status, data in
            guard self?.peerIdentityMatches == true, data.count <= 8_000_000,
                  (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else { failed(); return }
            completion.finish((status, data))
        }
    }
    func endSetup(reply: @escaping () -> Void) {
        let completion = OwnerGatewayReply<Void> { _ in reply() }
        let done = { completion.finish(()) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 35, execute: done)
        guard isReady, let proxy = proxy(error: done) else { done(); return }
        proxy.endSetup(withReply: done)
    }
    func invalidate() {
        lock.lock(); let alreadyClosed = closed; ready = false; closed = true; lock.unlock()
        if !alreadyClosed { connection.invalidate() }
    }
    deinit { invalidate() }
}

// Root-only, single-request HTTP over the supervisor's private Unix listener.
// A route/body never chooses a socket, URL, capability, interpreter or command.
final class OwnerUnixBackend: OwnerGatewayBackend {
    private let path: String
    private let capability: String
    private let port: Int

    init(path: String, capability: String, port: Int) throws {
        guard getuid() == 0, geteuid() == 0 else { throw OwnerGatewayError.invalidPolicy }
        try Self.checkLocation(path, uid: 0, protectedAncestors: true)
        try Self.checkCapability(capability, port: port)
        self.path = path; self.capability = capability; self.port = port
    }
    private init(path: String, capability: String, port: Int, fixtureUID: uid_t) throws {
        try Self.checkLocation(path, uid: fixtureUID, protectedAncestors: false)
        try Self.checkCapability(capability, port: port)
        self.path = path; self.capability = capability; self.port = port
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS
    static func fixture(path: String, capability: String, port: Int) throws -> OwnerUnixBackend {
        try OwnerUnixBackend(path: path, capability: capability, port: port, fixtureUID: getuid())
    }
    #endif
    private static func checkCapability(_ value: String, port: Int) throws {
        guard value.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
              (1...65535).contains(port) else { throw OwnerGatewayError.invalidPolicy }
    }
    private static func checkLocation(_ value: String, uid: uid_t, protectedAncestors: Bool) throws {
        guard value.hasPrefix("/"), !value.utf8.contains(0), value.utf8.count < 104,
              !value.split(separator: "/").contains("..") else { throw OwnerGatewayError.invalidPolicy }
        let socketURL = URL(fileURLWithPath: value)
        var info = stat()
        guard lstat(value, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK,
              info.st_uid == uid, info.st_mode & 0o077 == 0 else { throw OwnerGatewayError.invalidPolicy }
        let directory = socketURL.deletingLastPathComponent()
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == uid, info.st_mode & 0o077 == 0 else { throw OwnerGatewayError.invalidPolicy }
        if protectedAncestors {
            var pending = [directory, directory.resolvingSymlinksInPath()]
            var checked: Set<String> = []
            while var item = pending.popLast() {
                if checked.contains(item.path) { continue }
                checked.insert(item.path)
                guard checked.count <= 64 else { throw OwnerGatewayError.invalidPolicy }
                while true {
                    guard lstat(item.path, &info) == 0, info.st_uid == 0 else { throw OwnerGatewayError.invalidPolicy }
                    if info.st_mode & S_IFMT == S_IFLNK {
                        let target = try FileManager.default.destinationOfSymbolicLink(atPath: item.path)
                        pending.append(target.hasPrefix("/") ? URL(fileURLWithPath: target)
                            : item.deletingLastPathComponent().appendingPathComponent(target))
                    } else if info.st_mode & 0o022 != 0 { throw OwnerGatewayError.invalidPolicy }
                    if item.path == "/" { break }
                    item.deleteLastPathComponent()
                }
            }
        }
    }

    func request(_ route: OwnerGatewayRoute) throws -> (Int, Data) {
        try request(route, timeout: 35)
    }
    func health(timeout: TimeInterval) throws -> (Int, Data) {
        try request(OwnerGatewayRoute("owner/health", body: nil), timeout: timeout)
    }
    private func request(_ route: OwnerGatewayRoute, timeout: TimeInterval) throws -> (Int, Data) {
        guard timeout.isFinite, timeout > 0, timeout <= 35 else { throw OwnerGatewayError.invalidPolicy }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw OwnerGatewayError.unavailable }
        defer { Darwin.close(descriptor) }
        guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else { throw OwnerGatewayError.unavailable }
        let milliseconds = Int((min(timeout, 30) * 1000).rounded(.up))
        var socketTimeout = timeval(tv_sec: milliseconds / 1000, tv_usec: Int32((milliseconds % 1000) * 1000))
        var enabled: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &socketTimeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &socketTimeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw OwnerGatewayError.unavailable
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = path.utf8CString.map { UInt8(bitPattern: $0) }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { throw OwnerGatewayError.unavailable }
        let body = route.body ?? Data()
        let host = "127.0.0.1:" + String(port)
        var header = (route.body == nil ? "GET " : "POST ") + route.path + " HTTP/1.0\r\nHost: " + host
            + "\r\nAuthorization: Bearer " + capability + "\r\nConnection: close\r\n"
        if route.body != nil { header += "Origin: http://" + host + "\r\nContent-Type: application/json\r\n" }
        header += "Content-Length: " + String(body.count) + "\r\n\r\n"
        var payload = Data(header.utf8); payload.append(body)
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        try payload.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw OwnerGatewayError.unavailable }
                let count = Darwin.send(descriptor, raw.baseAddress!.advanced(by: sent), raw.count - sent, 0)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw OwnerGatewayError.unavailable }
                sent += count
            }
        }
        var received = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        var framing: (Int, Int, Int)?
        while true {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw OwnerGatewayError.unavailable }
            let count = Darwin.recv(descriptor, &buffer, buffer.count, 0)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw OwnerGatewayError.invalidResponse }
            received.append(contentsOf: buffer.prefix(count))
            if framing == nil {
                if let split = received.range(of: Data([13, 10, 13, 10])) {
                    guard split.upperBound <= 16384 else { throw OwnerGatewayError.invalidResponse }
                    let (status, length) = try Self.responseHeader(received[..<split.lowerBound])
                    framing = (status, length, split.upperBound)
                } else if received.count > 16384 { throw OwnerGatewayError.invalidResponse }
            }
            if let (status, length, offset) = framing {
                guard received.count <= offset + length else { throw OwnerGatewayError.invalidResponse }
                if received.count == offset + length { return (status, received.subdata(in: offset..<received.count)) }
            }
        }
    }

    static func responseHeader(_ data: Data) throws -> (Int, Int) {
        guard let header = String(data: data, encoding: .utf8) else { throw OwnerGatewayError.invalidResponse }
        let lines = header.components(separatedBy: "\r\n")
        let statusLine = (lines.first ?? "").split(separator: " ")
        guard statusLine.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(statusLine[0])),
              let status = Int(statusLine[1]), (200...299).contains(status) || (400...599).contains(status) else {
            throw OwnerGatewayError.invalidResponse
        }
        var fields: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":"), colon != line.startIndex else { throw OwnerGatewayError.invalidResponse }
            let key = String(line[..<colon]).lowercased()
            guard fields[key] == nil else { throw OwnerGatewayError.invalidResponse }
            fields[key] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        guard fields["transfer-encoding"] == nil, let raw = fields["content-length"],
              !raw.isEmpty, raw.utf8.allSatisfy({ (48...57).contains($0) }),
              let length = Int(raw), (1...8_000_000).contains(length) else { throw OwnerGatewayError.invalidResponse }
        return (status, length)
    }
}
