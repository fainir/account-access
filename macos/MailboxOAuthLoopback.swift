import Foundation
import Network

enum MailboxOAuthFailure: Error { case unavailable, invalidAuthorization, cancelled, timedOut }

// This listener belongs to the signed desktop, never the dedicated worker.
// It receives only one state-bound provider redirect and never logs its URL.
final class MailboxOAuthLoopback {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "com.fainir.accountaccess.mailbox-callback")
    private let lock = NSLock()
    private let ready = DispatchSemaphore(value: 0)
    private let completion = DispatchSemaphore(value: 0)
    private let account: String
    private var localPort: UInt16?
    private var state: String?
    private var callback: String?
    private var closed = false
    private var waiting = false
    private var connections: [NWConnection] = []

    init(account: String) throws {
        guard account.range(of: "^[a-z][a-z0-9_-]{0,63}$", options: .regularExpression) != nil else {
            throw MailboxOAuthFailure.invalidAuthorization
        }
        self.account = account
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        listener.stateUpdateHandler = { [weak self] change in
            guard let self else { return }
            switch change {
            case .ready:
                self.lock.lock(); self.localPort = self.listener.port?.rawValue; self.lock.unlock()
                self.ready.signal()
            case .failed:
                self.ready.signal(); self.close()
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.lock.lock()
            guard !self.closed, self.connections.count < 8 else {
                self.lock.unlock(); connection.cancel(); return
            }
            self.connections.append(connection); self.lock.unlock()
            connection.start(queue: self.queue)
            self.receive(connection, data: Data(), deadline: Date().addingTimeInterval(3))
            self.queue.asyncAfter(deadline: .now() + 3) { connection.cancel() }
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success, port != nil else {
            close(); throw MailboxOAuthFailure.unavailable
        }
    }

    private var port: UInt16? { lock.lock(); defer { lock.unlock() }; return localPort }
    var redirectURI: String { "http://127.0.0.1:\(port ?? 0)/callback/" + account }

    func authorize(_ value: String) throws -> URL {
        guard let url = URL(string: value), let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              parts.scheme == "https", parts.host == "accounts.google.com", parts.port == nil,
              parts.path == "/o/oauth2/v2/auth", parts.user == nil, parts.password == nil, parts.fragment == nil else {
            throw MailboxOAuthFailure.invalidAuthorization
        }
        let items = parts.queryItems ?? []
        func single(_ name: String) -> String? {
            let matching = items.filter { $0.name == name }
            return matching.count == 1 ? matching[0].value : nil
        }
        guard let state = single("state"), (32...256).contains(state.utf8.count),
              single("redirect_uri") == redirectURI, single("code_challenge_method") == "S256",
              single("response_type") == "code", let client = single("client_id"), !client.isEmpty,
              let challenge = single("code_challenge"), challenge.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else {
            throw MailboxOAuthFailure.invalidAuthorization
        }
        lock.lock(); defer { lock.unlock() }
        guard !closed, self.state == nil else { throw MailboxOAuthFailure.cancelled }
        self.state = state
        return url
    }

    func wait(timeout: TimeInterval = 300) throws -> String {
        lock.lock()
        guard !closed, !waiting, state != nil, timeout > 0, timeout <= 300 else {
            lock.unlock(); throw MailboxOAuthFailure.cancelled
        }
        waiting = true; lock.unlock()
        guard completion.wait(timeout: .now() + timeout) == .success else {
            close(); throw MailboxOAuthFailure.timedOut
        }
        lock.lock(); defer { lock.unlock() }
        guard !closed, let callback else { throw MailboxOAuthFailure.cancelled }
        return callback
    }

    func close() {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        let active = connections; connections.removeAll()
        lock.unlock()
        listener.cancel()
        for connection in active { connection.cancel() }
        completion.signal()
    }

    private func receive(_ connection: NWConnection, data: Data, deadline: Date) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8193 - data.count) { [weak self] part, _, ended, error in
            guard let self else { connection.cancel(); return }
            let buffer = data + (part ?? Data())
            if buffer.count > 8192 || deadline < Date() || error != nil {
                self.respond(connection, accepted: nil); return
            }
            guard buffer.range(of: Data("\r\n\r\n".utf8)) != nil else {
                if ended { self.respond(connection, accepted: nil) }
                else { self.receive(connection, data: buffer, deadline: deadline) }
                return
            }
            self.lock.lock()
            let accepted: String?
            if !self.closed, self.callback == nil, let state = self.state, let port = self.localPort {
                accepted = Self.callback(buffer, port: port, account: self.account, state: state)
                if let accepted { self.callback = accepted }
            } else { accepted = nil }
            self.lock.unlock()
            self.respond(connection, accepted: accepted)
        }
    }

    private func respond(_ connection: NWConnection, accepted: String?) {
        let body = accepted == nil ? "This connection was not accepted. Return to Account Access."
            : "Sign-in received. Return to Account Access to see the connection result."
        let status = accepted == nil ? "400 Bad Request" : "200 OK"
        let response = "HTTP/1.1 \(status)\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: \(body.utf8.count)\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n" + body
        connection.send(content: Data(response.utf8), completion: .contentProcessed { [weak self] _ in
            connection.cancel()
            guard let self else { return }
            self.lock.lock(); self.connections.removeAll { $0 === connection }; self.lock.unlock()
            if accepted != nil { self.listener.cancel(); self.completion.signal() }
        })
    }

    static func callback(_ data: Data, port: UInt16, account: String, state: String) -> String? {
        guard data.count <= 8192, let raw = String(data: data, encoding: .ascii), raw.hasSuffix("\r\n\r\n") else { return nil }
        let lines = raw.components(separatedBy: "\r\n")
        guard (4...36).contains(lines.count), lines.suffix(2).allSatisfy({ $0.isEmpty }) else { return nil }
        let request = lines[0].components(separatedBy: " ")
        guard request.count == 3, request[0] == "GET", ["HTTP/1.1", "HTTP/1.0"].contains(request[2]),
              request[1].hasPrefix("/callback/" + account + "?"), !request[1].contains("#") else { return nil }
        var headers: [String: String] = [:]
        for line in lines.dropFirst().dropLast(2) {
            let field = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard field.count == 2, !field[0].isEmpty, field[0].allSatisfy({ $0.isASCII && ($0.isLetter || $0 == "-") }) else { return nil }
            let key = field[0].lowercased()
            guard headers[key] == nil else { return nil }
            headers[key] = field[1].trimmingCharacters(in: .whitespaces)
        }
        guard headers["host"] == "127.0.0.1:\(port)", headers["transfer-encoding"] == nil,
              headers["content-length"] == nil || headers["content-length"] == "0",
              let parts = URLComponents(string: "http://127.0.0.1:\(port)" + request[1]),
              parts.path == "/callback/" + account else { return nil }
        let items = parts.queryItems ?? []
        let states = items.filter { $0.name == "state" }
        let codes = items.filter { $0.name == "code" }
        let errors = items.filter { $0.name == "error" }
        guard states.count == 1, states[0].value == state else { return nil }
        if codes.count == 1, errors.isEmpty, let code = codes[0].value, (1...4096).contains(code.utf8.count) {
            return parts.string
        }
        if errors.count == 1, codes.isEmpty, let error = errors[0].value, (1...200).contains(error.utf8.count) {
            return parts.string
        }
        return nil
    }
    deinit { close() }
}
