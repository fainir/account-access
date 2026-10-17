import Foundation
import AppKit
import SQLite3
import CryptoKit
import CoreFoundation

struct MessagesReader {
    static func messagesPath() -> String? {
        guard let user = getpwuid(getuid()) else { return nil }
        return URL(fileURLWithPath: String(cString: user.pointee.pw_dir))
            .appendingPathComponent("Library/Messages/chat.db").path
    }

    static func hasAccess(path: String) -> Bool {
        // Probe the required schema without reading any message row, sender,
        // body or code. SQLITE_OPEN_READONLY also prevents creating a missing DB.
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            if db != nil { sqlite3_close(db) }
            return false
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 1000)
        var statement: OpaquePointer?
        let sql = "SELECT message.guid, message.text, message.attributedBody, handle.id FROM message JOIN handle ON handle.ROWID=message.handle_id WHERE message.is_from_me=0 AND message.date>=0 LIMIT 0"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else { return false }
        defer { sqlite3_finalize(statement) }
        return sqlite3_step(statement) == SQLITE_DONE
    }

    static func hasAccess() -> Bool {
        guard let path = messagesPath() else { return false }
        return hasAccess(path: path)
    }

    static func githubTemplate(_ body: String) -> String? {
        let text = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.utf8.count <= 2000 else { return nil }
        let patterns = [
            "^([0-9]{6}) is your GitHub authentication code\\.$",
            "^Your GitHub authentication code is ([0-9]{6})\\.$",
            "^GitHub authentication code: ([0-9]{6})\\.?$",
            "^([0-9]{6}) is your GitHub verification code\\.$"
        ]
        for pattern in patterns {
            if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive),
               let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
               let range = Range(match.range(at: 1), in: text) {
                return text.replacingCharacters(in: range, with: "{code}")
            }
        }
        return nil
    }

    static func incomingBaseline(path: String) -> Int64? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            if db != nil { sqlite3_close(db) }
            return nil
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 1000)
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT COALESCE(MAX(ROWID),0) FROM message", -1, &statement, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return sqlite3_column_int64(statement, 0)
    }

    static func previewGitHubSMS(path: String, started: Double, afterRow: Int64? = nil) -> [String: String] {
        // One-time owner setup only. Inspect at most 20 fresh incoming texts,
        // accept only an identifiable GitHub login-code message, and return its
        // literal filter with the code removed. No message or code API is added.
        guard started.isFinite, started <= Date().timeIntervalSince1970,
              Date().timeIntervalSince1970 - started <= 120 else {
            return ["status": "NEEDS_USER", "reason": "sms_preview_expired"]
        }
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            if db != nil { sqlite3_close(db) }
            return ["status": "NEEDS_USER", "reason": "mac_messages_permission_required"]
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 1000)
        var statement: OpaquePointer?
        let sql = "SELECT handle.id,message.text,message.attributedBody FROM message JOIN handle ON handle.ROWID=message.handle_id WHERE message.is_from_me=0 AND message.date>=? AND message.date<=?" + (afterRow != nil ? " AND message.ROWID>?" : "") + " ORDER BY message.date DESC LIMIT 21"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            return ["status": "NEEDS_USER", "reason": "mac_messages_permission_required"]
        }
        defer { sqlite3_finalize(statement) }
        // A pre-request row boundary excludes every existing text. With that
        // boundary, tolerate small phone/carrier clock rounding without ever
        // considering the previous login's already-stored message.
        sqlite3_bind_double(statement, 1, (started - (afterRow != nil ? 5 : 0) - 978307200) * 1_000_000_000)
        sqlite3_bind_double(statement, 2, (min(started + 120, Date().timeIntervalSince1970 + 5) - 978307200) * 1_000_000_000)
        if let afterRow { sqlite3_bind_int64(statement, 3, afterRow) }
        var candidates: [[String: String]] = []
        var incoming = 0
        var unreadable = 0
        var status = sqlite3_step(statement)
        while status == SQLITE_ROW {
            incoming += 1
            guard incoming <= 20 else { return ["status": "NEEDS_USER", "reason": "ambiguous_login_code"] }
            if let handle = sqlite3_column_text(statement, 0) {
                let sender = String(cString: handle)
                var body = sqlite3_column_text(statement, 1).map { String(cString: $0) }
                if body?.isEmpty != false, sqlite3_column_bytes(statement, 2) <= 65536, let bytes = sqlite3_column_blob(statement, 2) {
                    let blob = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 2)))
                    body = MessageText.decode(blob)
                }
                if body == nil { unreadable += 1 }
                if !sender.isEmpty, sender.count <= 200, let body, let template = githubTemplate(body) {
                    candidates.append(["status": "FOUND", "sender": sender, "template": template])
                }
            }
            status = sqlite3_step(statement)
        }
        guard status == SQLITE_DONE else { return ["status": "NEEDS_USER", "reason": "mac_messages_permission_required"] }
        if candidates.count > 1 { return ["status": "NEEDS_USER", "reason": "ambiguous_login_code"] }
        return candidates.first ?? ["status": "WAITING", "incoming": String(incoming), "unreadable": String(unreadable)]
    }

    static func read(_ data: Data, path: String) -> [String: Any] {
        guard data.count <= 8192,
              let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              request["action"] as? String == "read",
              let rowNumber = request["after_row"] as? NSNumber,
              CFGetTypeID(rowNumber) != CFBooleanGetTypeID(),
              let afterRow = Int64(rowNumber.stringValue), afterRow >= 0,
              let sender = request["sender"] as? String, sender.count <= 200,
              let template = request["template"] as? String, template.count <= 2000,
              let started = request["started"] as? Double,
              started.isFinite, started <= Date().timeIntervalSince1970,
              Date().timeIntervalSince1970 - started <= 120 else {
            return ["status": "NEEDS_USER", "reason": "invalid_message_request"]
        }
        let parts = template.components(separatedBy: "{code}")
        guard parts.count == 2 else { return ["status": "NEEDS_USER", "reason": "invalid_message_request"] }
        let pattern = "^" + NSRegularExpression.escapedPattern(for: parts[0]) + "([0-9]{6})" + NSRegularExpression.escapedPattern(for: parts[1]) + "$"
        guard
              let regex = try? NSRegularExpression(pattern: pattern) else {
            return ["status": "NEEDS_USER", "reason": "invalid_message_request"]
        }
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            if db != nil { sqlite3_close(db) }
            return ["status": "NEEDS_USER", "reason": "mac_messages_permission_required"]
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 2000)
        var statement: OpaquePointer?
        let sql = "SELECT message.guid, message.text, message.attributedBody FROM message JOIN handle ON handle.ROWID=message.handle_id WHERE message.is_from_me=0 AND handle.id=? AND message.date>=? AND message.date<=? AND message.ROWID>? ORDER BY message.date DESC LIMIT 21"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            return ["status": "NEEDS_USER", "reason": "mac_messages_permission_required"]
        }
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(statement, 1, sender, -1, transient)
        sqlite3_bind_double(statement, 2, (started - 5 - 978307200) * 1_000_000_000)
        sqlite3_bind_double(statement, 3, (min(started + 120, Date().timeIntervalSince1970 + 5) - 978307200) * 1_000_000_000)
        sqlite3_bind_int64(statement, 4, afterRow)
        let used = Set(request["used"] as? [String] ?? [])
        var matches: [[String: Any]] = []
        var incoming = 0
        var status = sqlite3_step(statement)
        while status == SQLITE_ROW {
            incoming += 1
            // Reading the extra row detects a truncated result set. It must
            // never hide another matching code outside the first twenty rows.
            guard incoming <= 20 else { return ["status": "NEEDS_USER", "reason": "ambiguous_login_code"] }
            guard let guid = sqlite3_column_text(statement, 0) else { status = sqlite3_step(statement); continue }
            let id = String(cString: guid)
            var body = sqlite3_column_text(statement, 1).map { String(cString: $0) }
            if body?.isEmpty != false, sqlite3_column_bytes(statement, 2) <= 65536, let bytes = sqlite3_column_blob(statement, 2) {
                let blob = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 2)))
                body = MessageText.decode(blob)
            }
            if !used.contains(id), let text = body?.trimmingCharacters(in: .whitespacesAndNewlines), text.utf8.count <= 65536,
               let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
               match.numberOfRanges == 2, let range = Range(match.range(at: 1), in: text) {
                matches.append(["id": id, "code": String(text[range])])
            }
            status = sqlite3_step(statement)
        }
        guard status == SQLITE_DONE else { return ["status": "NEEDS_USER", "reason": "mac_messages_permission_required"] }
        if matches.count > 1 { return ["status": "NEEDS_USER", "reason": "ambiguous_login_code"] }
        return matches.first.map { ["status": "FOUND", "id": $0["id"]!, "code": $0["code"]!] } ?? ["status": "WAITING"]
    }

    static func begin(_ data: Data, path: String) -> [String: Any] {
        guard data.count <= 8192,
              let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              request["action"] as? String == "begin",
              let started = request["started"] as? Double, started.isFinite,
              started <= Date().timeIntervalSince1970,
              Date().timeIntervalSince1970 - started <= 120,
              let baseline = incomingBaseline(path: path) else {
            return ["status": "NEEDS_USER", "reason": "mac_messages_permission_required"]
        }
        // Metadata only, before password submission can trigger a login text.
        return ["status": "READY", "after_row": baseline]
    }

    static func run() {
        let data = (try? FileHandle.standardInput.read(upToCount: 8193)) ?? Data()
        guard let user = getpwuid(getuid()) else { return }
        let home = URL(fileURLWithPath: String(cString: user.pointee.pw_dir))
        // Bind the privileged reader to the signed app's data directory. A caller
        // cannot substitute an environment variable or a root in its request.
        let canonical = home.appendingPathComponent(".local/share/account-access")
        let legacy = home.appendingPathComponent("Library/Application Support/AccountAccess")
        let fallback = !FileManager.default.fileExists(atPath: canonical.appendingPathComponent("config.json").path) && FileManager.default.fileExists(atPath: legacy.appendingPathComponent("config.json").path) ? legacy : canonical
        let root = URL(fileURLWithPath: (Bundle.main.object(forInfoDictionaryKey: "AccountAccessDataDirectory") as? String) ?? fallback.path)
        guard let request = authenticate(data, root: root) else {
            FileHandle.standardOutput.write(Data("{\"status\":\"NEEDS_USER\",\"reason\":\"owner_authorization_required\"}".utf8))
            return
        }
        let path = home.appendingPathComponent("Library/Messages/chat.db").path
        let fields = (try? JSONSerialization.jsonObject(with: request)) as? [String: Any]
        let result = fields?["action"] as? String == "begin" ? begin(request, path: path) : read(request, path: path)
        if let output = try? JSONSerialization.data(withJSONObject: result) { FileHandle.standardOutput.write(output) }
    }

    static func authenticate(_ data: Data, root: URL) -> Data? {
        guard data.count <= 8192,
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let text = envelope["request"] as? String, let payload = text.data(using: .utf8),
              let signature = envelope["signature"] as? String, signature.count == 64,
              let request = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let source = request["source"] as? String else { return nil }
        let files = FileManager.default
        let keyPath = root.appendingPathComponent("native-reader.key")
        let configPath = root.appendingPathComponent("config.json")
        for path in [root, keyPath, configPath] {
            guard let info = try? files.attributesOfItem(atPath: path.path),
                  info[.type] as? FileAttributeType != .typeSymbolicLink,
                  (info[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
                  ((info[.posixPermissions] as? NSNumber)?.intValue ?? 0o777) & 0o077 == 0 else { return nil }
        }
        guard let key = try? Data(contentsOf: keyPath), key.count == 32,
              let configData = try? Data(contentsOf: configPath),
              let config = try? JSONSerialization.jsonObject(with: configData) as? [String: Any],
              let sources = config["code_sources"] as? [String: [String: Any]],
              let spec = sources[source], spec["kind"] as? String == "mac_messages",
              spec["sender"] as? String == request["sender"] as? String,
              spec["template"] as? String == request["template"] as? String else { return nil }
        var code = Data()
        var index = signature.startIndex
        while index < signature.endIndex {
            let end = signature.index(index, offsetBy: 2)
            guard let value = UInt8(signature[index..<end], radix: 16) else { return nil }
            code.append(value); index = end
        }
        return HMAC<SHA256>.isValidAuthenticationCode(code, authenticating: payload, using: SymmetricKey(data: key)) ? payload : nil
    }
}
