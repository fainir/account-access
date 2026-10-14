import Foundation
import AppKit
import SQLite3
import CryptoKit

struct MessagesReader {
    static func read(_ data: Data, path: String) -> [String: Any] {
        guard data.count <= 8192,
              let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sender = request["sender"] as? String, sender.count <= 200,
              let template = request["template"] as? String, template.count <= 2000,
              let started = request["started"] as? Double,
              started.isFinite, abs(Date().timeIntervalSince1970 - started) <= 120 else {
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
        let sql = "SELECT message.guid, message.text, message.attributedBody FROM message JOIN handle ON handle.ROWID=message.handle_id WHERE message.is_from_me=0 AND handle.id=? AND message.date>=? ORDER BY message.date DESC LIMIT 20"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            return ["status": "NEEDS_USER", "reason": "mac_messages_permission_required"]
        }
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(statement, 1, sender, -1, transient)
        sqlite3_bind_double(statement, 2, (started - 978307200) * 1_000_000_000)
        let used = Set(request["used"] as? [String] ?? [])
        var matches: [[String: Any]] = []
        var status = sqlite3_step(statement)
        while status == SQLITE_ROW {
            guard let guid = sqlite3_column_text(statement, 0) else { status = sqlite3_step(statement); continue }
            let id = String(cString: guid)
            var body = sqlite3_column_text(statement, 1).map { String(cString: $0) }
            if body == nil, sqlite3_column_bytes(statement, 2) <= 65536, let bytes = sqlite3_column_blob(statement, 2) {
                let blob = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 2)))
                body = (try? NSKeyedUnarchiver.unarchivedObject(ofClass: NSAttributedString.self, from: blob))?.string
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
        let result = read(request, path: path)
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
