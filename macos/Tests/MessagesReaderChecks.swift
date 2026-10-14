import Foundation
import AppKit
import SQLite3
import CryptoKit

@main struct Checks {
 static func main() throws {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent("aa-native-" + UUID().uuidString)
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
  defer { try? FileManager.default.removeItem(at: root) }
  let key = Data((0..<32).map { UInt8($0) })
  try key.write(to: root.appendingPathComponent("native-reader.key"))
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: root.appendingPathComponent("native-reader.key").path)
  let template = "Example [login]: {code}"
  let config: [String: Any] = ["code_sources": ["phone": ["kind": "mac_messages", "sender": "Example", "template": template]]]
  try JSONSerialization.data(withJSONObject: config).write(to: root.appendingPathComponent("config.json"))
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: root.appendingPathComponent("config.json").path)
  let path = root.appendingPathComponent("messages.db").path
  var db: OpaquePointer?
  precondition(sqlite3_open(path, &db) == SQLITE_OK)
  defer { sqlite3_close(db) }
  precondition(sqlite3_exec(db, "CREATE TABLE handle(id TEXT); INSERT INTO handle VALUES('Example'); INSERT INTO handle VALUES('Other'); CREATE TABLE message(guid TEXT, text TEXT, attributedBody BLOB, handle_id INTEGER, is_from_me INTEGER, date INTEGER);", nil, nil, nil) == SQLITE_OK)
  let now = Date().timeIntervalSince1970
  let date = Int64((now - 978307200) * 1_000_000_000)
  let rows = "INSERT INTO message VALUES('valid','Example [login]: 123456',NULL,1,0,\(date)); INSERT INTO message VALUES('payment','Payment: 654321',NULL,1,0,\(date)); INSERT INTO message VALUES('outgoing','Example [login]: 654321',NULL,1,1,\(date)); INSERT INTO message VALUES('wrong-sender','Example [login]: 654321',NULL,2,0,\(date)); INSERT INTO message VALUES('old','Example [login]: 654321',NULL,1,0,\(date - 300_000_000_000));"
  precondition(sqlite3_exec(db, rows, nil, nil, nil) == SQLITE_OK)
  var request: [String: Any] = ["source": "phone", "sender": "Example", "template": template, "started": now - 1, "used": [], "nonce": "example-request"]
  func payload() throws -> Data { try JSONSerialization.data(withJSONObject: request) }
  let bytes = try payload()
  let signature = HMAC<SHA256>.authenticationCode(for: bytes, using: SymmetricKey(data: key)).map { String(format: "%02x", $0) }.joined()
  let envelope = try JSONSerialization.data(withJSONObject: ["request": String(data: bytes, encoding: .utf8)!, "signature": signature])
  precondition(MessagesReader.authenticate(envelope, root: root) == bytes)
  let bad = try JSONSerialization.data(withJSONObject: ["request": String(data: bytes, encoding: .utf8)!, "signature": String(repeating: "0", count: 64)])
  precondition(MessagesReader.authenticate(bad, root: root) == nil)
  precondition(MessagesReader.read(bytes, path: path)["code"] as? String == "123456")
  request["used"] = ["valid"]
  let consumed = try payload()
  precondition(MessagesReader.read(consumed, path: path)["status"] as? String == "WAITING")
  let archived = try NSKeyedArchiver.archivedData(withRootObject: NSAttributedString(string: "Example [login]: 101010"), requiringSecureCoding: true)
  var insert: OpaquePointer?
  precondition(sqlite3_prepare_v2(db, "INSERT INTO message VALUES('archived',NULL,?,1,0,\(date))", -1, &insert, nil) == SQLITE_OK)
  archived.withUnsafeBytes { pointer in _ = sqlite3_bind_blob(insert, 1, pointer.baseAddress, Int32(archived.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
  precondition(sqlite3_step(insert) == SQLITE_DONE);sqlite3_finalize(insert)
  let attributed = try payload()
  precondition(MessagesReader.read(attributed, path: path)["code"] as? String == "101010")
  request["used"] = []
  let ambiguous = MessagesReader.read(try payload(), path: path)
  precondition(ambiguous["reason"] as? String == "ambiguous_login_code" && ambiguous["code"] == nil)
  print("PASS: signed request authentication, literal template, sender/time/incoming filters, used-message exclusion, attributed SMS text, ambiguity protection")
 }
}
