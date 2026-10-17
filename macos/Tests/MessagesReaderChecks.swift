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
  precondition(MessagesReader.hasAccess(path: path))
  let missing = root.appendingPathComponent("missing.db").path
  precondition(!MessagesReader.hasAccess(path: missing))
  precondition(!FileManager.default.fileExists(atPath: missing))
  let now = Date().timeIntervalSince1970
  let date = Int64((now - 978307200) * 1_000_000_000)
  let rows = "INSERT INTO message VALUES('valid','Example [login]: 123456',NULL,1,0,\(date)); INSERT INTO message VALUES('payment','Payment: 654321',NULL,1,0,\(date)); INSERT INTO message VALUES('outgoing','Example [login]: 654321',NULL,1,1,\(date)); INSERT INTO message VALUES('wrong-sender','Example [login]: 654321',NULL,2,0,\(date)); INSERT INTO message VALUES('old','Example [login]: 654321',NULL,1,0,\(date - 300_000_000_000));"
  precondition(sqlite3_exec(db, rows, nil, nil, nil) == SQLITE_OK)
  var request: [String: Any] = ["action": "read", "after_row": 0, "source": "phone", "sender": "Example", "template": template, "started": now - 1, "used": [], "nonce": "example-request"]
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
  precondition(MessagesReader.githubTemplate("123456 is your GitHub authentication code.") == "{code} is your GitHub authentication code.")
  precondition(MessagesReader.githubTemplate("GitHub authentication code: 123456. Approve payment") == nil)
  precondition(MessagesReader.githubTemplate("GitHub authentication code: 123456; 654321") == nil)
  precondition(MessagesReader.githubTemplate("GitHub password reset verification code: 123456") == nil)
  precondition(MessagesReader.githubTemplate("123456 is your GitHub authentication code. Private unrelated text") == nil)
  precondition(sqlite3_exec(db, "INSERT INTO message VALUES('github','123456 is your GitHub authentication code.',NULL,1,0,\(date))", nil, nil, nil) == SQLITE_OK)
  let preview = MessagesReader.previewGitHubSMS(path: path, started: now - 1)
  precondition(preview["status"] == "FOUND" && preview["template"] == "{code} is your GitHub authentication code.")
  let previewJSON = String(data: try JSONSerialization.data(withJSONObject: preview), encoding: .utf8)!
  precondition(!previewJSON.contains("123456"))
  precondition(MessagesReader.previewGitHubSMS(path: path, started: now - 121)["reason"] == "sms_preview_expired")
  precondition(sqlite3_exec(db, "INSERT INTO message VALUES('github-second','654321 is your GitHub authentication code.',NULL,1,0,\(date))", nil, nil, nil) == SQLITE_OK)
  precondition(MessagesReader.previewGitHubSMS(path: path, started: now - 1)["reason"] == "ambiguous_login_code")
  let fixtureURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/messages-typedstream.json")
  let fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as! [String: Any]
  let cases = fixture["cases"] as! [[String: Any]]
  func hex(_ value: String) -> Data {
    var result = Data(); var index = value.startIndex
    while index < value.endIndex {
      let end = value.index(index, offsetBy: 2)
      result.append(UInt8(value[index..<end], radix: 16)!); index = end
    }
    return result
  }
  for test in cases {
    let data = hex(test["hex"] as! String)
    let expected = test["text"] as? String
    guard MessageText.decode(data) == expected else { fatalError("Foundation fixture failed: " + (test["name"] as! String)) }
  }
  let short = hex(cases.first { $0["name"] as? String == "short" }!["hex"] as! String)
  let text = Data("Example [login]: 121212".utf8)
  let content = short.range(of: text)!
  for count in 0..<content.upperBound { precondition(MessageText.decode(short.prefix(count)) == nil) }
  var invalidUTF8 = short; invalidUTF8[content.lowerBound] = 0xff
  precondition(MessageText.decode(invalidUTF8) == nil)
  var invalidLength = short; invalidLength[content.lowerBound - 1] = 0x83
  precondition(MessageText.decode(invalidLength) == nil)
  precondition(MessageText.decode(Data(repeating: 0x84, count: 65537)) == nil)
  let github = hex(cases.first { $0["name"] as? String == "github" }!["hex"] as! String)
  precondition(sqlite3_exec(db, "DELETE FROM message", nil, nil, nil) == SQLITE_OK)
  var typedInsert: OpaquePointer?
  precondition(sqlite3_prepare_v2(db, "INSERT INTO message VALUES('typedstream',NULL,?,1,0,\(date))", -1, &typedInsert, nil) == SQLITE_OK)
  github.withUnsafeBytes { pointer in _ = sqlite3_bind_blob(typedInsert, 1, pointer.baseAddress, Int32(github.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
  precondition(sqlite3_step(typedInsert) == SQLITE_DONE); sqlite3_finalize(typedInsert)
  request["used"] = []; request["template"] = "{code} is your GitHub authentication code."
  let typedRequest = try payload()
  precondition(MessagesReader.read(typedRequest, path: path)["code"] as? String == "121212")
  precondition(MessagesReader.previewGitHubSMS(path: path, started: now - 1)["status"] == "FOUND")
  let baseline = MessagesReader.incomingBaseline(path: path)!
  precondition(MessagesReader.previewGitHubSMS(path: path, started: now - 1, afterRow: baseline)["status"] == "WAITING")
  precondition(sqlite3_exec(db, "INSERT INTO message VALUES('rounded-phone-time','343434 is your GitHub authentication code.',NULL,1,0,\(date - 2_000_000_000))", nil, nil, nil) == SQLITE_OK)
  precondition(MessagesReader.previewGitHubSMS(path: path, started: now - 1, afterRow: baseline)["status"] == "FOUND")
  request["after_row"] = baseline
  let roundedRead = MessagesReader.read(try payload(), path: path)
  precondition(roundedRead["code"] as? String == "343434")
  var beginRequest = request; beginRequest["action"] = "begin"
  let boundary = MessagesReader.begin(try JSONSerialization.data(withJSONObject: beginRequest), path: path)
  precondition(boundary["status"] as? String == "READY" && boundary["code"] == nil)
  request["after_row"] = boundary["after_row"]
  let oldRead = MessagesReader.read(try payload(), path: path)
  precondition(oldRead["status"] as? String == "WAITING")
  for invalid: Any in [true, -1, 0.5, "0", NSNull()] {
    request["after_row"] = invalid
    let invalidRead = MessagesReader.read(try payload(), path: path)
    precondition(invalidRead["reason"] as? String == "invalid_message_request")
  }
  request["after_row"] = baseline; request["started"] = now + 60
  let futureRead = MessagesReader.read(try payload(), path: path)
  precondition(futureRead["reason"] as? String == "invalid_message_request")
  request["started"] = now - 1; request["after_row"] = 0
  precondition(sqlite3_exec(db, "DELETE FROM message; INSERT INTO message VALUES('future-code','565656 is your GitHub authentication code.',NULL,1,0,\(date + 60_000_000_000));", nil, nil, nil) == SQLITE_OK)
  let futureMessage = MessagesReader.read(try payload(), path: path)
  precondition(futureMessage["status"] as? String == "WAITING")
  precondition(MessagesReader.previewGitHubSMS(path: path, started: now - 1)["status"] == "WAITING")
  precondition(sqlite3_exec(db, "DELETE FROM message; INSERT INTO message VALUES('hidden-second','787878 is your GitHub authentication code.',NULL,1,0,\(date - 500_000_000)); INSERT INTO message VALUES('visible-first','909090 is your GitHub authentication code.',NULL,1,0,\(date));", nil, nil, nil) == SQLITE_OK)
  for index in 0..<19 {
    precondition(sqlite3_exec(db, "INSERT INTO message VALUES('nonmatching-\(index)','Ordinary sender text',NULL,1,0,\(date));", nil, nil, nil) == SQLITE_OK)
  }
  let limited = MessagesReader.read(try payload(), path: path)
  precondition(limited["reason"] as? String == "ambiguous_login_code" && limited["code"] == nil)
  let previewLimited = MessagesReader.previewGitHubSMS(path: path, started: now - 1)
  precondition(previewLimited["reason"] == "ambiguous_login_code" && previewLimited["template"] == nil)
  print("PASS: future-dated messages are excluded and a truncated result set cannot hide a second login code")
  print("PASS: setup and normal SMS login ignore existing rows while allowing a small clock offset on a newly delivered text; invalid boundaries stop safely")
  print("PASS: Foundation-generated typedstream text, Unicode lengths, mutable strings, metadata exclusion, malformed archives and the native SMS paths")
  print("PASS: owner SMS template preview excludes codes, unrelated messages, expired requests and ambiguous deliveries")
  print("PASS: no-row permission probe, signed request authentication, literal template, sender/time/incoming filters, used-message exclusion, attributed SMS text, ambiguity protection")
 }
}
