import Foundation
import SQLite3
import Darwin

#if !ACCOUNT_ACCESS_ROOT_KEY_CHECKS || !ACCOUNT_ACCESS_GATEWAY_CHECKS
#error("Native SMS acceptance runs in disposable CI only")
#endif

enum RootMessagesChecks {
    static func run(_ value: [String: Any]) throws -> [String: Bool] {
        try RootVaultKeyStore.requireDaemon()
        let root = try WorkerLaunchPaths.protected(WorkerLaunchPaths.lexical(value["root"]))
        let settings = try WorkerLaunchPaths.object(root.appendingPathComponent("native-messages-fixture.json").path)
        guard Set(settings.keys) == ["owner_uid", "helper_hash", "parent_hash"],
              let helperHash = settings["helper_hash"] as? String, let parentHash = settings["parent_hash"] as? String else { throw WorkerLaunchFailure.invalidPolicy }
        let owner = try WorkerLaunchPaths.integer(settings["owner_uid"])
        guard let account = getpwuid(owner), owner != 0 else { throw WorkerLaunchFailure.invalidIdentity }
        let group = account.pointee.pw_gid
        let directory = root.appendingPathComponent("native-messages-owner")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        guard chown(directory.path, owner, group) == 0 else { throw WorkerLaunchFailure.invalidIdentity }
        let path = directory.appendingPathComponent("messages.sqlite").path
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK else { throw WorkerLaunchFailure.invalidPolicy }
        defer { sqlite3_close(db) }
        func sql(_ text: String) throws {
            guard sqlite3_exec(db, text, nil, nil, nil) == SQLITE_OK else { throw WorkerLaunchFailure.invalidPolicy }
        }
        try sql("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY,id TEXT); CREATE TABLE message (guid TEXT,text TEXT,attributedBody BLOB,handle_id INTEGER,is_from_me INTEGER,date INTEGER); INSERT INTO handle VALUES(1,'Example');")
        guard chown(path, owner, group) == 0, chmod(path, 0o600) == 0 else { throw WorkerLaunchFailure.invalidIdentity }
        let profile = root.appendingPathComponent("native-messages-profile.json")
        func publish(_ hash: String) throws {
            try JSONSerialization.data(withJSONObject: ["owner_uid": Int(owner), "parent_hash": hash]).write(to: profile, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: profile.path)
        }
        try publish(parentHash)
        let peer = try OwnerGatewayPeer.fixture(uid: owner, codeHash: helperHash)
        let collector = try RootMessagesCollector.fixture(owner: peer, app: root.appendingPathComponent("native-messages-helper").path,
            arguments: [profile.path, path])
        var checks: [String: Bool] = [:]
        let started = Date().timeIntervalSince1970
        var request: [String: Any] = ["action": "begin", "source": "fixture-sms", "sender": "Example", "template": "Example login: {code}", "started": started]
        func call() throws -> [String: Any] { try collector.read(JSONSerialization.data(withJSONObject: request)) }
        let baseline = try call()
        checks["root_launches_reader_as_separate_owner_uid"] = baseline["status"] as? String == "READY" && baseline["after_row"] as? Int == 0
        let date = Int64((Date().timeIntervalSince1970 - 978307200) * 1_000_000_000)
        try sql("INSERT INTO message VALUES('fresh','Example login: 123456',NULL,1,0,\(date));")
        request["action"] = "read"; request["after_row"] = 0; request["used"] = [String]()
        let found = try call()
        checks["private_socket_returns_matching_fresh_fixture_code"] = found["status"] as? String == "FOUND" && found["code"] as? String == "123456" && found["id"] as? String == "fresh"
        request["used"] = ["fresh"]
        checks["already_used_message_excluded"] = try call()["status"] as? String == "WAITING"
        request["used"] = [String](); request["after_row"] = 1
        checks["pre_request_baseline_excludes_old_messages"] = try call()["status"] as? String == "WAITING"
        request["after_row"] = 0; request["started"] = started - 121
        checks["expired_native_request_refused"] = try call()["reason"] as? String == "owner_authorization_required"
        request["started"] = started
        try publish(String(repeating: "a", count: 40))
        do { _ = try call(); checks["wrong_root_parent_signature_refused"] = false }
        catch { checks["wrong_root_parent_signature_refused"] = true }
        try publish(parentHash)
        request["after_row"] = true
        checks["boolean_baseline_refused"] = try call()["reason"] as? String == "owner_authorization_required"
        request["after_row"] = 0
        try sql("INSERT INTO message VALUES('second','Example login: 654321',NULL,1,0,\(date));")
        checks["ambiguous_matching_texts_refused"] = try call()["reason"] as? String == "ambiguous_login_code"
        let rejected = try RootMessagesCollector.fixture(owner: .fixture(uid: owner, codeHash: String(repeating: "b", count: 40)),
            app: root.appendingPathComponent("native-messages-helper").path, arguments: [profile.path, path])
        do { _ = try rejected.read(JSONSerialization.data(withJSONObject: request)); checks["wrong_reader_code_refused_before_launch"] = false }
        catch { checks["wrong_reader_code_refused_before_launch"] = true }
        let forged = try RootMessagesCollector.fixture(owner: peer, app: root.appendingPathComponent("native-messages-helper").path,
            arguments: [profile.path, path, "--wrong-pid"])
        do { _ = try forged.read(JSONSerialization.data(withJSONObject: request)); checks["forged_reader_pid_refused_before_request"] = false }
        catch { checks["forged_reader_pid_refused_before_request"] = true }
        return checks
    }
}
