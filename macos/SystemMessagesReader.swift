// A headless owner-UID reader. No legacy key/config is copied from the broker.
// Its only authority is a protected profile and the kernel's socket peer token.
import Foundation
import Security
import Darwin

struct SystemMessagesReader {
    static func parentAuthorized(_ peer: OwnerGatewayPeer) -> Bool {
        guard getuid() != 0, geteuid() == getuid(), peer.uid == 0 else { return false }
        // The root broker creates this anonymous socket before switching the
        // reader UID. The kernel retains its creator's audit identity across
        // exec/sudo; no PID supplied by a caller is trusted here.
        var token = audit_token_t()
        var size = socklen_t(MemoryLayout<audit_token_t>.size)
        var uid: uid_t = 0, gid: gid_t = 0
        guard getsockopt(STDIN_FILENO, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) == 0,
              size == MemoryLayout<audit_token_t>.size,
              getpeereid(STDIN_FILENO, &uid, &gid) == 0, uid == 0,
              audit_token_to_euid(token) == 0, audit_token_to_ruid(token) == 0,
              audit_token_to_pid(token) > 1 else { return false }
        let data = withUnsafeBytes(of: &token) { Data($0) }
        var code: SecCode?, requirement: SecRequirement?
        guard SecRequirementCreateWithString(peer.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code) == errSecSuccess,
              let code else { return false }
        return SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess
    }

    static func validRequest(_ data: Data) -> Bool {
        guard data.count <= 8192,
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let action = value["action"] as? String, ["begin", "read"].contains(action),
              Set(value.keys) == Set(["action", "source", "sender", "template", "started"] + (action == "read" ? ["after_row", "used"] : [])),
              let started = value["started"] as? NSNumber, CFGetTypeID(started) != CFBooleanGetTypeID(),
              started.doubleValue.isFinite, (0...120).contains(Date().timeIntervalSince1970 - started.doubleValue),
              let template = value["template"] as? String, template.components(separatedBy: "{code}").count == 2 else { return false }
        for (name, maximum) in [("source", 128), ("sender", 200), ("template", 1024)] {
            guard let text = value[name] as? String, (1...maximum).contains(text.utf8.count),
                  !text.unicodeScalars.contains(where: { $0.value < 32 }) else { return false }
        }
        if action == "read" {
            guard let row = value["after_row"] as? NSNumber, CFGetTypeID(row) != CFBooleanGetTypeID(),
                  let integer = Int64(row.stringValue), integer >= 0,
                  let used = value["used"] as? [String], used.count <= 100,
                  used.allSatisfy({ (1...128).contains($0.utf8.count) }) else { return false }
        }
        return true
    }
    static func perform(_ data: Data, peer: OwnerGatewayPeer, path: String) -> [String: Any] {
        guard parentAuthorized(peer), validRequest(data) else { return ["status": "NEEDS_USER", "reason": "owner_authorization_required"] }
        let value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        let response: [String: Any] = value?["action"] as? String == "begin"
            ? MessagesReader.begin(data, path: path) : MessagesReader.read(data, path: path)
        guard parentAuthorized(peer), validRequest(data) else { return ["status": "NEEDS_USER", "reason": "owner_authorization_required"] }
        return response
    }
    static func run() {
        var core = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(RLIMIT_CORE, &core) == 0 else { return }
        var output: [String: Any] = ["status": "NEEDS_USER", "reason": "owner_authorization_required"]
        // Reject an agent invocation before reading its stdin or any message.
        if let profile = try? DesktopOwnerProfile(), parentAuthorized(profile.peer), let path = MessagesReader.messagesPath() {
            announce()
            var data = Data()
            while data.count <= 8192 {
                guard let part = try? FileHandle.standardInput.read(upToCount: 8193 - data.count), !part.isEmpty else { break }
                data.append(part)
            }
            output = perform(data, peer: profile.peer, path: path)
        }
        if let data = try? JSONSerialization.data(withJSONObject: output) { FileHandle.standardOutput.write(data) }
    }
    static func announce() {
        if var data = try? JSONSerialization.data(withJSONObject: ["status": "READER_READY", "pid": Int(getpid())]) {
            data.append(10)
            FileHandle.standardOutput.write(data)
        }
    }
}
