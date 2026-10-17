// A headless owner-UID reader. No legacy key/config is copied from the broker.
// Its only authority is a protected profile and the kernel's parent chain.
import Foundation
import Security
import Darwin

struct SystemMessagesReader {
    static func parentAuthorized(_ peer: OwnerGatewayPeer) -> Bool {
        guard getuid() != 0, geteuid() == getuid(), peer.uid == 0 else { return false }
        var pid = getppid()
        for _ in 0..<4 {
            guard pid > 1 else { return false }
            var before = proc_bsdinfo()
            let size = Int32(MemoryLayout<proc_bsdinfo>.size)
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, size) == size else { return false }
            if before.pbi_uid == 0 && before.pbi_ruid == 0 {
                var code: SecCode?, requirement: SecRequirement?
                if SecRequirementCreateWithString(peer.requirement as CFString, [], &requirement) == errSecSuccess,
                   let requirement,
                   SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess,
                   let code, SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess {
                    var after = proc_bsdinfo()
                    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, size) == size
                        && after.pbi_uid == 0 && after.pbi_ruid == 0
                        && before.pbi_start_tvsec == after.pbi_start_tvsec && before.pbi_start_tvusec == after.pbi_start_tvusec
                }
            }
            // sudo can use a monitor process. Only the immutable OS executable
            // may intervene before the pinned root broker, never an arbitrary
            // process merely running as root or bearing a chosen argv[0].
            var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            guard proc_pidpath(pid, &path, UInt32(path.count)) > 0,
                  String(cString: path) == "/usr/bin/sudo",
                  [uid_t(0), getuid()].contains(before.pbi_uid),
                  [uid_t(0), getuid()].contains(before.pbi_ruid) else { return false }
            var after = proc_bsdinfo()
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, size) == size,
                  before.pbi_uid == after.pbi_uid, before.pbi_ruid == after.pbi_ruid,
                  before.pbi_ppid == after.pbi_ppid,
                  before.pbi_start_tvsec == after.pbi_start_tvsec,
                  before.pbi_start_tvusec == after.pbi_start_tvusec else { return false }
            pid = pid_t(before.pbi_ppid)
        }
        return false
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
