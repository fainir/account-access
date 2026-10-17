// Private root-to-owner reader bridge. No new agent/XPC route or reader key.
import Foundation
import Security
import Darwin

enum RootMessagesFailure: String, Error {
    case unavailable = "native_messages_reader_unavailable"
    case rejected = "native_messages_reader_rejected"
    case readerCode = "native_messages_reader_code_rejected"
    case readerIdentity = "native_messages_reader_identity_rejected"
    case readerAncestry = "native_messages_reader_ancestry_rejected"
    case handshake = "native_messages_reader_handshake_rejected"
}

final class RootMessagesCollector {
    private let owner: OwnerGatewayPeer
    private let app: String
    private let arguments: [String]
    init(owner: OwnerGatewayPeer) throws {
        try RootVaultKeyStore.requireDaemon()
        guard owner.uid != 0 else { throw RootMessagesFailure.rejected }
        self.owner = owner
        app = "/Applications/Account Access.app/Contents/MacOS/AccountAccess"
        arguments = ["--system-read-login-code"]
    }
    #if ACCOUNT_ACCESS_GATEWAY_CHECKS
    private init(owner: OwnerGatewayPeer, app: String, arguments: [String]) throws {
        try RootVaultKeyStore.requireDaemon()
        guard app.hasPrefix("/Library/PrivilegedHelperTools/account-access-worker-qa-"), owner.uid != 0 else { throw RootMessagesFailure.rejected }
        self.owner = owner; self.app = try WorkerLaunchPaths.protected(app).path; self.arguments = arguments
    }
    static func fixture(owner: OwnerGatewayPeer, app: String, arguments: [String]) throws -> RootMessagesCollector {
        try RootMessagesCollector(owner: owner, app: app, arguments: arguments)
    }
    #endif
    private func checkCode() throws {
        var code: SecStaticCode?, requirement: SecRequirement?
        guard SecRequirementCreateWithString(owner.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecStaticCodeCreateWithPath(URL(fileURLWithPath: app) as CFURL, [], &code) == errSecSuccess,
              let code, SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw RootMessagesFailure.readerCode
        }
    }
    private func checkReader(_ pid: pid_t, launcher: pid_t, birth: proc_bsdinfo) throws {
        var first = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        var current = proc_bsdinfo()
        guard proc_pidinfo(launcher, PROC_PIDTBSDINFO, 0, &current, size) == size,
              current.pbi_start_tvsec == birth.pbi_start_tvsec,
              current.pbi_start_tvusec == birth.pbi_start_tvusec else { throw RootMessagesFailure.rejected }
        guard pid > 1, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &first, size) == size,
              first.pbi_uid == owner.uid, first.pbi_ruid == owner.uid, first.pbi_svuid == owner.uid else { throw RootMessagesFailure.readerIdentity }
        var code: SecCode?, requirement: SecRequirement?
        guard SecRequirementCreateWithString(owner.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess,
              let code, SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw RootMessagesFailure.readerCode }
        var after = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, size) == size,
              first.pbi_start_tvsec == after.pbi_start_tvsec, first.pbi_start_tvusec == after.pbi_start_tvusec,
              first.pbi_ppid == after.pbi_ppid, after.pbi_uid == owner.uid,
              after.pbi_ruid == owner.uid, after.pbi_svuid == owner.uid else { throw RootMessagesFailure.rejected }
        if pid == launcher { return } // sudo may replace itself instead of retaining a monitor.
        var ancestor = pid_t(after.pbi_ppid)
        for _ in 0..<4 {
            if ancestor == launcher { return }
            var info = proc_bsdinfo()
            var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            guard ancestor > 1, proc_pidinfo(ancestor, PROC_PIDTBSDINFO, 0, &info, size) == size,
                  [uid_t(0), owner.uid].contains(info.pbi_uid),
                  [uid_t(0), owner.uid].contains(info.pbi_ruid),
                  proc_pidpath(ancestor, &path, UInt32(path.count)) > 0,
                  String(cString: path) == "/usr/bin/sudo" else { throw RootMessagesFailure.readerAncestry }
            ancestor = pid_t(info.pbi_ppid)
        }
        throw RootMessagesFailure.readerAncestry
    }
    func read(_ body: Data) throws -> [String: Any] {
        try RootVaultKeyStore.requireDaemon()
        guard body.count <= 8192 else { throw RootMessagesFailure.rejected }
        try checkCode()
        let process = Process()
        var descriptors: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else { throw RootMessagesFailure.unavailable }
        let channel = FileHandle(fileDescriptor: descriptors[0], closeOnDealloc: true)
        let child = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true)
        defer { try? channel.close(); try? child.close() }
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["asuser", String(owner.uid), "/usr/bin/sudo", "-n", "-H", "-u", "#" + String(owner.uid), "--", app] + arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"]
        process.standardInput = child; process.standardOutput = child; process.standardError = FileHandle.nullDevice
        guard fcntl(channel.fileDescriptor, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(child.fileDescriptor, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(channel.fileDescriptor, F_SETNOSIGPIPE, 1) == 0,
              fcntl(channel.fileDescriptor, F_SETFL, O_NONBLOCK) == 0 else { throw RootMessagesFailure.unavailable }
        try process.run()
        var birth = proc_bsdinfo()
        guard proc_pidinfo(process.processIdentifier, PROC_PIDTBSDINFO, 0, &birth,
                           Int32(MemoryLayout<proc_bsdinfo>.size)) == Int32(MemoryLayout<proc_bsdinfo>.size) else {
            if process.isRunning { process.terminate() }
            throw RootMessagesFailure.unavailable
        }
        try child.close()
        defer { if process.isRunning { process.terminate() } }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 1024)
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        var eof = false
        var attested = false
        while ProcessInfo.processInfo.systemUptime < deadline {
            let count = Darwin.read(channel.fileDescriptor, &buffer, buffer.count)
            if count > 0 {
                data.append(contentsOf: buffer.prefix(count))
                guard data.count <= 4096 else { throw RootMessagesFailure.rejected }
            } else if count == 0 { eof = true }
            else if errno != EAGAIN && errno != EINTR { throw RootMessagesFailure.unavailable }
            if !attested, let split = data.firstIndex(of: 10) {
                guard let hello = try JSONSerialization.jsonObject(with: data[..<split]) as? [String: Any],
                      Set(hello.keys) == ["status", "pid"], hello["status"] as? String == "READER_READY",
                      let id = hello["pid"] as? NSNumber, CFGetTypeID(id) != CFBooleanGetTypeID(),
                      id.int64Value > 1, id.int64Value <= Int64(Int32.max), id.doubleValue == Double(id.int64Value) else { throw RootMessagesFailure.rejected }
                guard process.isRunning else { throw RootMessagesFailure.rejected }
                try checkReader(pid_t(id.int32Value), launcher: process.processIdentifier, birth: birth)
                guard process.isRunning else { throw RootMessagesFailure.rejected }
                attested = true
                data.removeSubrange(...split)
                try channel.write(contentsOf: body)
                guard shutdown(channel.fileDescriptor, SHUT_WR) == 0 else { throw RootMessagesFailure.unavailable }
            }
            if eof && !process.isRunning { break }
            Thread.sleep(forTimeInterval: 0.01)
        }
        guard attested else { throw RootMessagesFailure.handshake }
        guard eof, !process.isRunning, process.terminationStatus == 0,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw RootMessagesFailure.unavailable }
        return value
    }
    func poll(_ backend: OwnerUnixBackend) {
        do {
            let result = try backend.nativeMessagesNext()
            guard result.0 == 200,
                  let value = try JSONSerialization.jsonObject(with: result.1) as? [String: Any],
                  value["status"] as? String == "OK",
                  let request = value["request"] as? [String: Any], Set(request.keys) == ["id", "body"],
                  let id = request["id"] as? String, id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
                  let body = request["body"] as? [String: Any] else { return }
            let payload = try JSONSerialization.data(withJSONObject: body)
            let response: [String: Any]
            do {
                let value = try read(payload)
                response = value["reason"] as? String == "owner_authorization_required"
                    ? ["status": "RETRYABLE", "reason": "mac_messages_reader_unavailable"] : value
            }
            catch { response = ["status": "RETRYABLE", "reason": "mac_messages_reader_unavailable"] }
            // Exactly one delivery attempt. A lost response is not replayed;
            // the worker retains the matching pending request until completion.
            _ = try backend.nativeMessagesRespond(JSONSerialization.data(withJSONObject: ["id": id, "response": response]))
        } catch { /* Fixed, silent failure: no source metadata or codes logged. */ }
    }
}
