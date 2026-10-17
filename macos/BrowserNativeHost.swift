// Chrome's fixed bridge into the protected worker. No vault or keyring access.
import Foundation
import Security
import Darwin

enum BrowserNativeHost {
    static let origin = "chrome-extension://nidjfmpcbbneapibefbhniaiijgigofo/"
    static let limit = 65536

    static func chromeParentAuthorized() -> Bool {
        let pid = getppid()
        guard pid > 1 else { return false }
        var before = proc_bsdinfo(), after = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, size) == size,
              before.pbi_pid == UInt32(pid), before.pbi_uid == getuid(), before.pbi_ruid == getuid() else { return false }
        let text = "anchor apple generic and identifier \"com.google.Chrome\" and certificate leaf[subject.OU] = \"EQHXZ8M8AV\" and !(entitlement[\"com.apple.security.get-task-allow\"] exists)"
        var requirement: SecRequirement?, code: SecCode?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess,
              let code, SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess,
              proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, size) == size,
              getppid() == pid, before.pbi_pid == after.pbi_pid, before.pbi_uid == after.pbi_uid,
              before.pbi_ruid == after.pbi_ruid, before.pbi_start_tvsec == after.pbi_start_tvsec,
              before.pbi_start_tvusec == after.pbi_start_tvusec else { return false }
        return true
    }

    private static func read(_ input: FileHandle, count: Int) throws -> Data {
        var value = Data()
        while value.count < count {
            guard let part = try input.read(upToCount: count - value.count), !part.isEmpty else { break }
            value.append(part)
        }
        return value
    }
    static func serve(input: FileHandle, output: FileHandle, presentedOrigin: String,
                      request: ([String: Any]) throws -> [String: Any]) -> Int32 {
        guard presentedOrigin == origin else { return 78 }
        do {
            while true {
                let header = try read(input, count: 4)
                if header.isEmpty { return 0 }
                guard header.count == 4 else { return 78 }
                let length = header.enumerated().reduce(UInt32(0)) { $0 | (UInt32($1.element) << ($1.offset * 8)) }
                guard (1...limit).contains(Int(length)) else { return 78 }
                let raw = try read(input, count: Int(length))
                guard raw.count == Int(length) else { return 78 }
                var id: NSNumber?
                var result: [String: Any] = ["status": "DENIED", "reason": "unsupported_browser_connection_request"]
                do {
                    guard let message = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
                          Set(message.keys) == ["id", "body"], let number = message["id"] as? NSNumber,
                          CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue >= 0,
                          number.doubleValue <= 2147483648, number.doubleValue.rounded() == number.doubleValue,
                          let body = message["body"] as? [String: Any] else { throw OwnerGatewayError.invalidPolicy }
                    id = number
                    let wrapped: [String: Any] = ["message": body]
                    _ = try OwnerGatewayRoute("owner/browser-message", body: JSONSerialization.data(withJSONObject: wrapped))
                    do { result = try request(wrapped) }
                    catch {
                        // No exception, message input, credentials or code is echoed.
                        result = ["status": "NEEDS_USER", "reason": "browser_connection_unavailable"]
                    }
                } catch { /* Invalid input retains the fixed denial above. */ }
                let encoded = try JSONSerialization.data(withJSONObject: ["id": (id as Any?) ?? NSNull(), "result": result])
                guard encoded.count <= limit else { return 78 }
                var size = UInt32(encoded.count).littleEndian
                try output.write(contentsOf: withUnsafeBytes(of: &size) { Data($0) })
                try output.write(contentsOf: encoded)
            }
        } catch { return 78 }
    }
    static func run(arguments: [String]) -> Int32 {
        guard getuid() != 0, getuid() == geteuid(), arguments == [origin], chromeParentAuthorized() else { return 78 }
        var core = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(RLIMIT_CORE, &core) == 0, let profile = try? DesktopOwnerProfile() else { return 78 }
        let connection = DesktopOwnerConnection(profile: profile)
        defer { connection.close() }
        return serve(input: .standardInput, output: .standardOutput, presentedOrigin: arguments[0]) { body in
            guard chromeParentAuthorized() else { throw DesktopOwnerFailure.unavailable }
            let response = try connection.request("owner/browser-message", body: body)
            guard chromeParentAuthorized() else { throw DesktopOwnerFailure.unavailable }
            return response.1
        }
    }
}
