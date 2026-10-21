// Identity checks for fixed public code and the existing system job only.
// No account-store/keychain reads, PID signaling, service actions or adoption.
import Foundation
import CoreFoundation
import Security
import Darwin

struct ComponentJobIdentity: Codable, Equatable {
    let pid: Int32
    let group: UInt32
    let birthSec: UInt64
    let birthUsec: UInt64
    let bootSession: String
}

enum ComponentUpdateIdentity {
    private static let broker = "/Library/Application Support/Account Access/bin/AccountAccess-broker"
    private static let label = "com.fainir.accountaccess.broker"
    private static let identifier = "com.fainir.accountaccess.componentupdate"

    private static func matches(_ text: String, _ pattern: String) -> Bool {
        text.range(of: pattern, options: .regularExpression) != nil
    }
    private static func peerValid(_ peer: ComponentPeerSignature) -> Bool {
        matches(peer.team, "^[A-Z0-9]{10}$") && matches(peer.identifier, "^[A-Za-z0-9][A-Za-z0-9.-]{1,199}$")
            && (1...2).contains(peer.hashes.count) && peer.hashes == Array(Set(peer.hashes)).sorted()
            && peer.hashes.allSatisfy({ matches($0, "^[a-f0-9]{40}$") })
    }
    private static func requirement(team: String, identifier: String, hashes: [String] = []) throws -> SecRequirement {
        guard matches(team, "^[A-Z0-9]{10}$"), matches(identifier, "^[A-Za-z0-9][A-Za-z0-9.-]{1,199}$"),
              hashes.count <= 4, hashes.allSatisfy({ matches($0, "^[a-f0-9]{40}$") }) else {
            throw ComponentUpdateFailure.source
        }
        // The two certificate extensions select genuine Developer ID
        // Application signing, rather than trusting a self-asserted team field.
        var text = "anchor apple generic and identifier \"" + identifier + "\""
            + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            + " and certificate leaf[subject.OU] = \"" + team + "\""
            + " and !(entitlement[\"com.apple.security.get-task-allow\"] exists)"
        if !hashes.isEmpty {
            text += " and (" + hashes.map({ "cdhash H\"" + $0 + "\"" }).joined(separator: " or ") + ")"
        }
        var value: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &value) == errSecSuccess, let value else {
            throw ComponentUpdateFailure.source
        }
        return value
    }

    // Caller pins protected/no-follow public-code or package-resource bytes.
    // A .bin resource need not have executable permission to validate Mach-O.
    static func verifyStatic(path: String, peer: ComponentPeerSignature, designated: String?) throws {
        guard path.hasPrefix("/"), !path.utf8.contains(0), peerValid(peer) else { throw ComponentUpdateFailure.source }
        let expected = try requirement(team: peer.team, identifier: peer.identifier, hashes: peer.hashes)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code, SecStaticCodeCheckValidity(code,
                SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), expected) == errSecSuccess else {
            throw ComponentUpdateFailure.source
        }
        var observed: Set<String> = []
        for architecture in ["arm64", "x86_64"] {
            var slice: SecStaticCode?
            let attributes = [kSecCodeAttributeArchitecture as String: architecture] as CFDictionary
            if SecStaticCodeCreateWithPathAndAttributes(URL(fileURLWithPath: path) as CFURL, [], attributes, &slice) != errSecSuccess {
                continue // A thin file legitimately lacks the other architecture.
            }
            var information: CFDictionary?
            guard let slice, SecStaticCodeCheckValidity(slice, SecCSFlags(rawValue: kSecCSStrictValidate), expected) == errSecSuccess,
                  SecCodeCopySigningInformation(slice, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
                  let values = information as? [String: Any],
                  values[kSecCodeInfoIdentifier as String] as? String == peer.identifier,
                  values[kSecCodeInfoTeamIdentifier as String] as? String == peer.team,
                  let unique = values[kSecCodeInfoUnique as String] as? Data, unique.count == 20 else {
                throw ComponentUpdateFailure.source
            }
            observed.insert(unique.map({ String(format: "%02x", $0) }).joined())
            if let designated {
                var actual: SecRequirement?, text: CFString?
                guard !designated.isEmpty, designated.utf8.count <= 8192,
                      SecCodeCopyDesignatedRequirement(slice, [], &actual) == errSecSuccess, let actual,
                      SecRequirementCopyString(actual, [], &text) == errSecSuccess,
                      let text, text as String == designated else { throw ComponentUpdateFailure.source }
            }
        }
        guard observed == Set(peer.hashes) else { throw ComponentUpdateFailure.source }
    }

    static func verifySelf(team: String) throws {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        do {
            let expected = try requirement(team: team, identifier: identifier)
            var code: SecCode?, disk: SecStaticCode?
            guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
                  SecCodeCheckValidity(code, [], expected) == errSecSuccess,
                  SecCodeCopyStaticCode(code, SecCSFlags(rawValue: kSecCSUseAllArchitectures), &disk) == errSecSuccess,
                  let disk, SecStaticCodeCheckValidity(disk,
                    SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), expected) == errSecSuccess else {
                throw ComponentUpdateFailure.context
            }
        } catch { throw ComponentUpdateFailure.context }
    }

    // A narrow parser for successful bounded print of this exact fixed job.
    // Only root-level fields count; nested dictionaries cannot smuggle a PID.
    static func printedPID(_ output: Data) throws -> Int32? {
        guard !output.isEmpty, output.count <= 256 * 1024, !output.contains(0),
              let text = String(data: output, encoding: .utf8) else { throw ComponentUpdateFailure.quiescence }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard lines.count <= 10_000, lines.first == "system/" + label + " = {" else {
            throw ComponentUpdateFailure.quiescence
        }
        var depth = 1, fields: [String: String] = [:]
        for line in lines.dropFirst() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if depth == 0 {
                guard trimmed.isEmpty else { throw ComponentUpdateFailure.quiescence }
                continue
            }
            if depth == 1, trimmed == "}" { depth = 0; continue }
            if depth == 1, let divider = trimmed.range(of: " = ") {
                let key = String(trimmed[..<divider.lowerBound])
                if ["program", "state", "pid"].contains(key) {
                    guard fields[key] == nil else { throw ComponentUpdateFailure.quiescence }
                    fields[key] = String(trimmed[divider.upperBound...])
                }
            }
            var quoted = false, escaped = false
            for byte in line.utf8 {
                if escaped { escaped = false; continue }
                if byte == 92 && quoted { escaped = true; continue }
                if byte == 34 { quoted.toggle(); continue }
                if !quoted {
                    if byte == 123 { depth += 1 }
                    if byte == 125 { depth -= 1 }
                    // Only a standalone root closing brace may finish output.
                    guard (1...32).contains(depth) else { throw ComponentUpdateFailure.quiescence }
                }
            }
            guard !quoted else { throw ComponentUpdateFailure.quiescence }
        }
        guard depth == 0, fields["program"] == broker, let state = fields["state"] else {
            throw ComponentUpdateFailure.quiescence
        }
        if let value = fields["pid"] {
            guard state == "running", matches(value, "^[1-9][0-9]{0,9}$"),
                  let pid = Int32(value), pid > 1 else { throw ComponentUpdateFailure.quiescence }
            return pid
        }
        guard ["spawn scheduled", "not running", "waiting", "exited", "stopped"].contains(state) else {
            throw ComponentUpdateFailure.quiescence
        }
        return nil
    }

    static func validateSnapshot(_ snapshot: ComponentJobIdentity) throws {
        guard snapshot.pid > 1, snapshot.group == UInt32(snapshot.pid), snapshot.birthSec > 0,
              snapshot.birthUsec < 1_000_000, let uuid = UUID(uuidString: snapshot.bootSession),
              uuid.uuidString.lowercased() == snapshot.bootSession else { throw ComponentUpdateFailure.quiescence }
    }
    static func requireEmptyProcessGroup(byteCount: Int32, error: Int32) throws {
        guard byteCount == 0, error == 0 else { throw ComponentUpdateFailure.quiescence }
    }
    private static func bootSession() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 128), size = 128
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0,
              size > 1, size <= bytes.count, bytes[size - 1] == 0,
              !bytes.prefix(size - 1).contains(0),
              let text = String(bytes: bytes.prefix(size - 1), encoding: .utf8),
              let uuid = UUID(uuidString: text), uuid.uuidString.lowercased() == text.lowercased() else {
            throw ComponentUpdateFailure.quiescence
        }
        return uuid.uuidString.lowercased()
    }
    private static func info(_ pid: Int32) throws -> proc_bsdinfo {
        var value = proc_bsdinfo()
        let expected = MemoryLayout<proc_bsdinfo>.size
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value, Int32(expected)) == expected,
              value.pbi_pid == UInt32(pid), value.pbi_uid == 0, value.pbi_ruid == 0, value.pbi_svuid == 0,
              value.pbi_ppid == 1, value.pbi_pgid == UInt32(pid), value.pbi_start_tvsec > 0,
              value.pbi_start_tvusec < 1_000_000 else { throw ComponentUpdateFailure.quiescence }
        return value
    }
    private static func path(_ pid: Int32) throws -> String {
        // sys/proc_info.h defines PROC_PIDPATHINFO_MAXSIZE as 4*MAXPATHLEN;
        // that expression macro is unavailable to Swift (4096 on this SDK).
        var bytes = [UInt8](repeating: 0, count: 4096)
        let size = proc_pidpath(pid, &bytes, UInt32(bytes.count))
        guard size > 0, size < bytes.count, let end = bytes.firstIndex(of: 0),
              end > 0, let value = String(bytes: bytes.prefix(end), encoding: .utf8), value == broker else {
            throw ComponentUpdateFailure.quiescence
        }
        return value
    }

    static func jobSnapshot(output: Data, allowedPeers: [ComponentPeerSignature]) throws -> ComponentJobIdentity? {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        guard (1...2).contains(allowedPeers.count), let team = allowedPeers.first?.team,
              allowedPeers.allSatisfy({ peerValid($0) && $0.team == team && $0.identifier == label }) else {
            throw ComponentUpdateFailure.source
        }
        guard let pid = try printedPID(output) else { return nil }
        let boot = try bootSession(), before = try info(pid)
        _ = try path(pid)
        var guest: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
        let hashes = Array(Set(allowedPeers.flatMap(\.hashes))).sorted()
        let expected = try requirement(team: team, identifier: label, hashes: hashes)
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess, let guest,
              SecCodeCheckValidity(guest, [], expected) == errSecSuccess else { throw ComponentUpdateFailure.quiescence }
        _ = try path(pid)
        let after = try info(pid)
        guard before.pbi_start_tvsec == after.pbi_start_tvsec, before.pbi_start_tvusec == after.pbi_start_tvusec,
              before.pbi_pid == after.pbi_pid, before.pbi_ppid == after.pbi_ppid,
              before.pbi_uid == after.pbi_uid, before.pbi_ruid == after.pbi_ruid, before.pbi_svuid == after.pbi_svuid,
              before.pbi_pgid == after.pbi_pgid, try bootSession() == boot else { throw ComponentUpdateFailure.quiescence }
        let result = ComponentJobIdentity(pid: pid, group: before.pbi_pgid,
            birthSec: before.pbi_start_tvsec, birthUsec: before.pbi_start_tvusec, bootSession: boot)
        try validateSnapshot(result)
        return result
    }

    static func requireGone(_ snapshot: ComponentJobIdentity?) throws {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        guard let snapshot else { return }
        try validateSnapshot(snapshot)
        if try bootSession() != snapshot.bootSession { return } // An old boot's group cannot survive reboot.
        var pids = [pid_t](repeating: 0, count: 65_536)
        var callError: Int32 = 0
        let count = pids.withUnsafeMutableBytes {
            // libproc maps syscall failure to zero, with errno set. A zero
            // count alone therefore cannot establish an empty process group.
            errno = 0
            let result = proc_listpids(UInt32(PROC_PGRP_ONLY), snapshot.group, $0.baseAddress, Int32($0.count))
            callError = errno
            return result
        }
        // A reused numeric group is never adopted or signalled either.
        try requireEmptyProcessGroup(byteCount: count, error: callError)
    }
}
