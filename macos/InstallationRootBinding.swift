// Immutable legacy receipt validation and explicit current-volume revalidation.
// No account data, executable code, service state or original receipt is changed.
import Foundation
import CoreFoundation
import CryptoKit
import Darwin

enum InstallationRootBinding {
    static let paths = [InstallerPayloadManifest.support, InstallerPayloadManifest.application]
    static let receiptNames = ["intent.json", "complete.json", "ready.json", "published.json"]
    static let namespace = "/Library/Application Support/Account Access Installation Binding"
    static let receiptName = "revalidated-v1.json"
    static let pendingName = "pending-revalidated-v1.json"
    static let marker = "account-access-installation-root-revalidation-v1"
    private static let policyNames: Set<String> = ["install", "host", "owner", "worker", "service"]

    struct LegacyRoot: Equatable { let device: Int32; let inode: UInt64 }
    struct Legacy: Equatable {
        let hashes: [String: String]
        let roots: [String: LegacyRoot]
        let ownerUID: uid_t
        let manifestSHA256: String
    }
    struct CurrentRoot: Equatable { let device: Int32; let inode: UInt64; let volumeUUID: String }

    private static func hex(_ text: String, count: Int) -> Bool {
        text.utf8.count == count && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func uuid(_ text: String) -> Bool {
        guard let value = UUID(uuidString: text), value.uuidString.lowercased() == text else { return false }
        return text != "00000000-0000-0000-0000-000000000000"
    }
    // JSONSerialization accepts duplicate keys. This bounded pass rejects them
    // at every object depth, including escaped spellings, after syntax validation.
    private static func object(_ data: Data) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= 8192, !data.contains(0),
              let result = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ComponentUpdateFailure.base
        }
        let bytes = [UInt8](data)
        var stack: [(object: Bool, keys: Set<String>, key: Bool)] = [], cursor = 0
        while cursor < bytes.count {
            switch bytes[cursor] {
            case 34:
                let start = cursor
                cursor += 1
                while cursor < bytes.count && bytes[cursor] != 34 { cursor += bytes[cursor] == 92 ? 2 : 1 }
                guard cursor < bytes.count else { throw ComponentUpdateFailure.base }
                cursor += 1
                if let last = stack.indices.last, stack[last].object && stack[last].key {
                    var token = Data([91]); token.append(contentsOf: bytes[start..<cursor]); token.append(93)
                    guard let key = try JSONSerialization.jsonObject(with: token) as? [String], key.count == 1,
                          stack[last].keys.insert(key[0]).inserted else { throw ComponentUpdateFailure.base }
                    stack[last].key = false
                }
                continue
            case 123, 91:
                guard stack.count < 8 else { throw ComponentUpdateFailure.base }
                stack.append((bytes[cursor] == 123, [], bytes[cursor] == 123))
            case 125, 93:
                guard !stack.isEmpty else { throw ComponentUpdateFailure.base }; stack.removeLast()
            case 44:
                if let last = stack.indices.last, stack[last].object { stack[last].key = true }
            default: break
            }
            cursor += 1
        }
        guard stack.isEmpty else { throw ComponentUpdateFailure.base }
        return result
    }
    static func parseLegacy(records: [String: Data], ownerUID: uid_t, manifestSHA256: String) throws -> Legacy {
        guard Set(records.keys) == Set(receiptNames), ownerUID > 0, hex(manifestSHA256, count: 64) else {
            throw ComponentUpdateFailure.base
        }
        let intent = try object(records["intent.json"]!), complete = try object(records["complete.json"]!)
        guard Set(intent.keys) == ["managed_by", "schema", "manifest_sha256", "owner_uid"],
              intent["managed_by"] as? String == "account-access-public-image-install-v1",
              try InstallerPayloadManifest.integer(intent["schema"], maximum: 1) == 1,
              intent["manifest_sha256"] as? String == manifestSHA256,
              try InstallerPayloadManifest.integer(intent["owner_uid"], maximum: Int64(UInt32.max)) == Int64(ownerUID),
              Set(complete.keys) == ["manifest_sha256", "owner_uid", "status"],
              complete["manifest_sha256"] as? String == manifestSHA256,
              complete["status"] as? String == "REGISTERED",
              try InstallerPayloadManifest.integer(complete["owner_uid"], maximum: Int64(UInt32.max)) == Int64(ownerUID) else {
            throw ComponentUpdateFailure.base
        }
        let ready = try object(records["ready.json"]!), published = try object(records["published.json"]!)
        guard Set(ready.keys) == ["manifest_sha256", "roots"], ready["manifest_sha256"] as? String == manifestSHA256,
              NSDictionary(dictionary: ready).isEqual(to: published),
              try JSONSerialization.data(withJSONObject: ready, options: [.sortedKeys, .withoutEscapingSlashes])
                == JSONSerialization.data(withJSONObject: published, options: [.sortedKeys, .withoutEscapingSlashes]),
              let roots = ready["roots"] as? [String: [NSNumber]],
              Set(roots.keys) == Set(paths) else { throw ComponentUpdateFailure.base }
        var result: [String: LegacyRoot] = [:]
        for path in paths {
            let pair = roots[path]!
            guard pair.count == 2 else { throw ComponentUpdateFailure.base }
            let device = try InstallerPayloadManifest.integer(pair[0], maximum: Int64(Int32.max))
            let inode = try InstallerPayloadManifest.integer(pair[1], maximum: Int64.max)
            result[path] = LegacyRoot(device: Int32(device), inode: UInt64(inode))
        }
        return Legacy(hashes: records.mapValues(ComponentFiles.digest), roots: result,
                      ownerUID: ownerUID, manifestSHA256: manifestSHA256)
    }
    static func exactLegacy(_ legacy: Legacy, current: [String: CurrentRoot]) throws -> Bool {
        guard Set(legacy.roots.keys) == Set(paths), Set(current.keys) == Set(paths) else { throw ComponentUpdateFailure.base }
        return paths.allSatisfy { legacy.roots[$0]!.device == current[$0]!.device && legacy.roots[$0]!.inode == current[$0]!.inode }
    }
    private static func requireSameRoots(_ legacy: Legacy, current: [String: CurrentRoot]) throws {
        guard Set(legacy.roots.keys) == Set(paths), Set(current.keys) == Set(paths),
              paths.allSatisfy({ legacy.roots[$0]!.inode == current[$0]!.inode && current[$0]!.inode > 0
                  && current[$0]!.inode <= UInt64(Int64.max) && current[$0]!.device >= 0 && uuid(current[$0]!.volumeUUID) }),
              Set(current.values.map(\.device)).count == 1, Set(current.values.map(\.volumeUUID)).count == 1 else {
            throw ComponentUpdateFailure.base
        }
    }
    static func requireDeviceOnly(_ legacy: Legacy, current: [String: CurrentRoot]) throws {
        try requireSameRoots(legacy, current: current)
        guard try !exactLegacy(legacy, current: current) else { throw ComponentUpdateFailure.base }
    }
    static func supplement(legacy: Legacy, current: [String: CurrentRoot], planSHA256: String,
                           sourceCommit: String, policyHashes: [String: String]) throws -> Data {
        try requireDeviceOnly(legacy, current: current)
        guard hex(planSHA256, count: 64), hex(sourceCommit, count: 40), Set(policyHashes.keys) == policyNames,
              policyHashes.values.allSatisfy({ hex($0, count: 64) }) else { throw ComponentUpdateFailure.base }
        let roots = current.mapValues { ["inode": NSNumber(value: $0.inode), "volume_uuid": $0.volumeUUID] as [String: Any] }
        let result: [String: Any] = ["schema": 1, "managed_by": marker, "base_manifest_sha256": legacy.manifestSHA256,
            "owner_uid": legacy.ownerUID, "original_receipt_sha256": legacy.hashes, "roots": roots,
            "publisher_team": "WBULD6N4NQ", "publisher_identifier": "com.fainir.accountaccess.componentupdate",
            "authorizing_plan_sha256": planSHA256, "authorizing_source_commit": sourceCommit, "policy_sha256": policyHashes]
        let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys, .withoutEscapingSlashes])
        try validateSupplement(data, legacy: legacy, current: current)
        return data
    }
    static func validateSupplement(_ data: Data, legacy: Legacy, current: [String: CurrentRoot]) throws {
        try requireSameRoots(legacy, current: current)
        let value = try object(data)
        guard Set(value.keys) == ["schema", "managed_by", "base_manifest_sha256", "owner_uid", "original_receipt_sha256",
            "roots", "publisher_team", "publisher_identifier", "authorizing_plan_sha256", "authorizing_source_commit", "policy_sha256"],
              try InstallerPayloadManifest.integer(value["schema"], maximum: 1) == 1,
              value["managed_by"] as? String == marker, value["base_manifest_sha256"] as? String == legacy.manifestSHA256,
              try InstallerPayloadManifest.integer(value["owner_uid"], maximum: Int64(UInt32.max)) == Int64(legacy.ownerUID),
              value["original_receipt_sha256"] as? [String: String] == legacy.hashes,
              value["publisher_team"] as? String == "WBULD6N4NQ",
              value["publisher_identifier"] as? String == "com.fainir.accountaccess.componentupdate",
              let plan = value["authorizing_plan_sha256"] as? String, hex(plan, count: 64),
              let source = value["authorizing_source_commit"] as? String, hex(source, count: 40),
              let policies = value["policy_sha256"] as? [String: String], Set(policies.keys) == policyNames,
              policies.values.allSatisfy({ hex($0, count: 64) }),
              let roots = value["roots"] as? [String: [String: Any]], Set(roots.keys) == Set(paths) else {
            throw ComponentUpdateFailure.base
        }
        for path in paths {
            let root = roots[path]!, actual = current[path]!
            guard Set(root.keys) == ["inode", "volume_uuid"], root["volume_uuid"] as? String == actual.volumeUUID,
                  try InstallerPayloadManifest.integer(root["inode"], maximum: Int64.max) == Int64(actual.inode) else {
                throw ComponentUpdateFailure.base
            }
        }
    }
    static func readLegacy(_ journal: Int32, ownerUID: uid_t, manifestSHA256: String) throws -> Legacy {
        var records: [String: Data] = [:]
        for name in receiptNames { records[name] = try ComponentFiles.read(journal, name, owner: 0, mode: 0o600).0 }
        return try parseLegacy(records: records, ownerUID: ownerUID, manifestSHA256: manifestSHA256)
    }
    static func volumeUUID(_ fd: Int32) throws -> String {
        // Darwin fgetattrlist reads the pinned directory's volume, including for
        // /Applications: the publication symlink is never followed for a UUID.
        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.volattr = ATTR_VOL_INFO | UInt32(ATTR_VOL_UUID)
        var bytes = [UInt8](repeating: 0, count: 20)
        let result = bytes.withUnsafeMutableBytes { fgetattrlist(fd, &attributes, $0.baseAddress!, $0.count, 0) }
        guard result == 0, bytes.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) == 20 else {
            throw ComponentUpdateFailure.base
        }
        let raw = Array(bytes[4..<20])
        let text = UUID(uuid: (raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                              raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])).uuidString.lowercased()
        guard uuid(text) else { throw ComponentUpdateFailure.base }
        return text
    }
    static func capture(withVolumeUUID: Bool) throws -> [String: CurrentRoot] {
        let support = try InstallerPayloadIO.directory(InstallerPayloadManifest.support, owner: 0)
        defer { Darwin.close(support) }
        let applications = try InstallerPayloadIO.directory("/Applications", owner: 0, sharedApplicationParent: true)
        defer { Darwin.close(applications) }
        let before = try InstallerPayloadIO.check(support, owner: 0, directory: true)
        var alias = stat(), supportPath = stat(), aliasAfter = stat()
        guard before.st_mode & 0o7777 == 0o755,
              lstat(InstallerPayloadManifest.support, &supportPath) == 0, InstallerPayloadIO.same(before, supportPath),
              fstatat(applications, "Account Access.app", &alias, AT_SYMLINK_NOFOLLOW) == 0,
              alias.st_uid == 0, alias.st_nlink == 1, alias.st_mode & S_IFMT == S_IFLNK, alias.st_mode & 0o6000 == 0 else {
            throw ComponentUpdateFailure.base
        }
        var target = [CChar](repeating: 0, count: 4097)
        let count = readlinkat(applications, "Account Access.app", &target, target.count)
        guard count > 0, count <= 4096,
              Data(target.prefix(count).map { UInt8(bitPattern: $0) }) == Data(InstallerPayloadManifest.applicationTarget.utf8) else {
            throw ComponentUpdateFailure.base
        }
        let supportUUID = withVolumeUUID ? try volumeUUID(support) : ""
        let applicationUUID = withVolumeUUID ? try volumeUUID(applications) : ""
        let applicationsNow = try InstallerPayloadIO.directory("/Applications", owner: 0, sharedApplicationParent: true)
        defer { Darwin.close(applicationsNow) }
        let applicationParent = try InstallerPayloadIO.check(applications, owner: 0, directory: true, sharedParent: true)
        let applicationCurrent = try InstallerPayloadIO.check(applicationsNow, owner: 0, directory: true, sharedParent: true)
        guard InstallerPayloadIO.same(before, try InstallerPayloadIO.check(support, owner: 0, directory: true)),
              lstat(InstallerPayloadManifest.support, &supportPath) == 0, InstallerPayloadIO.same(before, supportPath),
              fstatat(applications, "Account Access.app", &aliasAfter, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(alias, aliasAfter), alias.st_dev == applicationParent.st_dev,
              applicationParent.st_dev == applicationCurrent.st_dev, applicationParent.st_ino == applicationCurrent.st_ino,
              applicationParent.st_uid == applicationCurrent.st_uid, applicationParent.st_gid == applicationCurrent.st_gid,
              applicationParent.st_mode == applicationCurrent.st_mode else { throw ComponentUpdateFailure.base }
        return [paths[0]: CurrentRoot(device: before.st_dev, inode: before.st_ino, volumeUUID: supportUUID),
                paths[1]: CurrentRoot(device: alias.st_dev, inode: alias.st_ino, volumeUUID: applicationUUID)]
    }
    static func noACL(_ fd: Int32) throws {
        errno = 0
        guard let acl = acl_get_fd(fd) else {
            guard errno == ENOENT else { throw ComponentUpdateFailure.base }; return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) != 0, errno == EINVAL else { throw ComponentUpdateFailure.base }
    }
    static func receiptDirectory(create: Bool) throws -> Int32 {
        let parent = try InstallerPayloadIO.directory("/Library/Application Support", owner: 0)
        defer { Darwin.close(parent) }
        let name = "Account Access Installation Binding"
        if create {
            if mkdirat(parent, name, 0o700) == 0 { guard fsync(parent) == 0 else { throw ComponentUpdateFailure.unavailable } }
            else if errno != EEXIST { throw ComponentUpdateFailure.base }
        }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ComponentUpdateFailure.base }
        do {
            let info = try InstallerPayloadIO.check(fd, owner: 0, directory: true)
            var current = stat()
            guard info.st_mode & 0o7777 == 0o700, fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                  InstallerPayloadIO.same(info, current) else { throw ComponentUpdateFailure.base }
            try noACL(fd)
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    static func hasSupplementNamespace() throws -> Bool {
        var info = stat()
        if lstat(namespace, &info) == 0 { return true }
        guard errno == ENOENT else { throw ComponentUpdateFailure.base }
        return false
    }
    static func readSupplement(_ directory: Int32) throws -> Data {
        guard try InstallerPayloadIO.contents(directory) == [receiptName] else { throw ComponentUpdateFailure.base }
        let fd = openat(directory, receiptName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw ComponentUpdateFailure.base }
        defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: 0, directory: false)
        try noACL(fd)
        guard before.st_mode & 0o7777 == 0o600 else { throw ComponentUpdateFailure.base }
        let data = try InstallerPayloadIO.read(fd, maximum: 8192, owner: 0)
        var current = stat()
        guard fstatat(directory, receiptName, &current, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(before, current) else { throw ComponentUpdateFailure.base }
        return data
    }
    static func prepareSupplement(_ directory: Int32, data: Data) throws {
        guard !data.isEmpty, data.count <= 8192,
              try InstallerPayloadIO.contents(directory).isSubset(of: [pendingName]) else { throw ComponentUpdateFailure.base }
        var fd = openat(directory, pendingName, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        if fd < 0, errno == EEXIST { fd = openat(directory, pendingName, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK) }
        guard fd >= 0 else { throw ComponentUpdateFailure.base }
        defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: 0, directory: false)
        try noACL(fd)
        guard before.st_mode & 0o7777 == 0o600, before.st_size <= data.count else { throw ComponentUpdateFailure.base }
        let prefix = try InstallerPayloadIO.read(fd, maximum: data.count, owner: 0)
        var current = stat()
        guard prefix == data.prefix(prefix.count), fstatat(directory, pendingName, &current, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(before, current) else { throw ComponentUpdateFailure.base }
        try data.withUnsafeBytes { bytes in
            var offset = prefix.count
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw ComponentUpdateFailure.unavailable }
                offset += count
            }
        }
        guard fsync(fd) == 0, fsync(directory) == 0 else { throw ComponentUpdateFailure.unavailable }
        let final = try InstallerPayloadIO.check(fd, owner: 0, directory: false)
        guard final.st_size == data.count, fstatat(directory, pendingName, &current, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(final, current) else { throw ComponentUpdateFailure.base }
    }
    static func verify(journal: Int32, ownerUID: uid_t, manifestSHA256: String) throws {
        let legacy = try readLegacy(journal, ownerUID: ownerUID, manifestSHA256: manifestSHA256)
        if try !hasSupplementNamespace() {
            guard try exactLegacy(legacy, current: capture(withVolumeUUID: false)) else { throw ComponentUpdateFailure.base }
            return
        }
        let current = try capture(withVolumeUUID: true)
        let directory = try receiptDirectory(create: false)
        defer { Darwin.close(directory) }
        try validateSupplement(readSupplement(directory), legacy: legacy, current: current)
        guard try readLegacy(journal, ownerUID: ownerUID, manifestSHA256: manifestSHA256) == legacy,
              try capture(withVolumeUUID: true) == current else { throw ComponentUpdateFailure.base }
    }
}
