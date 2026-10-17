// Public installation image verification. No vault, key, identity, service or
// permission changes. The package supplies the manifest beside this executable.
import Foundation
import CoreFoundation
import CryptoKit
import Darwin

enum InstallerPayloadFailure: String, Error {
    case context = "installer_verifier_context_required"
    case manifest = "invalid_installer_payload_manifest"
    case path = "unsafe_installer_payload_path"
    case object = "unsafe_installer_payload_object"
    case changed = "installer_payload_changed"
    case limit = "installer_payload_limit"
}

struct InstallerPayloadNode {
    let kind: String
    let mode: mode_t?
    let size: Int64?
    let sha256: String?
    let target: String?
}

struct InstallerPayloadTree {
    let nodes: [String: InstallerPayloadNode]
    let children: [String: Set<String>]
}

struct InstallerPayloadManifest {
    static let support = "/Library/Application Support/Account Access"
    static let application = "/Applications/Account Access.app"
    static let maximumEntries = 100_000
    static let maximumFile: Int64 = 1024 * 1024 * 1024
    static let maximumTotal: Int64 = 8 * maximumFile
    static let maximumManifest = 16 * 1024 * 1024
    let trees: [String: InstallerPayloadTree]
    let sha256: String

    static func integer(_ value: Any?, maximum: Int64) throws -> Int64 {
        guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
              value.doubleValue >= 0, value.doubleValue <= Double(maximum),
              value.doubleValue == Double(value.int64Value) else { throw InstallerPayloadFailure.manifest }
        return value.int64Value
    }
    static func components(_ name: String) throws -> [String] {
        if name.isEmpty { return [] }
        let parts = name.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard name.utf8.count <= 4096, parts.count <= 128,
              !name.contains("\\"), !name.contains(":"),
              !name.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw InstallerPayloadFailure.path
        }
        return parts
    }
    static func folded(_ name: String) -> String {
        name.precomposedStringWithCanonicalMapping.folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
    }
    static func targetParts(_ target: String) throws -> [String] {
        guard !target.isEmpty, !target.hasPrefix("/"), target.utf8.count <= 4096,
              !target.contains("\\"), !target.contains(":"),
              !target.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else {
            throw InstallerPayloadFailure.path
        }
        return target.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    }
    static func confinedAlias(_ name: String, nodes: [String: InstallerPayloadNode]) throws {
        var current = Array(try components(name).dropLast())
        var pending = try targetParts(nodes[name]!.target!), links = 0
        while !pending.isEmpty {
            let part = pending.removeFirst()
            if part.isEmpty || part == "." { continue }
            if part == ".." {
                guard !current.isEmpty else { throw InstallerPayloadFailure.path }
                current.removeLast(); continue
            }
            let candidate = (current + [part]).joined(separator: "/")
            guard let node = nodes[candidate] else { throw InstallerPayloadFailure.path }
            if node.kind == "symlink" {
                links += 1
                guard links <= 40 else { throw InstallerPayloadFailure.path }
                pending = try targetParts(node.target!) + pending
            } else {
                current.append(part)
                guard pending.isEmpty || node.kind == "directory" else { throw InstallerPayloadFailure.path }
            }
        }
    }
    init(_ data: Data) throws {
        guard !data.isEmpty, data.count <= Self.maximumManifest,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(value.keys) == ["managed_by", "schema", "package_identifier", "version", "architecture", "roots"],
              value["managed_by"] as? String == "account-access-install-payload-v1",
              try Self.integer(value["schema"], maximum: 1) == 1,
              value["package_identifier"] as? String == "com.fainir.accountaccess.system",
              value["version"] as? String == "0.8.0", value["architecture"] as? String == "arm64",
              let roots = value["roots"] as? [String: [String: [String: Any]]],
              Set(roots.keys) == [Self.support, Self.application] else { throw InstallerPayloadFailure.manifest }
        var trees: [String: InstallerPayloadTree] = [:], count = 0, total: Int64 = 0
        for (root, rows) in roots {
            var nodes: [String: InstallerPayloadNode] = [:], names: Set<String> = []
            var children: [String: Set<String>] = [:]
            for (name, row) in rows {
                count += 1
                guard count <= Self.maximumEntries, names.insert(Self.folded(name)).inserted,
                      let kind = row["kind"] as? String else { throw InstallerPayloadFailure.manifest }
                let parts = try Self.components(name)
                if !parts.isEmpty {
                    let parent = parts.dropLast().joined(separator: "/")
                    children[parent, default: []].insert(parts.last!)
                }
                let keys: Set<String> = kind == "file" ? ["kind", "mode", "size", "sha256"]
                    : kind == "directory" ? ["kind", "mode"] : ["kind", "target"]
                guard ["file", "directory", "symlink"].contains(kind), Set(row.keys) == keys else {
                    throw InstallerPayloadFailure.manifest
                }
                if kind == "symlink" {
                    guard let target = row["target"] as? String else { throw InstallerPayloadFailure.manifest }
                    _ = try Self.targetParts(target)
                    nodes[name] = InstallerPayloadNode(kind: kind, mode: nil, size: nil, sha256: nil, target: target)
                } else {
                    let mode = mode_t(try Self.integer(row["mode"], maximum: 0o777))
                    guard mode & 0o022 == 0 else { throw InstallerPayloadFailure.manifest }
                    var size: Int64?, checksum: String?
                    if kind == "file" {
                        size = try Self.integer(row["size"], maximum: Self.maximumFile)
                        total += size!
                        guard total <= Self.maximumTotal, let hash = row["sha256"] as? String,
                              hash.utf8.count == 64,
                              hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                            throw InstallerPayloadFailure.manifest
                        }
                        checksum = hash
                    }
                    nodes[name] = InstallerPayloadNode(kind: kind, mode: mode, size: size, sha256: checksum, target: nil)
                }
            }
            guard nodes[""]?.kind == "directory" else { throw InstallerPayloadFailure.manifest }
            for (name, node) in nodes where !name.isEmpty {
                let parent = try Self.components(name).dropLast().joined(separator: "/")
                guard nodes[parent]?.kind == "directory" else { throw InstallerPayloadFailure.manifest }
                if node.kind == "symlink" { try Self.confinedAlias(name, nodes: nodes) }
            }
            trees[root] = InstallerPayloadTree(nodes: nodes, children: children)
        }
        self.trees = trees
        sha256 = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

struct InstallerPayloadCounts {
    var files = 0, directories = 0, aliases = 0
    mutating func add(_ other: InstallerPayloadCounts) {
        files += other.files; directories += other.directories; aliases += other.aliases
    }
}

enum InstallerPayloadIO {
    static func noGrantACL(_ fd: Int32) throws {
        errno = 0
        guard let acl = acl_get_fd(fd) else {
            guard errno == ENOENT else { throw InstallerPayloadFailure.object }; return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var position = ACL_FIRST_ENTRY.rawValue
        for _ in 0..<170 {
            var entry: acl_entry_t?, tag = acl_tag_t(rawValue: 0)
            errno = 0
            if acl_get_entry(acl, position, &entry) != 0 {
                guard errno == EINVAL else { throw InstallerPayloadFailure.object }; return
            }
            guard let entry, acl_get_tag_type(entry, &tag) == 0, tag == ACL_EXTENDED_DENY else {
                throw InstallerPayloadFailure.object
            }
            position = ACL_NEXT_ENTRY.rawValue
        }
        throw InstallerPayloadFailure.limit
    }
    static func check(_ fd: Int32, owner: uid_t, directory: Bool, sharedParent: Bool = false) throws -> stat {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == owner,
              info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG), info.st_mode & 0o6000 == 0,
              info.st_mode & (sharedParent ? 0o002 : 0o022) == 0,
              directory || info.st_nlink == 1 else { throw InstallerPayloadFailure.object }
        try noGrantACL(fd)
        return info
    }
    static func same(_ before: stat, _ after: stat) -> Bool {
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size
            && before.st_mode == after.st_mode && before.st_uid == after.st_uid && before.st_nlink == after.st_nlink
            && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec
            && before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
    }
    static func directory(_ path: String, owner: uid_t, sharedApplicationParent: Bool = false) throws -> Int32 {
        guard path.hasPrefix("/"), !path.utf8.contains(0), !path.contains("\\") else { throw InstallerPayloadFailure.path }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().map(String.init)
        guard parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw InstallerPayloadFailure.path }
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw InstallerPayloadFailure.path }
        do {
            _ = try check(fd, owner: owner, directory: true)
            for (index, name) in parts.enumerated() {
                let next = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw InstallerPayloadFailure.path }
                do {
                    // /Applications is normally root:admin 0775. This checker
                    // reads a descriptor-pinned app and hashes every member. It
                    // never executes root code from that shared namespace.
                    _ = try check(next, owner: owner, directory: true,
                                  sharedParent: sharedApplicationParent && index == 0 && name == "Applications")
                } catch { Darwin.close(next); throw error }
                Darwin.close(fd); fd = next
            }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    static func contents(_ fd: Int32) throws -> Set<String> {
        // dup would share the directory position and make a second check see
        // EOF. Open this same pinned directory with an independent position.
        let copied = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copied >= 0 else { throw InstallerPayloadFailure.path }
        guard let directory = fdopendir(copied) else { Darwin.close(copied); throw InstallerPayloadFailure.path }
        defer { closedir(directory) }
        var names: Set<String> = [], folded: Set<String> = []
        while true {
            errno = 0
            guard let entry = readdir(directory) else {
                guard errno == 0 else { throw InstallerPayloadFailure.path }; break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(validatingCString: $0) }
            }
            guard let name else { throw InstallerPayloadFailure.path }
            if name == "." || name == ".." { continue }
            guard try InstallerPayloadManifest.components(name).count == 1,
                  names.count < InstallerPayloadManifest.maximumEntries,
                  names.insert(name).inserted, folded.insert(InstallerPayloadManifest.folded(name)).inserted else {
                throw InstallerPayloadFailure.path
            }
        }
        return names
    }
    static func read(_ fd: Int32, maximum: Int, owner: uid_t) throws -> Data {
        let before = try check(fd, owner: owner, directory: false)
        guard before.st_size >= 0, before.st_size <= maximum else { throw InstallerPayloadFailure.limit }
        var result = Data(), buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, result.count + count <= maximum else { throw InstallerPayloadFailure.limit }
            if count == 0 { break }
            result.append(contentsOf: buffer.prefix(count))
        }
        guard result.count == before.st_size, same(before, try check(fd, owner: owner, directory: false)) else {
            throw InstallerPayloadFailure.changed
        }
        return result
    }
    static func verifyFile(_ fd: Int32, node: InstallerPayloadNode, owner: uid_t) throws {
        let before = try check(fd, owner: owner, directory: false)
        guard before.st_size == node.size, before.st_mode & 0o7777 == node.mode else { throw InstallerPayloadFailure.changed }
        var count: Int64 = 0, hasher = SHA256(), buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        while true {
            let read = Darwin.read(fd, &buffer, buffer.count)
            if read < 0 && errno == EINTR { continue }
            guard read >= 0, count + Int64(read) <= before.st_size else { throw InstallerPayloadFailure.changed }
            if read == 0 { break }
            count += Int64(read); hasher.update(data: buffer.prefix(read))
        }
        guard count == before.st_size, same(before, try check(fd, owner: owner, directory: false)),
              hasher.finalize().map({ String(format: "%02x", $0) }).joined() == node.sha256 else {
            throw InstallerPayloadFailure.changed
        }
    }
    static func verify(_ fd: Int32, tree: InstallerPayloadTree, owner: uid_t, name: String = "") throws -> InstallerPayloadCounts {
        let before = try check(fd, owner: owner, directory: true)
        guard before.st_mode & 0o7777 == tree.nodes[name]?.mode else { throw InstallerPayloadFailure.changed }
        let expected = tree.children[name] ?? []
        guard try contents(fd) == expected else { throw InstallerPayloadFailure.changed }
        var counts = InstallerPayloadCounts(files: 0, directories: 1, aliases: 0)
        for child in expected.sorted() {
            let relative = name.isEmpty ? child : name + "/" + child
            let node = tree.nodes[relative]!
            var info = stat()
            guard fstatat(fd, child, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_uid == owner else {
                throw InstallerPayloadFailure.object
            }
            if node.kind == "symlink" {
                var buffer = [CChar](repeating: 0, count: 4097)
                let size = readlinkat(fd, child, &buffer, buffer.count)
                guard info.st_mode & S_IFMT == S_IFLNK, size > 0, size <= 4096,
                      Data(buffer.prefix(size).map { UInt8(bitPattern: $0) }) == Data(node.target!.utf8) else {
                    throw InstallerPayloadFailure.changed
                }
                var after = stat()
                guard fstatat(fd, child, &after, AT_SYMLINK_NOFOLLOW) == 0, same(info, after) else { throw InstallerPayloadFailure.changed }
                counts.aliases += 1
            } else {
                let handle = openat(fd, child, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (node.kind == "directory" ? O_DIRECTORY : 0))
                guard handle >= 0 else { throw InstallerPayloadFailure.path }
                do {
                    if node.kind == "directory" { counts.add(try verify(handle, tree: tree, owner: owner, name: relative)) }
                    else { try verifyFile(handle, node: node, owner: owner); counts.files += 1 }
                    var observed = stat(), current = stat()
                    guard fstat(handle, &observed) == 0,
                          fstatat(fd, child, &current, AT_SYMLINK_NOFOLLOW) == 0,
                          same(info, observed), same(observed, current) else { throw InstallerPayloadFailure.changed }
                } catch { Darwin.close(handle); throw error }
                Darwin.close(handle)
            }
        }
        guard same(before, try check(fd, owner: owner, directory: true)) else { throw InstallerPayloadFailure.changed }
        return counts
    }
    static func installed() throws -> (InstallerPayloadManifest, InstallerPayloadCounts) {
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 1 else { throw InstallerPayloadFailure.context }
        let executable = CommandLine.arguments[0]
        guard executable.hasPrefix("/"), executable.hasSuffix("/AccountAccess-installerverify") else { throw InstallerPayloadFailure.context }
        let resources = try directory(URL(fileURLWithPath: executable).deletingLastPathComponent().path, owner: 0)
        defer { Darwin.close(resources) }
        let file = openat(resources, "RecoveryManifest.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard file >= 0 else { throw InstallerPayloadFailure.manifest }
        let data: Data
        do { data = try read(file, maximum: InstallerPayloadManifest.maximumManifest, owner: 0) }
        catch { Darwin.close(file); throw error }
        Darwin.close(file)
        let manifest = try InstallerPayloadManifest(data)
        var counts = InstallerPayloadCounts()
        for root in manifest.trees.keys.sorted() {
            let fd = try directory(root, owner: 0, sharedApplicationParent: root == InstallerPayloadManifest.application)
            do {
                counts.add(try verify(fd, tree: manifest.trees[root]!, owner: 0))
                // Reopen the namespace after hashing: a moved/replaced app may
                // not substitute for the descriptor-pinned image we inspected.
                let current = try directory(root, owner: 0, sharedApplicationParent: root == InstallerPayloadManifest.application)
                defer { Darwin.close(current) }
                var before = stat(), after = stat()
                guard fstat(fd, &before) == 0, fstat(current, &after) == 0, same(before, after) else { throw InstallerPayloadFailure.changed }
            } catch { Darwin.close(fd); throw error }
            Darwin.close(fd)
        }
        return (manifest, counts)
    }
}

#if ACCOUNT_ACCESS_INSTALL_VERIFIER_MAIN
@main struct AccountAccessInstallerVerifier {
    static func main() {
        do {
            let (manifest, counts) = try InstallerPayloadIO.installed()
            let output: [String: Any] = ["schema": 1, "status": "VERIFIED", "manifest_sha256": manifest.sha256,
                                         "files": counts.files, "directories": counts.directories, "aliases": counts.aliases]
            let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
            FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
        } catch {
            let reason = (error as? InstallerPayloadFailure)?.rawValue ?? "installer_payload_not_verified"
            FileHandle.standardOutput.write(Data(("{\"schema\":1,\"status\":\"FAILED\",\"reason\":\"" + reason + "\"}\n").utf8))
            exit(78)
        }
    }
}
#endif
