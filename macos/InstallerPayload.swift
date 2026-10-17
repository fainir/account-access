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
    case execution = "installer_source_not_started"
}

struct InstallerSpawnFailure: Error {
    enum Operation: String { case actions, attributes, input, inherit, replace }
    let operation: Operation
    let code: Int32
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
        let parts = target.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count <= 128 else { throw InstallerPayloadFailure.limit }
        return parts
    }
    static func confinedAlias(_ name: String, nodes: [String: InstallerPayloadNode], work: inout Int) throws {
        var current = Array(try components(name).dropLast())
        var pending = try targetParts(nodes[name]!.target!), links = 0, cursor = 0
        while cursor < pending.count {
            work += 1
            guard work <= 1_000_000 else { throw InstallerPayloadFailure.limit }
            let part = pending[cursor]
            cursor += 1
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
                pending = try targetParts(node.target!) + pending.dropFirst(cursor)
                cursor = 0
            } else {
                current.append(part)
                guard cursor == pending.count || node.kind == "directory" else { throw InstallerPayloadFailure.path }
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
        var trees: [String: InstallerPayloadTree] = [:], count = 0, total: Int64 = 0, aliasWork = 0
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
                if node.kind == "symlink" { try Self.confinedAlias(name, nodes: nodes, work: &aliasWork) }
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
    static func check(_ fd: Int32, owner: uid_t, directory: Bool, sharedParent: Bool = false,
                      installerTemporaryParent: Bool = false) throws -> stat {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == owner,
              info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG), info.st_mode & 0o6000 == 0,
              directory || info.st_nlink == 1 else { throw InstallerPayloadFailure.object }
        if installerTemporaryParent {
            // Apple's scripts live below root-owned /private/tmp (01777).
            // The sticky bit protects its root-owned child from other users;
            // every child is opened without following links and must satisfy
            // the ordinary protected-directory policy. No payload-root walk
            // receives this exception, and no directory permissions change.
            guard directory, !sharedParent, info.st_mode & 0o7777 == 0o1777 else { throw InstallerPayloadFailure.object }
        } else {
            guard info.st_mode & (sharedParent ? 0o002 : 0o022) == 0 else { throw InstallerPayloadFailure.object }
        }
        try noGrantACL(fd)
        return info
    }
    static func same(_ before: stat, _ after: stat) -> Bool {
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size
            && before.st_mode == after.st_mode && before.st_uid == after.st_uid && before.st_nlink == after.st_nlink
            && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec
            && before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
    }
    static func directory(_ path: String, owner: uid_t, sharedApplicationParent: Bool = false,
                          installerResources: Bool = false) throws -> Int32 {
        let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw InstallerPayloadFailure.path }
        defer { Darwin.close(root) }
        return try walkDirectory(path, from: root, owner: owner, sharedApplicationParent: sharedApplicationParent,
                                 installerResources: installerResources)
    }
    static func walkDirectory(_ path: String, from root: Int32, owner: uid_t, sharedApplicationParent: Bool = false,
                              installerResources: Bool = false) throws -> Int32 {
        guard path.hasPrefix("/"), !path.utf8.contains(0), !path.contains("\\") else { throw InstallerPayloadFailure.path }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().map(String.init)
        guard parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw InstallerPayloadFailure.path }
        var fd = dup(root)
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
                                  sharedParent: sharedApplicationParent && index == 0 && name == "Applications",
                                  installerTemporaryParent: installerResources && index == 1 && parts[0] == "private"
                                      && name == "tmp" && parts.count > 2)
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
            // Darwin dirents are variable-length records. Read only the name
            // bytes covered by this record rather than rebinding a full tuple.
            guard let offset = MemoryLayout<dirent>.offset(of: \.d_name) else { throw InstallerPayloadFailure.path }
            let length = Int(entry.pointee.d_namlen)
            guard length > 0, length < 1024, Int(entry.pointee.d_reclen) >= offset + length + 1 else {
                throw InstallerPayloadFailure.path
            }
            let bytes = UnsafeRawPointer(entry).advanced(by: offset).assumingMemoryBound(to: UInt8.self)
            guard bytes[length] == 0,
                  let name = String(bytes: UnsafeBufferPointer(start: bytes, count: length), encoding: .utf8) else {
                throw InstallerPayloadFailure.path
            }
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
    static func verify(_ fd: Int32, tree: InstallerPayloadTree, owner: uid_t, name: String = "",
                       rootExtras: Set<String> = []) throws -> InstallerPayloadCounts {
        let before = try check(fd, owner: owner, directory: true)
        guard before.st_mode & 0o7777 == tree.nodes[name]?.mode else { throw InstallerPayloadFailure.changed }
        let expected = tree.children[name] ?? []
        guard try contents(fd).subtracting(name.isEmpty ? rootExtras : []) == expected else { throw InstallerPayloadFailure.changed }
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
        let resources = try directory(URL(fileURLWithPath: executable).deletingLastPathComponent().path, owner: 0,
                                      installerResources: true)
        defer { Darwin.close(resources) }
        let file = openat(resources, "RecoveryManifest.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard file >= 0 else { throw InstallerPayloadFailure.manifest }
        let data: Data
        do { data = try read(file, maximum: InstallerPayloadManifest.maximumManifest, owner: 0) }
        catch { Darwin.close(file); throw error }
        Darwin.close(file)
        let manifest = try InstallerPayloadManifest(data)
        return (manifest, try installedImage(manifest))
    }
    static func installedImage(_ manifest: InstallerPayloadManifest, opaquePrivateBranches: Bool = false) throws -> InstallerPayloadCounts {
        var counts = InstallerPayloadCounts()
        for root in manifest.trees.keys.sorted() {
            let fd = try directory(root, owner: 0, sharedApplicationParent: root == InstallerPayloadManifest.application)
            do {
                let extras: Set<String> = opaquePrivateBranches && root == InstallerPayloadManifest.support
                    ? ["broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"] : []
                counts.add(try verify(fd, tree: manifest.trees[root]!, owner: 0, rootExtras: extras))
                // Reopen the namespace after hashing: a moved/replaced app may
                // not substitute for the descriptor-pinned image we inspected.
                let current = try directory(root, owner: 0, sharedApplicationParent: root == InstallerPayloadManifest.application)
                defer { Darwin.close(current) }
                var before = stat(), after = stat()
                guard fstat(fd, &before) == 0, fstat(current, &after) == 0, same(before, after) else { throw InstallerPayloadFailure.changed }
            } catch { Darwin.close(fd); throw error }
            Darwin.close(fd)
        }
        return counts
    }
    static func suppliedManifest() throws -> (InstallerPayloadManifest, InstallerPayloadCounts) {
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 3,
              CommandLine.arguments[1] == "--verify-image-manifest-fd",
              let fd = Int32(CommandLine.arguments[2]), fd >= 3 else { throw InstallerPayloadFailure.context }
        guard lseek(fd, 0, SEEK_SET) == 0 else { throw InstallerPayloadFailure.manifest }
        let manifest = try InstallerPayloadManifest(read(fd, maximum: InstallerPayloadManifest.maximumManifest, owner: 0))
        return (manifest, try installedImage(manifest, opaquePrivateBranches: true))
    }
    static func installSource() throws -> Never {
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 2,
              CommandLine.arguments[1] == "--install" else { throw InstallerPayloadFailure.context }
        let executable = CommandLine.arguments[0]
        guard executable.hasPrefix("/"), executable.hasSuffix("/AccountAccess-installerverify") else { throw InstallerPayloadFailure.context }
        let resourcePath = URL(fileURLWithPath: executable).deletingLastPathComponent().path
        let resources = try directory(resourcePath, owner: 0, installerResources: true)
        defer { Darwin.close(resources) }
        let file = openat(resources, "RecoveryManifest.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard file >= 3 else { throw InstallerPayloadFailure.manifest }
        defer { Darwin.close(file) }
        let data = try read(file, maximum: InstallerPayloadManifest.maximumManifest, owner: 0)
        let manifest = try InstallerPayloadManifest(data)
        let image = openat(resources, "PublicImage", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard image >= 3, image != file else { throw InstallerPayloadFailure.path }
        defer { Darwin.close(image) }
        _ = try check(image, owner: 0, directory: true)
        for root in manifest.trees.keys.sorted() {
            let fd = try walkDirectory(root, from: image, owner: 0)
            defer { Darwin.close(fd) }
            _ = try verify(fd, tree: manifest.trees[root]!, owner: 0)
            let current = try walkDirectory(root, from: image, owner: 0)
            defer { Darwin.close(current) }
            var first = stat(), second = stat()
            guard fstat(fd, &first) == 0, fstat(current, &second) == 0, same(first, second) else { throw InstallerPayloadFailure.changed }
        }
        guard manifest.trees[InstallerPayloadManifest.support]?.nodes["runtime/bin/python"] != nil,
              lseek(file, 0, SEEK_SET) == 0 else { throw InstallerPayloadFailure.manifest }
        let python = resourcePath + "/PublicImage" + InstallerPayloadManifest.support + "/runtime/bin/python"
        try replaceSource(python, source: image, manifest: file, digest: manifest.sha256)
    }
    static func replaceSource(_ python: String, source image: Int32, manifest file: Int32, digest: String) throws -> Never {
        // This primitive preserves identity; it never elevates. Production's
        // root-only caller verifies the complete source before reaching it.
        guard getuid() == geteuid(), image >= 3, file >= 3, image != file,
              python.hasPrefix("/"), !python.utf8.contains(0) else { throw InstallerPayloadFailure.context }
        _ = try check(image, owner: getuid(), directory: true)
        _ = try check(file, owner: getuid(), directory: false)
        // Keep sources above every destination. Explicit dup actions avoid
        // descriptor collisions and inherit only the fixed public 3/4 frame.
        let sourceCopy = fcntl(image, F_DUPFD_CLOEXEC, 10)
        guard sourceCopy >= 10 else { throw InstallerSpawnFailure(operation: .inherit, code: errno) }
        defer { Darwin.close(sourceCopy) }
        let manifestCopy = fcntl(file, F_DUPFD_CLOEXEC, 10)
        guard manifestCopy >= 10 else { throw InstallerSpawnFailure(operation: .inherit, code: errno) }
        defer { Darwin.close(manifestCopy) }
        let input = open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard input >= 0 else { throw InstallerSpawnFailure(operation: .input, code: errno) }
        defer { Darwin.close(input) }
        for fd in [sourceCopy, manifestCopy, input] {
            // SETEXEC applies file actions to these source handles before the
            // new image starts. Clear only our public duplicates; default
            // close-on-exec plus explicit closes still bound the child frame.
            guard fcntl(fd, F_SETFD, 0) == 0 else { throw InstallerSpawnFailure(operation: .inherit, code: errno) }
        }
        let values: [String] = [python, "-I", "-B", "-m", "account_access.install_transaction",
                                "--source-fd", "3", "--manifest-fd", "4",
                                "--manifest-sha256", digest]
        var arguments: [UnsafeMutablePointer<CChar>?] = values.map { value in value.withCString { strdup($0) } }
        arguments.append(nil)
        let settings: [String] = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "HOME=/var/root"]
        var environment: [UnsafeMutablePointer<CChar>?] = settings.map { value in value.withCString { strdup($0) } }
        environment.append(nil)
        defer { arguments.forEach { free($0) }; environment.forEach { free($0) } }
        guard !arguments.dropLast().contains(where: { $0 == nil }),
              !environment.dropLast().contains(where: { $0 == nil }) else { throw InstallerPayloadFailure.execution }
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        let actionStatus = posix_spawn_file_actions_init(&actions)
        guard actionStatus == 0 else { throw InstallerSpawnFailure(operation: .actions, code: actionStatus) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        let attributeStatus = posix_spawnattr_init(&attributes)
        guard attributeStatus == 0 else { throw InstallerSpawnFailure(operation: .attributes, code: attributeStatus) }
        defer { posix_spawnattr_destroy(&attributes) }
        let flagStatus = posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETEXEC | POSIX_SPAWN_CLOEXEC_DEFAULT))
        guard flagStatus == 0 else { throw InstallerSpawnFailure(operation: .attributes, code: flagStatus) }
        let inputStatus = posix_spawn_file_actions_adddup2(&actions, input, 0)
        guard inputStatus == 0 else { throw InstallerSpawnFailure(operation: .input, code: inputStatus) }
        // Only standard output/error and the two verified public handles reach
        // the trusted interpreter. Caller environment and other handles do not.
        for fd in [Int32(1), Int32(2)] {
            guard fcntl(fd, F_GETFD) != -1 else { throw InstallerSpawnFailure(operation: .inherit, code: EBADF) }
            let status = posix_spawn_file_actions_addinherit_np(&actions, fd)
            guard status == 0 else { throw InstallerSpawnFailure(operation: .inherit, code: status) }
        }
        for (source, destination) in [(sourceCopy, Int32(3)), (manifestCopy, Int32(4))] {
            let status = posix_spawn_file_actions_adddup2(&actions, source, destination)
            guard status == 0 else { throw InstallerSpawnFailure(operation: .inherit, code: status) }
        }
        for fd in [sourceCopy, manifestCopy] + (input > 4 ? [input] : []) {
            let status = posix_spawn_file_actions_addclose(&actions, fd)
            guard status == 0 else { throw InstallerSpawnFailure(operation: .inherit, code: status) }
        }
        var pid: pid_t = 0
        let status = arguments.withUnsafeMutableBufferPointer { args in
            environment.withUnsafeMutableBufferPointer { env in
                posix_spawn(&pid, python, &actions, &attributes, args.baseAddress!, env.baseAddress!)
            }
        }
        throw InstallerSpawnFailure(operation: .replace, code: status)
    }
}

#if ACCOUNT_ACCESS_INSTALL_VERIFIER_MAIN
@main struct AccountAccessInstallerVerifier {
    static func main() {
        do {
            if CommandLine.arguments.count == 2, CommandLine.arguments[1] == "--install" {
                try InstallerPayloadIO.installSource()
            }
            if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--verify-image-manifest-fd" {
                let (manifest, counts) = try InstallerPayloadIO.suppliedManifest()
                try output(manifest, counts: counts, status: "VERIFIED")
                return
            }
            // Maintainer preflight accepts only bounded stdin metadata. It
            // cannot read a path or select a target, and root cannot use it to
            // bypass the installed-image check.
            if getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 2,
               CommandLine.arguments[1] == "--inspect-manifest" {
                var data = Data()
                while let block = try FileHandle.standardInput.read(upToCount: 64 * 1024), !block.isEmpty {
                    guard data.count + block.count <= InstallerPayloadManifest.maximumManifest else { throw InstallerPayloadFailure.limit }
                    data.append(block)
                }
                let manifest = try InstallerPayloadManifest(data)
                var counts = InstallerPayloadCounts()
                for tree in manifest.trees.values {
                    for node in tree.nodes.values {
                        if node.kind == "file" { counts.files += 1 }
                        else if node.kind == "directory" { counts.directories += 1 }
                        else { counts.aliases += 1 }
                    }
                }
                try output(manifest, counts: counts, status: "INSPECTED")
                return
            }
            let (manifest, counts) = try InstallerPayloadIO.installed()
            try output(manifest, counts: counts, status: "VERIFIED")
        } catch {
            if let failure = error as? InstallerSpawnFailure {
                let value: [String: Any] = ["schema": 1, "status": "FAILED", "reason": "installer_source_not_started",
                                          "operation": failure.operation.rawValue, "error_code": Int(failure.code)]
                if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) {
                    FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
                }
                exit(78)
            }
            let reason = (error as? InstallerPayloadFailure)?.rawValue ?? "installer_payload_not_verified"
            FileHandle.standardOutput.write(Data(("{\"schema\":1,\"status\":\"FAILED\",\"reason\":\"" + reason + "\"}\n").utf8))
            exit(78)
        }
    }
    static func output(_ manifest: InstallerPayloadManifest, counts: InstallerPayloadCounts, status: String) throws {
        let value: [String: Any] = ["schema": 1, "status": status, "manifest_sha256": manifest.sha256,
                                  "files": counts.files, "directories": counts.directories, "aliases": counts.aliases]
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
    }
}
#endif
