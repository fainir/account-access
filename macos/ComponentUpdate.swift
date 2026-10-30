// Explicit component transitions only. This is not a fresh-install exception.
// Original install journals/private stores remain opaque and are never reset.
import Foundation
import CoreFoundation
import CryptoKit
import Security
import Darwin

enum ComponentUpdateFailure: String, Error {
    case context = "component_update_context_required"
    case source = "component_source_not_verified"
    case base = "component_base_not_verified"
    case journal = "component_transition_conflict"
    case object = "component_object_changed"
    case unavailable = "component_update_unavailable"
    case disabled = "component_service_disable_not_confirmed"
    case quiescence = "component_service_quiescence_not_confirmed"
    case userDomain = "component_service_user_domain_not_confirmed"
    case owner = "component_owner_app_close_required"
    case recovery = "component_manual_retry_required"
    case rollback = "component_rollback_conflict"
}

struct ComponentObject: Codable, Equatable {
    let device: Int32
    let inode: UInt64
    let mode: UInt16
    let bytes: Int64
    let sha256: String
}

struct ComponentOperation: Codable {
    // A fixed target kind, never a journal-selected absolute pathname.
    enum Target: String, Codable { case image, hostPolicy, ownerPolicy, installRecord, head }
    let target: Target
    let path: String
    let slot: String
    let before: ComponentObject?
    let after: ComponentObject
}

struct ComponentTransitionIntent: Codable {
    let schema: Int
    let planSHA256: String
    let baseManifestSHA256: String
    let targetManifestSHA256: String
    let operations: [ComponentOperation]
    let ownerUID: UInt32
    let brokerUID: UInt32
    let service: ComponentJobIdentity?
    let workerPolicy: ComponentObject
    let servicePlist: ComponentObject
    // A package retry is required after a crash; no hidden recovery daemon.
    let automaticRebootRecovery: Bool
}

enum ComponentOperationState: Equatable { case staged, applied, conflict }

protocol ComponentServiceBarrier {
    // Persistent disable is necessary: bootout alone is not reboot-safe.
    func disableAndQuiesce(recovering: Bool) throws
    func requireDisabledAndQuiescent() throws
    func restoreEnabledJob() throws
}

protocol ComponentTransitionStorage {
    var operations: [ComponentOperation] { get }
    func writeEvent(_ event: String, operation: Int) throws
    func state(_ operation: ComponentOperation) throws -> ComponentOperationState
    func apply(_ operation: ComponentOperation) throws
    func reverse(_ operation: ComponentOperation) throws
    func verifyOldView() throws
    func verifyRecoverableView() throws
    func verifyNewView() throws
    func serviceDidQuiesce() throws
}

extension ComponentTransitionStorage {
    // Storage that does not own directory trees has no post-barrier fast path.
    func serviceDidQuiesce() throws {}
}

enum ComponentTransitionResult {
    case publishedGUIUnverified, restoredOldGUIUnverified
}

final class ComponentTransition {
    private let storage: ComponentTransitionStorage
    private let service: ComponentServiceBarrier
    init(storage: ComponentTransitionStorage, service: ComponentServiceBarrier) {
        self.storage = storage; self.service = service
    }
    func run(recovering: Bool) throws -> ComponentTransitionResult {
        // No private account read or owner impersonation is a health check.
        // Check every current object/slot before even changing service state.
        if recovering {
            try storage.verifyRecoverableView()
            var hasHead = false
            for operation in storage.operations where operation.target == .head {
                if try storage.state(operation) == .applied { hasHead = true }
            }
            if hasHead {
                for operation in storage.operations where operation.target != .head {
                    guard try storage.state(operation) == .applied else { throw ComponentUpdateFailure.journal }
                }
            }
        }
        else { try storage.verifyOldView() }
        try service.disableAndQuiesce(recovering: recovering)
        do {
            try storage.serviceDidQuiesce()
            if recovering { try storage.verifyRecoverableView() }
            else { try storage.verifyOldView() }
            for (index, operation) in storage.operations.enumerated() where operation.target != .head {
                try service.requireDisabledAndQuiescent()
                let state = try storage.state(operation)
                if recovering && state == .applied { continue }
                guard state == .staged else { throw ComponentUpdateFailure.object }
                try storage.writeEvent("apply_intent", operation: index)
                try storage.apply(operation)
                guard try storage.state(operation) == .applied else { throw ComponentUpdateFailure.object }
                try storage.writeEvent("applied", operation: index)
            }
            try storage.verifyNewView()
            // The current-head pointer is published only after the complete
            // new image verifies. Rollback removes only our exact head inode.
            for (index, operation) in storage.operations.enumerated() where operation.target == .head {
                try service.requireDisabledAndQuiescent()
                let state = try storage.state(operation)
                if recovering && state == .applied { continue }
                guard state == .staged else { throw ComponentUpdateFailure.object }
                try storage.writeEvent("apply_intent", operation: index)
                try storage.apply(operation)
                guard try storage.state(operation) == .applied else { throw ComponentUpdateFailure.object }
                try storage.writeEvent("applied", operation: index)
            }
            // This durable fact means coherent bytes/pins, never GUI readiness.
            try storage.writeEvent("new_image_verified_gui_unverified", operation: -1)
            try service.restoreEnabledJob()
            return .publishedGUIUnverified
        } catch {
            // Re-disable before reversing an image whose job might have been
            // enabled just before a failed bootstrap/result publication.
            try service.disableAndQuiesce(recovering: true)
            try rollback()
            try storage.verifyOldView()
            try storage.writeEvent("old_image_restored", operation: -1)
            try service.restoreEnabledJob()
            throw error
        }
    }
    private func rollback() throws {
        var conflict = false
        for index in storage.operations.indices.reversed() {
            let operation = storage.operations[index]
            try service.requireDisabledAndQuiescent()
            switch try storage.state(operation) {
            case .staged: continue
            case .conflict:
                conflict = true
                try storage.writeEvent("rollback_conflict", operation: index)
            case .applied:
                try storage.writeEvent("rollback_intent", operation: index)
                try storage.reverse(operation)
                guard try storage.state(operation) == .staged else { throw ComponentUpdateFailure.rollback }
                try storage.writeEvent("rolled_back", operation: index)
            }
        }
        guard !conflict else { throw ComponentUpdateFailure.rollback }
    }
}

enum ComponentFiles {
    static let maximumFile = 16 * 1024 * 1024
    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    static func name(_ value: String) throws {
        guard try InstallerPayloadManifest.components(value).count == 1 else { throw ComponentUpdateFailure.object }
    }
    static func read(_ parent: Int32, _ name: String, owner: uid_t, mode: mode_t? = nil) throws -> (Data, ComponentObject) {
        try self.name(name)
        let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw ComponentUpdateFailure.object }
        defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        if let mode { guard before.st_mode & 0o7777 == mode else { throw ComponentUpdateFailure.object } }
        let data = try InstallerPayloadIO.read(fd, maximum: maximumFile, owner: owner)
        var pathInfo = stat()
        guard fstatat(parent, name, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(before, pathInfo) else { throw ComponentUpdateFailure.object }
        return (data, ComponentObject(device: before.st_dev, inode: before.st_ino,
                                     mode: UInt16(before.st_mode & 0o7777), bytes: before.st_size, sha256: digest(data)))
    }
    static func observe(_ parent: Int32, _ name: String, owner: uid_t) throws -> ComponentObject? {
        try self.name(name)
        var pathInfo = stat()
        if fstatat(parent, name, &pathInfo, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw ComponentUpdateFailure.object }
            return nil
        }
        let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw ComponentUpdateFailure.object }; defer { Darwin.close(fd) }
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        try InstallerPayloadIO.noACL(fd)
        guard InstallerPayloadIO.same(pathInfo, before), before.st_size >= 0,
              before.st_size <= InstallerPayloadManifest.maximumFile else { throw ComponentUpdateFailure.object }
        var count: Int64 = 0, hasher = SHA256(), buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        while true {
            let amount = Darwin.read(fd, &buffer, buffer.count)
            if amount < 0 && errno == EINTR { continue }
            guard amount >= 0, count <= before.st_size - Int64(amount) else { throw ComponentUpdateFailure.object }
            if amount == 0 { break }
            count += Int64(amount); hasher.update(data: buffer.prefix(amount))
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        var pathAfter = stat()
        let after = try InstallerPayloadIO.check(fd, owner: owner, directory: false)
        guard count == before.st_size, InstallerPayloadIO.same(before, after),
              fstatat(parent, name, &pathAfter, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(before, pathAfter) else { throw ComponentUpdateFailure.object }
        return ComponentObject(device: before.st_dev, inode: before.st_ino,
            mode: UInt16(before.st_mode & 0o7777), bytes: before.st_size, sha256: digest)
    }
    static func writeExclusive(_ parent: Int32, _ name: String, data: Data, owner: uid_t, mode: mode_t) throws -> ComponentObject {
        try self.name(name)
        guard data.count <= maximumFile, [mode_t(0o600), 0o644, 0o755].contains(mode) else { throw ComponentUpdateFailure.object }
        let fd = openat(parent, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw ComponentUpdateFailure.object }
        defer { Darwin.close(fd) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw ComponentUpdateFailure.unavailable }
                offset += count
            }
        }
        guard fchmod(fd, mode) == 0, fsync(fd) == 0, fsync(parent) == 0 else { throw ComponentUpdateFailure.unavailable }
        return try read(parent, name, owner: owner, mode: mode).1
    }
    static func rename(_ source: Int32, _ name: String, _ destination: Int32, _ target: String, swap: Bool) throws {
        try self.name(name); try self.name(target)
        // Exclusive publication and atomic swap only; never overwrite rename.
        guard renameatx_np(source, name, destination, target, swap ? UInt32(RENAME_SWAP) : UInt32(RENAME_EXCL)) == 0,
              fsync(source) == 0, fsync(destination) == 0 else { throw ComponentUpdateFailure.object }
    }
}

final class ComponentFileTransaction: ComponentTransitionStorage {
    let operations: [ComponentOperation]
    private let backup: Int32
    private let owner: uid_t
    private let target: (ComponentOperation) throws -> (Int32, String)
    private let oldView: () throws -> Void
    private let newView: () throws -> Void
    private let recoverableView: () throws -> Void
    private var sequence: Int
    init(operations: [ComponentOperation], backup: Int32, owner: uid_t,
         nextEvent: Int = 0, target: @escaping (ComponentOperation) throws -> (Int32, String),
         verifyOld: @escaping () throws -> Void, verifyRecoverable: @escaping () throws -> Void,
         verifyNew: @escaping () throws -> Void) {
        self.operations = operations; self.backup = backup; self.owner = owner
        self.sequence = nextEvent; self.target = target; oldView = verifyOld; newView = verifyNew
        recoverableView = verifyRecoverable
    }
    func writeEvent(_ event: String, operation: Int) throws {
        let allowed: Set<String> = ["apply_intent", "applied", "rollback_intent", "rolled_back", "rollback_conflict",
                                    "old_image_restored", "new_image_verified_gui_unverified"]
        guard allowed.contains(event), operation == -1 || operations.indices.contains(operation), sequence < 10_000 else {
            throw ComponentUpdateFailure.journal
        }
        let data = try JSONSerialization.data(withJSONObject: ["schema": 1, "event": event, "operation": operation], options: [.sortedKeys])
        _ = try ComponentFiles.writeExclusive(backup, String(format: "event-%04d.json", sequence), data: data, owner: owner, mode: 0o600)
        sequence += 1
    }
    func state(_ operation: ComponentOperation) throws -> ComponentOperationState {
        let (parent, name) = try target(operation)
        defer { Darwin.close(parent) }
        let current = try ComponentFiles.observe(parent, name, owner: owner)
        let staged = try ComponentFiles.observe(backup, operation.slot, owner: owner)
        if current == operation.before, staged == operation.after { return .staged }
        if current == operation.after, staged == operation.before { return .applied }
        return .conflict
    }
    func apply(_ operation: ComponentOperation) throws {
        guard try state(operation) == .staged else { throw ComponentUpdateFailure.object }
        let (parent, name) = try target(operation)
        defer { Darwin.close(parent) }
        try ComponentFiles.rename(backup, operation.slot, parent, name, swap: operation.before != nil)
    }
    func reverse(_ operation: ComponentOperation) throws {
        guard try state(operation) == .applied else { throw ComponentUpdateFailure.rollback }
        let (parent, name) = try target(operation)
        defer { Darwin.close(parent) }
        if operation.before == nil {
            try ComponentFiles.rename(parent, name, backup, operation.slot, swap: false)
        } else {
            try ComponentFiles.rename(backup, operation.slot, parent, name, swap: true)
        }
    }
    func verifyOldView() throws { try oldView() }
    func verifyRecoverableView() throws {
        // A partly published image must never be mislabeled an old image.
        for operation in operations {
            guard try state(operation) != .conflict else { throw ComponentUpdateFailure.object }
        }
        try recoverableView()
    }
    func verifyNewView() throws { try newView() }
}

enum ComponentViews {
    // Original private branches are opaque, matching the original verifier.
    // Dynamic policies are separately checked as exact typed operations.
    private static let privateBranches: Set<String> = ["broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"]
    static func verifyRecoverableBase(_ manifest: InstallerPayloadManifest, operations: [ComponentOperation],
                                      owner: uid_t, root: String = InstallerPayloadManifest.support) throws {
        guard let tree = manifest.trees[root] else { throw ComponentUpdateFailure.base }
        let changed = Set(operations.filter { $0.target == .image }.map(\.path))
        let added = Set(operations.filter { $0.target == .image && $0.before == nil }.map(\.path))
        let directory = try InstallerPayloadIO.directory(root, owner: owner)
        defer { Darwin.close(directory) }
        try verifyDirectory(directory, relative: "", tree: tree, changed: changed, added: added, owner: owner)
    }
    private static func verifyDirectory(_ fd: Int32, relative: String, tree: InstallerPayloadTree,
                                        changed: Set<String>, added: Set<String>, owner: uid_t) throws {
        let before = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
        guard before.st_mode & 0o7777 == tree.nodes[relative]?.mode else { throw ComponentUpdateFailure.base }
        let expected = tree.children[relative] ?? []
        let possibleAdditions = Set(added.compactMap { name -> String? in
            let parts = name.split(separator: "/").map(String.init)
            let parent = parts.dropLast().joined(separator: "/")
            return parent == relative ? parts.last : nil
        })
        let actual = try InstallerPayloadIO.contents(fd).subtracting(relative.isEmpty ? privateBranches : [])
        guard expected.isSubset(of: actual), actual.isSubset(of: expected.union(possibleAdditions)) else {
            throw ComponentUpdateFailure.base
        }
        for name in actual.sorted() {
            let path = relative.isEmpty ? name : relative + "/" + name
            var info = stat()
            guard fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw ComponentUpdateFailure.object }
            if changed.contains(path) {
                // Actual before/after inode, mode, hash and backup are checked
                // by the transaction. No unlisted object is skipped here.
                _ = try ComponentFiles.read(fd, name, owner: owner)
                continue
            }
            guard let node = tree.nodes[path] else { throw ComponentUpdateFailure.base }
            if node.kind == "directory" {
                let child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw ComponentUpdateFailure.object }
                defer { Darwin.close(child) }
                try verifyDirectory(child, relative: path, tree: tree, changed: changed, added: added, owner: owner)
            } else if node.kind == "file" {
                let child = openat(fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                guard child >= 0 else { throw ComponentUpdateFailure.object }
                defer { Darwin.close(child) }
                try InstallerPayloadIO.verifyFile(child, node: node, owner: owner)
            } else {
                guard info.st_mode & S_IFMT == S_IFLNK, info.st_uid == owner, info.st_nlink == 1 else {
                    throw ComponentUpdateFailure.object
                }
                var buffer = [CChar](repeating: 0, count: 4097)
                let count = readlinkat(fd, name, &buffer, buffer.count)
                guard count > 0, count <= 4096,
                      String(decoding: buffer.prefix(count).map { UInt8(bitPattern: $0) }, as: UTF8.self) == node.target else {
                    throw ComponentUpdateFailure.object
                }
            }
            var after = stat()
            guard fstatat(fd, name, &after, AT_SYMLINK_NOFOLLOW) == 0,
                  InstallerPayloadIO.same(info, after) else { throw ComponentUpdateFailure.object }
        }
        guard InstallerPayloadIO.same(before, try InstallerPayloadIO.check(fd, owner: owner, directory: true)) else {
            throw ComponentUpdateFailure.object
        }
    }
}

// Revalidation only observes the currently authentic fixed job. It never
// acquires authority over a PID or process group, so it keeps no historical
// snapshot. A live observation must still pass every existing identity check.
struct ComponentRevalidationServiceObserver {
    let observe: () throws -> ComponentCommands.Result
    let attest: (Data) throws -> ComponentJobIdentity?

    func verify() throws {
        let current = try observe()
        guard current.status == 0 else { throw ComponentUpdateFailure.base }
        _ = try attest(current.output)
    }
}

enum ComponentCommands {
    struct Result { let status: Int32; let output: Data }
    // This parent owns and reaps its exact child. A PID cannot be reused before
    // waitpid; timeout/oversize never signals a service or adopted process.
    static func launchctl(_ arguments: [String]) throws -> Result {
        let allowed: Set<[String]> = [
            ["print-disabled", "system"], ["print", "system/com.fainir.accountaccess.broker"],
            ["disable", "system/com.fainir.accountaccess.broker"],
            ["enable", "system/com.fainir.accountaccess.broker"],
            ["bootout", "system/com.fainir.accountaccess.broker"],
            ["bootstrap", "system", "/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist"],
        ]
        guard getuid() == 0, geteuid() == 0, allowed.contains(arguments) else { throw ComponentUpdateFailure.context }
        return try executeLaunchctl(arguments, timeout: 20)
    }
    enum UserDomainAction: String { case bootout, bootstrap }
    static func launchctlUserDomain(_ action: UserDomainAction, brokerUID: uid_t, timeout: TimeInterval) throws -> Result {
        // The reserved nonlogin service identity is selected by the verified
        // installed policy. No owner/user-selected domain is accepted here.
        guard getuid() == 0, geteuid() == 0, (450..<500).contains(brokerUID),
              let account = getpwnam("_accountaccess"), account.pointee.pw_uid == brokerUID,
              account.pointee.pw_gid == brokerUID,
              String(cString: account.pointee.pw_name) == "_accountaccess",
              String(cString: account.pointee.pw_dir) == InstallerPayloadManifest.support + "/home",
              String(cString: account.pointee.pw_shell) == "/usr/bin/false" else {
            throw ComponentUpdateFailure.context
        }
        return try executeLaunchctl([action.rawValue, "user/" + String(brokerUID)], timeout: timeout)
    }
    private static func executeLaunchctl(_ arguments: [String], timeout: TimeInterval) throws -> Result {
        guard timeout.isFinite, timeout > 0, timeout <= 20 else { throw ComponentUpdateFailure.context }
        // This one-shot coordinator owns all of its command children. Do not
        // inherit an ignored SIGCHLD/automatic-reaping policy from a launcher.
        _ = signal(SIGCHLD, SIG_DFL)
        var descriptors: [Int32] = [0, 0]
        guard pipe(&descriptors) == 0 else { throw ComponentUpdateFailure.unavailable }
        defer { Darwin.close(descriptors[0]); Darwin.close(descriptors[1]) }
        let input = open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard input >= 0 else { throw ComponentUpdateFailure.unavailable }
        defer { Darwin.close(input) }
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw ComponentUpdateFailure.unavailable }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw ComponentUpdateFailure.unavailable }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0,
              posix_spawn_file_actions_adddup2(&actions, input, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, descriptors[1], 1) == 0,
              posix_spawn_file_actions_adddup2(&actions, descriptors[1], 2) == 0,
              posix_spawn_file_actions_addclose(&actions, descriptors[0]) == 0,
              posix_spawn_file_actions_addclose(&actions, descriptors[1]) == 0,
              posix_spawn_file_actions_addclose(&actions, input) == 0 else { throw ComponentUpdateFailure.unavailable }
        var argv = (["/bin/launchctl"] + arguments).map { strdup($0) }; argv.append(nil)
        let environmentStrings: [String] = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C"]
        var env = environmentStrings.map { strdup($0) }; env.append(nil)
        defer { argv.forEach { free($0) }; env.forEach { free($0) } }
        guard !argv.dropLast().contains(where: { $0 == nil }), !env.dropLast().contains(where: { $0 == nil }) else {
            throw ComponentUpdateFailure.unavailable
        }
        var pid: pid_t = 0
        let result = argv.withUnsafeMutableBufferPointer { args in env.withUnsafeMutableBufferPointer { settings in
            posix_spawn(&pid, "/bin/launchctl", &actions, &attributes, args.baseAddress!, settings.baseAddress!)
        } }
        guard result == 0, pid > 1 else { throw ComponentUpdateFailure.unavailable }
        // Close our writer now; sentinel -1 makes the deferred close harmless.
        Darwin.close(descriptors[1]); descriptors[1] = -1
        guard fcntl(descriptors[0], F_SETFL, O_NONBLOCK) == 0 else {
            _ = Darwin.kill(pid, SIGKILL); var status: Int32 = 0; _ = waitpid(pid, &status, 0)
            throw ComponentUpdateFailure.unavailable
        }
        var output = Data(), status: Int32 = 0, reaped = false, ownsChild = true, eof = false
        defer {
            if ownsChild { _ = Darwin.kill(pid, SIGKILL); _ = waitpid(pid, &status, 0) }
        }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var buffer = [UInt8](repeating: 0, count: 8192)
        while !reaped || !eof {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw ComponentUpdateFailure.unavailable }
            let count = Darwin.read(descriptors[0], &buffer, buffer.count)
            if count > 0 {
                guard output.count + count <= 256 * 1024 else { throw ComponentUpdateFailure.unavailable }
                output.append(contentsOf: buffer.prefix(count))
            } else if count == 0 { eof = true }
            else if errno != EAGAIN && errno != EINTR { throw ComponentUpdateFailure.unavailable }
            if !reaped {
                let state = waitpid(pid, &status, WNOHANG)
                if state == pid { reaped = true; ownsChild = false }
                else if state != 0 && errno != EINTR {
                    // ECHILD/ownership loss is never authority to signal that
                    // numeric PID; another reaper could have released it.
                    ownsChild = false
                    throw ComponentUpdateFailure.unavailable
                }
            }
            if !reaped || !eof { usleep(10_000) }
        }
        // wait status is returned as a raw closed success/nonzero check only.
        return Result(status: status, output: output)
    }
    static func disabled(_ data: Data) throws -> Bool {
        guard let text = String(data: data, encoding: .utf8), data.count <= 256 * 1024,
              text.unicodeScalars.allSatisfy({ ($0.value >= 32 && $0.value != 127) || $0.value == 9 || $0.value == 10 }) else {
            throw ComponentUpdateFailure.disabled
        }
        let lines = text.components(separatedBy: "\n")
        let horizontal = CharacterSet(charactersIn: " \t")
        var first = 0, last = lines.count
        while first < last && lines[first].trimmingCharacters(in: horizontal).isEmpty { first += 1 }
        while last > first && lines[last - 1].trimmingCharacters(in: horizontal).isEmpty { last -= 1 }
        guard (2...10_000).contains(last - first),
              lines[first].trimmingCharacters(in: horizontal) == "disabled services = {",
              lines[last - 1].trimmingCharacters(in: horizontal) == "}" else {
            throw ComponentUpdateFailure.disabled
        }
        // Actual macOS prints disabled/enabled. Boolean spellings remain an
        // explicit compatibility form; no arbitrary token means enabled.
        let row = try NSRegularExpression(pattern: #"^[ \t]*"([\x20-\x21\x23-\x5b\x5d-\x7e]{1,255})"[ \t]+=>[ \t]+([a-z]{1,16})[ \t]*$"#)
        var labels: Set<String> = [], target: Bool?
        for line in lines[(first + 1)..<(last - 1)] {
            let range = NSRange(line.startIndex..<line.endIndex, in: line)
            guard let match = row.firstMatch(in: line, range: range), match.range == range,
                  let labelRange = Range(match.range(at: 1), in: line),
                  let tokenRange = Range(match.range(at: 2), in: line) else { throw ComponentUpdateFailure.disabled }
            let label = String(line[labelRange]), token = String(line[tokenRange])
            guard ["disabled", "enabled", "true", "false"].contains(token),
                  labels.insert(label).inserted else { throw ComponentUpdateFailure.disabled }
            if label == "com.fainir.accountaccess.broker" { target = token == "disabled" || token == "true" }
        }
        // Successful, completely recognized output with no override is enabled.
        return target ?? false
    }
    static func definitivelyAbsent(_ result: Result) -> Bool {
        // Pinned macOS CLI contract, additionally required to pass the
        // disposable native Installer probe before any production assembly.
        result.status == (113 << 8) && result.output == Data((
            "Bad request.\nCould not find service \"com.fainir.accountaccess.broker\" in domain for system\n"
        ).utf8)
    }
}

enum ComponentProcesses {
    static func listed(_ type: UInt32, _ info: UInt32) throws -> [pid_t] {
        var pids = [pid_t](repeating: 0, count: 65_536)
        var failure: Int32 = 0
        let count = pids.withUnsafeMutableBytes {
            errno = 0
            let result = proc_listpids(type, info, $0.baseAddress, Int32($0.count))
            failure = errno
            return result
        }
        guard failure == 0, count >= 0, count < pids.count * MemoryLayout<pid_t>.size,
              count % Int32(MemoryLayout<pid_t>.size) == 0 else { throw ComponentUpdateFailure.quiescence }
        return pids.prefix(Int(count) / MemoryLayout<pid_t>.size).filter { $0 > 1 }
    }
    static func atPath(_ path: String) throws -> [pid_t] {
        var pids = [pid_t](repeating: 0, count: 65_536)
        let count = pids.withUnsafeMutableBytes { proc_listpidspath(UInt32(PROC_ALL_PIDS), 0, path, 0, $0.baseAddress, Int32($0.count)) }
        guard count >= 0, count < pids.count * MemoryLayout<pid_t>.size,
              count % Int32(MemoryLayout<pid_t>.size) == 0 else { throw ComponentUpdateFailure.quiescence }
        let references = pids.prefix(Int(count) / MemoryLayout<pid_t>.size).filter { $0 > 1 }
        return try references.filter { pid in
            // proc_listpidspath includes open file references. A verifier's
            // open descriptor is not an executing GUI/worker. Bind executable
            // path and process birth across this observation instead.
            var before = proc_bsdinfo(), after = proc_bsdinfo()
            let size = Int32(MemoryLayout<proc_bsdinfo>.size)
            errno = 0
            if proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, size) != size {
                if errno == ESRCH { return false }
                throw ComponentUpdateFailure.quiescence
            }
            var buffer = [CChar](repeating: 0, count: 4096)
            guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0,
                  proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, size) == size,
                  before.pbi_pid == after.pbi_pid, before.pbi_uid == after.pbi_uid,
                  before.pbi_start_tvsec == after.pbi_start_tvsec,
                  before.pbi_start_tvusec == after.pbi_start_tvusec else { throw ComponentUpdateFailure.quiescence }
            return String(cString: buffer) == path
        }
    }
    static func requireOwnerClosed() throws {
        guard try atPath(InstallerPayloadManifest.canonicalApplication + "/Contents/MacOS/AccountAccess").isEmpty else {
            throw ComponentUpdateFailure.owner
        }
    }
    static func requireQuiescent(brokerUID: uid_t) throws {
        try ComponentSystemProcessObserver.live(brokerUID: brokerUID).verify(brokerUID: brokerUID)
        guard try atPath(InstallerPayloadManifest.support + "/bin/AccountAccess-broker").isEmpty,
              try atPath(InstallerPayloadManifest.support + "/bin/AccountAccess-bootstrap").isEmpty else {
            throw ComponentUpdateFailure.quiescence
        }
    }
}

struct ComponentDisableOwnership {
    private var ownsIntent = false
    func permits(disabled: Bool, recovering: Bool, persistedIntent: Bool) -> Bool {
        !disabled || recovering && (persistedIntent || ownsIntent)
    }
    mutating func persistPriorEnabled(_ write: () throws -> Void) throws {
        try write()
        ownsIntent = true
    }
}

final class ComponentUserDomainQuiescence {
    enum Event: String {
        case bootoutIntent = "user_domain_bootout_intent"
        case quiescenceConfirmed = "user_domain_quiescence_confirmed"
        case bootstrapIntent = "user_domain_bootstrap_intent"
        case bootstrapConfirmed = "user_domain_bootstrap_confirmed"
    }
    struct Operations {
        let command: (ComponentCommands.UserDomainAction, TimeInterval) throws -> ComponentCommands.Result
        let requireFixedJobDisabled: () throws -> Void
        let verifyAllQuiescent: (Bool) throws -> Void
        let record: (Event) throws -> Void
    }
    private let operations: Operations
    private let clock: () -> TimeInterval
    private let pause: (TimeInterval) -> Void
    private var removalConfirmed = false
    init(operations: Operations, clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         pause: @escaping (TimeInterval) -> Void = { usleep(useconds_t($0 * 1_000_000)) }) {
        self.operations = operations; self.clock = clock; self.pause = pause
    }
    private func complete(_ action: ComponentCommands.UserDomainAction) throws {
        let deadline = clock() + 40
        for _ in 0..<161 {
            let remaining = deadline - clock()
            guard remaining.isFinite, remaining > 0 else { throw ComponentUpdateFailure.userDomain }
            let result = try operations.command(action, min(20, remaining))
            guard clock() <= deadline else { throw ComponentUpdateFailure.userDomain }
            if result.status == 0 {
                guard result.output.isEmpty else { throw ComponentUpdateFailure.userDomain }
                return
            }
            let tearingDown = action == .bootout ? "Boot-out failed: 124: Domain is tearing down\n"
                : "Bootstrap failed: 124: Domain is tearing down\n"
            guard result.status == (124 << 8), result.output == Data(tearingDown.utf8) else {
                throw ComponentUpdateFailure.userDomain
            }
            let delay = min(0.25, deadline - clock())
            guard delay.isFinite, delay > 0 else { throw ComponentUpdateFailure.userDomain }
            pause(delay)
        }
        throw ComponentUpdateFailure.userDomain
    }
    func quiesce() throws {
        removalConfirmed = false
        try operations.requireFixedJobDisabled()
        try operations.record(.bootoutIntent) // Existing exclusive event write/fsync precedes removal.
        try complete(.bootout)
        try operations.verifyAllQuiescent(true)
        removalConfirmed = true
        do { try operations.record(.quiescenceConfirmed) }
        catch { removalConfirmed = false; throw error }
    }
    func requireQuiescent() throws {
        guard removalConfirmed else { throw ComponentUpdateFailure.userDomain }
        try operations.verifyAllQuiescent(false)
    }
    func restore() throws {
        try requireQuiescent()
        try operations.record(.bootstrapIntent)
        // Domain creation can launch OS agents. It invalidates the removal
        // barrier even if the command or the following durable event fails.
        removalConfirmed = false
        try complete(.bootstrap)
        try operations.requireFixedJobDisabled()
        try operations.record(.bootstrapConfirmed)
    }
}

final class ComponentLaunchdBarrier: ComponentServiceBarrier {
    private let brokerUID: uid_t
    private let recoveringIntent: Bool
    private let record: (String) throws -> Void
    private var ownership = ComponentDisableOwnership()
    private var snapshots: [ComponentJobIdentity]
    private let peers: [ComponentPeerSignature]
    private let recordSnapshot: (ComponentJobIdentity) throws -> Void
    private lazy var userDomain = ComponentUserDomainQuiescence(operations: .init(command: { [unowned self] action, timeout in
        try ComponentCommands.launchctlUserDomain(action, brokerUID: self.brokerUID, timeout: timeout)
    }, requireFixedJobDisabled: { [unowned self] in
        guard try self.isDisabled() else { throw ComponentUpdateFailure.disabled }
    }, verifyAllQuiescent: { [unowned self] wait in
        try self.verifyDisabledAndProcesses(wait: wait)
    }, record: { [unowned self] event in try self.record(event.rawValue) }))
    init(brokerUID: uid_t, recoveringIntent: Bool, snapshots: [ComponentJobIdentity],
         peers: [ComponentPeerSignature], recordSnapshot: @escaping (ComponentJobIdentity) throws -> Void,
         record: @escaping (String) throws -> Void) {
        self.brokerUID = brokerUID; self.recoveringIntent = recoveringIntent; self.record = record
        self.snapshots = snapshots; self.peers = peers; self.recordSnapshot = recordSnapshot
    }
    private func isDisabled() throws -> Bool {
        let result = try ComponentCommands.launchctl(["print-disabled", "system"])
        guard result.status == 0 else { throw ComponentUpdateFailure.disabled }
        return try ComponentCommands.disabled(result.output)
    }
    func disableAndQuiesce(recovering: Bool) throws {
        try ComponentProcesses.requireOwnerClosed()
        let disabled = try isDisabled()
        // A disabled job is not an invitation to adopt the owner's pause. Only
        // our matching durable prior-enabled intent authorizes recovery.
        guard ownership.permits(disabled: disabled, recovering: recovering, persistedIntent: recoveringIntent) else {
            throw ComponentUpdateFailure.disabled
        }
        try ownership.persistPriorEnabled { try record("disable_intent_prior_enabled") }
        if !disabled {
            guard try ComponentCommands.launchctl(["disable", "system/com.fainir.accountaccess.broker"]).status == 0 else {
                throw ComponentUpdateFailure.disabled
            }
        }
        guard try isDisabled() else { throw ComponentUpdateFailure.disabled }
        try record("disabled_confirmed")
        let current = try ComponentCommands.launchctl(["print", "system/com.fainir.accountaccess.broker"])
        if current.status == 0 {
            if let snapshot = try ComponentUpdateIdentity.jobSnapshot(output: current.output, allowedPeers: peers) {
                try recordSnapshot(snapshot) // Durable before bootout; never an adopted PID.
                snapshots.append(snapshot)
            }
        } else if !ComponentCommands.definitivelyAbsent(current) { throw ComponentUpdateFailure.quiescence }
        _ = try ComponentCommands.launchctl(["bootout", "system/com.fainir.accountaccess.broker"])
        // A generic nonzero never establishes absence. Require the one exact
        // missing-service response, even after our own successful bootout.
        guard ComponentCommands.definitivelyAbsent(try ComponentCommands.launchctl([
            "print", "system/com.fainir.accountaccess.broker",
        ])) else { throw ComponentUpdateFailure.quiescence }
        try userDomain.quiesce()
        try requireDisabledAndQuiescent()
        try record("disabled_quiescence_confirmed")
    }
    func requireDisabledAndQuiescent() throws {
        try userDomain.requireQuiescent()
    }
    private func verifyDisabledAndProcesses(wait: Bool) throws {
        guard try isDisabled() else { throw ComponentUpdateFailure.disabled }
        guard ComponentCommands.definitivelyAbsent(try ComponentCommands.launchctl([
            "print", "system/com.fainir.accountaccess.broker",
        ])) else { throw ComponentUpdateFailure.quiescence }
        try ComponentProcesses.requireOwnerClosed()
        if wait {
            let deadline = ProcessInfo.processInfo.systemUptime + 20
            while true {
                if (try? ComponentProcesses.requireQuiescent(brokerUID: brokerUID)) != nil { break }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw ComponentUpdateFailure.quiescence }
                usleep(50_000)
            }
        }
        try ComponentProcesses.requireQuiescent(brokerUID: brokerUID)
        for snapshot in snapshots { try ComponentUpdateIdentity.requireGone(snapshot) }
    }
    func restoreEnabledJob() throws {
        try userDomain.restore()
        try record("coherent_image_enable_intent")
        guard try ComponentCommands.launchctl(["enable", "system/com.fainir.accountaccess.broker"]).status == 0,
              try !isDisabled() else { throw ComponentUpdateFailure.disabled }
        guard try ComponentCommands.launchctl(["bootstrap", "system", "/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist"]).status == 0 else {
            throw ComponentUpdateFailure.unavailable
        }
        // No owner-health RPC and no vault read; GUI connection is a separate
        // owner-session acceptance step after a normal reopen.
        try record("canonical_job_bootstrapped_gui_unverified")
    }
}

struct ComponentSource {
    static let baseDigest = "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8"
    static let support = InstallerPayloadManifest.support
    static let site = "runtime/lib/python3.12/site-packages/"
    static let allowed: Set<String> = ["bin/AccountAccess-broker", "bin/AccountAccess-bootstrap",
        site + "account_access/worker_bootstrap.py", site + "account_access/worker_host.py",
        site + "account_access/listener_binding.py", site + "account_access-0.8.0.dist-info/RECORD",
        "runtime-image.json", "package-identity.json", "component-identity.json"]
    struct Delta {
        let path: String
        let resource: String
        let before: InstallerPayloadNode?
        let after: InstallerPayloadNode
        let data: Data
    }
    let oldManifest: InstallerPayloadManifest
    let newManifest: InstallerPayloadManifest
    let planDigest: String
    let oldPeers: [String: ComponentPeerSignature]
    let newPeers: [String: ComponentPeerSignature]
    let oldFingerprint: String
    let newFingerprint: String
    let delta: [Delta]
    let designated: [String: String]

    private static func file(_ fd: Int32, _ name: String, maximum: Int = ComponentFiles.maximumFile) throws -> Data {
        let value = try ComponentFiles.read(fd, name, owner: 0, mode: 0o644).0
        guard value.count <= maximum else { throw ComponentUpdateFailure.source }
        return value
    }
    private static func nodeEqual(_ left: InstallerPayloadNode?, _ right: InstallerPayloadNode?) -> Bool {
        left?.kind == right?.kind && left?.mode == right?.mode && left?.size == right?.size
            && left?.sha256 == right?.sha256 && left?.target == right?.target
    }
    private static func peers(_ value: Any?) throws -> [String: ComponentPeerSignature] {
        guard let value = value as? [String: Any] else { throw ComponentUpdateFailure.source }
        return try JSONDecoder().decode([String: ComponentPeerSignature].self,
                                        from: JSONSerialization.data(withJSONObject: value))
    }
    private static func boolean(_ value: Any?, _ expected: Bool) -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return false }
        return number.boolValue == expected
    }
    private static func rowMatches(_ value: Any?, _ node: InstallerPayloadNode) throws -> Bool {
        guard let value = value as? [String: Any], Set(value.keys) == ["kind", "mode", "size", "sha256"],
              value["kind"] as? String == node.kind, value["sha256"] as? String == node.sha256 else { return false }
        return try InstallerPayloadManifest.integer(value["mode"], maximum: 0o777) == Int64(node.mode ?? 0)
            && InstallerPayloadManifest.integer(value["size"], maximum: Int64(ComponentFiles.maximumFile)) == node.size
    }
    static func load(_ resources: Int32, planPin: String) throws -> ComponentSource {
        let raw = try file(resources, "ComponentPlan.json", maximum: 256 * 1024)
        guard ComponentFiles.digest(raw) == planPin,
              let plan = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
              Set(plan.keys) == ["schema", "managed_by", "base_source_commit", "component_source_commit",
                "base_manifest_sha256", "target_manifest_sha256", "delta", "old_signatures", "new_signatures",
                "old_fingerprint", "new_fingerprint", "designated_requirements", "private_schema_unchanged",
                "automatic_reboot_recovery", "normal_gui_reopen_required", "sms_native_port_refresh_verified"],
              try InstallerPayloadManifest.integer(plan["schema"], maximum: 1) == 1,
              plan["managed_by"] as? String == "account-access-native-component-update-v1",
              plan["base_source_commit"] as? String == "fbd2a733b60acde68e82fe796cb7abd971d5d625",
              plan["base_manifest_sha256"] as? String == baseDigest,
              let targetDigest = plan["target_manifest_sha256"] as? String,
              let oldFingerprint = plan["old_fingerprint"] as? String,
              let newFingerprint = plan["new_fingerprint"] as? String,
              boolean(plan["private_schema_unchanged"], true),
              boolean(plan["automatic_reboot_recovery"], false),
              boolean(plan["normal_gui_reopen_required"], true),
              let rows = plan["delta"] as? [[String: Any]], rows.count == allowed.count else {
            throw ComponentUpdateFailure.source
        }
        let old = try InstallerPayloadManifest(file(resources, "BaseManifest.json"))
        let new = try InstallerPayloadManifest(file(resources, "TargetManifest.json"))
        guard old.sha256 == baseDigest, new.sha256 == targetDigest,
              let oldTree = old.trees[support], let newTree = new.trees[support],
              old.trees[InstallerPayloadManifest.application]?.nodes[""]?.target == new.trees[InstallerPayloadManifest.application]?.nodes[""]?.target,
              Set(newTree.nodes.keys) == Set(oldTree.nodes.keys).union([site + "account_access/listener_binding.py", "component-identity.json"]) else {
            throw ComponentUpdateFailure.source
        }
        for (path, before) in oldTree.nodes where !allowed.contains(path) {
            guard nodeEqual(before, newTree.nodes[path]) else { throw ComponentUpdateFailure.source }
        }
        for path in oldTree.nodes.keys {
            for module in ["worker_host", "worker_bootstrap", "listener_binding"] {
                guard !(path == site + "account_access/" + module + ".pyc"
                    || path.hasPrefix(site + "account_access/__pycache__/" + module + ".") && path.hasSuffix(".pyc")) else {
                    throw ComponentUpdateFailure.source
                }
            }
        }
        guard let designated = plan["designated_requirements"] as? [String: String],
              Set(designated.keys) == ["broker", "bootstrap"],
              designated.values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4096 }),
              boolean(plan["sms_native_port_refresh_verified"], false) else { throw ComponentUpdateFailure.source }
        let oldPeers = try peers(plan["old_signatures"]), newPeers = try peers(plan["new_signatures"])
        let baseIdentity = try file(resources, "BaseIdentity.json", maximum: 4096)
        guard ComponentFiles.digest(baseIdentity) == oldTree.nodes["package-identity.json"]?.sha256,
              let object = try JSONSerialization.jsonObject(with: baseIdentity) as? [String: Any],
              try peers(object["signatures"]) == oldPeers else { throw ComponentUpdateFailure.source }
        var delta: [Delta] = []
        var names: Set<String> = []
        for (index, row) in rows.enumerated() {
            guard Set(row.keys) == ["path", "before", "after", "resource"], let path = row["path"] as? String,
                  path == allowed.sorted()[index], names.insert(path).inserted,
                  let resource = row["resource"] as? String, resource == String(format: "delta-%02d.bin", index),
                  let after = newTree.nodes[path], after.kind == "file",
                  after.mode == (path.hasPrefix("bin/") ? 0o755 : 0o644) else { throw ComponentUpdateFailure.source }
            let data = try file(resources, resource)
            guard ComponentFiles.digest(data) == after.sha256, Int64(data.count) == after.size else { throw ComponentUpdateFailure.source }
            // A plan cannot disagree with either parsed full manifest.
            guard try rowMatches(row["after"], after) else { throw ComponentUpdateFailure.source }
            if let before = oldTree.nodes[path] {
                guard try rowMatches(row["before"], before) else { throw ComponentUpdateFailure.source }
            } else if !(row["before"] is NSNull) { throw ComponentUpdateFailure.source }
            delta.append(Delta(path: path, resource: resource, before: oldTree.nodes[path], after: after, data: data))
        }
        guard let identity = delta.first(where: { $0.path == "package-identity.json" }),
              let object = try JSONSerialization.jsonObject(with: identity.data) as? [String: Any],
              try peers(object["signatures"]) == newPeers else { throw ComponentUpdateFailure.source }
        let resourcesExpected = Set(["ComponentPlan.json", "BaseManifest.json", "TargetManifest.json", "BaseIdentity.json",
                                     "AccountAccess-componentupdate", "postinstall"] + delta.map(\.resource))
        guard try InstallerPayloadIO.contents(resources) == resourcesExpected else { throw ComponentUpdateFailure.source }
        return ComponentSource(oldManifest: old, newManifest: new, planDigest: planPin,
                               oldPeers: oldPeers, newPeers: newPeers, oldFingerprint: oldFingerprint,
                               newFingerprint: newFingerprint, delta: delta, designated: designated)
    }
}

// Preparation directories have no authority. Publish one complete fsynced
// directory exclusively; an interrupted earlier preparation is retained.
enum ComponentPreparation {
    static let byteLimit: Int64 = 64 * 1024 * 1024
    static func capacity(_ parent: Int32, bytes: Int64, owner: uid_t, sameDeviceAs: Int32? = nil) throws {
        let directory = try InstallerPayloadIO.check(parent, owner: owner, directory: true)
        guard bytes > 0 else { throw ComponentUpdateFailure.unavailable }
        if let source = sameDeviceAs {
            guard directory.st_dev == (try InstallerPayloadIO.check(source, owner: owner, directory: true)).st_dev else {
                throw ComponentUpdateFailure.unavailable
            }
        }
        var volume = statvfs()
        guard fstatvfs(parent, &volume) == 0, volume.f_frsize >= 512, volume.f_frsize <= 1024 * 1024 else {
            throw ComponentUpdateFailure.unavailable
        }
        // Compare blocks by division, avoiding capacity multiplication overflow.
        let block = UInt64(volume.f_frsize), requested = UInt64(bytes)
        let blocks = requested / block + (requested % block == 0 ? 0 : 1)
        guard UInt64(volume.f_bavail) >= blocks else { throw ComponentUpdateFailure.unavailable }
    }
    static func retained(_ parent: Int32, plan: String, slots: [String: mode_t], owner: uid_t, reserve: Int64 = 0) throws -> Int {
        let before = try InstallerPayloadIO.check(parent, owner: owner, directory: true)
        guard before.st_mode & 0o7777 == 0o700, (1...13).contains(slots.count),
              Set(slots.keys) == Set((0..<slots.count).map { String(format: "slot-%02d", $0) }) else {
            throw ComponentUpdateFailure.journal
        }
        let prefix = ".preparing-" + plan + "-"
        var count = 0, bytes: Int64 = 0
        for name in try InstallerPayloadIO.contents(parent) {
            if name == "transition-" + plan || name == "head.json" { continue }
            guard name.hasPrefix(prefix), let uuid = UUID(uuidString: String(name.dropFirst(prefix.count))),
                  uuid.uuidString.lowercased() == String(name.dropFirst(prefix.count)) else { throw ComponentUpdateFailure.journal }
            count += 1
            guard count <= 8 else { throw ComponentUpdateFailure.journal }
            let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw ComponentUpdateFailure.journal }
            defer { Darwin.close(fd) }
            let directory = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
            guard directory.st_mode & 0o7777 == 0o700 else { throw ComponentUpdateFailure.journal }
            let names = try InstallerPayloadIO.contents(fd)
            guard names.isSubset(of: Set(slots.keys).union(["intent.json"])) else { throw ComponentUpdateFailure.journal }
            for child in names {
                let file = openat(fd, child, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard file >= 0 else { throw ComponentUpdateFailure.journal }
                defer { Darwin.close(file) }
                let info = try InstallerPayloadIO.check(file, owner: owner, directory: false)
                var current = stat()
                let mode = info.st_mode & 0o7777
                guard mode == 0o600 || mode == slots[child],
                      info.st_size >= 0, info.st_size <= (child == "intent.json" ? 64 * 1024 : ComponentFiles.maximumFile),
                      fstatat(fd, child, &current, AT_SYMLINK_NOFOLLOW) == 0,
                      InstallerPayloadIO.same(info, current) else { throw ComponentUpdateFailure.journal }
                bytes += info.st_size
                guard bytes <= byteLimit else { throw ComponentUpdateFailure.journal }
            }
            var current = stat()
            guard InstallerPayloadIO.same(directory, try InstallerPayloadIO.check(fd, owner: owner, directory: true)),
                  fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                  InstallerPayloadIO.same(directory, current) else { throw ComponentUpdateFailure.journal }
        }
        guard InstallerPayloadIO.same(before, try InstallerPayloadIO.check(parent, owner: owner, directory: true)) else {
            throw ComponentUpdateFailure.journal
        }
        guard reserve >= 0, reserve <= byteLimit, bytes <= byteLimit - reserve else { throw ComponentUpdateFailure.journal }
        return count
    }
    static func begin(_ parent: Int32, plan: String, owner: uid_t) throws -> (String, Int32) {
        let name = ".preparing-" + plan + "-" + UUID().uuidString.lowercased()
        guard mkdirat(parent, name, 0o700) == 0, fsync(parent) == 0 else { throw ComponentUpdateFailure.journal }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ComponentUpdateFailure.journal }
        do {
            let info = try InstallerPayloadIO.check(fd, owner: owner, directory: true)
            var current = stat()
            guard info.st_mode & 0o7777 == 0o700, try InstallerPayloadIO.contents(fd).isEmpty,
                  fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                  InstallerPayloadIO.same(info, current) else { throw ComponentUpdateFailure.journal }
            return (name, fd)
        } catch { Darwin.close(fd); throw error }
    }
    static func publish(_ parent: Int32, name: String, directory: Int32, plan: String, owner: uid_t) throws {
        let before = try InstallerPayloadIO.check(directory, owner: owner, directory: true)
        var current = stat()
        guard before.st_mode & 0o7777 == 0o700,
              fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0, InstallerPayloadIO.same(before, current),
              fsync(directory) == 0 else { throw ComponentUpdateFailure.journal }
        let final = "transition-" + plan
        try ComponentFiles.rename(parent, name, parent, final, swap: false)
        let observed = try InstallerPayloadIO.check(directory, owner: owner, directory: true)
        guard before.st_dev == observed.st_dev, before.st_ino == observed.st_ino,
              fstatat(parent, final, &current, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(observed, current) else { throw ComponentUpdateFailure.journal }
    }
}

// The production adapter selects fixed public paths only. All journal bytes
// stay in a root-only namespace; private account directories are never opened.
enum ComponentController {
    static let namespace = "/Library/Application Support/Account Access Components"
    private static let oldJournal = "/Library/Application Support/Account Access Installer"
    private static let label = "com.fainir.accountaccess.broker"
    private static let dynamic: [(ComponentOperation.Target, String, mode_t)] = [
        (.hostPolicy, "broker/host.json", 0o644), (.ownerPolicy, "owner.json", 0o644),
        (.installRecord, "broker/install.json", 0o600), (.head, "head.json", 0o644),
    ]
    private static func encoded<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    private static func json(_ data: Data, maximum: Int = 8192) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= maximum,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw ComponentUpdateFailure.journal }
        return object
    }
    private static func directory(_ path: String, mode: mode_t) throws -> Int32 {
        let fd = try InstallerPayloadIO.directory(path, owner: 0)
        do {
            guard try InstallerPayloadIO.check(fd, owner: 0, directory: true).st_mode & 0o7777 == mode else {
                throw ComponentUpdateFailure.object
            }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    private static func child(_ parent: Int32, _ name: String, create: Bool) throws -> Int32 {
        try ComponentFiles.name(name)
        if create {
            if mkdirat(parent, name, 0o700) == 0 {
                guard fsync(parent) == 0 else { throw ComponentUpdateFailure.unavailable }
            } else if errno != EEXIST { throw ComponentUpdateFailure.object }
        }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ComponentUpdateFailure.object }
        do {
            let info = try InstallerPayloadIO.check(fd, owner: 0, directory: true)
            var current = stat()
            guard info.st_mode & 0o7777 == 0o700,
                  fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                  InstallerPayloadIO.same(info, current) else { throw ComponentUpdateFailure.object }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    private static func lease(_ parent: Int32, _ name: String) throws -> Int32 {
        let fd = openat(parent, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw ComponentUpdateFailure.journal }
        do {
            let before = try InstallerPayloadIO.check(fd, owner: 0, directory: false)
            var current = stat()
            guard before.st_mode & 0o7777 == 0o600, flock(fd, LOCK_EX | LOCK_NB) == 0,
                  fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                  InstallerPayloadIO.same(before, current) else { throw ComponentUpdateFailure.journal }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    private static func target(_ operation: ComponentOperation) throws -> (Int32, String) {
        let absolute: String
        switch operation.target {
        case .image:
            guard ComponentSource.allowed.contains(operation.path) else { throw ComponentUpdateFailure.journal }
            absolute = ComponentSource.support + "/" + operation.path
        case .hostPolicy, .ownerPolicy, .installRecord:
            guard let entry = dynamic.first(where: { $0.0 == operation.target }), entry.1 == operation.path else {
                throw ComponentUpdateFailure.journal
            }
            absolute = ComponentSource.support + "/" + operation.path
        case .head:
            guard operation.path == "head.json" else { throw ComponentUpdateFailure.journal }
            absolute = namespace + "/head.json"
        }
        return (try InstallerPayloadIO.directory(URL(fileURLWithPath: absolute).deletingLastPathComponent().path, owner: 0),
                URL(fileURLWithPath: absolute).lastPathComponent)
    }
    private static func publicRead(_ relative: String, mode: mode_t) throws -> (Data, ComponentObject) {
        let parts = try InstallerPayloadManifest.components(relative)
        guard !parts.isEmpty else { throw ComponentUpdateFailure.object }
        let fd = try InstallerPayloadIO.directory(ComponentSource.support + (parts.count == 1 ? "" : "/" + parts.dropLast().joined(separator: "/")), owner: 0)
        defer { Darwin.close(fd) }
        return try ComponentFiles.read(fd, parts.last!, owner: 0, mode: mode)
    }
    private static func owner() throws -> (uid_t, gid_t) {
        var console = stat()
        guard lstat("/dev/console", &console) == 0, console.st_mode & S_IFMT == S_IFCHR,
              console.st_uid > 0, let record = getpwuid(console.st_uid),
              !["root", "loginwindow", "_mbsetupuser", "_accountaccess"].contains(String(cString: record.pointee.pw_name)) else {
            throw ComponentUpdateFailure.context
        }
        return (console.st_uid, record.pointee.pw_gid)
    }
    private static func identity(_ ownerUID: uid_t, _ brokerUID: uid_t) throws {
        guard ownerUID != brokerUID, (450..<500).contains(brokerUID),
              let user = getpwnam("_accountaccess"), user.pointee.pw_uid == brokerUID,
              user.pointee.pw_gid == brokerUID,
              String(cString: user.pointee.pw_dir) == ComponentSource.support + "/home",
              String(cString: user.pointee.pw_shell) == "/usr/bin/false",
              let group = getgrnam("_accountaccess"), group.pointee.gr_gid == brokerUID else {
            throw ComponentUpdateFailure.base
        }
    }
    private static func originalReceipt(_ journal: Int32, ownerUID: uid_t) throws {
        try InstallationRootBinding.verify(journal: journal, ownerUID: ownerUID, manifestSHA256: ComponentSource.baseDigest)
    }

    // This separate Installer entrypoint attests to the current verified image.
    // It never rewrites a historical receipt, adopts an inode replacement,
    // changes service state, or enters a private account directory.
    static func revalidate(resources: Int32, planPin: String, checkpoint: (String) -> Void) throws -> String {
        guard getuid() == 0, geteuid() == 0 else { throw ComponentUpdateFailure.context }
        checkpoint("source")
        let source = try ComponentSource.load(resources, planPin: planPin)
        guard source.oldPeers["owner"]?.team == "WBULD6N4NQ", source.newPeers["owner"] == source.oldPeers["owner"] else {
            throw ComponentUpdateFailure.source
        }
        for kind in ["broker", "bootstrap"] {
            guard let delta = source.delta.first(where: { $0.path == "bin/AccountAccess-" + kind }),
                  let peer = source.newPeers[kind], let requirement = source.designated[kind] else { throw ComponentUpdateFailure.source }
            let path = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent(delta.resource).path
            try ComponentUpdateIdentity.verifyStatic(path: path, peer: peer, designated: requirement)
        }
        let plan = try json(ComponentFiles.read(resources, "ComponentPlan.json", owner: 0, mode: 0o644).0)
        guard let sourceCommit = plan["component_source_commit"] as? String,
              sourceCommit.utf8.count == 40,
              sourceCommit.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw ComponentUpdateFailure.source
        }
        checkpoint("legacy")
        let (ownerUID, ownerGroup) = try owner()
        let original = try directory(oldJournal, mode: 0o700)
        defer { Darwin.close(original) }
        let originalLease = try lease(original, "lock")
        defer { Darwin.close(originalLease) }
        let legacy = try InstallationRootBinding.readLegacy(original, ownerUID: ownerUID, manifestSHA256: source.oldManifest.sha256)
        let hasNamespace = try InstallationRootBinding.hasSupplementNamespace()
        if try !hasNamespace && InstallationRootBinding.exactLegacy(legacy, current: InstallationRootBinding.capture(withVolumeUUID: false)) {
            return "ALREADY_BOUND"
        }
        checkpoint("current_binding")
        let current = try InstallationRootBinding.capture(withVolumeUUID: true)
        var existingProof: Data?, previousProof: Data?, recoveryNeeded = false
        if hasNamespace {
            let existing = try InstallationRootBinding.receiptDirectory(create: false)
            defer { Darwin.close(existing) }
            let names = try InstallerPayloadIO.contents(existing)
            if names == [InstallationRootBinding.receiptName]
                || names == [InstallationRootBinding.receiptName, InstallationRootBinding.pendingRecoveryName] {
                previousProof = try InstallationRootBinding.readOriginalSupplement(existing)
                do {
                    try InstallationRootBinding.validateSupplement(previousProof!, legacy: legacy, current: current)
                    existingProof = previousProof
                } catch {
                    try InstallationRootBinding.requireRecoveryReplacement(previous: previousProof!, legacy: legacy, current: current)
                    existingProof = previousProof
                    recoveryNeeded = true
                }
            } else if names == [InstallationRootBinding.receiptName, InstallationRootBinding.recoveryName] {
                previousProof = try InstallationRootBinding.readOriginalSupplement(existing)
                existingProof = try InstallationRootBinding.readSupplement(existing)
                try InstallationRootBinding.validateSupplement(existingProof!, legacy: legacy, current: current)
            } else {
                guard names.isSubset(of: [InstallationRootBinding.pendingName]) else { throw ComponentUpdateFailure.journal }
            }
        }
        if existingProof == nil { try InstallationRootBinding.requireDeviceOnly(legacy, current: current) }
        let brokerDirectory = try InstallerPayloadIO.directory(ComponentSource.support + "/broker", owner: 0)
        defer { Darwin.close(brokerDirectory) }
        let provisionLease = try lease(brokerDirectory, "install.lock")
        defer { Darwin.close(provisionLease) }
        try ComponentProcesses.requireOwnerClosed()
        checkpoint("protected_policies")
        let worker = try publicRead("broker/worker.json", mode: 0o644)
        let install = try publicRead("broker/install.json", mode: 0o600)
        let host = try publicRead("broker/host.json", mode: 0o644)
        let profile = try publicRead("owner.json", mode: 0o644)
        let fingerprint = try json(install.0)["payload_fingerprint"] as? String
        let updated = existingProof != nil && fingerprint == source.newFingerprint
        let activePeers = updated ? source.newPeers : source.oldPeers
        let activeManifest = updated ? source.newManifest : source.oldManifest
        let activeFingerprint = updated ? source.newFingerprint : source.oldFingerprint
        let policy = try ComponentUpdatePolicies.derive(install: install.0, host: host.0, owner: profile.0, worker: worker.0,
            oldPeers: activePeers, newPeers: activePeers, oldFingerprint: activeFingerprint,
            newFingerprint: activeFingerprint, consoleOwner: ownerUID)
        try identity(ownerUID, policy.brokerUID)
        let plist = try jobPlist(ownerGroup: ownerGroup)
        checkpoint("public_image")
        _ = try InstallerPayloadIO.installedImage(activeManifest, opaquePrivateBranches: true)
        checkpoint("installed_signatures")
        for kind in ["owner", "broker", "bootstrap"] {
            guard let peer = activePeers[kind] else { throw ComponentUpdateFailure.source }
            let path = kind == "owner" ? InstallerPayloadManifest.canonicalApplication : ComponentSource.support + "/bin/AccountAccess-" + kind
            try ComponentUpdateIdentity.verifyStatic(path: path, peer: peer, designated: nil)
        }
        checkpoint("service")
        let service = ComponentRevalidationServiceObserver(observe: {
            try ComponentCommands.launchctl(["print", "system/" + label])
        }, attest: {
            try ComponentUpdateIdentity.jobSnapshot(output: $0, allowedPeers: [activePeers["broker"]!])
        })
        try service.verify()
        let hashes = ["install": install.1.sha256, "host": host.1.sha256, "owner": profile.1.sha256,
                      "worker": worker.1.sha256, "service": plist.sha256]
        let verifyCurrent = {
            try ComponentProcesses.requireOwnerClosed()
            guard try owner().0 == ownerUID,
                  try InstallationRootBinding.readLegacy(original, ownerUID: ownerUID, manifestSHA256: source.oldManifest.sha256) == legacy,
                  try InstallationRootBinding.capture(withVolumeUUID: true) == current,
                  try publicRead("broker/worker.json", mode: 0o644).1 == worker.1,
                  try publicRead("broker/install.json", mode: 0o600).1 == install.1,
                  try publicRead("broker/host.json", mode: 0o644).1 == host.1,
                  try publicRead("owner.json", mode: 0o644).1 == profile.1,
                  try jobPlist(ownerGroup: ownerGroup) == plist else { throw ComponentUpdateFailure.base }
            try identity(ownerUID, policy.brokerUID)
            _ = try InstallerPayloadIO.installedImage(activeManifest, opaquePrivateBranches: true)
            try service.verify()
        }
        checkpoint("publish")
        try verifyCurrent()
        let bindingDirectory = try InstallationRootBinding.receiptDirectory(create: true)
        defer { Darwin.close(bindingDirectory) }
        let names = try InstallerPayloadIO.contents(bindingDirectory)
        if names == [InstallationRootBinding.receiptName, InstallationRootBinding.recoveryName] {
            let proof = try InstallationRootBinding.readSupplement(bindingDirectory)
            guard proof == existingProof else { throw ComponentUpdateFailure.base }
            try InstallationRootBinding.validateSupplement(proof, legacy: legacy, current: current)
            try verifyCurrent()
            return "ALREADY_REVALIDATED"
        }
        if recoveryNeeded {
            guard names == [InstallationRootBinding.receiptName]
                    || names == [InstallationRootBinding.receiptName, InstallationRootBinding.pendingRecoveryName],
                  let previousProof else { throw ComponentUpdateFailure.journal }
            let data = try InstallationRootBinding.recoverySupplement(legacy: legacy, previous: previousProof, current: current,
                planSHA256: source.planDigest, sourceCommit: sourceCommit, policyHashes: hashes)
            try InstallationRootBinding.prepareRecoverySupplement(bindingDirectory, data: data)
            try verifyCurrent()
            try ComponentFiles.rename(bindingDirectory, InstallationRootBinding.pendingRecoveryName,
                                      bindingDirectory, InstallationRootBinding.recoveryName, swap: false)
            try InstallationRootBinding.validateSupplement(InstallationRootBinding.readSupplement(bindingDirectory),
                                                            legacy: legacy, current: current)
            try verifyCurrent()
            checkpoint("finished")
            return "RECOVERED_ROOT"
        }
        if names == [InstallationRootBinding.receiptName] {
            let proof = try InstallationRootBinding.readSupplement(bindingDirectory)
            guard proof == existingProof else { throw ComponentUpdateFailure.base }
            try InstallationRootBinding.validateSupplement(proof, legacy: legacy, current: current)
            try verifyCurrent()
            return "ALREADY_REVALIDATED"
        }
        guard existingProof == nil, names.isSubset(of: [InstallationRootBinding.pendingName]) else { throw ComponentUpdateFailure.journal }
        let data = try InstallationRootBinding.supplement(legacy: legacy, current: current, planSHA256: source.planDigest,
            sourceCommit: sourceCommit, policyHashes: hashes)
        try InstallationRootBinding.prepareSupplement(bindingDirectory, data: data)
        try verifyCurrent()
        try ComponentFiles.rename(bindingDirectory, InstallationRootBinding.pendingName, bindingDirectory, InstallationRootBinding.receiptName, swap: false)
        try InstallationRootBinding.validateSupplement(InstallationRootBinding.readSupplement(bindingDirectory), legacy: legacy, current: current)
        try verifyCurrent()
        checkpoint("finished")
        return "REVALIDATED"
    }
    private static func jobPlist(ownerGroup: gid_t) throws -> ComponentObject {
        let fd = try InstallerPayloadIO.directory("/Library/LaunchDaemons", owner: 0)
        defer { Darwin.close(fd) }
        let (data, object) = try ComponentFiles.read(fd, label + ".plist", owner: 0, mode: 0o644)
        guard data.count <= 8192,
              let value = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw ComponentUpdateFailure.base
        }
        let support = ComponentSource.support
        let expected: [String: Any] = ["Label": label, "AssociatedBundleIdentifiers": ["com.fainir.accountaccess"],
            "ProgramArguments": [support + "/bin/AccountAccess-broker"], "UserName": "root", "GroupName": "wheel",
            "RunAtLoad": true, "KeepAlive": false, "AbandonProcessGroup": false, "ExitTimeOut": 20, "Umask": 0o077,
            "ProcessType": "Background", "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
            "MachServices": ["com.fainir.accountaccess.broker.owner": true],
            "Sockets": ["AccountAccessAgent": ["SockPathName": support + "/run/agent.sock", "SockPathOwner": 0,
                "SockPathGroup": ownerGroup, "SockPathMode": 0o660],
                "AccountAccessOwner": ["SockPathName": support + "/control/owner.sock", "SockPathOwner": 0,
                    "SockPathGroup": 0, "SockPathMode": 0o600]]]
        guard NSDictionary(dictionary: value).isEqual(to: expected),
              try publicRead("broker/service.plist", mode: 0o644).0 == data else { throw ComponentUpdateFailure.base }
        return object
    }
    private static func head(_ source: ComponentSource) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["schema": 1, "managed_by": "account-access-component-head-v1",
            "plan_sha256": source.planDigest, "base_manifest_sha256": source.oldManifest.sha256,
            "manifest_sha256": source.newManifest.sha256, "state": "public_image_verified_gui_unverified",
            "automatic_reboot_recovery": false], options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private static func staged(_ backup: Int32, slot: String, data: Data, mode: mode_t) throws -> ComponentObject {
        if let existing = try ComponentFiles.observe(backup, slot, owner: 0) {
            guard existing.sha256 == ComponentFiles.digest(data), existing.bytes == data.count,
                  existing.mode == mode else { throw ComponentUpdateFailure.journal }
            return existing
        }
        return try ComponentFiles.writeExclusive(backup, slot, data: data, owner: 0, mode: mode)
    }
    private static func object(_ value: ComponentObject, mode: mode_t, hash: String?, size: Int64?) throws {
        guard value.device >= 0, value.inode > 0, value.mode == mode,
              value.bytes >= 0, value.bytes <= ComponentFiles.maximumFile,
              value.sha256.utf8.count == 64,
              value.sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              hash == nil || value.sha256 == hash, size == nil || value.bytes == size else {
            throw ComponentUpdateFailure.journal
        }
    }
    private static func loadIntent(_ backup: Int32) throws -> ComponentTransitionIntent {
        let data = try ComponentFiles.read(backup, "intent.json", owner: 0, mode: 0o600).0
        let value = try json(data, maximum: 64 * 1024)
        let intent = try JSONDecoder().decode(ComponentTransitionIntent.self, from: data)
        // Codable's normal unknown-member tolerance is unsuitable for an
        // immutable authority record. Re-encoding must preserve every member.
        guard NSDictionary(dictionary: value).isEqual(to: try json(encoded(intent), maximum: 64 * 1024)) else {
            throw ComponentUpdateFailure.journal
        }
        return intent
    }
    private struct JobRecord: Codable {
        let schema: Int
        let planSHA256: String
        let job: ComponentJobIdentity
    }
    private struct JournalState {
        let nextEvent: Int; let nextService: Int; let nextJob: Int
        let snapshots: [ComponentJobIdentity]; let ownsDisable: Bool; let finished: Bool
    }
    private static let serviceEvents: Set<String> = ["disable_intent_prior_enabled", "disabled_confirmed",
        "disabled_quiescence_confirmed", "coherent_image_enable_intent", "canonical_job_bootstrapped_gui_unverified",
        "user_domain_bootout_intent", "user_domain_quiescence_confirmed", "user_domain_bootstrap_intent",
        "user_domain_bootstrap_confirmed"]
    private static func journalState(_ backup: Int32, operations: [ComponentOperation], source: ComponentSource,
                                     intentExists: Bool) throws -> JournalState {
        var nextEvent = 0, nextService = 0, nextJob = 0, service: [(Int, String)] = []
        var snapshots: [ComponentJobIdentity] = []
        let slots = Set(operations.map(\.slot))
        for name in try InstallerPayloadIO.contents(backup) {
            if name == "intent.json" { guard intentExists else { throw ComponentUpdateFailure.journal }; continue }
            if slots.contains(name) { continue }
            let isService = name.hasPrefix("service-"), isJob = name.hasPrefix("job-")
            let prefix = isJob ? "job-" : isService ? "service-" : "event-"
            guard name.hasPrefix(prefix), name.hasSuffix(".json"),
                  name.utf8.count == prefix.utf8.count + 4 + 5,
                  let sequence = Int(name.dropFirst(prefix.count).dropLast(5)), sequence >= 0, sequence < 10_000,
                  name == String(format: prefix + "%04d.json", sequence), intentExists else { throw ComponentUpdateFailure.journal }
            let data = try ComponentFiles.read(backup, name, owner: 0, mode: 0o600).0
            guard data.count <= 4096 else { throw ComponentUpdateFailure.journal }
            if isJob {
                nextJob = max(nextJob, sequence + 1)
                if let parsed = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
                    guard let value = parsed as? [String: Any],
                          let record = try? JSONDecoder().decode(JobRecord.self, from: data), record.schema == 1,
                          record.planSHA256 == source.planDigest,
                          NSDictionary(dictionary: value).isEqual(to: try json(encoded(record), maximum: 4096)) else {
                        throw ComponentUpdateFailure.journal
                    }
                    try ComponentUpdateIdentity.validateSnapshot(record.job)
                    snapshots.append(record.job)
                }
            } else if isService {
                nextService = max(nextService, sequence + 1)
                // Only incomplete/unparseable bounded audit writes lack
                // authority. A complete foreign record is a conflict.
                if let parsed = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
                    guard let value = parsed as? [String: Any],
                          Set(value.keys) == ["schema", "event", "plan_sha256"],
                          (try? InstallerPayloadManifest.integer(value["schema"], maximum: 1)) == 1,
                          value["plan_sha256"] as? String == source.planDigest,
                          let event = value["event"] as? String, serviceEvents.contains(event) else {
                        throw ComponentUpdateFailure.journal
                    }
                    service.append((sequence, event))
                }
            } else { nextEvent = max(nextEvent, sequence + 1) }
        }
        let ordered = service.sorted { $0.0 < $1.0 }.map(\.1)
        let finished = ordered.last == "canonical_job_bootstrapped_gui_unverified"
        let ownsDisable = !finished && ordered.contains("disable_intent_prior_enabled")
        return JournalState(nextEvent: nextEvent, nextService: nextService, nextJob: nextJob, snapshots: snapshots, ownsDisable: ownsDisable, finished: finished)
    }
    private static func serviceWriter(_ backup: Int32, source: ComponentSource, start: Int) -> (String) throws -> Void {
        var sequence = start
        return { event in
            guard serviceEvents.contains(event), sequence < 10_000 else { throw ComponentUpdateFailure.journal }
            let data = try JSONSerialization.data(withJSONObject: ["schema": 1, "event": event, "plan_sha256": source.planDigest], options: [.sortedKeys])
            _ = try ComponentFiles.writeExclusive(backup, String(format: "service-%04d.json", sequence), data: data, owner: 0, mode: 0o600)
            sequence += 1
        }
    }
    private static func jobWriter(_ backup: Int32, source: ComponentSource, start: Int) -> (ComponentJobIdentity) throws -> Void {
        var sequence = start
        return { snapshot in
            guard sequence < 10_000 else { throw ComponentUpdateFailure.journal }
            try ComponentUpdateIdentity.validateSnapshot(snapshot)
            let data = try encoded(JobRecord(schema: 1, planSHA256: source.planDigest, job: snapshot))
            _ = try ComponentFiles.writeExclusive(backup, String(format: "job-%04d.json", sequence), data: data, owner: 0, mode: 0o600)
            sequence += 1
        }
    }
    private static func originalData(_ operation: ComponentOperation, backup: Int32) throws -> Data {
        guard let before = operation.before else { throw ComponentUpdateFailure.journal }
        let (parent, name) = try target(operation)
        defer { Darwin.close(parent) }
        if try ComponentFiles.observe(parent, name, owner: 0) == before {
            return try ComponentFiles.read(parent, name, owner: 0).0
        }
        let saved = try ComponentFiles.read(backup, operation.slot, owner: 0)
        guard saved.1 == before else { throw ComponentUpdateFailure.journal }
        return saved.0
    }
    private static func assertView(_ source: ComponentSource, operations: [ComponentOperation], new: Bool) throws {
        _ = try InstallerPayloadIO.installedImage(new ? source.newManifest : source.oldManifest, opaquePrivateBranches: true)
        for operation in operations where operation.target != .image && operation.target != .head {
            let (parent, name) = try target(operation)
            defer { Darwin.close(parent) }
            guard try ComponentFiles.observe(parent, name, owner: 0) == (new ? operation.after : operation.before) else {
                throw ComponentUpdateFailure.object
            }
        }
        if !new {
            let parent = try directory(namespace, mode: 0o700)
            defer { Darwin.close(parent) }
            guard try ComponentFiles.observe(parent, "head.json", owner: 0) == nil else { throw ComponentUpdateFailure.journal }
        }
    }
    static func run(resources: Int32, planPin: String) throws -> String {
        let source = try ComponentSource.load(resources, planPin: planPin)
        guard source.oldPeers["owner"]?.team == "WBULD6N4NQ", source.newPeers["owner"] == source.oldPeers["owner"] else {
            throw ComponentUpdateFailure.source
        }
        for kind in ["broker", "bootstrap"] {
            guard let delta = source.delta.first(where: { $0.path == "bin/AccountAccess-" + kind }),
                  let peer = source.newPeers[kind], let requirement = source.designated[kind] else { throw ComponentUpdateFailure.source }
            let path = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent(delta.resource).path
            try ComponentUpdateIdentity.verifyStatic(path: path, peer: peer, designated: requirement)
        }
        let (ownerUID, ownerGroup) = try owner()
        let original = try directory(oldJournal, mode: 0o700)
        defer { Darwin.close(original) }
        let originalLease = try lease(original, "lock")
        defer { Darwin.close(originalLease) }
        try originalReceipt(original, ownerUID: ownerUID)
        let brokerDirectory = try InstallerPayloadIO.directory(ComponentSource.support + "/broker", owner: 0)
        defer { Darwin.close(brokerDirectory) }
        let provisionLease = try lease(brokerDirectory, "install.lock")
        defer { Darwin.close(provisionLease) }
        try ComponentProcesses.requireOwnerClosed()
        let worker = try publicRead("broker/worker.json", mode: 0o644)
        let plist = try jobPlist(ownerGroup: ownerGroup)
        let library = try InstallerPayloadIO.directory("/Library/Application Support", owner: 0)
        defer { Darwin.close(library) }
        let components = try child(library, "Account Access Components", create: true)
        defer { Darwin.close(components) }
        let transitionName = "transition-" + source.planDigest
        var modes: [String: mode_t] = [:]
        for (index, delta) in source.delta.enumerated() { modes[String(format: "slot-%02d", index)] = delta.after.mode! }
        for (index, entry) in dynamic.enumerated() { modes[String(format: "slot-%02d", source.delta.count + index)] = entry.2 }
        let hasIntent = try InstallerPayloadIO.contents(components).contains(transitionName)
        var reserve: Int64 = 0
        if !hasIntent {
            reserve = 81_920 // Four 4096-byte policy slots plus a 64 KiB intent.
            for delta in source.delta {
                let itemBytes = Int64(delta.data.count)
                let addition = reserve.addingReportingOverflow(itemBytes)
                guard !addition.overflow else { throw ComponentUpdateFailure.unavailable }
                reserve = addition.partialValue
            }
        }
        let orphans = try ComponentPreparation.retained(components, plan: source.planDigest, slots: modes, owner: 0, reserve: reserve)
        let preparingName: String?
        let backup: Int32
        if hasIntent {
            preparingName = nil
            backup = try child(components, transitionName, create: false)
        } else {
            guard orphans < 8, try ComponentFiles.observe(components, "head.json", owner: 0) == nil else {
                throw ComponentUpdateFailure.journal
            }
            let installedRoot = try InstallerPayloadIO.directory(ComponentSource.support, owner: 0)
            defer { Darwin.close(installedRoot) }
            try ComponentPreparation.capacity(components, bytes: reserve + 2 * 1024 * 1024, owner: 0, sameDeviceAs: installedRoot)
            let preparation = try ComponentPreparation.begin(components, plan: source.planDigest, owner: 0)
            preparingName = preparation.0; backup = preparation.1
        }
        defer { Darwin.close(backup) }
        let intent: ComponentTransitionIntent
        if hasIntent { intent = try loadIntent(backup) }
        else {
            _ = try InstallerPayloadIO.installedImage(source.oldManifest, opaquePrivateBranches: true)
            guard try ComponentFiles.observe(components, "head.json", owner: 0) == nil else { throw ComponentUpdateFailure.journal }
            let install = try publicRead("broker/install.json", mode: 0o600)
            let host = try publicRead("broker/host.json", mode: 0o644)
            let profile = try publicRead("owner.json", mode: 0o644)
            let policy = try ComponentUpdatePolicies.derive(install: install.0, host: host.0, owner: profile.0, worker: worker.0,
                oldPeers: source.oldPeers, newPeers: source.newPeers, oldFingerprint: source.oldFingerprint,
                newFingerprint: source.newFingerprint, consoleOwner: ownerUID)
            try identity(ownerUID, policy.brokerUID)
            let observed = try ComponentCommands.launchctl(["print", "system/" + label])
            guard observed.status == 0 else { throw ComponentUpdateFailure.base }
            let snapshot = try ComponentUpdateIdentity.jobSnapshot(output: observed.output, allowedPeers: [source.oldPeers["broker"]!])
            var operations: [ComponentOperation] = []
            for delta in source.delta {
                let op = ComponentOperation(target: .image, path: delta.path, slot: String(format: "slot-%02d", operations.count), before: nil,
                    after: ComponentObject(device: 0, inode: 0, mode: 0, bytes: 0, sha256: ""))
                let (parent, name) = try target(op)
                defer { Darwin.close(parent) }
                let before = try ComponentFiles.observe(parent, name, owner: 0)
                if let expected = delta.before {
                    guard let before else { throw ComponentUpdateFailure.base }
                    try object(before, mode: expected.mode!, hash: expected.sha256, size: expected.size)
                } else { guard before == nil else { throw ComponentUpdateFailure.base } }
                let slot = String(format: "slot-%02d", operations.count)
                let after = try staged(backup, slot: slot, data: delta.data, mode: delta.after.mode!)
                operations.append(ComponentOperation(target: .image, path: delta.path, slot: slot, before: before, after: after))
            }
            for (index, entry) in dynamic.enumerated() {
                let data = try [policy.host, policy.owner, policy.install, head(source)][index]
                let before = [host.1, profile.1, install.1, nil][index]
                let slot = String(format: "slot-%02d", operations.count)
                let after = try staged(backup, slot: slot, data: data, mode: entry.2)
                operations.append(ComponentOperation(target: entry.0, path: entry.1, slot: slot, before: before, after: after))
            }
            guard Set(try InstallerPayloadIO.contents(backup)) == Set(operations.map(\.slot)) else { throw ComponentUpdateFailure.journal }
            intent = ComponentTransitionIntent(schema: 1, planSHA256: source.planDigest,
                baseManifestSHA256: source.oldManifest.sha256, targetManifestSHA256: source.newManifest.sha256,
                operations: operations, ownerUID: ownerUID, brokerUID: policy.brokerUID, service: snapshot,
                workerPolicy: worker.1, servicePlist: plist, automaticRebootRecovery: false)
            _ = try ComponentFiles.writeExclusive(backup, "intent.json", data: encoded(intent), owner: 0, mode: 0o600)
            guard let preparingName else { throw ComponentUpdateFailure.journal }
            try ComponentPreparation.publish(components, name: preparingName, directory: backup, plan: source.planDigest, owner: 0)
        }
        guard intent.schema == 1, intent.planSHA256 == source.planDigest,
              intent.baseManifestSHA256 == source.oldManifest.sha256, intent.targetManifestSHA256 == source.newManifest.sha256,
              !intent.automaticRebootRecovery, intent.ownerUID == ownerUID, intent.workerPolicy == worker.1,
              intent.servicePlist == plist, intent.operations.count == source.delta.count + dynamic.count else {
            throw ComponentUpdateFailure.journal
        }
        try identity(ownerUID, intent.brokerUID)
        if let snapshot = intent.service { try ComponentUpdateIdentity.validateSnapshot(snapshot) }
        var device: Int32?
        for (index, operation) in intent.operations.enumerated() {
            guard operation.slot == String(format: "slot-%02d", index) else { throw ComponentUpdateFailure.journal }
            if index < source.delta.count {
                let delta = source.delta[index]
                guard operation.target == .image, operation.path == delta.path,
                      (operation.before == nil) == (delta.before == nil) else { throw ComponentUpdateFailure.journal }
                try object(operation.after, mode: delta.after.mode!, hash: delta.after.sha256, size: delta.after.size)
                if let before = operation.before, let node = delta.before {
                    try object(before, mode: node.mode!, hash: node.sha256, size: node.size)
                }
            } else {
                let entry = dynamic[index - source.delta.count]
                guard operation.target == entry.0, operation.path == entry.1,
                      (operation.before == nil) == (entry.0 == .head) else { throw ComponentUpdateFailure.journal }
                try object(operation.after, mode: entry.2, hash: nil, size: nil)
                if let before = operation.before { try object(before, mode: entry.2, hash: nil, size: nil) }
            }
            if device == nil { device = operation.after.device }
            guard operation.after.device == device, operation.before == nil || operation.before?.device == device else {
                throw ComponentUpdateFailure.journal
            }
        }
        let state = try journalState(backup, operations: intent.operations, source: source, intentExists: true)
        let installOp = intent.operations[source.delta.count + 2]
        let hostOp = intent.operations[source.delta.count]
        let ownerOp = intent.operations[source.delta.count + 1]
        let policy = try ComponentUpdatePolicies.derive(install: originalData(installOp, backup: backup),
            host: originalData(hostOp, backup: backup), owner: originalData(ownerOp, backup: backup), worker: worker.0,
            oldPeers: source.oldPeers, newPeers: source.newPeers, oldFingerprint: source.oldFingerprint,
            newFingerprint: source.newFingerprint, consoleOwner: ownerUID)
        guard policy.brokerUID == intent.brokerUID else { throw ComponentUpdateFailure.journal }
        let expectedDynamic = try [policy.host, policy.owner, policy.install, head(source)]
        for (index, data) in expectedDynamic.enumerated() {
            let operation = intent.operations[source.delta.count + index]
            guard operation.after.sha256 == ComponentFiles.digest(data), operation.after.bytes == data.count else {
                throw ComponentUpdateFailure.journal
            }
        }
        let verifyUnchanged = {
            guard try publicRead("broker/worker.json", mode: 0o644).1 == intent.workerPolicy,
                  try jobPlist(ownerGroup: ownerGroup) == intent.servicePlist,
                  try owner().0 == ownerUID else { throw ComponentUpdateFailure.object }
            try originalReceipt(original, ownerUID: ownerUID)
        }
        let storage = ComponentFileTransaction(operations: intent.operations, backup: backup, owner: 0, nextEvent: state.nextEvent,
            target: target, verifyOld: {
                try verifyUnchanged(); try assertView(source, operations: intent.operations, new: false)
            }, verifyRecoverable: {
                try verifyUnchanged()
                try ComponentViews.verifyRecoverableBase(source.oldManifest, operations: intent.operations, owner: 0)
                let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard root >= 0 else { throw ComponentUpdateFailure.object }
                defer { Darwin.close(root) }
                _ = try InstallerPayloadIO.verifyApplicationAlias(from: root, owner: 0)
            }, verifyNew: {
                try verifyUnchanged(); try assertView(source, operations: intent.operations, new: true)
            })
        // Every actual slot/target state is checked before service mutation.
        try storage.verifyRecoverableView()
        let headOperation = intent.operations.last!
        if try storage.state(headOperation) == .applied {
            for operation in intent.operations {
                guard try storage.state(operation) == .applied else { throw ComponentUpdateFailure.journal }
            }
            try storage.verifyNewView()
            if state.finished { return "ALREADY_UPDATED_GUI_UNVERIFIED" }
        }
        let installedRoot = try InstallerPayloadIO.directory(ComponentSource.support, owner: 0)
        defer { Darwin.close(installedRoot) }
        try ComponentPreparation.capacity(components, bytes: 2 * 1024 * 1024, owner: 0, sameDeviceAs: installedRoot)
        let barrier = ComponentLaunchdBarrier(brokerUID: intent.brokerUID, recoveringIntent: state.ownsDisable,
            snapshots: (intent.service.map { [$0] } ?? []) + state.snapshots,
            peers: [source.oldPeers["broker"]!, source.newPeers["broker"]!],
            recordSnapshot: jobWriter(backup, source: source, start: state.nextJob),
            record: serviceWriter(backup, source: source, start: state.nextService))
        _ = try ComponentTransition(storage: storage, service: barrier).run(recovering: hasIntent)
        return "UPDATED_GUI_UNVERIFIED"
    }
}

#if ACCOUNT_ACCESS_COMPONENT_UPDATE_MAIN
@main struct ComponentUpdateMain {
    static func main() {
        // No filesystem access occurs in the ordinary-user refusal path.
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 1 else {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"component_update_context_required\"}")
            exit(78)
        }
        do {
            guard CommandLine.arguments[0].hasPrefix("/"), CommandLine.arguments[0].hasSuffix("/AccountAccess-componentupdate") else {
                throw ComponentUpdateFailure.context
            }
            umask(0o077)
            try ComponentUpdateIdentity.verifySelf(team: "WBULD6N4NQ")
            let resources = try InstallerPayloadIO.directory(URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path,
                owner: 0, installerResources: true)
            defer { Darwin.close(resources) }
            let result = try ComponentController.run(resources: resources, planPin: ComponentUpdateCompiledPins.planSHA256)
            print("{\"schema\":1,\"status\":\"" + result + "\",\"gui_verified\":false,\"account_qa_verified\":false}")
        } catch {
            let reason = (error as? ComponentUpdateFailure)?.rawValue ?? ComponentUpdateFailure.unavailable.rawValue
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"" + reason + "\"}")
            exit(78)
        }
    }
}
#endif
