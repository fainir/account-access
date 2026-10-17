// Publish one freshly initialized store, preserving both directories. The
// hosting daemon must separately authorize initial key enrollment and clients.
import Foundation
import Darwin

enum RootPublicationFailure: String, Error {
    case busy = "vault_publication_busy"
    case unsafeState = "vault_publication_unsafe_state"
    case notVerified = "vault_publication_requires_verified_stage"
    case unavailable = "vault_publication_unavailable"
}

final class RootStorePublication {
    private struct Identity: Equatable, Codable {
        let device: Int64
        let inode: UInt64
        init(_ info: stat) { device = Int64(info.st_dev); inode = UInt64(info.st_ino) }
    }
    private struct Record: Codable, Equatable {
        let schema: Int
        let vault: String
        let enrollment: String
        let stage: String
        let destination: String
        let uid: UInt32
        let gid: UInt32
        let stagedIdentity: Identity
        let emptyIdentity: Identity
    }
    private let plan: MacWorkerEnrollmentPlan
    private let destination: String
    private let stageName: String
    private let destinationName: String
    private let record: Record
    private var parentFD: Int32 = -1
    private var lockFD: Int32 = -1
    private var journalFD: Int32 = -1
    private let stateLock = NSLock()
    private static let marker = Data("account-access-publication-ready-v1\n".utf8)

    init(policy: String) throws {
        try RootVaultKeyStore.requireDaemon()
        plan = try MacWorkerEnrollmentPlan(policy: policy, requireEmptyStage: false)
        let configuration = try WorkerLaunchPaths.object(plan.base.workerPolicy)
        destination = try WorkerLaunchPaths.lexical(configuration["root"])
        stageName = URL(fileURLWithPath: plan.stage).lastPathComponent
        destinationName = URL(fileURLWithPath: destination).lastPathComponent
        let parent = try WorkerLaunchPaths.protected(URL(fileURLWithPath: destination).deletingLastPathComponent().path)
        guard parent == URL(fileURLWithPath: plan.stage).deletingLastPathComponent(),
              ![".", "..", ""].contains(destinationName), stageName != destinationName else {
            throw RootPublicationFailure.unsafeState
        }
        // Initialize the immutable record only after acquiring the shared
        // parent lock. No root-owned control data is placed inside the vault.
        let parentHandle = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentHandle >= 0 else { throw RootPublicationFailure.unavailable }
        var lockHandle: Int32 = -1, journalHandle: Int32 = -1
        var success = false
        defer {
            if !success {
                if journalHandle >= 0 { Darwin.close(journalHandle) }
                if lockHandle >= 0 { Darwin.close(lockHandle) }
                Darwin.close(parentHandle)
            }
        }
        lockHandle = openat(parentHandle, ".account-access-enrollment.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lockHandle >= 0 else { throw RootPublicationFailure.unavailable }
        try Self.privateRootFile(lockHandle)
        guard flock(lockHandle, LOCK_EX | LOCK_NB) == 0 else { throw RootPublicationFailure.busy }
        let journalName = ".enrollment-" + plan.enrollment + ".publication"
        let created = mkdirat(parentHandle, journalName, 0o700) == 0
        guard created || errno == EEXIST else { throw RootPublicationFailure.unavailable }
        journalHandle = openat(parentHandle, journalName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var journalInfo = stat()
        guard journalHandle >= 0, fstat(journalHandle, &journalInfo) == 0,
              journalInfo.st_uid == 0, journalInfo.st_mode & 0o7777 == 0o700 else {
            throw RootPublicationFailure.unsafeState
        }
        let stageInfo = try Self.directory(parentHandle, stageName, uid: plan.base.uid, gid: plan.base.gid)
        let destinationInfo = try Self.directory(parentHandle, destinationName, uid: plan.base.uid, gid: plan.base.gid)
        guard stageInfo.st_dev == destinationInfo.st_dev else { throw RootPublicationFailure.unsafeState }
        if created {
            guard try FileManager.default.contentsOfDirectory(atPath: destination).isEmpty,
                  try FileManager.default.contentsOfDirectory(atPath: plan.stage).isEmpty else {
                throw RootPublicationFailure.unsafeState
            }
            record = Record(schema: 1, vault: plan.vault, enrollment: plan.enrollment, stage: stageName,
                destination: destinationName, uid: plan.base.uid, gid: plan.base.gid,
                stagedIdentity: Identity(stageInfo), emptyIdentity: Identity(destinationInfo))
            try Self.create(journalHandle, "plan.json", data: JSONEncoder().encode(record))
            guard fsync(journalHandle) == 0, fsync(parentHandle) == 0 else { throw RootPublicationFailure.unavailable }
        } else {
            let data = try Self.read(journalHandle, "plan.json")
            guard let value = try? JSONDecoder().decode(Record.self, from: data),
                  let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(raw.keys) == ["schema", "vault", "enrollment", "stage", "destination", "uid", "gid", "stagedIdentity", "emptyIdentity"],
                  value.schema == 1, value.vault == plan.vault, value.enrollment == plan.enrollment,
                  value.stage == stageName, value.destination == destinationName,
                  value.uid == plan.base.uid, value.gid == plan.base.gid,
                  value.stagedIdentity != value.emptyIdentity else { throw RootPublicationFailure.unsafeState }
            record = value
        }
        parentFD = parentHandle; lockFD = lockHandle; journalFD = journalHandle
        success = true
    }

    private static func privateRootFile(_ fd: Int32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o7777 == 0o600, info.st_nlink == 1, info.st_size <= 4096 else {
            throw RootPublicationFailure.unsafeState
        }
    }
    private static func directory(_ parent: Int32, _ name: String, uid: uid_t, gid: gid_t) throws -> stat {
        var info = stat()
        guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == uid, info.st_gid == gid, info.st_mode & 0o7777 == 0o700 else {
            throw RootPublicationFailure.unsafeState
        }
        return info
    }
    private static func create(_ directory: Int32, _ name: String, data: Data) throws {
        guard data.count <= 4096 else { throw RootPublicationFailure.unsafeState }
        let fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw RootPublicationFailure.unavailable }
        defer { Darwin.close(fd) }
        try privateRootFile(fd)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { throw RootPublicationFailure.unavailable }
                offset += written
            }
        }
        guard fsync(fd) == 0, fsync(directory) == 0 else { throw RootPublicationFailure.unavailable }
    }
    private static func read(_ directory: Int32, _ name: String) throws -> Data {
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RootPublicationFailure.unsafeState }
        defer { Darwin.close(fd) }
        try privateRootFile(fd)
        var result = Data(), buffer = [UInt8](repeating: 0, count: 4097)
        while result.count <= 4096 {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RootPublicationFailure.unavailable }
            if count == 0 { return result }
            result.append(contentsOf: buffer.prefix(count))
        }
        throw RootPublicationFailure.unsafeState
    }
    private func ready() throws -> Bool {
        var info = stat()
        if fstatat(journalFD, "ready", &info, AT_SYMLINK_NOFOLLOW) == -1 {
            guard errno == ENOENT else { throw RootPublicationFailure.unsafeState }
            return false
        }
        guard try Self.read(journalFD, "ready") == Self.marker else { throw RootPublicationFailure.unsafeState }
        return true
    }
    private func swapped() throws -> Bool {
        let stage = Identity(try Self.directory(parentFD, stageName, uid: plan.base.uid, gid: plan.base.gid))
        let destination = Identity(try Self.directory(parentFD, destinationName, uid: plan.base.uid, gid: plan.base.gid))
        if stage == record.stagedIdentity && destination == record.emptyIdentity { return false }
        guard stage == record.emptyIdentity, destination == record.stagedIdentity,
              try ready() else { throw RootPublicationFailure.unsafeState }
        return true
    }
    func accept(_ receipt: VerifiedStagedVault) throws {
        try RootVaultKeyStore.requireDaemon()
        stateLock.lock(); defer { stateLock.unlock() }
        guard receipt.vault == plan.vault, receipt.enrollment == plan.enrollment, receipt.path == plan.stage,
              Int64(receipt.device) == record.stagedIdentity.device, UInt64(receipt.inode) == record.stagedIdentity.inode,
              try !swapped() else { throw RootPublicationFailure.notVerified }
        if try !ready() { try Self.create(journalFD, "ready", data: Self.marker) }
    }
    func publish() throws {
        try RootVaultKeyStore.requireDaemon()
        stateLock.lock(); defer { stateLock.unlock() }
        guard try ready() else { throw RootPublicationFailure.notVerified }
        if try !swapped() {
            guard try FileManager.default.contentsOfDirectory(atPath: destination).isEmpty else {
                throw RootPublicationFailure.unsafeState
            }
            // Same protected parent, fixed leaf names, both original inodes.
            // Unsupported filesystems stop here; there is no destructive rename
            // fallback and the old empty destination remains at the stage name.
            guard renameatx_np(parentFD, stageName, parentFD, destinationName, UInt32(RENAME_SWAP)) == 0 else {
                throw RootPublicationFailure.unavailable
            }
        }
        guard fsync(parentFD) == 0, try swapped() else { throw RootPublicationFailure.unavailable }
    }
    deinit {
        if journalFD >= 0 { Darwin.close(journalFD) }
        if lockFD >= 0 { Darwin.close(lockFD) }
        if parentFD >= 0 { Darwin.close(parentFD) }
    }
}
