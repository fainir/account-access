// Publish one freshly initialized store, preserving both directories. The
// hosting daemon must separately authorize initial key enrollment and clients.
import Foundation
import Darwin

enum RootPublicationFailure: String, Error {
    case busy = "vault_publication_busy"
    case unsafeState = "vault_publication_unsafe_state"
    case identityMismatch = "vault_publication_directory_identity_mismatch"
    case deviceChanged = "vault_publication_device_number_changed"
    case notVerified = "vault_publication_requires_verified_stage"
    case unavailable = "vault_publication_unavailable"
}

enum RootPublicationPhase { case empty, incomplete, ready, published }

struct RootPublicationIdentity: Equatable, Codable {
    let device: Int64
    let inode: UInt64
    init(device: Int64, inode: UInt64) { self.device = device; self.inode = inode }
    init(_ info: stat) { device = Int64(info.st_dev); inode = UInt64(info.st_ino) }
}

enum RootPublicationDirectoryOrder {
    static func published(stage: RootPublicationIdentity, destination: RootPublicationIdentity,
                          originalStage: RootPublicationIdentity, originalEmpty: RootPublicationIdentity) throws -> Bool {
        if stage == originalStage && destination == originalEmpty { return false }
        if stage == originalEmpty && destination == originalStage { return true }
        // This is a diagnostic distinction only. A changed mount-device number
        // remains refused; matching inodes alone never authorize opening data.
        if originalStage.device == originalEmpty.device, stage.device == destination.device,
           stage.device != originalStage.device,
           (stage.inode == originalStage.inode && destination.inode == originalEmpty.inode
            || stage.inode == originalEmpty.inode && destination.inode == originalStage.inode) {
            throw RootPublicationFailure.deviceChanged
        }
        throw RootPublicationFailure.identityMismatch
    }
}

final class RootStorePublication {
    private typealias Identity = RootPublicationIdentity
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
    private let parentPath: String
    private let journalName: String
    private let record: Record
    private let recordData: Data
    private let volumeData: Data?
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
        parentPath = parent.path
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
        journalName = ".enrollment-" + plan.enrollment + ".publication"
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
            recordData = try JSONEncoder().encode(record)
            try Self.create(journalHandle, "plan.json", data: recordData)
            guard fsync(journalHandle) == 0, fsync(parentHandle) == 0 else { throw RootPublicationFailure.unavailable }
        } else {
            let data = try Self.read(journalHandle, "plan.json")
            guard let value = try? JSONDecoder().decode(Record.self, from: data),
                  let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(raw.keys) == ["schema", "vault", "enrollment", "stage", "destination", "uid", "gid", "stagedIdentity", "emptyIdentity"],
                  value.schema == 1, value.vault == plan.vault, value.enrollment == plan.enrollment,
                  value.stage == stageName, value.destination == destinationName,
                  value.uid == plan.base.uid, value.gid == plan.base.gid,
                  value.stagedIdentity.device >= 0,
                  value.stagedIdentity.device == value.emptyIdentity.device,
                  value.stagedIdentity.inode > 0, value.emptyIdentity.inode > 0,
                  value.stagedIdentity.inode != value.emptyIdentity.inode else { throw RootPublicationFailure.unsafeState }
            record = value
            recordData = data
        }
        let context = try RootStoreVolumeBinding.capture(parentHandle)
        guard Int64(stageInfo.st_dev) == context.device, Int64(destinationInfo.st_dev) == context.device else {
            throw RootPublicationFailure.unsafeState
        }
        var bindingInfo = stat()
        if fstatat(journalHandle, RootStoreVolumeBinding.name, &bindingInfo, AT_SYMLINK_NOFOLLOW) == 0 {
            let data = try Self.read(journalHandle, RootStoreVolumeBinding.name)
            _ = try RootStoreVolumeBinding.decode(data, record: recordData, context: context)
            volumeData = data
        } else {
            guard errno == ENOENT else { throw RootPublicationFailure.unsafeState }
            let sameEpoch = record.stagedIdentity.device == context.device && record.emptyIdentity.device == context.device
            let exactPair = (Identity(stageInfo) == record.stagedIdentity && Identity(destinationInfo) == record.emptyIdentity)
                || (Identity(stageInfo) == record.emptyIdentity && Identity(destinationInfo) == record.stagedIdentity)
            if sameEpoch && exactPair {
                // Enroll persistent identity only while the original device and
                // both directory identities are still exact. An already changed
                // legacy record requires a separately reviewed migration proof.
                let data = try RootStoreVolumeBinding(record: recordData, context: context).encoded()
                let savedRecord = recordData
                let savedJournalName = journalName, savedStageName = stageName, savedDestinationName = destinationName
                let savedUID = plan.base.uid, savedGID = plan.base.gid
                try RootStoreVolumePublication.publish(directory: journalHandle, data: data, verify: {
                    var heldParent = stat(), attachedParent = stat(), heldJournal = stat(), attachedJournal = stat()
                    var heldLock = stat(), attachedLock = stat()
                    guard try WorkerLaunchPaths.protected(parent.path) == parent,
                          fstat(parentHandle, &heldParent) == 0, lstat(parent.path, &attachedParent) == 0,
                          heldParent.st_dev == attachedParent.st_dev, heldParent.st_ino == attachedParent.st_ino,
                          fstat(journalHandle, &heldJournal) == 0,
                          fstatat(parentHandle, savedJournalName, &attachedJournal, AT_SYMLINK_NOFOLLOW) == 0,
                          heldJournal.st_dev == attachedJournal.st_dev, heldJournal.st_ino == attachedJournal.st_ino,
                          fstat(lockHandle, &heldLock) == 0,
                          fstatat(parentHandle, ".account-access-enrollment.lock", &attachedLock, AT_SYMLINK_NOFOLLOW) == 0,
                          heldLock.st_dev == attachedLock.st_dev, heldLock.st_ino == attachedLock.st_ino,
                          try Self.read(journalHandle, "plan.json") == savedRecord,
                          try RootStoreVolumeBinding.capture(parentHandle) == context,
                          Identity(try Self.directory(parentHandle, savedStageName, uid: savedUID, gid: savedGID)) == Identity(stageInfo),
                          Identity(try Self.directory(parentHandle, savedDestinationName, uid: savedUID, gid: savedGID)) == Identity(destinationInfo) else {
                        throw RootStoreVolumeFailure.changed
                    }
                    try Self.noACL(parentHandle); try Self.noACL(journalHandle); try Self.privateRootFile(lockHandle)
                })
                volumeData = data
            } else { volumeData = nil }
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
        try noACL(fd)
    }
    private static func noACL(_ fd: Int32) throws {
        errno = 0
        guard let acl = acl_get_fd(fd) else {
            guard errno == ENOENT else { throw RootPublicationFailure.unsafeState }; return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) != 0, errno == EINVAL else {
            throw RootPublicationFailure.unsafeState
        }
    }
    private func currentIdentities() throws -> (Identity, Identity) {
        guard try WorkerLaunchPaths.protected(parentPath).path == parentPath else { throw RootPublicationFailure.unsafeState }
        var parent = stat(), path = stat(), journal = stat(), journalPath = stat()
        guard fstat(parentFD, &parent) == 0, lstat(parentPath, &path) == 0,
              parent.st_uid == 0, parent.st_mode & S_IFMT == S_IFDIR, parent.st_mode & 0o7022 == 0,
              parent.st_dev == path.st_dev, parent.st_ino == path.st_ino,
              parent.st_uid == path.st_uid, parent.st_mode == path.st_mode,
              fstat(journalFD, &journal) == 0,
              fstatat(parentFD, journalName, &journalPath, AT_SYMLINK_NOFOLLOW) == 0,
              journal.st_uid == 0, journal.st_mode & 0o7777 == 0o700,
              journal.st_dev == parent.st_dev, journal.st_dev == journalPath.st_dev,
              journal.st_ino == journalPath.st_ino, journal.st_uid == journalPath.st_uid,
              journal.st_mode == journalPath.st_mode,
              try Self.read(journalFD, "plan.json") == recordData else { throw RootPublicationFailure.unsafeState }
        try Self.noACL(parentFD); try Self.noACL(journalFD)
        let context = try RootStoreVolumeBinding.capture(parentFD)
        if let volumeData {
            guard try Self.read(journalFD, RootStoreVolumeBinding.name) == volumeData else {
                throw RootStoreVolumeFailure.changed
            }
            _ = try RootStoreVolumeBinding.decode(volumeData, record: recordData, context: context)
            return (Identity(device: context.device, inode: record.stagedIdentity.inode),
                    Identity(device: context.device, inode: record.emptyIdentity.inode))
        }
        var missing = stat()
        guard fstatat(journalFD, RootStoreVolumeBinding.name, &missing, AT_SYMLINK_NOFOLLOW) == -1,
              errno == ENOENT else { throw RootStoreVolumeFailure.changed }
        return (record.stagedIdentity, record.emptyIdentity)
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
        let originals = try currentIdentities()
        let stage = Identity(try Self.directory(parentFD, stageName, uid: plan.base.uid, gid: plan.base.gid))
        let destination = Identity(try Self.directory(parentFD, destinationName, uid: plan.base.uid, gid: plan.base.gid))
        guard try RootPublicationDirectoryOrder.published(stage: stage, destination: destination,
            originalStage: originals.0, originalEmpty: originals.1) else { return false }
        guard try ready() else { throw RootPublicationFailure.unsafeState }
        return true
    }
    private func marker(_ name: String, equals data: Data) throws -> Bool {
        var info = stat()
        if fstatat(journalFD, name, &info, AT_SYMLINK_NOFOLLOW) == -1 {
            guard errno == ENOENT else { throw RootPublicationFailure.unsafeState }
            return false
        }
        guard try Self.read(journalFD, name) == data else { throw RootPublicationFailure.unsafeState }
        return true
    }
    private func authorizationData(_ owner: uid_t) throws -> Data {
        guard owner == plan.base.agentUID else { throw RootPublicationFailure.unsafeState }
        return try JSONSerialization.data(withJSONObject: ["schema": 1, "owner_uid": Int(owner)], options: .sortedKeys)
    }
    func isAuthorized(owner: uid_t) throws -> Bool {
        try RootVaultKeyStore.requireDaemon()
        stateLock.lock(); defer { stateLock.unlock() }
        return try marker("authorized", equals: authorizationData(owner))
    }
    func authorize(_ approval: OwnerEnrollmentApproval, owner: uid_t) throws {
        try RootVaultKeyStore.requireDaemon()
        stateLock.lock(); defer { stateLock.unlock() }
        let data = try authorizationData(owner)
        if try !marker("authorized", equals: data) { try Self.create(journalFD, "authorized", data: data) }
    }
    func isPaused() throws -> Bool {
        try RootVaultKeyStore.requireDaemon()
        stateLock.lock(); defer { stateLock.unlock() }
        return try marker("paused", equals: Data("paused\n".utf8))
    }
    func pause() throws {
        try RootVaultKeyStore.requireDaemon()
        stateLock.lock(); defer { stateLock.unlock() }
        let data = Data("paused\n".utf8)
        if try !marker("paused", equals: data) { try Self.create(journalFD, "paused", data: data) }
    }
    func resume(_ approval: OwnerEnrollmentApproval) throws {
        try RootVaultKeyStore.requireDaemon()
        stateLock.lock(); defer { stateLock.unlock() }
        if try marker("paused", equals: Data("paused\n".utf8)) {
            guard unlinkat(journalFD, "paused", 0) == 0, fsync(journalFD) == 0 else { throw RootPublicationFailure.unavailable }
        }
    }
    func phase() throws -> RootPublicationPhase {
        try RootVaultKeyStore.requireDaemon()
        stateLock.lock(); defer { stateLock.unlock() }
        if try swapped() { return .published }
        guard try FileManager.default.contentsOfDirectory(atPath: destination).isEmpty else { throw RootPublicationFailure.unsafeState }
        if try ready() { return .ready }
        return try FileManager.default.contentsOfDirectory(atPath: plan.stage).isEmpty ? .empty : .incomplete
    }
    func accept(_ receipt: VerifiedStagedVault) throws {
        try RootVaultKeyStore.requireDaemon()
        stateLock.lock(); defer { stateLock.unlock() }
        let originals = try currentIdentities()
        guard receipt.vault == plan.vault, receipt.enrollment == plan.enrollment, receipt.path == plan.stage,
              Int64(receipt.device) == originals.0.device, UInt64(receipt.inode) == originals.0.inode,
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
