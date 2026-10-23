// Installed metadata adapter, deliberately without an entrypoint. A qualified
// successor updater holds maintenance locks and disables/quiesces the broker.
// Store directories are statted only; credential files are never opened.
import Foundation
import Darwin

final class StoreVolumeMigration {
    private final class Directory {
        let path: String, fd: Int32, identity: stat
        init(_ path: String, mode: mode_t? = nil) throws {
            self.path = path
            let opened = try InstallerPayloadIO.directory(path, owner: 0)
            do {
                let info = try InstallerPayloadIO.check(opened, owner: 0, directory: true)
                try InstallationRootBinding.noACL(opened)
                guard mode == nil || info.st_mode & 0o7777 == mode else { throw ComponentUpdateFailure.object }
                fd = opened; identity = info
            } catch { Darwin.close(opened); throw error }
        }
        func verify() throws {
            let current = try InstallerPayloadIO.directory(path, owner: 0)
            defer { Darwin.close(current) }
            try InstallationRootBinding.noACL(fd); try InstallationRootBinding.noACL(current)
            for handle in [fd, current] {
                let info = try InstallerPayloadIO.check(handle, owner: 0, directory: true)
                guard info.st_dev == identity.st_dev, info.st_ino == identity.st_ino,
                      info.st_uid == identity.st_uid, info.st_gid == identity.st_gid,
                      info.st_mode == identity.st_mode, info.st_nlink > 0 else { throw ComponentUpdateFailure.object }
            }
        }
        func read(_ name: String, mode: mode_t = 0o600, maximum: Int = 8192) throws -> Data {
            try ComponentFiles.name(name); try verify()
            let file = openat(fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard file >= 0 else { throw ComponentUpdateFailure.object }; defer { Darwin.close(file) }
            let before = try InstallerPayloadIO.check(file, owner: 0, directory: false)
            try InstallationRootBinding.noACL(file)
            guard before.st_mode & 0o7777 == mode else { throw ComponentUpdateFailure.object }
            let data = try InstallerPayloadIO.read(file, maximum: maximum, owner: 0)
            var path = stat()
            guard fstatat(fd, name, &path, AT_SYMLINK_NOFOLLOW) == 0,
                  InstallerPayloadIO.same(before, path) else { throw ComponentUpdateFailure.object }
            try verify(); return data
        }
        deinit { Darwin.close(fd) }
    }
    private let support: Directory, parent: Directory, journal: Directory, original: Directory
    private let volume: Directory, broker: Directory, services: Directory
    private var lock: Int32 = -1
    private let lockIdentity: stat
    private let ownerUID: uid_t, brokerUID: uid_t
    private let vaultID: String, enrollmentID: String
    private let requireQuiescent: () throws -> Void
    private var captured: StoreVolumeMigrationAuthority?

    private init(ownerUID: uid_t, brokerUID: uid_t, vaultID: String, enrollmentID: String,
                 requireQuiescent: @escaping () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0,
              let enrollment = UUID(uuidString: enrollmentID), enrollment.uuidString.lowercased() == enrollmentID else {
            throw ComponentUpdateFailure.context
        }
        try requireQuiescent()
        self.ownerUID = ownerUID; self.brokerUID = brokerUID; self.vaultID = vaultID; self.enrollmentID = enrollmentID
        self.requireQuiescent = requireQuiescent
        support = try Directory(InstallerPayloadManifest.support, mode: 0o755)
        parent = try Directory(StoreVolumeMigrationAuthority.parentPath, mode: 0o755)
        journal = try Directory(parent.path + "/.enrollment-" + enrollmentID + ".publication", mode: 0o700)
        original = try Directory("/Library/Application Support/Account Access Installer", mode: 0o700)
        volume = try Directory(InstallationRootBinding.namespace, mode: 0o700)
        broker = try Directory(InstallerPayloadManifest.support + "/broker", mode: 0o755)
        services = try Directory("/Library/LaunchDaemons")
        let handle = openat(parent.fd, ".account-access-enrollment.lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard handle >= 0 else { throw ComponentUpdateFailure.journal }
        do {
            let info = try InstallerPayloadIO.check(handle, owner: 0, directory: false)
            try InstallationRootBinding.noACL(handle)
            guard info.st_mode & 0o7777 == 0o600, info.st_size == 0,
                  flock(handle, LOCK_EX | LOCK_NB) == 0 else { throw ComponentUpdateFailure.journal }
            lockIdentity = info; lock = handle
        } catch { Darwin.close(handle); throw error }
    }
    deinit { if lock >= 0 { Darwin.close(lock) } }
    static func prepare(ownerUID: uid_t, brokerUID: uid_t, vaultID: String, enrollmentID: String,
                        requireQuiescent: @escaping () throws -> Void) throws -> StoreVolumeMigration {
        let prepared = try StoreVolumeMigration(ownerUID: ownerUID, brokerUID: brokerUID,
            vaultID: vaultID, enrollmentID: enrollmentID, requireQuiescent: requireQuiescent)
        prepared.captured = try prepared.observe()
        return prepared
    }
    private func directory(_ name: String) throws -> StoreVolumeMigrationAuthority.Directory {
        var info = stat()
        guard fstatat(parent.fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw ComponentUpdateFailure.object }
        return .init(device: Int64(info.st_dev), inode: UInt64(info.st_ino), owner: info.st_uid,
                     group: info.st_gid, mode: info.st_mode)
    }
    private func observe() throws -> StoreVolumeMigrationAuthority {
        try requireQuiescent()
        let directories = [support, parent, journal, original, volume, broker, services]
        for directory in directories { try directory.verify() }
        var attached = stat()
        let held = try InstallerPayloadIO.check(lock, owner: 0, directory: false)
        try InstallationRootBinding.noACL(lock)
        guard InstallerPayloadIO.same(held, lockIdentity),
              fstatat(parent.fd, ".account-access-enrollment.lock", &attached, AT_SYMLINK_NOFOLLOW) == 0,
              InstallerPayloadIO.same(held, attached),
              try InstallerPayloadIO.contents(volume.fd) == [InstallationRootBinding.receiptName] else {
            throw ComponentUpdateFailure.journal
        }
        let roots = try InstallationRootBinding.capture(withVolumeUUID: true)
        let context = try RootStoreVolumeBinding.capture(parent.fd)
        var receipts: [String: Data] = [:]
        for name in InstallationRootBinding.receiptNames { receipts[name] = try original.read(name) }
        let supplement = try volume.read(InstallationRootBinding.receiptName)
        let record = try journal.read("plan.json", maximum: 4096)
        let authorized = try journal.read("authorized", maximum: 1024)
        let ready = try journal.read("ready", maximum: 1024)
        var paused = stat()
        guard fstatat(journal.fd, "paused", &paused, AT_SYMLINK_NOFOLLOW) == -1, errno == ENOENT else {
            throw ComponentUpdateFailure.base
        }
        let worker = try broker.read("worker.json", mode: 0o644, maximum: 4096)
        let service = try services.read("com.fainir.accountaccess.broker.plist", mode: 0o644)
        let enrollment = try InstallationRootBinding.object(broker.read("enrollment.json", mode: 0o644, maximum: 4096))
        guard Set(enrollment.keys) == ["managed_by", "schema", "worker_launcher", "stage_policy", "vault_id", "enrollment_id"],
              enrollment["managed_by"] as? String == "account-access-worker-enrollment-v1",
              try InstallerPayloadManifest.integer(enrollment["schema"], maximum: 1) == 1,
              enrollment["worker_launcher"] as? String == broker.path + "/worker-launch.json",
              enrollment["stage_policy"] as? String == broker.path + "/stage.json",
              enrollment["vault_id"] as? String == vaultID, enrollment["enrollment_id"] as? String == enrollmentID else {
            throw ComponentUpdateFailure.base
        }
        let stage = try directory(".enrollment-" + enrollmentID), destination = try directory("data")
        let result = try StoreVolumeMigrationAuthority.qualify(originalReceipts: receipts, volumeReceipt: supplement,
            roots: roots, ownerUID: ownerUID, brokerUID: brokerUID,
            workerSHA256: ComponentFiles.digest(worker), serviceSHA256: ComponentFiles.digest(service),
            publication: record, authorization: authorized, ready: ready, paused: false,
            vaultID: vaultID, enrollmentID: enrollmentID, path: parent.path, parent: context, stage: stage, destination: destination)
        for directory in directories { try directory.verify() }
        guard try InstallationRootBinding.capture(withVolumeUUID: true) == roots,
              try RootStoreVolumeBinding.capture(parent.fd) == context else { throw ComponentUpdateFailure.object }
        try requireQuiescent()
        return result
    }
    func publish() throws {
        guard let captured else { throw ComponentUpdateFailure.context }
        try RootStoreVolumePublication.publish(directory: journal.fd, data: captured.bindingData, verify: {
            let current = try self.observe()
            guard current.bindingData == captured.bindingData,
                  current.originalRecordSHA256 == captured.originalRecordSHA256,
                  current.installationReceiptSHA256 == captured.installationReceiptSHA256 else {
                throw ComponentUpdateFailure.object
            }
        })
    }
}
