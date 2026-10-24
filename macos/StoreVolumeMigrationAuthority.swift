// Pure authority derivation for the one qualified legacy installation. The
// Installer adapter must supply protected, attached metadata under its locks.
// This file performs no reads, writes, service calls or credential operations.
import Foundation
import Darwin

// Closed diagnostic categories only. Neither an error description nor a value
// from protected metadata may be rendered by the Installer entry point.
enum StoreVolumeMigrationCheckpoint: String, CaseIterable {
    case directories, enrollmentLock = "enrollment_lock", attachments, roots
    case volumeContext = "volume_context", originalReceipts = "original_receipts"
    case volumeReceipt = "volume_receipt", publication, authorization, ready, pause, enrollment
    case storeDirectories = "store_directories", input, legacy, componentVolume = "component_volume"
    case provenance, ownerApproval = "owner_approval", record, identities
    case deviceEpoch = "device_epoch", directoryPair = "directory_pair", binding, stability, publish
}
struct StoreVolumeMigrationDiagnostic: Error {
    let checkpoint: StoreVolumeMigrationCheckpoint
    let failure: Error
    static func checked<T>(_ checkpoint: StoreVolumeMigrationCheckpoint, _ operation: () throws -> T) throws -> T {
        do { return try operation() }
        catch let diagnostic as StoreVolumeMigrationDiagnostic { throw diagnostic }
        catch { throw StoreVolumeMigrationDiagnostic(checkpoint: checkpoint, failure: error) }
    }
}

struct StoreVolumeMigrationAuthority {
    static let originalManifest = "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8"
    static let componentPlan = "be4e1429466cc0fbe8d2e85fe9f0d54f9c93b1a1edd6dfa32b77b9c72cc4d1b7"
    static let componentSource = "213509c6bd9ff40131bd71dcb1a2967e96cd76a3"
    static let parentPath = InstallerPayloadManifest.support + "/vault"

    struct Directory {
        let device: Int64
        let inode: UInt64
        let owner: uid_t
        let group: gid_t
        let mode: mode_t
    }
    let bindingData: Data
    let originalRecordSHA256: String
    let installationReceiptSHA256: String
    private init(binding: Data, record: Data, receipt: Data) {
        bindingData = binding
        originalRecordSHA256 = ComponentFiles.digest(record)
        installationReceiptSHA256 = ComponentFiles.digest(receipt)
    }

    // Directory contents are deliberately absent from the input. Both original
    // directory inodes must be present in the completed, reversed order. The
    // original device epoch must also be the one in the installation receipts;
    // an inode coincidence or a newly invented UUID is insufficient authority.
    static func qualify(originalReceipts: [String: Data], volumeReceipt: Data,
                        roots: [String: InstallationRootBinding.CurrentRoot],
                        ownerUID: uid_t, brokerUID: uid_t, workerSHA256: String, serviceSHA256: String,
                        publication: Data, authorization: Data, ready: Data, paused: Bool,
                        vaultID: String, enrollmentID: String, path: String,
                        parent: RootStoreVolumeBinding.Context,
                        stage: Directory, destination: Directory,
                        verifiedComponentDevice: Int32? = nil) throws -> StoreVolumeMigrationAuthority {
        // The optional epoch is supplied only by the completed-component
        // verifier, under the updater's maintenance locks. It must never come
        // from the publication record or an unverified historical intent.
        var checkpoint = StoreVolumeMigrationCheckpoint.input
        do {
        guard path == parentPath, ownerUID > 0, ownerUID != brokerUID, (450..<500).contains(brokerUID),
              canonicalUUID(vaultID), canonicalUUID(enrollmentID), !paused,
              ready == Data("account-access-publication-ready-v1\n".utf8),
              !publication.isEmpty, publication.count <= 4096, authorization.count <= 1024 else {
            throw ComponentUpdateFailure.base
        }
        checkpoint = .legacy
        let legacy = try InstallationRootBinding.parseLegacy(records: originalReceipts,
            ownerUID: ownerUID, manifestSHA256: originalManifest)
        checkpoint = .componentVolume
        let volume = try InstallationRootBinding.componentVolume(volumeReceipt, legacy: legacy, current: roots,
            planSHA256: componentPlan, workerSHA256: workerSHA256, serviceSHA256: serviceSHA256)
        checkpoint = .provenance
        let receipt = try InstallationRootBinding.object(volumeReceipt)
        guard receipt["authorizing_source_commit"] as? String == componentSource,
              parent.device == Int64(volume.device), parent.volumeUUID == volume.volumeUUID,
              parent.parentInode > 0, parent.parentInode != volume.inode else { throw ComponentUpdateFailure.base }
        checkpoint = .ownerApproval
        let approved = try InstallationRootBinding.object(authorization)
        guard Set(approved.keys) == ["schema", "owner_uid"],
              try integer(approved["schema"]) == 1,
              try integer(approved["owner_uid"]) == Int64(ownerUID) else { throw ComponentUpdateFailure.base }
        checkpoint = .record
        let record = try InstallationRootBinding.object(publication)
        guard Set(record.keys) == ["schema", "vault", "enrollment", "stage", "destination", "uid", "gid", "stagedIdentity", "emptyIdentity"],
              try integer(record["schema"]) == 1, record["vault"] as? String == vaultID,
              record["enrollment"] as? String == enrollmentID,
              record["stage"] as? String == ".enrollment-" + enrollmentID,
              record["destination"] as? String == "data", try integer(record["uid"]) == Int64(brokerUID),
              try integer(record["gid"]) == Int64(brokerUID) else { throw ComponentUpdateFailure.base }
        func identity(_ name: String) throws -> (device: Int64, inode: UInt64) {
            guard let raw = record[name] as? [String: Any], Set(raw.keys) == ["device", "inode"] else {
                throw ComponentUpdateFailure.base
            }
            let device = try InstallerPayloadManifest.integer(raw["device"], maximum: Int64(Int32.max))
            let inode = try integer(raw["inode"])
            guard inode > 0 else { throw ComponentUpdateFailure.base }
            return (device, UInt64(inode))
        }
        checkpoint = .identities
        let oldStage = try identity("stagedIdentity"), oldEmpty = try identity("emptyIdentity")
        checkpoint = .deviceEpoch
        guard verifiedComponentDevice == nil || verifiedComponentDevice! >= 0 else { throw ComponentUpdateFailure.base }
        guard oldStage.device == oldEmpty.device, oldStage.device != parent.device,
              oldStage.inode != oldEmpty.inode,
              legacy.roots.values.allSatisfy({ Int64($0.device) == oldStage.device })
                || verifiedComponentDevice.map({ Int64($0) == oldStage.device }) == true else {
            throw ComponentUpdateFailure.base
        }
        checkpoint = .directoryPair
        guard stage.inode == oldEmpty.inode, destination.inode == oldStage.inode,
              [stage, destination].allSatisfy({ $0.device == parent.device && $0.owner == brokerUID
                  && $0.group == brokerUID && $0.mode == (S_IFDIR | 0o700) }),
              ![stage.inode, destination.inode].contains(parent.parentInode) else { throw ComponentUpdateFailure.base }
        checkpoint = .binding
        let binding = try RootStoreVolumeBinding(record: publication, context: parent).encoded()
        return StoreVolumeMigrationAuthority(binding: binding, record: publication, receipt: volumeReceipt)
        } catch let diagnostic as StoreVolumeMigrationDiagnostic { throw diagnostic }
        catch { throw StoreVolumeMigrationDiagnostic(checkpoint: checkpoint, failure: error) }
    }
    private static func integer(_ value: Any?) throws -> Int64 {
        try InstallerPayloadManifest.integer(value, maximum: Int64.max)
    }
    private static func canonicalUUID(_ text: String) -> Bool {
        guard let id = UUID(uuidString: text) else { return false }
        return id.uuidString.lowercased() == text && text != "00000000-0000-0000-0000-000000000000"
    }
}
