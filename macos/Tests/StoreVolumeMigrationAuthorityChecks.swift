// Fictional bytes only: no installed paths, services, accounts or keys.
import Foundation
import Darwin

enum StoreVolumeMigrationAuthorityChecks {
    private static func encoded(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private static func changed(_ data: Data, _ key: String, _ value: Any) throws -> Data {
        var object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        object[key] = value
        return try encoded(object)
    }
    private struct Input {
        var original: [String: Data]
        var receipt: Data
        var roots: [String: InstallationRootBinding.CurrentRoot]
        var record: Data
        var authorization: Data
        var ready = Data("account-access-publication-ready-v1\n".utf8)
        var paused = false
        var owner: uid_t = 501
        var broker: uid_t = 470
        var worker = String(repeating: "1", count: 64)
        var service = String(repeating: "2", count: 64)
        var vault = "11111111-2222-4333-8444-555555555555"
        var enrollment = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        var path = StoreVolumeMigrationAuthority.parentPath
        var parent = RootStoreVolumeBinding.Context(device: 21, parentInode: 200,
            volumeUUID: "11111111-2222-4333-8444-55555555555a")
        var stage = StoreVolumeMigrationAuthority.Directory(device: 21, inode: 302, owner: 470, group: 470, mode: S_IFDIR | 0o700)
        var destination = StoreVolumeMigrationAuthority.Directory(device: 21, inode: 301, owner: 470, group: 470, mode: S_IFDIR | 0o700)
        func qualify() throws -> StoreVolumeMigrationAuthority {
            try StoreVolumeMigrationAuthority.qualify(originalReceipts: original, volumeReceipt: receipt, roots: roots,
                ownerUID: owner, brokerUID: broker, workerSHA256: worker, serviceSHA256: service,
                publication: record, authorization: authorization, ready: ready, paused: paused,
                vaultID: vault, enrollmentID: enrollment, path: path, parent: parent, stage: stage, destination: destination)
        }
    }
    static func run() throws -> (Int, [String: Bool]) {
        var assertions = 0
        func expect(_ value: Bool) throws {
            guard value else { throw ComponentUpdateFailure.context }; assertions += 1
        }
        let paths = InstallationRootBinding.paths
        let manifest = StoreVolumeMigrationAuthority.originalManifest
        let published = try encoded(["manifest_sha256": manifest, "roots": [paths[0]: [20, 100], paths[1]: [20, 101]]])
        let originals = [
            "intent.json": try encoded(["managed_by": "account-access-public-image-install-v1", "schema": 1,
                "manifest_sha256": manifest, "owner_uid": 501]),
            "complete.json": try encoded(["manifest_sha256": manifest, "owner_uid": 501, "status": "REGISTERED"]),
            "ready.json": published, "published.json": published]
        let roots: [String: InstallationRootBinding.CurrentRoot] = [
            paths[0]: .init(device: 21, inode: 100, volumeUUID: "11111111-2222-4333-8444-55555555555a"),
            paths[1]: .init(device: 21, inode: 101, volumeUUID: "11111111-2222-4333-8444-55555555555a")]
        let legacy = try InstallationRootBinding.parseLegacy(records: originals, ownerUID: 501, manifestSHA256: manifest)
        let receipt = try InstallationRootBinding.supplement(legacy: legacy, current: roots,
            planSHA256: StoreVolumeMigrationAuthority.componentPlan, sourceCommit: StoreVolumeMigrationAuthority.componentSource,
            policyHashes: ["worker": String(repeating: "1", count: 64), "service": String(repeating: "2", count: 64),
                "install": String(repeating: "3", count: 64), "host": String(repeating: "4", count: 64), "owner": String(repeating: "5", count: 64)])
        let record = try encoded(["schema": 1, "vault": "11111111-2222-4333-8444-555555555555",
            "enrollment": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "stage": ".enrollment-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "destination": "data", "uid": 470, "gid": 470,
            "stagedIdentity": ["device": 20, "inode": 301], "emptyIdentity": ["device": 20, "inode": 302]])
        let input = Input(original: originals, receipt: receipt, roots: roots, record: record,
            authorization: try encoded(["schema": 1, "owner_uid": 501]))
        let authority = try input.qualify()
        let binding = try RootStoreVolumeBinding.decode(authority.bindingData, record: record, context: input.parent)
        try expect(binding.parentInode == 200 && binding.volumeUUID == input.parent.volumeUUID)
        try expect(authority.originalRecordSHA256 == ComponentFiles.digest(record)
            && authority.installationReceiptSHA256 == ComponentFiles.digest(receipt))
        try expect(try input.qualify().bindingData == authority.bindingData)
        func refuses(_ modify: (inout Input) throws -> Void) throws {
            var candidate = input; try modify(&candidate)
            var rejected = false
            do { _ = try candidate.qualify() } catch { rejected = true }
            try expect(rejected)
        }
        for (key, value) in [("schema", true as Any), ("schema", 2 as Any), ("uid", 471 as Any),
            ("gid", 471 as Any), ("vault", UUID().uuidString.lowercased() as Any),
            ("enrollment", UUID().uuidString.lowercased() as Any), ("stage", "../data" as Any),
            ("destination", "other" as Any), ("extra", true as Any)] {
            try refuses { $0.record = try changed($0.record, key, value) }
        }
        for key in ["stagedIdentity", "emptyIdentity"] {
            for value: [String: Any] in [["device": 21, "inode": 301], ["device": 19, "inode": 301],
                ["device": -1, "inode": 301], ["device": 20, "inode": 0], ["device": true, "inode": 301],
                ["device": 20, "inode": true], ["device": 20, "inode": 999], ["device": 20, "inode": 301, "extra": 1]] {
                try refuses { $0.record = try changed($0.record, key, value) }
            }
        }
        try refuses { $0.record = try changed(changed($0.record, "stagedIdentity", ["device": 19, "inode": 301]),
                                              "emptyIdentity", ["device": 19, "inode": 302]) }
        for raw in [Data(), Data(repeating: 32, count: 4097), Data(("{\"schema\":1," + String(decoding: record, as: UTF8.self).dropFirst()).utf8),
                    Data(("{\"\\u0073chema\":1," + String(decoding: record, as: UTF8.self).dropFirst()).utf8)] {
            try refuses { $0.record = raw }
        }
        for (key, value) in [("schema", true as Any), ("owner_uid", 502 as Any), ("extra", true as Any)] {
            try refuses { $0.authorization = try changed($0.authorization, key, value) }
        }
        for (key, value) in [("authorizing_plan_sha256", String(repeating: "a", count: 64)),
            ("authorizing_source_commit", String(repeating: "a", count: 40)), ("publisher_team", "FOREIGN123"),
            ("base_manifest_sha256", String(repeating: "a", count: 64))] {
            try refuses { $0.receipt = try changed($0.receipt, key, value) }
        }
        for name in originals.keys {
            try refuses { $0.original.removeValue(forKey: name) }
            try refuses { $0.original[name]!.append(32) }
        }
        try refuses { $0.ready = Data() }; try refuses { $0.paused = true }
        try refuses { $0.owner = 502 }; try refuses { $0.broker = 471 }
        try refuses { $0.worker = String(repeating: "3", count: 64) }
        try refuses { $0.service = String(repeating: "3", count: 64) }
        try refuses { $0.path += "/.." }; try refuses { $0.vault = $0.vault.uppercased() + "0" }
        try refuses { $0.enrollment = "00000000-0000-0000-0000-000000000000" }
        for parent in [RootStoreVolumeBinding.Context(device: 22, parentInode: 200, volumeUUID: input.parent.volumeUUID),
            .init(device: 21, parentInode: 100, volumeUUID: input.parent.volumeUUID),
            .init(device: 21, parentInode: 301, volumeUUID: input.parent.volumeUUID),
            .init(device: 21, parentInode: 0, volumeUUID: input.parent.volumeUUID),
            .init(device: 21, parentInode: 200, volumeUUID: UUID().uuidString.lowercased())] {
            try refuses { $0.parent = parent }
        }
        for path in paths {
            try refuses { $0.roots.removeValue(forKey: path) }
            try refuses { $0.roots[path] = .init(device: 21, inode: 999, volumeUUID: input.parent.volumeUUID) }
        }
        try refuses { let old = $0.stage; $0.stage = $0.destination; $0.destination = old }
        for directory in [StoreVolumeMigrationAuthority.Directory(device: 22, inode: 302, owner: 470, group: 470, mode: S_IFDIR | 0o700),
            .init(device: 21, inode: 999, owner: 470, group: 470, mode: S_IFDIR | 0o700),
            .init(device: 21, inode: 302, owner: 0, group: 470, mode: S_IFDIR | 0o700),
            .init(device: 21, inode: 302, owner: 470, group: 0, mode: S_IFDIR | 0o700),
            .init(device: 21, inode: 302, owner: 470, group: 470, mode: S_IFDIR | 0o755),
            .init(device: 21, inode: 302, owner: 470, group: 470, mode: S_IFLNK | 0o700)] {
            try refuses { $0.stage = directory }
        }
        return (assertions, ["store_migration_binds_original_epoch_to_existing_volume_receipt": true,
            "store_migration_requires_authorized_completed_unchanged_directory_pair": true,
            "store_migration_rejects_foreign_roots_policies_and_ambiguous_records": true])
    }
}
