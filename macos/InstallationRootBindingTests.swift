// Synthetic bytes/identities plus one owned temporary-directory volume ABI
// check. No installed paths, private data, account or service queries.
import Foundation
import CryptoKit
import Darwin

enum InstallationRootBindingTests {
    static func run() throws -> (Int, [String: Bool]) {
        var checks = 0
        var passed: [String: Bool] = [:]
        func expect(_ condition: Bool) throws {
            guard condition else { throw ComponentUpdateFailure.context }
            checks += 1
        }
        func refuses(_ body: () throws -> Void) throws {
            var rejected = false
            do { try body() } catch { rejected = true }
            try expect(rejected)
        }
        func encoded(_ object: [String: Any]) throws -> Data {
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        }
        func object(_ data: Data) throws -> [String: Any] {
            guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw ComponentUpdateFailure.context
            }
            return value
        }
        func changed(_ data: Data, _ mutate: (inout [String: Any]) -> Void) throws -> Data {
            var value = try object(data); mutate(&value); return try encoded(value)
        }
        let paths = ["/Library/Application Support/Account Access", "/Applications/Account Access.app"]
        let owner: uid_t = 501
        let manifest = String(repeating: "a", count: 64)
        let plan = String(repeating: "b", count: 64)
        let revision = String(repeating: "c", count: 40)
        let volume = "11111111-2222-4333-8444-55555555555a"
        let differentVolume = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        let rootPairs: [String: [Int64]] = [paths[0]: [16_777_234, 123_456], paths[1]: [16_777_234, 654_321]]
        let publication = try encoded(["manifest_sha256": manifest, "roots": rootPairs])
        let records: [String: Data] = [
            "intent.json": try encoded(["schema": 1, "managed_by": "account-access-public-image-install-v1",
                                         "manifest_sha256": manifest, "owner_uid": owner]),
            "complete.json": try encoded(["manifest_sha256": manifest, "owner_uid": owner, "status": "REGISTERED"]),
            "ready.json": publication, "published.json": publication,
        ]
        func parse(_ value: [String: Data]) throws -> InstallationRootBinding.Legacy {
            try InstallationRootBinding.parseLegacy(records: value, ownerUID: owner, manifestSHA256: manifest)
        }
        func current(device: Int32 = 16_777_235, supportInode: UInt64 = 123_456,
                     applicationInode: UInt64 = 654_321, uuid: String = volume) -> [String: InstallationRootBinding.CurrentRoot] {
            [paths[0]: .init(device: device, inode: supportInode, volumeUUID: uuid),
             paths[1]: .init(device: device, inode: applicationInode, volumeUUID: uuid)]
        }
        let legacy = try parse(records)
        try expect(InstallationRootBinding.paths == paths)
        try expect(Set(InstallationRootBinding.receiptNames) == Set(records.keys))
        try expect(legacy.ownerUID == owner && legacy.manifestSHA256 == manifest)
        try expect(legacy.roots[paths[0]] == .init(device: 16_777_234, inode: 123_456))
        try expect(legacy.roots[paths[1]] == .init(device: 16_777_234, inode: 654_321))
        try expect(legacy.hashes == records.mapValues { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() })
        passed["legacy_receipts_bound_to_original_bytes_owner_and_roots"] = true

        var missing = records; missing.removeValue(forKey: "published.json")
        try refuses { _ = try parse(missing) }
        var extra = records; extra["unrelated.json"] = Data("{}".utf8)
        try refuses { _ = try parse(extra) }
        let invalidFields: [(String, String, Any)] = [
            ("intent.json", "schema", true), ("intent.json", "schema", 2),
            ("intent.json", "schema", 1.5), ("intent.json", "managed_by", "foreign"),
            ("intent.json", "owner_uid", true), ("intent.json", "owner_uid", 502),
            ("intent.json", "manifest_sha256", String(repeating: "b", count: 64)),
            ("complete.json", "owner_uid", false), ("complete.json", "owner_uid", 502),
            ("complete.json", "status", "READY"), ("complete.json", "manifest_sha256", "invalid"),
        ]
        for (name, key, value) in invalidFields {
            var modified = records; modified[name] = try changed(records[name]!) { $0[key] = value }
            try refuses { _ = try parse(modified) }
        }
        var inconsistent = records
        inconsistent["published.json"] = try changed(publication) { $0["unexpected"] = true }
        try refuses { _ = try parse(inconsistent) }
        var extraIntent = records
        extraIntent["intent.json"] = try changed(records["intent.json"]!) { $0["unexpected"] = true }
        try refuses { _ = try parse(extraIntent) }
        try refuses { _ = try InstallationRootBinding.parseLegacy(records: records, ownerUID: 0, manifestSHA256: manifest) }
        try refuses { _ = try InstallationRootBinding.parseLegacy(records: records, ownerUID: owner, manifestSHA256: "invalid") }
        passed["legacy_shape_digest_owner_status_and_record_set_fail_closed"] = true

        let malformedRoots: [[String: Any]] = [
            [paths[0]: [16_777_234, 123_456]],
            [paths[0]: [16_777_234, 123_456], "/foreign": [16_777_234, 654_321]],
            [paths[0]: [16_777_234], paths[1]: [16_777_234, 654_321]],
            [paths[0]: [true, 123_456] as [Any], paths[1]: [16_777_234, 654_321]],
            [paths[0]: [-1, 123_456], paths[1]: [16_777_234, 654_321]],
            [paths[0]: [Int64(Int32.max) + 1, 123_456], paths[1]: [16_777_234, 654_321]],
            [paths[0]: [16_777_234, false] as [Any], paths[1]: [16_777_234, 654_321]],
            [paths[0]: [16_777_234, -1], paths[1]: [16_777_234, 654_321]],
            [paths[0]: [16_777_234, 1.5], paths[1]: [16_777_234, 654_321]],
        ]
        for roots in malformedRoots {
            var modified = records
            let bad = try changed(publication) { $0["roots"] = roots }
            modified["ready.json"] = bad; modified["published.json"] = bad
            try refuses { _ = try parse(modified) }
        }
        // NSDictionary equality can equate NSNumber(true) and NSNumber(1).
        // Each complete receipt is otherwise valid, so these specifically
        // exercise semantic type preservation in the publication comparison.
        let smallRoots: [String: [Int64]] = [paths[0]: [1, 1], paths[1]: [1, 2]]
        let smallReady = try encoded(["manifest_sha256": manifest, "roots": smallRoots])
        for index in [0, 1] {
            var publishedRoots: [String: [Any]] = [paths[0]: [1, 1], paths[1]: [1, 2]]
            publishedRoots[paths[0]]![index] = true
            var modified = records
            modified["ready.json"] = smallReady
            modified["published.json"] = try encoded(["manifest_sha256": manifest, "roots": publishedRoots])
            try refuses { _ = try parse(modified) }
        }
        passed["legacy_fixed_roots_require_bounded_nonboolean_integer_pairs"] = true

        let intentText = String(decoding: records["intent.json"]!, as: UTF8.self)
        let duplicatedSchema = "{\"schema\":1," + intentText.dropFirst()
        let escapedSchema = "{\"\\u0073chema\":1," + intentText.dropFirst()
        for bad in [Data(), Data([0xff]), Data(duplicatedSchema.utf8), Data(escapedSchema.utf8), records["intent.json"]! + Data([0]),
                    records["intent.json"]! + Data(repeating: 32, count: 8193)] {
            var modified = records; modified["intent.json"] = bad
            try refuses { _ = try parse(modified) }
        }
        let readyText = String(decoding: publication, as: UTF8.self)
        let duplicatedRoot = readyText.replacingOccurrences(of: "\"roots\":{", with: "\"roots\":{\"" + paths[0] + "\":[16777234,123456],")
        var duplicates = records
        duplicates["ready.json"] = Data(duplicatedRoot.utf8); duplicates["published.json"] = Data(duplicatedRoot.utf8)
        try refuses { _ = try parse(duplicates) }
        passed["legacy_bounded_json_and_plain_escaped_nested_duplicates_rejected"] = true

        try expect(try InstallationRootBinding.exactLegacy(legacy, current: current(device: 16_777_234)))
        try expect(try !InstallationRootBinding.exactLegacy(legacy, current: current()))
        try expect(try !InstallationRootBinding.exactLegacy(legacy, current: current(device: 16_777_234, supportInode: 123_457)))
        try InstallationRootBinding.requireDeviceOnly(legacy, current: current()); checks += 1
        try refuses { try InstallationRootBinding.requireDeviceOnly(legacy, current: current(device: 16_777_234)) }
        try refuses { try InstallationRootBinding.requireDeviceOnly(legacy, current: current(supportInode: 123_457)) }
        try refuses { try InstallationRootBinding.requireDeviceOnly(legacy, current: current(applicationInode: 654_322)) }
        var absentRoot = current(); absentRoot.removeValue(forKey: paths[1])
        try refuses { try InstallationRootBinding.requireDeviceOnly(legacy, current: absentRoot) }
        var extraRoot = current(); extraRoot["/foreign"] = .init(device: 1, inode: 1, volumeUUID: volume)
        try refuses { try InstallationRootBinding.requireDeviceOnly(legacy, current: extraRoot) }
        var mixedDevices = current(); mixedDevices[paths[1]] = .init(device: 16_777_234, inode: 654_321, volumeUUID: volume)
        try refuses { try InstallationRootBinding.requireDeviceOnly(legacy, current: mixedDevices) }
        var mixedVolumes = current(); mixedVolumes[paths[1]] = .init(device: 16_777_235, inode: 654_321, volumeUUID: differentVolume)
        try refuses { try InstallationRootBinding.requireDeviceOnly(legacy, current: mixedVolumes) }
        passed["device_only_migration_never_accepts_inode_or_root_set_changes"] = true

        let policies = Dictionary(uniqueKeysWithValues: ["install", "host", "owner", "worker", "service"].enumerated().map {
            ($0.element, String(repeating: String($0.offset + 1), count: 64))
        })
        let supplement = try InstallationRootBinding.supplement(legacy: legacy, current: current(), planSHA256: plan,
                                                               sourceCommit: revision, policyHashes: policies)
        for path in paths {
            var invalidLegacyRoots = legacy.roots
            invalidLegacyRoots[path] = .init(device: 16_777_234, inode: UInt64.max)
            let invalidLegacy = InstallationRootBinding.Legacy(hashes: legacy.hashes, roots: invalidLegacyRoots,
                                                               ownerUID: owner, manifestSHA256: manifest)
            var invalidCurrent = current()
            invalidCurrent[path] = .init(device: 16_777_235, inode: UInt64.max, volumeUUID: volume)
            try refuses { try InstallationRootBinding.requireDeviceOnly(invalidLegacy, current: invalidCurrent) }
            try refuses { try InstallationRootBinding.validateSupplement(supplement, legacy: invalidLegacy, current: invalidCurrent) }
        }
        try InstallationRootBinding.validateSupplement(supplement, legacy: legacy, current: current()); checks += 1
        // Device numbering may change again; the UUID/inode pair is the stable supplemental binding.
        try InstallationRootBinding.validateSupplement(supplement, legacy: legacy, current: current(device: 16_777_236)); checks += 1
        try InstallationRootBinding.validateSupplement(supplement, legacy: legacy, current: current(device: 16_777_234)); checks += 1
        try refuses { try InstallationRootBinding.validateSupplement(supplement, legacy: legacy, current: current(uuid: differentVolume)) }
        try refuses { try InstallationRootBinding.validateSupplement(supplement, legacy: legacy, current: current(device: 16_777_234, uuid: differentVolume)) }
        try refuses { try InstallationRootBinding.validateSupplement(supplement, legacy: legacy, current: current(supportInode: 123_457)) }
        try refuses { try InstallationRootBinding.validateSupplement(supplement, legacy: legacy, current: current(applicationInode: 654_322)) }
        passed["supplement_binds_uuid_and_both_original_inodes_across_device_renumbering"] = true

        for uuid in ["", "unsupported", volume.uppercased(), "00000000-0000-0000-0000-000000000000"] {
            try refuses { _ = try InstallationRootBinding.supplement(legacy: legacy, current: current(uuid: uuid), planSHA256: plan,
                                                                    sourceCommit: revision, policyHashes: policies) }
            try refuses { try InstallationRootBinding.validateSupplement(supplement, legacy: legacy, current: current(uuid: uuid)) }
        }
        passed["supplement_requires_supported_canonical_nonzero_volume_uuid"] = true

        let invalidSupplementFields: [(String, Any)] = [
            ("schema", true), ("schema", 99), ("managed_by", "foreign"),
            ("owner_uid", true), ("owner_uid", 502), ("base_manifest_sha256", String(repeating: "d", count: 64)),
            ("publisher_team", "AAAAAAAAAA"), ("publisher_identifier", "com.foreign.helper"),
            ("authorizing_plan_sha256", String(repeating: "b", count: 63)),
            ("authorizing_source_commit", String(repeating: "C", count: 40)),
            ("policy_sha256", ["install": String(repeating: "1", count: 64)]),
        ]
        for (key, value) in invalidSupplementFields {
            let bad = try changed(supplement) { $0[key] = value }
            try refuses { try InstallationRootBinding.validateSupplement(bad, legacy: legacy, current: current()) }
        }
        var malformedPolicy = policies; malformedPolicy["service"] = "invalid"
        try refuses { _ = try InstallationRootBinding.supplement(legacy: legacy, current: current(), planSHA256: plan,
                                                                sourceCommit: revision, policyHashes: malformedPolicy) }
        try refuses { _ = try InstallationRootBinding.supplement(legacy: legacy, current: current(), planSHA256: "invalid",
                                                                sourceCommit: revision, policyHashes: policies) }
        try refuses { _ = try InstallationRootBinding.supplement(legacy: legacy, current: current(), planSHA256: plan,
                                                                sourceCommit: "invalid", policyHashes: policies) }
        passed["supplement_owner_publisher_schema_plan_source_policy_provenance_fail_closed"] = true

        let rootMutations: [(String, Any)] = [("inode", true), ("inode", 123_457),
                                            ("volume_uuid", differentVolume), ("extra", true)]
        for (key, value) in rootMutations {
            var roots = try object(supplement)["roots"] as! [String: [String: Any]]
            roots[paths[0]]![key] = value
            let bad = try changed(supplement) { $0["roots"] = roots }
            try refuses { try InstallationRootBinding.validateSupplement(bad, legacy: legacy, current: current()) }
        }
        var wrongRootSet = try object(supplement)["roots"] as! [String: [String: Any]]
        wrongRootSet["/foreign"] = wrongRootSet.removeValue(forKey: paths[1])
        let badRoots = try changed(supplement) { $0["roots"] = wrongRootSet }
        try refuses { try InstallationRootBinding.validateSupplement(badRoots, legacy: legacy, current: current()) }
        passed["supplement_fixed_root_schema_uuid_and_inode_cannot_be_substituted"] = true

        for name in InstallationRootBinding.receiptNames {
            var changedBytes = records; changedBytes[name] = records[name]! + Data([32])
            let changedLegacy = try parse(changedBytes)
            try refuses { try InstallationRootBinding.validateSupplement(supplement, legacy: changedLegacy, current: current()) }
        }
        let wrongHashes = try changed(supplement) { $0["original_receipt_sha256"] = records.mapValues { _ in String(repeating: "0", count: 64) } }
        try refuses { try InstallationRootBinding.validateSupplement(wrongHashes, legacy: legacy, current: current()) }
        passed["supplement_rejects_any_changed_original_receipt_bytes_or_digest"] = true

        let supplementText = String(decoding: supplement, as: UTF8.self)
        let duplicate = "{\"owner_uid\":501," + supplementText.dropFirst()
        let escapedDuplicate = "{\"owner_\\u0075id\":501," + supplementText.dropFirst()
        for bad in [Data(), Data([0xff]), Data(duplicate.utf8), Data(escapedDuplicate.utf8),
                    supplement + Data([0]), supplement + Data(repeating: 32, count: 8193)] {
            try refuses { try InstallationRootBinding.validateSupplement(bad, legacy: legacy, current: current()) }
        }
        passed["supplement_bounded_json_and_duplicate_members_rejected"] = true

        var template = Array("/private/tmp/account-access-volume-fixture-XXXXXX".utf8).map { CChar(bitPattern: $0) } + [0]
        guard let created = mkdtemp(&template) else { throw ComponentUpdateFailure.context }
        let scratch = String(cString: created)
        defer { _ = rmdir(scratch) }
        let directory = open(scratch, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw ComponentUpdateFailure.context }
        defer { Darwin.close(directory) }
        let measuredUUID = try InstallationRootBinding.volumeUUID(directory)
        try expect(UUID(uuidString: measuredUUID)?.uuidString.lowercased() == measuredUUID)
        try expect(measuredUUID != "00000000-0000-0000-0000-000000000000")
        passed["owned_directory_volume_uuid_abi_is_canonical_and_nonzero"] = true
        return (checks, passed)
    }
}
