// IGNORED synthetic predecessor fixture. No filesystem, service, process,
// account, owner profile, package, network or root operation is performed.
import Foundation
import Darwin

private enum PredecessorFixtureFailure: Error { case failed, initial, read }

struct CompletedPredecessorFixture {
    static let owner: UInt32 = 501
    static let broker: UInt32 = 450
    static let plan = String(repeating: "c", count: 64)
    static let oldFingerprint = String(repeating: "a", count: 64)
    static let newFingerprint = String(repeating: "b", count: 64)
    static let vault = "12345678-1234-1234-1234-123456789abc"
    static let enrollment = "12345678-1234-1234-1234-123456789def"
    let source: ComponentSource
    let snapshot: CompletedComponentSnapshot

    static func json(_ value: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    static func encoded<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    static func record(_ data: Data, inode: UInt64, mode: UInt16 = 0o600) -> CompletedComponentRecord {
        CompletedComponentRecord(data: data, object: ComponentObject(device: 7, inode: inode, mode: mode,
            bytes: Int64(data.count), sha256: ComponentFiles.digest(data)))
    }
    static func object(_ value: ComponentObject) throws -> [String: Any] {
        guard let result = try JSONSerialization.jsonObject(with: encoded(value)) as? [String: Any] else {
            throw PredecessorFixtureFailure.failed
        }
        return result
    }
    static func manifest(_ files: [String: Data]) throws -> InstallerPayloadManifest {
        let directory: [String: Any] = ["kind": "directory", "mode": 0o755]
        var rows: [String: [String: Any]] = ["": directory]
        var values = files
        values["owner.app/Contents/MacOS/AccountAccess"] = Data("fictional-not-executed".utf8)
        for (name, data) in values {
            let parts = name.split(separator: "/").map(String.init)
            if parts.count > 1 {
                for index in 1..<parts.count { rows[parts.prefix(index).joined(separator: "/")] = directory }
            }
            rows[name] = ["kind": "file", "mode": name.hasPrefix("bin/") ? 0o755 : 0o644,
                "size": data.count, "sha256": ComponentFiles.digest(data)]
        }
        return try InstallerPayloadManifest(json(["schema": 1, "managed_by": "account-access-install-payload-v1",
            "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
            "roots": [InstallerPayloadManifest.support: rows,
                InstallerPayloadManifest.application: ["": ["kind": "symlink", "target": InstallerPayloadManifest.applicationTarget]]]]))
    }
    init() throws {
        let team = "WBULD6N4NQ", base = InstallerPayloadManifest.support
        let oldPeers = ["owner": ComponentPeerSignature(team: team, identifier: "com.fainir.accountaccess", hashes: [String(repeating: "1", count: 40)]),
            "broker": ComponentPeerSignature(team: team, identifier: "com.fainir.accountaccess.broker", hashes: [String(repeating: "2", count: 40)]),
            "bootstrap": ComponentPeerSignature(team: team, identifier: "com.fainir.accountaccess.bootstrap", hashes: [String(repeating: "3", count: 40)])]
        var newPeers = oldPeers
        newPeers["broker"] = ComponentPeerSignature(team: team, identifier: "com.fainir.accountaccess.broker", hashes: [String(repeating: "4", count: 40), String(repeating: "5", count: 40)])
        newPeers["bootstrap"] = ComponentPeerSignature(team: team, identifier: "com.fainir.accountaccess.bootstrap", hashes: [String(repeating: "6", count: 40), String(repeating: "7", count: 40)])
        let paths = ComponentSource.allowed.sorted()
        let added: Set<String> = [ComponentSource.site + "account_access/listener_binding.py", "component-identity.json"]
        var oldFiles: [String: Data] = [:], newFiles: [String: Data] = [:]
        for path in paths {
            if !added.contains(path) { oldFiles[path] = Data(("old:" + path).utf8) }
            newFiles[path] = Data(("new:" + path).utf8)
        }
        let oldManifest = try Self.manifest(oldFiles), newManifest = try Self.manifest(newFiles)
        let delta = paths.enumerated().map { index, path in
            ComponentSource.Delta(path: path, resource: String(format: "delta-%02d.bin", index),
                before: oldManifest.trees[ComponentSource.support]!.nodes[path],
                after: newManifest.trees[ComponentSource.support]!.nodes[path]!, data: newFiles[path]!)
        }
        source = ComponentSource(oldManifest: oldManifest, newManifest: newManifest, planDigest: Self.plan,
            oldPeers: oldPeers, newPeers: newPeers, oldFingerprint: Self.oldFingerprint,
            newFingerprint: Self.newFingerprint, delta: delta,
            designated: ["broker": "fictional broker requirement", "bootstrap": "fictional bootstrap requirement"])
        let install = try Self.json(["managed_by": "account-access-system-install-v1", "schema": 1,
            "owner_uid": Self.owner, "broker_uid": Self.broker, "broker_name": "_accountaccess", "vault_id": Self.vault,
            "enrollment_id": Self.enrollment, "payload_fingerprint": Self.oldFingerprint])
        let worker = try Self.json(["managed_by": "account-access-worker-v1", "schema": 1,
            "broker_uid": Self.broker, "agent_uid": Self.owner, "root": base + "/vault/data",
            "agent_socket": base + "/run/agent.sock", "owner_socket": base + "/control/owner.sock", "owner_port": 8765])
        let host = try Self.json(["managed_by": "account-access-system-host-v1", "schema": 1,
            "worker_launcher": base + "/broker/worker-launch.json", "enrollment_policy": base + "/broker/enrollment.json",
            "bootstrap": base + "/bin/AccountAccess-bootstrap", "vault_id": Self.vault, "owner_uid": Self.owner,
            "publisher_team": team, "owner_identifier": "com.fainir.accountaccess", "owner_hashes": oldPeers["owner"]!.hashes,
            "bootstrap_identifier": "com.fainir.accountaccess.bootstrap", "bootstrap_hashes": oldPeers["bootstrap"]!.hashes])
        let owner = try Self.json(["managed_by": "account-access-desktop-owner-v1", "schema": 1, "owner_uid": Self.owner,
            "publisher_team": team, "server_identifier": "com.fainir.accountaccess.broker", "server_hashes": oldPeers["broker"]!.hashes])
        let policy = try ComponentUpdatePolicies.derive(install: install, host: host, owner: owner, worker: worker,
            oldPeers: oldPeers, newPeers: newPeers, oldFingerprint: Self.oldFingerprint,
            newFingerprint: Self.newFingerprint, consoleOwner: Self.owner)
        let service = try PropertyListSerialization.data(fromPropertyList: ["Label": "com.fainir.accountaccess.broker",
            "AssociatedBundleIdentifiers": ["com.fainir.accountaccess"], "ProgramArguments": [base + "/bin/AccountAccess-broker"],
            "UserName": "root", "GroupName": "wheel", "RunAtLoad": true, "KeepAlive": false, "AbandonProcessGroup": false,
            "ExitTimeOut": 20, "Umask": 0o077, "ProcessType": "Background", "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
            "MachServices": ["com.fainir.accountaccess.broker.owner": true],
            "Sockets": ["AccountAccessAgent": ["SockPathName": base + "/run/agent.sock", "SockPathOwner": 0,
                "SockPathGroup": 20, "SockPathMode": 0o660],
                "AccountAccessOwner": ["SockPathName": base + "/control/owner.sock", "SockPathOwner": 0,
                    "SockPathGroup": 0, "SockPathMode": 0o600]]], format: .xml, options: 0)
        let workerRecord = Self.record(worker, inode: 800, mode: 0o644)
        let serviceRecord = try ComponentController.fixtureCompletedServiceRecord(
            support: Self.record(service, inode: 1801, mode: 0o644),
            validatedGlobal: Self.record(service, inode: 801, mode: 0o644))
        let head = try Self.json(["schema": 1, "managed_by": "account-access-component-head-v1", "plan_sha256": Self.plan,
            "base_manifest_sha256": oldManifest.sha256, "manifest_sha256": newManifest.sha256,
            "state": "public_image_verified_gui_unverified", "automatic_reboot_recovery": false])
        var operations: [ComponentOperation] = [], records: [String: CompletedComponentRecord] = [:]
        for (index, item) in delta.enumerated() {
            let slot = String(format: "slot-%02d", index)
            let before = oldFiles[item.path].map { Self.record($0, inode: UInt64(500 + index), mode: UInt16(item.before!.mode!)) }
            if let before { records[slot] = before }
            operations.append(ComponentOperation(target: .image, path: item.path, slot: slot, before: before?.object,
                after: Self.record(item.data, inode: UInt64(1000 + index), mode: UInt16(item.after.mode!)).object))
        }
        let dynamic: [(ComponentOperation.Target, String, Data?, Data, UInt16)] = [
            (.hostPolicy, "broker/host.json", host, policy.host, 0o644),
            (.ownerPolicy, "owner.json", owner, policy.owner, 0o644),
            (.installRecord, "broker/install.json", install, policy.install, 0o600),
            (.head, "head.json", nil, head, 0o644)]
        for (offset, item) in dynamic.enumerated() {
            let index = delta.count + offset, slot = String(format: "slot-%02d", index)
            let before = item.2.map { Self.record($0, inode: UInt64(500 + index), mode: item.4) }
            if let before { records[slot] = before }
            operations.append(ComponentOperation(target: item.0, path: item.1, slot: slot, before: before?.object,
                after: Self.record(item.3, inode: UInt64(1000 + index), mode: item.4).object))
        }
        let job = ComponentJobIdentity(pid: 321, group: 321, birthSec: 1_700_000_000, birthUsec: 12345,
            bootSession: "12345678-1234-1234-1234-123456789abc")
        let intent = ComponentTransitionIntent(schema: 1, planSHA256: Self.plan,
            baseManifestSHA256: oldManifest.sha256, targetManifestSHA256: newManifest.sha256,
            operations: operations, ownerUID: Self.owner, brokerUID: Self.broker, service: job,
            workerPolicy: workerRecord.object, servicePlist: serviceRecord.object, automaticRebootRecovery: false)
        records["intent.json"] = Self.record(try Self.encoded(intent), inode: 1500)
        for (index, event) in ["disable_intent_prior_enabled", "disabled_confirmed", "canonical_job_bootstrapped_gui_unverified"].enumerated() {
            records[String(format: "service-%04d.json", index)] = Self.record(try Self.json(["schema": 1,
                "event": event, "plan_sha256": Self.plan]), inode: UInt64(1600 + index))
        }
        for index in operations.indices {
            for (offset, event) in ["apply_intent", "applied"].enumerated() {
                let sequence = 2 * index + offset
                records[String(format: "event-%04d.json", sequence)] = Self.record(try Self.json(["schema": 1,
                    "event": event, "operation": index]), inode: UInt64(1700 + sequence))
            }
        }
        records["event-0026.json"] = Self.record(try Self.json(["schema": 1,
            "event": "new_image_verified_gui_unverified", "operation": -1]), inode: 1726)
        records["job-0000.json"] = Self.record(try Self.json(["schema": 1, "planSHA256": Self.plan,
            "job": ["pid": job.pid, "group": job.group, "birthSec": job.birthSec,
                "birthUsec": job.birthUsec, "bootSession": job.bootSession]]), inode: 1800)
        let ready = try Self.json(["manifest_sha256": oldManifest.sha256,
            "roots": [InstallerPayloadManifest.support: [7, 100], InstallerPayloadManifest.application: [7, 200]]])
        let original = [
            "intent.json": Self.record(try Self.json(["managed_by": "account-access-public-image-install-v1", "schema": 1,
                "manifest_sha256": oldManifest.sha256, "owner_uid": Self.owner]), inode: 400),
            "complete.json": Self.record(try Self.json(["manifest_sha256": oldManifest.sha256,
                "owner_uid": Self.owner, "status": "REGISTERED"]), inode: 401),
            "ready.json": Self.record(ready, inode: 402), "published.json": Self.record(ready, inode: 403)]
        snapshot = CompletedComponentSnapshot(ownerUID: Self.owner, ownerGroup: 20,
            roots: ["original": CompletedComponentDirectory(device: 7, inode: 101, owner: 0, group: 0, mode: 0o700),
                    "components": CompletedComponentDirectory(device: 7, inode: 102, owner: 0, group: 0, mode: 0o700),
                    "transition": CompletedComponentDirectory(device: 7, inode: 103, owner: 0, group: 0, mode: 0o700)],
            namespaceNames: ["head.json", "transition-" + Self.plan].sorted(), original: original,
            rootBindingSHA256: String(repeating: "d", count: 64), records: records,
            head: Self.record(head, inode: 1012, mode: 0o644), worker: workerRecord, service: serviceRecord)
    }
}

typealias PredecessorFixture = CompletedPredecessorFixture

struct CompletedPredecessorSnapshotBuilder {
    var ownerUID: uid_t, ownerGroup: gid_t
    var roots: [String: CompletedComponentDirectory]
    var namespaceNames: [String]
    var original: [String: CompletedComponentRecord]
    var rootBindingSHA256: String
    var records: [String: CompletedComponentRecord]
    var head: CompletedComponentRecord, worker: CompletedComponentRecord, service: CompletedComponentRecord
    init(_ value: CompletedComponentSnapshot) {
        ownerUID = value.ownerUID; ownerGroup = value.ownerGroup; roots = value.roots; namespaceNames = value.namespaceNames
        original = value.original; rootBindingSHA256 = value.rootBindingSHA256; records = value.records
        head = value.head; worker = value.worker; service = value.service
    }
    var value: CompletedComponentSnapshot {
        CompletedComponentSnapshot(ownerUID: ownerUID, ownerGroup: ownerGroup, roots: roots, namespaceNames: namespaceNames,
            original: original, rootBindingSHA256: rootBindingSHA256, records: records, head: head, worker: worker, service: service)
    }
    mutating func intent(_ change: (inout [String: Any]) -> Void) throws {
        let saved = records["intent.json"]!
        guard var object = try JSONSerialization.jsonObject(with: saved.data) as? [String: Any] else { throw PredecessorFixtureFailure.failed }
        change(&object)
        records["intent.json"] = PredecessorFixture.record(try PredecessorFixture.json(object), inode: saved.object.inode)
    }
    mutating func intentOperation(_ index: Int, _ change: (inout [String: Any]) -> Void) throws {
        try intent { value in
            var operations = value["operations"] as! [[String: Any]]
            change(&operations[index]); value["operations"] = operations
        }
    }
    mutating func rawIntent(_ data: Data) {
        records["intent.json"] = PredecessorFixture.record(data, inode: records["intent.json"]!.object.inode)
    }
}

typealias PredecessorSnapshotBuilder = CompletedPredecessorSnapshotBuilder

#if ACCOUNT_ACCESS_COMPONENT_PREDECESSOR_FIXTURE_MAIN
@main struct CompletedComponentPredecessorChecks {
    private static var checks: [String: Bool] = [:]
    private static func expect(_ value: Bool, _ name: String) throws {
        checks[name] = value
        guard value else {
            FileHandle.standardError.write(Data(("predecessor_fixture_failed:" + name + "\n").utf8))
            throw PredecessorFixtureFailure.failed
        }
    }
    private static func refuses(_ name: String, _ body: () throws -> Void) throws {
        var refused = false
        do { try body() } catch { refused = true }
        try expect(refused, name)
    }
    private static func changed(_ base: CompletedComponentSnapshot, _ change: (inout PredecessorSnapshotBuilder) throws -> Void) rethrows -> CompletedComponentSnapshot {
        var builder = PredecessorSnapshotBuilder(base); try change(&builder); return builder.value
    }
    private static func source(_ base: ComponentSource, plan: String? = nil, oldPeers: [String: ComponentPeerSignature]? = nil,
        newPeers: [String: ComponentPeerSignature]? = nil, delta: [ComponentSource.Delta]? = nil, oldFingerprint: String? = nil) -> ComponentSource {
        ComponentSource(oldManifest: base.oldManifest, newManifest: base.newManifest, planDigest: plan ?? base.planDigest,
            oldPeers: oldPeers ?? base.oldPeers, newPeers: newPeers ?? base.newPeers, oldFingerprint: oldFingerprint ?? base.oldFingerprint,
            newFingerprint: base.newFingerprint, delta: delta ?? base.delta, designated: base.designated)
    }
    static func main() {
        guard getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 1 else { exit(77) }
        do {
            for recovery in [false, true] {
                var refusedBeforeRead = false
                do {
                    if recovery {
                        _ = try ComponentController.revalidateCompletedPredecessor(resources: -1,
                            planPin: String(repeating: "a", count: 64), expectedEvidence: Data("x".utf8))
                    } else {
                        _ = try ComponentController.initialCompletedPredecessor(resources: -1,
                            planPin: String(repeating: "a", count: 64))
                    }
                } catch ComponentUpdateFailure.context { refusedBeforeRead = true }
                catch { refusedBeforeRead = false }
                try expect(refusedBeforeRead, recovery ? "ordinary_recovery_refuses_before_native_reads" : "ordinary_initial_refuses_before_native_reads")
            }
            let fixture = try PredecessorFixture(), base = fixture.snapshot
            // Identify failed comparisons without publishing record values.
            // A changed runtime device still refuses: diagnostics do not grant
            // authority to normalize historical state or bypass a binding.
            for (name, expected, mutate) in [
                ("worker", CompletedPredecessorCheckpoint.workerBinding, { (b: inout PredecessorSnapshotBuilder) in
                    let old = b.worker
                    b.worker = CompletedComponentRecord(data: old.data, object: ComponentObject(device: 8,
                        inode: old.object.inode, mode: old.object.mode, bytes: old.object.bytes, sha256: old.object.sha256))
                }),
                ("service", CompletedPredecessorCheckpoint.serviceBinding, { (b: inout PredecessorSnapshotBuilder) in
                    let old = b.service
                    b.service = CompletedComponentRecord(data: old.data, object: ComponentObject(device: 8,
                        inode: old.object.inode, mode: old.object.mode, bytes: old.object.bytes, sha256: old.object.sha256))
                }),
                ("head", CompletedPredecessorCheckpoint.head, { (b: inout PredecessorSnapshotBuilder) in
                    b.head = PredecessorFixture.record(b.head.data, inode: 9999, mode: 0o644)
                }),
                ("journal", CompletedPredecessorCheckpoint.journal, { (b: inout PredecessorSnapshotBuilder) in
                    b.records.removeValue(forKey: "service-0002.json")
                }),
            ] {
                let invalid = changed(base, mutate)
                var observed: CompletedPredecessorCheckpoint?
                do {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source,
                        read: { invalid }, verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial })
                } catch let failure as CompletedPredecessorDiagnostic {
                    observed = failure.checkpoint
                    try expect(failure.failure is ComponentUpdateFailure, "diagnostic_preserves_" + name + "_refusal")
                }
                try expect(observed == expected, "diagnostic_identifies_" + name + "_binding")
            }
            var diagnosticRead = 0
            var secondReadDiagnosed = false
            do {
                _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source,
                    read: { diagnosticRead += 1; if diagnosticRead == 2 { throw PredecessorFixtureFailure.read }; return base },
                    verifyInitial: { _, _ in })
            } catch let failure as CompletedPredecessorDiagnostic {
                secondReadDiagnosed = failure.checkpoint == .snapshotAfter && diagnosticRead == 2
            }
            try expect(secondReadDiagnosed, "diagnostic_identifies_second_read")
            var shaContextRefused = false
            do {
                _ = try ComponentController.revalidateCompletedPredecessor(resources: -1,
                    planPin: String(repeating: "a", count: 64), expectedEvidenceSHA256: String(repeating: "b", count: 64))
            } catch ComponentUpdateFailure.context { shaContextRefused = true }
            catch { shaContextRefused = false }
            try expect(shaContextRefused, "ordinary_sha_recovery_refuses_before_native_reads")
            let equalSupport = PredecessorFixture.record(base.service.data, inode: 9999, mode: 0o644)
            let selectedService = try ComponentController.fixtureCompletedServiceRecord(support: equalSupport, validatedGlobal: base.service)
            try expect(equalSupport.object.inode != base.service.object.inode && selectedService.object == base.service.object,
                "equal_service_bytes_preserve_global_object_despite_distinct_inodes")
            try refuses("service_copy_mismatched_bytes_refused") {
                _ = try ComponentController.fixtureCompletedServiceRecord(
                    support: PredecessorFixture.record(Data("different".utf8), inode: 9999, mode: 0o644), validatedGlobal: base.service)
            }
            let badServiceHash = CompletedComponentRecord(data: equalSupport.data,
                object: ComponentObject(device: equalSupport.object.device, inode: equalSupport.object.inode, mode: equalSupport.object.mode,
                    bytes: equalSupport.object.bytes, sha256: String(repeating: "f", count: 64)))
            try refuses("service_copy_mismatched_hash_refused") {
                _ = try ComponentController.fixtureCompletedServiceRecord(support: badServiceHash, validatedGlobal: base.service)
            }
            var reads = 0, initial = 0
            let proof = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { reads += 1; return base },
                verifyInitial: { snapshot, intent in
                    initial += 1
                    try expect(snapshot.ownerUID == 501 && intent.operations.count == 13, "initial_receives_validated_shape")
                })
            try expect(reads == 2 && initial == 1, "initial_reads_twice_and_calls_current_gate_once")
            try expect(!proof.evidence.isEmpty && proof.sha256 == ComponentFiles.digest(proof.evidence), "proof_binds_canonical_evidence")
            var recoveryInitial = 0, recoveryReads = 0
            let recovered = try ComponentController.fixtureCompletedPredecessor(source: fixture.source,
                read: { recoveryReads += 1; return base }, verifyInitial: { _, _ in
                    recoveryInitial += 1; throw PredecessorFixtureFailure.initial
                }, expectedEvidence: proof.evidence)
            try expect(recovered.evidence == proof.evidence && recovered.sha256 == proof.sha256 && recoveryReads == 2 && recoveryInitial == 0,
                "stable_recovery_uses_immutable_evidence_without_current_image_gate")
            var shaInitial = 0, shaReads = 0
            let shaRecovered = try ComponentController.fixtureCompletedPredecessor(source: fixture.source,
                read: { shaReads += 1; return base }, verifyInitial: { _, _ in
                    shaInitial += 1; throw PredecessorFixtureFailure.initial
                }, expectedEvidenceSHA256: proof.sha256)
            try expect(shaRecovered.evidence == proof.evidence && shaReads == 2 && shaInitial == 0,
                "sha_recovery_recomputes_evidence_without_current_image_gate")
            // Original213 mkdir preserves each parent's group. Different
            // protected root groups are legitimate metadata, never authority
            // to relax ownership/mode or alter a historical directory.
            let mixedGroups = changed(base) { builder in
                for (name, group) in [("original", UInt32(0)), ("components", UInt32(80)), ("transition", UInt32(20))] {
                    let root = builder.roots[name]!
                    builder.roots[name] = CompletedComponentDirectory(device: root.device, inode: root.inode,
                        owner: root.owner, group: group, mode: root.mode)
                }
            }
            var mixedInitial = 0
            let mixedProof = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { mixedGroups },
                verifyInitial: { _, _ in mixedInitial += 1 })
            let mixedEvidence = try JSONSerialization.jsonObject(with: mixedProof.evidence) as! [String: Any]
            let mixedRoots = mixedEvidence["roots"] as! [String: [String: Any]]
            try expect(mixedInitial == 1 && mixedProof.evidence != proof.evidence &&
                mixedRoots["original"]?["group"] as? Int == 0 && mixedRoots["components"]?["group"] as? Int == 80 &&
                mixedRoots["transition"]?["group"] as? Int == 20,
                "mixed_inherited_directory_groups_initial_proof_preserves_actual_metadata")
            let mixedRecovered = try ComponentController.fixtureCompletedPredecessor(source: fixture.source,
                read: { mixedGroups }, verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial },
                expectedEvidence: mixedProof.evidence)
            try expect(mixedRecovered.evidence == mixedProof.evidence,
                "stable_mixed_directory_groups_data_recovery_preserves_exact_evidence")
            let mixedSHARecovered = try ComponentController.fixtureCompletedPredecessor(source: fixture.source,
                read: { mixedGroups }, verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial },
                expectedEvidenceSHA256: mixedProof.sha256)
            try expect(mixedSHARecovered.sha256 == mixedProof.sha256,
                "stable_mixed_directory_groups_sha_recovery_preserves_exact_evidence")
            for name in ["original", "components", "transition"] {
                let changedGroup = changed(mixedGroups) { builder in
                    let root = builder.roots[name]!
                    builder.roots[name] = CompletedComponentDirectory(device: root.device, inode: root.inode,
                        owner: root.owner, group: root.group + 1, mode: root.mode)
                }
                try refuses("changed_" + name + "_directory_group_data_recovery_refused") {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { changedGroup },
                        verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial }, expectedEvidence: mixedProof.evidence)
                }
                try refuses("changed_" + name + "_directory_group_sha_recovery_refused") {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { changedGroup },
                        verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial }, expectedEvidenceSHA256: mixedProof.sha256)
                }
            }
            var mixedReads = 0
            try refuses("changed_directory_group_between_snapshots_refused") {
                _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source,
                    read: { mixedReads += 1; return mixedReads == 1 ? base : mixedGroups }, verifyInitial: { _, _ in })
            }
            try expect(mixedReads == 2, "both_directory_group_snapshot_reads_reached")
            for (name, root) in [
                ("nonroot_owner_with_inherited_group", CompletedComponentDirectory(device: 7, inode: 103, owner: 501, group: 20, mode: 0o700)),
                ("wrong_mode_with_inherited_group", CompletedComponentDirectory(device: 7, inode: 103, owner: 0, group: 20, mode: 0o720))
            ] {
                let invalid = changed(mixedGroups) { $0.roots["transition"] = root }
                try refuses(name + "_refused") {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { invalid },
                        verifyInitial: { _, _ in })
                }
            }
            var forgedEvidence = mixedEvidence
            var forgedRoots = mixedRoots
            forgedRoots["components"]?["group"] = 0
            forgedEvidence["roots"] = forgedRoots
            let forgedBytes = try PredecessorFixture.json(forgedEvidence)
            try refuses("reforged_expected_evidence_directory_group_refused") {
                _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { mixedGroups },
                    verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial }, expectedEvidence: forgedBytes)
            }
            for (index, digest) in ["", String(repeating: "A", count: 64), String(repeating: "x", count: 64),
                                     String(repeating: "a", count: 63), String(repeating: "f", count: 64)].enumerated() {
                try refuses("invalid_or_foreign_expected_sha_\(index)_refused") {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { base },
                        verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial }, expectedEvidenceSHA256: digest)
                }
            }
            try refuses("ambiguous_data_and_sha_expectation_refused") {
                _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { base },
                    verifyInitial: { _, _ in }, expectedEvidence: proof.evidence, expectedEvidenceSHA256: proof.sha256)
            }
            try refuses("foreign_expected_evidence_refused") {
                _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { base },
                    verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial }, expectedEvidence: Data("foreign".utf8))
            }
            try refuses("initial_current_gate_refusal_prevents_proof") {
                _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { base },
                    verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial })
            }
            let mutations: [(String, (inout PredecessorSnapshotBuilder) throws -> Void)] = [
                ("changed_original_receipt", { b in
                    let old = b.original["intent.json"]!
                    b.original["intent.json"] = PredecessorFixture.record(old.data + Data(" ".utf8), inode: old.object.inode)
                }),
                ("missing_original_receipt", { $0.original.removeValue(forKey: "published.json") }),
                ("changed_protected_root_inode", { $0.roots["transition"] = CompletedComponentDirectory(device: 7, inode: 999, owner: 0, group: 0, mode: 0o700) }),
                ("writable_protected_root", { $0.roots["transition"] = CompletedComponentDirectory(device: 7, inode: 103, owner: 0, group: 0, mode: 0o722) }),
                ("foreign_protected_root_owner", { $0.roots["transition"] = CompletedComponentDirectory(device: 7, inode: 103, owner: 501, group: 0, mode: 0o700) }),
                ("mixed_protected_root_devices", { $0.roots["transition"] = CompletedComponentDirectory(device: 8, inode: 103, owner: 0, group: 0, mode: 0o700) }),
                ("changed_root_binding", { $0.rootBindingSHA256 = String(repeating: "e", count: 64) }),
                ("malformed_root_binding", { $0.rootBindingSHA256 = "*" }),
                ("changed_namespace_inventory", { $0.namespaceNames = ["head.json", "unreviewed"] }),
                ("duplicate_namespace_member", { $0.namespaceNames.append("head.json") }),
                ("changed_head", { $0.head = PredecessorFixture.record(Data("other".utf8), inode: 1012, mode: 0o644) }),
                ("changed_retained_before_slot", { $0.records["slot-00"] = PredecessorFixture.record(Data("other".utf8), inode: $0.records["slot-00"]!.object.inode, mode: $0.records["slot-00"]!.object.mode) }),
                ("missing_retained_before_slot", { $0.records.removeValue(forKey: "slot-00") }),
                ("unknown_journal_member", { $0.records["unexpected.json"] = PredecessorFixture.record(Data("{}".utf8), inode: 1900) }),
                ("changed_journal_bytes", { b in
                    let old = b.records["event-0000.json"]!
                    b.records["event-0000.json"] = PredecessorFixture.record(old.data + Data(" ".utf8), inode: old.object.inode)
                }),
                ("missing_completion_audit", { $0.records.removeValue(forKey: "service-0002.json") }),
                ("incomplete_completion_audit", { $0.records["service-0002.json"] = PredecessorFixture.record(Data("{".utf8), inode: 1602) }),
                ("foreign_completion_plan", { $0.records["service-0002.json"] = PredecessorFixture.record(try PredecessorFixture.json(["schema": 1, "event": "canonical_job_bootstrapped_gui_unverified", "plan_sha256": String(repeating: "f", count: 64)]), inode: 1602) }),
                ("changed_worker", { $0.worker = PredecessorFixture.record(Data("other".utf8), inode: 800, mode: 0o644) }),
                ("changed_service", { $0.service = PredecessorFixture.record(Data("other".utf8), inode: 801, mode: 0o644) }),
                ("changed_owner", { $0.ownerUID = 502 }),
                ("changed_owner_group", { $0.ownerGroup = 21 }),
                ("unknown_intent_member", { try $0.intent { $0["unreviewed"] = true } }),
                ("boolean_intent_schema", { try $0.intent { $0["schema"] = true } }),
                ("fractional_owner_uid", { try $0.intent { $0["ownerUID"] = 501.5 } }),
                ("boolean_broker_uid", { try $0.intent { $0["brokerUID"] = true } }),
                ("automatic_reboot_recovery", { try $0.intent { $0["automaticRebootRecovery"] = true } }),
                ("unknown_operation_slot", { try $0.intentOperation(0) { $0["slot"] = "../slot-00" } }),
                ("unreviewed_operation_path", { try $0.intentOperation(0) { $0["path"] = "vault/data/identity.json" } }),
                ("wrong_operation_target", { try $0.intentOperation(0) { $0["target"] = "ownerPolicy" } }),
                ("negative_operation_size", { try $0.intentOperation(0) { operation in var after = operation["after"] as! [String: Any]; after["bytes"] = -1; operation["after"] = after } }),
                ("boolean_operation_inode", { try $0.intentOperation(0) { operation in var after = operation["after"] as! [String: Any]; after["inode"] = true; operation["after"] = after } }),
                ("foreign_job_snapshot", { b in
                    try b.intent { intent in var job = intent["service"] as! [String: Any]; job["group"] = 322; intent["service"] = job }
                }),
            ]
            let immutableOnly: Set<String> = ["changed_original_receipt", "changed_protected_root_inode",
                "changed_root_binding", "changed_journal_bytes", "changed_owner_group"]
            for (name, mutate) in mutations {
                let snapshot = try changed(base, mutate)
                try refuses(name + "_refused") {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { snapshot },
                        verifyInitial: { _, _ in }, expectedEvidence: immutableOnly.contains(name) ? proof.evidence : nil)
                }
            }
            for member in ["\"inode\":1000,", "\"in\\u006fde\":1000,"] {
                var builder = PredecessorSnapshotBuilder(base)
                var text = String(decoding: builder.records["intent.json"]!.data, as: UTF8.self)
                guard let range = text.range(of: "\"after\":{") else { throw PredecessorFixtureFailure.failed }
                text.replaceSubrange(range, with: "\"after\":{" + member)
                builder.rawIntent(Data(text.utf8))
                try refuses(member.contains("\\u") ? "escaped_nested_duplicate_refused" : "plain_nested_duplicate_refused") {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { builder.value }, verifyInitial: { _, _ in })
                }
            }
            var policy = PredecessorSnapshotBuilder(base)
            let saved = policy.records["slot-11"]!
            var changedInstall = try JSONSerialization.jsonObject(with: saved.data) as! [String: Any]
            changedInstall["vault_id"] = "not-a-uuid"
            let malformedPolicy = PredecessorFixture.record(try PredecessorFixture.json(changedInstall), inode: saved.object.inode, mode: saved.object.mode)
            policy.records["slot-11"] = malformedPolicy
            let malformedPolicyObject = try PredecessorFixture.object(malformedPolicy.object)
            try policy.intentOperation(11) { $0["before"] = malformedPolicyObject }
            try refuses("typed_retained_policy_refused_even_with_updated_object_pins") {
                _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { policy.value }, verifyInitial: { _, _ in })
            }
            let changedSources = [
                ("changed_source_plan", source(fixture.source, plan: String(repeating: "f", count: 64))),
                ("malformed_source_plan", source(fixture.source, plan: "*")),
                ("missing_source_delta", source(fixture.source, delta: Array(fixture.source.delta.dropLast()))),
                ("reordered_source_delta", source(fixture.source, delta: Array(fixture.source.delta.reversed()))),
                ("changed_source_fingerprint", source(fixture.source, oldFingerprint: String(repeating: "f", count: 64)))
            ]
            for (name, changedSource) in changedSources {
                try refuses(name + "_refused") {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: changedSource, read: { base },
                        verifyInitial: { _, _ in })
                }
            }
            let badEvents: [(String, [String: Any])] = [
                ("foreign_event_name", ["schema": 1, "event": "unreviewed", "operation": 0]),
                ("foreign_event_member", ["schema": 1, "event": "applied", "operation": 0, "unreviewed": true]),
                ("invalid_event_operation", ["schema": 1, "event": "applied", "operation": 13]),
                ("invalid_negative_event_operation", ["schema": 1, "event": "applied", "operation": -2]),
                ("boolean_event_schema", ["schema": true, "event": "applied", "operation": 0]),
                ("fractional_event_operation", ["schema": 1, "event": "applied", "operation": 0.5]),
                ("boolean_event_operation", ["schema": 1, "event": "applied", "operation": false]),
                ("per_operation_event_with_global_discriminator", ["schema": 1, "event": "applied", "operation": -1]),
                ("new_image_global_event_with_operation_discriminator", ["schema": 1, "event": "new_image_verified_gui_unverified", "operation": 0]),
                ("old_image_global_event_with_operation_discriminator", ["schema": 1, "event": "old_image_restored", "operation": 0])
            ]
            for (name, event) in badEvents {
                let snapshot = try changed(base) {
                    $0.records["event-0000.json"] = PredecessorFixture.record(try PredecessorFixture.json(event), inode: 1700)
                }
                try refuses(name + "_refused") {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { snapshot }, verifyInitial: { _, _ in })
                }
            }
            for member in ["\"operation\":0,", "\"oper\\u0061tion\":0,"] {
                let data = Data(("{" + member + "\"schema\":1,\"event\":\"applied\",\"operation\":0}").utf8)
                let snapshot = changed(base) { $0.records["event-0000.json"] = PredecessorFixture.record(data, inode: 1700) }
                try refuses(member.contains("\\u") ? "escaped_event_duplicate_refused" : "plain_event_duplicate_refused") {
                    _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { snapshot }, verifyInitial: { _, _ in })
                }
            }
            let incomplete = changed(base) { $0.records["event-0000.json"] = PredecessorFixture.record(Data("{".utf8), inode: 1700) }
            var incompleteInitial = 0
            let incompleteProof = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { incomplete },
                verifyInitial: { _, _ in incompleteInitial += 1 })
            try expect(incompleteInitial == 1 && incompleteProof.evidence != proof.evidence, "incomplete_audit_is_hashed_evidence_not_completion_authority")
            let incompleteRecovery = try ComponentController.fixtureCompletedPredecessor(source: fixture.source, read: { incomplete },
                verifyInitial: { _, _ in throw PredecessorFixtureFailure.initial }, expectedEvidence: incompleteProof.evidence)
            try expect(incompleteRecovery.evidence == incompleteProof.evidence, "stable_incomplete_audit_recovery_preserves_exact_evidence")
            var calls = 0
            let changedBinding = changed(base) { $0.rootBindingSHA256 = String(repeating: "e", count: 64) }
            try refuses("changed_second_snapshot_refused") {
                _ = try ComponentController.fixtureCompletedPredecessor(source: fixture.source,
                    read: { calls += 1; return calls == 1 ? base : changedBinding }, verifyInitial: { _, _ in })
            }
            try expect(calls == 2, "both_snapshot_reads_reached")
            for (name, value) in try FullImagePredecessorAuthorityChecks.run(fixture: fixture, proof: proof) {
                try expect(value, name)
            }
            let report: [String: Any] = ["schema": 1, "status": "PASSED", "count": checks.count, "checks": checks,
                "fictional_in_memory_only": true, "fixture_proof_not_native_qualification": true,
                "installed_reads": false, "root_execution": false, "service_actions": false,
                "provider_process_or_network_used": false, "production_ready": false]
            print(String(decoding: try JSONSerialization.data(withJSONObject: report, options: .sortedKeys), as: UTF8.self))
        } catch {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"predecessor_synthetic_fixture_failed\",\"production_ready\":false}")
            exit(78)
        }
    }
}
#endif
