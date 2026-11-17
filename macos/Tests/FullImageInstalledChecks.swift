// Ordinary invocation-owned temporary roots only. No installed reads, service
// commands, credential inputs, package code or provider operations.
import Foundation
import Darwin
import Security

private enum InstalledFixtureFailure: Error { case failed }
@main struct FullImageInstalledChecks {
    static var checks = 0
    static func expect(_ value: Bool) throws { guard value else { throw InstalledFixtureFailure.failed }; checks += 1 }
    static func refuses(_ body: () throws -> Void) throws {
        var failed = false; do { try body() } catch { failed = true }; try expect(failed)
    }
    static func directory(_ parent: Int32, _ name: String, _ mode: mode_t = 0o700) throws -> Int32 {
        guard mkdirat(parent, name, mode) == 0 else { throw InstalledFixtureFailure.failed }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0, fchmod(fd, mode) == 0, fchown(fd, uid_t.max, getgid()) == 0 else { throw InstalledFixtureFailure.failed }; return fd
    }
    static func path(_ root: Int32, _ value: String) throws -> Int32 {
        var current = dup(root); guard current >= 0 else { throw InstalledFixtureFailure.failed }
        do {
            for name in try InstallerPayloadManifest.components(value) {
                if mkdirat(current, name, 0o755) != 0 && errno != EEXIST { throw InstalledFixtureFailure.failed }
                let next = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0, fchmod(next, 0o755) == 0, fchown(next, uid_t.max, getgid()) == 0 else { throw InstalledFixtureFailure.failed }
                Darwin.close(current); current = next
            }; return current
        } catch { Darwin.close(current); throw error }
    }
    static func acl(_ fd: Int32) throws {
        var value: acl_t? = acl_init(1); guard value != nil else { throw InstalledFixtureFailure.failed }
        defer { if let value { acl_free(UnsafeMutableRawPointer(value)) } }
        var entry: acl_entry_t?, permissions: acl_permset_t?, principal = UUID().uuid
        guard acl_create_entry(&value, &entry) == 0, let value, let entry,
              acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0,
              withUnsafeBytes(of: &principal, { acl_set_qualifier(entry, $0.baseAddress!) }) == 0,
              acl_get_permset(entry, &permissions) == 0, let permissions,
              acl_clear_perms(permissions) == 0, acl_add_perm(permissions, ACL_READ_DATA) == 0,
              acl_set_permset(entry, permissions) == 0, acl_valid(value) == 0,
              acl_set_fd(fd, value) == 0 else { throw InstalledFixtureFailure.failed }
    }
    static func put(_ tree: InstallerPayloadTree, in root: Int32) throws {
        var bytes: [String: Data] = [:]
        for unit in PublicTreeUnit.fullImageCases {
            for prefix in ["old-", "new-"] { let data = Data((prefix + unit.rawValue).utf8); bytes[FullImageJSON.hash(data)] = data }
        }
        for unit in FullImagePlanFileUnit.fullImageCases {
            for prefix in ["old-", "new-"] { let data = Data((prefix + unit.rawValue).utf8); bytes[FullImageJSON.hash(data)] = data }
        }
        let fictional = Data("fictional-owner-not-executed".utf8); bytes[FullImageJSON.hash(fictional)] = fictional
        for (name, node) in tree.nodes.sorted(by: { $0.key.count < $1.key.count }) where !name.isEmpty {
            if node.kind == "directory" { let made = try path(root, name); Darwin.close(made) }
            else {
                let parts = name.split(separator: "/").map(String.init)
                let parent = try path(root, parts.dropLast().joined(separator: "/")); defer { Darwin.close(parent) }
                if node.kind == "file" {
                    guard let data = bytes[node.sha256!] else { throw InstalledFixtureFailure.failed }
                    _ = try ComponentFiles.writeExclusive(parent, parts.last!, data: data, owner: getuid(), mode: node.mode!)
                } else { guard symlinkat(node.target!, parent, parts.last!) == 0 else { throw InstalledFixtureFailure.failed } }
            }
        }
    }
    static func copyInventory(_ source: FullImageSource) throws -> PublicTreeInventory {
        var rows: [String: [String: Any]] = [:]
        for (name, node) in source.after.trees[InstallerPayloadManifest.support]!.nodes {
            if node.kind == "file" { rows[name] = ["kind": node.kind, "mode": node.mode!, "size": node.size!, "sha256": node.sha256!] }
            else if node.kind == "directory" { rows[name] = ["kind": node.kind, "mode": node.mode!] }
            else { rows[name] = ["kind": node.kind, "target": node.target!] }
        }
        rows["owner.app/alias.txt"] = ["kind": "symlink", "target": "entry.txt"]
        let value: [String: Any] = ["schema": 1, "managed_by": "account-access-install-payload-v1",
            "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
            "roots": [InstallerPayloadManifest.support: rows,
                InstallerPayloadManifest.application: ["": ["kind": "symlink", "target": InstallerPayloadManifest.applicationTarget]]]]
        return try PublicTreeInventory(validatedManifest: InstallerPayloadManifest(FullImageJSON.encode(value)), unit: .owner)
    }
    static func aliasRepairChecks(_ root: Int32) throws {
        let support = try directory(root, "runtime-alias-repair", 0o755); defer { Darwin.close(support) }
        var nodes: [String: InstallerPayloadNode] = [:]
        for (relative, target) in RuntimePublicAliasPermissions.targets.sorted(by: { $0.key < $1.key }) {
            let pieces = relative.split(separator: "/").map(String.init)
            let parent = try path(support, pieces.dropLast().joined(separator: "/")); defer { Darwin.close(parent) }
            var info = stat()
            if fstatat(parent, target, &info, AT_SYMLINK_NOFOLLOW) != 0 {
                _ = try ComponentFiles.writeExclusive(parent, target, data: Data("fictional-runtime-target".utf8), owner: getuid(), mode: 0o644)
            }
            guard symlinkat(target, parent, pieces.last!) == 0 else { throw InstalledFixtureFailure.failed }
            nodes[relative] = InstallerPayloadNode(kind: "symlink", mode: nil, size: nil, sha256: nil, target: target)
        }
        let tree = InstallerPayloadTree(nodes: nodes, children: [:])
        let paths = nodes.keys.sorted(), first = paths.first!, last = paths.last!
        func parentOf(_ relative: String) throws -> Int32 {
            try path(support, relative.split(separator: "/").dropLast().joined(separator: "/"))
        }
        func linkMode(_ relative: String, set mode: mode_t? = nil) throws -> mode_t {
            let parent = try parentOf(relative); defer { Darwin.close(parent) }
            let fd = openat(parent, String(relative.split(separator: "/").last!), O_RDONLY | O_SYMLINK | O_CLOEXEC)
            guard fd >= 0 else { throw InstalledFixtureFailure.failed }; defer { Darwin.close(fd) }
            if let mode { guard fchmod(fd, mode) == 0 else { throw InstalledFixtureFailure.failed } }
            var value = stat(); guard fstat(fd, &value) == 0 else { throw InstalledFixtureFailure.failed }
            return value.st_mode & 0o7777
        }
        func reset() throws { for relative in paths { _ = try linkMode(relative, set: 0o700) } }
        func repair(_ binding: () throws -> Void = {}) throws -> Int {
            try RuntimePublicAliasPermissions.repair(support: support, tree: tree, owner: getuid(), group: getgid(), verifyBinding: binding)
        }
        try expect(paths.count == 20)
        for relative in paths { try expect(try linkMode(relative) == 0o700) }
        try expect(try repair() == 20)
        for relative in paths { try expect(try linkMode(relative) == 0o755) }
        try expect(try repair() == 0)
        _ = try linkMode(first, set: 0o700)
        try expect(try repair() == 1)
        try reset()
        _ = try linkMode(last, set: 0o777)
        try refuses { _ = try repair() }
        try expect(try linkMode(first) == 0o700)
        _ = try linkMode(last, set: 0o700)
        var extra = nodes
        extra["runtime/bin/unreviewed"] = InstallerPayloadNode(kind: "symlink", mode: nil, size: nil, sha256: nil, target: "python3.12")
        try refuses { _ = try RuntimePublicAliasPermissions.repair(support: support,
            tree: InstallerPayloadTree(nodes: extra, children: [:]), owner: getuid(), group: getgid(), verifyBinding: {}) }
        try expect(try linkMode(first) == 0o700)
        try refuses { _ = try RuntimePublicAliasPermissions.repair(support: support, tree: tree,
            owner: getuid(), group: getgid() + 1, verifyBinding: {}) }
        try refuses { _ = try repair { throw InstalledFixtureFailure.failed } }
        try expect(try linkMode(first) == 0o700)
        let lastParent = try parentOf(last); defer { Darwin.close(lastParent) }
        let lastName = String(last.split(separator: "/").last!)
        guard unlinkat(lastParent, lastName, 0) == 0, symlinkat("unreviewed-target", lastParent, lastName) == 0 else {
            throw InstalledFixtureFailure.failed
        }
        try refuses { _ = try repair() }
        try expect(try linkMode(first) == 0o700)
        guard unlinkat(lastParent, lastName, 0) == 0,
              symlinkat(RuntimePublicAliasPermissions.targets[last]!, lastParent, lastName) == 0 else { throw InstalledFixtureFailure.failed }
        var calls = 0
        try refuses { _ = try repair {
            calls += 1
            if calls == 3 { throw InstalledFixtureFailure.failed } // One completed mode change.
        } }
        try expect(try linkMode(first) == 0o755 && linkMode(last) == 0o700)
        try expect(try repair() == 19)
        try expect(try repair() == 0)
        try reset()
        calls = 0
        try refuses { _ = try repair {
            calls += 1
            if calls == 2 {
                guard unlinkat(lastParent, lastName, 0) == 0,
                      symlinkat(RuntimePublicAliasPermissions.targets[last]!, lastParent, lastName) == 0 else {
                    throw InstalledFixtureFailure.failed
                }
            }
        } }
        try expect(try linkMode(first) == 0o700)
        try expect(try repair() == 20)
        for relative in paths {
            let parent = try parentOf(relative); defer { Darwin.close(parent) }
            let target = RuntimePublicAliasPermissions.targets[relative]!
            let value = try ComponentFiles.read(parent, target, owner: getuid(), mode: 0o644)
            try expect(value.0 == Data("fictional-runtime-target".utf8))
        }
    }
    static func main() {
        guard getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 1 else { exit(77) }
        umask(0o077)
        do {
            var template = Array("/private/tmp/account-access-installed-adapter-XXXXXX".utf8CString)
            let ownedPath = try template.withUnsafeMutableBufferPointer { value -> String in
                guard let result = mkdtemp(value.baseAddress!) else { throw InstalledFixtureFailure.failed }; return String(cString: result)
            }
            let root = open(ownedPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0, fchmod(root, 0o700) == 0, fchown(root, uid_t.max, getgid()) == 0 else { throw InstalledFixtureFailure.failed }
            defer { Darwin.close(root) }
            let original = try PublicTreeDirectoryIdentity.observe(root, owner: getuid(), group: getgid())
            let source = try FullImageInstalledSourceFixture.source()
            try refuses { _ = try ComponentController.runFullImage(resources: -1, pins: source.pins) }
            var checkpoints: [FullImageInstallCheckpoint] = []
            try refuses { _ = try ComponentController.runFullImage(resources: -1, pins: source.pins, checkpoint: { checkpoints.append($0) }) }
            try expect(checkpoints == [.context])
            for category in CompletedPredecessorCheckpoint.allCases {
                let privateFailure = NSError(domain: "fictional-private-path-and-record", code: 123,
                    userInfo: [NSLocalizedDescriptionKey: "fictional-private-account-value"])
                let result = FullImageUpdateMain.refusal(
                    CompletedPredecessorDiagnostic(checkpoint: category, failure: privateFailure), checkpoint: .predecessor)
                let data = try JSONSerialization.jsonObject(with: Data(result.utf8)) as! [String: Any]
                try expect(Set(data.keys) == ["schema", "status", "reason", "checkpoint"])
                try expect(data["status"] as? String == "REFUSED"
                    && data["reason"] as? String == "full_image_update_unavailable"
                    && data["checkpoint"] as? String == "predecessor_" + category.rawValue)
                try expect(!result.contains("fictional-private"))
            }
            let fixedRefusal = FullImageUpdateMain.refusal(
                CompletedPredecessorDiagnostic(checkpoint: .workerBinding, failure: ComponentUpdateFailure.journal),
                checkpoint: .predecessor)
            try expect(fixedRefusal.contains("component_transition_conflict") && fixedRefusal.contains("predecessor_worker_binding"))
            let privateError = NSError(domain: "fictional-private-path", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "fictional-private-record"])
            let nestedCases: [(Error, String, String)] = [
                (privateError, "migration", "broker_repair_not_verified"),
                (CompletedFullImageDiagnostic(checkpoint: .journal, failure: FullImageFailure.journal),
                 "predecessor_full_image_journal", "full_image_transition_conflict"),
                (CompletedFullImageDiagnostic(checkpoint: .predecessor,
                    failure: CompletedPredecessorDiagnostic(checkpoint: .workerBinding, failure: privateError)),
                 "predecessor_component_worker_binding", "broker_repair_not_verified"),
                (CompletedFullImageDiagnostic(checkpoint: .predecessor,
                    failure: CompletedPredecessorDiagnostic(checkpoint: .expectedEvidence, failure: ComponentUpdateFailure.journal)),
                 "predecessor_component_expected_evidence", "component_transition_conflict"),
            ]
            for (failure, category, reason) in nestedCases {
                let text = BrokerRepairMain.refusal(failure, checkpoint: .migration)
                let value = try JSONSerialization.jsonObject(with: Data(text.utf8)) as! [String: Any]
                try expect(Set(value.keys) == ["schema", "status", "reason", "checkpoint"]
                    && value["status"] as? String == "REFUSED" && value["reason"] as? String == reason
                    && value["checkpoint"] as? String == category && !text.contains("fictional-private"))
            }
            for category in StoreVolumeMigrationCheckpoint.allCases {
                for (error, reason): (Error, String) in [
                    (privateError, "broker_repair_not_verified"),
                    (ComponentUpdateFailure.base, "component_base_not_verified"),
                    (RootStoreVolumeFailure.invalid, "vault_publication_volume_binding_invalid"),
                    (RootStoreVolumeFailure.changed, "vault_publication_volume_binding_changed")
                ] {
                    let failure = StoreVolumeMigrationDiagnostic(checkpoint: category, failure: error)
                    let text = BrokerRepairMain.refusal(failure, checkpoint: .migration)
                    let value = try JSONSerialization.jsonObject(with: Data(text.utf8)) as! [String: Any]
                    try expect(Set(value.keys) == ["schema", "status", "reason", "checkpoint"]
                        && value["status"] as? String == "REFUSED" && value["reason"] as? String == reason
                        && value["checkpoint"] as? String == "migration_" + category.rawValue
                        && !text.contains("fictional-private"))
                }
            }
            do {
                try StoreVolumeMigrationDiagnostic.checked(.publish) {
                    try StoreVolumeMigrationDiagnostic.checked(.deviceEpoch) { throw ComponentUpdateFailure.base }
                }
                throw InstalledFixtureFailure.failed
            } catch let diagnostic as StoreVolumeMigrationDiagnostic {
                try expect(diagnostic.checkpoint == .deviceEpoch && diagnostic.failure as? ComponentUpdateFailure == .base)
            }
            var completedContextRefused = false
            do { _ = try ComponentController.completedFullImage(resources: -1, pins: source.pins) }
            catch let diagnostic as CompletedFullImageDiagnostic {
                completedContextRefused = diagnostic.checkpoint == .context && diagnostic.failure as? ComponentUpdateFailure == .context
            }
            try expect(completedContextRefused)
            let progressCases = BrokerRepairCheckpoint.allCases.map { BrokerRepairProgressCheckpoint.repair($0) }
                + FullImageInstallCheckpoint.allCases.map { BrokerRepairProgressCheckpoint.predecessor($0) }
            let fullImageCheckpoints = FullImageInstallCheckpoint.allCases.map(\.rawValue)
            try expect(Set(fullImageCheckpoints).count == fullImageCheckpoints.count)
            let repairEvidence: [String: Any] = ["schema": 1, "managed_by": "account-access-completed-broker-repair-v1",
                "plan_sha256": String(repeating: "1", count: 64), "manifest_sha256": String(repeating: "2", count: 64),
                "source_commit": String(repeating: "a", count: 40), "owner_uid": 501, "broker_uid": 450,
                "intent_sha256": String(repeating: "3", count: 64), "history_sha256": String(repeating: "4", count: 64),
                "predecessor_evidence_sha256": String(repeating: "5", count: 64), "head_sha256": String(repeating: "6", count: 64),
                "mount_sha256": String(repeating: "7", count: 64), "worker_sha256": String(repeating: "8", count: 64),
                "service_sha256": String(repeating: "9", count: 64), "host_sha256": String(repeating: "a", count: 64)]
            let repairEvidenceBytes = try FullImageJSON.encode(repairEvidence)
            try expect(try CompletedRuntimeRepairEvidenceDifference.compare(repairEvidenceBytes, repairEvidenceBytes) == .same)
            try expect(CompletedRuntimeRepairEvidenceDifference.same.checkpoint == .predecessorViewRepairProofSameHashMismatch)
            for difference in CompletedRuntimeRepairEvidenceDifference.allCases where difference.key != nil {
                var changed = repairEvidence
                let key = difference.key!
                if key == "schema" || key == "owner_uid" || key == "broker_uid" {
                    changed[key] = (changed[key] as! Int) + 1
                } else {
                    changed[key] = (changed[key] as! String) + "-changed"
                }
                try expect(try CompletedRuntimeRepairEvidenceDifference.compare(
                    repairEvidenceBytes, FullImageJSON.encode(changed)) == difference)
            }
            var missingRepairEvidenceField = repairEvidence
            missingRepairEvidenceField.removeValue(forKey: "host_sha256")
            try expect(try CompletedRuntimeRepairEvidenceDifference.compare(
                repairEvidenceBytes, FullImageJSON.encode(missingRepairEvidenceField)) == .structure)
            let prettyRepairEvidence = try JSONSerialization.data(withJSONObject: repairEvidence, options: [.prettyPrinted, .fragmentsAllowed])
            if prettyRepairEvidence != repairEvidenceBytes {
                try expect(try CompletedRuntimeRepairEvidenceDifference.compare(repairEvidenceBytes, prettyRepairEvidence) == .encoding)
            }
            try expect(["predecessor_runtime_source", "predecessor_repair_source", "predecessor_namespace",
                        "predecessor_intent", "predecessor_repair_history", "predecessor_repair_route",
                        "predecessor_repair_intent", "predecessor_repair_evidence",
                        "predecessor_component_revalidation", "predecessor_repair_stability", "predecessor_authority",
                        "predecessor_policy", "predecessor_storage", "predecessor_view",
                        "predecessor_view_routes", "predecessor_view_owner", "predecessor_view_policies",
                        "predecessor_view_journal", "predecessor_view_original_receipt",
                        "predecessor_view_repair_proof", "predecessor_view_before", "predecessor_view_states",
                        "predecessor_view_layout", "predecessor_view_projection", "predecessor_view_after",
                        "predecessor_final_tree_history_read", "predecessor_final_tree_history_compare",
                        "predecessor_final_tree_history_verified", "predecessor_initial_head_read",
                        "predecessor_final_head_read",
                        "predecessor_final_head_compare", "predecessor_final_head_verified",
                        "predecessor_final_roots_read", "predecessor_final_roots_compare",
                        "predecessor_final_roots_verified", "predecessor_evidence"].allSatisfy { fullImageCheckpoints.contains($0) })
            for category in progressCases {
                for elapsed in [0.0, 1800.9, 86400.0] {
                    let text = BrokerRepairProgress.encoded(category, elapsed: elapsed)!
                    let value = try JSONSerialization.jsonObject(with: Data(text.utf8)) as! [String: Any]
                    try expect(Set(value.keys) == ["schema", "status", "checkpoint", "elapsed_seconds"]
                        && value["schema"] as? Int == 1 && value["status"] as? String == "RUNNING"
                        && value["checkpoint"] as? String == category.value
                        && value["elapsed_seconds"] as? Int == Int(elapsed))
                }
            }
            for invalid in [Double.nan, Double.infinity, -1.0, 86400.1] {
                try expect(BrokerRepairProgress.encoded(.repair(.context), elapsed: invalid) == nil)
            }
            var peers: [String: ComponentPeerSignature] = [:]
            for kind in ["owner", "broker", "bootstrap"] {
                peers[kind] = ComponentPeerSignature(team: "WBULD6N4NQ", identifier: "com.fainir.accountaccess" + (kind == "owner" ? "" : "." + kind),
                    hashes: [String(repeating: "1", count: 40), String(repeating: "2", count: 40)])
            }
            try expect(try FullImagePolicyFingerprint.value(peers) == "653f6d72b103d3d97b40895b04ebec116a8db3a76455d1a7586c5b9d4a8f4c13")
            peers.removeValue(forKey: "owner"); try refuses { _ = try FullImagePolicyFingerprint.value(peers) }
            print("INSTALLED_FIXTURE_STAGE: root_gate_and_fingerprint"); fflush(stdout)
            do {
                let owned = try directory(root, "signature"); defer { Darwin.close(owned) }
                // This is the binary just compiled for this invocation, copied
                // as opaque bytes. Signature checking never executes the copy.
                let binary = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[0]))
                _ = try ComponentFiles.writeExclusive(owned, "probe", data: binary, owner: getuid(), mode: 0o755)
                let canonical = try FullImageFDCanonicalPath.fixture(owned, owner: getuid())
                try canonical.checked { path in
                    var code: SecStaticCode?
                    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path + "/probe") as CFURL,
                        SecCSFlags(rawValue: 0), &code) == errSecSuccess, let code,
                        SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), nil) == errSecSuccess else {
                        throw InstalledFixtureFailure.failed
                    }
                    checks += 1
                }
                guard renameat(root, "signature", root, "signature-moved") == 0 else { throw InstalledFixtureFailure.failed }
                var invoked = false
                try refuses { try canonical.checked { _ in invoked = true } }
                try expect(!invoked)
            }
            print("INSTALLED_FIXTURE_STAGE: qualified_canonical_signature_path"); fflush(stdout)
            do {
                let fake = try directory(root, "routes"); defer { Darwin.close(fake) }
                let installed = try path(fake, "Library/Application Support/Account Access/python/bin"); Darwin.close(installed)
                let routes = try FullImageInstalledRoutes.fixture(root: fake, owner: getuid())
                let parent = try routes.fileParent(.pythonPip312); try parent.verify(parent.fd); checks += 1
                let support = try routes.support()
                guard renameat(support.fd, "python", support.fd, "detached-python") == 0 else { throw InstalledFixtureFailure.failed }
                let replacement = try path(support.fd, "python/bin"); Darwin.close(replacement)
                try refuses { try routes.verify() }
            }
            do {
                let fake = try directory(root, "acl"); defer { Darwin.close(fake) }
                let made = try path(fake, "Library/Application Support/Account Access"); Darwin.close(made)
                let routes = try FullImageInstalledRoutes.fixture(root: fake, owner: getuid())
                let support = try routes.support(); try acl(support.fd)
                try refuses { try routes.verify() }
                try refuses { _ = try FullImageInstalledRoutes.fixture(root: fake, owner: getuid()).support() }
            }
            print("INSTALLED_FIXTURE_STAGE: attached_routes_and_acl"); fflush(stdout)
            do {
                let support = try directory(root, "projection", 0o755); defer { Darwin.close(support) }
                var states = Array(repeating: ComponentOperationState.staged, count: source.units.count)
                for (index, unit) in source.units.enumerated() {
                    if [PublicTreeUnit.pythonOldPipInfo.path, PublicTreeUnit.pythonPipInfo.path, FullImagePlanFileUnit.pythonPip312.path].contains(unit.path) { states[index] = .applied }
                }
                let mixed = try FullImagePublicView.projection(source: source, states: states)
                try expect(mixed.nodes[PublicTreeUnit.pythonOldPipInfo.path] == nil)
                try expect(mixed.nodes[PublicTreeUnit.pythonPipInfo.path]?.kind == "directory")
                try expect(mixed.nodes[FullImagePlanFileUnit.pythonPip312.path] == nil)
                try expect(mixed.nodes[PublicTreeUnit.runtimeOldPipInfo.path]?.kind == "directory")
                try put(mixed, in: support)
                try FullImagePublicView.verify(source: source, states: states, support: support, owner: getuid()); checks += 1
                _ = try ComponentFiles.writeExclusive(support, "unlisted.txt", data: Data("unexpected".utf8), owner: getuid(), mode: 0o644)
                try refuses { try FullImagePublicView.verify(source: source, states: states, support: support, owner: getuid()) }
                states[0] = .conflict; try refuses { _ = try FullImagePublicView.projection(source: source, states: states) }
            }
            do {
                let fake = try directory(root, "alias"); defer { Darwin.close(fake) }
                let apps = try directory(fake, "Applications", 0o755); defer { Darwin.close(apps) }
                guard symlinkat(InstallerPayloadManifest.applicationTarget, apps, "Account Access.app") == 0 else { throw InstalledFixtureFailure.failed }
                try expect(try InstallerPayloadIO.verifyApplicationAlias(from: fake, owner: getuid()).aliases == 1)
                guard unlinkat(apps, "Account Access.app", 0) == 0, symlinkat("../foreign.app", apps, "Account Access.app") == 0 else { throw InstalledFixtureFailure.failed }
                try refuses { _ = try InstallerPayloadIO.verifyApplicationAlias(from: fake, owner: getuid()) }
            }
            print("INSTALLED_FIXTURE_STAGE: complete_projection_and_alias"); fflush(stdout)
            do {
                let input = try directory(root, "source", 0o755), output = try directory(root, "output")
                defer { Darwin.close(input); Darwin.close(output) }
                let raw = Data("new-value".utf8)
                _ = try ComponentFiles.writeExclusive(input, "pip", data: raw, owner: getuid(), mode: 0o755)
                let node = InstallerPayloadNode(kind: "file", mode: 0o755, size: Int64(raw.count), sha256: FullImageJSON.hash(raw), target: nil)
                try FullImagePublicStager.copyFile(from: input, name: "pip", to: output, slot: "slot-00", node: node, owner: getuid(), group: getgid())
                let copied = try ComponentFiles.read(output, "slot-00", owner: getuid(), mode: 0o755)
                try expect(copied.0 == raw)
                try refuses { try FullImagePublicStager.copyFile(from: input, name: "pip", to: output, slot: "slot-00", node: node, owner: getuid(), group: getgid()) }
                try refuses { try FullImagePublicStager.copyFile(from: input, name: "pip", to: output, slot: "wrong-group", node: node, owner: getuid(), group: getgid() + 1) }
                let wrong = InstallerPayloadNode(kind: "file", mode: 0o755, size: Int64(raw.count), sha256: String(repeating: "0", count: 64), target: nil)
                try refuses { try FullImagePublicStager.copyFile(from: input, name: "pip", to: output, slot: "wrong-hash", node: wrong, owner: getuid(), group: getgid()) }
            }
            do {
                let fake = try directory(root, "wrapper"); defer { Darwin.close(fake) }
                let parent = try path(fake, "Library/Application Support/Account Access/python/bin"); defer { Darwin.close(parent) }
                let retained = try directory(root, "wrapper-retained"); defer { Darwin.close(retained) }
                let before = try ComponentFiles.writeExclusive(parent, "pip3.12", data: Data("fictional-not-executed".utf8), owner: getuid(), mode: 0o755)
                let operation = FullImageFileOperation(schema: 1, unit: .pythonPip312, planSHA256: source.pins.planSHA256, index: 0, before: before, after: nil)
                let routes = try FullImageInstalledRoutes.fixture(root: fake, owner: getuid())
                var quiescent = false
                func open() throws -> FullImageFileStorage {
                    try FullImageFileStorage(operation: operation, retained: retained, owner: getuid(), resolve: routes.resolve,
                        verifyAttachments: { try routes.verify() }, requireQuiescent: { guard quiescent else { throw InstalledFixtureFailure.failed } })
                }
                let storage = try open(); try refuses { try storage.apply() }
                quiescent = true; try storage.apply(); try expect(try storage.state() == .applied)
                let recovered = try open(); try expect(try recovered.state() == .applied)
                try recovered.reverse(); try expect(try recovered.state() == .staged)
                try expect(try ComponentFiles.observe(parent, "pip3.12", owner: getuid()) == before)
            }
            print("INSTALLED_FIXTURE_STAGE: staging_and_wrapper_recovery"); fflush(stdout)
            do {
                let inventory = try copyInventory(source)
                let input = try directory(root, "tree-source", 0o755), output = try directory(root, "tree-output")
                defer { Darwin.close(input); Darwin.close(output) }
                try put(inventory.tree!, in: input)
                try FullImagePublicStager.copyTree(from: input, to: output, inventory: inventory, owner: getuid(), group: getgid())
                guard fchmod(output, 0o755) == 0 else { throw InstalledFixtureFailure.failed }
                try PublicTreeIO.metadata(output, inventory: inventory, owner: getuid(), group: getgid())
                _ = try InstallerPayloadIO.verify(output, tree: inventory.tree!, owner: getuid()); checks += 1
                var link = [CChar](repeating: 0, count: 128)
                let length = readlinkat(output, "alias.txt", &link, link.count)
                try expect(length == 9 && Data(link.prefix(length).map { UInt8(bitPattern: $0) }) == Data("entry.txt".utf8))
                var aliasInfo = stat(), targetInfo = stat()
                try expect(fstatat(output, "alias.txt", &aliasInfo, AT_SYMLINK_NOFOLLOW) == 0
                    && aliasInfo.st_mode & S_IFMT == S_IFLNK && aliasInfo.st_mode & 0o7777 == 0o755)
                try expect(fstatat(output, "entry.txt", &targetInfo, AT_SYMLINK_NOFOLLOW) == 0
                    && targetInfo.st_mode & 0o7777 == inventory.tree!.nodes["entry.txt"]!.mode)
                try refuses { try FullImagePublicStager.copyTree(from: input, to: output, inventory: inventory, owner: getuid(), group: getgid()) }
                let wrongGroup = try directory(root, "tree-wrong-group"); defer { Darwin.close(wrongGroup) }
                try refuses { try FullImagePublicStager.copyTree(from: input, to: wrongGroup, inventory: inventory, owner: getuid(), group: getgid() + 1) }
                guard linkat(input, "entry.txt", root, "tree-source-hardlink", 0) == 0 else { throw InstalledFixtureFailure.failed }
                let hardlink = try directory(root, "tree-hardlink"); defer { Darwin.close(hardlink) }
                try refuses { try FullImagePublicStager.copyTree(from: input, to: hardlink, inventory: inventory, owner: getuid(), group: getgid()) }
                guard unlinkat(root, "tree-source-hardlink", 0) == 0, unlinkat(input, "entry.txt", 0) == 0,
                      mkdirat(input, "entry.txt", 0o755) == 0 else { throw InstalledFixtureFailure.failed }
                let wrongType = try directory(root, "tree-wrong-type"); defer { Darwin.close(wrongType) }
                try refuses { try FullImagePublicStager.copyTree(from: input, to: wrongType, inventory: inventory, owner: getuid(), group: getgid()) }
            }
            print("INSTALLED_FIXTURE_STAGE: recursive_staging_symlink_and_refusals"); fflush(stdout)
            do {
                let namespace = try directory(root, "orphans"); defer { Darwin.close(namespace) }
                for _ in 0..<8 {
                    let name = ".preparing-" + source.pins.planSHA256 + "-" + UUID().uuidString.lowercased()
                    let child = try directory(namespace, name); Darwin.close(child)
                }
                try expect(try FullImagePreparationInspector.retained(namespace, plan: source.pins.planSHA256, owner: getuid(), group: getgid()) == 8)
                let name = ".preparing-" + source.pins.planSHA256 + "-" + UUID().uuidString.lowercased()
                let ninth = try directory(namespace, name); Darwin.close(ninth)
                try refuses { _ = try FullImagePreparationInspector.retained(namespace, plan: source.pins.planSHA256, owner: getuid(), group: getgid()) }
            }
            do {
                let namespace = try directory(root, "hardlink-orphan"); defer { Darwin.close(namespace) }
                let name = ".preparing-" + source.pins.planSHA256 + "-" + UUID().uuidString.lowercased()
                let child = try directory(namespace, name); defer { Darwin.close(child) }
                _ = try ComponentFiles.writeExclusive(child, "partial", data: Data("fictional".utf8), owner: getuid(), mode: 0o600)
                guard linkat(child, "partial", root, "hardlink-outside-orphan", 0) == 0 else { throw InstalledFixtureFailure.failed }
                try refuses { _ = try FullImagePreparationInspector.retained(namespace, plan: source.pins.planSHA256, owner: getuid(), group: getgid()) }
            }
            try aliasRepairChecks(root)
            print("INSTALLED_FIXTURE_STAGE: runtime_alias_permissions_repair_and_recovery"); fflush(stdout)
            var final = stat()
            guard lstat(ownedPath, &final) == 0, PublicTreeDirectoryIdentity(final) == original else { throw InstalledFixtureFailure.failed }
            try FileManager.default.removeItem(atPath: ownedPath) // Exclusive invocation-owned tree only.
            print("{\"status\":\"PASSED\",\"checks\":\(checks),\"ordinary_owned_temp_only\":true,\"installed_reads\":false,\"root_execution\":false,\"service_actions\":false,\"production_ready\":false}")
        } catch { fputs("FULL_IMAGE_INSTALLED_FIXTURE_FAILED\n", stderr); exit(1) }
    }
}
