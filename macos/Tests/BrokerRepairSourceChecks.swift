// Synthetic source contracts; executable-named files contain inert text only.
import Foundation
import Darwin

@main struct BrokerRepairSourceChecks {
    struct Fixture {
        var plan: Data, before: Data, after: Data, oldIdentity: Data, newIdentity: Data, provenance: Data, broker: Data
        let pins: BrokerRepairSource.Pins
        func load() throws -> BrokerRepairSource {
            try BrokerRepairSource.load(pins: pins, plan: plan, before: before, after: after,
                oldIdentity: oldIdentity, newIdentity: newIdentity, provenance: provenance, broker: broker)
        }
    }
    static func identity(broker: String) -> [String: Any] {
        var peers: [String: Any] = [:]
        for (kind, hash) in [("owner", "1"), ("broker", broker), ("bootstrap", "2")] {
            peers[kind] = ["team": "WBULD6N4NQ", "identifier": kind == "owner" ? "com.fainir.accountaccess" : "com.fainir.accountaccess." + kind,
                "hashes": [String(repeating: hash, count: 40)]]
        }
        return ["schema": 1, "managed_by": "account-access-package-identity-v1", "signatures": peers]
    }
    static func fixture(changeIdentity: (inout [String: Any]) -> Void = { _ in },
                        changeHistory: (inout [String: Any]) -> Void = { _ in },
                        changeNodes: (inout [String: Any]) -> Void = { _ in },
                        changePlan: (inout [String: Any]) -> Void = { _ in }) throws -> Fixture {
        func node(_ data: Data, mode: Int = 0o644) -> [String: Any] {
            ["kind": "file", "mode": mode, "size": data.count, "sha256": FullImageJSON.hash(data)]
        }
        func manifest(_ nodes: [String: Any]) throws -> Data {
            try FullImageJSON.encode(["schema": 1, "managed_by": "account-access-install-payload-v1",
                "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
                "roots": [InstallerPayloadManifest.support: nodes, InstallerPayloadManifest.application:
                    ["": ["kind": "symlink", "target": InstallerPayloadManifest.applicationTarget]]]])
        }
        let oldIdentity = try FullImageJSON.encode(identity(broker: "3"))
        var newObject = identity(broker: "4"); changeIdentity(&newObject)
        let newIdentity = try FullImageJSON.encode(newObject)
        let broker = Data("fictional new broker, never executed".utf8)
        let directory: [String: Any] = ["kind": "directory", "mode": 0o755]
        let old: [String: Any] = ["": directory, "bin": directory, "owner.app": directory,
            "owner.app/Contents": directory, "owner.app/Contents/MacOS": directory,
            "owner.app/Contents/MacOS/AccountAccess": node(Data("fictional owner".utf8), mode: 0o755),
            "bin/AccountAccess-broker": node(Data("fictional old broker".utf8), mode: 0o755),
            "bin/AccountAccess-bootstrap": node(Data("fictional unchanged bootstrap".utf8), mode: 0o755),
            "package-identity.json": node(oldIdentity)]
        let before = try manifest(old), commit = String(repeating: "c", count: 40), predecessor = String(repeating: "d", count: 64)
        var history: [String: Any] = ["schema": 1, "managed_by": "account-access-broker-repair-image-v1",
            "before_manifest_sha256": FullImageJSON.hash(before), "source_commit": commit,
            "broker_sha256": FullImageJSON.hash(broker), "package_identity_sha256": FullImageJSON.hash(newIdentity),
            "native_sources": ["macos/SystemBroker.swift": String(repeating: "e", count: 64)]]
        changeHistory(&history)
        let provenance = try FullImageJSON.encode(history)
        var new = old
        new["bin/AccountAccess-broker"] = node(broker, mode: 0o755)
        new["package-identity.json"] = node(newIdentity)
        new["broker-repair-identity.json"] = node(provenance)
        changeNodes(&new)
        let after = try manifest(new)
        var plan: [String: Any] = ["schema": 1, "managed_by": "account-access-broker-repair-plan-v1",
            "predecessor_plan_sha256": predecessor, "before_manifest_sha256": FullImageJSON.hash(before),
            "after_manifest_sha256": FullImageJSON.hash(after), "source_commit": commit,
            "changed": BrokerRepairUnit.allCases.map(\.path).sorted(),
            "private_schema_unchanged": true, "worker_abi_unchanged": true, "production_ready": false]
        changePlan(&plan)
        let raw = try FullImageJSON.encode(plan)
        return Fixture(plan: raw, before: before, after: after, oldIdentity: oldIdentity, newIdentity: newIdentity,
            provenance: provenance, broker: broker, pins: .init(planSHA256: FullImageJSON.hash(raw), predecessorPlanSHA256: predecessor,
                beforeManifestSHA256: FullImageJSON.hash(before), afterManifestSHA256: FullImageJSON.hash(after), sourceCommit: commit))
    }
    static func main() throws {
        guard getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 1 else { exit(77) }
        var assertions = 0
        func check(_ value: Bool) { precondition(value); assertions += 1 }
        func refuses(_ body: () throws -> Void) {
            var refused = false; do { try body() } catch { refused = true }; check(refused)
        }
        let fixture = try fixture(), source = try fixture.load()
        check(source.oldPeers["owner"] == source.newPeers["owner"] && source.oldPeers["bootstrap"] == source.newPeers["bootstrap"])
        check(source.oldPeers["broker"] != source.newPeers["broker"] && source.oldFingerprint != source.newFingerprint)
        check(source.payloads.count == 3 && source.payloads[.broker] == fixture.broker)
        for key in ["schema", "managed_by", "predecessor_plan_sha256", "before_manifest_sha256", "after_manifest_sha256", "source_commit", "changed",
                    "private_schema_unchanged", "worker_abi_unchanged", "production_ready", "extra"] {
            refuses { _ = try self.fixture(changePlan: { $0[key] = "foreign" }).load() }
        }
        for key in ["schema", "managed_by", "before_manifest_sha256", "source_commit", "broker_sha256", "package_identity_sha256", "native_sources", "extra"] {
            refuses { _ = try self.fixture(changeHistory: { $0[key] = "foreign" }).load() }
        }
        for sources: [String: String] in [[:], ["macos/../secret.swift": String(repeating: "e", count: 64)],
            ["other/file.swift": String(repeating: "e", count: 64)], ["macos/SystemBroker.swift": "invalid"]] {
            refuses { _ = try self.fixture(changeHistory: { $0["native_sources"] = sources }).load() }
        }
        for kind in ["owner", "bootstrap"] {
            refuses { _ = try self.fixture(changeIdentity: {
                var peers = $0["signatures"] as! [String: [String: Any]]
                peers[kind]!["hashes"] = [String(repeating: "a", count: 40)]; $0["signatures"] = peers
            }).load() }
        }
        for (key, value) in [("team", "FOREIGN123" as Any), ("identifier", "foreign" as Any),
            ("hashes", [String(repeating: "a", count: 40), String(repeating: "a", count: 40)] as Any),
            ("hashes", [String(repeating: "3", count: 40)] as Any), ("extra", true as Any)] {
            refuses { _ = try self.fixture(changeIdentity: {
                var peers = $0["signatures"] as! [String: [String: Any]]
                peers["broker"]![key] = value; $0["signatures"] = peers
            }).load() }
        }
        for path in ["owner.app/Contents/MacOS/AccountAccess", "bin/AccountAccess-bootstrap"] {
            refuses { _ = try self.fixture(changeNodes: { var node = $0[path] as! [String: Any]; node["sha256"] = String(repeating: "a", count: 64); $0[path] = node }).load() }
        }
        for unit in BrokerRepairUnit.allCases {
            for key in ["mode", "size", "sha256", "kind"] {
                refuses { _ = try self.fixture(changeNodes: {
                    var node = $0[unit.path] as! [String: Any]
                    node[key] = key == "mode" ? 0o600 : key == "size" ? 1 : "foreign"
                    $0[unit.path] = node
                }).load() }
            }
        }
        for key in ["plan", "before", "after", "oldIdentity", "newIdentity", "provenance", "broker"] {
            var changed = fixture
            switch key {
            case "plan": changed.plan.append(32)
            case "before": changed.before.append(32)
            case "after": changed.after.append(32)
            case "oldIdentity": changed.oldIdentity.append(32)
            case "newIdentity": changed.newIdentity.append(32)
            case "provenance": changed.provenance.append(32)
            default: changed.broker.append(32)
            }
            refuses { _ = try changed.load() }
        }
        let recoveryAssertions = try BrokerRepairIntentChecks.run(source: source)
        let transactionAssertions = try BrokerRepairRecoveryChecks.run(source: source)
        print("{\"schema\":1,\"status\":\"PASSED\",\"source_assertions\":\(assertions),\"recovery_assertions\":\(recoveryAssertions),\"transaction_assertions\":\(transactionAssertions),\"installed_reads\":false,\"payload_executed\":false,\"production_ready\":false}")
    }
}
