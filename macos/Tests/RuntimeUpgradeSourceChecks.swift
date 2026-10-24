// Ordinary-user, data-only checks. Inputs are generated public package fixtures.
// No installed path or updater entrypoint can be selected by these arguments.
import Foundation
import Darwin

@main struct RuntimeUpgradeSourceChecks {
    static func main() throws {
        guard getuid() != 0, getuid() == geteuid(),
              CommandLine.arguments.count == 2 || (CommandLine.arguments.count == 3 && CommandLine.arguments[2] == "--positive-only") else { exit(77) }
        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        func read(_ name: String) throws -> Data { try Data(contentsOf: root.appendingPathComponent(name)) }
        let raw = try read("plan.json"), before = try read("before.json"), after = try read("after.json")
        let oldIdentity = try read("old-identity.json"), newIdentity = try read("new-identity.json")
        let value = try FullImageJSON.object(raw, maximum: 34 * 1024 * 1024)
        func pins(_ plan: Data) throws -> RuntimeUpgradeSource.Pins {
            guard let before = value["before_manifest_sha256"] as? String,
                  let after = value["after_manifest_sha256"] as? String,
                  let repair = value["predecessor_repair_plan_sha256"] as? String,
                  let repairSource = value["predecessor_repair_source"] as? String,
                  let source = value["target_source"] as? String,
                  let files = value["target_source_files"] as? [String: String] else { throw FullImageFailure.source }
            return .init(planSHA256: FullImageJSON.hash(plan), beforeSHA256: before, afterSHA256: after,
                repairPlan: repair, repairSource: repairSource, targetSource: source, sourceFiles: files)
        }
        func load(_ plan: Data, before candidateBefore: Data? = nil, after candidateAfter: Data? = nil,
                  old oldCandidate: Data? = nil, new newCandidate: Data? = nil) throws -> RuntimeUpgradeSource {
            try RuntimeUpgradeSource.load(pins: pins(plan), plan: plan, before: candidateBefore ?? before,
                after: candidateAfter ?? after, oldIdentity: oldCandidate ?? oldIdentity, newIdentity: newCandidate ?? newIdentity)
        }
        var checks = 0
        func check(_ yes: Bool) { precondition(yes); checks += 1 }
        func refuses(_ body: () throws -> Void) {
            var refused = false; do { try body() } catch { refused = true }; check(refused)
        }
        let accepted = try load(raw)
        check(accepted.changed == value["changed"] as? [String])
        check(accepted.units.count == (value["units"] as? [Any])?.count)
        if CommandLine.arguments.count == 3 {
            print("{\"status\":\"PASSED\",\"checks\":" + String(checks) + ",\"installed_reads\":false,\"production_ready\":false}")
            return
        }
        for key in Array(value.keys) + ["extra"] {
            var changed = value; changed[key] = "foreign"
            var bytes = try FullImageJSON.canonical(changed); bytes.append(10)
            refuses { _ = try load(bytes) }
        }
        for name in ["before", "after", "old", "new"] {
            refuses {
                _ = try load(raw, before: name == "before" ? Data("{}".utf8) : nil,
                    after: name == "after" ? Data("{}".utf8) : nil,
                    old: name == "old" ? Data("{}".utf8) : nil, new: name == "new" ? Data("{}".utf8) : nil)
            }
        }
        var noncanonical = raw; noncanonical.append(32)
        refuses { _ = try load(noncanonical) }
        print("{\"status\":\"PASSED\",\"checks\":" + String(checks) + ",\"installed_reads\":false,\"production_ready\":false}")
    }
}
