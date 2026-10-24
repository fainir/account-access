// Hosted read-only API qualification. No service actions or installed records.
import Foundation
import Darwin

@main struct ComponentSystemProcessNativeChecks {
    static func main() {
        let environment = ProcessInfo.processInfo.environment
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 1,
              environment["GITHUB_ACTIONS"] == "true", environment["RUNNER_ENVIRONMENT"] == "github-hosted",
              environment["GITHUB_REPOSITORY"] == "fainir/account-access" else { exit(77) }
        var stage = "system_processes", checks: [String: Bool] = [:]
        do {
            let api = ComponentSystemProcessObserver.live(brokerUID: 450)
            for (path, identifier) in [("/usr/sbin/distnoted", "com.apple.distnoted"), ("/usr/libexec/lsd", "com.apple.lsd")] {
                stage = identifier + "_lookup"
                let pids = try ComponentProcesses.atPath(path)
                guard !pids.isEmpty else { throw ComponentUpdateFailure.quiescence }
                var accepted = false
                for pid in pids {
                    let before = try api.observe(pid)
                    guard before.path == path else { throw ComponentUpdateFailure.quiescence }
                    stage = identifier + "_attestation"
                    try api.attest(before, identifier)
                    guard try api.observe(pid) == before else { throw ComponentUpdateFailure.quiescence }
                    stage = identifier + "_wrong_identifier"
                    do {
                        try api.attest(before, identifier == "com.apple.lsd" ? "com.apple.distnoted" : "com.apple.lsd")
                        throw ComponentUpdateFailure.context
                    } catch ComponentUpdateFailure.quiescence { }
                    accepted = true
                }
                checks[identifier + "_live_signature_and_path"] = accepted
                checks[identifier + "_wrong_identifier_refused"] = accepted
            }
            stage = "non_apple_code"
            let own = try api.observe(getpid())
            do {
                try api.attest(own, "com.apple.lsd")
                throw ComponentUpdateFailure.context
            } catch ComponentUpdateFailure.quiescence { }
            checks["non_apple_process_refused"] = true
            guard checks.count == 5, checks.values.allSatisfy({ $0 }) else { throw ComponentUpdateFailure.context }
            emit(status: "PASSED", stage: "complete", checks: checks)
        } catch { emit(status: "FAILED", stage: stage, checks: checks); exit(78) }
    }
    private static func emit(status: String, stage: String, checks: [String: Bool]) {
        let result: [String: Any] = ["schema": 1, "status": status, "stage": stage, "checks": checks,
            "scope": "live Apple code attestation; eligibility and race cases are separate synthetic tests",
            "service_actions": false, "installed_records_read": false, "production_ready": false]
        if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) {
            FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
        }
    }
}
