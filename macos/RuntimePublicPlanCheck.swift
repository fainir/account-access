// One-use, owner-approved metadata diagnostic. No daemon/service composition,
// authorization policy, Keychain, account reads, or private directory contents.
import Foundation
import Darwin

private enum PublicPlanCheckLabel: String {
    case context, policyPaths = "policy_paths", workerPlan = "worker_plan"
    case enrollmentPlan = "enrollment_plan", brokerDomain = "broker_domain"
    case agentSocket = "agent_socket", ownerSocket = "owner_socket"
}

private enum PublicPlanCheckReason: String {
    case context = "root_no_argument_context_required"
    case unavailable = "public_plan_check_unavailable"
    case workerUnavailable = "worker_plan_not_confirmed"
    case domainNotConfirmed = "broker_domain_not_confirmed"
    case domainUnavailable = "broker_domain_check_unavailable"
    case domainTimeout = "broker_domain_check_timeout"
}

private struct PublicPlanCheckRow {
    let check: PublicPlanCheckLabel
    let reason: String?
    var value: [String: Any] { ["check": check.rawValue, "reason": reason.map { $0 as Any } ?? NSNull()] }
}

private enum RuntimePublicPlanCheck {
    private static let base = "/Library/Application Support/Account Access"
    private static let hostPolicy = base + "/broker/host.json"
    private static let launcherPolicy = base + "/broker/worker-launch.json"
    private static let workerPolicy = base + "/broker/worker.json"
    private static let enrollmentPolicy = base + "/broker/enrollment.json"
    private static let stagePolicy = base + "/broker/stage.json"
    private static let agentSocket = base + "/run/agent.sock"
    private static let ownerSocket = base + "/control/owner.sock"

    private static func reason(_ error: Error) -> String {
        (error as? WorkerLaunchFailure)?.rawValue ?? PublicPlanCheckReason.unavailable.rawValue
    }

    private static func publicObject(_ path: String) throws -> [String: Any] {
        // Never let a policy symlink redirect this diagnostic into another
        // root-owned file. Only these fixed public, published JSON files enter.
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == 0, info.st_nlink == 1, info.st_mode & 0o7777 == 0o644 else {
            throw WorkerLaunchFailure.invalidPolicy
        }
        return try WorkerLaunchPaths.object(path)
    }

    private static func fixedPolicyPaths() throws {
        let host = try publicObject(hostPolicy)
        guard host["managed_by"] as? String == "account-access-system-host-v1",
              try WorkerLaunchPaths.integer(host["schema"]) == 1,
              host["worker_launcher"] as? String == launcherPolicy,
              host["enrollment_policy"] as? String == enrollmentPolicy else {
            throw WorkerLaunchFailure.invalidPolicy
        }
        let launcher = try publicObject(launcherPolicy)
        guard launcher["python"] as? String == base + "/runtime/bin/python",
              launcher["runtime"] as? String == base + "/runtime",
              launcher["worker_policy"] as? String == workerPolicy,
              launcher["broker_home"] as? String == base + "/home",
              launcher["browsers"] as? String == base + "/browsers",
              let fixture = launcher["fixture"] as? NSNumber,
              CFGetTypeID(fixture) == CFBooleanGetTypeID(), !fixture.boolValue,
              launcher["fixture_ca"] is NSNull else { throw WorkerLaunchFailure.invalidPolicy }
        let worker = try publicObject(workerPolicy)
        guard worker["root"] as? String == base + "/vault/data",
              worker["agent_socket"] as? String == agentSocket,
              worker["owner_socket"] as? String == ownerSocket else {
            throw WorkerLaunchFailure.invalidPolicy
        }
        let enrollment = try publicObject(enrollmentPolicy)
        guard enrollment["worker_launcher"] as? String == launcherPolicy,
              enrollment["stage_policy"] as? String == stagePolicy else {
            throw WorkerLaunchFailure.invalidPolicy
        }
        _ = try publicObject(stagePolicy)
    }

    private static func socketMetadata(_ path: String, group: gid_t, mode: mode_t) throws {
        _ = try WorkerLaunchPaths.protected(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK,
              info.st_uid == 0, info.st_gid == group, info.st_mode & 0o7777 == mode else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        try WorkerLaunchPaths.rejectGrantACL(path)
    }

    private static func brokerDomain(_ uid: uid_t) -> String? {
        // This read-only command cannot bootstrap, start, debug, kill or change
        // a launchd domain. Its complete output is discarded without reading.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", "user/" + String(uid)]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() }
        catch { return PublicPlanCheckReason.domainUnavailable.rawValue }
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        if process.isRunning {
            // Only this exact child is stopped, never a service, another PID,
            // process group, or a launchctl mutation command.
            process.terminate()
            let grace = ProcessInfo.processInfo.systemUptime + 1
            while process.isRunning && ProcessInfo.processInfo.systemUptime < grace {
                Thread.sleep(forTimeInterval: 0.02)
            }
            if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            return PublicPlanCheckReason.domainTimeout.rawValue
        }
        // Nonzero may mean authorization/transport failure, not absence.
        return process.terminationStatus == 0 ? nil : PublicPlanCheckReason.domainNotConfirmed.rawValue
    }

    static func main() -> Int32 {
        // Before policy, code-tree, identity or directory metadata reads.
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 1 else {
            emit([PublicPlanCheckRow(check: .context, reason: PublicPlanCheckReason.context.rawValue)])
            return 77
        }
        var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(RLIMIT_CORE, &noCore) == 0 else {
            emit([PublicPlanCheckRow(check: .context, reason: PublicPlanCheckReason.unavailable.rawValue)])
            return 77
        }
        alarm(30)
        defer { alarm(0) }
        var rows: [PublicPlanCheckRow] = []
        do {
            try fixedPolicyPaths()
            rows.append(PublicPlanCheckRow(check: .policyPaths, reason: nil))
        } catch {
            emit([PublicPlanCheckRow(check: .policyPaths, reason: reason(error))])
            return 0
        }
        var plan: MacWorkerPlan?
        do {
            plan = try MacWorkerPlan(policy: launcherPolicy)
            rows.append(PublicPlanCheckRow(check: .workerPlan, reason: nil))
        } catch { rows.append(PublicPlanCheckRow(check: .workerPlan, reason: reason(error))) }
        do {
            // false is mandatory: neither private stage nor vault contents are
            // enumerated. Production validation reads their directory nodes only.
            _ = try MacWorkerEnrollmentPlan(policy: enrollmentPolicy, requireEmptyStage: false)
            rows.append(PublicPlanCheckRow(check: .enrollmentPlan, reason: nil))
        } catch { rows.append(PublicPlanCheckRow(check: .enrollmentPlan, reason: reason(error))) }
        let ownerGroup = plan.flatMap { getpwuid($0.agentUID)?.pointee.pw_gid }
        if let plan, let ownerGroup {
            rows.append(PublicPlanCheckRow(check: .brokerDomain, reason: brokerDomain(plan.uid)))
            do {
                try socketMetadata(agentSocket, group: ownerGroup, mode: 0o660)
                rows.append(PublicPlanCheckRow(check: .agentSocket, reason: nil))
            } catch { rows.append(PublicPlanCheckRow(check: .agentSocket, reason: reason(error))) }
            do {
                try socketMetadata(ownerSocket, group: 0, mode: 0o600)
                rows.append(PublicPlanCheckRow(check: .ownerSocket, reason: nil))
            } catch { rows.append(PublicPlanCheckRow(check: .ownerSocket, reason: reason(error))) }
        } else {
            for label in [PublicPlanCheckLabel.brokerDomain, .agentSocket, .ownerSocket] {
                rows.append(PublicPlanCheckRow(check: label, reason: PublicPlanCheckReason.workerUnavailable.rawValue))
            }
        }
        emit(rows)
        return 0 // Completed observations can contain failures; never claim readiness.
    }

    private static func emit(_ rows: [PublicPlanCheckRow]) {
        guard let data = try? JSONSerialization.data(withJSONObject: rows.map(\.value), options: .sortedKeys),
              let text = String(data: data, encoding: .utf8) else {
            print("[{\"check\":\"context\",\"reason\":\"public_plan_check_unavailable\"}]")
            return
        }
        print(text)
    }
}

@main struct RuntimePublicPlanCheckMain {
    static func main() { exit(RuntimePublicPlanCheck.main()) }
}
