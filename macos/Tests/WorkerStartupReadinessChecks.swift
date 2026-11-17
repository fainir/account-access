// Pure fake-clock checks. No root, process, file, key, network or account access.
import Foundation
import Darwin

@main struct WorkerStartupReadinessChecks {
    static func main() {
        do { try run() }
        catch { print("FAIL " + ((error as? RootWorkerProcessFailure)?.rawValue ?? "unexpected")); exit(1) }
    }
    static func run() throws {
        var time: TimeInterval = 0
        var probes = 0
        // A cold but live worker becomes ready after the former 30s limit.
        try WorkerStartupReadiness.wait(childAlive: { true }, health: { budget in
            guard budget > 0 && budget <= 1 else { fatalError("invalid health budget") }
            probes += 1
            return time >= 45
        }, clock: { time }, pause: { time += $0 })
        guard time >= 45 && time <= 46 && probes > 1 else { fatalError("late readiness not observed") }
        print("PASS cold_live_worker_ready_after_45_seconds")

        time = 0
        do {
            try WorkerStartupReadiness.wait(childAlive: { true }, health: { _ in false },
                clock: { time }, pause: { time += $0 })
            fatalError("unbounded startup accepted")
        } catch RootWorkerProcessFailure.startupTimedOut {
            guard time == WorkerStartupReadiness.timeout else { fatalError("deadline exceeded") }
        }
        print("PASS unready_worker_stops_at_fixed_deadline")

        time = 0; probes = 0
        do {
            try WorkerStartupReadiness.wait(childAlive: { false }, health: { _ in probes += 1; return true },
                clock: { time }, pause: { time += $0 })
            fatalError("dead child accepted")
        } catch RootWorkerProcessFailure.bootstrapExited {
            guard probes == 0 else { fatalError("probed dead child") }
        }
        print("PASS child_exit_refuses_before_health_probe")

        do {
            try WorkerStartupReadiness.wait(childAlive: { throw RootWorkerProcessFailure.ownershipLost },
                health: { _ in fatalError("probed unowned child") }, clock: { 0 }, pause: { _ in })
            fatalError("unowned child accepted")
        } catch RootWorkerProcessFailure.ownershipLost {}
        print("PASS ownership_failure_is_preserved")

        time = 0
        try WorkerStartupReadiness.wait(childAlive: { true }, health: { _ in
            if time < 2 { throw RootWorkerProcessFailure.unavailable }
            return true
        }, clock: { time }, pause: { time += $0 })
        print("PASS temporary_health_transport_failure_can_recover")

        time = 0
        do {
            try WorkerStartupReadiness.wait(childAlive: { true }, health: { _ in
                time = WorkerStartupReadiness.timeout + 1; return true
            }, clock: { time }, pause: { _ in })
            fatalError("late health reply accepted")
        } catch RootWorkerProcessFailure.startupTimedOut {}
        print("PASS health_reply_cannot_outlive_deadline")
    }
}
