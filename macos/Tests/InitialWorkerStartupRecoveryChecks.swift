// Exact production orchestration with fake clocks and owned synthetic resources.
// No root, process, file, key, network, account or installed-service access.
import Foundation
import Darwin

enum InitialStartupFixtureFailure: Error, Equatable { case missingKey, authorization, publication }

@main struct InitialWorkerStartupRecoveryChecks {
    static func main() {
        do { try run() }
        catch { print("FAIL unexpected_startup_recovery_result"); exit(1) }
    }
    static func require(_ value: @autoclosure () -> Bool) {
        if !value() { fatalError("startup recovery invariant failed") }
    }
    static func run() throws {
        var time: TimeInterval = 0
        var launches = 0, cleanups = 0, owned = false
        var events: [String] = []
        let recovered = try InitialWorkerStartupRecovery.run(launch: {
            require(!owned)
            launches += 1; owned = true; events.append("launch")
            if launches == 1 { throw RootWorkerProcessFailure.startupTimedOut }
            return true
        }, cleanup: {
            require(owned)
            owned = false; cleanups += 1; events.append("cleanup")
        }, revalidate: {
            require(!owned && cleanups == 1)
            events.append("validate")
            return true
        }, clock: { time }, pause: { time += $0 })
        require(recovered && launches == 2 && cleanups == 1 && owned && time == 5)
        require(Array(events.prefix(3)) == ["launch", "cleanup", "validate"])
        require(events[events.count - 2] == "validate" && events.last == "launch")
        print("PASS initial_timeout_retries_only_after_owned_cleanup_and_fresh_authority")

        time = 0; launches = 0; cleanups = 0
        do {
            _ = try InitialWorkerStartupRecovery.run(launch: {
                launches += 1
                require(launches <= 3)
                throw RootWorkerProcessFailure.startupTimedOut
            }, cleanup: { cleanups += 1 }, revalidate: { true }, clock: { time }, pause: { time += $0 })
            fatalError("unbounded startup retry accepted")
        } catch RootWorkerProcessFailure.startupTimedOut {
            require(launches == 3 && cleanups == 3 && time == 25)
        }
        print("PASS two_retry_budget_exhaustion_preserves_exact_timeout")

        time = 0; launches = 0; cleanups = 0
        let third = try InitialWorkerStartupRecovery.run(launch: {
            launches += 1
            if launches < 3 { throw RootWorkerProcessFailure.startupTimedOut }
            return true
        }, cleanup: { cleanups += 1 }, revalidate: { true }, clock: { time }, pause: { time += $0 })
        require(third && launches == 3 && cleanups == 2 && time == 25)
        print("PASS later_success_uses_finite_separate_startup_backoff")

        let terminal: [RootWorkerProcessFailure] = [.invalidState, .unavailable, .occupied, .unsafeCode,
            .ownershipLost, .changedSocket, .paused, .bootstrapExited]
        for reason in terminal {
            launches = 0; cleanups = 0
            do {
                _ = try InitialWorkerStartupRecovery.run(launch: { launches += 1; throw reason },
                    cleanup: { cleanups += 1 }, revalidate: { fatalError("validated terminal failure") },
                    clock: { 0 }, pause: { _ in fatalError("waited after terminal failure") })
                fatalError("terminal worker failure retried")
            } catch let actual as RootWorkerProcessFailure {
                require(actual == reason && launches == 1 && cleanups == 1)
            }
        }
        print("PASS identity_socket_code_pause_and_exit_failures_never_retry")

        for reason in [InitialStartupFixtureFailure.missingKey, .authorization, .publication] {
            launches = 0; cleanups = 0
            do {
                _ = try InitialWorkerStartupRecovery.run(launch: { launches += 1; throw reason },
                    cleanup: { cleanups += 1 }, revalidate: { fatalError("validated unsupported failure") },
                    clock: { 0 }, pause: { _ in fatalError("waited after unsupported failure") })
                fatalError("unsupported failure retried")
            } catch let actual as InitialStartupFixtureFailure {
                require(actual == reason && launches == 1 && cleanups == 1)
            }
        }
        print("PASS key_authorization_and_publication_failures_never_retry")

        launches = 0; cleanups = 0
        do {
            _ = try InitialWorkerStartupRecovery.run(launch: {
                launches += 1; throw RootWorkerProcessFailure.startupTimedOut
            }, cleanup: { cleanups += 1; throw RootWorkerProcessFailure.changedSocket },
                revalidate: { fatalError("validated failed cleanup") }, clock: { 0 },
                pause: { _ in fatalError("waited after failed cleanup") })
            fatalError("cleanup failure accepted")
        } catch RootWorkerProcessFailure.changedSocket { require(launches == 1 && cleanups == 1) }
        print("PASS cleanup_failure_replaces_timeout_without_retry")

        launches = 0; cleanups = 0
        do {
            _ = try InitialWorkerStartupRecovery.run(launch: {
                launches += 1; throw RootWorkerProcessFailure.startupTimedOut
            }, cleanup: { cleanups += 1 }, revalidate: nil, clock: { 0 },
                pause: { _ in fatalError("unapproved retry waited") })
            fatalError("default caller retried")
        } catch RootWorkerProcessFailure.startupTimedOut { require(launches == 1 && cleanups == 1) }
        print("PASS default_caller_retains_one_attempt_without_enrollment_callback")

        time = 0; launches = 0; cleanups = 0
        let paused = try InitialWorkerStartupRecovery.run(launch: {
            launches += 1; throw RootWorkerProcessFailure.startupTimedOut
        }, cleanup: { cleanups += 1 }, revalidate: { false }, clock: { time }, pause: { time += $0 })
        require(!paused && launches == 1 && cleanups == 1 && time == 0)
        print("PASS pause_before_backoff_returns_interrupted_without_repair_error")

        time = 0; launches = 0; cleanups = 0
        let cancelled = try InitialWorkerStartupRecovery.run(launch: {
            launches += 1; throw RootWorkerProcessFailure.startupTimedOut
        }, cleanup: { cleanups += 1 }, revalidate: { time < 0.25 }, clock: { time }, pause: { time += $0 })
        require(!cancelled && launches == 1 && cleanups == 1 && time >= 0.25 && time <= 0.35)
        print("PASS pause_during_backoff_stops_before_another_child")

        time = 0; launches = 0
        let lastMomentPause = try InitialWorkerStartupRecovery.run(launch: {
            launches += 1; throw RootWorkerProcessFailure.startupTimedOut
        }, cleanup: {}, revalidate: { time < 5 }, clock: { time }, pause: { time += $0 })
        require(!lastMomentPause && launches == 1 && time == 5)
        print("PASS final_backoff_slice_rechecks_pause_before_launch")

        launches = 0; cleanups = 0
        do {
            _ = try InitialWorkerStartupRecovery.run(launch: {
                launches += 1; throw RootWorkerProcessFailure.startupTimedOut
            }, cleanup: { cleanups += 1 }, revalidate: { throw InitialStartupFixtureFailure.authorization },
                clock: { 0 }, pause: { _ in fatalError("waited after authority changed") })
            fatalError("authority failure ignored")
        } catch InitialStartupFixtureFailure.authorization { require(launches == 1 && cleanups == 1) }
        print("PASS changed_durable_authority_is_terminal_after_cleanup")

        time = 0; launches = 0; cleanups = 0
        do {
            _ = try InitialWorkerStartupRecovery.run(launch: {
                launches += 1
                if launches == 1 { throw RootWorkerProcessFailure.startupTimedOut }
                throw RootWorkerProcessFailure.unsafeCode
            }, cleanup: { cleanups += 1 }, revalidate: { true }, clock: { time }, pause: { time += $0 })
            fatalError("later security failure ignored")
        } catch RootWorkerProcessFailure.unsafeCode { require(launches == 2 && cleanups == 2 && time == 5) }
        print("PASS later_security_failure_does_not_consume_another_retry")

        let stoppedByMarker = try InitialWorkerStartupRecovery.run(launch: { false },
            cleanup: { fatalError("cleaned up a paused launch") },
            revalidate: { fatalError("revalidated a paused launch") }, clock: { 0 },
            pause: { _ in fatalError("waited after a paused launch") })
        require(!stoppedByMarker)
        print("PASS paused_launch_without_worker_never_reports_readiness")
    }
}
