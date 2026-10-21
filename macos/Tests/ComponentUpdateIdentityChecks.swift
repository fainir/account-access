// Pure public-text/value checks only: no process queries, signatures or service actions.
import Foundation
import Darwin

enum ComponentUpdateIdentityChecks {
    private static let header = "system/com.fainir.accountaccess.broker = {\n"
    private static let program = "\tprogram = /Library/Application Support/Account Access/bin/AccountAccess-broker\n"
    private static let boot = "01234567-89ab-cdef-0123-456789abcdef"

    private static func printData(_ body: String) -> Data { Data((header + body + "}\n").utf8) }
    private static func rejects(_ action: () throws -> Void) throws {
        do { try action(); throw ComponentUpdateFailure.context }
        catch ComponentUpdateFailure.quiescence {}
    }
    // Injected observations exercise the actual production observer, without
    // querying any process or performing a Security framework attestation.
    private final class RevalidationAPI {
        var results: [ComponentCommands.Result]
        var commandFailure: ComponentUpdateFailure?
        var attestationFailure: ComponentUpdateFailure?
        var failAttestationAt = 1
        var allowedPIDs: Set<Int32> = [123, 124]
        var reads = 0, attestations = 0
        var seen: [ComponentJobIdentity?] = []
        init(_ output: [ComponentCommands.Result]) { results = output }
        func make() -> ComponentRevalidationServiceObserver {
            ComponentRevalidationServiceObserver(observe: {
                self.reads += 1
                if let failure = self.commandFailure { throw failure }
                guard !self.results.isEmpty else { throw ComponentUpdateFailure.context }
                return self.results.removeFirst()
            }, attest: { output in
                self.attestations += 1
                if self.attestations == self.failAttestationAt, let failure = self.attestationFailure { throw failure }
                let pid = try ComponentUpdateIdentity.printedPID(output)
                var identity: ComponentJobIdentity?
                if let pid {
                    guard self.allowedPIDs.contains(pid) else { throw ComponentUpdateFailure.source }
                    identity = ComponentJobIdentity(pid: pid, group: UInt32(pid), birthSec: UInt64(pid),
                        birthUsec: 10, bootSession: ComponentUpdateIdentityChecks.boot)
                    try ComponentUpdateIdentity.validateSnapshot(identity!)
                }
                self.seen.append(identity)
                return identity
            })
        }
    }
    private static func revalidationObservations() throws -> (Int, [String: Bool]) {
        var count = 0
        func expect(_ value: Bool) throws {
            guard value else { throw ComponentUpdateFailure.context }; count += 1
        }
        func refuses(_ expected: ComponentUpdateFailure, _ action: () throws -> Void) throws {
            do { try action() }
            catch let failure as ComponentUpdateFailure {
                guard failure == expected else { throw ComponentUpdateFailure.context }; count += 1; return
            }
            throw ComponentUpdateFailure.context
        }
        let stopped = printData(program + "\tstate = spawn scheduled\n")
        let runningA = printData(program + "\tstate = running\n\tpid = 123\n")
        let runningB = printData(program + "\tstate = running\n\tpid = 124\n")
        do {
            let api = RevalidationAPI([stopped, runningA, runningB, stopped].map { .init(status: 0, output: $0) })
            let observer = api.make()
            for index in 1...4 {
                try observer.verify()
                try expect(api.reads == index && api.attestations == index && api.seen.count == index)
            }
            try expect(api.seen.map { $0?.pid } == [nil, 123, 124, nil])
        }
        do {
            let api = RevalidationAPI([.init(status: 0, output: stopped), .init(status: 113 << 8, output: Data())])
            let observer = api.make()
            try observer.verify(); try expect(api.seen.count == 1)
            try refuses(.base) { try observer.verify() }
            try expect(api.reads == 2 && api.attestations == 1 && api.seen.count == 1)
        }
        do {
            let api = RevalidationAPI([]); api.commandFailure = .unavailable
            try refuses(.unavailable) { try api.make().verify() }
            try expect(api.reads == 1 && api.attestations == 0 && api.seen.isEmpty)
        }
        for malformed in [printData("\tprogram = /tmp/forged\n\tstate = running\n\tpid = 123\n"),
                          printData(program + "\tstate = running\n\tpid = 123\n\tpid = 124\n"), Data()] {
            let api = RevalidationAPI([.init(status: 0, output: malformed)])
            try refuses(.quiescence) { try api.make().verify() }
            try expect(api.reads == 1 && api.attestations == 1 && api.seen.isEmpty)
        }
        do {
            let api = RevalidationAPI([.init(status: 0, output: runningA)]); api.allowedPIDs = []
            try refuses(.source) { try api.make().verify() }
            try expect(api.reads == 1 && api.attestations == 1 && api.seen.isEmpty)
        }
        do {
            let api = RevalidationAPI([.init(status: 0, output: runningA), .init(status: 0, output: runningB)])
            api.attestationFailure = .quiescence; api.failAttestationAt = 2
            let observer = api.make()
            try observer.verify(); try expect(api.seen.count == 1)
            try refuses(.quiescence) { try observer.verify() }
            try expect(api.reads == 2 && api.attestations == 2 && api.seen.count == 1)
        }
        guard count == 21 else { throw ComponentUpdateFailure.context }
        return (count, ["root_revalidation_attests_each_current_lifecycle_independently": true,
                        "root_revalidation_command_failure_never_reuses_prior_authority": true,
                        "root_revalidation_malformed_or_forged_observation_refused": true,
                        "root_revalidation_live_attestation_failure_propagates": true])
    }
    static func run() throws -> (Int, [String: Bool]) {
        var count = 0
        var stage = "valid_job_print"
        var completed = false
        defer {
            if !completed {
                let failure: [String: Any] = ["schema": 1, "status": "FAILED",
                    "managed_by": "account-access-component-identity-fixture-failure-v1", "stage": stage,
                    "completed_assertions": count, "next_assertion": count + 1,
                    "installed_reads": false, "service_actions": false]
                if let data = try? JSONSerialization.data(withJSONObject: failure, options: [.sortedKeys]) {
                    FileHandle.standardError.write(data); FileHandle.standardError.write(Data([10]))
                }
            }
        }
        var valid: [(Data, Int32?)] = [(printData(program + "\tstate = running\n\tpid = 123\n"), 123)]
        for state in ["spawn scheduled", "not running", "waiting", "exited", "stopped"] {
            valid.append((printData(program + "\tstate = " + state + "\n"), nil))
        }
        valid.append((printData(program + "\tstate = running\n\tpid = 123\n\tnested = {\n\t\tpid = 456\n\t}\n"), 123))
        valid.append((printData(program + "\tstate = running\n\tpid = 123\n\tother = \"escaped \\\" { }\"\n"), 123))
        for (data, expected) in valid {
            guard try ComponentUpdateIdentity.printedPID(data) == expected else { throw ComponentUpdateFailure.context }
            count += 1
        }
        stage = "invalid_job_print"
        let running = program + "\tstate = running\n\tpid = 123\n"
        var invalid: [Data] = [
            Data(("gui/501/com.fainir.accountaccess.broker = {\n" + running + "}\n").utf8),
            printData("\tprogram = /tmp/other\n\tstate = running\n\tpid = 123\n"),
            printData("\tstate = running\n\tpid = 123\n"),
            printData(program + "\tpid = 123\n"),
            printData(program + "\tstate = running\n"),
            printData(program + "\tstate = unknown\n"),
            printData(program + "\tstate = stopped\n\tpid = 123\n"),
            printData(running + program),
            printData(running + "\tstate = running\n"),
            printData(running + "\tpid = 123\n"),
            printData(program + "\tstate = running\n\tpid = 0\n"),
            printData(program + "\tstate = running\n\tpid = 1\n"),
            printData(program + "\tstate = running\n\tpid = -1\n"),
            printData(program + "\tstate = running\n\tpid = 2147483648\n"),
            printData(program + "\tstate = running\n\tpid = 3.0\n"),
            printData(program + "\tstate = running\n\tpid = 0123\n"),
            printData(program + "\tstate = running\n\tpid = +123\n"),
            Data((header + running).utf8),
            Data((header + running + "}\nextra\n").utf8),
            Data((header + running + "} extra\n").utf8),
            Data((header + running + "} { }\n").utf8),
            printData(running + "\tother = \"unclosed\n"),
            printData(program + "\tstate = running\n\tnested = {\n\t\tpid = 123\n\t}\n"),
            Data((header + running + "}\n" + header + running + "}\n").utf8),
        ]
        invalid += [Data([0xff]), printData(running) + Data([0]), Data(repeating: 65, count: 256 * 1024 + 1),
                    printData(running + String(repeating: "\n", count: 10_001))]
        for data in invalid {
            try rejects { _ = try ComponentUpdateIdentity.printedPID(data) }
            count += 1
        }
        stage = "valid_process_identity"
        let good = ComponentJobIdentity(pid: 123, group: 123, birthSec: 100, birthUsec: 10, bootSession: boot)
        try ComponentUpdateIdentity.validateSnapshot(good); count += 1
        stage = "invalid_process_identity"
        let bad: [ComponentJobIdentity] = [
            .init(pid: 1, group: 1, birthSec: 100, birthUsec: 10, bootSession: boot),
            .init(pid: -1, group: 123, birthSec: 100, birthUsec: 10, bootSession: boot),
            .init(pid: 123, group: 456, birthSec: 100, birthUsec: 10, bootSession: boot),
            .init(pid: 123, group: 123, birthSec: 0, birthUsec: 10, bootSession: boot),
            .init(pid: 123, group: 123, birthSec: 100, birthUsec: 1_000_000, bootSession: boot),
            .init(pid: 123, group: 123, birthSec: 100, birthUsec: 10, bootSession: boot.uppercased()),
            .init(pid: 123, group: 123, birthSec: 100, birthUsec: 10, bootSession: "not-a-boot-uuid"),
        ]
        for item in bad {
            try rejects { try ComponentUpdateIdentity.validateSnapshot(item) }; count += 1
        }
        stage = "empty_process_group"
        try ComponentUpdateIdentity.requireEmptyProcessGroup(byteCount: 0, error: 0); count += 1
        stage = "invalid_process_group"
        let groupResults: [(Int32, Int32)] = [(0, EPERM), (4, 0), (-1, 0)]
        for (bytes, error) in groupResults {
            try rejects { try ComponentUpdateIdentity.requireEmptyProcessGroup(byteCount: bytes, error: error) }
            count += 1
        }
        stage = "revalidation_service_observations"
        let revalidation = try revalidationObservations()
        count += revalidation.0
        stage = "final_count"
        guard count == 69 else { throw ComponentUpdateFailure.context }
        completed = true
        return (count, ["fixed_job_parser_accepts_only_closed_states": true,
                        "foreign_or_malformed_job_print_rejected": true,
                        "saved_process_identity_bound_to_birth_and_boot": true,
                        "process_group_error_not_empty": true].merging(revalidation.1) { _, _ in true })
    }
}
