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
    private static func systemProcessObservations() throws -> (Int, [String: Bool]) {
        var count = 0
        func expect(_ value: Bool) throws {
            guard value else { throw ComponentUpdateFailure.context }; count += 1
        }
        func identity(pid: Int32 = 123, parent: UInt32 = 1, uid: UInt32 = 450,
                      real: UInt32 = 450, saved: UInt32 = 450, sec: UInt64 = 100,
                      usec: UInt64 = 10, path: String = "/usr/sbin/distnoted") -> ComponentSystemProcessIdentity {
            .init(pid: pid, parent: parent, uid: uid, realUID: real, savedUID: saved,
                  birthSec: sec, birthUsec: usec, path: path)
        }
        let first = identity(), second = identity(pid: 124, path: "/usr/libexec/lsd")
        try expect(first.signingIdentifier(brokerUID: 450) == "com.apple.distnoted")
        try expect(second.signingIdentifier(brokerUID: 450) == "com.apple.lsd")
        for invalid in [identity(pid: 1), identity(parent: 2), identity(uid: 451), identity(real: 0),
                        identity(saved: 0), identity(sec: 0), identity(usec: 1_000_000),
                        identity(path: "/tmp/distnoted"), identity(path: "/usr/sbin/../sbin/distnoted"),
                        identity(path: "/usr/libexec/other"), identity(path: "/usr/sbin/distnoted\0"),
                        identity(path: "/Library/Application Support/Account Access/bin/AccountAccess-broker")] {
            try rejects { _ = try invalid.signingIdentifier(brokerUID: 450) }; count += 1
        }
        for uid: uid_t in [0, 449, 500, 501] {
            try rejects { _ = try first.signingIdentifier(brokerUID: uid) }; count += 1
        }
        do {
            var reads = 0, attestations = 0, lists = 0
            let api = ComponentSystemProcessObserver(list: { lists += 1; return lists == 1 ? [124, 123] : [123, 124] },
                observe: { pid in reads += 1; return pid == 123 ? first : second }, attest: { row, name in
                    guard name == (row.pid == 123 ? "com.apple.distnoted" : "com.apple.lsd") else { throw ComponentUpdateFailure.context }
                    attestations += 1
                })
            try api.verify(brokerUID: 450)
            try expect(reads == 4 && attestations == 2 && lists == 2)
            // Every barrier repeats the observations and signature checks.
            try api.verify(brokerUID: 450)
            try expect(reads == 8 && attestations == 4 && lists == 4)
        }
        do {
            var lists = 0
            let api = ComponentSystemProcessObserver(list: { lists += 1; return [] },
                observe: { _ in throw ComponentUpdateFailure.context }, attest: { _, _ in throw ComponentUpdateFailure.context })
            try api.verify(brokerUID: 450); try expect(lists == 2)
        }
        for scenario in ["duplicate", "too_many", "wrong_pid", "unknown_path", "duplicate_path", "signature",
                         "changed_birth", "changed_path", "changed_uid", "list_error", "info_error", "new_pid", "exited_pid"] {
            var lists = 0, observations = 0
            let api = ComponentSystemProcessObserver(list: {
                lists += 1
                switch scenario {
                case "list_error": throw ComponentUpdateFailure.quiescence
                case "duplicate": return [123, 123]
                case "too_many": return [123, 124, 125]
                case "duplicate_path": return [123, 124]
                case "new_pid" where lists == 2: return [123, 124]
                case "exited_pid" where lists == 2: return []
                default: return [123]
                }
            }, observe: { pid in
                observations += 1
                switch scenario {
                case "info_error": throw ComponentUpdateFailure.quiescence
                case "wrong_pid": return identity(pid: 456)
                case "unknown_path": return identity(path: "/tmp/distnoted")
                case "duplicate_path": return identity(pid: pid)
                case "changed_birth" where observations == 2: return identity(sec: 101)
                case "changed_path" where observations == 2: return identity(path: "/usr/libexec/lsd")
                case "changed_uid" where observations == 2: return identity(uid: 451)
                default: return first
                }
            }, attest: { _, _ in
                if scenario == "signature" { throw ComponentUpdateFailure.quiescence }
            })
            try rejects { try api.verify(brokerUID: 450) }; count += 1
        }
        guard count == 34 else { throw ComponentUpdateFailure.context }
        return (count, ["only_fixed_apple_process_paths_and_dedicated_identity_eligible": true,
                        "system_process_signature_failure_refuses": true,
                        "system_process_pid_birth_path_uid_races_refuse": true,
                        "system_process_new_duplicate_or_unobservable_pids_refuse": true,
                        "system_process_attestation_repeats_at_every_barrier": true])
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
        stage = "system_process_observations"
        let systemProcesses = try systemProcessObservations()
        count += systemProcesses.0
        completed = true
        return (count, ["fixed_job_parser_accepts_only_closed_states": true,
                        "foreign_or_malformed_job_print_rejected": true,
                        "saved_process_identity_bound_to_birth_and_boot": true,
                        "process_group_error_not_empty": true].merging(revalidation.1) { _, _ in true }
                            .merging(systemProcesses.1) { _, _ in true })
    }
}
