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
        stage = "final_count"
        guard count == 48 else { throw ComponentUpdateFailure.context }
        completed = true
        return (count, ["fixed_job_parser_accepts_only_closed_states": true,
                        "foreign_or_malformed_job_print_rejected": true,
                        "saved_process_identity_bound_to_birth_and_boot": true,
                        "process_group_error_not_empty": true])
    }
}
