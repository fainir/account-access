import Foundation
import Darwin

@main struct WorkerBootstrapChecks {
    static func main() throws {
        guard getuid() != 0 else { exit(1) }
        for value in [true, false, -1, 0, 1.5, "501"] as [Any] {
            guard (try? WorkerLaunchPaths.integer(value)) == nil else { exit(1) }
        }
        guard try WorkerLaunchPaths.integer(501) == 501 else { exit(1) }
        for path in ["relative", "/tmp/../policy", "/tmp/policy\0"] {
            guard (try? WorkerLaunchPaths.lexical(path)) == nil else { exit(1) }
        }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("aawb-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("policy.json")
        try Data("{}".utf8).write(to: file)
        guard (try? WorkerLaunchPaths.object(file.path)) == nil else { exit(1) }
        do {
            try MacWorkerBootstrap.run([])
        } catch let error as WorkerLaunchFailure {
            guard error == .rootRequired else { exit(1) }
        }
        print("PASS: non-root launcher denied, unsafe paths/policies and invalid identity values rejected")
    }
}
