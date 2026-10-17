import Foundation
import Darwin

@main struct WorkerBootstrapChecks {
    static func main() throws {
        guard getuid() != 0 else { exit(1) }
        if CommandLine.arguments.dropFirst().first == "--check-inherited" {
            guard CommandLine.arguments.count == 3, Int32(CommandLine.arguments[2]) == getpid(),
                  (Int32(0)...5).allSatisfy({ fcntl($0, F_GETFD) != -1 }),
                  fcntl(6, F_GETFD) == -1, fcntl(128, F_GETFD) == -1,
                  getenv("ACCOUNT_ACCESS_INERT_INHERITANCE_FIXTURE") == nil else { exit(1) }
            print("PASS: kernel descriptor allowlist retained only approved handles and preserved PID")
            return
        }
        if CommandLine.arguments.dropFirst().first == "--prepare-inherited" {
            var limit = rlimit()
            guard getrlimit(RLIMIT_NOFILE, &limit) == 0, limit.rlim_max >= 256 else { exit(1) }
            limit.rlim_cur = 256
            guard setrlimit(RLIMIT_NOFILE, &limit) == 0 else { exit(1) }
            let source = open("/dev/null", O_RDONLY)
            guard source >= 0 else { exit(1) }
            let safe = fcntl(source, F_DUPFD_CLOEXEC, 10)
            guard safe >= 10 else { exit(1) }
            for fd in Int32(3)...6 { guard dup2(safe, fd) == fd else { exit(1) } }
            guard fcntl(safe, F_DUPFD, 128) == 128, fcntl(128, F_SETFD, 0) == 0 else { exit(1) }
            limit.rlim_cur = 64
            guard setrlimit(RLIMIT_NOFILE, &limit) == 0, getdtablesize() == 64,
                  fcntl(128, F_GETFD) != -1 else { exit(1) }
            setenv("ACCOUNT_ACCESS_INERT_INHERITANCE_FIXTURE", "fictional-only", 1)
            let executable = URL(fileURLWithPath: CommandLine.arguments[0]).path
            try MacWorkerBootstrap.replaceImage(executable,
                arguments: [executable, "--check-inherited", String(getpid())], environment: ["PATH=/usr/bin:/bin"])
        }
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
        let probe = Process()
        probe.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        probe.arguments = ["--prepare-inherited"]
        try probe.run(); probe.waitUntilExit()
        guard probe.terminationReason == .exit, probe.terminationStatus == 0 else { exit(1) }
        print("PASS: non-root launcher denied, unsafe paths/policies and invalid identity values rejected")
    }
}
