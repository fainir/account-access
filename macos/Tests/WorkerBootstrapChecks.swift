import Foundation
import Darwin

@main struct WorkerBootstrapChecks {
    static func main() throws {
        guard getuid() != 0 else { exit(1) }
        if ["--check-inherited", "--check-inherited-enrollment"].contains(CommandLine.arguments.dropFirst().first ?? "") {
            let last: Int32 = CommandLine.arguments[1] == "--check-inherited-enrollment" ? 4 : 5
            guard CommandLine.arguments.count == 3, Int32(CommandLine.arguments[2]) == getpid(),
                  (Int32(0)...last).allSatisfy({ fcntl($0, F_GETFD) != -1 }),
                  ((last + 1)...6).allSatisfy({ fcntl($0, F_GETFD) == -1 }), fcntl(128, F_GETFD) == -1,
                  getenv("ACCOUNT_ACCESS_INERT_INHERITANCE_FIXTURE") == nil else { exit(1) }
            print("PASS: kernel descriptor allowlist retained only approved handles and preserved PID")
            return
        }
        if ["--prepare-inherited", "--prepare-inherited-enrollment"].contains(CommandLine.arguments.dropFirst().first ?? "") {
            let enrollment = CommandLine.arguments[1] == "--prepare-inherited-enrollment"
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
                arguments: [executable, enrollment ? "--check-inherited-enrollment" : "--check-inherited", String(getpid())],
                environment: ["PATH=/usr/bin:/bin"], lastDescriptor: enrollment ? 4 : 5)
        }
        for value in [true, false, -1, 0, 1.5, "501"] as [Any] {
            guard (try? WorkerLaunchPaths.integer(value)) == nil else { exit(1) }
        }
        guard try WorkerLaunchPaths.integer(501) == 501 else { exit(1) }
        for path in ["relative", "/tmp/../policy", "/tmp/policy\0"] {
            guard (try? WorkerLaunchPaths.lexical(path)) == nil else { exit(1) }
        }
        let folder = URL(fileURLWithPath: "/tmp").appendingPathComponent("aawb-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("policy.json")
        try Data("{}".utf8).write(to: file)
        func aclCommand(_ arguments: [String]) throws {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = arguments + [file.path]
            try process.run(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { exit(1) }
        }
        try WorkerLaunchPaths.rejectGrantACL(file.path)
        try aclCommand(["+a", "everyone allow write"])
        guard (try? WorkerLaunchPaths.rejectGrantACL(file.path)) == nil else { exit(1) }
        try aclCommand(["-N"])
        try aclCommand(["+a", "everyone deny delete"])
        try WorkerLaunchPaths.rejectGrantACL(file.path)
        try aclCommand(["-N"])
        print("PASS: runtime allow ACL refused; absent/restrictive ACL accepted")
        let ordinary = open(file.path, O_RDONLY)
        guard ordinary >= 3 else { exit(1) }
        defer { Darwin.close(ordinary) }
        guard (try? MacWorkerBootstrap.requireListening(ordinary)) == nil else { exit(1) }
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        let client = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 3, client >= 3 else { exit(1) }
        defer { Darwin.close(listener); Darwin.close(client) }
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size); address.sun_family = sa_family_t(AF_UNIX)
        let bytes = folder.appendingPathComponent("listen.sock").path.utf8CString.map { UInt8(bitPattern: $0) }
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { exit(1) }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0 else { exit(1) }
        try MacWorkerBootstrap.requireListening(listener)
        try MacWorkerBootstrap.requireListening(listener)
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard connected == 0 else { exit(1) }
        let accepted = accept(listener, nil, nil)
        guard accepted >= 3 else { exit(1) }
        defer { Darwin.close(accepted) }
        guard (try? MacWorkerBootstrap.requireListening(accepted)) == nil else { exit(1) }
        print("PASS: Unix listener readiness/relisten verified; regular files and connected streams rejected")
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
        let enrollmentProbe = Process()
        enrollmentProbe.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        enrollmentProbe.arguments = ["--prepare-inherited-enrollment"]
        try enrollmentProbe.run(); enrollmentProbe.waitUntilExit()
        guard enrollmentProbe.terminationReason == .exit, enrollmentProbe.terminationStatus == 0 else { exit(1) }
        print("PASS: non-root launcher denied, unsafe paths/policies and invalid identity values rejected")
    }
}
