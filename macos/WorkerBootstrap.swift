// Root-invoked child launcher for a separately managed Mac broker. No setuid
// bit, elevation request, service installation or credential-file fallback.
import Foundation
import Darwin

enum WorkerLaunchFailure: String, Error {
    case rootRequired = "worker_launcher_requires_root"
    case invalidArguments = "invalid_worker_launcher_arguments"
    case invalidPolicy = "invalid_worker_launcher_policy"
    case unsafeRuntime = "unsafe_worker_launcher_runtime"
    case invalidIdentity = "invalid_worker_launcher_identity"
    case invalidDescriptors = "invalid_worker_launcher_descriptors"
    case identityDropFailed = "worker_identity_drop_failed"
    case executionFailed = "worker_execution_failed"
}

enum WorkerLaunchPaths {
    static func protected(_ path: String) throws -> URL {
        guard path.hasPrefix("/"), !path.utf8.contains(0), !path.split(separator: "/").contains("..") else {
            throw WorkerLaunchFailure.unsafeRuntime
        }
        let original = URL(fileURLWithPath: path)
        var pending = [original, original.resolvingSymlinksInPath()]
        var checked: Set<String> = []
        while var item = pending.popLast() {
            if checked.contains(item.path) { continue }
            checked.insert(item.path)
            guard checked.count <= 64 else { throw WorkerLaunchFailure.unsafeRuntime }
            while true {
                var info = stat()
                guard lstat(item.path, &info) == 0, info.st_uid == 0 else { throw WorkerLaunchFailure.unsafeRuntime }
                if info.st_mode & S_IFMT == S_IFLNK {
                    let target = try FileManager.default.destinationOfSymbolicLink(atPath: item.path)
                    pending.append(target.hasPrefix("/") ? URL(fileURLWithPath: target)
                        : item.deletingLastPathComponent().appendingPathComponent(target))
                } else if info.st_mode & 0o022 != 0 { throw WorkerLaunchFailure.unsafeRuntime }
                if item.path == "/" { break }
                item.deleteLastPathComponent()
            }
        }
        return original.resolvingSymlinksInPath()
    }

    static func object(_ path: String) throws -> [String: Any] {
        let url = try protected(path)
        var info = stat()
        guard lstat(url.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_nlink == 1, info.st_size <= 4096,
              let value = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any] else {
            throw WorkerLaunchFailure.invalidPolicy
        }
        return value
    }
    static func integer(_ value: Any?, maximum: UInt32 = UInt32.max) throws -> UInt32 {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue > 0, number.doubleValue <= Double(maximum),
              number.doubleValue == Double(number.uint32Value) else { throw WorkerLaunchFailure.invalidPolicy }
        return number.uint32Value
    }
    static func lexical(_ value: Any?) throws -> String {
        guard let path = value as? String, path.hasPrefix("/"), !path.utf8.contains(0),
              !path.split(separator: "/").contains(".."), !path.hasSuffix("/") else { throw WorkerLaunchFailure.invalidPolicy }
        return path
    }
}

struct MacWorkerPlan {
    let python: String
    let runtime: String
    let workerPolicy: String
    let uid: uid_t
    let gid: gid_t
    let agentUID: uid_t
    let brokerHome: String
    let brokerName: String
    let agentSocket: String
    let ownerSocket: String
    let browsers: String
    let fixtureCA: String?
    let fixture: Bool

    init(policy path: String) throws {
        let value = try WorkerLaunchPaths.object(path)
        guard Set(value.keys) == ["managed_by", "schema", "python", "runtime", "worker_policy", "broker_gid",
                                 "broker_home", "browsers", "fixture", "fixture_ca"],
              value["managed_by"] as? String == "account-access-mac-worker-v1",
              try WorkerLaunchPaths.integer(value["schema"]) == 1,
              let fixtureNumber = value["fixture"] as? NSNumber,
              CFGetTypeID(fixtureNumber) == CFBooleanGetTypeID() else { throw WorkerLaunchFailure.invalidPolicy }
        fixture = fixtureNumber.boolValue
        python = try WorkerLaunchPaths.lexical(value["python"])
        runtime = try WorkerLaunchPaths.lexical(value["runtime"])
        workerPolicy = try WorkerLaunchPaths.lexical(value["worker_policy"])
        brokerHome = try WorkerLaunchPaths.lexical(value["broker_home"])
        browsers = try WorkerLaunchPaths.lexical(value["browsers"])
        gid = try WorkerLaunchPaths.integer(value["broker_gid"])
        if value["fixture_ca"] is NSNull { fixtureCA = nil }
        else {
            guard fixture else { throw WorkerLaunchFailure.invalidPolicy }
            fixtureCA = try WorkerLaunchPaths.lexical(value["fixture_ca"])
        }
        let worker = try WorkerLaunchPaths.object(workerPolicy)
        guard Set(worker.keys) == ["managed_by", "schema", "broker_uid", "agent_uid", "root", "agent_socket", "owner_socket", "owner_port"],
              worker["managed_by"] as? String == "account-access-worker-v1",
              try WorkerLaunchPaths.integer(worker["schema"]) == 1 else { throw WorkerLaunchFailure.invalidPolicy }
        uid = try WorkerLaunchPaths.integer(worker["broker_uid"])
        agentUID = try WorkerLaunchPaths.integer(worker["agent_uid"])
        guard uid != agentUID else { throw WorkerLaunchFailure.invalidIdentity }
        agentSocket = try WorkerLaunchPaths.lexical(worker["agent_socket"])
        ownerSocket = try WorkerLaunchPaths.lexical(worker["owner_socket"])
        guard agentSocket != ownerSocket else { throw WorkerLaunchFailure.invalidPolicy }
        let _ = try WorkerLaunchPaths.integer(worker["owner_port"], maximum: 65535)
        let state = try WorkerLaunchPaths.lexical(worker["root"])
        _ = try WorkerLaunchPaths.protected(URL(fileURLWithPath: state).deletingLastPathComponent().path)
        var stateInfo = stat()
        guard lstat(state, &stateInfo) == 0, stateInfo.st_mode & S_IFMT == S_IFDIR,
              stateInfo.st_uid == uid, stateInfo.st_mode & 0o077 == 0 else { throw WorkerLaunchFailure.invalidIdentity }
        guard let account = getpwuid(uid) else { throw WorkerLaunchFailure.invalidIdentity }
        let registeredGID = account.pointee.pw_gid
        brokerName = String(cString: account.pointee.pw_name)
        let registeredHome = String(cString: account.pointee.pw_dir)
        let shell = String(cString: account.pointee.pw_shell)
        guard registeredGID == gid, registeredHome == brokerHome,
              ["/usr/bin/false", "/usr/sbin/nologin"].contains(shell),
              let agent = getpwuid(agentUID), agent.pointee.pw_gid != gid else { throw WorkerLaunchFailure.invalidIdentity }
        var homeInfo = stat()
        guard lstat(brokerHome, &homeInfo) == 0, homeInfo.st_mode & S_IFMT == S_IFDIR,
              homeInfo.st_uid == uid, homeInfo.st_mode & 0o077 == 0 else { throw WorkerLaunchFailure.invalidIdentity }
        _ = try WorkerLaunchPaths.protected(URL(fileURLWithPath: brokerHome).deletingLastPathComponent().path)
        let runtimeURL = try WorkerLaunchPaths.protected(runtime)
        let executable = try WorkerLaunchPaths.protected(python)
        _ = try WorkerLaunchPaths.protected(browsers)
        if let fixtureCA { _ = try WorkerLaunchPaths.protected(fixtureCA) }
        // The selected venv is fixed by root policy; its bin/python may point
        // to a different root-owned Python installation, as normal venvs do.
        guard URL(fileURLWithPath: python).deletingLastPathComponent().deletingLastPathComponent().resolvingSymlinksInPath() == runtimeURL,
              FileManager.default.isExecutableFile(atPath: executable.path) else { throw WorkerLaunchFailure.unsafeRuntime }
        var executableInfo = stat()
        guard lstat(executable.path, &executableInfo) == 0, executableInfo.st_mode & S_IFMT == S_IFREG,
              executableInfo.st_mode & 0o6000 == 0 else { throw WorkerLaunchFailure.unsafeRuntime }
        for socketPath in [agentSocket, ownerSocket] {
            _ = try WorkerLaunchPaths.protected(URL(fileURLWithPath: socketPath).deletingLastPathComponent().path)
        }
        var ownerDirectory = stat()
        guard lstat(URL(fileURLWithPath: ownerSocket).deletingLastPathComponent().path, &ownerDirectory) == 0,
              ownerDirectory.st_mode & 0o077 == 0 else { throw WorkerLaunchFailure.invalidPolicy }
    }

    var arguments: [String] {
        [python, "-I", "-B", "-m", "account_access.worker_host", "--policy", workerPolicy,
         "--bootstrap-fd", "3", "--agent-fd", "4", "--owner-fd", "5"] + (fixture ? ["--controlled-fixture"] : [])
    }
    var environment: [String] {
        ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8", "HOME=" + brokerHome,
         "USER=" + brokerName, "LOGNAME=" + brokerName, "PLAYWRIGHT_BROWSERS_PATH=" + browsers]
            + (fixtureCA.map { ["SSL_CERT_FILE=" + $0] } ?? [])
    }
}

enum MacWorkerBootstrap {
    static func checkFD(_ fd: Int32, type: mode_t, socketPath: String? = nil) throws {
        var info = stat()
        guard fd >= 3, fstat(fd, &info) == 0, info.st_mode & S_IFMT == type, info.st_uid == 0 else {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        // XNU reports the stat caller's uid for anonymous pipes. This check
        // establishes the channel's shape, not its creator; the trusted root
        // parent must create/pass it. Reject vnode-backed filesystem FIFOs.
        if type == S_IFIFO && (info.st_dev != 0 || info.st_nlink != 0) {
            throw WorkerLaunchFailure.invalidDescriptors
        }
        if let socketPath {
            var address = sockaddr_un(), length = socklen_t(MemoryLayout<sockaddr_un>.size)
            let result = withUnsafeMutablePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
            }
            var kind: Int32 = 0, kindLength = socklen_t(MemoryLayout<Int32>.size)
            guard result == 0, address.sun_family == sa_family_t(AF_UNIX),
                  getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &kindLength) == 0, kind == SOCK_STREAM else {
                throw WorkerLaunchFailure.invalidDescriptors
            }
            let name = withUnsafeBytes(of: address.sun_path) { raw in String(bytes: raw.prefix(while: { $0 != 0 }), encoding: .utf8) }
            guard name == socketPath else { throw WorkerLaunchFailure.invalidDescriptors }
        }
    }

    static func run(_ argv: [String]) throws -> Never {
        guard getuid() == 0, geteuid() == 0 else { throw WorkerLaunchFailure.rootRequired }
        umask(0o077)
        var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(RLIMIT_CORE, &noCore) == 0 else { throw WorkerLaunchFailure.unsafeRuntime }
        guard argv.count == 8, argv[0] == "--policy", argv[2] == "--bootstrap-fd",
              argv[4] == "--agent-fd", argv[6] == "--owner-fd",
              let secretFD = Int32(argv[3]), let agentFD = Int32(argv[5]), let ownerFD = Int32(argv[7]),
              Set([secretFD, agentFD, ownerFD]).count == 3 else { throw WorkerLaunchFailure.invalidArguments }
        let plan = try MacWorkerPlan(policy: argv[1])
        try checkFD(secretFD, type: S_IFIFO)
        try checkFD(agentFD, type: S_IFSOCK, socketPath: plan.agentSocket)
        try checkFD(ownerFD, type: S_IFSOCK, socketPath: plan.ownerSocket)
        let tableSize = getdtablesize()
        guard tableSize > 5, tableSize <= 65536 else { throw WorkerLaunchFailure.invalidDescriptors }
        // Make all three sources independent before overwriting descriptors
        // 3/4/5; the caller's descriptor numbers may overlap those targets.
        var duplicates: [Int32] = []
        for fd in [secretFD, agentFD, ownerFD] {
            let duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 10)
            guard duplicate >= 10 else { throw WorkerLaunchFailure.invalidDescriptors }
            duplicates.append(duplicate)
        }
        for (index, source) in duplicates.enumerated() {
            guard dup2(source, Int32(index + 3)) == index + 3 else { throw WorkerLaunchFailure.invalidDescriptors }
        }
        guard chdir(plan.brokerHome) == 0, setgroups(0, nil) == 0,
              setgid(plan.gid) == 0, setuid(plan.uid) == 0,
              getuid() == plan.uid, geteuid() == plan.uid, getgid() == plan.gid, getegid() == plan.gid else {
            throw WorkerLaunchFailure.identityDropFailed
        }
        var groups = [gid_t](repeating: 0, count: 128)
        let groupCount = getgroups(Int32(groups.count), &groups)
        guard groupCount >= 0, !groups.prefix(Int(groupCount)).contains(0),
              setuid(0) == -1, errno == EPERM, setgid(0) == -1, errno == EPERM else {
            throw WorkerLaunchFailure.identityDropFailed
        }
        var arguments = plan.arguments.map { strdup($0) }; arguments.append(nil)
        var environment = plan.environment.map { strdup($0) }; environment.append(nil)
        guard !arguments.dropLast().contains(where: { $0 == nil }),
              !environment.dropLast().contains(where: { $0 == nil }) else { throw WorkerLaunchFailure.executionFailed }
        // The next image gets only stdio and the three approved channels, even
        // if a library opened a descriptor while root policy was being read.
        for fd in Int32(6)..<tableSize {
            if fcntl(fd, F_GETFD) != -1 { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }
        }
        for fd in Int32(3)...5 {
            guard fcntl(fd, F_SETFD, 0) == 0 else { throw WorkerLaunchFailure.invalidDescriptors }
        }
        arguments.withUnsafeMutableBufferPointer { args in
            environment.withUnsafeMutableBufferPointer { env in _ = execve(plan.python, args.baseAddress!, env.baseAddress!) }
        }
        throw WorkerLaunchFailure.executionFailed
    }
}

#if ACCOUNT_ACCESS_WORKER_BOOTSTRAP_MAIN
@main struct MacWorkerBootstrapMain {
    static func main() {
        do { try MacWorkerBootstrap.run(Array(CommandLine.arguments.dropFirst())) }
        catch {
            let reason = (error as? WorkerLaunchFailure)?.rawValue ?? WorkerLaunchFailure.invalidPolicy.rawValue
            print("{\"status\":\"NEEDS_USER\",\"reason\":\"" + reason + "\"}")
            exit(78)
        }
    }
}
#endif
