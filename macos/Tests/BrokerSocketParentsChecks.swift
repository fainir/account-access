// Synthetic, root-owned fixture only. This executable never targets the app.
import Darwin
import Foundation

@main struct BrokerSocketParentsChecks {
    private static func metadata(_ path: String, mode: mode_t) -> stat {
        var value = stat()
        precondition(lstat(path, &value) == 0 && value.st_uid == 0)
        precondition(value.st_mode & S_IFMT == S_IFDIR && value.st_mode & 0o7777 == mode)
        return value
    }

    static func main() throws {
        let args = CommandLine.arguments
        precondition(getuid() == 0 && geteuid() == 0 && args.count == 2)
        let root = args[1]
        let prefix = "/Library/Application Support/.aa-socket-parent-check-"
        precondition(root.hasPrefix(prefix) && !root.dropFirst(prefix.count).contains("/"))
        let run = root + "/run", control = root + "/control"
        _ = umask(0o077)
        precondition(!FileManager.default.fileExists(atPath: run) && !FileManager.default.fileExists(atPath: control))

        if getppid() == 1 {
            try BrokerSocketParents.prepare(in: root)
            for name in ["Agent", "Owner"] {
                var fd: Int32 = -1
                precondition(AccountAccessActivateSocket(name, &fd) == 0 && fd >= 3)
                _ = close(fd)
            }
            _ = metadata(run, mode: 0o755)
            _ = metadata(control, mode: 0o700)
            print("PASS: launchd supplied both sockets with the intended parent modes")
            return
        }

        func expectUnsafeControl() throws {
            do {
                try BrokerSocketParents.prepare(in: root)
                preconditionFailure("unsafe control directory was admitted")
            } catch SystemBrokerFailure.socketParents {}
            precondition(!FileManager.default.fileExists(atPath: run))
        }

        precondition(symlink(root, control) == 0)
        try expectUnsafeControl()
        precondition(unlink(control) == 0)
        precondition(mkdir(control, 0o700) == 0 && chmod(control, 0o755) == 0)
        try expectUnsafeControl()
        precondition(rmdir(control) == 0)

        try BrokerSocketParents.prepare(in: root)
        let agent = metadata(run, mode: 0o755), owner = metadata(control, mode: 0o700)
        try BrokerSocketParents.prepare(in: root)
        precondition(metadata(run, mode: 0o755).st_ino == agent.st_ino)
        precondition(metadata(control, mode: 0o700).st_ino == owner.st_ino)
        print("PASS: creates both missing parents, preserves existing directories, and refuses an unsafe control path before creating run")
    }
}
