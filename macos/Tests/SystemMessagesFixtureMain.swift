// CI-only receiver. Never included in a consumer download.
import Foundation
import Darwin

#if !ACCOUNT_ACCESS_GATEWAY_CHECKS
#error("Synthetic Messages receiver requires CI flags")
#endif
@main struct SystemMessagesFixtureMain {
    static func main() throws {
        guard getuid() != 0, [3, 4].contains(CommandLine.arguments.count) else { exit(78) }
        let profile = CommandLine.arguments[1], database = CommandLine.arguments[2]
        let prefix = "/Library/PrivilegedHelperTools/account-access-worker-qa-"
        guard profile.hasPrefix(prefix), database.hasPrefix(prefix) else { exit(78) }
        let object = try WorkerLaunchPaths.object(profile)
        guard Set(object.keys) == ["owner_uid", "parent_hash"],
              try WorkerLaunchPaths.integer(object["owner_uid"]) == getuid(),
              let hash = object["parent_hash"] as? String else { exit(78) }
        var info = stat()
        guard lstat(database, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0, info.st_nlink == 1 else { exit(78) }
        let peer = try OwnerGatewayPeer.fixture(uid: 0, codeHash: hash)
        if !SystemMessagesReader.parentAuthorized(peer) {
            FileHandle.standardOutput.write(Data("{\"status\":\"NEEDS_USER\",\"reason\":\"owner_authorization_required\"}".utf8))
            return
        }
        if CommandLine.arguments.count == 4 {
            guard CommandLine.arguments[3] == "--wrong-pid" else { exit(78) }
            var hello = try JSONSerialization.data(withJSONObject: ["status": "READER_READY", "pid": Int(getppid())])
            hello.append(10); FileHandle.standardOutput.write(hello)
        } else { SystemMessagesReader.announce() }
        var data = Data()
        while data.count <= 8192 {
            guard let part = try? FileHandle.standardInput.read(upToCount: 8193 - data.count), !part.isEmpty else { break }
            data.append(part)
        }
        let value = SystemMessagesReader.perform(data, peer: peer, path: database)
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: value))
    }
}
