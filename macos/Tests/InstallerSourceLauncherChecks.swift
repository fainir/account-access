// Ordinary-user public fixtures only. Never linked into the installer.
import Foundation
import CryptoKit
import Darwin

@main struct InstallerSourceLauncherChecks {
    static func main() {
        guard getuid() != 0, geteuid() == getuid(), CommandLine.arguments.count == 5 else { exit(64) }
        do {
            let source = open(CommandLine.arguments[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let manifest = open(CommandLine.arguments[3], O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard source >= 3, manifest >= 3 else { exit(64) }
            let data = try InstallerPayloadIO.read(manifest, maximum: InstallerPayloadManifest.maximumManifest, owner: getuid())
            guard lseek(manifest, 0, SEEK_SET) == 0, dup2(manifest, 200) == 200 else { exit(64) }
            setenv("ACCOUNT_ACCESS_UNRELATED_ENV", "public-unrelated-sentinel", 1)
            setenv("PYTHONPATH", "/public-unrelated-sentinel", 1)
            if CommandLine.arguments[4] == "closed-stdin" { Darwin.close(0) }
            let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            try InstallerPayloadIO.replaceSource(CommandLine.arguments[1], source: source, manifest: manifest, digest: digest)
        } catch {
            if let error = error as? InstallerSpawnFailure {
                print("{\"status\":\"FAILED\",\"operation\":\"\(error.operation.rawValue)\",\"error_code\":\(error.code)}")
            } else { print("{\"status\":\"FAILED\"}") }
            exit(78)
        }
    }
}
