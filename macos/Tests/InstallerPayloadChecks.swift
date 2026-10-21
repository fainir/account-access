// Ordinary-user fixtures only. This main is never linked into the installer.
import Foundation
import Darwin

@main struct InstallerPayloadChecks {
    static func main() {
        guard getuid() != 0, geteuid() == getuid() else { exit(64) }
        do {
            if CommandLine.arguments.count == 4, ["--resources", "--directory"].contains(CommandLine.arguments[1]) {
                let root = open(CommandLine.arguments[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard root >= 0 else { throw InstallerPayloadFailure.path }
                defer { Darwin.close(root) }
                let directory = try InstallerPayloadIO.walkDirectory(CommandLine.arguments[3], from: root, owner: getuid(),
                                                                      installerResources: CommandLine.arguments[1] == "--resources")
                Darwin.close(directory)
                print("{\"status\":\"VERIFIED\"}")
                return
            }
            let publicImage = CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--public-image"
            guard CommandLine.arguments.count == 3 || publicImage else { exit(64) }
            let file = open(CommandLine.arguments[publicImage ? 2 : 1], O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard file >= 0 else { throw InstallerPayloadFailure.path }
            let data: Data
            do { data = try InstallerPayloadIO.read(file, maximum: InstallerPayloadManifest.maximumManifest, owner: getuid()) }
            catch { Darwin.close(file); throw error }
            Darwin.close(file)
            let manifest = try InstallerPayloadManifest(data)
            let root = open(CommandLine.arguments[publicImage ? 3 : 2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0 else { throw InstallerPayloadFailure.path }
            defer { Darwin.close(root) }
            guard (try? InstallerPayloadIO.check(root, owner: getuid() + 1, directory: true)) == nil else { exit(1) }
            let counts = try InstallerPayloadIO.verifyImage(root, manifest: manifest, owner: getuid(), opaquePrivateBranches: publicImage)
            let second = try InstallerPayloadIO.verifyImage(root, manifest: manifest, owner: getuid(), opaquePrivateBranches: publicImage)
            guard counts.files == second.files, counts.directories == second.directories,
                  counts.aliases == second.aliases else { exit(1) }
            print("{\"status\":\"VERIFIED\",\"files\":\(counts.files),\"directories\":\(counts.directories),\"aliases\":\(counts.aliases)}")
        } catch {
            let reason = (error as? InstallerPayloadFailure)?.rawValue ?? "invalid_installer_payload_manifest"
            print("{\"status\":\"REFUSED\",\"reason\":\"\(reason)\"}")
            exit(78)
        }
    }
}
