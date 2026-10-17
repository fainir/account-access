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
            var counts = InstallerPayloadCounts()
            for path in manifest.trees.keys.sorted() {
                var directory = dup(root)
                guard directory >= 0 else { throw InstallerPayloadFailure.path }
                do {
                    let parts = path.split(separator: "/").map(String.init)
                    for (index, part) in parts.enumerated() {
                        let next = openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                        guard next >= 0 else { throw InstallerPayloadFailure.path }
                        do { _ = try InstallerPayloadIO.check(next, owner: getuid(), directory: true,
                                                             sharedParent: index == 0 && part == "Applications") }
                        catch { Darwin.close(next); throw error }
                        Darwin.close(directory); directory = next
                    }
                    let extras: Set<String> = publicImage && path == InstallerPayloadManifest.support
                        ? ["broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"] : []
                    let first = try InstallerPayloadIO.verify(directory, tree: manifest.trees[path]!, owner: getuid(), rootExtras: extras)
                    let second = try InstallerPayloadIO.verify(directory, tree: manifest.trees[path]!, owner: getuid(), rootExtras: extras)
                    guard first.files == second.files, first.directories == second.directories,
                          first.aliases == second.aliases else { exit(1) }
                    counts.add(first)
                } catch { Darwin.close(directory); throw error }
                Darwin.close(directory)
            }
            print("{\"status\":\"VERIFIED\",\"files\":\(counts.files),\"directories\":\(counts.directories),\"aliases\":\(counts.aliases)}")
        } catch {
            let reason = (error as? InstallerPayloadFailure)?.rawValue ?? "invalid_installer_payload_manifest"
            print("{\"status\":\"REFUSED\",\"reason\":\"\(reason)\"}")
            exit(78)
        }
    }
}
