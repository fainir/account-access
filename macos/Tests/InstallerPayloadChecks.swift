// Ordinary-user fixtures only. This main is never linked into the installer.
import Foundation
import Darwin

@main struct InstallerPayloadChecks {
    static func installIntentChecks(_ manifest: InstallerPayloadManifest) throws {
        let digest = manifest.sha256
        func record(_ image: String) throws -> Data {
            try JSONSerialization.data(withJSONObject: [
                "managed_by": "account-access-public-image-install-v1",
                "manifest_sha256": image,
                "owner_uid": Int(getuid()),
                "schema": 1,
            ], options: [.sortedKeys])
        }
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("AccountAccessInstallPreflight-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: base) }
        let support = base.appendingPathComponent("Library/Application Support", isDirectory: true)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let root = open(base.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw InstallerPayloadFailure.path }
        defer { Darwin.close(root) }
        try InstallerPayloadIO.preflightExistingInstall(manifest, from: root, objectOwner: getuid())
        let journal = support.appendingPathComponent("Account Access Installer", isDirectory: true)
        try FileManager.default.createDirectory(at: journal, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        let intent = journal.appendingPathComponent("intent.json")
        let pending = journal.appendingPathComponent(".pending-intent.json")
        try record(digest).write(to: intent, options: .atomic)
        guard chmod(intent.path, 0o600) == 0 else { throw InstallerPayloadFailure.object }
        try InstallerPayloadIO.preflightExistingInstall(manifest, from: root, objectOwner: getuid())

        try record(String(repeating: "b", count: 64)).write(to: intent, options: .atomic)
        guard chmod(intent.path, 0o600) == 0 else { throw InstallerPayloadFailure.object }
        do {
            try InstallerPayloadIO.preflightExistingInstall(manifest, from: root, objectOwner: getuid())
            throw InstallerPayloadFailure.manifest
        } catch let failure as InstallerPayloadFailure {
            guard failure.rawValue == InstallerPayloadFailure.updateRequired.rawValue else { throw failure }
        }

        try Data("{}".utf8).write(to: intent, options: .atomic)
        guard chmod(intent.path, 0o600) == 0 else { throw InstallerPayloadFailure.object }
        do {
            try InstallerPayloadIO.preflightExistingInstall(manifest, from: root, objectOwner: getuid())
            throw InstallerPayloadFailure.manifest
        } catch let failure as InstallerPayloadFailure {
            guard failure.rawValue == InstallerPayloadFailure.installJournal.rawValue else { throw failure }
        }

        try record(digest).write(to: intent, options: .atomic)
        guard chmod(intent.path, 0o600) == 0, link(intent.path, pending.path) == 0 else {
            throw InstallerPayloadFailure.object
        }
        try InstallerPayloadIO.preflightExistingInstall(manifest, from: root, objectOwner: getuid())
    }
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
            try installIntentChecks(manifest)
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
