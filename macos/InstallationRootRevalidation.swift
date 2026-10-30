// Standalone native Installer entrypoint; no ordinary-user filesystem access.
import Foundation
import Darwin

#if ACCOUNT_ACCESS_INSTALLATION_ROOT_REVALIDATION_MAIN && ACCOUNT_ACCESS_COMPONENT_UPDATE_MAIN
#error("The revalidation and component update entrypoints must be built separately")
#endif

#if ACCOUNT_ACCESS_INSTALLATION_ROOT_REVALIDATION_MAIN
private enum InstallationRevalidationReport {
    // Diagnostic output only. Eight completed OR interrupted attempts consume
    // at most eight fixed slots; existing reports are never overwritten.
    static func publish(_ data: Data, plan: String) throws {
        guard getuid() == 0, geteuid() == 0, data.count <= 1024,
              plan.utf8.count == 64, plan.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw ComponentUpdateFailure.context
        }
        let parent = try InstallerPayloadIO.directory("/Library/Application Support", owner: 0)
        defer { Darwin.close(parent) }
        let name = "Account Access Diagnostics"
        let created = mkdirat(parent, name, 0o700) == 0
        if !created && errno != EEXIST { throw ComponentUpdateFailure.object }
        let directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw ComponentUpdateFailure.object }
        defer { Darwin.close(directory) }
        var current = stat()
        let before = try InstallerPayloadIO.check(directory, owner: 0, directory: true)
        guard fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0, InstallerPayloadIO.same(before, current) else {
            throw ComponentUpdateFailure.object
        }
        try InstallationRootBinding.noACL(directory)
        if created {
            guard before.st_mode & 0o7777 == 0o700, fchmod(directory, 0o755) == 0,
                  fsync(directory) == 0, fsync(parent) == 0 else { throw ComponentUpdateFailure.object }
        }
        guard try InstallerPayloadIO.check(directory, owner: 0, directory: true).st_mode & 0o7777 == 0o755 else {
            throw ComponentUpdateFailure.object
        }
        for slot in 0..<8 {
            let final = "root-revalidation-" + plan + String(format: "-attempt-%02d.json", slot)
            let pending = "pending-" + final
            var info = stat()
            if fstatat(directory, final, &info, AT_SYMLINK_NOFOLLOW) == 0 { continue }
            guard errno == ENOENT else { throw ComponentUpdateFailure.object }
            if fstatat(directory, pending, &info, AT_SYMLINK_NOFOLLOW) == 0 { continue }
            guard errno == ENOENT else { throw ComponentUpdateFailure.object }
            _ = try ComponentFiles.writeExclusive(directory, pending, data: data, owner: 0, mode: 0o644)
            let file = openat(directory, pending, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard file >= 0 else { throw ComponentUpdateFailure.object }
            do { try InstallationRootBinding.noACL(file) } catch { Darwin.close(file); throw error }
            Darwin.close(file)
            try ComponentFiles.rename(directory, pending, directory, final, swap: false)
            return
        }
        throw ComponentUpdateFailure.unavailable
    }
    static func emit(status: String, checkpoint: String? = nil, publisherVerified: Bool) {
        let checkpoints: Set<String> = ["source", "legacy", "current_binding", "protected_policies", "public_image",
            "installed_signatures", "service", "publish", "finished"]
        let statuses: Set<String> = ["REVALIDATED", "ALREADY_BOUND", "ALREADY_REVALIDATED", "RECOVERED_ROOT", "REFUSED"]
        guard statuses.contains(status), checkpoint == nil || checkpoints.contains(checkpoint!) else { return }
        var value: [String: Any] = ["schema": 1, "status": status, "production_ready": false]
        if let checkpoint {
            value["reason"] = "installation_root_revalidation_refused"; value["checkpoint"] = checkpoint
        }
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return }
        print(text)
        // Reporting failure cannot change the verified/refused operation result.
        if publisherVerified { try? publish(data, plan: ComponentUpdateCompiledPins.planSHA256) }
    }
}

@main struct InstallationRootRevalidationMain {
    static func main() {
        guard getuid() == 0, geteuid() == 0, CommandLine.arguments.count == 1 else {
            print("{\"schema\":1,\"status\":\"REFUSED\",\"reason\":\"installation_revalidation_context_required\",\"production_ready\":false}")
            exit(78)
        }
        var checkpoint = "source"
        var publisherVerified = false
        do {
            guard CommandLine.arguments[0].hasPrefix("/"), CommandLine.arguments[0].hasSuffix("/AccountAccess-componentupdate") else {
                throw ComponentUpdateFailure.context
            }
            umask(0o077)
            try ComponentUpdateIdentity.verifySelf(team: "WBULD6N4NQ")
            publisherVerified = true
            let resources = try InstallerPayloadIO.directory(URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path,
                owner: 0, installerResources: true)
            defer { Darwin.close(resources) }
            let result = try ComponentController.revalidate(resources: resources, planPin: ComponentUpdateCompiledPins.planSHA256,
                checkpoint: { checkpoint = $0 })
            InstallationRevalidationReport.emit(status: result, publisherVerified: publisherVerified)
        } catch {
            InstallationRevalidationReport.emit(status: "REFUSED", checkpoint: checkpoint, publisherVerified: publisherVerified)
            exit(78)
        }
    }
}
#endif
