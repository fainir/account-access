import Foundation
import Darwin

@main struct AccountAccessBackgroundMain {
    static func main() {
        // Use the kernel's executable path, not a caller-controlled argv[0].
        var size: UInt32 = 0
        _NSGetExecutablePath(nil, &size)
        var bytes = [CChar](repeating: 0, count: Int(size))
        guard _NSGetExecutablePath(&bytes, &size) == 0 else { exit(0) }
        let executable = URL(fileURLWithPath: String(cString: bytes)).resolvingSymlinksInPath()
        let app = executable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        do {
            guard let bundle = Bundle(url: app) else { exit(0) }
            let layout = try BackgroundRecovery.Layout(bundle: bundle)
            guard let command = try BackgroundRecovery.command(layout: layout) else { exit(0) }
            var arguments = command.map { strdup($0) }
            arguments.append(nil)
            defer { for argument in arguments { free(argument) } }
            // Replacing this process preserves launchd's tracked PID and
            // avoids an orphan guardian if the native helper dies.
            arguments.withUnsafeMutableBufferPointer { buffer in
                _ = execv(command[0], buffer.baseAddress!)
            }
            exit(errno == ENOENT || errno == EACCES ? 0 : 75)
        } catch { exit(0) } // Invalid/owner-blocked setup is a normal stop.
    }
}
