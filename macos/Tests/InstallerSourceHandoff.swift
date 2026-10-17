// Disposable CI only. Native executable in place of Python: validates the
// kernel handoff without running a coordinator or touching target/account data.
import Foundation
import CryptoKit
import Darwin

@main struct InstallerSourceHandoff {
    static func main() {
        let args = CommandLine.arguments
        guard args.count == 11, args[1] == "-I", args[2] == "-B", args[3] == "-m",
              args[4] == "account_access.install_transaction", args[5] == "--source-fd",
              args[7] == "--manifest-fd", args[9] == "--manifest-sha256",
              let source = Int32(args[6]), let manifest = Int32(args[8]), source >= 3, manifest >= 3, source != manifest else {
            print("{\"status\":\"FAILED\",\"reason\":\"invalid_source_handoff_arguments\"}"); exit(78)
        }
        var directory = stat(), file = stat(), input = stat(), null = stat()
        #if ACCOUNT_ACCESS_SOURCE_HANDOFF_USER_FIXTURE
        let expectedUID = getuid()
        #else
        let expectedUID: uid_t = 0
        #endif
        let sourceOK = fstat(source, &directory) == 0 && directory.st_uid == expectedUID && directory.st_mode & S_IFMT == S_IFDIR
        let fileOK = fstat(manifest, &file) == 0 && file.st_uid == expectedUID && file.st_mode & S_IFMT == S_IFREG
            && file.st_nlink == 1 && file.st_size > 0 && file.st_size <= 16 * 1024 * 1024
        let inputOK = fstat(0, &input) == 0 && lstat("/dev/null", &null) == 0 && input.st_rdev == null.st_rdev && input.st_mode & S_IFMT == S_IFCHR
        let unrelatedClosed = [source, manifest].contains(200) || fcntl(200, F_GETFD) == -1
        let duplicatesClosed = fcntl(10, F_GETFD) == -1 && fcntl(11, F_GETFD) == -1
        let environment = ProcessInfo.processInfo.environment
        var digestOK = false
        if fileOK, lseek(manifest, 0, SEEK_SET) == 0,
           let data = try? FileHandle(fileDescriptor: manifest, closeOnDealloc: false).readToEnd() {
            digestOK = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == args[10]
        }
        let checks: [String: Bool] = ["expected_process_identity_preserved": getuid() == expectedUID && geteuid() == expectedUID,
            "verified_public_directory_passed": sourceOK, "verified_public_manifest_passed": fileOK && digestOK,
            "unrelated_descriptor_closed": unrelatedClosed, "stdin_is_dev_null": inputOK,
            "temporary_public_duplicates_closed": duplicatesClosed,
            "caller_environment_removed": environment["ACCOUNT_ACCESS_UNRELATED_ENV"] == nil && environment["PYTHONPATH"] == nil,
            "fixed_environment_present": environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin" && environment["LANG"] == "C" && environment["HOME"] == "/var/root"]
        let passed = checks.values.allSatisfy { $0 }
        let value: [String: Any] = ["status": passed ? "PASSED" : "FAILED", "checks": checks,
            "environment": "disposable-ci-native-source-handoff", "private_signins": 0,
            "production_ready": false, "actual_python_or_provisioning_executed": false]
        let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
        if !passed { exit(78) }
    }
}
