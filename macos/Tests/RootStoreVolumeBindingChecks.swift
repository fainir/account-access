// Ordinary-user tests: fictional record bytes and one new temporary directory.
import Foundation
import Darwin

@main struct RootStoreVolumeBindingChecks {
    static func main() throws {
        precondition(getuid() != 0 && geteuid() == getuid())
        var assertions = 0
        func check(_ condition: Bool) { precondition(condition); assertions += 1 }
        func refuses(_ body: () throws -> Void) throws {
            do { try body(); preconditionFailure("Changed volume binding accepted") }
            catch is RootStoreVolumeFailure { assertions += 1 }
        }
        let record = Data("fictional immutable publication record".utf8)
        let original = RootStoreVolumeBinding.Context(device: 10, parentInode: 123,
            volumeUUID: "12345678-1234-4234-8234-123456789abc")
        let binding = try RootStoreVolumeBinding(record: record, context: original)
        let bytes = try binding.encoded()
        check(try RootStoreVolumeBinding.decode(bytes, record: record, context: original) == binding)
        for device: Int64 in [11, 12, 0, Int64(Int32.max)] {
            let changed = RootStoreVolumeBinding.Context(device: device, parentInode: original.parentInode,
                volumeUUID: original.volumeUUID)
            check(try RootStoreVolumeBinding.decode(bytes, record: record, context: changed) == binding)
        }
        for changed in [
            RootStoreVolumeBinding.Context(device: 10, parentInode: 999, volumeUUID: original.volumeUUID),
            RootStoreVolumeBinding.Context(device: 10, parentInode: 123, volumeUUID: UUID().uuidString.lowercased()),
            RootStoreVolumeBinding.Context(device: -1, parentInode: 123, volumeUUID: original.volumeUUID)
        ] { try refuses { _ = try RootStoreVolumeBinding.decode(bytes, record: record, context: changed) } }
        try refuses { _ = try RootStoreVolumeBinding.decode(bytes, record: Data("changed".utf8), context: original) }
        let object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        for (key, value) in [
            ("schema", 2 as Any), ("schema", true as Any), ("parentInode", 0 as Any),
            ("parentInode", -1 as Any), ("parentInode", true as Any),
            ("recordSHA256", String(repeating: "0", count: 64) as Any),
            ("volumeUUID", original.volumeUUID.uppercased() as Any),
            ("volumeUUID", "00000000-0000-0000-0000-000000000000" as Any),
            ("extra", "private input must not be used" as Any)
        ] {
            var altered = object; altered[key] = value
            let data = try JSONSerialization.data(withJSONObject: altered, options: [.sortedKeys, .withoutEscapingSlashes])
            try refuses { _ = try RootStoreVolumeBinding.decode(data, record: record, context: original) }
        }
        var missing = object; missing.removeValue(forKey: "volumeUUID")
        try refuses { _ = try RootStoreVolumeBinding.decode(JSONSerialization.data(withJSONObject: missing), record: record, context: original) }
        let text = String(decoding: bytes, as: UTF8.self)
        for malformed in [
            "", text + "\n", text.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1,\"schema\":1"),
            text.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1,\"\\u0073chema\":1"),
            text.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1.0"),
            String(repeating: " ", count: 513)
        ] { try refuses { _ = try RootStoreVolumeBinding.decode(Data(malformed.utf8), record: record, context: original) } }
        for invalidRecord in [Data(), Data(repeating: 1, count: 4097)] {
            try refuses { _ = try RootStoreVolumeBinding(record: invalidRecord, context: original) }
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("account-access-volume-fixture-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        precondition(fd >= 0); defer { Darwin.close(fd) }
        let first = try RootStoreVolumeBinding.capture(fd), second = try RootStoreVolumeBinding.capture(fd)
        check(first == second && first.parentInode > 0 && first.device >= 0)
        let measured = try RootStoreVolumeBinding(record: record, context: first)
        check(try RootStoreVolumeBinding.decode(measured.encoded(), record: record, context: second) == measured)
        try refuses { _ = try RootStoreVolumeBinding.capture(-1) }
        #if ACCOUNT_ACCESS_STORE_VOLUME_CHECKS
        let content = try measured.encoded()
        func fixture(_ body: (URL, Int32) throws -> Void) throws {
            let child = directory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: child, withIntermediateDirectories: false)
            precondition(chmod(child.path, 0o700) == 0)
            let handle = open(child.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            precondition(handle >= 0); defer { Darwin.close(handle) }
            try body(child, handle)
        }
        enum Interrupted: Error { case injected }
        for point: RootStoreVolumePublication.Phase in [.created, .partial, .synced, .published] {
            try fixture { child, handle in
                var injected = false
                do {
                    try RootStoreVolumePublication.fixture(directory: handle, data: content, fault: { phase in
                        if phase == point && !injected { injected = true; throw Interrupted.injected }
                    })
                    preconditionFailure("Interruption seam did not run")
                } catch Interrupted.injected { check(injected) }
                let published = child.appendingPathComponent(RootStoreVolumeBinding.name)
                check(FileManager.default.fileExists(atPath: published.path) == (point == .published))
                try RootStoreVolumePublication.fixture(directory: handle, data: content)
                check(try Data(contentsOf: published) == content)
                let before = try FileManager.default.attributesOfItem(atPath: published.path)[.systemFileNumber] as! NSNumber
                try RootStoreVolumePublication.fixture(directory: handle, data: content)
                let after = try FileManager.default.attributesOfItem(atPath: published.path)[.systemFileNumber] as! NSNumber
                check(before == after)
                check(!FileManager.default.fileExists(atPath: child.appendingPathComponent(RootStoreVolumePublication.pendingName).path))
            }
        }
        for name in [RootStoreVolumePublication.pendingName, RootStoreVolumeBinding.name] {
            try fixture { child, handle in
                let target = child.appendingPathComponent(name), foreign = Data("foreign bytes".utf8)
                try foreign.write(to: target); precondition(chmod(target.path, 0o600) == 0)
                try refuses { try RootStoreVolumePublication.fixture(directory: handle, data: content) }
                check(try Data(contentsOf: target) == foreign)
            }
            try fixture { child, handle in
                let target = child.appendingPathComponent(name), outside = directory.appendingPathComponent(UUID().uuidString)
                try content.write(to: outside); precondition(chmod(outside.path, 0o600) == 0)
                precondition(symlink(outside.path, target.path) == 0)
                try refuses { try RootStoreVolumePublication.fixture(directory: handle, data: content) }
                check(try Data(contentsOf: outside) == content)
            }
        }
        try fixture { child, handle in
            var validations = 0
            do {
                try RootStoreVolumePublication.fixture(directory: handle, data: content, verify: {
                    validations += 1
                    if validations == 3 { throw Interrupted.injected }
                })
                preconditionFailure("Changed authority accepted")
            } catch Interrupted.injected { check(validations == 3) }
            check(!FileManager.default.fileExists(atPath: child.appendingPathComponent(RootStoreVolumeBinding.name).path))
            check(try Data(contentsOf: child.appendingPathComponent(RootStoreVolumePublication.pendingName)) == content)
        }
        #endif
        print("PASS: \(assertions) persistent-volume checks; device changes retain the binding, changed volumes, parent directories and records are refused; only a new temporary directory was inspected")
    }
}
