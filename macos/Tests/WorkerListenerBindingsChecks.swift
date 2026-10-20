import Foundation
import Darwin

@main struct WorkerListenerBindingsChecks {
    static func require(_ value: Bool) { if !value { exit(1) } }
    static func rejects(_ body: () throws -> Void) {
        do { try body(); exit(1) }
        catch WorkerLaunchFailure.invalidDescriptors { }
        catch { exit(1) }
    }
    static func listener(_ path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        require(fd >= 3)
        var success = false
        defer { if !success { Darwin.close(fd) } }
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString).map { UInt8(bitPattern: $0) }
        require(bytes.count <= MemoryLayout.size(ofValue: address.sun_path))
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        require(result == 0 && chown(path, getuid(), getgid()) == 0 && chmod(path, 0o600) == 0 && listen(fd, 128) == 0)
        success = true
        return fd
    }
    static func pipeWith(_ bytes: Data, keepWriter: Bool = false) -> (Int32, Int32) {
        var pair: [Int32] = [-1, -1]
        require(pipe(&pair) == 0)
        require(bytes.withUnsafeBytes { Darwin.write(pair[1], $0.baseAddress, $0.count) } == bytes.count)
        if !keepWriter { Darwin.close(pair[1]); pair[1] = -1 }
        return (pair[0], pair[1])
    }
    static func main() throws {
        require(getuid() != 0)
        let folder = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("aa-lb-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                              attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let paths = [folder.appendingPathComponent("a").path, folder.appendingPathComponent("o").path]
        let agent = try listener(paths[0]), owner = try listener(paths[1])
        defer { Darwin.close(agent); Darwin.close(owner) }
        let agentRecord = try WorkerListenerBindings.fixtureRecord(fd: agent, role: 1, path: paths[0])
        let ownerRecord = try WorkerListenerBindings.fixtureRecord(fd: owner, role: 2, path: paths[1])
        let bindings = try WorkerListenerBindings(records: [agentRecord, ownerRecord])
        require(bindings.metadata.count == 216 && bindings.hex.count == 432)
        require(bindings.metadata.prefix(16) == Data([65, 65, 76, 83, 78, 48, 48, 50, 0, 2, 2, 0, 0, 0, 1, 24]))
        require(bindings.records[0].descriptorDevice == -1 && bindings.metadata[20..<28] == Data(repeating: 255, count: 8))
        require(try WorkerListenerBindings(metadata: bindings.metadata).records == bindings.records)
        try bindings.fixtureValidate(agentFD: agent, ownerFD: owner, paths: paths)
        rejects { try bindings.fixtureValidate(agentFD: owner, ownerFD: agent, paths: paths) }
        let other = try listener(folder.appendingPathComponent("other").path)
        defer { Darwin.close(other) }
        rejects { try bindings.fixtureValidate(agentFD: other, ownerFD: owner, paths: paths) }
        rejects { _ = try WorkerListenerBindings(records: [ownerRecord, agentRecord]) }
        rejects { _ = try WorkerListenerBindings(records: [agentRecord, agentRecord]) }
        for (offset, byte) in [(0, UInt8(0)), (9, 3), (10, 1), (11, 1), (15, 25),
                               (16, 2), (17, 2), (18, 1), (116, 1), (117, 2)] {
            var invalid = bindings.metadata; invalid[offset] = byte
            rejects { _ = try WorkerListenerBindings(metadata: invalid) }
        }
        for range in [28..<36, 44..<52, 128..<136, 144..<152] {
            var invalid = bindings.metadata; invalid.replaceSubrange(range, with: Data(repeating: 0, count: 8))
            rejects { _ = try WorkerListenerBindings(metadata: invalid) }
        }
        var duplicateIdentity = bindings.metadata
        duplicateIdentity.replaceSubrange(120..<136, with: bindings.metadata[20..<36])
        rejects { _ = try WorkerListenerBindings(metadata: duplicateIdentity) }
        var duplicateNode = bindings.metadata
        duplicateNode.replaceSubrange(136..<152, with: bindings.metadata[36..<52])
        rejects { _ = try WorkerListenerBindings(metadata: duplicateNode) }
        var duplicatePath = bindings.metadata
        duplicatePath.replaceSubrange(152..<184, with: bindings.metadata[52..<84])
        rejects { _ = try WorkerListenerBindings(metadata: duplicatePath) }
        var duplicateAddress = bindings.metadata
        duplicateAddress.replaceSubrange(184..<216, with: bindings.metadata[84..<116])
        rejects { _ = try WorkerListenerBindings(metadata: duplicateAddress) }
        var wrongDirectAddress = bindings.metadata; wrongDirectAddress[84] ^= 1
        rejects { _ = try WorkerListenerBindings(metadata: wrongDirectAddress) }
        rejects { _ = try WorkerListenerBindings(metadata: bindings.metadata.dropLast()) }
        rejects { _ = try WorkerListenerBindings(metadata: bindings.metadata + Data([0])) }
        require(chmod(paths[0], 0o666) == 0)
        rejects { try bindings.fixtureValidate(agentFD: agent, ownerFD: owner, paths: paths) }
        require(chmod(paths[0], 0o600) == 0)

        // A renamed vnode retains its bind address. Only the activation source
        // fixture may attest that relationship; direct binding remains strict.
        let original = folder.appendingPathComponent("source").path
        let canonical = folder.appendingPathComponent("renamed").path
        let renamed = try listener(original)
        defer { Darwin.close(renamed) }
        require(rename(original, canonical) == 0)
        rejects { _ = try WorkerListenerBindings.fixtureRecord(fd: renamed, role: 1, path: canonical) }
        let renamedRecord = try WorkerListenerBindings.fixtureRecord(fd: renamed, role: 1, path: canonical, source: 1)
        let renamedBindings = try WorkerListenerBindings(records: [renamedRecord, ownerRecord])
        try renamedBindings.fixtureValidate(agentFD: renamed, ownerFD: owner, paths: [canonical, paths[1]])
        require(WorkerListenerBindings.digest(canonical) != WorkerListenerBindings.digest(original))
        let retained = folder.appendingPathComponent("retained").path
        require(rename(canonical, retained) == 0)
        let replacement = try listener(canonical)
        defer { Darwin.close(replacement) }
        rejects { try renamedBindings.fixtureValidate(agentFD: renamed, ownerFD: owner, paths: [canonical, paths[1]]) }
        rejects { try renamedBindings.fixtureValidate(agentFD: replacement, ownerFD: owner, paths: [canonical, paths[1]]) }

        let suffix = Data(repeating: 120, count: 32) + Data(repeating: 121, count: 32)
        let (reader, _) = pipeWith(bindings.metadata + suffix)
        defer { Darwin.close(reader) }
        let consumed = try WorkerListenerBindings.fixtureConsume(reader)
        require(consumed.metadata == bindings.metadata)
        var remaining = [UInt8](repeating: 0, count: 65)
        let remainingCount = remaining.withUnsafeMutableBytes { Darwin.read(reader, $0.baseAddress, $0.count) }
        require(remainingCount == 64 && Data(remaining.prefix(remainingCount)) == suffix)
        require(remaining.withUnsafeMutableBytes { Darwin.read(reader, $0.baseAddress, $0.count) } == 0)
        let (legacy, _) = pipeWith(suffix)
        defer { Darwin.close(legacy) }
        rejects { _ = try WorkerListenerBindings.fixtureConsume(legacy) }
        let (incomplete, incompleteWriter) = pipeWith(Data(), keepWriter: true)
        defer { Darwin.close(incomplete); Darwin.close(incompleteWriter) }
        let start = ProcessInfo.processInfo.systemUptime
        rejects { _ = try WorkerListenerBindings.fixtureConsume(incomplete, timeout: 0.05) }
        require(ProcessInfo.processInfo.systemUptime - start < 1)
        print("PASS: v2 layout/signed device, strict malformed frames, wrong/swapped descriptors, renamed activation binding, changed node/mode, exact prefix-only consumption and bounded timeout")
    }
}
