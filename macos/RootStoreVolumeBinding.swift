// A publication record stays bound to one persistent volume and parent inode.
// This type measures or validates metadata; it never opens credential files,
// rewrites the publication record, or authorizes a legacy migration.
import Foundation
import CryptoKit
import Darwin

enum RootStoreVolumeFailure: String, Error {
    case invalid = "vault_publication_volume_binding_invalid"
    case changed = "vault_publication_volume_binding_changed"
    case unavailable = "vault_publication_volume_binding_unavailable"
}

struct RootStoreVolumeBinding: Codable, Equatable {
    static let name = "volume-v1.json"
    struct Context: Equatable {
        let device: Int64
        let parentInode: UInt64
        let volumeUUID: String
    }
    let schema: Int
    let recordSHA256: String
    let parentInode: UInt64
    let volumeUUID: String

    private static func uuid(_ text: String) -> Bool {
        guard let value = UUID(uuidString: text), value.uuidString.lowercased() == text else { return false }
        return value != UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
    }
    private static func hash(_ record: Data) throws -> String {
        guard !record.isEmpty, record.count <= 4096 else { throw RootStoreVolumeFailure.invalid }
        return SHA256.hash(data: record).map { String(format: "%02x", $0) }.joined()
    }
    init(record: Data, context: Context) throws {
        guard context.device >= 0, context.parentInode > 0,
              context.parentInode <= UInt64(Int64.max), Self.uuid(context.volumeUUID) else {
            throw RootStoreVolumeFailure.invalid
        }
        schema = 1; recordSHA256 = try Self.hash(record)
        parentInode = context.parentInode; volumeUUID = context.volumeUUID
    }
    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
    static func decode(_ data: Data, record: Data, context: Context) throws -> RootStoreVolumeBinding {
        guard !data.isEmpty, data.count <= 512,
              let value = try? JSONDecoder().decode(Self.self, from: data),
              value.schema == 1, value.recordSHA256 == (try hash(record)),
              value.parentInode > 0, value.parentInode <= UInt64(Int64.max), uuid(value.volumeUUID),
              try value.encoded() == data else { throw RootStoreVolumeFailure.invalid }
        // Exact canonical encoding also rejects extra and duplicate keys,
        // alternate numeric representations and noncanonical UUID spellings.
        guard context.device >= 0, context.parentInode == value.parentInode,
              context.volumeUUID == value.volumeUUID else { throw RootStoreVolumeFailure.changed }
        return value
    }
    static func capture(_ fd: Int32) throws -> Context {
        var before = stat(), after = stat(), attributes = attrlist()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFDIR else {
            throw RootStoreVolumeFailure.unavailable
        }
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.volattr = ATTR_VOL_INFO | UInt32(ATTR_VOL_UUID)
        var bytes = [UInt8](repeating: 0, count: 20)
        let status = bytes.withUnsafeMutableBytes { fgetattrlist(fd, &attributes, $0.baseAddress!, $0.count, 0) }
        guard status == 0, bytes.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) == 20,
              fstat(fd, &after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_uid == after.st_uid, before.st_gid == after.st_gid, before.st_mode == after.st_mode else {
            throw RootStoreVolumeFailure.unavailable
        }
        let b = Array(bytes[4..<20])
        let id = UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])).uuidString.lowercased()
        guard uuid(id), before.st_dev >= 0, before.st_ino > 0 else { throw RootStoreVolumeFailure.unavailable }
        return Context(device: Int64(before.st_dev), parentInode: UInt64(before.st_ino), volumeUUID: id)
    }
}
