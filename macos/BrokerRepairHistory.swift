// A successor may compare this digest only with evidence already minted by
// completedFullImage. Hashing an arbitrary history does not grant authority.
import Foundation

enum BrokerRepairHistory {
    static func evidence(names: Set<String>, read: (String, Int) throws -> Data) throws -> Data {
        // Pending audit writes are deliberately unsupported in this first
        // successor. They cannot silently disappear from predecessor evidence.
        guard names.contains("intent.json"), (2...10001).contains(names.count) else {
            throw ComponentUpdateFailure.journal
        }
        let count = names.count - 1
        let ordered = (0..<count).map { String(format: "record-%04d.json", $0) }
        guard names == Set(ordered + ["intent.json"]) else { throw ComponentUpdateFailure.journal }
        let intent = try read("intent.json", 262144)
        guard !intent.isEmpty, intent.count <= 262144 else { throw ComponentUpdateFailure.journal }
        var hashes: [String] = []
        for name in ordered {
            let bytes = try read(name, 8192)
            guard !bytes.isEmpty, bytes.count <= 8192 else { throw ComponentUpdateFailure.journal }
            hashes.append(FullImageJSON.hash(bytes))
        }
        return try FullImageJSON.encode(["intent_sha256": FullImageJSON.hash(intent),
            "record_sha256": hashes, "pending_sha256": [:] as [String: String]])
    }
}
