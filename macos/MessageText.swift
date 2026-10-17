import Foundation

// Reads only the first string in a known attributed-string archive. It never
// instantiates archived classes, follows arbitrary object graphs, or searches
// for printable fragments that could actually be formatting metadata.
struct MessageText {
    static func decode(_ data: Data) -> String? {
        guard !data.isEmpty, data.count <= 65536 else { return nil }
        if data.starts(with: Data("bplist00".utf8)) {
            return (try? NSKeyedUnarchiver.unarchivedObject(ofClass: NSAttributedString.self, from: data))?.string
        }
        var reader = PrefixReader(bytes: Array(data))
        return try? reader.string()
    }

    private enum Invalid: Error { case archive }
    private struct PrefixReader {
        let bytes: [UInt8]
        var cursor = 0
        var strings: [String] = []
        var objects: [String?] = []

        mutating func byte() throws -> UInt8 {
            guard cursor < bytes.count else { throw Invalid.archive }
            defer { cursor += 1 }
            return bytes[cursor]
        }

        mutating func expect(_ expected: UInt8) throws {
            guard try byte() == expected else { throw Invalid.archive }
        }

        mutating func integer() throws -> Int {
            let first = try byte()
            if first <= 0x7f { return Int(first) }
            guard first >= 0x81 && first <= 0x83 else { throw Invalid.archive }
            let width = 1 << (first - 0x80)
            guard cursor + width <= bytes.count else { throw Invalid.archive }
            var value: UInt64 = 0
            for offset in 0..<width { value |= UInt64(try byte()) << (8 * offset) }
            guard value <= 65536 else { throw Invalid.archive }
            return Int(value)
        }

        mutating func utf8() throws -> String {
            let count = try integer()
            guard cursor + count <= bytes.count,
                  let value = String(bytes: bytes[cursor..<(cursor + count)], encoding: .utf8) else { throw Invalid.archive }
            cursor += count
            return value
        }

        mutating func shared() throws -> String {
            let marker = try byte()
            if marker >= 0x92 {
                let index = Int(marker - 0x92)
                guard index < strings.count else { throw Invalid.archive }
                return strings[index]
            }
            guard marker == 0x84, strings.count < 16 else { throw Invalid.archive }
            let value = try utf8()
            guard value.utf8.count <= 64 else { throw Invalid.archive }
            strings.append(value)
            return value
        }

        mutating func archiveClass(depth: Int = 0) throws -> String? {
            guard depth < 5 else { throw Invalid.archive }
            let marker = try byte()
            if marker == 0x85 { return nil }
            if marker >= 0x92 {
                let index = Int(marker - 0x92)
                guard index < objects.count, let name = objects[index] else { throw Invalid.archive }
                return name
            }
            guard marker == 0x84, objects.count < 12 else { throw Invalid.archive }
            let name = try shared()
            let versions = ["NSObject": 0, "NSAttributedString": 0, "NSMutableAttributedString": 0,
                            "NSString": 1, "NSMutableString": 1]
            guard let version = versions[name], try integer() == version else { throw Invalid.archive }
            objects.append(name)
            let parent = try archiveClass(depth: depth + 1)
            let expected: String? = ["NSAttributedString": "NSObject", "NSMutableAttributedString": "NSAttributedString",
                                     "NSString": "NSObject", "NSMutableString": "NSString"][name]
            guard parent == expected else { throw Invalid.archive }
            return name
        }

        mutating func string() throws -> String {
            // Modern Macs use this little-endian, version-four archive framing.
            try expect(4); try expect(11)
            guard cursor + 11 <= bytes.count,
                  String(bytes: bytes[cursor..<(cursor + 11)], encoding: .ascii) == "streamtyped" else { throw Invalid.archive }
            cursor += 11
            guard try integer() == 1000, try shared() == "@" else { throw Invalid.archive }
            try expect(0x84)
            objects.append(nil)
            guard let root = try archiveClass(), ["NSAttributedString", "NSMutableAttributedString"].contains(root),
                  try shared() == "@" else { throw Invalid.archive }
            try expect(0x84)
            objects.append(nil)
            guard let body = try archiveClass(), ["NSString", "NSMutableString"].contains(body),
                  try shared() == "+" else { throw Invalid.archive }
            let result = try utf8()
            try expect(0x86)
            return result
        }
    }
}
