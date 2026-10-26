// Exact synthetic source() extraction from frozen global-journal fixture; no installed authority.
import Foundation
import Darwin
enum FullImageInstalledSourceFixture {
    static func source() throws -> FullImageSource {
        let directory: [String: Any] = ["kind": "directory", "mode": 0o755]
        var old: [String: Any] = ["": directory], new: [String: Any] = ["": directory]
        func put(_ rows: inout [String: Any], _ path: String, _ value: [String: Any]) {
            let parts = path.split(separator: "/").map(String.init)
            for count in 1..<parts.count { rows[parts.prefix(count).joined(separator: "/")] = directory }
            rows[path] = value
        }
        func node(_ text: String, mode: UInt16 = 0o644) -> [String: Any] {
            let data = Data(text.utf8)
            return ["kind": "file", "mode": mode, "size": data.count, "sha256": FullImageJSON.hash(data)]
        }
        for unit in PublicTreeUnit.fullImageCases {
            if unit.beforePresent { put(&old, unit.path + "/entry.txt", node("old-" + unit.rawValue)) }
            if unit.afterPresent { put(&new, unit.path + "/entry.txt", node("new-" + unit.rawValue)) }
        }
        for unit in FullImagePlanFileUnit.fullImageCases {
            if unit.beforePresent { put(&old, unit.path, node("old-" + unit.rawValue, mode: unit.mode)) }
            if unit.afterPresent { put(&new, unit.path, node("new-" + unit.rawValue, mode: unit.mode)) }
        }
        // Required manifest member, represented only as nonexecuted fictional
        // bytes. Keeping it identical isolates this journal fixture's changes.
        put(&old, "owner.app/Contents/MacOS/AccountAccess", node("fictional-owner-not-executed", mode: 0o755))
        put(&new, "owner.app/Contents/MacOS/AccountAccess", node("fictional-owner-not-executed", mode: 0o755))
        func manifest(_ rows: [String: Any]) throws -> InstallerPayloadManifest {
            let value: [String: Any] = ["schema": 1, "managed_by": "account-access-install-payload-v1",
                "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
                "roots": [InstallerPayloadManifest.support: rows,
                    InstallerPayloadManifest.application: ["": ["kind": "symlink",
                        "target": "../Library/Application Support/Account Access/owner.app"]]]]
            return try InstallerPayloadManifest(FullImageJSON.encode(value))
        }
        let before = try manifest(old), after = try manifest(new)
        let pins = FullImageSourcePins(planSHA256: String(repeating: "9", count: 64), targetSourceCommit: String(repeating: "4", count: 40),
            targetManifestSHA256: after.sha256, caReceiptSHA256: FullImageJSON.hash(Data("new-caReceipt".utf8)),
            predecessor: FullImagePredecessorPins(planSHA256: String(repeating: "2", count: 64), originalManifestSHA256: ComponentSource.baseDigest,
                manifestSHA256: before.sha256, headSHA256: String(repeating: "8", count: 64)),
            predecessorSourceCommit: String(repeating: "3", count: 40), targetSourceFiles: [:],
            providerManifestSHA256: String(repeating: "7", count: 64), providerSourceBundleSHA256: String(repeating: "1", count: 64))
        var units: [FullImageSource.Unit] = []
        for unit in PublicTreeUnit.fullImageCases {
            units.append(.tree(unit, try PublicTreeInventory(validatedManifest: before, unit: unit),
                               try PublicTreeInventory(validatedManifest: after, unit: unit)))
        }
        for unit in FullImagePlanFileUnit.fullImageCases.sorted(by: { $0.path < $1.path }) {
            units.append(.file(unit, before.trees[InstallerPayloadManifest.support]!.nodes[unit.path],
                               after.trees[InstallerPayloadManifest.support]!.nodes[unit.path]))
        }
        let changed = try Set(old.keys).union(new.keys).filter { name in
            try !FullImageJSON.same(old[name] ?? NSNull(), new[name] ?? NSNull())
        }.sorted()
        return FullImageSource(pins: pins, before: before, after: after, oldPeers: [:], newPeers: [:],
                               designatedRequirements: [:], units: units, changed: changed)
    }
}
