// Pure metadata checks. No RootVaultKeyStore construction or Keychain access.
import Foundation
import Security

@main struct VaultReferenceChecks {
    static func main() throws {
        let first = Data([1, 2, 3]), other = Data([4, 5, 6])
        var passed = 0
        for values in [[first], [first, first], [first, first, first]] {
            guard try RootVaultItemReference.unique(values as CFArray) == first else { fatalError("reference_selection_failed") }
            passed += 1
        }
        let refused: [CFTypeRef?] = [nil, [] as CFArray, [first, other] as CFArray,
                                    [Data()] as CFArray, [first, Data()] as CFArray,
                                    ["unexpected"] as CFArray, first as CFData, [:] as CFDictionary]
        for value in refused {
            do {
                _ = try RootVaultItemReference.unique(value)
                fatalError("ambiguous_reference_accepted")
            } catch let failure as RootVaultRecordFailure {
                guard failure.stage == .references else { fatalError("unexpected_reference_failure") }
                passed += 1
            }
        }
        print("{\"status\":\"PASSED\",\"vault_reference_checks\":\(passed),\"keychain_accessed\":false}")
    }
}
