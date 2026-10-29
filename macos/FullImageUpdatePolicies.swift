// Data-only policy derivation for the separate complete-image proposal.
// This has no installed-state reader or production controller entry point.
import Foundation
import Darwin

enum FullImageUpdatePolicies {
    static func derive(install: Data, host: Data, owner: Data, worker: Data,
                       oldPeers: [String: ComponentPeerSignature], newPeers: [String: ComponentPeerSignature],
                       oldFingerprint: String, newFingerprint: String, consoleOwner: uid_t) throws -> ComponentPolicyResult {
        // The target image carries the exact owner/broker/bootstrap identities
        // and designated requirements pinned by FullImageSource. Permit code
        // hash rotation for those peers while preserving the publisher team and
        // bundle identifiers; ComponentUpdatePolicies revalidates the complete
        // peer set and updates the corresponding protected policy fields.
        guard let oldOwner = oldPeers["owner"], let newOwner = newPeers["owner"],
              newOwner.team == oldOwner.team, newOwner.identifier == oldOwner.identifier,
              (1...2).contains(newOwner.hashes.count),
              newOwner.hashes == Array(Set(newOwner.hashes)).sorted(),
              newOwner.hashes.allSatisfy({ value in
                  value.utf8.count == 40 && value.utf8.allSatisfy {
                      (48...57).contains($0) || (97...102).contains($0)
                  }
              }) else { throw ComponentPolicyFailure.invalid }

        // Reuse the closed existing derivation for every original policy field,
        // duplicate-key/UID/path/ID check and the complete peer set. Substituting
        // the old owner here deliberately leaves its policy unchanged until all
        // those checks succeed. The startup component's own API is unchanged.
        var preservedOwnerPeers = newPeers
        preservedOwnerPeers["owner"] = oldOwner
        let checked = try ComponentUpdatePolicies.derive(install: install, host: host, owner: owner, worker: worker,
            oldPeers: oldPeers, newPeers: preservedOwnerPeers, oldFingerprint: oldFingerprint,
            newFingerprint: newFingerprint, consoleOwner: consoleOwner)
        guard var hostValue = try JSONSerialization.jsonObject(with: checked.host) as? [String: Any] else {
            throw ComponentPolicyFailure.invalid
        }
        hostValue["owner_hashes"] = newOwner.hashes
        let changedHost = try JSONSerialization.data(withJSONObject: hostValue,
            options: [.sortedKeys, .withoutEscapingSlashes])
        guard changedHost.count <= 4096 else { throw ComponentPolicyFailure.invalid }
        return ComponentPolicyResult(install: checked.install, host: changedHost, owner: checked.owner,
            ownerUID: checked.ownerUID, brokerUID: checked.brokerUID)
    }
}
