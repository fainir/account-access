// Ordinary-user check only; never creates or modifies an authorization rule.
import Foundation
import Darwin

@main struct OwnerPolicyGuardChecks {
    static func main() throws {
        guard getuid() != 0 else { fatalError("ordinary_user_required") }
        do {
            _ = try OwnerAuthorizationPolicy.installIfAbsent()
            fatalError("unprivileged_policy_install_accepted")
        } catch OwnerPolicyFailure.daemonRequired {
            print("{\"status\":\"PASSED\",\"unprivileged_policy_install_refused\":true,\"authorization_database_changed\":false}")
        }
    }
}
