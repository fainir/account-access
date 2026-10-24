// All production paths are fixed native routes. Journal strings cannot select
// an arbitrary destination. Retain and recheck every ancestor attachment.
import Foundation
import Darwin

final class BrokerRepairRoutes {
    private let root: Int32, anchor: PublicTreeTrustedAnchor
    private var held: [String: FullImageAttachedDirectory] = [:]
    let plan: String, predecessorPlan: String
    init(plan: String, predecessorPlan: String) throws {
        guard getuid() == 0, geteuid() == 0, FullImageJSON.hex(plan), FullImageJSON.hex(predecessorPlan) else {
            throw ComponentUpdateFailure.context
        }
        let fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ComponentUpdateFailure.object }
        do {
            let info = try InstallerPayloadIO.check(fd, owner: 0, directory: true)
            let pin = try PublicTreeDirectoryIdentity.observe(fd, owner: 0, group: info.st_gid)
            anchor = try PublicTreeTrustedAnchor.acceptVerifiedDescriptor(fd, expected: pin)
            root = fd; self.plan = plan; self.predecessorPlan = predecessorPlan
        } catch { Darwin.close(fd); throw error }
    }
    deinit { Darwin.close(root) }
    private func directory(_ path: String) throws -> FullImageAttachedDirectory {
        if let item = held[path] { try item.verify(item.fd); return item }
        let item = try FullImageAttachedDirectory(root: root, anchor: anchor, absolute: path, owner: 0)
        held[path] = item; return item
    }
    func support() throws -> FullImageAttachedDirectory { try directory(InstallerPayloadManifest.support) }
    func namespace() throws -> FullImageAttachedDirectory { try directory(BrokerRepairIntent.namespace) }
    func transition() throws -> FullImageAttachedDirectory {
        try directory(BrokerRepairIntent.namespace + "/transition-" + plan)
    }
    func predecessor() throws -> FullImageAttachedDirectory { try directory(FullImageFixedNamespace.namespace) }
    func predecessorHistory() throws -> FullImageAttachedDirectory {
        try directory(FullImageFixedNamespace.transition(predecessorPlan) + "/global")
    }
    func resolve(_ operation: ComponentOperation) throws -> (Int32, String) {
        guard BrokerRepairIntent.targets.contains(where: { $0.0 == operation.target && $0.1 == operation.path }) else {
            throw ComponentUpdateFailure.journal
        }
        if operation.target == .head { return (try namespace().duplicate(), "head.json") }
        let parts = try InstallerPayloadManifest.components(operation.path)
        let parent = InstallerPayloadManifest.support + (parts.count == 1 ? "" : "/" + parts.dropLast().joined(separator: "/"))
        return (try directory(parent).duplicate(), parts.last!)
    }
    func read(_ operation: ComponentOperation) throws -> (Data, ComponentObject) {
        let (parent, name) = try resolve(operation); defer { Darwin.close(parent) }
        return try ComponentFiles.read(parent, name, owner: 0)
    }
    func verify() throws { for item in held.values { try item.verify(item.fd) } }
    func mount() throws -> BrokerRepairMount {
        try verify()
        let roots = try InstallationRootBinding.capture(withVolumeUUID: true)
        guard let support = roots[InstallerPayloadManifest.support], let alias = roots[InstallerPayloadManifest.application],
              support.device == alias.device, support.volumeUUID == alias.volumeUUID else { throw ComponentUpdateFailure.object }
        let namespace = try namespace(), predecessor = try predecessorHistory()
        guard namespace.identity.device == support.device, predecessor.identity.device == support.device,
              namespace.identity.mode == 0o700, predecessor.identity.mode == 0o700,
              namespace.identity.group == 0, predecessor.identity.group == 0 else { throw ComponentUpdateFailure.object }
        let mount = BrokerRepairMount(device: support.device, volumeUUID: support.volumeUUID, supportInode: support.inode,
            applicationAliasInode: alias.inode, namespaceInode: namespace.identity.inode,
            predecessorJournalInode: predecessor.identity.inode)
        try mount.validate(); try verify(); return mount
    }
    func history() throws -> Data {
        let directory = try predecessorHistory()
        let names = try InstallerPayloadIO.contents(directory.fd)
        let evidence = try BrokerRepairHistory.evidence(names: names) { name, maximum in
            let bytes = try ComponentFiles.read(directory.fd, name, owner: 0, mode: 0o600).0
            guard bytes.count <= maximum else { throw ComponentUpdateFailure.journal }
            return bytes
        }
        guard try InstallerPayloadIO.contents(directory.fd) == names else { throw ComponentUpdateFailure.journal }
        try verify(); return evidence
    }
}
