"""Data-only owner-app successor proposal; grants no installation authority.

The completed runtime95 history still needs an independently qualified native
verifier. A manifest match alone must never authorize this proposed update.
"""

from macos import full_image_update as image

BEFORE = "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
AFTER = "c80f0430c7529acb8479661554aadd7e6b1cfb98303df1e2bda1e5024a75356c"
PREDECESSOR_PLAN = "671c32eb5daacb79a1ec5f63d97cc29d2b6f34b5c75a773a1b477aca981ce6df"
SOURCE = "6736a20f8ed20d9188380b83b808ec9e380df501"
CHANGED = frozenset(
    (
        "owner.app/Contents/Info.plist",
        "owner.app/Contents/MacOS/AccountAccess",
        "package-identity.json",
    )
)
NATIVE_SOURCES = frozenset(
    "macos/" + name + ".swift"
    for name in (
        "AccountAccess",
        "MailboxOAuthLoopback",
        "OwnerGateway",
        "DesktopOwnerConnection",
        "BrowserNativeHost",
        "ManagedAgentSetup",
        "WorkerBootstrap",
        "WorkerListenerBindings",
        "BackgroundRecovery",
        "MessageText",
        "MessagesReader",
        "SystemMessagesReader",
    )
)

SOURCE_FILES = {
    "macos/AccountAccess.swift": "5069971f4c4da8ff1908b8d6938c4535062c38e7a81963beb7de9638ede350da",
    "macos/MailboxOAuthLoopback.swift": "84ff1c1206f8d46a7e1664ac0d8c57dfaebd83788f62d596a45d804509de116b",
    "macos/OwnerGateway.swift": "ccd62d87af5bab675ce71d8421fd09133d9d4675689e850b8688674ed7e38bec",
    "macos/DesktopOwnerConnection.swift": "1776f14c5537f253aa667d489f95a6db0fd0e0848a5188cff7553e32c0bde1fb",
    "macos/BrowserNativeHost.swift": "5e42768342aea1fe0d38cca590699e894c2bb92f1d61a0554a00085292a471a2",
    "macos/ManagedAgentSetup.swift": "d4d5cfa834fc52d22404c45a4d16a1d89f7a97b2cfe007fcac414151e8aeed2b",
    "macos/WorkerBootstrap.swift": "1ca28068fd18ad972ac456da09a974d4ea4275ef22338efda370ed5bcbfdcb13",
    "macos/WorkerListenerBindings.swift": "3816f60d7700bfd927fcc1931a0604123f88eb865ec63471cdeacbafb2431103",
    "macos/BackgroundRecovery.swift": "87fdb09fe79b06b1fe4a523080d793d29ecbea199962c199e9d518e85f49ff3d",
    "macos/MessageText.swift": "a7487d5df866fbe1a2fe4e6fb490978f2923259e2caaba0a8420700994451f82",
    "macos/MessagesReader.swift": "bd46b96af41e92f3b224935f0c33f714a5786ec01482464ccb1b5428429ef243",
    "macos/SystemMessagesReader.swift": "147ed425ea0a79214e1e6b40d084eaeedc26c73c42bb6207e64a1f5d3b5fdc30",
}


def require(value):
    if not value:
        raise image.Refused("owner_upgrade_plan_refused")


def derive(*, before_manifest, after_manifest, old_identity, new_identity, source_files):
    require(
        type(before_manifest) is bytes
        and type(after_manifest) is bytes
        and image.digest(before_manifest) == BEFORE
        and image.digest(after_manifest) == AFTER
    )
    before, after = image._manifest(before_manifest), image._manifest(after_manifest)
    old, new = before["roots"][image.SUPPORT], after["roots"][image.SUPPORT]
    require(
        before["roots"][image.APPLICATION] == after["roots"][image.APPLICATION]
        and old[""] == new[""] == {"kind": "directory", "mode": 0o755}
        and old.get("owner.app") == new.get("owner.app") == {"kind": "directory", "mode": 0o755}
        and set(old) == set(new)
    )
    changed = sorted(path for path in old if old[path] != new[path])
    require(set(changed) == CHANGED)
    for path in CHANGED:
        mode = 0o755 if path.endswith("/AccountAccess") else 0o644
        require(
            all(
                rows[path].get("kind") == "file" and rows[path].get("mode") == mode
                for rows in (old, new)
            )
        )
    old_peers, new_peers = image._identity(old_identity, old), image._identity(new_identity, new)
    require(
        old_peers["owner"] != new_peers["owner"]
        and all(old_peers[k] == new_peers[k] for k in ("broker", "bootstrap"))
    )
    require(
        type(source_files) is dict
        and source_files == SOURCE_FILES
        and set(source_files) == NATIVE_SOURCES
        and all(image._hex(value) for value in source_files.values())
    )
    inventories = [
        {name: node for name, node in rows.items() if image._below(name, "owner.app")}
        for rows in (old, new)
    ]
    return image.encoded(
        {
            "schema": 1,
            "managed_by": "account-access-owner-successor-proposal-v1",
            "before_manifest_sha256": BEFORE,
            "after_manifest_sha256": AFTER,
            "predecessor_runtime_plan_sha256": PREDECESSOR_PLAN,
            "target_source": SOURCE,
            "target_native_source_files": source_files,
            "old_peers": old_peers,
            "new_peers": new_peers,
            "changed": changed,
            "units": [
                {
                    "kind": "public_tree",
                    "path": "owner.app",
                    "before": inventories[0],
                    "after": inventories[1],
                    "before_inventory_sha256": image.digest(image.encoded(inventories[0])),
                    "after_inventory_sha256": image.digest(image.encoded(inventories[1])),
                },
                {
                    "kind": "public_file",
                    "path": "package-identity.json",
                    "before": old["package-identity.json"],
                    "after": new["package-identity.json"],
                },
            ],
            "completed_runtime_proof_required": True,
            "native_signature_checks_required": True,
            "private_policy_rotation_requires_qualified_controller": True,
            "installation_authority": False,
            "production_ready": False,
        }
    )


def parse(raw, *, expected_sha256, **inputs):
    require(
        type(raw) is bytes
        and image._hex(expected_sha256)
        and len(raw) <= image.MAX_PLAN_BYTES
        and image.digest(raw) == expected_sha256
    )
    require(raw == derive(**inputs))
    return image._json(raw, image.MAX_PLAN_BYTES)
