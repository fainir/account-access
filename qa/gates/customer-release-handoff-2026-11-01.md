# Customer release handoff - 1 November 2026

Publisher approval has since completed: see [approval and next action](publisher-approval-2026-11-01.md). The staged-review section below records the preparation, not a new pending approval.

## Verified this session

The normal installed Account Access launcher reports service 0.8.0, browser
READY, recovery RUNNING, zero consecutive/total failures. Installed app plist
reads version 0.8.0/build 122. Discovery only was performed: the authorized
public example retains saved access, and private Namecheap remains paused with
needs_attention. No private read, new enrollment or code retrieval was attempted.

Created a separate [0.8.0 customer release draft](https://github.com/fainir/account-access/releases/tag/untagged-270c0c3b7fa304bc7299),
reusing the unchanged qualified packages. The original build-122 QA release and
its four pinned assets remain intact for the dated macOS 14 check. No installer
was rebuilt and no Android APK was uploaded.

Actual GitHub release read-back confirms `isDraft: true`, `publishedAt: null`,
target commit `13c5621ae436bdbe36ebab64f963d1ec52021a8e`, and exactly three
completed assets. This source target includes the current customer instructions;
the privacy/terms are unchanged from the exact reviewed revisions. Each server-reported digest and byte count matches its local
qualified input:

| Customer download | Bytes | Purpose |
|---|---:|---|
| Account-Access-0.8.0-Mac-arm64.pkg | 289,330,711 | Clean Mac installation or qualified identical-image repair |
| Account-Access-0.8.0-update-from-build121.pkg | 5,813,686 | Exact protected build-121-to-122 update only |
| account-access-bitwarden-2026.10.0-corresponding-source.tar.gz | 219,117,936 | Adjacent third-party source download at no additional charge |

The existing `macos.bitwarden_runtime.source_bundle` verifier passed against
the actual archive. Its digest matches both build-122 runtime manifests and
their required source asset. This technical read-back is not an independent
legal audit; existing source-review scope limits remain unchanged.

The exact release notes were read back from GitHub and matched
[the prepared notes](../../docs/mac-release-candidate.md). The real Chrome page
shows Draft, the two installer choices, an adjacent no-additional-charge source
link, and Assets 3. Future public download URLs are explicitly documented as
unavailable until publication; no successful public download is claimed.

README and Mac distribution notes now correctly record completed Android
signing/Keychain custody and emulator acceptance. They retain the physical and
private MFA limits and point to the customer package/source instructions.

## One staged publisher action

The exact complete [privacy notice](https://github.com/fainir/account-access/blob/7903cafa50d1510dd56011e5450b48df415aca7a/docs/privacy.md)
and [terms](https://github.com/fainir/account-access/blob/7903cafa50d1510dd56011e5450b48df415aca7a/docs/terms.md)
are open in two owner Chrome review tabs and retained as handoffs. Both visible
pages show version 0.8.0, draft status, Nir Fainshtein, עוסק פטור and the selected
support/privacy contact. [Staged terms screen](publisher-terms-review-2026-11-01.png).

The owner is asked once to approve using those two documents for the 0.8.0
public release, at no fee. The documents remain drafts until that response;
no acceptance is inferred from the request to finish the product. The existing
owner-actions skill reserves statements in the owner's own name for the owner.
Physical/private MFA and the existing paused Namecheap challenge remain
separate. No phone action is requested after the owner chose emulator testing.

## Next check and cleanup

The existing daily follow-up remains the single watcher for the macOS 14 runner
qualification: 1 November at 12:00 Asia/Jerusalem, outside the recorded outage.
Do not retry early or repeat publisher/signing questions. On completion, read
both actual OS/architecture reports and remove the completed follow-up.

The stopped disposable API 35 AVD and the emulator/system image restored for
its completed tests were more than 30 minutes old, outside the keep list, and
had no open files. Removed only those test dependencies through avdmanager and
sdkmanager. SDK build tools/ADB, final APK/report, private publisher identity,
Mac packages/source and linked QA screenshots were preserved. The customer
asset aliases use APFS clones, so no new binary build or full duplicate payload
was needed.
