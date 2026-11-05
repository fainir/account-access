# Build 124 qualification - 2 November 2026

The owner completed manual Lemon Squeezy MFA in personal Chrome. That established
the exact password, authenticator and dashboard contracts, not automated acceptance.
Build 124 adds a separate status-only connector, a distinct unenrolled TOTP source
and a script-free server-page readiness predicate. No installed account, password,
seed or grant was used for image/package assembly.

The [matching owner/broker compile](https://github.com/fainir/account-access/actions/runs/41435565761)
uses source 276207e. Build metadata and both embedded/source wheel bytes agree.
The [qualified image](image-qualification.json) verifies all 49 native publisher
signatures, unchanged dependency/JIT bytes and actual sandboxed browser execution.
59 native owner-screen PASS cases and two mailbox-retry CHECK lines are true.
The 110 focused provider/marker/MFA tests and 164 packaging/refusal tests pass.

The [native updater qualification](https://github.com/fainir/account-access/actions/runs/41437170446)
uses source 49a20fa. All seven actual result files were downloaded and read:
[shared adapter](full-image.json), [72 runtime checks](runtime.json),
[123-to-124](direct.json), and earlier [110-to-120](direct-compat.json),
[120-to-121](jit-compat.json), [121-to-122](connection-compat.json),
[122-to-123](betterloop-compat.json). The new plan has 15 units, 18 changed nodes,
19 journal operations, two projections, eight refusal checks and nine retained
preparation checks. No installed reads or service actions occurred in these probes.

The full signed installer is Apple Accepted, stapled and Gatekeeper accepted.
Actual stapler validate succeeds; pkgutil reports trusted Apple notarization and
the existing Developer ID Installer. Its final hash starts 33ecb2e9. The [exact updater](updater-package.json) is also
Apple Accepted, stapled and Gatekeeper accepted, including the persistent copy.
Its signed packaged target and complete owner signature are independently read
back. Ordinary-user invocation refuses. Both exact package digests, byte counts
and complete QA release asset states match [the Installer contract](../../artifacts/runtime124-installer-inputs.json).
Actual signed Installer acceptance is complete on all three supported test systems.
Neither package has been installed on the owner Mac.

## Historical regression correction

[Complete source regression](https://github.com/fainir/account-access/actions/runs/41435565661)
ran 4,695 passing tests, 113 skips and one stale historical assertion. It compared
the old signed configuration-model upgrade with the moving current models.py.
The historical Python/native pins stay unchanged. The corrected test exercises
refusal of the actual newer model through that old transition. All 160 focused
historical/image/update tests pass with lint. This changes only a test; program
and package bytes remain unchanged. [Corrected complete CI](https://github.com/fainir/account-access/actions/runs/41438932448)
passes all 4,704 tests with 113 skips, Ruff, dependency audit (no known vulnerabilities), and native UI/gateway/updater checks. Private automated TOTP acceptance remains separate.

## Completed actual signed Installer and worker acceptance

The exact final bytes pass both actual Installer journeys on
[macOS 14](https://github.com/fainir/account-access/actions/runs/41439179854),
[macOS 15](https://github.com/fainir/account-access/actions/runs/41439176186) and
[macOS 26](https://github.com/fainir/account-access/actions/runs/41439183599).
All six reports were downloaded and read: [14 fresh](macos14-fresh/report.json),
[14 upgrade](macos14-upgrade/report.json), [15 fresh](macos15-fresh/report.json),
[15 upgrade](macos15-upgrade/report.json), [26 fresh](macos26-fresh/report.json),
[26 upgrade](macos26-upgrade/report.json). Each OS passes 11 fresh/repair and
27 upgrade/reapply checks: **114 total**. Build 124, actual publisher-signed
sandboxed browser execution, patched dependency guards, private sentinel/root
inodes, receipts and policies pass. Histories 120/121/122/123 survive every
upgrade/reapply. No personal accounts were used; fixture jobs are stopped.

[Current-source Mac worker acceptance](https://github.com/fainir/account-access/actions/runs/41438932447)
passes all 18 actual reports and 426 true check values, including
[16 offline-package](account-access-mac-package.json) and
[23 prepared-package](account-access-mac-prepared-package.json) checks with
actual prepared-runtime execution. The matching runtime-source run 41435565714
also passed all 18/426. These worker fixtures are separate from publisher-signed
Installer acceptance. Current-source Android, separate-user and component
review workflows also completed successfully; no Android rebuild or upload.

The [existing unpublished customer draft](../gates/customer-release-handoff-2026-11-02.md)
has seven complete assets. Server bytes/digests, current/legacy labels, exact
notes, source target, draft state and null publication were read back. No asset
was overwritten or deleted. Publisher-approved policy/terms bodies are unchanged.

## Owner-Mac installation handoff

The owner Mac still reports 0.8.0/build 123. Eight existing directory/alias
identities are captured in [the pre-install log](owner-installed.log), by
metadata only. The exact qualified 123-to-124 updater matches its final digest
and is [selected in Finder](install-handoff.png). Installer was opened for that
file and reached Standard Install on Macintosh HD. Subsequent Installer actions
and state reads timed out, while Finder remained controllable. The last
observable Installer surface was an Open file picker, not an authorization
dialog. No owner-Mac installation or new OS approval is claimed. Do not repeat
hidden clicks or force-stop an unknown install backend.

The one handoff is to open the selected updater and complete the native Mac
installation locally; restart Installer first if it remains frozen. The local
Mac approval belongs to the owner and no password belongs in chat. After the
installed build changes, verify exact public owner/runtime bytes, all eight
metadata identities, service/browser health and approved reads through both
installed AI launchers. Then stage Lemon's local import/grant and existing
authenticator enrollment. The completed manual Chrome sign-in is not repeated.
Real protected-service Lemon MFA remains F5; no new credential/grant/seed was used.

## Actual owner installation and new startup defect

The owner reported failure. Scoped PackageKit read-back shows both earlier
attempts refused at context with component_owner_app_close_required. The actual
Quit Account Access menu exited the owner GUI process. The same unchanged
package completed at 14:37:49 Asia/Jerusalem, 2 November. Kernel boot at 14:38:46
confirms a full OS restart. Exact installed public owner wheel/catalog/models/
browser and all eight original inode/mode/uid/gid identities pass; device numbers
changed after the reboot. The install handoff is complete and must not be asked
again. [Exact outcomes](owner-installer-outcome.log), [owner observations](owner-installed.log).

Current installed discovery is RETRYABLE/service_unavailable. The launchd broker
is running, but public startup diagnostics record worker_start/worker_process_unavailable.
A bootstrap lived approximately 43 seconds, matching the code's 30-second
readiness deadline plus bounded 12-second shutdown. This is an inference; the
old diagnostic does not distinguish timeout from child exit. Public metadata
audits now pass in 0.76 seconds, with no private data/configuration/key access.
Normal owner app launch does not recover the failed worker. D18 is buildable
work and current installed acceptance remains incomplete.

Best way first: keep [Apple's daemon/session boundaries](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/)
and a finite [monotonic uptime](https://developer.apple.com/documentation/foundation/processinfo/systemuptime)
deadline. Preserve all code/path/key/listener/UID checks and owned-child cleanup.
The proposed fix uses a bounded 120-second readiness window and closed timeout/
child-exit diagnostics. A fake-clock slow-start regression fails at the original
30 seconds and passes at 45 seconds with the new window; six cases also cover
deadline expiry, early exit, ownership failure, transient health errors and
late health replies. No signature or privilege boundary changes. Actual native
compilation, exact build-125 package qualification and installed acceptance are
still required; this does not establish the real startup cause or a completed fix.
