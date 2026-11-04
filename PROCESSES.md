# Account Access - how we work

READINESS.md defines completion. This file assigns the work and its runners.

## Strategy

- Diagnosis: 41 flow rows include a reproduced127 postboot failure. Corrected128 passes5146 tests and native/package qualification; installed launchers await native action21. Installed 127 preserves four grants, but real Harel email/SMS and authenticator acceptance are unfinished. More source tests alone cannot close those flows.
- Guiding policy: prove one installed sign-in method at a time in the owner's order. Preserve completed imports and prior releases while the corrected128 update is installed and accepted. Keep private values in the native app and return only sign-in status.
- Coherent actions: preserve F2/D15's actual Chrome/password evidence; fix and independently review D29 bounded cold-start recovery; retain verified D21/D22 components, then correct D23 signed delivery and test one fresh automatic email login; then take F4 SMS and F5 authenticator enrollment in that order, preserving paused challenges.
- Feasible because: the Mac, installed service, checked TLS mailbox, existing publisher tooling and local native/test tooling exist. No OWNER.md is present and no new spending, account, publisher identity or upload is authorized here. GitHub Actions budget is $0 and no Actions may run. Existing approvals stay in READINESS.md; native presence remains the owner's action. The riskiest assumption is Harel's private response/message shape; its cheapest honest test is one qualified native setup and one explicitly approved automatic email login.
- Next objective: verify1 installed corrected128 after action21 and complete available approved launcher checks in that pickup; next technical review by2026-11-06. Actual private email enrollment remains a separate native owner action.
- Review by: 2026-11-06

## Processes

| ID | Process | When | Runner | How (where the steps live) | Done when | Last run | Health |
|---|---|---|---|---|---|---|---|
| P1 | Build the next ordered sign-in flow | every run | session | READINESS.md; qa/ordered-verification-2026-11-04/notes.md | code, refusals and real owned UI verified; evidence committed | 2026-11-05 00:47 | ok |
| P2 | Review and fix isolated setup safety before release | on source candidate | agent | readiness/harel-release-plan.md; readiness/harel-setup-review.md | concrete findings fixed and exact release inputs identified | 2026-11-05 00:47 | ok |
| P3 | Run and read local qualification | on source change | session | shared local CI wrapper in a detached ordinary session; READINESS.md | exact-source local reports inspected; failures fixed; no GitHub Actions | 2026-11-05 00:47 | ok |
| P4 | Deliver and accept the installed candidate | before owner setup | session | macos/README.md; READINESS.md | signed update matches installation and available launcher checks pass; owner action staged once | 2026-11-05 00:47 | owner |
| P5 | Review workflow and remove recurring friction | weekly sun | session | /Users/nirfeinstein/.agents/skills/learn/SKILL.md | ledger/workspace refreshed and one evidence-backed process kept or improved | - | new |

## Lanes

| Lane | Covers (tracks, processes) | Runner | Owns (files) | WIP | Waits on |
|---|---|---|---|---|---|
| Installed acceptance | D23/D29/F1/F6/P4 | session | qa/ordered-verification-2026-11-04/, READINESS.md | 1 | owner action21 |
| Ordered email then SMS | F3/F9/F4/P1 | session | account_access/, macos/AccountAccess.swift, provider tests | 1 | F3 native enrollment after action21 |

Coordinator owns ledgers/git/release qualification. Startup source fix and independent review are complete; their files return to the coordinator. Corrected source32e5870 full local CI, helper qualification, all120-127 compatibility and final signed/notarized updater read back successfully. No jobs remain. Installer is staged for the one new native action21. While it is unchanged, stay quiet; never reapply old packages or repeat approval. Use exact installed/public-byte/postinstall read-back and approved launcher operations after change. Private Harel enrollment stays in the native app, followed by SMS and authenticator in the owner's order. No Actions, new keys, account data access or spending. The two-hour technical follow-up remains active and deletes itself after installation/available automated acceptance; personal setup and publication remain owner work.

## Changes (last 10)

- 2026-11-04 - P2 - Separate release preparation from the product writer; preserve one writer per file set - why: D22 needs UI work while D23 has independent predecessor/profile research - read on 2026-11-05: pending

- 2026-11-04 - P3 - Read kernel boot and completed CI before diagnosing a lost runner; use detached ordinary execution - evidence: initial managed CI predates a real reboot, final local runner completed successfully - read on2026-11-05: pending
