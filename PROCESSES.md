# Account Access - how we work

READINESS.md defines completion. This file assigns the work and its runners.

## Strategy

- Diagnosis: 41 flow rows now include a newly observed127 postboot worker failure (D29); source CI passed5145 tests, but installed launchers are unavailable. Installed 127 preserves four grants, but real Harel email/SMS and authenticator acceptance are unfinished. More source tests alone cannot close those flows.
- Guiding policy: prove one installed sign-in method at a time in the owner's order. Retain qualified 127 and completed imports while the Harel email candidate is built. Keep private values in the native app and return only sign-in status.
- Coherent actions: preserve F2/D15's actual Chrome/password evidence; fix and independently review D29 bounded cold-start recovery; retain verified D21/D22 components, then correct D23 signed delivery and test one fresh automatic email login; then take F4 SMS and F5 authenticator enrollment in that order, preserving paused challenges.
- Feasible because: the Mac, installed service, checked TLS mailbox, existing publisher tooling and local native/test tooling exist. No OWNER.md is present and no new spending, account, publisher identity or upload is authorized here. GitHub Actions budget is $0 and no Actions may run. Existing approvals stay in READINESS.md; native presence remains the owner's action. The riskiest assumption is Harel's private response/message shape; its cheapest honest test is one qualified native setup and one explicitly approved automatic email login.
- Next objective: one corrected candidate covering D29 and Harel email with a matching signed update by2026-11-05; actual private acceptance remains a staged owner action.
- Review by: 2026-11-05

## Processes

| ID | Process | When | Runner | How (where the steps live) | Done when | Last run | Health |
|---|---|---|---|---|---|---|---|
| P1 | Build the next ordered sign-in flow | every run | session | READINESS.md; qa/ordered-verification-2026-11-04/notes.md | code, refusals and real owned UI verified; evidence committed | 2026-11-04 19:23 | ok |
| P2 | Review and fix isolated setup safety before release | on source candidate | agent | readiness/harel-release-plan.md; readiness/harel-setup-review.md | concrete findings fixed and exact release inputs identified | 2026-11-04 18:36 | ok |
| P3 | Run and read local qualification | on source change | session | shared local CI wrapper in a detached ordinary session; READINESS.md | exact-source local reports inspected; failures fixed; no GitHub Actions | 2026-11-04 20:32 | ok |
| P4 | Deliver and accept the installed candidate | before owner setup | session | macos/README.md; READINESS.md | signed update matches installation and available launcher checks pass; owner action staged once | 2026-11-04 23:10 | failing |
| P5 | Review workflow and remove recurring friction | weekly sun | session | /Users/nirfeinstein/.agents/skills/learn/SKILL.md | ledger/workspace refreshed and one evidence-backed process kept or improved | - | new |

## Lanes

| Lane | Covers (tracks, processes) | Runner | Owns (files) | WIP | Waits on |
|---|---|---|---|---|---|
| Startup recovery | D29/P1 | agent | macos/RootInitialEnrollment.swift, macos/RootWorkerSupervisor.swift, macos/Tests/InitialWorkerStartupRecoveryChecks.swift, tests/test_worker_startup_recovery.py, readiness/cold-start-recovery.md | 1 | - |
| Safety review | D29/P2 | agent | readiness/cold-start-review.md (source read only) | 1 | - |
| Release coordination | D23/P3/P4 | session | READINESS.md, PROCESSES.md, macos/direct_runtime_upgrade_plan.py, release profiles/pins, qa/ordered-verification-2026-11-04/ | 1 | D29 |

Coordinator owns ledgers, git, package source/pins and publication. New actual cold-start timeout D29 takes priority; keep the signed128 candidate held and uninstalled. Root startup fix and independent safety review run on separate file sets; no private/owner/credential/key/policy reads or service changes. The completed66b69b6 full local CI is green. Its earlier managed predecessor ended before a confirmed Mac reboot; heartbeat causation was incorrectly inferred and has been corrected. Detached CI remains useful isolation from the chat session; check kernel boot, actual process and final logs before retrying. Owner/native release compilation is complete. With more than10GiB now free, the independent two-thread native-probe sequence and source CI may run concurrently against frozen source; do not start a second release compiler or edit tracked files. Use no Actions and never recompile an unchanged package. Private sign-ins remain native owner steps. The existing two-hour follow-up reads this ledger and stays quiet on unchanged state; delete it after installation and available automated checks finish.

## Changes (last 10)

- 2026-11-04 - P2 - Separate release preparation from the product writer; preserve one writer per file set - why: D22 needs UI work while D23 has independent predecessor/profile research - read on 2026-11-05: pending

- 2026-11-04 - P3 - Read kernel boot and completed CI before diagnosing a lost runner; use detached ordinary execution - evidence: initial managed CI predates a real reboot, final local runner completed successfully - read on2026-11-05: pending
