# Account Access - how we work

READINESS.md defines completion. This file assigns the work and its runners.

## Strategy

- Diagnosis: 40 flow rows have 26 verified, 8 owner, 5 building and 1 cut. Installed 127 preserves four grants, but real Harel email/SMS and authenticator acceptance are unfinished. More source tests alone cannot close those flows.
- Guiding policy: prove one installed sign-in method at a time in the owner's order. Retain qualified 127 and completed imports while the Harel email candidate is built. Keep private values in the native app and return only sign-in status.
- Coherent actions: preserve F2/D15's actual Chrome/password evidence; finish D21/D22's checked-mailbox review and fresh automatic email test; qualify and deliver one matching update in D23; then take F4 SMS and F5 authenticator enrollment in that order, preserving paused challenges.
- Feasible because: the Mac, installed service, checked TLS mailbox, existing publisher tooling and local native/test tooling exist. No OWNER.md is present and no new spending, account, publisher identity or upload is authorized here. GitHub Actions budget is $0 and no Actions may run. Existing approvals stay in READINESS.md; native presence remains the owner's action. The riskiest assumption is Harel's private response/message shape; its cheapest honest test is one qualified native setup and one explicitly approved automatic email login.
- Next objective: one qualified Harel email candidate with native setup and a matching signed update by 2026-11-05; actual private acceptance remains a staged owner action.
- Review by: 2026-11-05

## Processes

| ID | Process | When | Runner | How (where the steps live) | Done when | Last run | Health |
|---|---|---|---|---|---|---|---|
| P1 | Build the next ordered sign-in flow | every run | session | READINESS.md; qa/ordered-verification-2026-11-04/notes.md | code, refusals and real owned UI verified; evidence committed | 2026-11-04 19:23 | ok |
| P2 | Review and fix isolated setup safety before release | on source candidate | agent | readiness/harel-release-plan.md; readiness/harel-setup-review.md | concrete findings fixed and exact release inputs identified | 2026-11-04 18:36 | ok |
| P3 | Run and read local qualification | on source change | session | scripts/ci-local.sh; READINESS.md | exact-source local reports inspected; failures fixed; no GitHub Actions | 2026-11-04 19:09 | failing |
| P4 | Deliver and accept the installed candidate | before owner setup | session | macos/README.md; READINESS.md | signed update matches installation and available launcher checks pass; owner action staged once | - | new |
| P5 | Review workflow and remove recurring friction | weekly sun | session | /Users/nirfeinstein/.agents/skills/learn/SKILL.md | ledger/workspace refreshed and one evidence-backed process kept or improved | - | new |

## Lanes

| Lane | Covers (tracks, processes) | Runner | Owns (files) | WIP | Waits on |
|---|---|---|---|---|---|
| Build | D21/D22/D26, P1 | session | macos/, account_access/owner.py, account_access/harel_protocol.py, account_access/harel_login.py, account_access/models.py, account_access/browser.py, account_access/broker.py, scripts/build_owner_routes_update_image.py, scripts/build_direct_runtime_upgrade_candidate.py, scripts/mac_owner_gateway_smoke.py, tests/test_harel_protocol.py, tests/test_harel_owner_ui.py, qa/ordered-verification-2026-11-04/ | 1 | - |
| Local CI | D23/P3 | session | .github/workflows/, scripts/ci-local.sh, readiness/local-ci-transition.md | 1 | - |

Coordinator: this desktop session owns READINESS.md, PROCESSES.md, approvals, git publication and final qualification. Setup safety and final independent review are complete; those files return to the coordinator. Local CI migration and its306 workflow/14 gateway checks are complete; ownership returns to the coordinator. Release compilation and local CI run one at a time on this low-disk Mac. Only temporary synthetic ad-hoc signing fixtures are allowed in CI; publisher signing stays a separate release step. No GitHub Actions dispatch or automatic trigger is permitted. Private browser/sign-in work stays in the desktop session and installed launcher, never a headless loop. P3 uses the existing two-hour desktop follow-up; unchanged jobs or the same owner approval remain quiet. Delete the follow-up when technical delivery and available acceptance finish.

## Changes (last 10)

- 2026-11-04 - P2 - Separate release preparation from the product writer; preserve one writer per file set - why: D22 needs UI work while D23 has independent predecessor/profile research - read on 2026-11-05: pending
