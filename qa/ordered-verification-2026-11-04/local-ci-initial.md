# Initial local qualification - 4 November 2026

The shared wrapper ran program source13fc473 in2802s and GitHub reports its local-ci status **failure**. This is not a successful full CI claim.

- Full pytest:5078 passed,5 skipped,29 failed in1970.48s. The28 permission/group failures came from the runner’s077 umask and Darwin /tmp wheel inheritance; the final packaging case correctly refused an in-flight uncommitted source edit.
- Corrected targeted rechecks: the [first3](local-ci-permissions.log) pass; [25 further cases](local-ci-permissions-broad.log) pass, with the dirty-tree case then passing after commit ([clean recheck](clean-source-recheck.log)). These are combined rechecks, not a second full run.
- Audit, lock, dependency export, lint and Python distribution build pass.
- Production owner/gateway typechecks for arm64 and x86_64 pass. Optimized64 native UI groups,84 ad-hoc native gateway checks, desktop channel, browser bridge, mailbox callback and isolated launch pass. No publisher/private/installed acceptance is inferred.
- [Runtime source](runtime-source.json) passes72 checks. [Owner-upgrade source](owner-upgrade-source.json) passes its native source/storage/recovery groups and ordinary refusal.
- The shared installed-source probe correctly refuses its /tmp alias before compilation. The runner now uses canonical /private/tmp, primary owner group and standard022 for child fixtures inside private0700 scratch. Its original guards are intact.

No installed paths or owner data changed. Final full local CI is still required at the new helper source, after actual128 manifest/plan bindings exist. Do not repeat an intermediate unchanged source-only full job.

Policy read-back additionally confirms all31 repository-controlled workflows are disabled_manually ([actual workflow state](actions-workflow-policy.json)); the repository Actions switch is disabled. Dynamic GitHub system entries are not repository workflows. No Actions run was started.
