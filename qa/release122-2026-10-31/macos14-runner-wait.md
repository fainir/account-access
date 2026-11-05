# macOS 14 acceptance - resolved 1 November 2026

The earlier provider wait below is resolved by [completed run 41286876216](https://github.com/fainir/account-access/actions/runs/41286876216).
Actual macOS 14.8.9 arm64 reports pass [fresh/repair](macos14-fresh-result/report.json)
and [upgrade/reapply](macos14-upgrade-result/report.json), 11 and 27 checks.
The same pinned signed packages were used. The completed follow-up was deleted;
no noon retry or replacement monitor is needed. Details: [acceptance](acceptance.md).

## Earlier provider failure


The exact unchanged signed build-122 packages were dispatched for fresh/repair and upgrade/reapply. GitHub cancelled both Mac jobs before any VM or test step started. This is not a product test result.

Actual workflow: https://github.com/fainir/account-access/actions/runs/41224873826

Provider annotations:

- "This job failed because of a scheduled macOS 14 runner image brownout. macOS 14 runner images will be retired on November 2, 2026. For migration options and the brownout schedule, see https://github.com/actions/runner-images/issues/13518"
- "This job failed because of a scheduled macOS 14 runner image brownout. macOS 14 runner images will be retired on November 2, 2026. For migration options and the brownout schedule, see https://github.com/actions/runner-images/issues/13518"

The provider's [current schedule](https://github.com/actions/runner-images/issues/13518) includes 31 October 14:00 UTC to 1 November 00:00 UTC, then 1 November 14:00 UTC to 2 November 00:00 UTC. The image retires on 2 November. Retry the same release/platform/journey once on 1 November at 12:00 Asia/Jerusalem (10:00 UTC), outside that window. Read back actual OS/architecture and both reports. If still unavailable, record a precise owner/test-host action rather than rebuilding unchanged packages or polling repeatedly. macOS 14 remains unqualified until actual execution passes.
