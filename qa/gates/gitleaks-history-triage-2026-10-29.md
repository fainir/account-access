# Historical Gitleaks triage - 2026-10-29

- Re-ran Gitleaks 8.17.0 over the repository history: 606 commits scanned.
- The report contains 237 findings, all from the `generic-api-key` rule, across 69 files in 57 historical commits. There are no findings in the current HEAD or current `account_access` source tree.
- All 237 reported match values are the literal `REDACTED` marker. This was confirmed by counting the marker in memory; no matched values were printed or included in this report. The matches are false positives in generated QA/build artifacts and their captured source manifests: 181 under `artifacts/`, 32 under `qa/`, 14 under `scripts/`, 9 under `macos/`, and 1 under `tests/`.
- No credential rotation or history rewrite is indicated by these findings. A separate `account_access` source scan also completed with zero findings.
- The temporary scanner reports were deleted after summarizing their counts. No raw report or matched value is committed.

The security gate remains open because the updated runtime still needs a signed successor and installed-service acceptance; the historical findings themselves are triaged.
