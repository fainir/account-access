Evidence for READINESS.md rows. Layout: qa/<row-id>/<date>-<width>.png and qa/<row-id>/notes.md;
qa/ux/, qa/gates/, qa/perf/, qa/prod/ for reviews, gates, Lighthouse and production smoke tests.
Keep it small: overwrite superseded screenshots. Never store secrets or real user data here.

Publisher-signed Android emulator QA: follow [the signed-candidate acceptance](gates/android-publisher-acceptance-2026-10-31.md) for the local AVD setup, real UI checks and ATD limits. Do not run the guarded hosted-only update fixture locally or attach development-key instrumentation to the publisher-signed app.
