# Account Access - agent notes

Follow the production-ready skill (`/Users/nirfeinstein/.agents/skills/production-ready/SKILL.md`);
`READINESS.md` at the repo root is the definition of done.

- Done means, on a clean Mac from the public download: signed install and update, Chrome
  password import, email/SMS/authenticator code handling, and automatic use by Codex and
  Claude Code for an approved sign-in. Each is a flow row with evidence.
- Owner-only steps (Touch ID, macOS permission prompts, notarization or signing credentials)
  are one-line owner actions; keep building everything else meanwhile.
- Builds: cut a new installer only when it contains a fix for a verified defect. More than
  two builds a day is a signal to stop and diagnose, not to retry.
- Run checks with the repo's own tooling (`uv run pytest`, scripts under `scripts/`); keep
  QA evidence under `qa/` and prune superseded builds from `dist/`.
