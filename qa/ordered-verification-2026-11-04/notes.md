# Owner-requested verification order - 4 November 2026

Order: Chrome import and email/password sign-in, then email verification, then
SMS, then authenticator transfer. Existing approvals/data are preserved.

## Step 1: actual Chrome-import/password baseline

The real native Chrome import and initial Betterloop email/password sign-in
were observed on 2 November: [native journey](../betterloop-private-2026-11-02/acceptance.md).
Only the owner-selected account/status grant was saved; no credential file was
opened by the agent. The installed 127 login code for this password-only
connector retains that path. Current normal installed [Codex](codex-password-status.json)
and [Claude](claude-password-status.json) operations each return
COMPLETED/environment live and only authenticated=true. These two current reads
confirm the existing session; they are not fresh password submissions. No
session/credential was erased, no new import/grant or duplicate login challenge.

## Step 2: Harel email, then Step 3: Harel SMS

The owner explicitly selected Harel and identified its email/SMS choice.
This reopens Harel's earlier v1 exclusion; Phoenix stays excluded. Public review
already identified identity/mobile fields and a native GET form wrapped by
JavaScript. The generic GET refusal must remain;IDs/phone/codes must never enter
URLs, agent output or logs. Review the exact provider-owned API sequence before
an installed connector or local personal enrollment is requested. Only boolean
session status is in scope;no insurance policies/medical/payment data.

Best way: use Harel's official public entry/application assets as primary
implementation evidence and enforce a closed, attempt-bound request/response
state machine. Stop on declarations, document-issue-date,card or stronger identity
branches. Reuse the already checked mailbox through native owner binding;
request no saved mailbox password again. Provider and controlled fixture proof
remain distinct from a real email/SMS login. Existing insurer observations:
[review](../../docs/insurer-login-acceptance.md),
[official entry](https://www.harel-group.co.il/Pages/login-page/Login.aspx).

Authenticator action 18 is deferred by the owner until the preceding stages are
accepted. Preserve the existing paused Lemon task/challenge and Namecheap pause;
request no further QR,authenticator setup or manual login codes now.
