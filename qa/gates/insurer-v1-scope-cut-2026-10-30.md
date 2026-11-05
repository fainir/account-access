# Insurer connector v1 scope decision - 2026-10-30

## Decision

Harel and Phoenix direct login automation is cut from v1. Account Access does
not claim to support either insurer; the application must refuse these flows.
This is a release-scope decision, not a claim that insurer login was completed.

## Evidence

- [Insurer acceptance record](../../docs/insurer-login-acceptance.md) records
  Harel's identity/mobile form and unqualified JavaScript challenge branches,
  Phoenix's state-bound login and unavailable request contract, and the
  requirements for any future connector.
- [Public Harel login observation](../insurer-public-login-2026-10-29.md)
  confirms the visible identity/mobile form. The native GET form must not be
  submitted because that would put personal identifiers in a URL.
- [Identity/SMS continuation regression](continuation-smoke-2026-10-30.md)
  passes 53 synthetic cases, including refusal before identity or phone is
  sent for the observed Harel GET form.
- Current targeted regression run: `uv run pytest -q tests/test_identity_contact_login.py` passed **23 tests** on 30 October 2026.
- [Release copy](../../docs/release-copy-draft.md) already states that Harel
  and Phoenix are not supported connectors.

No owner identity, phone, password, insurer session or SMS code was entered or
transmitted during this decision. Reopen as a new build row only when the exact
provider contract and owner acceptance can be verified without broadening the
generic connector's permissions.
