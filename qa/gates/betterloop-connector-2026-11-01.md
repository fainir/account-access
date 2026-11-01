# Betterloop connector - 1 November 2026

## Source and public-form verification

The public `https://betterloopai.com/login` page has one native multipart POST
form, with the `email` and `password` inputs and one Log in submit button.
Its native destination is exactly `/login`. Next/React supplies opaque hidden
action fields; the connector does not invent or retain their values.

The connector has JavaScript disabled, one POST destination (`/login`), one
login landing (`/app`) and one authenticated status page (`/app/account`).
Its only proposed operation returns `{"authenticated": true}`. It extracts no
page text, email, project information, API key or billing detail. Landing-page
HTML can contain private account metadata; it stays inside the browser.
API-key, billing, export, deletion, project and signup actions are not operations.

`uv run pytest -q tests/test_betterloop.py tests/test_browser_session_status.py tests/test_catalog.py`
passed **29 tests**. Provider-shaped multipart fixtures cover session reuse and
expiry recovery, incorrect credentials, lookalike imports, unapproved reads,
changed form destinations/methods, submit overrides, unreviewed redirects,
and no extraction of private page text. These are controlled fixtures, not a
successful live private account login.

`uv run python -m scripts.betterloop_preflight` passed **11/11** on the live
public form through the product's network guard: correct HTTP/URL/form,
multipart encoding, unique visible fields/submit, no authenticated marker,
safe anonymous status redirect, and no POST/code request. No personal profile,
password, private session or new account was used.

Ruff passes for the changed catalog, test and preflight source. The existing
build-122 wheel was compared with the current source: only `catalog.py` differs
among runtime Python modules, with no added/removed runtime module.

## Installed acceptance remains open

The installed app is still build 122 and has no Betterloop entry. A matching
successor, signature/notarization and exact predecessor update acceptance must
finish before asking the owner to connect Betterloop locally. No private login,
new grant, saved credential, production release or real MFA success is claimed.
Do not use the Chrome login page as a substitute for installed Account Access.
No raw browsing history or history URLs are retained in this evidence.

## Matching successor image

[Completed owner/broker compilation](https://github.com/fainir/account-access/actions/runs/41288435608)
passed native UI checks and produced build 123 with the exact new embedded wheel.
The matching private image copy passed [actual image qualification](../release123-2026-11-01/image-qualification.json):
49 native-file publisher signatures, unchanged dependency/JIT bytes and real
signed sandboxed-browser execution. No installed path or account data changed.
This image audit does not claim notarization or Installer acceptance.

Its exact predecessor delta has 15 units and 16 changed nodes, including two
public Python trees. The build-122-to-123 native contract uses its own compiled
namespace and retains the previous 120, 121 and 122 recovery histories.
The release/packaging tests pass 168 cases with one platform skip; the focused
frozen-source/catalog/contract run passes 82 cases. Those sets overlap; they are
not an additional 250 distinct checks. Ruff and frozen-input validation pass.
Actual native contract qualification and signed Installer acceptance remain next.
