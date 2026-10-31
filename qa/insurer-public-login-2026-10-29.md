# Public insurer login observation

Date: 2026-10-29. Surface: user Chrome, anonymous public pages. No account identity, contact value, password or code was entered. No login or code-send button was pressed.

| Provider | Observed public form | Limits |
| --- | --- | --- |
| Harel | Direct personal-area dialog showed identity number and mobile fields. SMS was selected by default; email was an alternative. | No submit was sent. API sequence, OTP request, authenticated marker and session status were not tested. |
| Phoenix | Personal-area entry redirected to a state-bound login page. It asked for identity type/number and phone or email. Login-code and voice-call buttons were disabled until values were entered. | No values were entered. The transient `state` query was not retained. API sequence, challenge, authenticated marker and session status were not tested. |

This is public discovery only. It does not qualify either connector. Their JavaScript flows still need narrow request/response review, safe synthetic coverage and owner acceptance with the approved Android SMS source. Continue to refuse unreviewed actions and return session status only.
