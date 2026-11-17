"""First-use local review with synthetic messages; no account or inbox reads."""

from email.message import EmailMessage
import json

import pytest

from account_access.email_codes import login_code
from account_access.harel_email_review import preview
from account_access.models import CodeSource

CODE = "654321"
RECIPIENT = "owner@example.test"


def mail(body="Harel sign-in verification code: 654321", *, html=False):
    message = EmailMessage()
    message["From"] = "Harel fixture <login@example.test>"
    message["To"] = RECIPIENT
    message["Subject"] = "Harel sign-in verification"
    message.set_content(body, subtype="html" if html else "plain")
    return message


@pytest.mark.parametrize("body,html", [
    ("Harel sign-in verification code: 654321", False),
    ("הראל - קוד אימות לכניסה: 654321", False),
    ("<html><head><style>p{color:red}</style></head><body><p>Harel sign-in verification code: <b>654321</b></p></body></html>", True),
])
def test_owner_review_redacts_code_and_proposes_exact_reusable_filter(body, html):
    raw = mail(body, html=html).as_bytes()
    result = preview(raw, recipient=RECIPIENT, code=CODE)
    assert result and result["template"].count("{code}") == 1
    assert CODE not in json.dumps(result)
    source = CodeSource(kind="imap", host="mail.example.test", **result)
    assert login_code(raw, source) == CODE
    assert login_code(mail(body.replace(CODE, "123456"), html=html).as_bytes(), source) == "123456"


@pytest.mark.parametrize("body", [
    "Other sign-in verification code: 654321", "Harel message: 654321",
    "Harel sign-in verification code: 654321 123456", "Harel sign-in verification code: 123456",
    "Harel sign-in verification code: 16543210", "Harel sign-in verification code: 654321 {code}",
    "Harel payment verification code: 654321", "Harel transfer verification code: 654321",
    "הראל קוד אימות לחתימה: 654321", "הראל קוד אימות לתשלום: 654321",
    "הראל קוד אימות לחיוב: 654321", "Harel signature verification code: 654321",
    "Harel sign-in verification code: 654321" + "x" * 2000,
])
def test_wrong_brand_purpose_code_and_ambiguous_templates_cannot_be_enabled(body):
    message = mail(body)
    message.replace_header("Subject", "Notification")
    assert preview(message.as_bytes(), recipient=RECIPIENT, code=CODE) is None


@pytest.mark.parametrize("name,value", [("From", "login@other.example.test, another@example.test"),
                                        ("To", "another@example.test"), ("To", "owner@example.test, another@example.test"),
                                        ("Subject", "Harel sign-in 654321")])
def test_review_binds_exact_single_sender_recipient_and_stable_subject(name, value):
    message = mail()
    message.replace_header(name, value)
    assert preview(message.as_bytes(), recipient=RECIPIENT, code=CODE) is None


@pytest.mark.parametrize("name", ["From", "To", "Subject", "Content-Type"])
def test_duplicate_headers_refuse_review(name):
    message = mail()
    raw = (name + ": " + str(message[name]) + "\n").encode() + message.as_bytes()
    assert preview(raw, recipient=RECIPIENT, code=CODE) is None


@pytest.mark.parametrize("body", [
    "<form><p>Harel sign-in verification code: 654321</p></form>",
    "<script>654321</script><p>Harel sign-in verification code: 654321</p>",
    "<iframe src='https://evil.invalid'>Harel sign-in verification code: 654321</iframe>",
])
def test_review_never_renders_fetches_or_accepts_active_mail(body):
    assert preview(mail(body, html=True).as_bytes(), recipient=RECIPIENT, code=CODE) is None


@pytest.mark.parametrize("raw,recipient,code", [(b"", RECIPIENT, CODE), (b"x" * 256001, RECIPIENT, CODE),
                                               (b"invalid", RECIPIENT, CODE), (mail().as_bytes(), "bad", CODE),
                                               (mail().as_bytes(), RECIPIENT, "654321\n")])
def test_invalid_review_inputs_refuse_without_messages_in_errors(raw, recipient, code):
    assert preview(raw, recipient=recipient, code=code) is None
