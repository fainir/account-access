from email.message import EmailMessage

import pytest

from account_access.email_codes import MAX_MESSAGE_BYTES, login_code
from account_access.models import CodeSource

SOURCE = CodeSource(kind="imap", host="mail.example.test", sender="login@example.test",
                    recipient="owner@example.test", subject="Your sign-in code",
                    template="Example sign-in: {code}")


def mail(body="Example sign-in: 123456", subtype="plain"):
    message = EmailMessage()
    message["From"] = "Example <login@example.test>"
    message["To"] = "Owner <owner@example.test>"
    message["Subject"] = SOURCE.subject
    message.set_content(body, subtype=subtype)
    return message


@pytest.mark.parametrize("body", [
    "<html><head><style>p { color: blue }</style><title>Sign in</title></head>"
    "<body><p>Example sign-in: <b>123456</b></p></body></html>",
    "<div>Example&nbsp;sign-in:<br><span>12<strong>34</strong>56</span></div>",
    "<p>Example sign-in: &#49;&#50;&#51;&#52;&#53;&#54;</p><img src='https://example.test/tracker'>",
], ids=["styled-html", "layout-and-inline-code", "entities-and-remote-image"])
def test_html_only_login_email_matches_exact_text_without_rendering_or_fetching(body):
    assert login_code(mail(body, "html").as_bytes(), SOURCE) == "123456"


@pytest.mark.parametrize("transfer", ["base64", "quoted-printable", "8bit"])
def test_plain_email_decodes_charset_and_transfer_encoding(transfer):
    source = SOURCE.model_copy(update={"subject": "Votre code de connexion",
                                       "template": "Votre code vérifié : {code}"})
    message = mail()
    message.replace_header("Subject", source.subject)
    message.set_content("Votre code vérifié : 123456", charset="iso-8859-1", cte=transfer)
    assert login_code(message.as_bytes(), source) == "123456"


@pytest.mark.parametrize("body", [
    "<p>Confirm payment: 123456</p>",
    "<p>Example sign-in: 123456</p><p>Transfer money</p>",
    "<p>Example sign-in: 123456</p><span hidden>Confirm payment</span>",
    "<p>Example sign-in: 123456</p><p>Example sign-in: 654321</p>",
    "<script>123456</script><p>Example sign-in: 123456</p>",
    "<form><p>Example sign-in: 123456</p></form>",
    "<iframe src='https://example.test'><p>Example sign-in: 123456</p></iframe>",
    "<style>p { color: blue }</style>" + "<span> </span>" * 4096 + "Example sign-in: 123456",
], ids=["payment", "extra-purpose", "hidden-purpose", "two-codes", "script", "form", "frame", "element-limit"])
def test_html_never_extracts_arbitrary_or_ambiguous_codes(body):
    assert login_code(mail(body, "html").as_bytes(), SOURCE) is None


@pytest.mark.parametrize("field", ["From", "To", "Subject"])
def test_duplicate_identity_headers_are_rejected_in_either_order(field):
    raw = mail().as_bytes()
    extra = (field + ": " + str(mail()[field]) + "\n").encode()
    assert login_code(extra + raw, SOURCE) is None
    head, body = raw.split(b"\n\n", 1)
    assert login_code(head + b"\n" + extra + b"\n" + body, SOURCE) is None


@pytest.mark.parametrize("field,value", [
    ("From", "login@example.test, attacker@example.test"),
    ("To", "owner@example.test, other@example.test"),
    ("From", "login@other.example.test"),
    ("To", "other@example.test"),
    ("Subject", "Confirm a payment"),
])
def test_identity_and_login_purpose_must_match_exactly(field, value):
    message = mail()
    message.replace_header(field, value)
    assert login_code(message.as_bytes(), SOURCE) is None


def test_plain_alternative_takes_priority_and_cannot_fall_back_to_different_html_purpose():
    message = mail()
    message.add_alternative("<p>Example sign-in: 654321</p>", subtype="html")
    assert login_code(message.as_bytes(), SOURCE) == "123456"
    message.get_payload(0).set_content("Confirm payment: 123456")
    assert login_code(message.as_bytes(), SOURCE) is None


def test_html_related_body_uses_exact_root_and_ignores_image_attachment():
    message = mail("<p>Example sign-in: <b>123456</b></p>", "html")
    message.add_related(b"not a real image", maintype="image", subtype="png", cid="<logo>")
    assert login_code(message.as_bytes(), SOURCE) == "123456"
    message.get_payload(0)["Content-ID"] = "<body>"
    message.set_param("start", "<body>")
    assert login_code(message.as_bytes(), SOURCE) == "123456"
    message.set_param("start", "<missing>")
    assert login_code(message.as_bytes(), SOURCE) is None


def test_attached_forwarded_or_multiple_message_bodies_cannot_supply_a_login_code():
    message = mail("Not a login message")
    message.add_attachment("Example sign-in: 123456", filename="login.txt")
    assert login_code(message.as_bytes(), SOURCE) is None
    forwarded = mail("Not a login message")
    forwarded.add_attachment(mail())
    assert login_code(forwarded.as_bytes(), SOURCE) is None
    ambiguous = mail()
    ambiguous.make_mixed()
    ambiguous.attach(mail("Confirm payment: 654321"))
    assert login_code(ambiguous.as_bytes(), SOURCE) is None


@pytest.mark.parametrize("case", ["oversize", "truncated", "deep", "wide", "charset", "encoding"])
def test_malformed_or_unbounded_email_is_ignored(case):
    message = mail()
    if case == "oversize":
        raw = message.as_bytes() + b" " * MAX_MESSAGE_BYTES
    elif case == "truncated":
        message.add_alternative("<p>Example sign-in: 123456</p>", subtype="html")
        raw = message.as_bytes().rsplit(b"--", 2)[0]
    elif case == "deep":
        for _ in range(10):
            parent = EmailMessage()
            parent.make_mixed()
            parent.attach(message)
            message = parent
        raw = message.as_bytes()
    elif case == "wide":
        message.make_mixed()
        for _ in range(65):
            message.attach(mail())
        raw = message.as_bytes()
    elif case == "charset":
        raw = message.as_bytes().replace(b'charset="utf-8"', b'charset="unknown-encoding"')
    else:
        raw = message.as_bytes().replace(b"7bit", b"base64").replace(b"Example sign-in: 123456", b"%%%")
    assert login_code(raw, SOURCE) is None
