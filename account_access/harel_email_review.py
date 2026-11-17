"""Prepare a local first-use Harel email pattern for explicit owner review.

This is not an inbox search or an automatic code resolver. The native owner
supplies the code from the email for the service-owned login attempt, once.
Only that matching message can propose a source; its sender/subject/pattern
still need local approval before later unattended reads can use them.
"""

import email.policy
from email.parser import BytesParser
import re

from .email_codes import MAX_MESSAGE_BYTES, MessageHTML, _body, _validate_tree

ADDRESS = re.compile(r"[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+")
BRAND = re.compile(r"הראל|\bharel\b", re.IGNORECASE)
LOGIN = re.compile(r"כניסה|התחברות|הזדהות|אימות|\bsign[ -]?in\b|\blog[ -]?in\b|\bverification\b", re.IGNORECASE)
TRANSACTION = re.compile(r"תשלום|רכישה|העברה|חתימה|חיוב|\bpayment\b|\bpurchase\b|\btransfer\b|\btransaction\b|\bsignature\b", re.IGNORECASE)


def preview(raw, *, recipient, code):
    """Return a redacted owner-only filter proposal, or None; never the code.

    Header matching and MIME normalization are the same as the existing
    resolver. The caller must also bind this message to the current mailbox
    UID/validity, arrival window, profile generation and Harel attempt.
    """
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_MESSAGE_BYTES
            or not isinstance(recipient, str) or not ADDRESS.fullmatch(recipient)
            or not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code)):
        return None
    try:
        message = BytesParser(policy=email.policy.default).parsebytes(raw)
        _validate_tree(message)
        selected = {}
        for name in ("From", "To", "Subject"):
            headers = message.get_all(name, [])
            if len(headers) != 1 or getattr(headers[0], "defects", ()):
                return None
            header = headers[0]
            if name == "Subject":
                value = str(header)
            else:
                if len(header.addresses) != 1:
                    return None
                value = header.addresses[0].addr_spec
                if not ADDRESS.fullmatch(value):
                    return None
            if not 1 <= len(value) <= 200 or any(ord(char) < 32 or ord(char) == 127 for char in value):
                return None
            selected[name] = value
        if selected["To"].lower() != recipient.lower():
            return None
        body = _body(message)
        if not body:
            return None
        kind, text = body
        if kind == "text/html":
            parser = MessageHTML()
            parser.feed(text)
            parser.close()
            if parser.ignored:
                return None
            text = " ".join("".join(parser.text).split())
        text = text.strip()
        combined = selected["Subject"] + " " + text
        matches = list(re.finditer(r"(?<![0-9])[0-9]{6}(?![0-9])", text))
        if (not 1 <= len(text) <= 2000 or len(matches) != 1 or matches[0].group() != code
                or "{code}" in text or code in selected["From"] or code in selected["Subject"]
                or any(ord(char) < 32 and char not in "\n\r\t" or ord(char) == 127 for char in text)
                or not BRAND.search(combined) or not LOGIN.search(combined) or TRANSACTION.search(combined)):
            return None
        start, end = matches[0].span()
        template = text[:start] + "{code}" + text[end:]
        if len(template) > 2000:
            return None
        return {"sender": selected["From"], "recipient": recipient,
                "subject": selected["Subject"], "template": template}
    except (ValueError, TypeError, AttributeError, LookupError, RecursionError):
        return None
