"""Bounded MIME parsing for an exact, owner-reviewed login-message template.

HTML is parsed as text only. Nothing is rendered, executed or fetched. This is
not an inbox search, a generic six-digit-code extractor or sender authentication.
"""

import email.policy
import re
from email.parser import BytesParser
from html.parser import HTMLParser

MAX_MESSAGE_BYTES = 256_000
MAX_PARTS = 64
MAX_DEPTH = 8


class MessageHTML(HTMLParser):
    blocks = {"br", "p", "div", "li", "tr", "td", "th", "table", "h1", "h2", "h3",
              "h4", "h5", "h6", "blockquote", "section", "article", "hr"}
    unsafe = {"script", "form", "input", "button", "iframe", "object", "embed", "svg",
              "math", "template", "noscript"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.ignored = []
        self.elements = 0

    def handle_starttag(self, tag, attrs):
        self.elements += 1
        if self.elements > 4096 or tag in self.unsafe:
            raise ValueError("unsupported email markup")
        if tag in {"head", "style", "title"}:
            self.ignored.append(tag)
        elif not self.ignored and tag in self.blocks:
            self.text.append(" ")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.ignored:
            if self.ignored[-1] == tag:
                self.ignored.pop()
        elif tag in self.blocks:
            self.text.append(" ")

    def handle_data(self, data):
        if not self.ignored:
            self.text.append(data)


def _validate_tree(part, depth=0, budget=None):
    budget = [0] if budget is None else budget
    budget[0] += 1
    if depth > MAX_DEPTH or budget[0] > MAX_PARTS or part.defects:
        raise ValueError("invalid email structure")
    for name in ["Content-Type", "Content-Transfer-Encoding", "Content-Disposition"]:
        headers = part.get_all(name, [])
        if len(headers) > 1 or any(getattr(header, "defects", ()) for header in headers):
            raise ValueError("ambiguous email part")
    if part.is_multipart():
        for child in part.iter_parts():
            _validate_tree(child, depth + 1, budget)


def _body(part):
    if part.get_content_disposition() == "attachment" or part.get_filename():
        return None
    kind = part.get_content_type()
    if kind in {"text/plain", "text/html"}:
        # Decode strictly: replacing malformed bytes must not create a match.
        raw = part.get_payload(decode=True)
        if not isinstance(raw, bytes) or part.defects:
            raise ValueError("invalid email encoding")
        return kind, raw.decode(part.get_content_charset() or "ascii", errors="strict")
    if part.get_content_maintype() != "multipart":
        return None  # Never look inside forwarded messages or attachments.
    parts = list(part.iter_parts())
    if kind == "multipart/related":
        start = part.get_param("start")
        roots = [child for child in parts if child.get("Content-ID") == start] if start else parts[:1]
        if len(roots) != 1:
            raise ValueError("ambiguous related email")
        return _body(roots[0])
    bodies = [body for child in parts if (body := _body(child)) is not None]
    if kind == "multipart/alternative":
        preferred = "text/plain" if any(body[0] == "text/plain" for body in bodies) else "text/html"
        bodies = [body for body in bodies if body[0] == preferred]
    if len(bodies) > 1:
        raise ValueError("ambiguous email body")
    return bodies[0] if bodies else None


def login_code(raw, source):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_MESSAGE_BYTES:
        return None
    try:
        message = BytesParser(policy=email.policy.default).parsebytes(raw)
        _validate_tree(message)
        for name, expected in [("From", source.sender), ("To", source.recipient),
                               ("Subject", source.subject)]:
            headers = message.get_all(name, [])
            if len(headers) != 1 or getattr(headers[0], "defects", ()):
                return None
            if name == "Subject":
                if str(headers[0]) != expected:
                    return None
            else:
                addresses = headers[0].addresses
                if len(addresses) != 1 or addresses[0].addr_spec.lower() != expected.lower():
                    return None
        body = _body(message)
        if not body:
            return None
        kind, text = body
        template = source.template
        if kind == "text/html":
            parser = MessageHTML()
            parser.feed(text)
            parser.close()
            if parser.ignored:
                return None
            # HTML layout and entities can change whitespace, never words,
            # punctuation, the number of codes or the approved message purpose.
            text = " ".join("".join(parser.text).split())
            template = " ".join(template.split())
        pattern = re.escape(template).replace(re.escape("{code}"), r"([0-9]{6})")
        match = re.fullmatch(pattern, text.strip())
        return match[1] if match else None
    except (ValueError, TypeError, AttributeError, LookupError, RecursionError):
        return None
