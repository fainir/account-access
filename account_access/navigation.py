"""Fixed-vocabulary owner diagnostics. Never persist a provider-controlled URL."""

import re
from urllib.parse import urlsplit

from .models import origin

# Public route words, not a general URL sanitizer. Unknown segments, user names,
# identifiers, percent encodings and tokens collapse to one marker. Adding a word
# here reveals only that literal word; it never authorizes a network request.
WORDS = frozenset("""
account account_verifications accounts app auth authenticate authentication
callback challenge check compromised_password device email error flow github
login mobile new notification oauth otp password password_reset profile recovery
required reset security session sessions settings setup sms sso sudo totp
two-factor two_factor trusted-device trusted_device verification verified-device
verified_device verify webauthn
""".split())


def route_hint(url, known_origins):
    parts = urlsplit(url)
    origins = sorted(set(known_origins))
    destination = origin(url)
    host = "origin_" + str(origins.index(destination)) if destination in origins else "external"
    segments = parts.path.split("/")[1:]
    path = "/".join(word if word in WORDS else "?" for word in segments[:8])
    if len(segments) > 8:
        path += "/?"
    return host + ":/" + path


def valid_hint(value):
    if not isinstance(value, str) or len(value) > 240:
        return False
    host, separator, path = value.partition(":/")
    if not separator or not re.fullmatch(r"(?:origin_[0-9]{1,3}|external)", host):
        return False
    segments = path.split("/")
    return len(segments) <= 9 and all(word in WORDS or word in {"", "?"} for word in segments)
