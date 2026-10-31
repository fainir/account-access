"""Regression for CVE-2026-119284: reject before copying compact-JWS segments."""
import pytest
from joserfc import jws
from joserfc.errors import ExceededSizeError


def test_oversized_compact_jws_is_rejected_before_split():
    class NoSegmentCopies(bytes):
        def split(self, *args, **kwargs):
            raise AssertionError('Oversized input must not be split into copied segments')

    value = NoSegmentCopies(b'a' * 1_000_000 + b'.b.c')
    with pytest.raises(ExceededSizeError):
        jws.deserialize_compact(value, None)
