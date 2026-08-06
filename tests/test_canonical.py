from __future__ import annotations

import pytest

from agent_warrant.canonical import canonicalize


def test_canonicalize_sorts_keys_deterministically():
    a = canonicalize({"b": 1, "a": 2})
    b = canonicalize({"a": 2, "b": 1})
    assert a == b


def test_canonicalize_rejects_nan():
    with pytest.raises(ValueError, match="non-finite"):
        canonicalize({"x": float("nan")})


def test_canonicalize_rejects_infinity():
    with pytest.raises(ValueError, match="non-finite"):
        canonicalize({"x": float("inf")})


def test_canonicalize_rejects_non_finite_nested_in_list():
    with pytest.raises(ValueError, match="non-finite"):
        canonicalize({"x": [1, 2, float("nan")]})
