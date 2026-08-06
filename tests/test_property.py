from __future__ import annotations

import base64
import binascii
import json as _json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from agent_warrant.canonical import canonicalize
from agent_warrant.exceptions import UnresolvableIssuer
from agent_warrant.grant import Grant, PossessionProof, verify
from agent_warrant.identity import generate_keypair
from agent_warrant.resolver import PinnedResolver

# Property-based tests added after a fourth manual review pass found three real
# never-raises violations across three review cycles, each via a genuinely different
# unguarded field, plus a vacuous regression test that passed for the wrong reason.
# Manual hand-built payloads kept hitting a ceiling -- each pass found the NEXT field
# nobody had thought to try. These tests state the invariants once and let Hypothesis
# search for the adversarial payload, rather than a reviewer guessing it.

_JSON_LEAF = st.one_of(
    st.text(max_size=20),
    st.integers(min_value=-1000, max_value=1000),
    st.booleans(),
    st.none(),
    st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
)

_JSON_VALUE = st.recursive(
    _JSON_LEAF,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=10), children, max_size=5),
    ),
    max_leaves=200,
)

_ADVERSARIAL_SCALAR = st.one_of(
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=20),
    st.none(),
    st.booleans(),
    st.integers(),
    st.lists(st.integers(), max_size=3),
    st.dictionaries(st.text(max_size=5), st.integers(), max_size=3),
)


class _NullResolver:
    """Always refuses ANY issuer it's asked to resolve for a str issuer. Deliberately
    NOT used for the adversarial-issuer-value properties below -- it doesn't touch a
    dict at all, so it can never exercise PinnedResolver's real vulnerable path
    (dict.get() on an attacker-controlled, possibly-unhashable key). Caught live while
    writing these tests: using this resolver for the issuer-fuzzing property gave a
    false "no bug found" result even with the isinstance(issuer, str) guard removed,
    because the mutation this property exists to catch was never on this resolver's
    code path in the first place. Kept for the possession-proof-only property, where
    the resolver is never reached at all regardless."""

    def resolve(self, issuer):
        raise UnresolvableIssuer(f"no such issuer: {issuer!r}")


@given(_JSON_VALUE)
@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_canonicalize_never_raises_recursion_error(value):
    # The core invariant: canonicalize() either succeeds (bytes) or fails closed with
    # ValueError -- never RecursionError, never anything else, for any JSON-shaped input.
    #
    # Honest limitation, checked live: st.recursive's natural distribution with
    # max_leaves=200 rarely generates a chain deep enough to approach Python's
    # recursion limit -- it favors wide-shallow structures over narrow-deep ones, so
    # this property did NOT catch the depth guard being removed in mutation testing.
    # The explicit, hand-built depth-chain tests in test_canonical.py and test_grant.py
    # (mutation-confirmed) remain the load-bearing coverage for the recursion-depth
    # class of bug specifically -- this property test is real, additional coverage for
    # structural variety (mixed types, wide structures, unusual shapes) at the depths
    # it does explore, not a replacement for the explicit boundary tests.
    try:
        result = canonicalize({"x": value})
        assert isinstance(result, bytes)
    except ValueError:
        pass  # expected fail-closed path (depth limit)


@given(data=st.binary(max_size=2000))
@settings(max_examples=300, deadline=None)
def test_decode_only_raises_expected_types(data):
    # Grant.decode()'s own contract: every caller (verify()) catches exactly
    # (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError) around it.
    # Any OTHER exception type escaping here would be an uncaught raise one level up.
    encoded = data.decode("latin-1")
    try:
        Grant.decode(encoded)
    except (ValueError, TypeError, KeyError, binascii.Error, _json.JSONDecodeError):
        pass


@given(
    issuer=_JSON_VALUE,
    subject=_JSON_VALUE,
    scope=_JSON_VALUE,
    issued_at=_ADVERSARIAL_SCALAR,
    expires_at=_ADVERSARIAL_SCALAR,
    version=st.one_of(st.just(1), st.integers(), st.text(max_size=5), st.none(), st.booleans()),
)
@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_verify_never_raises_for_wellformed_envelope_adversarial_fields(
    issuer, subject, scope, issued_at, expires_at, version
):
    # Wraps arbitrary, adversarial field VALUES in a syntactically well-formed envelope
    # -- this is exactly the shape of the three real bugs found across four review
    # passes (unhashable issuer, non-numeric timestamps, deeply-nested scope), fuzzed
    # instead of hand-picked.
    body = {
        "version": version,
        "issuer": issuer,
        "subject": subject,
        "scope": scope,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    try:
        raw = _json.dumps(body).encode()
    except (TypeError, ValueError):
        return  # a small fraction of generated values aren't JSON-serializable at all; not this test's concern
    body_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    encoded = f"{body_b64}.AAAA"  # base64-valid garbage proof -- see grant.py review history for why this matters

    proof = PossessionProof(grant_binding="x", iat=1000.0, signature="AAAA")
    # A REAL PinnedResolver, not _NullResolver: this is the actual vulnerable path
    # (dict.get() on an attacker-controlled key) -- a resolver that always refuses
    # regardless of input can never exercise it, which is exactly the flaw an earlier
    # draft of this test had (confirmed live: it gave a false pass even with the
    # issuer isinstance guard removed, because it never reached PinnedResolver at all).
    resolver = PinnedResolver({"team-a": generate_keypair().public_key()})
    result = verify(encoded, proof, resolver, now=1000.0)
    assert result.valid is False
    assert isinstance(result.reason, str)


@given(
    grant_binding=_JSON_VALUE,
    iat=_ADVERSARIAL_SCALAR,
    signature=st.text(max_size=200),
)
@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_verify_never_raises_for_adversarial_possession_proof(grant_binding, iat, signature):
    # Same property, targeting PossessionProof's own fields specifically -- this is the
    # exact shape of the "deeply-nested grant_binding" and "non-numeric iat" findings.
    proof = PossessionProof(grant_binding=grant_binding, iat=iat, signature=signature)
    result = verify("AAAA.AAAA", proof, _NullResolver(), now=1000.0)
    assert result.valid is False
    assert isinstance(result.reason, str)
