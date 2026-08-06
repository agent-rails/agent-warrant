from __future__ import annotations

from dataclasses import replace

import pytest

from agent_warrant.grant import CURRENT_VERSION, prove, sign, verify
from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.resolver import PinnedResolver


def _issuer_and_resolver():
    issuer_private = generate_keypair()
    issuer_public = issuer_private.public_key()
    resolver = PinnedResolver({"team-a": issuer_public})
    return issuer_private, resolver


def _valid_grant_and_proof(now: float = 1000.0):
    issuer_private, resolver = _issuer_and_resolver()
    holder_private = generate_keypair()
    holder_public_b64 = encode_public_key(holder_private.public_key())

    fields = {
        "version": CURRENT_VERSION,
        "issuer": "team-a",
        "subject": holder_public_b64,
        "scope": {"tool": "read_file"},
        "issued_at": now,
        "expires_at": now + 300.0,
    }
    grant = sign(fields, issuer_private)
    proof = prove(grant, holder_private, now=now)
    return grant, proof, resolver, holder_private


def test_sign_and_verify_roundtrip():
    grant, proof, resolver, _ = _valid_grant_and_proof()
    result = verify(grant.encode(), proof, resolver, now=1010.0)
    assert result.valid is True
    assert result.reason == "ok"
    assert result.grant is not None


def test_verify_never_raises_on_malformed_encoding():
    _, proof, resolver, _ = _valid_grant_and_proof()
    result = verify("not a real grant at all", proof, resolver, now=1000.0)
    assert result.valid is False
    assert "malformed" in result.reason


def test_verify_rejects_unsupported_version_before_parsing_other_fields():
    grant, proof, resolver, _ = _valid_grant_and_proof()
    tampered = replace(grant, version=999)
    # Re-sign is not needed to prove the version gate fires -- an unsigned/mis-signed
    # v999 grant must still be rejected on version alone, before signature is even checked.
    body_b64, _, _ = grant.encode().partition(".")
    from agent_warrant.canonical import canonicalize
    from agent_warrant.grant import _b64u

    bad_body = _b64u(canonicalize(tampered._signable_fields()))
    bad_encoded = f"{bad_body}.{grant.proof}"
    result = verify(bad_encoded, proof, resolver, now=1000.0)
    assert result.valid is False
    assert "version" in result.reason


def test_verify_rejects_non_numeric_iat_not_raises():
    # Deliberately NOT constructed via replace(proof, iat=bad_iat) after signing --
    # that tampers the signed body post-signature, so the possession-proof SIGNATURE
    # check catches it first and the iat-type guard is never actually exercised (caught
    # by mutation-testing this test: removing the guard didn't turn it red). Instead,
    # sign a proof body that genuinely contains the bad iat from the start, so the
    # signature is valid and verify() must reach the iat guard to reject it.
    #
    # None is deliberately excluded from this loop: prove(..., now=None) means "use
    # time.time()", not "sign a proof with iat=None" -- caught live: that case silently
    # substituted wall-clock time and failed on staleness instead, not the iat guard.
    # Covered separately below via a hand-built signable body that bypasses prove()'s
    # None-means-unset convention.
    grant, _, resolver, holder_private = _valid_grant_and_proof()
    for bad_iat in ("not-a-number", [], {}):
        bad_proof = prove(grant, holder_private, now=bad_iat)
        result = verify(grant.encode(), bad_proof, resolver, now=1000.0)
        assert result.valid is False
        assert "iat" in result.reason


def test_verify_rejects_none_iat_not_raises():
    from agent_warrant.canonical import canonicalize
    from agent_warrant.grant import PossessionProof, _b64u

    grant, _, resolver, holder_private = _valid_grant_and_proof()
    grant_binding = _b64u(__import__("hashlib").sha256(canonicalize(grant._signable_fields())).digest())
    signable = {"grant_binding": grant_binding, "iat": None}
    signature = _b64u(holder_private.sign(canonicalize(signable)))
    bad_proof = PossessionProof(grant_binding=grant_binding, iat=None, signature=signature)

    result = verify(grant.encode(), bad_proof, resolver, now=1000.0)
    assert result.valid is False
    assert "iat" in result.reason


def test_verify_rejects_bool_iat_not_raises():
    # True/False are int subclasses in Python -- isinstance(True, (int, float)) is True,
    # so the guard needs its OWN isinstance(iat, bool) exclusion, not just a numeric-type
    # check. Chosen now/max_age here so a bool-as-1 iat would coincidentally look FRESH if
    # the bool exclusion were missing (checked_at=1.5, iat=True==1, within a 60s window) --
    # a value that would only be caught by the freshness check wouldn't prove this branch.
    grant, _, resolver, holder_private = _valid_grant_and_proof(now=1.0)
    bad_proof = prove(grant, holder_private, now=True)
    result = verify(grant.encode(), bad_proof, resolver, now=1.5, max_age_seconds=60.0)
    assert result.valid is False
    assert "iat" in result.reason


def test_verify_rejects_unresolvable_issuer():
    grant, proof, _, _ = _valid_grant_and_proof()
    empty_resolver = PinnedResolver({})
    result = verify(grant.encode(), proof, empty_resolver, now=1000.0)
    assert result.valid is False
    assert "unresolvable" in result.reason


def test_verify_rejects_invalid_issuer_signature():
    grant, proof, resolver, _ = _valid_grant_and_proof()
    tampered_encoded = grant.encode()[:-4] + "AAAA"
    result = verify(tampered_encoded, proof, resolver, now=1000.0)
    assert result.valid is False


def test_verify_rejects_expired_grant():
    grant, proof, resolver, _ = _valid_grant_and_proof(now=1000.0)
    result = verify(grant.encode(), proof, resolver, now=5000.0)
    assert result.valid is False
    assert "expired" in result.reason


def test_verify_rejects_forged_possession_proof():
    grant, _, resolver, _ = _valid_grant_and_proof(now=1000.0)
    attacker_private = generate_keypair()
    forged_proof = prove(grant, attacker_private, now=1000.0)
    result = verify(grant.encode(), forged_proof, resolver, now=1000.0)
    assert result.valid is False


def test_verify_rejects_possession_proof_bound_to_different_grant():
    grant_a, _, resolver, holder_private = _valid_grant_and_proof(now=1000.0)
    issuer_private, _ = _issuer_and_resolver()
    other_fields = {
        "version": CURRENT_VERSION,
        "issuer": "team-a",
        "subject": encode_public_key(holder_private.public_key()),
        "scope": {"tool": "write_file"},
        "issued_at": 1000.0,
        "expires_at": 1300.0,
    }
    # Sign grant_b with the SAME resolver's pinned issuer key isn't guaranteed here since
    # _issuer_and_resolver() makes a fresh keypair each call -- what matters is the proof
    # itself binds to a specific grant, so use the holder's proof for a DIFFERENT grant B
    # (same holder key, different scope/grant content) against grant A.
    from agent_warrant.grant import sign as _sign

    grant_b = _sign(other_fields, issuer_private)
    proof_for_b = prove(grant_b, holder_private, now=1000.0)

    result = verify(grant_a.encode(), proof_for_b, resolver, now=1000.0)
    assert result.valid is False
    assert "different grant" in result.reason


def test_verify_rejects_stale_possession_proof():
    grant, proof, resolver, _ = _valid_grant_and_proof(now=1000.0)
    result = verify(grant.encode(), proof, resolver, now=1000.0 + 61.0, max_age_seconds=60.0)
    assert result.valid is False
    assert "stale" in result.reason


def test_possession_proof_replay_within_window_at_different_verifier_succeeds():
    # Documented, accepted residual (THREAT_MODEL.md): a captured (grant, proof) pair
    # is replayable at any verifier within max_age_seconds -- same shape as agent-guard's
    # own PoP freshness window. This test asserts the CURRENT, honest behavior rather than
    # hiding it -- it should keep passing unless/until an audience-binding fix lands.
    grant, proof, resolver, _ = _valid_grant_and_proof(now=1000.0)
    first = verify(grant.encode(), proof, resolver, now=1000.0)
    second = verify(grant.encode(), proof, resolver, now=1030.0)
    assert first.valid is True
    assert second.valid is True


def test_sign_rejects_missing_required_field():
    issuer_private, _ = _issuer_and_resolver()
    with pytest.raises(ValueError, match="missing required grant fields"):
        sign({"version": CURRENT_VERSION, "issuer": "team-a"}, issuer_private)
