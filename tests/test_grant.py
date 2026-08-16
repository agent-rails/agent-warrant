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


def test_issuer_rejects_ttl_above_revocation_free_limit():
    from agent_warrant.issuer import MAX_TTL_SECONDS, Issuer

    issuer = Issuer(issuer_id="team-a", private_key=generate_keypair())
    holder_private = generate_keypair()
    subject = encode_public_key(holder_private.public_key())

    with pytest.raises(ValueError, match="no revocation"):
        issuer.issue(subject, {"tool": "read_file"}, ttl_seconds=MAX_TTL_SECONDS + 1)


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


def test_verify_rejects_boolean_version():
    from agent_warrant.canonical import canonicalize
    from agent_warrant.grant import _b64u

    grant, proof, resolver, _ = _valid_grant_and_proof()
    tampered = replace(grant, version=True)
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


def test_verify_uses_same_possession_proof_fields_for_all_trust_decisions():
    from agent_warrant.grant import PossessionProof

    issuer_private, resolver = _issuer_and_resolver()
    holder_private = generate_keypair()
    fields = {
        "version": CURRENT_VERSION,
        "issuer": "team-a",
        "subject": encode_public_key(holder_private.public_key()),
        "scope": {"tool": "read_file"},
        "issued_at": 0.0,
        "expires_at": 10_000.0,
    }
    grant = sign(fields, issuer_private)
    old_proof = prove(grant, holder_private, now=100.0)

    class DecoupledProof(PossessionProof):
        def _signable_fields(self):
            return {
                "grant_binding": old_proof.grant_binding,
                "iat": old_proof.iat,
            }

    deceptive_proof = DecoupledProof(
        grant_binding=old_proof.grant_binding,
        iat=9_000.0,
        signature=old_proof.signature,
    )
    result = verify(grant.encode(), deceptive_proof, resolver, now=9_000.0)
    assert result.valid is False
    assert "stale" in result.reason


def test_verify_rejects_stale_possession_proof():
    grant, proof, resolver, _ = _valid_grant_and_proof(now=1000.0)
    result = verify(grant.encode(), proof, resolver, now=1000.0 + 61.0, max_age_seconds=60.0)
    assert result.valid is False
    assert "stale" in result.reason


def test_verify_rejects_proof_postdated_beyond_clock_skew_allowance():
    from agent_warrant.grant import POSSESSION_PROOF_CLOCK_SKEW_SECONDS

    grant, _, resolver, holder_private = _valid_grant_and_proof(now=1000.0)
    proof = prove(grant, holder_private, now=1000.0 + POSSESSION_PROOF_CLOCK_SKEW_SECONDS + 1.0)
    result = verify(grant.encode(), proof, resolver, now=1000.0)
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


def test_verify_never_raises_on_deeply_nested_json():
    # Reproduces the live-found gap exactly: a deeply-nested JSON body reaches
    # json.loads' recursion limit and raises RecursionError, uncaught -- falsifying
    # verify()'s own never-raises contract. Two independent defenses close this (the
    # size cap AND the RecursionError catch in decode()) -- this test proves the
    # overall contract holds, see the two isolated tests below for each mechanism.
    grant, proof, resolver, _ = _valid_grant_and_proof()
    huge_body = "[" * 200_000 + "]" * 200_000
    oversized_encoded = huge_body + "." + grant.proof

    result = verify(oversized_encoded, proof, resolver, now=1000.0)
    assert result.valid is False


def test_decode_rejects_oversized_flat_payload_isolating_size_cap():
    # Isolates the size cap specifically: a large but FLAT payload (no deep nesting)
    # cannot trigger RecursionError on its own, so this only fails closed if the size
    # cap itself is doing the rejecting -- mutation-tested to confirm removing the
    # size cap (independent of the RecursionError catch) turns this red.
    import base64
    import json as _json

    from agent_warrant.grant import MAX_ENCODED_GRANT_BYTES, Grant

    # A genuinely valid, parseable, FLAT (non-nested) body -- large only in byte count,
    # so a RecursionError could never fire for it. If this is rejected, it can only be
    # the size cap doing the rejecting, not the RecursionError defense-in-depth layer.
    big_flat_body = {"padding": "x" * (MAX_ENCODED_GRANT_BYTES * 2)}
    body_b64 = base64.urlsafe_b64encode(_json.dumps(big_flat_body).encode()).rstrip(b"=").decode()
    with pytest.raises(ValueError, match="exceeds"):
        Grant.decode(body_b64 + "." + "fakeproof")


def test_decode_translates_recursion_error_to_value_error_isolating_that_catch(monkeypatch):
    # Isolates the RecursionError-catch defense-in-depth layer specifically. A payload
    # under the size cap that's ALSO deep enough to recurse doesn't exist in practice
    # (the cap bounds nesting depth tightly enough to prevent it in this environment),
    # so this proves the translation code path exists and works by simulating the
    # failure directly, rather than only relying on the size cap to prevent reaching it.
    import json as _json

    from agent_warrant.grant import Grant

    def _boom(*_a, **_kw):
        raise RecursionError("simulated")

    monkeypatch.setattr(_json, "loads", _boom)
    with pytest.raises(ValueError, match="nesting too deep"):
        Grant.decode("AA==.fakeproof")


def test_verify_rejects_non_numeric_issued_at_not_raises():
    # Symmetric regression for the asymmetry found by review: the iat guard existed,
    # this one didn't. A validly-signed grant (the issuer signature covers whatever
    # value issued_at holds, numeric or not) with a non-numeric issued_at must still
    # fail closed, not raise TypeError out of the expiry comparison.
    issuer_private, resolver = _issuer_and_resolver()
    holder_private = generate_keypair()
    fields = {
        "version": CURRENT_VERSION,
        "issuer": "team-a",
        "subject": encode_public_key(holder_private.public_key()),
        "scope": {"tool": "read_file"},
        "issued_at": "not-a-number",
        "expires_at": 2000.0,
    }
    grant = sign(fields, issuer_private)
    proof = prove(grant, holder_private, now=1000.0)

    result = verify(grant.encode(), proof, resolver, now=1000.0)
    assert result.valid is False
    assert "issued_at" in result.reason


def test_verify_rejects_non_numeric_expires_at_not_raises():
    issuer_private, resolver = _issuer_and_resolver()
    holder_private = generate_keypair()
    fields = {
        "version": CURRENT_VERSION,
        "issuer": "team-a",
        "subject": encode_public_key(holder_private.public_key()),
        "scope": {"tool": "read_file"},
        "issued_at": 1000.0,
        "expires_at": None,
    }
    grant = sign(fields, issuer_private)
    proof = prove(grant, holder_private, now=1000.0)

    result = verify(grant.encode(), proof, resolver, now=1000.0)
    assert result.valid is False
    assert "expires_at" in result.reason


def test_verify_rejects_unhashable_issuer_not_raises():
    # Reproduces the live-found gap: an unauthenticated grant (no valid signature
    # needed -- this happens before the signature check) with an unhashable JSON
    # issuer (a list or dict) made a dict-based resolver's .get() raise TypeError,
    # uncaught. Reachable with a 185-byte unsigned payload -- doesn't need a real
    # issuer/holder keypair at all, only a version that passes the gate.
    import base64
    import json as _json

    from agent_warrant.grant import CURRENT_VERSION, PossessionProof, verify
    from agent_warrant.resolver import PinnedResolver

    resolver = PinnedResolver({})
    dummy_proof = PossessionProof(grant_binding="x", iat=1000.0, signature="y")

    for bad_issuer in ([], {}, 123, None, True):
        body = {
            "version": CURRENT_VERSION,
            "issuer": bad_issuer,
            "subject": "irrelevant",
            "scope": {},
            "issued_at": 0.0,
            "expires_at": 2000.0,
        }
        body_b64 = base64.urlsafe_b64encode(_json.dumps(body).encode()).rstrip(b"=").decode()
        encoded = f"{body_b64}.fakeproof"

        result = verify(encoded, dummy_proof, resolver, now=1000.0)
        assert result.valid is False


def test_verify_rejects_deeply_nested_scope_not_raises():
    # Live-found gap: canonicalize()'s own pure-Python recursion (not json.loads', which
    # decode()'s size cap/RecursionError catch already guard) trips at a MUCH smaller
    # payload than the 16KB encoded-grant cap allows. This scope is sub-16KB and is
    # reachable pre-authentication, at the issuer-signature-verification input (not
    # "before any signature is checked" as an earlier draft of this comment claimed --
    # imprecise; it fires AT that check, first-argument-permitting).
    #
    # CORRECTED after a fourth review pass found this test was VACUOUS: the original
    # proof string "fakeproof" is not valid base64 (9 chars, invalid length), so
    # _b64u_decode(grant.proof) -- the FIRST argument evaluated in
    # issuer_key.verify(_b64u_decode(grant.proof), canonicalize(...)) -- raised
    # binascii.Error before canonicalize() on the nested scope was ever reached. The
    # test passed, but for the wrong reason, and would not have caught a regression in
    # the depth guard. A prior commit misdiagnosed this as a "pytest execution-context /
    # test-harness artifact" -- it wasn't; it's plain left-to-right argument-evaluation
    # order, reproduced identically inside and outside pytest. Fixed by using a
    # base64-VALID garbage proof ("AAAA") so _b64u_decode succeeds and execution
    # actually reaches canonicalize(grant._signable_fields()).
    import base64
    import json as _json

    from agent_warrant.grant import CURRENT_VERSION, PossessionProof, verify
    from agent_warrant.identity import generate_keypair
    from agent_warrant.resolver import PinnedResolver

    resolver = PinnedResolver({"team-a": generate_keypair().public_key()})
    dummy_proof = PossessionProof(grant_binding="x", iat=1000.0, signature="y")

    # List-based nesting (lower JSON overhead per level than dict-chain nesting), so this
    # reaches Python's default recursion limit (~1000) while staying well under
    # MAX_ENCODED_GRANT_BYTES (16KB) -- must be sub-cap to prove the gap is
    # canonicalize()'s own recursion, not json.loads' (already guarded by the cap).
    # Mutation-tested: a dict-chain version at a shallower depth did NOT reliably trigger
    # Python's natural RecursionError once the explicit guard was removed, giving a false
    # sense of coverage -- this shape does.
    deeply_nested_list = []
    cursor = deeply_nested_list
    for _ in range(3000):
        cursor.append([])
        cursor = cursor[0]

    body = {
        "version": CURRENT_VERSION,
        "issuer": "team-a",
        "subject": "irrelevant",
        "scope": {"items": deeply_nested_list},
        "issued_at": 0.0,
        "expires_at": 2000.0,
    }
    body_b64 = base64.urlsafe_b64encode(_json.dumps(body).encode()).rstrip(b"=").decode()
    encoded = f"{body_b64}.AAAA"  # base64-valid garbage proof, NOT "fakeproof" -- see comment above
    assert len(encoded) < 16_384

    result = verify(encoded, dummy_proof, resolver, now=1000.0)
    assert result.valid is False


def test_verify_rejects_deeply_nested_grant_binding_not_raises():
    # Second reachable path for the same gap: a validly-signed grant (so execution reaches
    # the possession-proof signature check) presented with a possession proof whose
    # grant_binding is deeply nested. Deliberately NOT constructed via prove() -- signing a
    # deeply-nested body is now architecturally impossible through this library's own
    # canonicalize()-based signer (confirmed live: prove() itself raises ValueError on nested
    # input), which is the correct, more thorough outcome -- but a real attacker isn't
    # required to use this library's signer at all, so verify() must still fail closed
    # against a hand-built PossessionProof carrying an arbitrary (garbage-signed) nested
    # grant_binding, not just against proofs this library would agree to construct.
    from agent_warrant.grant import PossessionProof

    grant, _, resolver, _ = _valid_grant_and_proof()

    deeply_nested_binding = []
    cursor = deeply_nested_binding
    for _ in range(3000):
        cursor.append([])
        cursor = cursor[0]

    bad_proof = PossessionProof(grant_binding=deeply_nested_binding, iat=1000.0, signature="garbage")
    result = verify(grant.encode(), bad_proof, resolver, now=1000.0)
    assert result.valid is False


def test_sign_rejects_missing_required_field():
    issuer_private, _ = _issuer_and_resolver()
    with pytest.raises(ValueError, match="missing required grant fields"):
        sign({"version": CURRENT_VERSION, "issuer": "team-a"}, issuer_private)
