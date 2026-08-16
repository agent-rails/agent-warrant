from __future__ import annotations

from agent_warrant import HolderKeypair, Issuer, PinnedResolver, Verifier, encode_public_key, generate_keypair, prove


def test_cross_org_grant_verified_with_no_shared_secret():
    # Team A: mints a grant for a holder it doesn't need to share any secret with.
    team_a_private = generate_keypair()
    issuer = Issuer(issuer_id="team-a", private_key=team_a_private, default_ttl_seconds=300.0)

    holder_private = generate_keypair()
    holder = HolderKeypair(holder_private)
    holder_public_b64 = encode_public_key(holder_private.public_key())

    # path_prefix is illustrative application data; the library authenticates
    # the scope but does not interpret or enforce it for authorization.
    grant = issuer.issue(subject=holder_public_b64, scope={"tool": "read_file", "path_prefix": "/reports/"})
    proof = holder.prove_possession(grant)

    # Team B: only ever obtains team A's PUBLIC key (out-of-band), never a shared secret.
    resolver = PinnedResolver({"team-a": team_a_private.public_key()})
    verifier = Verifier(resolver)

    result = verifier.check(grant.encode(), proof)
    assert result.valid is True
    assert result.grant.scope == {"tool": "read_file", "path_prefix": "/reports/"}


def test_stolen_grant_without_possession_proof_is_rejected():
    """The single most important test in the suite: a captured encoded_grant
    ALONE is not enough to be verified -- the whole point of holder-binding."""
    team_a_private = generate_keypair()
    issuer = Issuer(issuer_id="team-a", private_key=team_a_private)

    real_holder_private = generate_keypair()
    real_holder_public_b64 = encode_public_key(real_holder_private.public_key())
    grant = issuer.issue(subject=real_holder_public_b64, scope={"tool": "read_file"})

    resolver = PinnedResolver({"team-a": team_a_private.public_key()})
    verifier = Verifier(resolver)

    # Attacker intercepts the encoded grant on the wire but does NOT have the real
    # holder's private key -- they can only forge a proof with a DIFFERENT keypair.
    attacker_private = generate_keypair()
    forged_proof = prove(grant, attacker_private)

    result = verifier.check(grant.encode(), forged_proof)
    assert result.valid is False
    assert "possession proof" in result.reason.lower() or "signature" in result.reason.lower()
