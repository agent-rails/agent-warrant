from __future__ import annotations

import json

import pytest

from agent_warrant.exceptions import RevocationSourceUnreachable
from agent_warrant.grant import CURRENT_VERSION, prove, sign, verify
from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.resolver import PinnedResolver
from agent_warrant.revocation import (
    HttpRevocationChecker,
    RevocationList,
    StaticRevocationChecker,
    sign_revocation_list,
)


def _issuer_and_resolver():
    issuer_private = generate_keypair()
    resolver = PinnedResolver({"team-a": issuer_private.public_key()})
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
    return grant, proof, resolver, issuer_private


# --- RevocationList sign / encode / decode ---


def test_sign_revocation_list_roundtrips_through_json_bytes():
    issuer_private, resolver = _issuer_and_resolver()
    revocation_list = sign_revocation_list("team-a", ["binding-a", "binding-b"], issuer_private, issued_at=42.0)
    decoded = RevocationList.from_json_bytes(revocation_list.to_json_bytes())
    assert decoded.issuer == "team-a"
    assert set(decoded.revoked_bindings) == {"binding-a", "binding-b"}
    assert decoded.issued_at == 42.0
    assert decoded.proof == revocation_list.proof


def test_revocation_list_from_json_bytes_rejects_malformed_json():
    with pytest.raises(ValueError, match="malformed"):
        RevocationList.from_json_bytes(b"not json")


def test_revocation_list_from_json_bytes_rejects_missing_fields():
    with pytest.raises(ValueError, match="missing fields"):
        RevocationList.from_json_bytes(json.dumps({"issuer": "team-a"}).encode())


def test_revocation_list_from_json_bytes_rejects_non_list_bindings():
    payload = {"issuer": "team-a", "revoked_bindings": "not-a-list", "issued_at": 1.0, "proof": "x"}
    with pytest.raises(ValueError, match="revoked_bindings"):
        RevocationList.from_json_bytes(json.dumps(payload).encode())


# --- StaticRevocationChecker (in-process, already-fetched list) ---


def test_static_revocation_checker_reports_membership_correctly():
    issuer_private, resolver = _issuer_and_resolver()
    revocation_list = sign_revocation_list("team-a", ["revoked-binding"], issuer_private)
    checker = StaticRevocationChecker(revocation_list, resolver)
    assert checker.is_revoked("revoked-binding") is True
    assert checker.is_revoked("some-other-binding") is False


def test_static_revocation_checker_rejects_tampered_list_at_construction():
    issuer_private, resolver = _issuer_and_resolver()
    revocation_list = sign_revocation_list("team-a", ["revoked-binding"], issuer_private)
    from dataclasses import replace

    tampered = replace(revocation_list, revoked_bindings=(*revocation_list.revoked_bindings, "sneaked-in-binding"))
    with pytest.raises(RevocationSourceUnreachable):
        StaticRevocationChecker(tampered, resolver)


def test_static_revocation_checker_rejects_list_from_unresolvable_issuer():
    issuer_private = generate_keypair()
    empty_resolver = PinnedResolver({})
    revocation_list = sign_revocation_list("team-a", ["revoked-binding"], issuer_private)
    with pytest.raises(RevocationSourceUnreachable):
        StaticRevocationChecker(revocation_list, empty_resolver)


# --- HttpRevocationChecker (mocked fetcher -- no real network calls) ---


class _FixedFetcher:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def fetch(self) -> bytes:
        return self._payload


class _BoomFetcher:
    def fetch(self) -> bytes:
        raise OSError("connection refused")


def test_http_revocation_checker_happy_path():
    issuer_private, resolver = _issuer_and_resolver()
    revocation_list = sign_revocation_list("team-a", ["revoked-binding"], issuer_private)
    checker = HttpRevocationChecker(_FixedFetcher(revocation_list.to_json_bytes()), resolver)
    assert checker.is_revoked("revoked-binding") is True
    assert checker.is_revoked("clean-binding") is False


def test_http_revocation_checker_fails_closed_when_source_unreachable():
    _, resolver = _issuer_and_resolver()
    checker = HttpRevocationChecker(_BoomFetcher(), resolver)
    with pytest.raises(RevocationSourceUnreachable, match="fetch failed"):
        checker.is_revoked("anything")


def test_http_revocation_checker_fails_closed_on_malformed_payload():
    _, resolver = _issuer_and_resolver()
    checker = HttpRevocationChecker(_FixedFetcher(b"not json"), resolver)
    with pytest.raises(RevocationSourceUnreachable, match="malformed"):
        checker.is_revoked("anything")


def test_http_revocation_checker_fails_closed_on_bad_signature():
    issuer_private, resolver = _issuer_and_resolver()
    revocation_list = sign_revocation_list("team-a", ["revoked-binding"], issuer_private)
    from dataclasses import replace

    tampered = replace(revocation_list, revoked_bindings=(*revocation_list.revoked_bindings, "extra"))
    checker = HttpRevocationChecker(_FixedFetcher(tampered.to_json_bytes()), resolver)
    with pytest.raises(RevocationSourceUnreachable):
        checker.is_revoked("anything")


# --- end-to-end: revocation gate wired through verify() ---


def test_verify_accepts_valid_non_revoked_grant_with_revocation_checker_configured():
    grant, proof, resolver, issuer_private = _valid_grant_and_proof()
    revocation_list = sign_revocation_list("team-a", ["some-other-grants-binding"], issuer_private)
    checker = StaticRevocationChecker(revocation_list, resolver)

    result = verify(grant.encode(), proof, resolver, now=1010.0, revocation_checker=checker)
    assert result.valid is True


def test_verify_rejects_revoked_grant():
    grant, proof, resolver, issuer_private = _valid_grant_and_proof()
    revocation_list = sign_revocation_list("team-a", [proof.grant_binding], issuer_private)
    checker = StaticRevocationChecker(revocation_list, resolver)

    result = verify(grant.encode(), proof, resolver, now=1010.0, revocation_checker=checker)
    assert result.valid is False
    assert "revoked" in result.reason


class _AlwaysUnreachableChecker:
    def is_revoked(self, grant_binding: str) -> bool:
        raise RevocationSourceUnreachable("revocation service is down")


def test_verify_fails_closed_when_revocation_source_unreachable():
    grant, proof, resolver, _ = _valid_grant_and_proof()
    result = verify(grant.encode(), proof, resolver, now=1010.0, revocation_checker=_AlwaysUnreachableChecker())
    assert result.valid is False
    assert "revocation status unavailable" in result.reason


def test_verify_without_revocation_checker_ignores_revocation_status():
    # Documents the OPT-IN nature honestly: a Verifier/verify() call that
    # doesn't pass a revocation_checker behaves exactly as before this
    # feature existed -- a "revoked" grant_binding that nothing ever checks
    # is not rejected. Default behavior is genuinely unchanged.
    grant, proof, resolver, issuer_private = _valid_grant_and_proof()
    sign_revocation_list("team-a", [proof.grant_binding], issuer_private)  # published, but never wired in

    result = verify(grant.encode(), proof, resolver, now=1010.0)
    assert result.valid is True
