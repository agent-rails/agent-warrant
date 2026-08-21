from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest

from agent_warrant.exceptions import RevocationSourceUnreachable
from agent_warrant.grant import CURRENT_VERSION, prove, sign, verify
from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.resolver import PinnedResolver
from agent_warrant.revocation import (
    HttpRevocationChecker,
    HttpRevocationListFetcher,
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
    revocation_list = sign_revocation_list(
        "team-a", ["binding-a", "binding-b"], issuer_private, issued_at=42.0, sequence=7, ttl_seconds=100.0
    )
    decoded = RevocationList.from_json_bytes(revocation_list.to_json_bytes())
    assert decoded.version == 1
    assert decoded.issuer == "team-a"
    assert set(decoded.revoked_bindings) == {"binding-a", "binding-b"}
    assert decoded.issued_at == 42.0
    assert decoded.expires_at == 142.0
    assert decoded.sequence == 7
    assert decoded.proof == revocation_list.proof


def test_revocation_list_from_json_bytes_rejects_malformed_json():
    with pytest.raises(ValueError, match="malformed"):
        RevocationList.from_json_bytes(b"not json")


def test_revocation_list_from_json_bytes_rejects_missing_fields():
    with pytest.raises(ValueError, match="missing fields"):
        RevocationList.from_json_bytes(json.dumps({"issuer": "team-a"}).encode())


def test_revocation_list_from_json_bytes_rejects_non_list_bindings():
    payload = {
        "version": 1,
        "issuer": "team-a",
        "revoked_bindings": "not-a-list",
        "issued_at": 1.0,
        "expires_at": 2.0,
        "sequence": 0,
        "proof": "x",
    }
    with pytest.raises(ValueError, match="revoked_bindings"):
        RevocationList.from_json_bytes(json.dumps(payload).encode())


def _full_revocation_payload(**overrides) -> dict:
    payload = {
        "version": 1,
        "issuer": "team-a",
        "revoked_bindings": ["binding-a"],
        "issued_at": 1.0,
        "expires_at": 2.0,
        "sequence": 0,
        "proof": "x",
    }
    payload.update(overrides)
    return payload


def test_revocation_list_from_json_bytes_rejects_unexpected_fields():
    payload = {**_full_revocation_payload(), "surprise": "unsigned-extension"}
    with pytest.raises(ValueError, match="unexpected fields"):
        RevocationList.from_json_bytes(json.dumps(payload).encode())


def test_revocation_list_from_json_bytes_rejects_duplicate_json_keys():
    raw = b'{"version":1,"issuer":"team-a","issuer":"attacker","revoked_bindings":[],'
    raw += b'"issued_at":1.0,"expires_at":2.0,"sequence":0,"proof":"x"}'
    with pytest.raises(ValueError, match="malformed"):
        RevocationList.from_json_bytes(raw)


def test_revocation_list_from_json_bytes_rejects_duplicate_bindings():
    payload = _full_revocation_payload(revoked_bindings=["dup", "dup"])
    with pytest.raises(ValueError, match="duplicates"):
        RevocationList.from_json_bytes(json.dumps(payload).encode())


# --- StaticRevocationChecker (in-process, already-fetched list) ---


def test_static_revocation_checker_reports_membership_correctly():
    issuer_private, resolver = _issuer_and_resolver()
    revocation_list = sign_revocation_list("team-a", ["revoked-binding"], issuer_private)
    checker = StaticRevocationChecker(revocation_list, resolver)
    assert checker.is_revoked("team-a", "revoked-binding") is True
    assert checker.is_revoked("team-a", "some-other-binding") is False


def test_static_revocation_checker_rejects_tampered_list_at_construction():
    issuer_private, resolver = _issuer_and_resolver()
    revocation_list = sign_revocation_list("team-a", ["revoked-binding"], issuer_private)
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
    checker = HttpRevocationChecker(_FixedFetcher(revocation_list.to_json_bytes()), resolver, "team-a")
    assert checker.is_revoked("team-a", "revoked-binding") is True
    assert checker.is_revoked("team-a", "clean-binding") is False


def test_http_revocation_checker_fails_closed_when_source_unreachable():
    _, resolver = _issuer_and_resolver()
    checker = HttpRevocationChecker(_BoomFetcher(), resolver, "team-a")
    with pytest.raises(RevocationSourceUnreachable, match="fetch failed"):
        checker.is_revoked("team-a", "anything")


def test_http_revocation_checker_fails_closed_on_malformed_payload():
    _, resolver = _issuer_and_resolver()
    checker = HttpRevocationChecker(_FixedFetcher(b"not json"), resolver, "team-a")
    with pytest.raises(RevocationSourceUnreachable, match="malformed"):
        checker.is_revoked("team-a", "anything")


def test_http_revocation_checker_fails_closed_on_bad_signature():
    issuer_private, resolver = _issuer_and_resolver()
    revocation_list = sign_revocation_list("team-a", ["revoked-binding"], issuer_private)
    tampered = replace(revocation_list, revoked_bindings=(*revocation_list.revoked_bindings, "extra"))
    checker = HttpRevocationChecker(_FixedFetcher(tampered.to_json_bytes()), resolver, "team-a")
    with pytest.raises(RevocationSourceUnreachable):
        checker.is_revoked("team-a", "anything")


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
    def is_revoked(self, issuer: str, grant_binding: str) -> bool:
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


# --- freshness / rollback: a stale signed list must not suppress revocations ---


def test_static_checker_rejects_expired_list():
    # An OLD signed list (empty, from before a binding was revoked) replayed
    # from a compromised cache must fail closed -- never silently "not revoked".
    issuer_private, resolver = _issuer_and_resolver()
    stale = sign_revocation_list("team-a", [], issuer_private, issued_at=1.0, ttl_seconds=10.0)
    with pytest.raises(RevocationSourceUnreachable, match="expired"):
        StaticRevocationChecker(stale, resolver)


def test_http_checker_rejects_expired_list():
    issuer_private, resolver = _issuer_and_resolver()
    stale = sign_revocation_list("team-a", [], issuer_private, issued_at=1.0, ttl_seconds=10.0)
    checker = HttpRevocationChecker(_FixedFetcher(stale.to_json_bytes()), resolver, "team-a")
    with pytest.raises(RevocationSourceUnreachable, match="expired"):
        checker.is_revoked("team-a", "anything")


def test_http_checker_rejects_future_dated_list():
    issuer_private, resolver = _issuer_and_resolver()
    future = sign_revocation_list("team-a", [], issuer_private, issued_at=time.time() + 10_000.0)
    checker = HttpRevocationChecker(_FixedFetcher(future.to_json_bytes()), resolver, "team-a")
    with pytest.raises(RevocationSourceUnreachable, match="not yet valid"):
        checker.is_revoked("team-a", "anything")


def test_http_checker_rejects_sequence_rollback():
    # A newer list (sequence 5) accepted first; a replayed older list
    # (sequence 3) must be rejected as a rollback, not trusted.
    issuer_private, resolver = _issuer_and_resolver()
    newer = sign_revocation_list("team-a", ["b"], issuer_private, sequence=5)
    older = sign_revocation_list("team-a", [], issuer_private, sequence=3)

    class _SwappableFetcher:
        def __init__(self) -> None:
            self.payload = newer.to_json_bytes()

        def fetch(self) -> bytes:
            return self.payload

    fetcher = _SwappableFetcher()
    checker = HttpRevocationChecker(fetcher, resolver, "team-a")
    assert checker.is_revoked("team-a", "b") is True
    fetcher.payload = older.to_json_bytes()
    with pytest.raises(RevocationSourceUnreachable, match="rolled back"):
        checker.is_revoked("team-a", "b")


# --- issuer binding: issuer B's list must not vouch for issuer A's grant ---


def test_static_checker_rejects_grant_from_other_issuer():
    issuer_b_private = generate_keypair()
    resolver = PinnedResolver({"issuer-b": issuer_b_private.public_key()})
    empty_list_b = sign_revocation_list("issuer-b", [], issuer_b_private)
    checker = StaticRevocationChecker(empty_list_b, resolver)
    with pytest.raises(RevocationSourceUnreachable, match="different issuer"):
        checker.is_revoked("issuer-a", "some-binding")


def test_http_checker_rejects_list_signed_by_wrong_issuer():
    # A checker bound to issuer-a is handed a list authentically signed by
    # issuer-b. Even though the signature is valid, the issuer binding fails.
    issuer_a_private = generate_keypair()
    issuer_b_private = generate_keypair()
    resolver = PinnedResolver({"issuer-a": issuer_a_private.public_key(), "issuer-b": issuer_b_private.public_key()})
    list_b = sign_revocation_list("issuer-b", [], issuer_b_private)
    checker = HttpRevocationChecker(_FixedFetcher(list_b.to_json_bytes()), resolver, "issuer-a")
    with pytest.raises(RevocationSourceUnreachable, match="does not match"):
        checker.is_revoked("issuer-a", "some-binding")


def test_version_mismatch_fails_closed():
    issuer_private, resolver = _issuer_and_resolver()
    good = sign_revocation_list("team-a", ["b"], issuer_private)
    wrong_version = replace(good, version=99)
    checker = HttpRevocationChecker(_FixedFetcher(wrong_version.to_json_bytes()), resolver, "team-a")
    with pytest.raises(RevocationSourceUnreachable, match="version"):
        checker.is_revoked("team-a", "b")


# --- HttpRevocationListFetcher URL validation (finding: loose URL parsing) ---


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://user:pass@example.com/list.json",
        "https://example.com/list.json#frag",
        "https://example.com:0/list.json",
        "https://example.com//evil/list.json",
        "http://example.com/list.json",
        "ftp://example.com/list.json",
    ],
)
def test_http_revocation_list_fetcher_rejects_malformed_urls(bad_url):
    with pytest.raises(ValueError):
        HttpRevocationListFetcher(bad_url)


def test_http_revocation_list_fetcher_accepts_well_formed_url():
    fetcher = HttpRevocationListFetcher("https://example.com/revocations/team-a.json?v=2")
    assert fetcher._host == "example.com"
    assert fetcher._path == "/revocations/team-a.json?v=2"
