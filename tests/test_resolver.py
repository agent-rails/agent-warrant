from __future__ import annotations

import base64
import json

import pytest

from agent_warrant.exceptions import UnresolvableIssuer
from agent_warrant.identity import generate_keypair
from agent_warrant.resolver import DidWebResolver, PinnedResolver, _parse_did_web_issuer

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    # Test-fixture-only encoder (inverse of resolver.py's production-only
    # decoder -- resolve() never needs to CONSTRUCT a multibase key, only
    # parse one, so no encoder exists in production code).
    num = int.from_bytes(data, "big")
    digits = []
    while num > 0:
        num, remainder = divmod(num, 58)
        digits.append(_BASE58_ALPHABET[remainder])
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + "".join(reversed(digits))


def _multibase_key(raw_public_key: bytes) -> str:
    prefix = bytes([0xED, 0x01])
    return "z" + _base58_encode(prefix + raw_public_key)


def _did_document(verification_methods: list[dict]) -> bytes:
    return json.dumps({"id": "did:web:example.com", "verificationMethod": verification_methods}).encode()


def test_pinned_resolver_resolves_known_issuer():
    key = generate_keypair().public_key()
    resolver = PinnedResolver({"team-a": key})
    assert resolver.resolve("team-a") is key


def test_pinned_resolver_raises_on_unknown_issuer():
    resolver = PinnedResolver({})
    with pytest.raises(UnresolvableIssuer):
        resolver.resolve("team-a")


# --- did:web URL construction (pure function, no network) ---


def test_parse_did_web_issuer_domain_only():
    host, port, path = _parse_did_web_issuer("example.com")
    assert (host, port, path) == ("example.com", None, "/.well-known/did.json")


def test_parse_did_web_issuer_with_path_segments():
    host, port, path = _parse_did_web_issuer("example.com:agents:team-a")
    assert (host, port, path) == ("example.com", None, "/agents/team-a/did.json")


def test_parse_did_web_issuer_with_encoded_port():
    host, port, path = _parse_did_web_issuer("example.com%3A3000")
    assert (host, port, path) == ("example.com", 3000, "/.well-known/did.json")


def test_parse_did_web_issuer_with_lowercase_encoded_port():
    host, port, path = _parse_did_web_issuer("example.com%3a8443:agents:team-a")
    assert (host, port, path) == ("example.com", 8443, "/agents/team-a/did.json")


@pytest.mark.parametrize(
    "bad_issuer",
    [
        "",
        "not a domain",
        "example.com:..:team-a",
        "example.com:.:team-a",
        "example.com:/etc/passwd",
        "example.com%2F..%2F..",
        "-example.com",
        "example.com:agents:",
        "http://example.com",
    ],
)
def test_parse_did_web_issuer_rejects_malformed_identifiers(bad_issuer):
    with pytest.raises(ValueError):
        _parse_did_web_issuer(bad_issuer)


# --- DidWebResolver.resolve() (mocked HTTP layer -- no real network calls) ---


def test_did_web_resolver_happy_path_multibase(monkeypatch):
    private_key = generate_keypair()
    raw_public = private_key.public_key().public_bytes_raw()
    document = _did_document(
        [
            {
                "id": "did:web:example.com#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": _multibase_key(raw_public),
            }
        ]
    )
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)

    resolver = DidWebResolver()
    resolved = resolver.resolve("example.com")
    assert resolved.public_bytes_raw() == raw_public


def test_did_web_resolver_happy_path_jwk(monkeypatch):
    private_key = generate_keypair()
    raw_public = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode()
    document = _did_document(
        [
            {
                "id": "did:web:example.com#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:web:example.com",
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
            }
        ]
    )
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)

    resolver = DidWebResolver()
    resolved = resolver.resolve("example.com")
    assert resolved.public_bytes_raw() == raw_public


def test_did_web_resolver_happy_path_legacy_base58(monkeypatch):
    private_key = generate_keypair()
    raw_public = private_key.public_key().public_bytes_raw()
    document = _did_document(
        [
            {
                "id": "did:web:example.com#key-1",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:web:example.com",
                "publicKeyBase58": _base58_encode(raw_public),
            }
        ]
    )
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)

    resolver = DidWebResolver()
    resolved = resolver.resolve("example.com")
    assert resolved.public_bytes_raw() == raw_public


def test_did_web_resolver_uses_first_matching_method_and_passes_correct_url(monkeypatch):
    private_key = generate_keypair()
    raw_public = private_key.public_key().public_bytes_raw()
    document = _did_document(
        [
            {
                "id": "did:web:example.com:agents:team-a#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com:agents:team-a",
                "publicKeyMultibase": _multibase_key(raw_public),
            }
        ]
    )
    captured = {}

    def _fake_https_get(host, path, **kwargs):
        captured["host"] = host
        captured["path"] = path
        return document

    monkeypatch.setattr("agent_warrant.resolver.https_get", _fake_https_get)
    resolver = DidWebResolver()
    resolver.resolve("example.com:agents:team-a")
    assert captured == {"host": "example.com", "path": "/agents/team-a/did.json"}


def test_did_web_resolver_fails_closed_on_malformed_issuer():
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer):
        resolver.resolve("not a domain")


def test_did_web_resolver_fails_closed_on_fetch_failure(monkeypatch):
    def _boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr("agent_warrant.resolver.https_get", _boom)
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer, match="connection refused"):
        resolver.resolve("example.com")


def test_did_web_resolver_fails_closed_on_non_json_body(monkeypatch):
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: b"not json at all")
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer):
        resolver.resolve("example.com")


def test_did_web_resolver_fails_closed_on_non_object_body(monkeypatch):
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: b"[1, 2, 3]")
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer):
        resolver.resolve("example.com")


def test_did_web_resolver_fails_closed_on_missing_verification_method(monkeypatch):
    document = json.dumps({"id": "did:web:example.com"}).encode()
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer, match="no verificationMethod"):
        resolver.resolve("example.com")


def test_did_web_resolver_fails_closed_on_empty_verification_method(monkeypatch):
    document = _did_document([])
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer):
        resolver.resolve("example.com")


def test_did_web_resolver_fails_closed_on_key_type_mismatch(monkeypatch):
    document = _did_document(
        [
            {
                "id": "did:web:example.com#key-1",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": "did:web:example.com",
                "publicKeyJwk": {"kty": "EC", "crv": "secp256k1", "x": "abcd"},
            }
        ]
    )
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer, match="no verificationMethod encoding"):
        resolver.resolve("example.com")


def test_did_web_resolver_fails_closed_on_wrong_curve_jwk(monkeypatch):
    document = _did_document(
        [
            {
                "id": "did:web:example.com#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:web:example.com",
                "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": "abcd"},
            }
        ]
    )
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer):
        resolver.resolve("example.com")


def test_did_web_resolver_fails_closed_on_malformed_multibase(monkeypatch):
    document = _did_document(
        [
            {
                "id": "did:web:example.com#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "not-base58-and-no-z-prefix",
            }
        ]
    )
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer):
        resolver.resolve("example.com")


def test_did_web_resolver_fails_closed_on_wrong_multicodec_prefix(monkeypatch):
    # Valid base58, valid length, WRONG multicodec prefix (e.g. secp256k1-pub
    # 0xe7 instead of ed25519-pub 0xed01) -- must still be rejected, not
    # silently treated as an Ed25519 key.
    wrong_prefix_key = bytes([0xE7, 0x01]) + b"\x01" * 32
    document = _did_document(
        [
            {
                "id": "did:web:example.com#key-1",
                "type": "Multikey",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "z" + _base58_encode(wrong_prefix_key),
            }
        ]
    )
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)
    resolver = DidWebResolver()
    with pytest.raises(UnresolvableIssuer):
        resolver.resolve("example.com")


def test_did_web_resolver_skips_non_matching_and_finds_valid_entry(monkeypatch):
    private_key = generate_keypair()
    raw_public = private_key.public_key().public_bytes_raw()
    document = _did_document(
        [
            {
                "id": "did:web:example.com#key-0",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": "did:web:example.com",
                "publicKeyJwk": {"kty": "EC", "crv": "secp256k1", "x": "abcd"},
            },
            {
                "id": "did:web:example.com#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": _multibase_key(raw_public),
            },
        ]
    )
    monkeypatch.setattr("agent_warrant.resolver.https_get", lambda *a, **k: document)
    resolver = DidWebResolver()
    resolved = resolver.resolve("example.com")
    assert resolved.public_bytes_raw() == raw_public
