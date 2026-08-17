from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .exceptions import UnresolvableIssuer
from .https_fetch import DEFAULT_HTTPS_TIMEOUT_SECONDS, https_get

MAX_DID_DOCUMENT_BYTES = 65_536

_DOMAIN_PORT_RE = re.compile(
    r"^(?P<host>[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)"
    r"(?::(?P<port>[0-9]{1,5}))?$"
)
_PATH_SEGMENT_RE = re.compile(r"^[a-zA-Z0-9._-]+$")

_ED25519_VERIFICATION_TYPES = frozenset(
    {
        "Ed25519VerificationKey2020",
        "Ed25519VerificationKey2018",
        "JsonWebKey2020",
        "Multikey",
    }
)
_ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class IssuerResolver(Protocol):
    """Resolves an issuer identifier to the public key that should have
    signed a Grant claiming to come from that issuer. Kept to one method
    deliberately -- a caching wrapper (CachingResolver, not yet built) can
    wrap ANY implementation transparently without widening this interface."""

    def resolve(self, issuer: str) -> Ed25519PublicKey: ...


class PinnedResolver:
    """Performs NO trust verification. Out-of-band key pinning (TOFU) --
    the caller is responsible for how the {issuer_id: public_key} mapping
    was obtained and trusted. Does not, on its own, satisfy "verify without
    pre-established trust" (see docs/DESIGN.md's Q1/B1 discussion) -- a
    did:web-based resolver (DidWebResolver, below) is what actually delivers
    that property. The name is deliberately unglamorous: a reader should not
    mistake this for a real trust-verification mechanism."""

    def __init__(self, known_issuers: dict[str, Ed25519PublicKey]) -> None:
        self._known_issuers = dict(known_issuers)

    def resolve(self, issuer: str) -> Ed25519PublicKey:
        key = self._known_issuers.get(issuer)
        if key is None:
            raise UnresolvableIssuer(f"issuer {issuer!r} is not in the pinned key set")
        return key


class DidWebResolver:
    """Real trust bootstrap via HTTPS + domain ownership, per the did:web
    method spec (https://w3c-ccg.github.io/did-method-web/). `issuer` is a
    did:web method-specific identifier WITHOUT the "did:web:" prefix (this
    resolver IS the did:web method, so the prefix would be redundant) --
    e.g. "example.com" resolves to https://example.com/.well-known/did.json,
    "example.com:agents:team-a" resolves to
    https://example.com/agents/team-a/did.json, and "example.com%3A3000"
    resolves to https://example.com:3000/.well-known/did.json.

    Every failure mode fails closed as UnresolvableIssuer -- DNS/connection
    failure, non-2xx HTTP status, oversized response, malformed JSON, a
    document missing verificationMethod, or a verificationMethod that isn't
    a supported Ed25519 key encoding (publicKeyMultibase/Multikey,
    publicKeyJwk/JsonWebKey2020 OKP+Ed25519, or the legacy
    publicKeyBase58/Ed25519VerificationKey2018 form). The scheme is
    hardcoded to HTTPS (see https_fetch.https_get) so no attacker-controlled
    issuer string can make this resolver speak plaintext HTTP, and redirects
    are never followed, so a compromised host can't downgrade a resolution
    via a 3xx Location header.

    Returns the FIRST verificationMethod entry that decodes to a supported
    Ed25519 key -- does not implement purpose-based selection
    (assertionMethod/authentication references). A document with multiple
    keys for different purposes is out of scope for this version; see
    docs/DESIGN.md.

    No caching: every resolve() call is a fresh HTTPS fetch. A caching
    wrapper can be layered on top of this Protocol implementation without
    widening IssuerResolver -- deliberately not built into this class."""

    def __init__(self, timeout_seconds: float = DEFAULT_HTTPS_TIMEOUT_SECONDS) -> None:
        self._timeout_seconds = timeout_seconds

    def resolve(self, issuer: str) -> Ed25519PublicKey:
        try:
            host, port, path = _parse_did_web_issuer(issuer)
            document = _fetch_did_document(host, port, path, self._timeout_seconds)
            return _extract_ed25519_public_key(document, issuer)
        except (ValueError, TypeError, OSError) as err:
            raise UnresolvableIssuer(f"did:web resolution failed for {issuer!r}: {err}") from err


def _parse_did_web_issuer(issuer: str) -> tuple[str, int | None, str]:
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("did:web issuer identifier must be a non-empty string")
    segments = issuer.split(":")
    domain_segment = _unescape_port_colon(segments[0])
    path_segments = segments[1:]

    match = _DOMAIN_PORT_RE.match(domain_segment)
    if match is None:
        raise ValueError(f"issuer {issuer!r} is not a valid did:web domain[:port]")
    host = match.group("host")
    port = int(match.group("port")) if match.group("port") else None

    for segment in path_segments:
        if not segment or segment in (".", "..") or not _PATH_SEGMENT_RE.match(segment):
            raise ValueError(f"issuer {issuer!r} has an invalid did:web path segment {segment!r}")

    path = "/" + "/".join(path_segments) + "/did.json" if path_segments else "/.well-known/did.json"
    return host, port, path


def _unescape_port_colon(domain_segment: str) -> str:
    if "%" not in domain_segment:
        return domain_segment
    unescaped = domain_segment.replace("%3A", ":").replace("%3a", ":")
    if "%" in unescaped:
        raise ValueError(f"domain segment {domain_segment!r} has an unsupported percent-escape")
    return unescaped


def _fetch_did_document(host: str, port: int | None, path: str, timeout_seconds: float) -> dict[str, Any]:
    body = https_get(host, path, port=port, timeout_seconds=timeout_seconds, max_bytes=MAX_DID_DOCUMENT_BYTES)
    try:
        document = json.loads(body)
    except json.JSONDecodeError as err:
        raise ValueError(f"did:web document is not valid JSON: {err}") from err
    if not isinstance(document, dict):
        raise ValueError("did:web document is not a JSON object")
    return document


def _extract_ed25519_public_key(document: dict[str, Any], issuer: str) -> Ed25519PublicKey:
    methods = document.get("verificationMethod")
    if not isinstance(methods, list) or not methods:
        raise ValueError(f"did:web document for {issuer!r} has no verificationMethod entries")
    for method in methods:
        if not isinstance(method, dict):
            continue
        key = _ed25519_key_from_verification_method(method)
        if key is not None:
            return key
    raise ValueError(f"did:web document for {issuer!r} has no verificationMethod encoding a supported Ed25519 key")


def _ed25519_key_from_verification_method(method: dict[str, Any]) -> Ed25519PublicKey | None:
    if method.get("type") not in _ED25519_VERIFICATION_TYPES:
        return None
    if "publicKeyMultibase" in method:
        return _ed25519_key_from_multibase(method["publicKeyMultibase"])
    if "publicKeyJwk" in method:
        return _ed25519_key_from_jwk(method["publicKeyJwk"])
    if "publicKeyBase58" in method:
        return _ed25519_key_from_base58(method["publicKeyBase58"])
    return None


def _ed25519_key_from_multibase(encoded: Any) -> Ed25519PublicKey | None:
    if not isinstance(encoded, str) or not encoded.startswith("z"):
        return None
    try:
        decoded = _base58_decode(encoded[1:])
    except ValueError:
        return None
    if len(decoded) != len(_ED25519_MULTICODEC_PREFIX) + 32 or not decoded.startswith(_ED25519_MULTICODEC_PREFIX):
        return None
    return _build_ed25519_public_key(decoded[len(_ED25519_MULTICODEC_PREFIX) :])


def _ed25519_key_from_jwk(jwk: Any) -> Ed25519PublicKey | None:
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return None
    x = jwk.get("x")
    if not isinstance(x, str):
        return None
    try:
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32:
        return None
    return _build_ed25519_public_key(raw)


def _ed25519_key_from_base58(encoded: Any) -> Ed25519PublicKey | None:
    if not isinstance(encoded, str):
        return None
    try:
        raw = _base58_decode(encoded)
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    return _build_ed25519_public_key(raw)


def _build_ed25519_public_key(raw: bytes) -> Ed25519PublicKey | None:
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        return None


def _base58_decode(value: str) -> bytes:
    if not value:
        raise ValueError("empty base58 string")
    num = 0
    for char in value:
        digit = _BASE58_ALPHABET.find(char)
        if digit == -1:
            raise ValueError(f"{char!r} is not a valid base58 character")
        num = num * 58 + digit
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeros + body
