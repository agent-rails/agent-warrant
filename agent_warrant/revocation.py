from __future__ import annotations

import base64
import binascii
import http.client
import json
import math
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize
from .exceptions import RevocationSourceUnreachable, UnresolvableIssuer
from .https_fetch import DEFAULT_HTTPS_TIMEOUT_SECONDS, https_get
from .resolver import IssuerResolver

MAX_REVOCATION_LIST_BYTES = 262_144
CURRENT_REVOCATION_VERSION = 1
DEFAULT_REVOCATION_TTL_SECONDS = 3_600.0
# A signed revocation list is only accepted if issued_at is not in the future
# beyond this skew and expires_at has not passed. Bounds clock disagreement
# between issuer and verifier without opening a meaningful replay window.
REVOCATION_CLOCK_SKEW_SECONDS = 60.0
_SIGNABLE_REVOCATION_FIELDS = ("version", "issuer", "revoked_bindings", "issued_at", "expires_at", "sequence")
_ALLOWED_REVOCATION_KEYS = frozenset({*_SIGNABLE_REVOCATION_FIELDS, "proof"})


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key {key!r} in revocation list")
        seen[key] = value
    return seen


@dataclass(frozen=True)
class RevocationList:
    """Issuer-signed set of revoked `grant_binding` values -- see
    grant.py's PossessionProof.grant_binding and docs/THREAT_MODEL.md's
    explicit guidance that grant_binding, not the raw encoded grant string,
    is this project's stable identity for a specific Grant. Signed the same
    way as a Grant -- canonicalize() + the issuer's existing Ed25519 key --
    so revocation checking introduces NO new trust root or shared secret.

    Carries freshness and anti-rollback metadata that IS part of the signed
    body: `issued_at`, `expires_at`, and a monotonic `sequence`. A verifier
    rejects a list whose `expires_at` has passed or whose `sequence` is lower
    than one it has already accepted for this issuer -- so a stale signed list
    (e.g. an old empty one replayed from a compromised CDN/cache/backup)
    cannot silently suppress later revocations. `version` is a signed format
    discriminator.

    Deliberately NOT a StatusList2021/Bitstring Status List: that spec's
    bitstring-bundling design exists to hide which specific entry an
    anonymous verifier is checking, among a public, million-entry-scale
    population. agent-warrant's actual shape is a known, pre-arranged
    cross-org relationship with a small, bounded verifier population per
    issuer -- the anonymity-set machinery StatusList2021 needs isn't earned
    here. See docs/DESIGN.md."""

    version: int
    issuer: str
    revoked_bindings: tuple[str, ...]
    issued_at: float
    expires_at: float
    sequence: int
    proof: str

    def _signable_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "issuer": self.issuer,
            "revoked_bindings": sorted(self.revoked_bindings),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "sequence": self.sequence,
        }

    def to_json_bytes(self) -> bytes:
        payload = {**self._signable_fields(), "proof": self.proof}
        return json.dumps(payload).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> RevocationList:
        try:
            payload = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, ValueError) as err:
            raise ValueError("malformed revocation list") from err
        if not isinstance(payload, dict):
            raise ValueError("malformed revocation list: body is not a JSON object")

        unexpected = payload.keys() - _ALLOWED_REVOCATION_KEYS
        if unexpected:
            raise ValueError(f"malformed revocation list: unexpected fields {sorted(unexpected)}")
        missing = _ALLOWED_REVOCATION_KEYS - payload.keys()
        if missing:
            raise ValueError(f"malformed revocation list: missing fields {sorted(missing)}")

        version = payload["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError("malformed revocation list: version is not an integer")

        issuer = payload["issuer"]
        if not isinstance(issuer, str):
            raise ValueError("malformed revocation list: issuer is not a string")

        bindings = payload["revoked_bindings"]
        if not isinstance(bindings, list) or not all(isinstance(binding, str) for binding in bindings):
            raise ValueError("malformed revocation list: revoked_bindings is not a list of strings")
        if len(bindings) != len(set(bindings)):
            raise ValueError("malformed revocation list: revoked_bindings has duplicates")

        issued_at = _finite_number(payload["issued_at"], "issued_at")
        expires_at = _finite_number(payload["expires_at"], "expires_at")

        sequence = payload["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ValueError("malformed revocation list: sequence is not a non-negative integer")

        proof = payload["proof"]
        if not isinstance(proof, str):
            raise ValueError("malformed revocation list: proof is not a string")

        return cls(
            version=version,
            issuer=issuer,
            revoked_bindings=tuple(bindings),
            issued_at=issued_at,
            expires_at=expires_at,
            sequence=sequence,
            proof=proof,
        )


def _finite_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"malformed revocation list: {field_name} is not a finite number")
    return value


def sign_revocation_list(
    issuer: str,
    revoked_bindings: list[str] | tuple[str, ...] | frozenset[str],
    private_key: Ed25519PrivateKey,
    issued_at: float | None = None,
    sequence: int = 0,
    ttl_seconds: float = DEFAULT_REVOCATION_TTL_SECONDS,
) -> RevocationList:
    ts = issued_at if issued_at is not None else time.time()
    expires_at = ts + ttl_seconds
    bindings = tuple(sorted(set(revoked_bindings)))
    signable = {
        "version": CURRENT_REVOCATION_VERSION,
        "issuer": issuer,
        "revoked_bindings": list(bindings),
        "issued_at": ts,
        "expires_at": expires_at,
        "sequence": sequence,
    }
    signature = private_key.sign(canonicalize(signable))
    return RevocationList(
        version=CURRENT_REVOCATION_VERSION,
        issuer=issuer,
        revoked_bindings=bindings,
        issued_at=ts,
        expires_at=expires_at,
        sequence=sequence,
        proof=_b64u(signature),
    )


def _verify_revocation_list(
    revocation_list: RevocationList,
    resolver: IssuerResolver,
    expected_issuer: str,
    now: float,
) -> None:
    """Authenticate a fetched/supplied list and confirm it is fresh and bound
    to the expected issuer. Every failure fails closed as
    RevocationSourceUnreachable -- never a silent 'not revoked'."""
    if revocation_list.version != CURRENT_REVOCATION_VERSION:
        raise RevocationSourceUnreachable("unsupported revocation list version")
    # Bind status to the grant's own authenticated issuer: a different issuer's
    # authentic (possibly empty) list must not vouch for this issuer's grant.
    if revocation_list.issuer != expected_issuer:
        raise RevocationSourceUnreachable("revocation list issuer does not match the grant issuer")
    try:
        issuer_key = resolver.resolve(revocation_list.issuer)
    except UnresolvableIssuer as err:
        raise RevocationSourceUnreachable("cannot resolve issuer for revocation list") from err
    try:
        issuer_key.verify(_b64u_decode(revocation_list.proof), canonicalize(revocation_list._signable_fields()))
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as err:
        raise RevocationSourceUnreachable("revocation list signature is invalid") from err
    if revocation_list.issued_at > now + REVOCATION_CLOCK_SKEW_SECONDS:
        raise RevocationSourceUnreachable("revocation list is not yet valid")
    if revocation_list.expires_at < now:
        raise RevocationSourceUnreachable("revocation list has expired (possible rollback/replay)")


class RevocationChecker(Protocol):
    """Checked as the final gate in verify(), only once a Grant has already
    passed every other check. `issuer` is the grant's ALREADY-AUTHENTICATED
    issuer (its signature verified), passed so the checker can bind revocation
    status to that specific issuer. MUST raise RevocationSourceUnreachable,
    never return a silent 'not revoked' guess, when revocation status can't be
    determined -- verify() treats that exception as fail-closed."""

    def is_revoked(self, issuer: str, grant_binding: str) -> bool: ...


class StaticRevocationChecker:
    """Wraps an already-fetched RevocationList. Verifies the list's signature,
    issuer binding, and freshness at construction time against `resolver` --
    the SAME IssuerResolver already used for grant verification, so this
    introduces no new trust root. A tampered, wrongly-signed, expired, or
    wrong-issuer list is rejected at construction, not silently trusted. The
    checker is bound to the list's issuer: an is_revoked() call whose grant
    issuer differs fails closed."""

    def __init__(
        self,
        revocation_list: RevocationList,
        resolver: IssuerResolver,
        now: float | None = None,
    ) -> None:
        checked_at = now if now is not None else time.time()
        self._expected_issuer = revocation_list.issuer
        _verify_revocation_list(revocation_list, resolver, self._expected_issuer, checked_at)
        self._sequence = revocation_list.sequence
        self._revoked = frozenset(revocation_list.revoked_bindings)

    def is_revoked(self, issuer: str, grant_binding: str) -> bool:
        if issuer != self._expected_issuer:
            raise RevocationSourceUnreachable("revocation checker is bound to a different issuer")
        return grant_binding in self._revoked


class RevocationListFetcher(Protocol):
    """Kept to one method, same minimalism as IssuerResolver -- any
    transport (HTTPS, local file, object storage) implements this without
    widening RevocationChecker's own interface."""

    def fetch(self) -> bytes: ...


class HttpRevocationListFetcher:
    """Fetches raw revocation-list bytes from an HTTPS URL. HTTPS-only by
    construction. Routes through https_fetch.https_get, so it inherits the
    same redirect-refusal, size cap, total-time bound, and SSRF hardening
    DidWebResolver uses. URL syntax is validated strictly at construction:
    userinfo and fragments are rejected, the path must have a single leading
    slash, and the port (if present) must be 1-65535."""

    def __init__(self, url: str, timeout_seconds: float = DEFAULT_HTTPS_TIMEOUT_SECONDS) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ValueError(f"revocation list URL must use https, got {url!r}")
        if parts.username or parts.password:
            raise ValueError("revocation list URL must not contain userinfo")
        if parts.fragment:
            raise ValueError("revocation list URL must not contain a fragment")
        if not parts.hostname:
            raise ValueError(f"revocation list URL has no host: {url!r}")
        port = parts.port  # raises ValueError for a non-numeric or >65535 port
        if port is not None and not (1 <= port <= 65535):
            raise ValueError("revocation list URL port is out of range")
        path = parts.path or "/"
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("revocation list URL path must have a single leading slash")
        if parts.query:
            path = f"{path}?{parts.query}"
        self._host = parts.hostname
        self._port = port
        self._path = path
        self._timeout_seconds = timeout_seconds

    def fetch(self) -> bytes:
        return https_get(
            self._host,
            self._path,
            port=self._port,
            timeout_seconds=self._timeout_seconds,
            max_bytes=MAX_REVOCATION_LIST_BYTES,
        )


class HttpRevocationChecker:
    """Fetches and verifies a signed RevocationList on EVERY is_revoked() call
    -- no caching (deliberately; see docs/THREAT_MODEL.md for the availability
    cost). Bound to `expected_issuer` at construction: the fetched list's
    issuer must equal that AND the grant issuer passed to is_revoked(). Fails
    closed: a fetch failure, malformed document, invalid/unresolvable
    signature, an issuer mismatch, a stale/expired list, or a sequence lower
    than one already accepted all raise RevocationSourceUnreachable rather
    than silently reporting 'not revoked.' The highest accepted sequence is
    remembered per instance so a replayed older list is rejected as a
    rollback."""

    def __init__(
        self,
        fetcher: RevocationListFetcher,
        resolver: IssuerResolver,
        expected_issuer: str,
    ) -> None:
        self._fetcher = fetcher
        self._resolver = resolver
        self._expected_issuer = expected_issuer
        self._highest_sequence: int | None = None

    def is_revoked(self, issuer: str, grant_binding: str) -> bool:
        if issuer != self._expected_issuer:
            raise RevocationSourceUnreachable("revocation checker is bound to a different issuer")
        try:
            raw = self._fetcher.fetch()
        except (OSError, http.client.HTTPException) as err:
            raise RevocationSourceUnreachable("revocation list fetch failed") from err
        try:
            revocation_list = RevocationList.from_json_bytes(raw)
        except ValueError as err:
            raise RevocationSourceUnreachable("revocation list is malformed") from err
        now = time.time()
        _verify_revocation_list(revocation_list, self._resolver, self._expected_issuer, now)
        if self._highest_sequence is not None and revocation_list.sequence < self._highest_sequence:
            raise RevocationSourceUnreachable("revocation list sequence rolled back (possible replay)")
        self._highest_sequence = max(self._highest_sequence or 0, revocation_list.sequence)
        return grant_binding in frozenset(revocation_list.revoked_bindings)
