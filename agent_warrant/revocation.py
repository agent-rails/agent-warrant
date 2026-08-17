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
_REQUIRED_REVOCATION_FIELDS = ("issuer", "revoked_bindings", "issued_at")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@dataclass(frozen=True)
class RevocationList:
    """Issuer-signed set of revoked `grant_binding` values -- see
    grant.py's PossessionProof.grant_binding and docs/THREAT_MODEL.md's
    explicit guidance that grant_binding, not the raw encoded grant string,
    is this project's stable identity for a specific Grant. Signed the same
    way as a Grant -- canonicalize() + the issuer's existing Ed25519 key --
    so revocation checking introduces NO new trust root or shared secret;
    it reuses exactly the trust an IssuerResolver already establishes for
    grants themselves.

    Deliberately NOT a StatusList2021/Bitstring Status List: that spec's
    bitstring-bundling design exists to hide which specific entry an
    anonymous verifier is checking, among a public, million-entry-scale
    population (mobile driver's licenses, diplomas). agent-warrant's actual
    shape is a known, pre-arranged cross-org relationship with a small,
    bounded verifier population per issuer -- the anonymity-set machinery
    StatusList2021 needs at public-VC scale isn't earned here. See
    docs/DESIGN.md."""

    issuer: str
    revoked_bindings: tuple[str, ...]
    issued_at: float
    proof: str

    def _signable_fields(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "revoked_bindings": sorted(self.revoked_bindings),
            "issued_at": self.issued_at,
        }

    def to_json_bytes(self) -> bytes:
        payload = {**self._signable_fields(), "proof": self.proof}
        return json.dumps(payload).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> RevocationList:
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as err:
            raise ValueError(f"malformed revocation list: {err}") from err
        if not isinstance(payload, dict):
            raise ValueError("malformed revocation list: body is not a JSON object")
        missing = set(_REQUIRED_REVOCATION_FIELDS) - payload.keys()
        if missing:
            raise ValueError(f"malformed revocation list: missing fields {sorted(missing)}")
        if "proof" not in payload:
            raise ValueError("malformed revocation list: missing proof")

        issuer = payload["issuer"]
        if not isinstance(issuer, str):
            raise ValueError("malformed revocation list: issuer is not a string")

        bindings = payload["revoked_bindings"]
        if not isinstance(bindings, list) or not all(isinstance(b, str) for b in bindings):
            raise ValueError("malformed revocation list: revoked_bindings is not a list of strings")

        issued_at = payload["issued_at"]
        if isinstance(issued_at, bool) or not isinstance(issued_at, (int, float)) or not math.isfinite(issued_at):
            raise ValueError("malformed revocation list: issued_at is not a finite number")

        proof = payload["proof"]
        if not isinstance(proof, str):
            raise ValueError("malformed revocation list: proof is not a string")

        return cls(issuer=issuer, revoked_bindings=tuple(bindings), issued_at=issued_at, proof=proof)


def sign_revocation_list(
    issuer: str,
    revoked_bindings: list[str] | tuple[str, ...] | frozenset[str],
    private_key: Ed25519PrivateKey,
    issued_at: float | None = None,
) -> RevocationList:
    ts = issued_at if issued_at is not None else time.time()
    bindings = tuple(sorted(set(revoked_bindings)))
    signable = {"issuer": issuer, "revoked_bindings": list(bindings), "issued_at": ts}
    signature = private_key.sign(canonicalize(signable))
    return RevocationList(issuer=issuer, revoked_bindings=bindings, issued_at=ts, proof=_b64u(signature))


def _verify_revocation_list(revocation_list: RevocationList, resolver: IssuerResolver) -> None:
    try:
        issuer_key = resolver.resolve(revocation_list.issuer)
    except UnresolvableIssuer as err:
        raise RevocationSourceUnreachable(
            f"cannot resolve issuer {revocation_list.issuer!r} for revocation list: {err}"
        ) from err
    try:
        issuer_key.verify(_b64u_decode(revocation_list.proof), canonicalize(revocation_list._signable_fields()))
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as err:
        raise RevocationSourceUnreachable(
            f"revocation list signature invalid for issuer {revocation_list.issuer!r}"
        ) from err


class RevocationChecker(Protocol):
    """Checked as the final gate in verify(), only once a Grant has already
    passed every other check. Kept to one method, mirroring
    IssuerResolver's own minimalism. MUST raise RevocationSourceUnreachable,
    never return a silent 'not revoked' guess, when revocation status can't
    be determined -- verify() treats that exception as fail-closed."""

    def is_revoked(self, grant_binding: str) -> bool: ...


class StaticRevocationChecker:
    """Wraps an already-fetched RevocationList. No network or freshness
    logic of its own -- for callers who fetch/cache the list themselves, or
    for in-process/test use. Verifies the list's signature once, at
    construction time, against `resolver` -- the SAME IssuerResolver
    already used for grant verification, so this introduces no new trust
    root. A tampered or wrongly-signed list is rejected at construction,
    not silently trusted."""

    def __init__(self, revocation_list: RevocationList, resolver: IssuerResolver) -> None:
        _verify_revocation_list(revocation_list, resolver)
        self._revoked = frozenset(revocation_list.revoked_bindings)

    def is_revoked(self, grant_binding: str) -> bool:
        return grant_binding in self._revoked


class RevocationListFetcher(Protocol):
    """Kept to one method, same minimalism as IssuerResolver -- any
    transport (HTTPS, local file, object storage) implements this without
    widening RevocationChecker's own interface."""

    def fetch(self) -> bytes: ...


class HttpRevocationListFetcher:
    """Fetches raw revocation-list bytes from an HTTPS URL. HTTPS-only by
    construction -- a caller supplying a non-https URL is rejected at
    construction time, not silently upgraded or silently allowed to fetch
    in plaintext. Routes through https_fetch.https_get, so it inherits the
    same redirect-refusal, size cap, and private-address (SSRF) rejection
    DidWebResolver uses."""

    def __init__(self, url: str, timeout_seconds: float = DEFAULT_HTTPS_TIMEOUT_SECONDS) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ValueError(f"revocation list URL must use https, got {url!r}")
        if not parts.hostname:
            raise ValueError(f"revocation list URL has no host: {url!r}")
        self._host = parts.hostname
        self._port = parts.port
        self._path = parts.path or "/"
        if parts.query:
            self._path = f"{self._path}?{parts.query}"
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
    """Fetches and verifies a signed RevocationList on EVERY is_revoked()
    call -- no caching (deliberately, matching this version's narrow scope;
    see docs/THREAT_MODEL.md for the disclosed cost: every verify() call
    using this checker makes a network round trip, and an unreachable
    revocation endpoint fails every verification for callers who opted in).
    Fails closed: a fetch failure, a malformed document, or an
    invalid/unresolvable issuer signature all raise
    RevocationSourceUnreachable rather than silently reporting 'not
    revoked.'"""

    def __init__(self, fetcher: RevocationListFetcher, resolver: IssuerResolver) -> None:
        self._fetcher = fetcher
        self._resolver = resolver

    def is_revoked(self, grant_binding: str) -> bool:
        try:
            raw = self._fetcher.fetch()
        except (OSError, http.client.HTTPException) as err:
            raise RevocationSourceUnreachable(f"revocation list fetch failed: {err}") from err
        try:
            revocation_list = RevocationList.from_json_bytes(raw)
        except ValueError as err:
            raise RevocationSourceUnreachable(f"revocation list is malformed: {err}") from err
        _verify_revocation_list(revocation_list, self._resolver)
        return grant_binding in frozenset(revocation_list.revoked_bindings)
