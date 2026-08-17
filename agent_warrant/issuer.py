from __future__ import annotations

import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .grant import CURRENT_VERSION, Grant, PossessionProof, VerifyResult, prove, sign, verify
from .resolver import IssuerResolver
from .revocation import RevocationChecker

MAX_TTL_SECONDS = 86_400.0


class Issuer:
    """Holds `private_key` once, for the object's lifetime, rather than
    threading it through every call site -- fewer places the key bytes can
    leak into a log or traceback. This is a real, named tradeoff (see
    docs/DESIGN.md): a long-lived Issuer keeps the key resident in the heap
    longer than the bare sign() function would for a single call. The bare
    `sign()` function remains available directly for callers that want
    minimal key residency; Issuer is a convenience over it, not a strictly
    better replacement. Mirrors agent_guard's own Broker/token.sign() split."""

    def __init__(self, issuer_id: str, private_key: Ed25519PrivateKey, default_ttl_seconds: float = 300.0) -> None:
        self._issuer_id = issuer_id
        self._private_key = private_key
        self._default_ttl_seconds = default_ttl_seconds

    def issue(self, subject: str, scope: dict[str, Any], ttl_seconds: float | None = None) -> Grant:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds
        if ttl <= 0:
            raise ValueError(f"ttl_seconds must be positive, got {ttl!r}")
        if ttl > MAX_TTL_SECONDS:
            raise ValueError(
                f"ttl_seconds must not exceed {MAX_TTL_SECONDS!r}; a grant this issuer signs "
                "has no revocation unless the verifier opts in with a RevocationChecker (see "
                "revocation.py) -- this Issuer cannot guarantee that, so long-lived grants "
                "still defeat TTL-only containment by default"
            )
        if not isinstance(scope, dict):
            raise TypeError(f"scope must be a dict, got {type(scope).__name__}")
        now = time.time()
        fields = {
            "version": CURRENT_VERSION,
            "issuer": self._issuer_id,
            "subject": subject,
            "scope": scope,
            "issued_at": now,
            "expires_at": now + ttl,
        }
        return sign(fields, self._private_key)


class HolderKeypair:
    """The holder side of a possession proof -- generates a keypair, exposes
    the public key to be embedded as a Grant's `subject`, and proves
    possession of the matching private key for a specific grant."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    def prove_possession(self, grant: Grant, now: float | None = None) -> PossessionProof:
        return prove(grant, self._private_key, now=now)


class Verifier:
    """Holds an IssuerResolver instance (and its cache, once a caching
    resolver wrapper exists) rather than re-threading it through every
    verify() call site. `revocation_checker` is opt-in and None by default --
    a Verifier constructed without one behaves exactly as before revocation
    checking existed (TTL is the only expiry mechanism); see revocation.py
    and docs/THREAT_MODEL.md for what wiring one in actually buys you."""

    def __init__(
        self,
        resolver: IssuerResolver,
        max_age_seconds: float = 60.0,
        revocation_checker: RevocationChecker | None = None,
    ) -> None:
        self._resolver = resolver
        self._max_age_seconds = max_age_seconds
        self._revocation_checker = revocation_checker

    def check(self, encoded_grant: str, possession_proof: PossessionProof) -> VerifyResult:
        return verify(
            encoded_grant,
            possession_proof,
            self._resolver,
            max_age_seconds=self._max_age_seconds,
            revocation_checker=self._revocation_checker,
        )
