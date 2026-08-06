from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .exceptions import UnresolvableIssuer


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
    did:web-based resolver (V2, not built here) is what actually delivers
    that property. The name is deliberately unglamorous: a reader should not
    mistake this for a real trust-verification mechanism."""

    def __init__(self, known_issuers: dict[str, Ed25519PublicKey]) -> None:
        self._known_issuers = dict(known_issuers)

    def resolve(self, issuer: str) -> Ed25519PublicKey:
        key = self._known_issuers.get(issuer)
        if key is None:
            raise UnresolvableIssuer(f"issuer {issuer!r} is not in the pinned key set")
        return key
