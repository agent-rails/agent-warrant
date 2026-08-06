from __future__ import annotations


class UnresolvableIssuer(Exception):
    """Raised by an IssuerResolver when it cannot produce a public key for an
    issuer identifier. This is an internal-collaborator exception -- verify()
    must catch it and never let it propagate to verify()'s own caller, which
    has a never-raises contract."""
