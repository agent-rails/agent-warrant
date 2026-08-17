from __future__ import annotations


class UnresolvableIssuer(Exception):
    """Raised by an IssuerResolver when it cannot produce a public key for an
    issuer identifier. This is an internal-collaborator exception -- verify()
    must catch it and never let it propagate to verify()'s own caller, which
    has a never-raises contract."""


class RevocationSourceUnreachable(Exception):
    """Raised by a RevocationChecker when it cannot determine whether a
    grant_binding is revoked -- a fetch failure, a malformed revocation
    list, or an invalid/unresolvable issuer signature on the list. This is
    an internal-collaborator exception -- verify() must catch it and never
    let it propagate to verify()'s own caller, which has a never-raises
    contract. Deliberately distinct from returning False (not revoked):
    inability to determine status must fail closed, never be silently
    treated as 'not revoked.'"""
