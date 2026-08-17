from __future__ import annotations

from .canonical import canonicalize
from .exceptions import RevocationSourceUnreachable, UnresolvableIssuer
from .grant import CURRENT_VERSION, Grant, PossessionProof, VerifyResult, prove, sign, verify
from .identity import decode_public_key, encode_public_key, generate_keypair
from .issuer import HolderKeypair, Issuer, Verifier
from .resolver import DidWebResolver, IssuerResolver, PinnedResolver
from .revocation import (
    HttpRevocationChecker,
    HttpRevocationListFetcher,
    RevocationChecker,
    RevocationList,
    RevocationListFetcher,
    StaticRevocationChecker,
    sign_revocation_list,
)

__all__ = [
    "CURRENT_VERSION",
    "DidWebResolver",
    "Grant",
    "HolderKeypair",
    "HttpRevocationChecker",
    "HttpRevocationListFetcher",
    "Issuer",
    "IssuerResolver",
    "PinnedResolver",
    "PossessionProof",
    "RevocationChecker",
    "RevocationList",
    "RevocationListFetcher",
    "RevocationSourceUnreachable",
    "StaticRevocationChecker",
    "UnresolvableIssuer",
    "VerifyResult",
    "Verifier",
    "canonicalize",
    "decode_public_key",
    "encode_public_key",
    "generate_keypair",
    "prove",
    "sign",
    "sign_revocation_list",
    "verify",
]
