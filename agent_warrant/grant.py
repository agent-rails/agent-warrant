from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize
from .exceptions import UnresolvableIssuer
from .identity import decode_public_key
from .resolver import IssuerResolver

CURRENT_VERSION = 1
_REQUIRED_FIELDS = ("version", "issuer", "subject", "scope", "issued_at", "expires_at")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@dataclass(frozen=True)
class Grant:
    """A VC-data-model-*shaped* authority grant -- NOT VC-spec-conformant.
    In particular there is no `credentialStatus`/StatusList2021 revocation
    mechanism (see docs/THREAT_MODEL.md's explicit non-goal); do not emit or
    expect a literal `type: VerifiableCredential`, which would invite a real
    VC verifier to misread the absence of revocation status as "permanently
    valid." `subject` is the holder's public key -- this is a holder-bound
    credential, not a bearer one, but ONLY when paired with a fresh
    PossessionProof at verification time (see verify() below); the Grant's
    own `proof` field is the ISSUER's signature, not a possession proof."""

    version: int
    issuer: str
    subject: str
    scope: dict[str, Any]
    issued_at: float
    expires_at: float
    proof: str

    def _signable_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "issuer": self.issuer,
            "subject": self.subject,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def encode(self) -> str:
        body_b64 = _b64u(canonicalize(self._signable_fields()))
        return f"{body_b64}.{self.proof}"

    @classmethod
    def decode(cls, encoded: str) -> Grant:
        body_b64, _, proof = encoded.partition(".")
        if not proof:
            raise ValueError("malformed grant: missing '.' separator")
        fields = json.loads(_b64u_decode(body_b64))
        if not isinstance(fields, dict):
            raise ValueError("malformed grant: body is not a JSON object")
        missing = set(_REQUIRED_FIELDS) - fields.keys()
        if missing:
            raise ValueError(f"malformed grant: missing fields {sorted(missing)}")
        return cls(**{k: fields[k] for k in _REQUIRED_FIELDS}, proof=proof)


@dataclass(frozen=True)
class PossessionProof:
    """A fresh, single-grant-scoped proof that the presenter holds the
    private key matching a Grant's `subject`. Mirrors agent-guard's own
    PoPProof/verify_pop shape (agentguard_identity/pop.py) -- structurally,
    not by inline-reuse of its json.dumps body (that would reintroduce the
    exact canonicalization drift this project's canonical.py module exists
    to prevent; the signable body here routes through canonicalize())."""

    grant_binding: str
    iat: float
    signature: str

    def _signable_fields(self) -> dict[str, Any]:
        return {"grant_binding": self.grant_binding, "iat": self.iat}


def sign(fields: dict[str, Any], private_key: Ed25519PrivateKey) -> Grant:
    missing = set(_REQUIRED_FIELDS) - fields.keys()
    if missing:
        raise ValueError(f"sign(): missing required grant fields {sorted(missing)}")
    signable = {k: fields[k] for k in _REQUIRED_FIELDS}
    signature = private_key.sign(canonicalize(signable))
    return Grant(**signable, proof=_b64u(signature))


def prove(grant: Grant, holder_private_key: Ed25519PrivateKey, now: float | None = None) -> PossessionProof:
    grant_binding = _b64u(hashlib.sha256(canonicalize(grant._signable_fields())).digest())
    iat = now if now is not None else time.time()
    signable = {"grant_binding": grant_binding, "iat": iat}
    signature = _b64u(holder_private_key.sign(canonicalize(signable)))
    return PossessionProof(grant_binding=grant_binding, iat=iat, signature=signature)


@dataclass(frozen=True)
class VerifyResult:
    valid: bool
    reason: str
    grant: Grant | None = None
    checked_at: float = 0.0


def verify(
    encoded_grant: str,
    possession_proof: PossessionProof,
    resolver: IssuerResolver,
    now: float | None = None,
    max_age_seconds: float = 60.0,
) -> VerifyResult:
    """Never raises -- encoded_grant AND possession_proof are both
    attacker-controlled. Every branch is a fail-closed exit with a narrow,
    named exception catch (binascii.Error, ValueError, TypeError,
    json.JSONDecodeError, InvalidSignature) around each parse/verify block --
    never a bare `except`, which would swallow a real bug (a NameError from a
    typo, an AttributeError from a genuine logic error) and misreport it as
    "invalid grant" instead of surfacing it. Matches agent_guard's own
    verify_pop discipline exactly (agentguard_identity/pop.py)."""
    checked_at = now if now is not None else time.time()

    try:
        grant = Grant.decode(encoded_grant)
    except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError):
        return VerifyResult(valid=False, reason="malformed grant encoding", checked_at=checked_at)

    if grant.version != CURRENT_VERSION:
        # STOP here -- no other field of a version we don't understand is trusted.
        return VerifyResult(valid=False, reason=f"unsupported grant version {grant.version!r}", checked_at=checked_at)

    try:
        issuer_key = resolver.resolve(grant.issuer)
    except UnresolvableIssuer as err:
        return VerifyResult(valid=False, reason=f"unresolvable issuer: {err}", checked_at=checked_at)

    try:
        issuer_key.verify(_b64u_decode(grant.proof), canonicalize(grant._signable_fields()))
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return VerifyResult(valid=False, reason="invalid issuer signature", checked_at=checked_at)

    if not (grant.issued_at <= checked_at <= grant.expires_at):
        return VerifyResult(valid=False, reason="grant expired or not yet valid", checked_at=checked_at)

    try:
        holder_key = decode_public_key(grant.subject)
        holder_key.verify(_b64u_decode(possession_proof.signature), canonicalize(possession_proof._signable_fields()))
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return VerifyResult(valid=False, reason="invalid possession proof signature", checked_at=checked_at)

    expected_binding = _b64u(hashlib.sha256(canonicalize(grant._signable_fields())).digest())
    if possession_proof.grant_binding != expected_binding:
        return VerifyResult(valid=False, reason="possession proof bound to a different grant", checked_at=checked_at)

    # iat is attacker-controlled (part of a signed body, but the signature check above only
    # proves the HOLDER produced it -- a buggy holder client could still sign a bad iat).
    # isinstance/isfinite guard BEFORE the arithmetic, matching pop.py's own precedent, so a
    # non-numeric iat can't raise TypeError out of this never-raises function.
    iat = possession_proof.iat
    if isinstance(iat, bool) or not isinstance(iat, (int, float)) or not math.isfinite(iat):
        return VerifyResult(valid=False, reason="possession proof has a non-numeric iat", checked_at=checked_at)
    if abs(checked_at - iat) > max_age_seconds:
        return VerifyResult(valid=False, reason="possession proof is stale", checked_at=checked_at)

    return VerifyResult(valid=True, reason="ok", grant=grant, checked_at=checked_at)
