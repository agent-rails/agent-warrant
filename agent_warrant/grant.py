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
from .exceptions import RevocationSourceUnreachable, UnresolvableIssuer
from .identity import decode_public_key
from .resolver import IssuerResolver
from .revocation import RevocationChecker

CURRENT_VERSION = 1
_REQUIRED_FIELDS = ("version", "issuer", "subject", "scope", "issued_at", "expires_at")
# A compact authority claim never legitimately needs to be large -- callers with a
# genuinely large `scope` should reconsider the design, not raise this constant (see
# README.md's documented constraint). Bounding the encoded string BEFORE any parsing
# closes a live-reproduced gap: an attacker-controlled deeply nested JSON body (e.g.
# repeated `[[[...]]]`) reaches json.loads' recursion limit and raises RecursionError,
# uncaught, falsifying this module's own "never raises" contract.
#
# CORRECTED after a second review pass: this cap was originally described as the
# "primary defense" with decode()'s `except RecursionError` framed as mere
# defense-in-depth. That framing is backwards on most supported interpreters. It was
# measured live only on Python 3.14 (threshold ~150,000 nesting levels, ~391KB) -- but
# this project's own `requires-python = ">=3.10"` covers versions with much lower
# recursion ceilings (CPython's own C_RECURSION_LIMIT is 3000 on Windows, 800 on
# s390x, and 3.10/3.11 fall back to sys.getrecursionlimit(), ~1000 by default). A
# nested payload of only a few KB -- comfortably UNDER this 16KB cap -- can trip
# RecursionError on those interpreters. On them, the `except RecursionError` in
# decode() is the load-bearing defense, not a redundant backstop; do not remove it on
# the assumption this cap alone makes it unreachable.
MAX_ENCODED_GRANT_BYTES = 16_384
POSSESSION_PROOF_CLOCK_SKEW_SECONDS = 5.0


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@dataclass(frozen=True)
class Grant:
    """A VC-data-model-*shaped* authority grant -- NOT VC-spec-conformant.
    There is no `credentialStatus`/StatusList2021 field on the Grant itself
    (see docs/DESIGN.md for why this project's revocation mechanism is
    deliberately NOT StatusList2021-shaped); do not emit or expect a literal
    `type: VerifiableCredential`, which would invite a real VC verifier to
    misread the absence of `credentialStatus` as "permanently valid." Real,
    opt-in revocation checking DOES exist (see `revocation.py`'s
    RevocationChecker, wired into verify() below) -- it lives outside the
    Grant's own fields, as a separate check verify() runs against a
    caller-supplied checker, not as data carried on the credential.
    `subject` is the holder's public key -- this is a holder-bound
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
        if len(encoded) > MAX_ENCODED_GRANT_BYTES:
            raise ValueError(f"malformed grant: encoded length {len(encoded)} exceeds {MAX_ENCODED_GRANT_BYTES} bytes")
        body_b64, _, proof = encoded.partition(".")
        if not proof:
            raise ValueError("malformed grant: missing '.' separator")
        try:
            fields = json.loads(_b64u_decode(body_b64))
        except RecursionError as err:
            # Defense-in-depth: the size cap above is what actually prevents reaching this,
            # but a bare json.loads() recursion is not in the exception types this class's
            # callers otherwise catch, so it's translated to a normal parse failure here too.
            raise ValueError("malformed grant: body nesting too deep to parse") from err
        if not isinstance(fields, dict):
            raise ValueError("malformed grant: body is not a JSON object")
        missing = set(_REQUIRED_FIELDS) - fields.keys()
        if missing:
            raise ValueError(f"malformed grant: missing fields {sorted(missing)}")
        # scope's type annotation (dict[str, Any]) is not enforced by json.loads --
        # an issuer-signed grant with a non-dict scope would otherwise reach callers
        # doing grant.scope["tool"] and hit a runtime TypeError far from this boundary.
        if not isinstance(fields["scope"], dict):
            raise ValueError("malformed grant: scope is not a JSON object")
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
    """Authentication result only. `valid=True` means the grant is authentic,
    unexpired, and holder-bound; callers remain entirely responsible for
    interpreting `grant.scope` and making authorization decisions."""

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
    revocation_checker: RevocationChecker | None = None,
) -> VerifyResult:
    """Never raises -- encoded_grant AND possession_proof are both
    attacker-controlled. Every branch is a fail-closed exit with a narrow,
    named exception catch (binascii.Error, ValueError, TypeError,
    json.JSONDecodeError, InvalidSignature, RevocationSourceUnreachable)
    around each parse/verify block -- never a bare `except`, which would
    swallow a real bug (a NameError from a typo, an AttributeError from a
    genuine logic error) and misreport it as
    "invalid grant" instead of surfacing it. Matches agent_guard's own
    verify_pop discipline exactly (agentguard_identity/pop.py)."""
    checked_at = now if now is not None else time.time()

    try:
        grant = Grant.decode(encoded_grant)
    except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError):
        return VerifyResult(valid=False, reason="malformed grant encoding", checked_at=checked_at)

    if not isinstance(grant.version, int) or isinstance(grant.version, bool) or grant.version != CURRENT_VERSION:
        # STOP here -- no other field of a version we don't understand is trusted.
        return VerifyResult(valid=False, reason=f"unsupported grant version {grant.version!r}", checked_at=checked_at)

    # grant.issuer is attacker-controlled JSON and reaches resolver.resolve() before any
    # signature check -- an unhashable value (a list or dict) makes a dict-based resolver's
    # .get() raise TypeError, uncaught here before this guard. Found live: a 185-byte
    # unsigned payload with issuer=[] or issuer={} raised out of verify() with no
    # authentication required at all. Same isinstance-guard-before-use pattern as the
    # timestamp/iat guards elsewhere in this function.
    if not isinstance(grant.issuer, str):
        return VerifyResult(valid=False, reason="grant issuer is not a string", checked_at=checked_at)

    try:
        issuer_key = resolver.resolve(grant.issuer)
    except UnresolvableIssuer as err:
        return VerifyResult(valid=False, reason=f"unresolvable issuer: {err}", checked_at=checked_at)

    try:
        issuer_key.verify(_b64u_decode(grant.proof), canonicalize(grant._signable_fields()))
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return VerifyResult(valid=False, reason="invalid issuer signature", checked_at=checked_at)

    # Same reasoning as the possession_proof.iat guard below: the issuer signature only
    # proves the ISSUER produced these values, not that they're well-typed -- a buggy or
    # malicious pinned issuer could still sign a grant with a non-numeric timestamp.
    # Symmetric fix for the same defect class found in the iat guard (asymmetry flagged
    # by adversarial review: this comparison had no guard while iat's did).
    for field_name, value in (("issued_at", grant.issued_at), ("expires_at", grant.expires_at)):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return VerifyResult(valid=False, reason=f"grant has a non-numeric {field_name}", checked_at=checked_at)

    if not (grant.issued_at <= checked_at <= grant.expires_at):
        return VerifyResult(valid=False, reason="grant expired or not yet valid", checked_at=checked_at)

    try:
        proof_fields = possession_proof._signable_fields()
        binding = proof_fields["grant_binding"]
        iat = proof_fields["iat"]
        holder_key = decode_public_key(grant.subject)
        holder_key.verify(_b64u_decode(possession_proof.signature), canonicalize(proof_fields))
    except (InvalidSignature, ValueError, TypeError, KeyError, binascii.Error):
        return VerifyResult(valid=False, reason="invalid possession proof signature", checked_at=checked_at)

    # Not independently reachable with a value that raises here -- grant._signable_fields()
    # was already canonicalized successfully at the issuer-signature check above, and this is
    # the same deterministic input -- but wrapped anyway so no canonicalize() call in this
    # function sits outside a fail-closed handler, robust against a future refactor changing
    # what reaches this line.
    try:
        expected_binding = _b64u(hashlib.sha256(canonicalize(grant._signable_fields())).digest())
    except (ValueError, TypeError):
        return VerifyResult(valid=False, reason="could not compute expected grant binding", checked_at=checked_at)
    if binding != expected_binding:
        return VerifyResult(valid=False, reason="possession proof bound to a different grant", checked_at=checked_at)

    # iat is attacker-controlled (part of a signed body, but the signature check above only
    # proves the HOLDER produced it -- a buggy holder client could still sign a bad iat).
    # isinstance/isfinite guard BEFORE the arithmetic, matching pop.py's own precedent, so a
    # non-numeric iat can't raise TypeError out of this never-raises function.
    if isinstance(iat, bool) or not isinstance(iat, (int, float)) or not math.isfinite(iat):
        return VerifyResult(valid=False, reason="possession proof has a non-numeric iat", checked_at=checked_at)
    age = checked_at - iat
    if age < -POSSESSION_PROOF_CLOCK_SKEW_SECONDS or age > max_age_seconds:
        return VerifyResult(valid=False, reason="possession proof is stale", checked_at=checked_at)

    # Opt-in, checked LAST -- only once a grant has already passed every other
    # check, so an unauthenticated or already-invalid grant never triggers a
    # revocation lookup (cheaper, and avoids exposing the revocation source to
    # queries about grants that were never valid to begin with). Reuses
    # `expected_binding` (already computed above as this grant's grant_binding)
    # rather than recomputing it -- see THREAT_MODEL.md: grant_binding, not the
    # raw encoded string, is this project's stable identity for a specific Grant.
    if revocation_checker is not None:
        try:
            # grant.issuer is the ALREADY-AUTHENTICATED issuer (its signature was
            # verified above). Passing it lets the checker bind revocation status
            # to this issuer -- so another issuer's authentic (empty) list can't
            # vouch "not revoked" for this grant.
            revoked = revocation_checker.is_revoked(grant.issuer, expected_binding)
        except RevocationSourceUnreachable as err:
            return VerifyResult(valid=False, reason=f"revocation status unavailable: {err}", checked_at=checked_at)
        if revoked:
            return VerifyResult(valid=False, reason="grant has been revoked", checked_at=checked_at)

    return VerifyResult(valid=True, reason="ok", grant=grant, checked_at=checked_at)
