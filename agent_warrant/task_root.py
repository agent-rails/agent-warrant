from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import MAX_SAFE_INTEGER, canonicalize, signing_input, strict_decode
from .exceptions import RevocationSourceUnreachable, UnresolvableIssuer
from .identity import is_valid_public_key
from .issuer import MAX_TTL_SECONDS
from .resolver import IssuerResolver
from .revocation import RevocationChecker
from .scope import validate_scope
from .trust import IssuerTrustPolicy

RECORD_TYPE = "task-root"
RECORD_VERSION = 1
MAX_ENCODED_TASK_ROOT_BYTES = 16_384
MAX_FIELD_CHARACTERS = 256
MAX_CHAIN_DEPTH = 16
MAX_TTL = int(MAX_TTL_SECONDS)
CLOCK_SKEW_SECONDS = 5

_ID_FIELDS = ("task_id", "tenant_id", "principal", "purpose", "issuer")
_STRING_FIELDS = _ID_FIELDS + ("subject",)
_INTEGER_FIELDS = ("budget", "max_depth", "issued_at", "expires_at")
_BODY_FIELDS = _STRING_FIELDS + _INTEGER_FIELDS + ("scope",)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(data: str) -> bytes:
    decoded = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    if _b64u(decoded) != data:
        raise ValueError("not canonical unpadded base64url")
    return decoded


@dataclass(frozen=True)
class TaskRoot:
    """The signed root of a delegation: who is allowed to start a task, for which
    tenant and principal, with what scope, budget and delegation depth. `subject` is the
    first delegate's public key; `proof` is the ISSUER's signature over
    signing_input("task-root", 1, body). Verifying a TaskRoot proves the issuer
    signed these claims, not that any presenter holds `subject`'s key, and not that
    the issuer may assert them (see trust.py). Strings are compared byte for byte:
    callers must normalise ids before they enter a record."""

    task_id: str
    tenant_id: str
    principal: str
    purpose: str
    budget: int
    max_depth: int
    issued_at: int
    expires_at: int
    scope: dict[str, Any]
    subject: str
    issuer: str
    proof: str

    def signable_fields(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in _BODY_FIELDS}

    def signing_bytes(self) -> bytes:
        return signing_input(RECORD_TYPE, RECORD_VERSION, self.signable_fields())

    def binding(self) -> str:
        """Stable identity of this root: sha256 of its domain-tagged signing bytes."""
        return _b64u(hashlib.sha256(self.signing_bytes()).digest())

    def encode(self) -> str:
        return f"{_b64u(canonicalize(self.signable_fields()))}.{self.proof}"

    @classmethod
    def decode(cls, encoded: str) -> TaskRoot:
        if not isinstance(encoded, str):
            raise ValueError(f"malformed task root: expected str, got {type(encoded).__name__}")
        if len(encoded) > MAX_ENCODED_TASK_ROOT_BYTES:
            raise ValueError(f"malformed task root: encoded length exceeds {MAX_ENCODED_TASK_ROOT_BYTES}")
        body_b64, separator, proof = encoded.partition(".")
        if not separator or not proof or "." in proof:
            raise ValueError("malformed task root: expected exactly one '.' separator")
        try:
            body = _b64u_decode(body_b64)
            _b64u_decode(proof)
        except (ValueError, binascii.Error) as err:
            raise ValueError(f"malformed task root: {err}") from None
        fields = strict_decode(body, required=_BODY_FIELDS, integer_fields=_INTEGER_FIELDS)
        _validate_fields(fields)
        if canonicalize(fields) != body:
            raise ValueError("body is not in canonical form")
        return cls(**fields, proof=proof)


def _validate_fields(fields: dict[str, Any]) -> None:
    for name in _ID_FIELDS:
        value = fields[name]
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must be a non-empty string")
        if len(value) > MAX_FIELD_CHARACTERS:
            raise ValueError(f"{name} is longer than {MAX_FIELD_CHARACTERS} characters")
        if not all("!" <= character <= "~" for character in value):
            raise ValueError(f"{name} must be ASCII printable without whitespace or control characters")
    for name in _INTEGER_FIELDS:
        value = fields[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        if not 0 <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"{name} must be between 0 and {MAX_SAFE_INTEGER}")
    scope_refusal = validate_scope(fields["scope"])
    if scope_refusal:
        raise ValueError(f"scope: {scope_refusal}")
    if fields["max_depth"] > MAX_CHAIN_DEPTH:
        raise ValueError(f"max_depth must not exceed {MAX_CHAIN_DEPTH}")
    if fields["expires_at"] <= fields["issued_at"]:
        raise ValueError("expires_at must be after issued_at")
    if fields["expires_at"] - fields["issued_at"] > MAX_TTL:
        raise ValueError(f"lifetime must not exceed {MAX_TTL} seconds")
    if not is_valid_public_key(fields["subject"]):
        raise ValueError("subject is not a canonical base64url Ed25519 public key of full order")


def issue_task_root(
    issuer_key: Ed25519PrivateKey,
    *,
    issuer: str,
    task_id: str,
    tenant_id: str,
    principal: str,
    purpose: str,
    budget: int,
    max_depth: int,
    issued_at: int,
    expires_at: int,
    scope: dict[str, Any],
    subject: str,
) -> TaskRoot:
    fields = {
        "task_id": task_id,
        "tenant_id": tenant_id,
        "principal": principal,
        "purpose": purpose,
        "budget": budget,
        "max_depth": max_depth,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "scope": scope,
        "subject": subject,
        "issuer": issuer,
    }
    _validate_fields(fields)
    signature = issuer_key.sign(signing_input(RECORD_TYPE, RECORD_VERSION, fields))
    return TaskRoot(**fields, proof=_b64u(signature))


@dataclass(frozen=True)
class TaskRootResult:
    """Authentication result only. `valid=True` means the root is authentic,
    inside its validity window and not revoked. It does not mean any presenter
    holds `root.subject`'s key: possession is proven per link, not here."""

    valid: bool
    reason: str
    root: TaskRoot | None = None
    checked_at: int = 0


def verify_root(
    encoded: str,
    resolver: IssuerResolver,
    trust_policy: IssuerTrustPolicy,
    revocation_checker: RevocationChecker,
    now: int,
) -> TaskRootResult:
    """Never raises on attacker-controlled `encoded`; every failure is a
    fail-closed result. No possession proof is checked. The trust policy is
    mandatory: an issuer it does not list is refused before any key lookup, and
    claims beyond the issuer's allowance are refused after its signature checks."""
    if not isinstance(trust_policy, IssuerTrustPolicy):
        raise TypeError("verify_root requires an IssuerTrustPolicy")
    if isinstance(now, bool) or not isinstance(now, int):
        return TaskRootResult(valid=False, reason="now must be an integer", checked_at=0)

    try:
        root = TaskRoot.decode(encoded)
    except (ValueError, TypeError) as err:
        return TaskRootResult(valid=False, reason=f"malformed task root: {err}", checked_at=now)

    refusal = trust_policy.check_issuer(root.issuer)
    if refusal:
        return TaskRootResult(valid=False, reason=refusal, checked_at=now)

    try:
        issuer_key = resolver.resolve(root.issuer)
    except UnresolvableIssuer as err:
        return TaskRootResult(valid=False, reason=f"unresolvable issuer: {err}", checked_at=now)

    try:
        issuer_key.verify(_b64u_decode(root.proof), root.signing_bytes())
    except (InvalidSignature, ValueError, binascii.Error):
        return TaskRootResult(valid=False, reason="invalid issuer signature", checked_at=now)

    if root.issued_at > now + CLOCK_SKEW_SECONDS:
        return TaskRootResult(valid=False, reason="task root is not yet valid", checked_at=now)
    if now >= root.expires_at:
        return TaskRootResult(valid=False, reason="task root has expired", checked_at=now)

    refusal = trust_policy.check_claims(root)
    if refusal:
        return TaskRootResult(valid=False, reason=refusal, checked_at=now)

    try:
        revoked = revocation_checker.is_revoked(root.issuer, root.binding())
    except RevocationSourceUnreachable as err:
        return TaskRootResult(valid=False, reason=f"revocation status unavailable: {err}", checked_at=now)
    if revoked:
        return TaskRootResult(valid=False, reason="task root has been revoked", checked_at=now)

    return TaskRootResult(valid=True, reason="ok", root=root, checked_at=now)
