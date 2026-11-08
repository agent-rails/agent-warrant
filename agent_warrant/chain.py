from __future__ import annotations

import binascii
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import MAX_SAFE_INTEGER, canonicalize, signing_input, strict_decode
from .encoding import b64u, b64u_decode, sha256_b64u, unpack
from .exceptions import RevocationSourceUnreachable
from .identity import decode_public_key, encode_public_key, is_valid_public_key
from .resolver import IssuerResolver
from .scope import scope_narrows, validate_scope
from .task_root import (
    CLOCK_SKEW_SECONDS,
    MAX_CHAIN_DEPTH,
    MAX_FIELD_CHARACTERS,
    MAX_TTL,
    TaskRoot,
    check_root,
)
from .trust import IssuerTrustPolicy

LINK_TYPE = "chain-link"
LINK_VERSION = 1
POSSESSION_TYPE = "possession"
POSSESSION_VERSION = 1
MAX_ENCODED_LINK_BYTES = 16_384
MAX_ENCODED_PROOF_BYTES = 1_024
MAX_CHAIN_ENCODED_BYTES = 262_144
DEFAULT_PROOF_MAX_AGE_SECONDS = 60

_LINK_STRING_FIELDS = ("task_id", "tenant_id")
_LINK_HASH_FIELDS = ("task_root", "parent_hash")
_LINK_KEY_FIELDS = ("issuer", "subject")
_LINK_INTEGER_FIELDS = ("budget", "depth", "issued_at", "expires_at")
_LINK_BODY_FIELDS = _LINK_STRING_FIELDS + _LINK_HASH_FIELDS + _LINK_KEY_FIELDS + _LINK_INTEGER_FIELDS + ("scope",)
_PROOF_FIELDS = ("binding", "iat")


def _is_binding(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(b64u_decode(value)) == 32
    except ValueError:
        return False


@dataclass(frozen=True)
class ChainLink:
    """One delegation step. `issuer` is the previous holder's public key and signs
    the link; `subject` is the next holder's public key. `parent_hash` is the binding
    of the previous record (the TaskRoot for the first link, otherwise the previous
    link) and `task_root` is the TaskRoot's binding, so a link fits exactly one chain
    position in one task and tenant. `proof` is the issuer's signature over
    signing_input("chain-link", 1, body)."""

    task_id: str
    tenant_id: str
    task_root: str
    parent_hash: str
    issuer: str
    subject: str
    scope: dict[str, Any]
    budget: int
    depth: int
    issued_at: int
    expires_at: int
    proof: str

    def signable_fields(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in _LINK_BODY_FIELDS}

    def signing_bytes(self) -> bytes:
        return signing_input(LINK_TYPE, LINK_VERSION, self.signable_fields())

    def binding(self) -> str:
        return sha256_b64u(self.signing_bytes())

    def encode(self) -> str:
        return f"{b64u(canonicalize(self.signable_fields()))}.{self.proof}"

    @classmethod
    def decode(cls, encoded: str) -> ChainLink:
        try:
            body, proof = unpack(encoded, MAX_ENCODED_LINK_BYTES)
        except ValueError as err:
            raise ValueError(f"malformed chain link: {err}") from None
        fields = strict_decode(body, required=_LINK_BODY_FIELDS, integer_fields=_LINK_INTEGER_FIELDS)
        _validate_link_fields(fields)
        if canonicalize(fields) != body:
            raise ValueError("body is not in canonical form")
        return cls(**fields, proof=proof)


def _validate_link_fields(fields: dict[str, Any]) -> None:
    for name in _LINK_STRING_FIELDS:
        value = fields[name]
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must be a non-empty string")
        if len(value) > MAX_FIELD_CHARACTERS:
            raise ValueError(f"{name} is longer than {MAX_FIELD_CHARACTERS} characters")
        if not all("!" <= character <= "~" for character in value):
            raise ValueError(f"{name} must be ASCII printable without whitespace or control characters")
    for name in _LINK_HASH_FIELDS:
        if not _is_binding(fields[name]):
            raise ValueError(f"{name} is not a canonical base64url sha256 digest")
    for name in _LINK_KEY_FIELDS:
        if not is_valid_public_key(fields[name]):
            raise ValueError(f"{name} is not a canonical base64url Ed25519 public key")
    for name in _LINK_INTEGER_FIELDS:
        value = fields[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        if not 0 <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"{name} must be between 0 and {MAX_SAFE_INTEGER}")
    scope_refusal = validate_scope(fields["scope"])
    if scope_refusal:
        raise ValueError(f"scope: {scope_refusal}")
    if not 1 <= fields["depth"] <= MAX_CHAIN_DEPTH:
        raise ValueError(f"depth must be between 1 and {MAX_CHAIN_DEPTH}")
    if fields["expires_at"] <= fields["issued_at"]:
        raise ValueError("expires_at must be after issued_at")
    if fields["expires_at"] - fields["issued_at"] > MAX_TTL:
        raise ValueError(f"lifetime must not exceed {MAX_TTL} seconds")


def delegate(
    root: TaskRoot,
    parent: TaskRoot | ChainLink,
    parent_holder_key: Ed25519PrivateKey,
    *,
    child_subject: str,
    scope: dict[str, Any],
    budget: int,
    ttl: int,
    now: int,
) -> ChainLink:
    """Sign the next link, issued by the holder of `parent.subject`. Refuses, with
    ValueError, anything verify_chain would refuse: a key that is not the parent's
    subject, a scope that does not narrow, a budget above the parent's, a depth past
    the root's max_depth, or no remaining lifetime. Expiry is clamped to the parent's."""
    if not isinstance(parent, (TaskRoot, ChainLink)):
        raise TypeError("parent must be a TaskRoot or ChainLink")
    if isinstance(now, bool) or not isinstance(now, int):
        raise ValueError("now must be an integer")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        raise ValueError("ttl must be a positive integer")
    if encode_public_key(parent_holder_key.public_key()) != parent.subject:
        raise ValueError("key does not match the parent's subject")
    if isinstance(parent, ChainLink) and (
        (parent.task_id, parent.tenant_id, parent.task_root) != (root.task_id, root.tenant_id, root.binding())
    ):
        raise ValueError("parent link does not belong to this task root")
    depth = 1 if isinstance(parent, TaskRoot) else parent.depth + 1
    if depth > root.max_depth:
        raise ValueError(f"depth {depth} exceeds the root's max_depth {root.max_depth}")
    if not scope_narrows(parent.scope, scope):
        raise ValueError("scope does not narrow the parent's scope")
    if isinstance(budget, bool) or not isinstance(budget, int) or not 0 <= budget <= parent.budget:
        raise ValueError(f"budget must be an integer between 0 and the parent's budget {parent.budget}")
    if not parent.issued_at <= now < parent.expires_at:
        raise ValueError("parent is not valid at now")
    fields = {
        "task_id": root.task_id,
        "tenant_id": root.tenant_id,
        "task_root": root.binding(),
        "parent_hash": parent.binding(),
        "issuer": parent.subject,
        "subject": child_subject,
        "scope": scope,
        "budget": budget,
        "depth": depth,
        "issued_at": now,
        "expires_at": min(now + ttl, parent.expires_at),
    }
    _validate_link_fields(fields)
    signature = parent_holder_key.sign(signing_input(LINK_TYPE, LINK_VERSION, fields))
    return ChainLink(**fields, proof=b64u(signature))


@dataclass(frozen=True)
class LeafProof:
    """Fresh proof that the presenter holds the key of the chain's leaf subject. It
    is bound to the leaf record's binding and a timestamp, and signed under its own
    domain tag (`possession`), so it cannot be replayed as a link or a root."""

    binding: str
    iat: int
    signature: str

    def signable_fields(self) -> dict[str, Any]:
        return {"binding": self.binding, "iat": self.iat}

    def encode(self) -> str:
        return f"{b64u(canonicalize(self.signable_fields()))}.{self.signature}"

    @classmethod
    def decode(cls, encoded: str) -> LeafProof:
        try:
            body, signature = unpack(encoded, MAX_ENCODED_PROOF_BYTES)
        except ValueError as err:
            raise ValueError(f"malformed leaf proof: {err}") from None
        fields = strict_decode(body, required=_PROOF_FIELDS, integer_fields=("iat",))
        if not _is_binding(fields["binding"]):
            raise ValueError("binding is not a canonical base64url sha256 digest")
        if not 0 <= fields["iat"] <= MAX_SAFE_INTEGER:
            raise ValueError("iat is out of range")
        if canonicalize(fields) != body:
            raise ValueError("body is not in canonical form")
        return cls(binding=fields["binding"], iat=fields["iat"], signature=signature)


def prove_leaf(leaf: TaskRoot | ChainLink, holder_key: Ed25519PrivateKey, now: int) -> LeafProof:
    fields = {"binding": leaf.binding(), "iat": now}
    signature = holder_key.sign(signing_input(POSSESSION_TYPE, POSSESSION_VERSION, fields))
    return LeafProof(binding=fields["binding"], iat=now, signature=b64u(signature))


@dataclass(frozen=True)
class ChainVerifyResult:
    """Authentication result only. `valid=True` means the chain from the root to the
    leaf is authentic, narrowing, in its validity window, and the presenter holds the
    leaf subject's key now. Interpreting `leaf_scope` is the caller's job."""

    valid: bool
    reason: str
    root: TaskRoot | None = None
    links: tuple[ChainLink, ...] = ()
    checked_at: int = 0

    @property
    def leaf_subject(self) -> str | None:
        if not self.valid or self.root is None:
            return None
        return self.links[-1].subject if self.links else self.root.subject

    @property
    def leaf_scope(self) -> dict[str, Any] | None:
        if not self.valid or self.root is None:
            return None
        return self.links[-1].scope if self.links else self.root.scope


@dataclass(frozen=True)
class ChainContext:
    """What a revocation source needs to judge a verified chain: the task and tenant,
    the root's issuer and binding, and the binding of every link in order. The chain
    is revoked if the task, the tenant, the root or any link is."""

    task_id: str
    tenant_id: str
    root_issuer: str
    task_root: str
    link_bindings: tuple[str, ...]


class ChainRevocationChecker(Protocol):
    """MUST return True when the task, tenant, root or any link in `context` is
    revoked, and MUST raise RevocationSourceUnreachable, never return False, when
    status cannot be determined: verify_chain treats that exception as fail-closed."""

    def is_revoked(self, context: ChainContext) -> bool: ...


def verify_chain(
    root_encoded: str,
    links_encoded: list[str],
    leaf_proof: str,
    resolver: IssuerResolver,
    trust_policy: IssuerTrustPolicy,
    revocation_checker: ChainRevocationChecker,
    now: int,
    max_proof_age_seconds: int = DEFAULT_PROOF_MAX_AGE_SECONDS,
) -> ChainVerifyResult:
    """Never raises on attacker-controlled `root_encoded`, `links_encoded` or
    `leaf_proof`; every failure is a fail-closed result. Verifies the root with
    verify_root, then each link in order, then a fresh possession proof by the leaf
    subject. A TaskRoot alone, without the leaf key, never yields a valid chain."""

    def fail(reason: str) -> ChainVerifyResult:
        return ChainVerifyResult(valid=False, reason=reason, checked_at=now if isinstance(now, int) else 0)

    if isinstance(now, bool) or not isinstance(now, int):
        return fail("now must be an integer")
    if not isinstance(links_encoded, (list, tuple)) or not all(isinstance(item, str) for item in links_encoded):
        return fail("links must be a list of strings")
    if not isinstance(root_encoded, str) or not isinstance(leaf_proof, str):
        return fail("root and leaf proof must be strings")
    if len(root_encoded) + sum(len(item) for item in links_encoded) > MAX_CHAIN_ENCODED_BYTES:
        return fail("chain is larger than the size cap")

    if revocation_checker is None or not callable(getattr(revocation_checker, "is_revoked", None)):
        raise TypeError("verify_chain requires a ChainRevocationChecker")

    root_result = check_root(root_encoded, resolver, trust_policy, now)
    if not root_result.valid or root_result.root is None:
        return fail(f"task root: {root_result.reason}")
    root = root_result.root

    if len(links_encoded) > root.max_depth:
        return fail(f"chain has {len(links_encoded)} links, over the root's max_depth {root.max_depth}")

    root_binding = root.binding()
    previous: TaskRoot | ChainLink = root
    previous_hash = root_binding
    previous_depth = 0
    links: list[ChainLink] = []
    for position, encoded in enumerate(links_encoded, start=1):
        try:
            link = ChainLink.decode(encoded)
        except (ValueError, TypeError) as err:
            return fail(f"link {position}: {err}")
        reason = _check_link(link, previous, previous_hash, previous_depth, root, root_binding, now)
        if reason:
            return fail(f"link {position}: {reason}")
        links.append(link)
        previous = link
        previous_hash = link.binding()
        previous_depth = link.depth

    try:
        proof = LeafProof.decode(leaf_proof)
    except (ValueError, TypeError) as err:
        return fail(f"leaf proof: {err}")
    if proof.binding != previous_hash:
        return fail("leaf proof is bound to a different record than the chain leaf")
    try:
        decode_public_key(previous.subject).verify(
            b64u_decode(proof.signature), signing_input(POSSESSION_TYPE, POSSESSION_VERSION, proof.signable_fields())
        )
    except (InvalidSignature, ValueError, binascii.Error):
        return fail("leaf proof: invalid signature")
    if proof.iat > now + CLOCK_SKEW_SECONDS:
        return fail("leaf proof: issued in the future")
    if now - proof.iat > max_proof_age_seconds:
        return fail("leaf proof: stale")

    context = ChainContext(
        task_id=root.task_id,
        tenant_id=root.tenant_id,
        root_issuer=root.issuer,
        task_root=root_binding,
        link_bindings=tuple(link.binding() for link in links),
    )
    try:
        revoked = revocation_checker.is_revoked(context)
    except RevocationSourceUnreachable as err:
        return fail(f"revocation status unavailable: {err}")
    if revoked:
        return fail("chain has been revoked")

    return ChainVerifyResult(valid=True, reason="ok", root=root, links=tuple(links), checked_at=now)


def _check_link(
    link: ChainLink,
    previous: TaskRoot | ChainLink,
    previous_hash: str,
    previous_depth: int,
    root: TaskRoot,
    root_binding: str,
    now: int,
) -> str | None:
    if (link.task_id, link.tenant_id) != (root.task_id, root.tenant_id):
        return "task or tenant differs from the root"
    if link.task_root != root_binding:
        return "bound to a different task root"
    if link.issuer != previous.subject:
        return "issuer is not the previous subject"
    if link.parent_hash != previous_hash:
        return "parent_hash does not match the previous record"
    if link.depth != previous_depth + 1:
        return "depth does not increment by one"
    try:
        decode_public_key(link.issuer).verify(b64u_decode(link.proof), link.signing_bytes())
    except (InvalidSignature, ValueError, binascii.Error):
        return "invalid signature"
    if not scope_narrows(previous.scope, link.scope):
        return "scope does not narrow the previous scope"
    if link.budget > previous.budget:
        return "budget exceeds the previous budget"
    if link.expires_at > previous.expires_at:
        return "expires after the previous record"
    if now >= link.expires_at:
        return "expired"
    if link.issued_at < previous.issued_at:
        return "issued before the previous record"
    if link.issued_at > now + CLOCK_SKEW_SECONDS:
        return "not yet valid"
    return None
