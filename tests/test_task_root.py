from __future__ import annotations

import base64
import dataclasses
import json

import pytest

from agent_warrant.canonical import canonicalize, signing_input
from agent_warrant.exceptions import RevocationSourceUnreachable
from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.resolver import PinnedResolver
from agent_warrant.task_root import (
    MAX_CHAIN_DEPTH,
    MAX_TTL,
    TaskRoot,
    issue_task_root,
    verify_root,
)
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance

NOW = 1_000_000
POLICY = IssuerTrustPolicy(
    {
        "issuer-a": IssuerAllowance(
            tenants={"tenant-1": TenantAllowance(principals={"alice"})}, max_budget=100, max_depth=3
        )
    }
)


class FakeRevocation:
    def __init__(self, revoked=(), unreachable=False):
        self.revoked = set(revoked)
        self.unreachable = unreachable
        self.calls = []

    def is_revoked(self, issuer, binding):
        self.calls.append((issuer, binding))
        if self.unreachable:
            raise RevocationSourceUnreachable("down")
        return binding in self.revoked


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture
def issuer_key():
    return generate_keypair()


@pytest.fixture
def resolver(issuer_key):
    return PinnedResolver({"issuer-a": issuer_key.public_key()})


def make_fields(**overrides):
    fields = {
        "issuer": "issuer-a",
        "task_id": "task-1",
        "tenant_id": "tenant-1",
        "principal": "alice",
        "purpose": "deploy",
        "budget": 100,
        "max_depth": 3,
        "issued_at": NOW,
        "expires_at": NOW + 300,
        "subject": encode_public_key(generate_keypair().public_key()),
    }
    fields.update(overrides)
    return fields


def make_root(issuer_key, **overrides):
    return issue_task_root(issuer_key, **make_fields(**overrides))


def forge(issuer_key, body_fields, tag_type="task-root", version=1, raw_body=None):
    body = raw_body if raw_body is not None else canonicalize(body_fields)
    signature = issuer_key.sign(signing_input(tag_type, version, body_fields))
    return f"{b64u(body)}.{b64u(signature)}"


def test_issue_encode_decode_roundtrip(issuer_key):
    root = make_root(issuer_key)
    assert TaskRoot.decode(root.encode()) == root


def test_valid_root_verifies(issuer_key, resolver):
    root = make_root(issuer_key)
    result = verify_root(root.encode(), resolver, POLICY, FakeRevocation(), NOW)
    assert result.valid is True
    assert result.reason == "ok"
    assert result.root == root


def test_verification_needs_no_possession_proof(issuer_key, resolver):
    root = make_root(issuer_key)
    assert verify_root(root.encode(), resolver, POLICY, FakeRevocation(), NOW).valid is True


def test_tampered_body_fails_signature(issuer_key, resolver):
    root = make_root(issuer_key)
    tampered = dataclasses.replace(root, budget=999)
    result = verify_root(tampered.encode(), resolver, POLICY, FakeRevocation(), NOW)
    assert (result.valid, result.reason) == (False, "invalid issuer signature")


def test_wrong_signing_key_fails(resolver):
    root = make_root(generate_keypair())
    result = verify_root(root.encode(), resolver, POLICY, FakeRevocation(), NOW)
    assert (result.valid, result.reason) == (False, "invalid issuer signature")


def test_unresolvable_issuer_fails(issuer_key):
    root = make_root(issuer_key)
    result = verify_root(root.encode(), PinnedResolver({}), POLICY, FakeRevocation(), NOW)
    assert result.valid is False
    assert result.reason.startswith("unresolvable issuer")


def test_expired_root_fails(issuer_key, resolver):
    root = make_root(issuer_key)
    result = verify_root(root.encode(), resolver, POLICY, FakeRevocation(), root.expires_at)
    assert (result.valid, result.reason) == (False, "task root has expired")


def test_last_valid_second_passes(issuer_key, resolver):
    root = make_root(issuer_key)
    assert verify_root(root.encode(), resolver, POLICY, FakeRevocation(), root.expires_at - 1).valid is True


def test_issued_in_future_beyond_skew_fails(issuer_key, resolver):
    root = make_root(issuer_key)
    result = verify_root(root.encode(), resolver, POLICY, FakeRevocation(), NOW - 6)
    assert (result.valid, result.reason) == (False, "task root is not yet valid")


def test_issued_within_skew_passes(issuer_key, resolver):
    root = make_root(issuer_key)
    assert verify_root(root.encode(), resolver, POLICY, FakeRevocation(), NOW - 5).valid is True


def test_revoked_root_fails(issuer_key, resolver):
    root = make_root(issuer_key)
    result = verify_root(root.encode(), resolver, POLICY, FakeRevocation({root.binding()}), NOW)
    assert (result.valid, result.reason) == (False, "task root has been revoked")


def test_revocation_checked_with_authenticated_issuer_and_binding(issuer_key, resolver):
    root = make_root(issuer_key)
    checker = FakeRevocation()
    verify_root(root.encode(), resolver, POLICY, checker, NOW)
    assert checker.calls == [("issuer-a", root.binding())]


def test_unreachable_revocation_fails_closed(issuer_key, resolver):
    root = make_root(issuer_key)
    result = verify_root(root.encode(), resolver, POLICY, FakeRevocation(unreachable=True), NOW)
    assert result.valid is False
    assert result.reason.startswith("revocation status unavailable")


def test_invalid_root_never_reaches_revocation_lookup(issuer_key, resolver):
    root = make_root(issuer_key)
    checker = FakeRevocation()
    verify_root(dataclasses.replace(root, budget=1).encode(), resolver, POLICY, checker, NOW)
    assert checker.calls == []


def test_non_integer_now_fails_closed(issuer_key, resolver):
    root = make_root(issuer_key)
    for now in (float(NOW), True, None, "1"):
        assert verify_root(root.encode(), resolver, POLICY, FakeRevocation(), now).valid is False


@pytest.mark.parametrize("encoded", ["", ".", "a.", ".b", "a.b.c", "!!!.sig", 5, None, b"x", "x" * 20000])
def test_malformed_encodings_fail_closed(resolver, encoded):
    result = verify_root(encoded, resolver, POLICY, FakeRevocation(), NOW)
    assert result.valid is False
    assert result.reason.startswith("malformed task root")


def test_non_canonical_base64_is_refused(issuer_key, resolver):
    root = make_root(issuer_key)
    body, proof = root.encode().split(".")
    assert verify_root(body + "=." + proof, resolver, POLICY, FakeRevocation(), NOW).valid is False
    assert verify_root(body + "\n." + proof, resolver, POLICY, FakeRevocation(), NOW).valid is False


def test_unknown_key_is_refused(issuer_key, resolver):
    fields = {**make_fields(), "extra": 1}
    result = verify_root(forge(issuer_key, fields), resolver, POLICY, FakeRevocation(), NOW)
    assert result.valid is False
    assert "unknown keys: extra" in result.reason


def test_missing_key_is_refused(issuer_key, resolver):
    fields = make_fields()
    del fields["purpose"]
    result = verify_root(forge(issuer_key, fields), resolver, POLICY, FakeRevocation(), NOW)
    assert "missing required keys: purpose" in result.reason


def test_duplicate_key_is_refused(issuer_key, resolver):
    fields = make_fields()
    raw = json.dumps(fields)[:-1] + ', "task_id": "task-2"}'
    result = verify_root(forge(issuer_key, fields, raw_body=raw.encode()), resolver, POLICY, FakeRevocation(), NOW)
    assert "duplicate key" in result.reason


@pytest.mark.parametrize("value", [1000000.0, "1000000", True])
def test_non_integer_timestamp_is_refused(issuer_key, resolver, value):
    fields = make_fields(issued_at=value)
    raw = json.dumps(fields).encode()
    result = verify_root(forge(issuer_key, make_fields(), raw_body=raw), resolver, POLICY, FakeRevocation(), NOW)
    assert result.valid is False
    assert result.reason.startswith("malformed task root")


def test_wrong_domain_tag_does_not_verify_as_task_root(issuer_key, resolver):
    encoded = forge(issuer_key, make_fields(), tag_type="chain-link")
    result = verify_root(encoded, resolver, POLICY, FakeRevocation(), NOW)
    assert (result.valid, result.reason) == (False, "invalid issuer signature")


def test_wrong_version_tag_does_not_verify(issuer_key, resolver):
    result = verify_root(forge(issuer_key, make_fields(), version=2), resolver, POLICY, FakeRevocation(), NOW)
    assert (result.valid, result.reason) == (False, "invalid issuer signature")


def test_untagged_signature_does_not_verify(issuer_key, resolver):
    fields = make_fields()
    body = canonicalize(fields)
    encoded = f"{b64u(body)}.{b64u(issuer_key.sign(body))}"
    result = verify_root(encoded, resolver, POLICY, FakeRevocation(), NOW)
    assert (result.valid, result.reason) == (False, "invalid issuer signature")


def test_v1_grant_encoding_is_not_a_task_root(issuer_key, resolver):
    from agent_warrant.grant import CURRENT_VERSION, sign

    grant = sign(
        {
            "version": CURRENT_VERSION,
            "issuer": "issuer-a",
            "subject": make_fields()["subject"],
            "scope": {"tool": "x"},
            "issued_at": NOW,
            "expires_at": NOW + 300,
        },
        issuer_key,
    )
    result = verify_root(grant.encode(), resolver, POLICY, FakeRevocation(), NOW)
    assert result.valid is False
    assert result.reason.startswith("malformed task root")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"budget": -1}, "budget"),
        ({"budget": 2**53}, "budget"),
        ({"budget": True}, "budget must be an integer"),
        ({"budget": 1.5}, "budget must be an integer"),
        ({"max_depth": -1}, "max_depth"),
        ({"max_depth": MAX_CHAIN_DEPTH + 1}, "max_depth must not exceed"),
        ({"expires_at": NOW}, "expires_at must be after issued_at"),
        ({"expires_at": NOW - 1}, "expires_at must be after issued_at"),
        ({"expires_at": NOW + MAX_TTL + 1}, "lifetime must not exceed"),
        ({"issued_at": -1}, "issued_at"),
        ({"task_id": ""}, "task_id must be a non-empty string"),
        ({"tenant_id": 5}, "tenant_id must be a non-empty string"),
        ({"purpose": "p" * 257}, "purpose is longer than"),
        ({"subject": "not-a-key"}, "subject is not a canonical"),
        ({"subject": "AAAA"}, "subject is not a canonical"),
    ],
)
def test_issue_refuses_invalid_fields(issuer_key, overrides, message):
    with pytest.raises(ValueError, match=message):
        make_root(issuer_key, **overrides)


def test_boundary_values_accepted(issuer_key, resolver):
    root = make_root(issuer_key, budget=0, max_depth=MAX_CHAIN_DEPTH, expires_at=NOW + MAX_TTL)
    wide = IssuerTrustPolicy(
        {
            "issuer-a": IssuerAllowance(
                tenants={"tenant-1": TenantAllowance(principals={"alice"})}, max_budget=0, max_depth=MAX_CHAIN_DEPTH
            )
        }
    )
    assert verify_root(root.encode(), resolver, wide, FakeRevocation(), NOW).valid is True


def test_signed_invalid_fields_are_refused_at_verify(issuer_key, resolver):
    fields = make_fields(budget=-5)
    result = verify_root(forge(issuer_key, fields), resolver, POLICY, FakeRevocation(), NOW)
    assert result.valid is False
    assert "budget" in result.reason


def test_binding_differs_per_root(issuer_key):
    assert make_root(issuer_key).binding() != make_root(issuer_key, task_id="task-2").binding()


def test_static_revocation_checker_integration(issuer_key, resolver):
    from agent_warrant.revocation import StaticRevocationChecker, sign_revocation_list

    root = make_root(issuer_key)
    revocation_list = sign_revocation_list(
        "issuer-a", [root.binding()], issuer_key, issued_at=float(NOW), sequence=1, ttl_seconds=600.0
    )
    checker = StaticRevocationChecker(revocation_list, resolver, now=float(NOW))
    assert verify_root(root.encode(), resolver, POLICY, checker, NOW).reason == "task root has been revoked"


WEAK_SUBJECTS = {
    "identity": bytes([1]) + bytes(31),
    "order-2": (2**255 - 20).to_bytes(32, "little"),
    "order-4": bytes(32),
    "order-8": bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    "y-equals-p-plus-1": (2**255 - 18).to_bytes(32, "little"),
}


@pytest.mark.parametrize("name", sorted(WEAK_SUBJECTS))
def test_issue_refuses_weak_subject_keys(issuer_key, name):
    with pytest.raises(ValueError, match="subject is not a canonical"):
        make_root(issuer_key, subject=b64u(WEAK_SUBJECTS[name]))


@pytest.mark.parametrize("name", sorted(WEAK_SUBJECTS))
def test_verify_refuses_signed_root_with_weak_subject(issuer_key, resolver, name):
    fields = make_fields(subject=b64u(WEAK_SUBJECTS[name]))
    result = verify_root(forge(issuer_key, fields), resolver, POLICY, FakeRevocation(), NOW)
    assert result.valid is False
    assert "subject is not a canonical" in result.reason


BAD_IDS = {
    "space": "svc: a",
    "tab": "a\tb",
    "newline": "a\nb",
    "nul": "a\x00b",
    "del": "a\x7fb",
    "bidi-override": "svc:team-a\u202eadmin",
    "zero-width-space": "a\u200bb",
    "non-ascii": "caf\u00e9",
    "leading-space": " a",
    "trailing-space": "a ",
}


@pytest.mark.parametrize("field", ["task_id", "tenant_id", "principal", "purpose", "issuer"])
@pytest.mark.parametrize("name", sorted(BAD_IDS))
def test_issue_refuses_non_printable_or_non_ascii_ids(issuer_key, field, name):
    with pytest.raises(ValueError, match=f"{field} must be ASCII printable"):
        make_root(issuer_key, **{field: BAD_IDS[name]})


@pytest.mark.parametrize("field", ["task_id", "tenant_id", "principal", "purpose", "issuer"])
def test_verify_refuses_signed_root_with_bad_id(issuer_key, resolver, field):
    fields = make_fields(**{field: "a\x00b"})
    result = verify_root(forge(issuer_key, fields), resolver, POLICY, FakeRevocation(), NOW)
    assert result.valid is False
    assert f"{field} must be ASCII printable" in result.reason


def test_all_printable_ascii_ids_are_accepted(issuer_key):
    printable = "".join(chr(code) for code in range(0x21, 0x7F))
    root = make_root(issuer_key, task_id=printable, purpose=printable)
    assert TaskRoot.decode(root.encode()) == root


def reencoded(issuer_key, fields, body):
    signature = issuer_key.sign(signing_input("task-root", 1, fields))
    return f"{b64u(body)}.{b64u(signature)}"


def test_reordered_keys_are_refused_even_with_a_valid_signature(issuer_key, resolver):
    fields = make_fields()
    body = json.dumps(fields, separators=(",", ":")).encode()
    assert body != canonicalize(fields)
    result = verify_root(reencoded(issuer_key, fields, body), resolver, POLICY, FakeRevocation(), NOW)
    assert (result.valid, result.reason) == (False, "malformed task root: body is not in canonical form")


def test_whitespace_in_body_is_refused(issuer_key, resolver):
    fields = make_fields()
    body = json.dumps(fields, sort_keys=True).encode()
    result = verify_root(reencoded(issuer_key, fields, body), resolver, POLICY, FakeRevocation(), NOW)
    assert result.reason == "malformed task root: body is not in canonical form"


def test_escaped_characters_are_refused(issuer_key, resolver):
    fields = make_fields()
    body = canonicalize(fields).replace(b'"alice"', b'"\\u0061lice"')
    result = verify_root(reencoded(issuer_key, fields, body), resolver, POLICY, FakeRevocation(), NOW)
    assert result.reason == "malformed task root: body is not in canonical form"


def test_exactly_one_encoding_verifies(issuer_key, resolver):
    root = make_root(issuer_key)
    assert verify_root(root.encode(), resolver, POLICY, FakeRevocation(), NOW).valid is True
    assert TaskRoot.decode(root.encode()).encode() == root.encode()
