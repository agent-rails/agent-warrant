from __future__ import annotations

import pytest

from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.resolver import PinnedResolver
from agent_warrant.task_root import issue_task_root, verify_root
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance

NOW = 1_000_000


class NeverRevoked:
    def __init__(self):
        self.calls = 0

    def is_revoked(self, issuer, binding):
        self.calls += 1
        return False


class CountingResolver(PinnedResolver):
    def __init__(self, known):
        super().__init__(known)
        self.calls = 0

    def resolve(self, issuer):
        self.calls += 1
        return super().resolve(issuer)


def allowance(tenants=("t1",), principals=("alice",), principal_prefixes=(), max_budget=100, max_depth=3):
    return IssuerAllowance(
        tenants={
            tenant: TenantAllowance(principals=principals, principal_prefixes=principal_prefixes) for tenant in tenants
        },
        max_budget=max_budget,
        max_depth=max_depth,
    )


def issue(key, **overrides):
    fields = {
        "issuer": "issuer-a",
        "task_id": "task-1",
        "tenant_id": "t1",
        "principal": "alice",
        "purpose": "deploy",
        "budget": 100,
        "max_depth": 3,
        "issued_at": NOW,
        "expires_at": NOW + 300,
        "scope": {"tools": ["deploy.*"], "resources": ["env/*"], "max_cost_per_call": 5},
        "subject": encode_public_key(generate_keypair().public_key()),
    }
    fields.update(overrides)
    return issue_task_root(key, **fields)


def run(key, policy, **overrides):
    resolver = PinnedResolver({"issuer-a": key.public_key(), "issuer-b": key.public_key()})
    root = issue(key, **overrides)
    return verify_root(root.encode(), resolver, policy, NeverRevoked(), NOW)


def test_claims_within_allowance_pass():
    key = generate_keypair()
    assert run(key, IssuerTrustPolicy({"issuer-a": allowance()})).valid is True


def test_validly_signed_root_from_unlisted_issuer_is_refused():
    key = generate_keypair()
    result = run(key, IssuerTrustPolicy({"issuer-b": allowance()}))
    assert result.valid is False
    assert result.reason == "issuer 'issuer-a' is not in the trust policy"


def test_empty_policy_refuses_everything():
    assert run(generate_keypair(), IssuerTrustPolicy({})).valid is False


def test_unlisted_issuer_is_refused_before_key_lookup_and_revocation():
    key = generate_keypair()
    resolver = CountingResolver({"issuer-a": key.public_key()})
    checker = NeverRevoked()
    encoded = issue(key).encode()
    result = verify_root(encoded, resolver, IssuerTrustPolicy({}), checker, NOW)
    assert result.valid is False
    assert (resolver.calls, checker.calls) == (0, 0)


def test_tenant_beyond_allowance_is_refused():
    result = run(generate_keypair(), IssuerTrustPolicy({"issuer-a": allowance()}), tenant_id="t2")
    assert (result.valid, result.reason) == (False, "issuer may not assert tenant 't2'")


def test_principal_beyond_allowance_is_refused():
    result = run(generate_keypair(), IssuerTrustPolicy({"issuer-a": allowance()}), principal="mallory")
    assert (result.valid, result.reason) == (False, "issuer may not assert principal 'mallory' for tenant 't1'")


def test_budget_beyond_allowance_is_refused():
    result = run(generate_keypair(), IssuerTrustPolicy({"issuer-a": allowance()}), budget=101)
    assert (result.valid, result.reason) == (False, "budget 101 exceeds issuer allowance 100")


def test_depth_beyond_allowance_is_refused():
    result = run(generate_keypair(), IssuerTrustPolicy({"issuer-a": allowance()}), max_depth=4)
    assert (result.valid, result.reason) == (False, "max_depth 4 exceeds issuer allowance 3")


def test_claim_refusal_never_reaches_revocation_lookup():
    key = generate_keypair()
    checker = NeverRevoked()
    resolver = PinnedResolver({"issuer-a": key.public_key()})
    policy = IssuerTrustPolicy({"issuer-a": allowance()})
    verify_root(issue(key, budget=101).encode(), resolver, policy, checker, NOW)
    assert checker.calls == 0


def test_principal_prefix_matches_only_when_listed():
    policy = IssuerTrustPolicy({"issuer-a": allowance(principals=set(), principal_prefixes={"svc:"})})
    key = generate_keypair()
    assert run(key, policy, principal="svc:deployer").valid is True
    assert run(key, policy, principal="svc").valid is False
    assert run(key, policy, principal="xsvc:deployer").valid is False


def test_exact_principal_is_not_a_prefix():
    policy = IssuerTrustPolicy({"issuer-a": allowance(principals={"alice"})})
    assert run(generate_keypair(), policy, principal="alice2").valid is False


def test_tenant_match_is_exact_not_prefix():
    policy = IssuerTrustPolicy({"issuer-a": allowance(tenants={"t1"})})
    assert run(generate_keypair(), policy, tenant_id="t10").valid is False


def test_allowance_at_limits_passes():
    policy = IssuerTrustPolicy({"issuer-a": allowance(max_budget=0, max_depth=0)})
    assert run(generate_keypair(), policy, budget=0, max_depth=0).valid is True


def test_each_issuer_has_its_own_allowance():
    key = generate_keypair()
    policy = IssuerTrustPolicy({"issuer-a": allowance(), "issuer-b": allowance(tenants={"t2"})})
    assert run(key, policy, issuer="issuer-b", tenant_id="t1").valid is False
    assert run(key, policy, issuer="issuer-b", tenant_id="t2").valid is True


def test_verify_root_requires_a_policy():
    key = generate_keypair()
    resolver = PinnedResolver({"issuer-a": key.public_key()})
    with pytest.raises(TypeError, match="IssuerTrustPolicy"):
        verify_root(issue(key).encode(), resolver, None, NeverRevoked(), NOW)


@pytest.mark.parametrize("name", ["principals", "principal_prefixes"])
def test_tenant_allowance_rejects_str_collection(name):
    with pytest.raises(TypeError, match=name):
        TenantAllowance(**{name: "svc:"})


@pytest.mark.parametrize("name", ["principals", "principal_prefixes"])
def test_tenant_allowance_rejects_empty_entry(name):
    with pytest.raises(ValueError, match="non-empty|principal_prefixes"):
        TenantAllowance(**{name: {""}})


@pytest.mark.parametrize("tenants", ["t1", ["t1"], {"t1"}, None])
def test_issuer_allowance_requires_a_tenant_mapping(tenants):
    with pytest.raises(TypeError, match="tenants must be a mapping"):
        IssuerAllowance(tenants=tenants, max_budget=1, max_depth=1)


def test_issuer_allowance_rejects_non_tenant_allowance_values():
    with pytest.raises(TypeError, match="TenantAllowance"):
        IssuerAllowance(tenants={"t1": {"principals": ["alice"]}}, max_budget=1, max_depth=1)


def test_issuer_allowance_rejects_empty_tenant_id():
    with pytest.raises(ValueError, match="tenant ids"):
        IssuerAllowance(tenants={"": TenantAllowance()}, max_budget=1, max_depth=1)


def test_principal_of_another_tenant_is_refused():
    shared = IssuerAllowance(
        tenants={
            "acme": TenantAllowance(principals={"acme:ceo"}),
            "globex": TenantAllowance(principals={"globex:intern"}),
        },
        max_budget=100,
        max_depth=3,
    )
    policy = IssuerTrustPolicy({"issuer-a": shared})
    key = generate_keypair()
    assert run(key, policy, tenant_id="acme", principal="acme:ceo").valid is True
    assert run(key, policy, tenant_id="globex", principal="globex:intern").valid is True
    result = run(key, policy, tenant_id="globex", principal="acme:ceo")
    assert (result.valid, result.reason) == (False, "issuer may not assert principal 'acme:ceo' for tenant 'globex'")


def test_prefixes_are_bound_to_their_tenant():
    mixed = IssuerAllowance(
        tenants={"acme": TenantAllowance(principal_prefixes={"acme:"}), "globex": TenantAllowance(principals={"g"})},
        max_budget=100,
        max_depth=3,
    )
    policy = IssuerTrustPolicy({"issuer-a": mixed})
    assert run(generate_keypair(), policy, tenant_id="globex", principal="acme:x").valid is False


def test_tenant_with_empty_allowance_permits_no_principal():
    policy = IssuerTrustPolicy(
        {"issuer-a": IssuerAllowance(tenants={"t1": TenantAllowance()}, max_budget=10, max_depth=3)}
    )
    assert run(generate_keypair(), policy).valid is False


def test_tenant_mapping_is_copied_and_read_only():
    tenants = {"t1": TenantAllowance(principals={"alice"})}
    built = IssuerAllowance(tenants=tenants, max_budget=10, max_depth=3)
    tenants.clear()
    assert "t1" in built.tenants
    with pytest.raises(TypeError):
        built.tenants["t2"] = TenantAllowance()


@pytest.mark.parametrize("name", ["max_budget", "max_depth"])
@pytest.mark.parametrize("value", [-1, True, 1.5, 2**53])
def test_allowance_rejects_bad_limits(name, value):
    with pytest.raises(ValueError, match=name):
        allowance(**{name: value})


def test_policy_rejects_non_allowance_values():
    with pytest.raises(TypeError, match="IssuerAllowance"):
        IssuerTrustPolicy({"issuer-a": {"tenants": ["t1"]}})


def test_policy_rejects_empty_issuer_id():
    with pytest.raises(ValueError, match="issuer ids"):
        IssuerTrustPolicy({"": allowance()})


def test_policy_is_not_affected_by_later_mutation_of_input():
    mapping = {"issuer-a": allowance()}
    policy = IssuerTrustPolicy(mapping)
    mapping.clear()
    assert run(generate_keypair(), policy).valid is True


@pytest.mark.parametrize("prefix", ["svc:team-a", "svc", "svc-", "svc_", ":", "/", ".", "svc:*"])
def test_prefix_without_delimiter_boundary_is_refused_at_construction(prefix):
    with pytest.raises(ValueError, match="principal_prefixes"):
        allowance(principals=set(), principal_prefixes={prefix})


@pytest.mark.parametrize("prefix", ["svc:", "svc/", "svc."])
def test_prefix_ending_in_delimiter_is_accepted(prefix):
    allowance(principals=set(), principal_prefixes={prefix})


def test_prefix_does_not_match_a_longer_sibling_segment():
    policy = IssuerTrustPolicy({"issuer-a": allowance(principals=set(), principal_prefixes={"svc:team-a:"})})
    key = generate_keypair()
    assert run(key, policy, principal="svc:team-a:deployer").valid is True
    assert run(key, policy, principal="svc:team-admin").valid is False
    assert run(key, policy, principal="svc:team-a").valid is False
