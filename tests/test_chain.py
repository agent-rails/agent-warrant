from __future__ import annotations

import dataclasses

import pytest

from agent_warrant.canonical import signing_input
from agent_warrant.chain import (
    MAX_CHAIN_ENCODED_BYTES,
    ChainLink,
    LeafProof,
    delegate,
    prove_leaf,
    verify_chain,
)
from agent_warrant.encoding import b64u
from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.resolver import PinnedResolver
from agent_warrant.task_root import issue_task_root
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance

NOW = 1_000_000
SCOPE = {"tools": ["deploy.*", "read"], "resources": ["env/*"], "max_cost_per_call": 5}
POLICY = IssuerTrustPolicy(
    {
        "issuer-a": IssuerAllowance(
            tenants={"t1": TenantAllowance(principals={"alice"}), "t2": TenantAllowance(principals={"alice"})},
            max_budget=1000,
            max_depth=16,
        )
    }
)


class NeverRevoked:
    def is_revoked(self, issuer, binding):
        return False


class Revoked:
    def __init__(self, bindings):
        self.bindings = set(bindings)

    def is_revoked(self, issuer, binding):
        return binding in self.bindings


def pub(key):
    return encode_public_key(key.public_key())


class World:
    def __init__(self, max_depth=3, tenant="t1", task="task-1", budget=100, ttl=3600):
        self.issuer_key = generate_keypair()
        self.resolver = PinnedResolver({"issuer-a": self.issuer_key.public_key()})
        self.keys = [generate_keypair() for _ in range(6)]
        self.root = issue_task_root(
            self.issuer_key,
            issuer="issuer-a",
            task_id=task,
            tenant_id=tenant,
            principal="alice",
            purpose="deploy",
            budget=budget,
            max_depth=max_depth,
            issued_at=NOW,
            expires_at=NOW + ttl,
            scope=SCOPE,
            subject=pub(self.keys[0]),
        )

    def link(self, parent, depth_index, **overrides):
        args = {
            "child_subject": pub(self.keys[depth_index + 1]),
            "scope": parent.scope,
            "budget": parent.budget,
            "ttl": 600,
            "now": NOW,
        }
        args.update(overrides)
        return delegate(self.root, parent, self.keys[depth_index], **args)

    def chain(self, length, **overrides):
        links = []
        parent = self.root
        for index in range(length):
            parent = self.link(parent, index, **overrides)
            links.append(parent)
        return links

    def forge(self, signer, parent, subject_index=1, **overrides):
        tag = overrides.pop("_tag", "chain-link")
        depth = 1 if parent is self.root else parent.depth + 1
        fields = {
            "task_id": self.root.task_id,
            "tenant_id": self.root.tenant_id,
            "task_root": self.root.binding(),
            "parent_hash": parent.binding(),
            "issuer": parent.subject,
            "subject": pub(self.keys[subject_index]),
            "scope": parent.scope,
            "budget": parent.budget,
            "depth": depth,
            "issued_at": NOW,
            "expires_at": parent.expires_at,
        }
        fields.update(overrides)
        signature = signer.sign(signing_input(tag, 1, fields))
        return ChainLink(**fields, proof=b64u(signature))

    def verify(self, links, holder_key=None, leaf=None, now=NOW, checker=None, root=None, proof_iat=None, **kwargs):
        leaf = leaf if leaf is not None else (links[-1] if links else self.root)
        holder = holder_key if holder_key is not None else self.keys[len(links)]
        proof = prove_leaf(leaf, holder, now if proof_iat is None else proof_iat).encode()
        return verify_chain(
            (root or self.root).encode(),
            [link.encode() for link in links],
            proof,
            self.resolver,
            POLICY,
            checker or NeverRevoked(),
            now,
            **kwargs,
        )


@pytest.fixture
def world():
    return World()


@pytest.mark.parametrize("length", [1, 2, 3])
def test_valid_chains_of_each_depth_verify(world, length):
    links = world.chain(length)
    result = world.verify(links)
    assert (result.valid, result.reason) == (True, "ok")
    assert result.links == tuple(links)
    assert result.leaf_subject == links[-1].subject
    assert result.leaf_scope == links[-1].scope


def test_root_only_chain_needs_the_root_subject_key(world):
    assert world.verify([]).valid is True
    assert world.verify([], holder_key=generate_keypair()).valid is False


def test_narrowing_scope_and_budget_along_the_chain(world):
    first = world.link(
        world.root, 0, scope={"tools": ["deploy.prod.*"], "resources": ["env/prod"], "max_cost_per_call": 3}, budget=50
    )
    second = world.link(
        first, 1, scope={"tools": ["deploy.prod.eu"], "resources": ["env/prod"], "max_cost_per_call": 1}, budget=10
    )
    assert world.verify([first, second]).valid is True


def test_encoded_round_trip(world):
    link = world.chain(1)[0]
    assert ChainLink.decode(link.encode()) == link


def test_leaf_proof_round_trip(world):
    proof = prove_leaf(world.root, world.keys[0], NOW)
    assert LeafProof.decode(proof.encode()) == proof


def test_delegate_refuses_key_that_is_not_the_parents_subject(world):
    with pytest.raises(ValueError, match="parent's subject"):
        delegate(
            world.root,
            world.root,
            generate_keypair(),
            child_subject=pub(world.keys[1]),
            scope=SCOPE,
            budget=1,
            ttl=10,
            now=NOW,
        )


def test_delegate_refuses_wider_scope(world):
    with pytest.raises(ValueError, match="narrow"):
        world.link(
            world.root, 0, scope={"tools": ["deploy.*", "admin"], "resources": ["env/*"], "max_cost_per_call": 5}
        )


def test_delegate_refuses_higher_cost(world):
    with pytest.raises(ValueError, match="narrow"):
        world.link(world.root, 0, scope={**SCOPE, "max_cost_per_call": 6})


def test_delegate_refuses_higher_budget(world):
    with pytest.raises(ValueError, match="budget"):
        world.link(world.root, 0, budget=101)


@pytest.mark.parametrize("budget", [-1, True, 1.5])
def test_delegate_refuses_bad_budget(world, budget):
    with pytest.raises(ValueError, match="budget"):
        world.link(world.root, 0, budget=budget)


@pytest.mark.parametrize("ttl", [0, -5, True, 1.5])
def test_delegate_refuses_bad_ttl(world, ttl):
    with pytest.raises(ValueError, match="ttl"):
        world.link(world.root, 0, ttl=ttl)


def test_delegate_clamps_expiry_to_parent(world):
    link = world.link(world.root, 0, ttl=10**6)
    assert link.expires_at == world.root.expires_at
    assert world.verify([link]).valid is True


def test_delegate_uses_ttl_when_shorter_than_parent(world):
    assert world.link(world.root, 0, ttl=60).expires_at == NOW + 60


def test_delegate_refuses_depth_over_root_max():
    world = World(max_depth=1)
    first = world.link(world.root, 0)
    with pytest.raises(ValueError, match="max_depth"):
        world.link(first, 1)


def test_delegate_refuses_when_root_allows_no_delegation():
    world = World(max_depth=0)
    with pytest.raises(ValueError, match="max_depth"):
        world.link(world.root, 0)


def test_delegate_refuses_expired_or_future_parent(world):
    with pytest.raises(ValueError, match="not valid at now"):
        world.link(world.root, 0, now=world.root.expires_at)
    with pytest.raises(ValueError, match="not valid at now"):
        world.link(world.root, 0, now=NOW - 1)


def test_delegate_refuses_invalid_child_subject(world):
    with pytest.raises(ValueError, match="subject"):
        world.link(world.root, 0, child_subject="nope")


def test_delegate_refuses_parent_from_another_root(world):
    other = World()
    foreign = other.chain(1)[0]
    with pytest.raises(ValueError, match="does not belong"):
        delegate(
            world.root, foreign, other.keys[1], child_subject=pub(world.keys[2]), scope=SCOPE, budget=1, ttl=10, now=NOW
        )


def test_delegate_refuses_non_record_parent(world):
    with pytest.raises(TypeError):
        delegate(
            world.root, "x", world.keys[0], child_subject=pub(world.keys[1]), scope=SCOPE, budget=1, ttl=10, now=NOW
        )


def test_stolen_root_alone_cannot_produce_a_valid_chain(world):
    thief = generate_keypair()
    with pytest.raises(ValueError, match="parent's subject"):
        delegate(world.root, world.root, thief, child_subject=pub(thief), scope=SCOPE, budget=1, ttl=10, now=NOW)
    forged = world.forge(thief, world.root, subject_index=5)
    result = world.verify([forged], holder_key=world.keys[5])
    assert (result.valid, result.reason) == (False, "link 1: invalid signature")


def test_stolen_root_cannot_pass_with_a_thief_proof(world):
    result = world.verify([], holder_key=generate_keypair())
    assert (result.valid, result.reason) == (False, "leaf proof: invalid signature")


def test_first_link_issuer_must_be_root_subject(world):
    rogue = generate_keypair()
    forged = world.forge(rogue, world.root, issuer=pub(rogue))
    result = world.verify([forged])
    assert (result.valid, result.reason) == (False, "link 1: issuer is not the previous subject")


def test_leaf_proof_from_wrong_holder_fails(world):
    links = world.chain(2)
    result = world.verify(links, holder_key=world.keys[1])
    assert (result.valid, result.reason) == (False, "leaf proof: invalid signature")


def test_leaf_proof_bound_to_an_earlier_record_fails(world):
    links = world.chain(2)
    result = world.verify(links, leaf=links[0], holder_key=world.keys[2])
    assert (result.valid, result.reason) == (False, "leaf proof is bound to a different record than the chain leaf")


def test_missing_leaf_proof_fails(world):
    links = world.chain(1)
    for proof in ("", ".", "x"):
        result = verify_chain(
            world.root.encode(), [links[0].encode()], proof, world.resolver, POLICY, NeverRevoked(), NOW
        )
        assert result.valid is False
        assert result.reason.startswith("leaf proof:")


def test_stale_leaf_proof_fails(world):
    links = world.chain(1)
    result = world.verify(links, proof_iat=NOW - 61)
    assert (result.valid, result.reason) == (False, "leaf proof: stale")


def test_leaf_proof_at_max_age_passes(world):
    assert world.verify(world.chain(1), proof_iat=NOW - 60).valid is True


def test_future_leaf_proof_fails(world):
    result = world.verify(world.chain(1), proof_iat=NOW + 6)
    assert (result.valid, result.reason) == (False, "leaf proof: issued in the future")


def test_max_proof_age_is_configurable(world):
    assert world.verify(world.chain(1), proof_iat=NOW - 10, max_proof_age_seconds=5).valid is False


def test_leaf_proof_is_not_a_link_or_root_signature(world):
    proof = prove_leaf(world.root, world.keys[0], NOW)
    fields = proof.signable_fields()
    rewrapped = world.keys[0].sign(signing_input("chain-link", 1, fields))
    assert proof.signature != b64u(rewrapped)


def test_reordered_links_fail(world):
    first, second, third = world.chain(3)
    result = world.verify([second, first, third], holder_key=world.keys[3])
    assert result.valid is False
    assert result.reason.startswith("link 1:")


def test_duplicated_link_fails(world):
    first = world.chain(1)[0]
    result = world.verify([first, first], holder_key=world.keys[1])
    assert result.valid is False
    assert result.reason.startswith("link 2:")


def test_skipped_link_fails(world):
    first, second, third = world.chain(3)
    result = world.verify([first, third], holder_key=world.keys[3])
    assert result.valid is False
    assert result.reason.startswith("link 2:")


def test_cross_task_splice_fails():
    one, two = World(task="task-1"), World(task="task-2")
    two.issuer_key = one.issuer_key
    spliced = two.chain(1)[0]
    result = one.verify([spliced], holder_key=two.keys[1])
    assert result.valid is False


def test_cross_task_splice_with_shared_keys_fails_on_task_id():
    one = World(task="task-1")
    other_root = issue_task_root(
        one.issuer_key,
        issuer="issuer-a",
        task_id="task-2",
        tenant_id="t1",
        principal="alice",
        purpose="deploy",
        budget=100,
        max_depth=3,
        issued_at=NOW,
        expires_at=NOW + 3600,
        scope=SCOPE,
        subject=pub(one.keys[0]),
    )
    foreign = delegate(
        other_root, other_root, one.keys[0], child_subject=pub(one.keys[1]), scope=SCOPE, budget=1, ttl=60, now=NOW
    )
    result = one.verify([foreign], holder_key=one.keys[1])
    assert (result.valid, result.reason) == (False, "link 1: task or tenant differs from the root")


def test_cross_tenant_splice_fails_on_tenant():
    one = World(tenant="t1")
    other_root = issue_task_root(
        one.issuer_key,
        issuer="issuer-a",
        task_id="task-1",
        tenant_id="t2",
        principal="alice",
        purpose="deploy",
        budget=100,
        max_depth=3,
        issued_at=NOW,
        expires_at=NOW + 3600,
        scope=SCOPE,
        subject=pub(one.keys[0]),
    )
    foreign = delegate(
        other_root, other_root, one.keys[0], child_subject=pub(one.keys[1]), scope=SCOPE, budget=1, ttl=60, now=NOW
    )
    result = one.verify([foreign], holder_key=one.keys[1])
    assert (result.valid, result.reason) == (False, "link 1: task or tenant differs from the root")


def test_same_task_and_tenant_but_different_root_binding_fails(world):
    reissued = issue_task_root(
        world.issuer_key,
        issuer="issuer-a",
        task_id="task-1",
        tenant_id="t1",
        principal="alice",
        purpose="deploy",
        budget=100,
        max_depth=3,
        issued_at=NOW,
        expires_at=NOW + 3600,
        scope=SCOPE,
        subject=pub(world.keys[0]),
    )
    reissued = dataclasses.replace(reissued)
    other = issue_task_root(
        world.issuer_key,
        issuer="issuer-a",
        task_id="task-1",
        tenant_id="t1",
        principal="alice",
        purpose="other",
        budget=100,
        max_depth=3,
        issued_at=NOW,
        expires_at=NOW + 3600,
        scope=SCOPE,
        subject=pub(world.keys[0]),
    )
    foreign = delegate(
        other, other, world.keys[0], child_subject=pub(world.keys[1]), scope=SCOPE, budget=1, ttl=60, now=NOW
    )
    result = world.verify([foreign], holder_key=world.keys[1])
    assert (result.valid, result.reason) == (False, "link 1: bound to a different task root")


def test_chain_longer_than_max_depth_fails():
    world = World(max_depth=2)
    links = world.chain(2)
    extra = world.forge(world.keys[2], links[-1], subject_index=3, depth=3)
    result = world.verify([*links, extra], holder_key=world.keys[3])
    assert result.valid is False
    assert "over the root's max_depth 2" in result.reason


def test_depth_must_increment_by_one(world):
    forged = world.forge(world.keys[0], world.root, depth=2)
    result = world.verify([forged])
    assert (result.valid, result.reason) == (False, "link 1: depth does not increment by one")


def test_depth_zero_is_malformed(world):
    forged = world.forge(world.keys[0], world.root, depth=0)
    assert world.verify([forged]).reason.startswith("link 1: depth must be between")


def test_widened_scope_fails(world):
    forged = world.forge(world.keys[0], world.root, scope={**SCOPE, "tools": ["deploy.*", "admin"]})
    result = world.verify([forged])
    assert (result.valid, result.reason) == (False, "link 1: scope does not narrow the previous scope")


def test_widened_scope_at_second_hop_fails(world):
    first = world.link(world.root, 0, scope={"tools": ["read"], "resources": ["env/*"], "max_cost_per_call": 5})
    forged = world.forge(world.keys[1], first, scope=SCOPE)
    assert (
        world.verify([first, forged], holder_key=world.keys[2]).reason
        == "link 2: scope does not narrow the previous scope"
    )


def test_higher_budget_fails(world):
    forged = world.forge(world.keys[0], world.root, budget=101)
    assert world.verify([forged]).reason == "link 1: budget exceeds the previous budget"


def test_later_expiry_than_parent_fails(world):
    forged = world.forge(world.keys[0], world.root, expires_at=world.root.expires_at + 1)
    assert world.verify([forged]).reason == "link 1: expires after the previous record"


def test_expired_link_fails(world):
    link = world.link(world.root, 0, ttl=60)
    result = world.verify([link], now=link.expires_at)
    assert (result.valid, result.reason) == (False, "link 1: expired")


def test_issued_before_parent_fails(world):
    forged = world.forge(world.keys[0], world.root, issued_at=NOW - 1)
    assert world.verify([forged]).reason == "link 1: issued before the previous record"


def test_issued_in_future_fails(world):
    forged = world.forge(world.keys[0], world.root, issued_at=NOW + 6, expires_at=NOW + 100)
    assert world.verify([forged]).reason == "link 1: not yet valid"


def test_issued_within_skew_passes(world):
    forged = world.forge(world.keys[0], world.root, issued_at=NOW + 5, expires_at=NOW + 100)
    assert world.verify([forged]).valid is True


def test_tampered_link_fails_signature(world):
    link = world.chain(1)[0]
    tampered = dataclasses.replace(link, budget=link.budget - 1)
    assert world.verify([tampered]).reason == "link 1: invalid signature"


def test_link_signed_under_another_tag_fails(world):
    forged = world.forge(world.keys[0], world.root, _tag="task-root")
    assert world.verify([forged]).reason.startswith("link 1:")


def test_link_signed_with_possession_tag_fails():
    world = World()
    fields = {
        "task_id": world.root.task_id,
        "tenant_id": world.root.tenant_id,
        "task_root": world.root.binding(),
        "parent_hash": world.root.binding(),
        "issuer": world.root.subject,
        "subject": pub(world.keys[1]),
        "scope": SCOPE,
        "budget": 1,
        "depth": 1,
        "issued_at": NOW,
        "expires_at": NOW + 10,
    }
    signature = world.keys[0].sign(signing_input("possession", 1, fields))
    link = ChainLink(**fields, proof=b64u(signature))
    assert world.verify([link]).reason == "link 1: invalid signature"


def test_unknown_key_in_link_fails(world):
    link = world.chain(1)[0]
    body = link.encode().split(".")[0]
    import base64
    import json

    raw = json.loads(base64.urlsafe_b64decode(body + "=="))
    raw["extra"] = 1
    forged = b64u(json.dumps(raw).encode()) + "." + link.proof
    result = verify_chain(
        world.root.encode(),
        [forged],
        prove_leaf(link, world.keys[1], NOW).encode(),
        world.resolver,
        POLICY,
        NeverRevoked(),
        NOW,
    )
    assert result.valid is False
    assert "unknown keys: extra" in result.reason


def test_revoked_root_fails(world):
    result = world.verify(world.chain(1), checker=Revoked({world.root.binding()}))
    assert (result.valid, result.reason) == (False, "task root: task root has been revoked")


def test_root_from_unlisted_issuer_fails(world):
    result = verify_chain(
        world.root.encode(),
        [],
        prove_leaf(world.root, world.keys[0], NOW).encode(),
        world.resolver,
        IssuerTrustPolicy({}),
        NeverRevoked(),
        NOW,
    )
    assert result.valid is False
    assert result.reason.startswith("task root:")


def test_expired_root_fails(world):
    assert world.verify([], now=world.root.expires_at).reason.startswith("task root:")


def test_size_cap(world):
    big = "a" * (MAX_CHAIN_ENCODED_BYTES + 1)
    result = verify_chain(world.root.encode(), [big], "x", world.resolver, POLICY, NeverRevoked(), NOW)
    assert (result.valid, result.reason) == (False, "chain is larger than the size cap")


@pytest.mark.parametrize(
    ("root", "links", "proof"),
    [
        (None, [], ""),
        ("", [], ""),
        ("x.y", [], "x.y"),
        ("ROOT", "notalist", "p"),
        ("ROOT", [None], "p"),
        ("ROOT", [5], "p"),
        ("ROOT", [], None),
        ("ROOT", ["bad"], "p"),
        ("ROOT", ["a.b"], "p"),
    ],
)
def test_malformed_inputs_fail_closed(world, root, links, proof):
    root = world.root.encode() if root == "ROOT" else root
    result = verify_chain(root, links, proof, world.resolver, POLICY, NeverRevoked(), NOW)
    assert result.valid is False


@pytest.mark.parametrize("now", [None, 1.5, True, "1"])
def test_non_integer_now_fails_closed(world, now):
    result = verify_chain(world.root.encode(), [], "p", world.resolver, POLICY, NeverRevoked(), now)
    assert result.valid is False


def test_failed_results_carry_no_authority(world):
    result = world.verify(world.chain(1), holder_key=generate_keypair())
    assert result.valid is False
    assert result.leaf_subject is None and result.leaf_scope is None


def test_binding_is_unique_per_link(world):
    links = world.chain(3)
    assert len({link.binding() for link in links} | {world.root.binding()}) == 4
