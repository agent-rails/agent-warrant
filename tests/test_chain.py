from __future__ import annotations

import dataclasses
import json

import pytest

from agent_warrant import chain as chain_module
from agent_warrant.canonical import canonicalize, signing_input
from agent_warrant.chain import (
    MAX_CHAIN_ENCODED_BYTES,
    ChainLink,
    LeafProof,
    delegate,
)
from agent_warrant.chain import (
    prove_leaf as raw_prove_leaf,
)
from agent_warrant.chain import (
    verify_chain as raw_verify_chain,
)
from agent_warrant.encoding import b64u, sha256_b64u
from agent_warrant.exceptions import RevocationSourceUnreachable
from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.resolver import PinnedResolver
from agent_warrant.task_root import issue_task_root
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance

NOW = 1_000_000
AUDIENCE = "executor-1"
REQUEST = sha256_b64u(b"request-1")
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


def prove_leaf(leaf, holder_key, now, audience=AUDIENCE, request_digest=REQUEST):
    return raw_prove_leaf(leaf, holder_key, now, audience=audience, request_digest=request_digest)


def verify_chain(*args, expected_audience=AUDIENCE, expected_request_digest=REQUEST, **kwargs):
    return raw_verify_chain(
        *args, expected_audience=expected_audience, expected_request_digest=expected_request_digest, **kwargs
    )


class NeverRevoked:
    def __init__(self):
        self.contexts = []

    def is_revoked(self, context):
        self.contexts.append(context)
        return False


class Revoked:
    def __init__(self, bindings=(), tasks=(), tenants=(), unreachable=False):
        self.bindings = set(bindings)
        self.tasks = set(tasks)
        self.tenants = set(tenants)
        self.unreachable = unreachable
        self.contexts = []

    def is_revoked(self, context):
        self.contexts.append(context)
        if self.unreachable:
            raise RevocationSourceUnreachable("down")
        return (
            context.task_id in self.tasks
            or context.tenant_id in self.tenants
            or context.task_root in self.bindings
            or any(binding in self.bindings for binding in context.link_bindings)
        )


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
    assert (result.valid, result.reason) == (False, "chain has been revoked")


def test_revoked_leaf_link_fails(world):
    links = world.chain(3)
    result = world.verify(links, checker=Revoked({links[2].binding()}))
    assert (result.valid, result.reason) == (False, "chain has been revoked")


def test_revoked_mid_chain_link_fails_the_chain_through_it(world):
    links = world.chain(3)
    result = world.verify(links, checker=Revoked({links[1].binding()}))
    assert (result.valid, result.reason) == (False, "chain has been revoked")


def test_revoked_mid_chain_link_leaves_the_prefix_valid(world):
    links = world.chain(3)
    checker = Revoked({links[1].binding()})
    assert world.verify(links[:1], checker=checker).valid is True


def test_revoked_task_fails(world):
    assert world.verify(world.chain(1), checker=Revoked(tasks={"task-1"})).valid is False


def test_revoked_tenant_fails(world):
    assert world.verify(world.chain(1), checker=Revoked(tenants={"t1"})).valid is False


def test_other_task_and_tenant_revocations_do_not_apply(world):
    assert world.verify(world.chain(1), checker=Revoked(tasks={"task-2"}, tenants={"t2"})).valid is True


def test_unreachable_revocation_source_fails_closed(world):
    result = world.verify(world.chain(2), checker=Revoked(unreachable=True))
    assert result.valid is False
    assert result.reason == "revocation status unavailable: down"


def test_revocation_context_carries_task_tenant_root_and_every_link(world):
    links = world.chain(3)
    checker = NeverRevoked()
    world.verify(links, checker=checker)
    assert len(checker.contexts) == 1
    context = checker.contexts[0]
    assert context.task_id == "task-1"
    assert context.tenant_id == "t1"
    assert context.root_issuer == "issuer-a"
    assert context.task_root == world.root.binding()
    assert context.link_bindings == tuple(link.binding() for link in links)


def test_revocation_is_not_consulted_for_an_invalid_chain(world):
    checker = NeverRevoked()
    world.verify(world.chain(1), holder_key=generate_keypair(), checker=checker)
    world.verify(world.chain(1), now=NOW + 10**6, checker=checker)
    assert checker.contexts == []


@pytest.mark.parametrize("checker", [None, object(), "checker", lambda context: False])
def test_revocation_checker_is_mandatory(world, checker):
    proof = prove_leaf(world.root, world.keys[0], NOW).encode()
    with pytest.raises(TypeError, match="ChainRevocationChecker"):
        verify_chain(world.root.encode(), [], proof, world.resolver, POLICY, checker, NOW)


def test_root_level_revocation_is_decided_only_by_the_chain_checker(world):
    class RootOnly:
        def is_revoked(self, context):
            return context.task_root == world.root.binding()

    assert world.verify(world.chain(1), checker=RootOnly()).valid is False


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


P = 2**255 - 19
WEAK_KEYS = {
    "identity": bytes([1]) + bytes(31),
    "order-2": (P - 1).to_bytes(32, "little"),
    "order-4": bytes(32),
    "order-8": bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    "y-equals-p-plus-1": (P + 1).to_bytes(32, "little"),
}


@pytest.mark.parametrize("name", sorted(WEAK_KEYS))
def test_delegate_refuses_weak_child_subject(world, name):
    with pytest.raises(ValueError, match="subject is not a canonical"):
        world.link(world.root, 0, child_subject=b64u(WEAK_KEYS[name]))


@pytest.mark.parametrize("name", sorted(WEAK_KEYS))
def test_signed_link_with_weak_subject_is_refused_at_verify(world, name):
    forged = world.forge(world.keys[0], world.root, subject=b64u(WEAK_KEYS[name]))
    result = world.verify([forged], holder_key=world.keys[1])
    assert result.valid is False
    assert "subject is not a canonical" in result.reason


@pytest.mark.parametrize("name", sorted(WEAK_KEYS))
def test_signed_link_with_weak_issuer_is_refused_at_verify(world, name):
    forged = world.forge(world.keys[0], world.root, issuer=b64u(WEAK_KEYS[name]))
    result = world.verify([forged], holder_key=world.keys[1])
    assert result.valid is False
    assert "issuer is not a canonical" in result.reason


def test_identity_point_holder_cannot_be_forged_into_a_chain(world):
    identity_subject = b64u(WEAK_KEYS["identity"])
    with pytest.raises(ValueError, match="subject is not a canonical"):
        world.link(world.root, 0, child_subject=identity_subject)


@pytest.mark.parametrize("field", ["task_id", "tenant_id"])
@pytest.mark.parametrize("value", ["a b", "a\x00b", "a\u202eb", "caf\u00e9"])
def test_link_ids_must_be_printable_ascii(world, field, value):
    forged = world.forge(world.keys[0], world.root, **{field: value})
    result = world.verify([forged])
    assert result.valid is False
    assert f"{field} must be ASCII printable" in result.reason


def sign_body(world, signer, link, body):
    signature = signer.sign(link.signing_bytes())
    return f"{b64u(body)}.{b64u(signature)}"


def test_non_canonical_link_body_is_refused_even_with_a_valid_signature(world):
    link = world.chain(1)[0]
    body = json.dumps(link.signable_fields(), separators=(",", ":")).encode()
    assert body != canonicalize(link.signable_fields())
    encoded = sign_body(world, world.keys[0], link, body)
    result = verify_chain(
        world.root.encode(),
        [encoded],
        prove_leaf(link, world.keys[1], NOW).encode(),
        world.resolver,
        POLICY,
        NeverRevoked(),
        NOW,
    )
    assert (result.valid, result.reason) == (False, "link 1: body is not in canonical form")


def test_non_canonical_leaf_proof_body_is_refused(world):
    proof = prove_leaf(world.root, world.keys[0], NOW)
    body = json.dumps(proof.signable_fields()).encode()
    assert body != canonicalize(proof.signable_fields())
    encoded = f"{b64u(body)}.{proof.signature}"
    result = verify_chain(world.root.encode(), [], encoded, world.resolver, POLICY, NeverRevoked(), NOW)
    assert (result.valid, result.reason) == (False, "leaf proof: body is not in canonical form")


def test_weak_key_holder_proof_cannot_pass_for_a_valid_chain(world):
    proof = prove_leaf(world.root, world.keys[0], NOW)
    forged = dataclasses.replace(proof, signature=b64u(bytes([1]) + bytes(63)))
    result = verify_chain(world.root.encode(), [], forged.encode(), world.resolver, POLICY, NeverRevoked(), NOW)
    assert result.valid is False


def audience_verify(world, links, proof, audience=AUDIENCE, request=REQUEST, now=NOW, **kwargs):
    return chain_module.verify_chain(
        world.root.encode(),
        [link.encode() for link in links],
        proof,
        world.resolver,
        POLICY,
        NeverRevoked(),
        now,
        expected_audience=audience,
        expected_request_digest=request,
        **kwargs,
    )


def audience_proof(world, links, holder, audience=AUDIENCE, request=REQUEST, now=NOW):
    leaf = links[-1] if links else world.root
    return chain_module.prove_leaf(leaf, holder, now, audience=audience, request_digest=request).encode()


def test_proof_bound_to_audience_and_request_verifies(world):
    links = world.chain(2)
    result = audience_verify(world, links, audience_proof(world, links, world.keys[2]))
    assert (result.valid, result.reason) == (True, "ok")


def test_proof_for_another_audience_is_refused(world):
    links = world.chain(1)
    proof = audience_proof(world, links, world.keys[1], audience="executor-2")
    result = audience_verify(world, links, proof)
    assert (result.valid, result.reason) == (False, "leaf proof: audience mismatch")


def test_proof_for_another_request_is_refused(world):
    links = world.chain(1)
    proof = audience_proof(world, links, world.keys[1], request=sha256_b64u(b"request-2"))
    result = audience_verify(world, links, proof)
    assert (result.valid, result.reason) == (False, "leaf proof: request digest mismatch")


def test_captured_chain_and_proof_cannot_be_replayed_for_a_second_request(world):
    links = world.chain(1)
    proof = audience_proof(world, links, world.keys[1])
    assert audience_verify(world, links, proof).valid is True
    replay = audience_verify(world, links, proof, request=sha256_b64u(b"attacker-request"))
    assert (replay.valid, replay.reason) == (False, "leaf proof: request digest mismatch")


def test_captured_chain_and_proof_cannot_be_replayed_to_another_verifier(world):
    links = world.chain(1)
    proof = audience_proof(world, links, world.keys[1])
    replay = audience_verify(world, links, proof, audience="other-verifier")
    assert (replay.valid, replay.reason) == (False, "leaf proof: audience mismatch")


def test_audience_and_request_are_covered_by_the_signature(world):
    links = world.chain(1)
    proof = LeafProof.decode(audience_proof(world, links, world.keys[1], audience="executor-2"))
    swapped = dataclasses.replace(proof, audience=AUDIENCE)
    result = audience_verify(world, links, swapped.encode())
    assert (result.valid, result.reason) == (False, "leaf proof: invalid signature")
    swapped = dataclasses.replace(proof, request_digest=sha256_b64u(b"other"))
    assert audience_verify(world, links, swapped.encode(), audience="executor-2").valid is False


def test_leaf_proof_round_trip_keeps_audience_and_request(world):
    proof = chain_module.prove_leaf(world.root, world.keys[0], NOW, audience=AUDIENCE, request_digest=REQUEST)
    assert LeafProof.decode(proof.encode()) == proof
    assert (proof.audience, proof.request_digest) == (AUDIENCE, REQUEST)


@pytest.mark.parametrize("audience", ["", "a b", "a\x00b", "café", None, 5, "x" * 257])
def test_expected_audience_must_be_an_id(world, audience):
    links = world.chain(1)
    result = audience_verify(world, links, audience_proof(world, links, world.keys[1]), audience=audience)
    assert result.valid is False
    assert result.reason.startswith("expected_audience")


@pytest.mark.parametrize("request_digest", ["", "short", None, 5, "B" * 43])
def test_expected_request_digest_must_be_a_digest(world, request_digest):
    links = world.chain(1)
    result = audience_verify(world, links, audience_proof(world, links, world.keys[1]), request=request_digest)
    assert result.valid is False
    assert result.reason.startswith("expected_request_digest")


def test_verify_chain_requires_audience_and_request_arguments(world):
    links = world.chain(1)
    with pytest.raises(TypeError):
        chain_module.verify_chain(
            world.root.encode(),
            [links[0].encode()],
            "p",
            world.resolver,
            POLICY,
            NeverRevoked(),
            NOW,
        )


class OddChainChecker:
    def __init__(self, outcome):
        self.outcome = outcome

    def is_revoked(self, context):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


@pytest.mark.parametrize("outcome", [None, "", 0, 1, "no", [], object()])
def test_verify_chain_treats_any_non_false_checker_result_as_revoked(world, outcome):
    result = world.verify(world.chain(1), checker=OddChainChecker(outcome))
    assert (result.valid, result.reason) == (False, "chain has been revoked")


def test_verify_chain_accepts_only_an_explicit_false(world):
    assert world.verify(world.chain(1), checker=OddChainChecker(False)).valid is True


@pytest.mark.parametrize("error", [OSError("disk"), RuntimeError("boom"), KeyError("k"), TimeoutError()])
def test_verify_chain_fails_closed_when_the_checker_raises(world, error):
    result = world.verify(world.chain(1), checker=OddChainChecker(error))
    assert (result.valid, result.reason) == (False, "revocation check failed")


@pytest.mark.parametrize("age", [-1, 1.5, True, None, "60", float("nan")])
def test_max_proof_age_must_be_a_non_negative_integer(world, age):
    links = world.chain(1)
    result = world.verify(links, max_proof_age_seconds=age)
    assert (result.valid, result.reason) == (False, "max_proof_age_seconds must be a non-negative integer")


def test_zero_max_proof_age_accepts_only_a_proof_issued_now(world):
    links = world.chain(1)
    assert world.verify(links, max_proof_age_seconds=0).valid is True
    assert world.verify(links, proof_iat=NOW - 1, max_proof_age_seconds=0).valid is False


def test_delegate_refuses_a_task_root_parent_that_is_not_the_given_root(world):
    other = World()
    with pytest.raises(ValueError, match="parent task root is not the given root"):
        delegate(
            world.root,
            other.root,
            other.keys[0],
            child_subject=pub(other.keys[1]),
            scope=SCOPE,
            budget=1,
            ttl=10,
            now=NOW,
        )


def test_delegate_refuses_a_non_root_first_argument(world):
    with pytest.raises(TypeError, match="root must be a TaskRoot"):
        delegate(
            "root", world.root, world.keys[0], child_subject=pub(world.keys[1]), scope=SCOPE, budget=1, ttl=10, now=NOW
        )


@pytest.mark.parametrize("now", [-1, 1.5, True, None])
def test_prove_leaf_refuses_a_malformed_time(world, now):
    with pytest.raises(ValueError, match="now must be a non-negative integer"):
        prove_leaf(world.root, world.keys[0], now)
