from __future__ import annotations

import statistics
import time

import pytest

from agent_warrant.chain import delegate, prove_leaf, verify_chain
from agent_warrant.encoding import sha256_b64u
from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.resolver import PinnedResolver
from agent_warrant.scope import (
    MAX_ID_CHARACTERS,
    MAX_PERMISSIONS,
    MAX_TOTAL_ENTRIES,
    CallRefusal,
    check_call,
    permissions_of,
)
from agent_warrant.task_root import MAX_CHAIN_DEPTH, issue_task_root
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance

pytestmark = pytest.mark.bench

NOW = 1_000_000
AUDIENCE = "executor-1"
REQUEST = sha256_b64u(b"request-1")
CHECK_CALL_P50_LIMIT_NS = 50_000
ROUNDS = 2_000
TOOL_STEM = "svc." + "t" * (MAX_ID_CHARACTERS - 12) + "."
RESOURCE_STEM = "env/" + "r" * (MAX_ID_CHARACTERS - 12)
TAGS = ("a", "b")


def max_scope():
    return {
        "permissions": [
            {
                "tools": [f"{TOOL_STEM}{tag}.*" for tag in TAGS],
                "resources": [f"{RESOURCE_STEM}{index:02d}{tag}/*" for tag in TAGS],
                "max_cost_per_call": 100,
            }
            for index in range(MAX_PERMISSIONS)
        ]
    }


def p50_ns(call, rounds=ROUNDS):
    samples = []
    for _ in range(rounds):
        started = time.perf_counter_ns()
        call()
        samples.append(time.perf_counter_ns() - started)
    return statistics.median(samples)


def test_max_scope_is_at_the_bounds():
    view = permissions_of(max_scope())
    assert len(view) == MAX_PERMISSIONS
    assert sum(len(item.tools) + len(item.resources) for item in view) == MAX_TOTAL_ENTRIES


def test_check_call_worst_case_p50(record_property):
    view = permissions_of(max_scope())
    tool = f"{TOOL_STEM}a.run"
    resource = f"{RESOURCE_STEM}99a/db"
    assert check_call(view, tool, resource, 1) is CallRefusal.OUT_OF_SCOPE
    median = p50_ns(lambda: check_call(view, tool, resource, 1))
    record_property("check_call_p50_ns", median)
    print(f"check_call 16 permissions p50: {median / 1000:.1f} us")
    assert median < CHECK_CALL_P50_LIMIT_NS


def test_depth_16_chain_verify_is_recorded(record_property):
    issuer_key = generate_keypair()
    keys = [generate_keypair() for _ in range(MAX_CHAIN_DEPTH + 1)]
    scope = max_scope()
    policy = IssuerTrustPolicy(
        {
            "issuer-a": IssuerAllowance(
                tenants={"t1": TenantAllowance(principals={"alice"})},
                max_budget=1000,
                max_depth=MAX_CHAIN_DEPTH,
            )
        }
    )
    root = issue_task_root(
        issuer_key,
        issuer="issuer-a",
        task_id="task-1",
        tenant_id="t1",
        principal="alice",
        purpose="deploy",
        budget=1000,
        max_depth=MAX_CHAIN_DEPTH,
        issued_at=NOW,
        expires_at=NOW + 3600,
        scope=scope,
        subject=encode_public_key(keys[0].public_key()),
    )
    links = []
    parent = root
    for index in range(MAX_CHAIN_DEPTH):
        parent = delegate(
            root,
            parent,
            keys[index],
            child_subject=encode_public_key(keys[index + 1].public_key()),
            scope=scope,
            budget=1000,
            ttl=600,
            now=NOW,
        )
        links.append(parent)
    encoded_root = root.encode()
    encoded_links = [link.encode() for link in links]
    proof = prove_leaf(links[-1], keys[-1], NOW, audience=AUDIENCE, request_digest=REQUEST).encode()
    resolver = PinnedResolver({"issuer-a": issuer_key.public_key()})

    class NeverRevoked:
        def is_revoked(self, context):
            return False

    def verify():
        return verify_chain(
            encoded_root,
            encoded_links,
            proof,
            resolver,
            policy,
            NeverRevoked(),
            NOW,
            expected_audience=AUDIENCE,
            expected_request_digest=REQUEST,
            scope_v1_cutoff=0,
        )

    assert verify().valid is True
    median = p50_ns(verify, rounds=50)
    size = len(encoded_root) + sum(len(item) for item in encoded_links)
    record_property("depth_16_verify_p50_ns", median)
    record_property("depth_16_encoded_bytes", size)
    print(f"depth-16 chain verify p50: {median / 1000:.1f} us, {size} encoded bytes")
