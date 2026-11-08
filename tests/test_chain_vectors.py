from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_warrant.chain import verify_chain
from agent_warrant.exceptions import RevocationSourceUnreachable
from agent_warrant.identity import decode_public_key
from agent_warrant.resolver import PinnedResolver
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance

DOC = json.loads((Path(__file__).parent / "vectors" / "chain.json").read_text(encoding="utf-8"))
RESOLVER = PinnedResolver({issuer: decode_public_key(key) for issuer, key in DOC["issuers"].items()})
POLICY = IssuerTrustPolicy(
    {
        issuer: IssuerAllowance(
            tenants={tenant: TenantAllowance(**rules) for tenant, rules in allowance["tenants"].items()},
            max_budget=allowance["max_budget"],
            max_depth=allowance["max_depth"],
        )
        for issuer, allowance in DOC["policy"].items()
    }
)


class Checker:
    def __init__(self, vector):
        self.revoked = set(vector["revoked_bindings"])
        self.unreachable = vector["revocation_unreachable"]

    def is_revoked(self, context):
        if self.unreachable:
            raise RevocationSourceUnreachable("down")
        return context.task_root in self.revoked or any(binding in self.revoked for binding in context.link_bindings)


@pytest.mark.parametrize("vector", DOC["vectors"], ids=lambda v: v["name"])
def test_chain_vector(vector):
    result = verify_chain(
        vector["root"],
        vector["links"],
        vector["leaf_proof"],
        RESOLVER,
        POLICY,
        Checker(vector),
        vector["now"],
        expected_audience=vector["expected_audience"],
        expected_request_digest=vector["expected_request_digest"],
    )
    assert result.valid is vector["expect_valid"]
    assert vector["reason"] in result.reason


def test_vector_bindings_are_pinned():
    valid = next(vector for vector in DOC["vectors"] if vector["name"] == "depth-3")
    result = verify_chain(
        valid["root"],
        valid["links"],
        valid["leaf_proof"],
        RESOLVER,
        POLICY,
        Checker(valid),
        valid["now"],
        expected_audience=valid["expected_audience"],
        expected_request_digest=valid["expected_request_digest"],
    )
    assert result.root.binding() == DOC["root_binding"]
    assert [link.binding() for link in result.links] == DOC["leaf_bindings"]
