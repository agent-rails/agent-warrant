from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_warrant.identity import decode_public_key
from agent_warrant.resolver import PinnedResolver
from agent_warrant.task_root import TaskRoot, verify_root
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy

DOC = json.loads((Path(__file__).parent / "vectors" / "task_root.json").read_text(encoding="utf-8"))
RESOLVER = PinnedResolver({issuer: decode_public_key(key) for issuer, key in DOC["issuers"].items()})
POLICY = IssuerTrustPolicy({issuer: IssuerAllowance(**allowance) for issuer, allowance in DOC["policy"].items()})


class Revocation:
    def __init__(self, revoked):
        self.revoked = revoked

    def is_revoked(self, issuer, binding):
        return self.revoked


@pytest.mark.parametrize("vector", DOC["vectors"], ids=lambda v: v["name"])
def test_task_root_vector(vector):
    result = verify_root(vector["encoded"], RESOLVER, POLICY, Revocation(vector["revoked"]), vector["now"])
    assert result.valid is vector["expect_valid"]
    assert vector["reason"] in result.reason


def test_valid_vector_decodes_to_documented_fields_and_binding():
    valid = next(vector for vector in DOC["vectors"] if vector["name"] == "valid")
    root = TaskRoot.decode(valid["encoded"])
    assert root.signable_fields() == DOC["root_fields"]
    assert root.binding() == DOC["binding"]
    assert root.encode() == valid["encoded"]
