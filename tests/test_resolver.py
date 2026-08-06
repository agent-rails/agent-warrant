from __future__ import annotations

import pytest

from agent_warrant.exceptions import UnresolvableIssuer
from agent_warrant.identity import generate_keypair
from agent_warrant.resolver import PinnedResolver


def test_pinned_resolver_resolves_known_issuer():
    key = generate_keypair().public_key()
    resolver = PinnedResolver({"team-a": key})
    assert resolver.resolve("team-a") is key


def test_pinned_resolver_raises_on_unknown_issuer():
    resolver = PinnedResolver({})
    with pytest.raises(UnresolvableIssuer):
        resolver.resolve("team-a")
