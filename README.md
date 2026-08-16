# agent-warrant

A portable, cryptographically-verifiable authority grant for AI agents — cross-org, no shared infrastructure.

Lets one team's AI agent cryptographically verify another team's agent's delegated authority, with no shared secret. V1 requires out-of-band issuer-key pinning via `PinnedResolver`; no-prearranged-trust bootstrap via `did:web` is planned for V2. Spun out of [`agent-guard`](https://github.com/agent-rails/agent-guard) (which stays the local, single-org authorization/audit boundary) specifically because cross-org verification needs a different crypto trust model — asymmetric signing, not a shared HMAC secret.

Deeper reference: [`docs/DESIGN.md`](docs/DESIGN.md) (why it's shaped this way, including the design history — what was tried, what was corrected, and why), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) (what's defended, what's explicitly not).

## The shape

- A `Grant` is issuer-signed (Ed25519), scoped, expiring — VC-data-model-*shaped*, not VC-spec-conformant (no `credentialStatus`/revocation; see THREAT_MODEL.md).
- `subject` is the holder's public key — but a Grant alone is still a bearer credential unless paired with a fresh `PossessionProof` at verification time, proving the presenter actually holds the matching private key.
- `IssuerResolver` resolves an issuer identifier to a public key. V1 ships `PinnedResolver` — honestly named: it performs zero trust verification, it's out-of-band key pinning (TOFU). A `did:web`-based resolver (real trust bootstrap via HTTPS + domain ownership) is a planned V2, not built here.

## Install

Not yet published to PyPI — install from GitHub:

```bash
pip install git+https://github.com/agent-rails/agent-warrant.git
```

## Quickstart

```python
from agent_warrant import Issuer, HolderKeypair, PinnedResolver, Verifier, generate_keypair, encode_public_key

# Team A: mints a grant for a holder it doesn't need to share any secret with.
team_a_key = generate_keypair()
issuer = Issuer(issuer_id="team-a", private_key=team_a_key)

holder_key = generate_keypair()
holder = HolderKeypair(holder_key)
grant = issuer.issue(subject=encode_public_key(holder_key.public_key()), scope={"tool": "read_file"})
proof = holder.prove_possession(grant)

# Team B: only ever obtains team A's PUBLIC key, out-of-band. No shared secret.
# `path_prefix` is illustrative application data: agent-warrant authenticates
# the scope but does not interpret or enforce it for authorization.
resolver = PinnedResolver({"team-a": team_a_key.public_key()})
verifier = Verifier(resolver)

result = verifier.check(grant.encode(), proof)
assert result.valid
```

A stolen `grant.encode()` string alone is not enough — presenting it without a valid `PossessionProof` (or with a proof forged by a different keypair) is rejected. See `tests/test_integration.py::test_stolen_grant_without_possession_proof_is_rejected` for the live proof.

## Constraints worth knowing before you hit them

- **Encoded grant size**: capped at `agent_warrant.grant.MAX_ENCODED_GRANT_BYTES` (16KB). A compact authority claim never legitimately needs more — if your `scope` is large enough to hit this, reconsider what you're encoding into it rather than raising the constant (it's load-bearing for a resource-exhaustion defense, see docs/THREAT_MODEL.md).

## Design history worth knowing before extending this

This design went through two real review cycles (documented in full at `~/identity-unification-plan.md` in the originating session) before any code was written. The most important correction: an earlier draft called `subject = holder's public key` alone "holder-binding" — it wasn't. A public key sitting in an issuer-signed credential with no separate possession check at verification time is still a bearer credential; anyone who intercepts the encoded grant can replay it. `PossessionProof` exists specifically to close that gap, mirroring `agent-guard`'s own `PoPProof`/`verify_pop` pattern. Read `docs/DESIGN.md` before changing anything in `grant.py`'s `verify()` — most of its structure (narrow exception catches, version-check-first ordering, the iat type guard) is there because a specific finding required it, not by convention.
