# agent-warrant

A portable, cryptographically-verifiable authority grant for AI agents — cross-org, no shared infrastructure.

Lets one team's AI agent cryptographically verify another team's agent's delegated authority, with no shared secret. Ships two `IssuerResolver` implementations: out-of-band issuer-key pinning via `PinnedResolver` (TOFU), and real trust bootstrap via `DidWebResolver` (HTTPS + domain ownership, per the [did:web method spec](https://w3c-ccg.github.io/did-method-web/)). Also ships opt-in revocation checking (`RevocationChecker`) — pre-expiry invalidation of a specific `Grant`, checked as the last gate in `verify()`. Spun out of [`agent-guard`](https://github.com/agent-rails/agent-guard) (which stays the local, single-org authorization/audit boundary) specifically because cross-org verification needs a different crypto trust model — asymmetric signing, not a shared HMAC secret.

Deeper reference: [`docs/DESIGN.md`](docs/DESIGN.md) (why it's shaped this way, including the design history — what was tried, what was corrected, and why), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) (what's defended, what's explicitly not).

## The shape

- A `Grant` is issuer-signed (Ed25519), scoped, expiring — VC-data-model-*shaped*, not VC-spec-conformant (no `credentialStatus` field on the Grant itself; see THREAT_MODEL.md). Revocation checking exists, but as a separate, opt-in gate `verify()` runs against a caller-supplied `RevocationChecker` — not as data carried on the credential.
- `subject` is the holder's public key — but a Grant alone is still a bearer credential unless paired with a fresh `PossessionProof` at verification time, proving the presenter actually holds the matching private key.
- `IssuerResolver` resolves an issuer identifier to a public key. `PinnedResolver` — honestly named: it performs zero trust verification, it's out-of-band key pinning (TOFU). `DidWebResolver` is real trust bootstrap via HTTPS + domain ownership: it fetches `https://<domain>/.well-known/did.json` (or a path-scoped variant, e.g. `example.com:agents:team-a` → `https://example.com/agents/team-a/did.json`) and extracts an Ed25519 key from the DID document — binding selection to the document's `id`, the method's `controller`, and any declared `assertionMethod`, not array order. Every failure (DNS/HTTP error, non-200 status, `id` mismatch, malformed document, wrong key type, ambiguous or no matching `verificationMethod`) fails closed as `UnresolvableIssuer`.
- Revocation is opt-in: a `Verifier` constructed without a `revocation_checker` behaves exactly as before this existed — TTL is the only expiry mechanism. Opting in means the issuer publishes a `RevocationList` (a signed set of revoked `grant_binding` values carrying a signed `issued_at`/`expires_at`/monotonic `sequence` — see `sign_revocation_list()`), and a caller wires up `StaticRevocationChecker` (for an already-fetched list) or `HttpRevocationChecker` (fetches + verifies on every `is_revoked()` call, no caching). Any inability to determine revocation status — fetch failure, malformed list, bad signature, a stale/expired or rolled-back list, or a list whose issuer doesn't match the grant's — fails closed: the grant is rejected, never silently treated as "not revoked."

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

### did:web, instead of pinning

```python
from agent_warrant import DidWebResolver, Verifier

# No out-of-band key exchange -- team-a's key is fetched from
# https://team-a.example.com/.well-known/did.json and cryptographically
# tied to domain ownership over HTTPS, the same trust model TLS uses.
resolver = DidWebResolver()
verifier = Verifier(resolver)
result = verifier.check(grant.encode(), proof)  # grant.issuer == "team-a.example.com"
```

### Revocation, opt-in

```python
from agent_warrant import StaticRevocationChecker, Verifier, sign_revocation_list

# Team A decides to invalidate a specific grant before its TTL expires
# (compromised holder key, mistaken scope, ended sponsorship) and signs a
# RevocationList naming it -- by grant_binding, this project's stable
# identity for a specific Grant (see PossessionProof.grant_binding).
revocation_list = sign_revocation_list("team-a", [proof.grant_binding], team_a_key)

# Team B opts in by wiring a RevocationChecker into its Verifier. Without
# this, revocation is never checked -- default behavior is unchanged.
checker = StaticRevocationChecker(revocation_list, resolver)
verifier = Verifier(resolver, revocation_checker=checker)
result = verifier.check(grant.encode(), proof)
assert result.valid is False and "revoked" in result.reason
```

`HttpRevocationChecker` + `HttpRevocationListFetcher` do the same thing over HTTPS instead of an in-process `RevocationList` -- fetching and re-verifying the signed list on every `is_revoked()` call, no caching. If the revocation endpoint is unreachable, verification fails closed (rejected), not open.

## Constraints worth knowing before you hit them

- **Encoded grant size**: capped at `agent_warrant.grant.MAX_ENCODED_GRANT_BYTES` (16KB). A compact authority claim never legitimately needs more — if your `scope` is large enough to hit this, reconsider what you're encoding into it rather than raising the constant (it's load-bearing for a resource-exhaustion defense, see docs/THREAT_MODEL.md).
- **`DidWebResolver` fetches on every `resolve()` call, no caching.** And because `grant.issuer` reaches `resolver.resolve()` before any signature check, an unauthenticated grant can make the verifying process issue an outbound HTTPS request to an attacker-influenced host. `https_fetch.py` resolves the host once, rejects the fetch if any resolved address is private/loopback/link-local/reserved/multicast/unspecified, pins the screened IP, and connects to it directly while verifying TLS against the original hostname (SSRF hardening; this closes the DNS-rebinding TOCTOU a check-then-connect pattern would have). A wall-clock watchdog bounds the total time any single fetch can consume against a slow-drip host. See docs/THREAT_MODEL.md for the remaining residual (the DNS-resolution step uses the OS resolver's own timeout).
- **Revocation is opt-in and unbundled from StatusList2021.** It's a small signed set of revoked `grant_binding` values, sized for a known, bounded cross-org verifier population -- not the anonymity-preserving bitstring StatusList2021 uses for public, anonymous-verifier scale. See docs/DESIGN.md for why that tradeoff fits this project's actual shape.

## Design history worth knowing before extending this

This design went through two real review cycles (documented in full at `~/identity-unification-plan.md` in the originating session) before any code was written. The most important correction: an earlier draft called `subject = holder's public key` alone "holder-binding" — it wasn't. A public key sitting in an issuer-signed credential with no separate possession check at verification time is still a bearer credential; anyone who intercepts the encoded grant can replay it. `PossessionProof` exists specifically to close that gap, mirroring `agent-guard`'s own `PoPProof`/`verify_pop` pattern. Read `docs/DESIGN.md` before changing anything in `grant.py`'s `verify()` — most of its structure (narrow exception catches, version-check-first ordering, the iat type guard) is there because a specific finding required it, not by convention.
