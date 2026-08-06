# Threat Model

## Pillar 1 — Cross-org authority verification (`Grant`/`verify`/`Verifier`)

**Prevent:**
- A stolen `encoded_grant` string alone is not usable — verification requires a fresh `PossessionProof` signed by the private key matching the grant's `subject`. A captured grant with no proof, or a proof forged by a different keypair, is rejected. Live-verified: `tests/test_integration.py::test_stolen_grant_without_possession_proof_is_rejected`.
- A grant issued by an unresolvable/unknown issuer is rejected (`UnresolvableIssuer`, caught inside `verify()`, never propagated).
- An unsupported grant `version` is rejected before any other field is trusted or parsed.
- Every fail-closed exit in `verify()` uses narrow, named exception catches (`binascii.Error`, `ValueError`, `TypeError`, `json.JSONDecodeError`, `InvalidSignature`) around each parse/verify block — never a bare `except`, which would swallow a genuine bug (a `NameError` from a typo, an `AttributeError` from a real logic error) and misreport it as "invalid grant."

**Contain:** all failures fail closed (`valid=False`); `verify()` never raises regardless of how malformed either `encoded_grant` or `possession_proof` are — every field in both is attacker-controlled.

**Detect:** `VerifyResult.reason` names why a check failed, distinct for each failure class (malformed encoding, unsupported version, unresolvable issuer, invalid issuer signature, expired, invalid possession-proof signature, possession proof bound to a different grant, stale, non-numeric `iat`).

## Explicit non-goals (V1)

- **Revocation.** There is no `credentialStatus`/StatusList2021 mechanism, and none is planned for V1. If an issuer's private key is compromised, every outstanding `Grant` it signed is forgeable and unrevocable until its own `expires_at`. The only containment is a short TTL — callers of `Issuer.issue()` should treat `ttl_seconds` as load-bearing, not a convenience default. This mirrors `agent-guard`'s own stated revocation posture (TTL + denylist) but V1 doesn't even have the denylist half yet.
- **VC-spec conformance.** `Grant` is VC-data-model-*shaped* (issuer, subject, claim, expiry, proof), not VC-spec-conformant. It carries no `@context`, no `credentialStatus`, and must never emit a literal `type: VerifiableCredential`. A real foreign VC verifier ingesting this and reading the absence of `credentialStatus` as "permanently valid, not revocable" would be wrong — this project's own verifier correctly treats absence of revocation infrastructure as "TTL is the only expiry mechanism," but a foreign verifier has no reason to know that convention.
- **Cross-verifier replay within the freshness window.** `PossessionProof` binds to a specific `Grant` (via `grant_binding`) and has a freshness window (`max_age_seconds`, default 60s) — but no audience/verifier binding. A passive observer who captures a valid `(grant, proof)` pair can replay it at *any* verifier within that window. This is the same residual `agent-guard`'s own `verify_pop` has (a generous, non-single-use freshness window, not a nonce-tracked one), disclosed there for the same reason. Not closed in V1 — would need an `aud` field and a real reason (multi-verifier deployments) before adding that complexity.
- **`did:web` / real trust bootstrap.** V1's `PinnedResolver` performs zero trust verification — it's out-of-band key pinning (TOFU). It does not, on its own, satisfy "verify without pre-established trust"; the caller is responsible for how the pinned key mapping was obtained and trusted. A `did:web`-based resolver (HTTPS + domain ownership, the same trust model as TLS today) is what would actually deliver that property — planned V2, not built.

## Pillar 2 — Canonicalization (`canonical.py`)

**Prevent:** every signature (issuer signature over a `Grant`, holder signature over a `PossessionProof`) is computed over the same single canonicalization implementation — no inline `json.dumps` anywhere in `grant.py`, `issuer.py`, or `identity.py`. Caught in review: an early draft of `PossessionProof.prove()` would have used inline `json.dumps` (mirroring `agent-guard`'s own `pop.py` literally, which itself predates this project's canonicalization discipline) — reintroducing the exact "two drifting implementations" risk this module exists to prevent, inside the fix for a different bug. Corrected before the first commit.

**Explicit non-goal:** this is a deterministic JSON serialization (sorted keys, compact separators, UTF-8), not full RFC 8785 JCS conformance — no float-exponent-normalization edge cases are handled, because this project's own data model never signs a float that isn't a Unix timestamp, and non-finite floats (NaN/Infinity) are rejected outright rather than needing JCS's normalization rules.
