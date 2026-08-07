# Threat Model

## Pillar 1 — Cross-org authority verification (`Grant`/`verify`/`Verifier`)

**Prevent:**
- A stolen `encoded_grant` string alone is not usable — verification requires a fresh `PossessionProof` signed by the private key matching the grant's `subject`. A captured grant with no proof, or a proof forged by a different keypair, is rejected. Live-verified: `tests/test_integration.py::test_stolen_grant_without_possession_proof_is_rejected`.
- A grant issued by an unresolvable/unknown issuer is rejected (`UnresolvableIssuer`, caught inside `verify()`, never propagated).
- An unsupported grant `version` is rejected before any other field is TRUSTED (not before parsed -- Grant.decode() parses the full JSON body, size-bounded to MAX_ENCODED_GRANT_BYTES, before the version check runs; corrected wording after review found the original 'or parsed' claim was false and the unbounded parse was a live resource-exhaustion / RecursionError gap, now closed by the size bound).
- Every fail-closed exit in `verify()` uses narrow, named exception catches (`binascii.Error`, `ValueError`, `TypeError`, `json.JSONDecodeError`, `InvalidSignature`) around each parse/verify block — never a bare `except`, which would swallow a genuine bug (a `NameError` from a typo, an `AttributeError` from a real logic error) and misreport it as "invalid grant."
- `grant.issuer` is type-checked (`isinstance(..., str)`) before being passed to `resolver.resolve()` — a second, independently-found live gap: an unhashable JSON value (a list or dict) as `issuer` made a dict-based resolver's `.get()` raise `TypeError`, reachable pre-authentication (before any signature check) with an unsigned, 185-byte payload. Same pattern as the timestamp guards: a value that reaches a resolver/comparison/arithmetic operation must be type-checked first, not assumed safe because it came from a JSON object.

**Contain:** all failures fail closed (`valid=False`); `verify()` never raises regardless of how malformed either `encoded_grant` or `possession_proof` are — every field in both is attacker-controlled.

**Detect:** `VerifyResult.reason` names why a check failed, distinct for each failure class (malformed encoding, unsupported version, unresolvable issuer, invalid issuer signature, expired, invalid possession-proof signature, possession proof bound to a different grant, stale, non-numeric `iat`).

## Explicit non-goals (V1)

- **Revocation.** There is no `credentialStatus`/StatusList2021 mechanism, and none is planned for V1. If an issuer's private key is compromised, every outstanding `Grant` it signed is forgeable and unrevocable until its own `expires_at`. The only containment is a short TTL — callers of `Issuer.issue()` should treat `ttl_seconds` as load-bearing, not a convenience default. This mirrors `agent-guard`'s own stated revocation posture (TTL + denylist) but V1 doesn't even have the denylist half yet.
- **VC-spec conformance.** `Grant` is VC-data-model-*shaped* (issuer, subject, claim, expiry, proof), not VC-spec-conformant. It carries no `@context`, no `credentialStatus`, and must never emit a literal `type: VerifiableCredential`. A real foreign VC verifier ingesting this and reading the absence of `credentialStatus` as "permanently valid, not revocable" would be wrong — this project's own verifier correctly treats absence of revocation infrastructure as "TTL is the only expiry mechanism," but a foreign verifier has no reason to know that convention.
- **Cross-verifier replay within the freshness window.** `PossessionProof` binds to a specific `Grant` (via `grant_binding`) and has a freshness window (`max_age_seconds`, default 60s) — but no audience/verifier binding. A passive observer who captures a valid `(grant, proof)` pair can replay it at *any* verifier within that window. This is the same residual `agent-guard`'s own `verify_pop` has (a generous, non-single-use freshness window, not a nonce-tracked one), disclosed there for the same reason. Not closed in V1 — would need an `aud` field and a real reason (multi-verifier deployments) before adding that complexity.
- **`did:web` / real trust bootstrap.** V1's `PinnedResolver` performs zero trust verification — it's out-of-band key pinning (TOFU). It does not, on its own, satisfy "verify without pre-established trust"; the caller is responsible for how the pinned key mapping was obtained and trusted. A `did:web`-based resolver (HTTPS + domain ownership, the same trust model as TLS today) is what would actually deliver that property — planned V2, not built.
- **Encoded-grant malleability.** `verify()` re-canonicalizes the decoded body rather than trusting the transmitted bytes — deliberate, and confirmed robust: a re-ordered/re-whitespaced JSON body still verifies to the same `Grant` and the same `grant_binding`. A consequence, not a bug: many distinct encoded strings verify identically, so the encoded string itself is not a stable identity for replay-detection or dedup purposes. Callers needing a replay/dedup key MUST use `grant_binding` (or a hash of it), never the raw encoded string.

## Note on `MAX_ENCODED_GRANT_BYTES`'s two independent defenses

The 16KB size cap and `decode()`'s `except RecursionError` both close the same
resource-exhaustion / never-raises gap, but on different interpreters. The cap was
measured against Python 3.14's own recursion threshold (~150,000 nesting levels);
CPython's actual recursion limits are much lower on other supported versions
(`requires-python = ">=3.10"` covers interpreters with recursion ceilings around
1000-3000). On those, the `except RecursionError` catch is the defense that actually
fires — the size cap alone does not make it unreachable. Both must be kept; neither
is redundant given the full supported-version range.

## Pillar 2 — Canonicalization (`canonical.py`)

**Prevent:** every signature (issuer signature over a `Grant`, holder signature over a `PossessionProof`) is computed over the same single canonicalization implementation — no inline `json.dumps` anywhere in `grant.py`, `issuer.py`, or `identity.py`. Caught in review: an early draft of `PossessionProof.prove()` would have used inline `json.dumps` (mirroring `agent-guard`'s own `pop.py` literally, which itself predates this project's canonicalization discipline) — reintroducing the exact "two drifting implementations" risk this module exists to prevent, inside the fix for a different bug. Corrected before the first commit.

**Explicit non-goal:** this is a deterministic JSON serialization (sorted keys, compact separators, UTF-8), not full RFC 8785 JCS conformance — no float-exponent-normalization edge cases are handled, because this project's own data model never signs a float that isn't a Unix timestamp, and non-finite floats (NaN/Infinity) are rejected outright rather than needing JCS's normalization rules.
