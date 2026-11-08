# Grant chain, part 1: task root and issuer trust policy

Facts about `agent_warrant.task_root` and `agent_warrant.trust`. Byte profile: `canonical.md`. Vectors: `tests/vectors/task_root.json`, checked by `tests/test_task_root_vectors.py`. Later parts (delegation links, ledger) are not specified here.

## TaskRoot

Record type `task-root`, version 1. Fields, all required, none optional:

| Field | Type | Rule |
| --- | --- | --- |
| `task_id` | id | see Ids below |
| `tenant_id` | id | see Ids below |
| `principal` | id | see Ids below |
| `purpose` | id | persona label; see Ids below |
| `budget` | integer | 0 to 2**53-1 |
| `max_depth` | integer | 0 to 16 (`MAX_CHAIN_DEPTH`) |
| `issued_at` | integer | seconds, 0 to 2**53-1 |
| `expires_at` | integer | seconds; greater than `issued_at`; at most 86400 s after it (same cap as `Issuer.MAX_TTL_SECONDS`) |
| `scope` | object | `{"tools": [...], "resources": [...], "max_cost_per_call": int}`; see `scope.py` rules below; bounds every delegated link |
| `subject` | string | first delegate's Ed25519 public key; must satisfy Public keys below |
| `issuer` | id | resolved to a key by the `IssuerResolver`; see Ids below |

`proof` is the issuer's Ed25519 signature and is not part of the body.

## Ids

`task_id`, `tenant_id`, `principal`, `purpose` and `issuer` are 1 to 256 characters, each in ASCII 0x21 to 0x7E. Space, control characters (including NUL and DEL) and all non-ASCII characters are refused, so bidi overrides, zero-width characters and look-alike letters cannot appear. Ids are compared byte for byte; callers map names into this alphabet before they enter a record.

## Public keys

`identity.is_valid_public_key` accepts a key only if it is the unique unpadded base64url form of 32 bytes, y is below 2**255-19, the point is on the curve, x = 0 does not carry a sign bit, and the point is not one of the 8 small-order points (a signature by or for those can be forged without a private key). Keys that carry a torsion component on top of a large-order part are not detected. The same check applies to `subject`.

## Wire form and signed bytes

- Body: `canonicalize` of the eleven fields above.
- Signed bytes: `signing_input("task-root", 1, body)`, which is `b"agent-warrant/task-root/v1" + b"\x00" + canonical body`.
- Transport: `base64url(canonical body) + "." + base64url(signature)`, unpadded. Padding, whitespace or any other non-canonical base64url is refused. Encoded length is at most 16384 characters.
- The received body must equal `canonicalize` of the decoded fields byte for byte (sorted keys, no whitespace, no escapes where a raw character is canonical); anything else is refused even with a valid signature, so each root has exactly one encoding.
- Decoding uses `strict_decode` only: duplicate keys, unknown keys, missing keys, floats, non-integer timestamps, lone surrogates and integers outside +/-(2**53-1) are refused.
- The signature covers the re-canonicalized body, never the received bytes.
- A signature made over the untagged body, over another record type's tag, or over another version's tag does not verify. A v1 `Grant` encoding is refused at decode (unknown and missing keys).
- Binding: `base64url(sha256(signed bytes))`. This is the identifier passed to the `RevocationChecker`, together with the root's issuer.

## verify_root

`verify_root(encoded, resolver, trust_policy, revocation_checker, now) -> TaskRootResult(valid, reason, root, checked_at)`

- `now` is an integer number of seconds. A non-integer `now` yields an invalid result.
- Never raises on attacker-controlled `encoded`; every failure is `valid=False` with a reason. `trust_policy` that is not an `IssuerTrustPolicy` raises `TypeError` (caller bug).
- Order of checks, stopping at the first failure:
  1. decode and field validation
  2. issuer is listed in the trust policy (before any key lookup)
  3. issuer key resolves
  4. issuer signature over the signed bytes
  5. `issued_at <= now + 5` (clock skew, seconds)
  6. `now < expires_at`
  7. claims within the issuer's allowance
  8. revocation: `is_revoked(root.issuer, root.binding())`; `RevocationSourceUnreachable` fails closed
- No possession proof is checked. `valid=True` means the issuer signed these claims, the issuer may assert them, and the root is in its validity window and not revoked. It does not show that any presenter holds `subject`'s key.

## Scope

Shape is exactly `{"tools": [...], "resources": [...], "max_cost_per_call": int}` (at most 64 entries per list, integer 0 to 2**53-1).

- Entry: an exact id, or a prefix pattern. Ids are ASCII printable (0x21 to 0x7E, no whitespace), at most 128 characters; callers normalise before.
- A prefix pattern is a non-empty prefix whose last character is one of `.` `:` `/` `_` `-`, followed by a single final `*`. `deploy.*` is valid and covers `deploy.prod` but not `deployx`. `deploy*`, bare `*`, `a*b` and `**` are refused.
- `covers(scope, tool, resource)`: both ids concrete (no `*`), each covered by some entry. An invalid scope covers nothing. This is the single matcher; it is not `fnmatch`.
- `scope_narrows(parent, child)`: every child entry lies inside some parent entry (exact by equal id or covering prefix; prefix pattern only by a prefix pattern whose prefix it extends) and child cost is not above parent cost. An invalid scope on either side does not narrow.
- The issuer trust policy does not bound `scope`; the root scope is whatever the listed issuer signed.

## Issuer trust policy

A resolver maps an issuer to a key only, so a valid signature alone does not authorise a tenant, principal or budget. `IssuerTrustPolicy` maps issuer id to an `IssuerAllowance`:

- `tenants`: mapping tenant id to `TenantAllowance`. A tenant not in the mapping is refused. Principals are bound to their tenant: a principal allowed for one tenant is refused under another.
- `TenantAllowance.principals`: exact principals.
- `TenantAllowance.principal_prefixes`: a principal also matches if it starts with a listed prefix. A prefix is a stem of at least one character followed by one of `:` `/` `.` as its last character, so `svc:team-a:` matches `svc:team-a:x` and never `svc:team-admin`. No wildcards.
- `max_budget`, `max_depth`: inclusive upper bounds, integers 0 to 2**53-1.
- An empty set allows nothing. An issuer absent from the policy is refused.
- Collections passed as a bare `str` raise `TypeError`; empty entries raise `ValueError`.

The policy is copied at construction.

# Part 2: delegation links, possession proof and chain verification

Facts about `agent_warrant.chain`, `agent_warrant.scope` and chain revocation. Vectors: `tests/vectors/chain.json`, checked by `tests/test_chain_vectors.py`. The ledger is not specified here.

## ChainLink

Record type `chain-link`, version 1. Fields, all required, none optional:

| Field | Type | Rule |
| --- | --- | --- |
| `task_id` | id | equals the root's |
| `tenant_id` | id | equals the root's |
| `task_root` | digest | binding of the TaskRoot |
| `parent_hash` | digest | binding of the previous record: the TaskRoot for the first link, otherwise the previous link |
| `issuer` | public key | the previous holder; signs the link; must equal the previous record's `subject` |
| `subject` | public key | the next holder |
| `scope` | object | narrows the previous record's scope |
| `budget` | integer | at most the previous record's budget |
| `depth` | integer | 1 to 16; previous depth + 1 (the TaskRoot is depth 0) |
| `issued_at` | integer | seconds; at least the previous `issued_at`; at most `now + 5` |
| `expires_at` | integer | seconds; greater than `issued_at`; at most the previous `expires_at`; at most 86400 s after `issued_at`; greater than `now` |

- Digests are canonical unpadded base64url of 32 bytes. Public keys follow the TaskRoot "Public keys" rule. Ids follow the TaskRoot "Ids" rule.
- A link's binding is `base64url(sha256(signed bytes))`. Signed bytes are `signing_input("chain-link", 1, body)`. Transport and canonical-body rules are the TaskRoot's; encoded length is at most 16384 characters.
- The root's `max_depth` bounds the number of links. `max_depth` 0 allows no links.

## delegate

`delegate(root, parent, parent_holder_key, *, child_subject, scope, budget, ttl, now) -> ChainLink`, where `parent` is the TaskRoot or the previous link. It raises `ValueError` for anything verification would refuse: a key that is not `parent.subject`, a parent from another root, depth over `root.max_depth`, a scope that does not narrow, budget above the parent's or not an integer, a parent not valid at `now`, an invalid `child_subject`, a non-positive `ttl`. `expires_at` is `min(now + ttl, parent.expires_at)`.

## Possession proof

`LeafProof` is `{audience, binding, iat, request_digest}` plus a signature, transported like a link. The signed bytes are `signing_input("possession", 1, {"audience": ..., "binding": ..., "iat": ..., "request_digest": ...})` under the leaf subject's key (the TaskRoot's subject when there are no links).

- `binding` is the leaf record's binding, so a proof for one record does not satisfy another.
- `audience` is the id of the verifier the proof is addressed to (same alphabet and length as other ids). A proof presented to a different verifier is refused.
- `request_digest` is the canonical base64url sha256 digest of the one request the proof authorizes (the executor uses the Operation digest). A proof presented with a different request is refused.
- The `possession` tag keeps a proof from verifying as a link or a root and the reverse.
- A proof is not single-use: the same chain and proof replayed to the same verifier for the same request within the age window is accepted. Making that effect happen once is the ledger's idempotency key, not this check.

## verify_chain

`verify_chain(root_encoded, links_encoded, leaf_proof, resolver, trust_policy, revocation_checker, now, *, expected_audience, expected_request_digest, max_proof_age_seconds=60) -> ChainVerifyResult(valid, reason, root, links, checked_at)`

- Never raises on attacker-controlled input; every failure is `valid=False` with a reason. `expected_audience` must be an id and `expected_request_digest` a canonical digest, else the result is `valid=False`. `revocation_checker` that is `None` or lacks `is_revoked` raises `TypeError` (caller bug). `now` is an integer.
- Total encoded size (root plus links) is at most 262144 characters.
- Order of checks, stopping at the first failure:
  1. the root, as in `verify_root` without the revocation lookup (decode, policy lists issuer, issuer signature, validity window, issuer allowance)
  2. number of links at most `root.max_depth`
  3. per link, in order: decode; same `task_id` and `tenant_id` as the root; `task_root` equals the root binding; `issuer` equals the previous subject; `parent_hash` equals the previous binding; `depth` is previous + 1; signature by `issuer`; scope narrows; budget not above previous; `expires_at` not after previous; `now < expires_at`; `issued_at` not before previous; `issued_at <= now + 5`
  4. leaf proof: decodes; bound to the leaf binding; signature by the leaf subject; `audience` equals `expected_audience`; `request_digest` equals `expected_request_digest`; `iat <= now + 5`; `now - iat <= max_proof_age_seconds`
  5. revocation, once, with a `ChainContext`
- Reordered, duplicated or skipped links fail the `parent_hash`/`issuer`/`depth` checks. A link from another task or tenant fails the `task_id`/`tenant_id` check; a link under a different root with the same task and tenant fails the `task_root` check.
- A TaskRoot alone never yields a valid chain: the proof must be signed by the leaf subject's key, and links must be signed by the previous subject's key. A captured chain and proof is useless to another verifier or for another request.
- `valid=True` means the chain is authentic and narrowing, inside its validity window, not revoked, and the presenter holds the leaf key now. `leaf_scope` and `leaf_subject` expose the leaf's authority; applying them (`covers`) and charging budget are the caller's job.

## Chain revocation

`ChainRevocationChecker.is_revoked(context) -> bool`, with `ChainContext(task_id, tenant_id, root_issuer, task_root, link_bindings)`.

- Mandatory. Called last and once, so an invalid chain never triggers a lookup.
- Returns `True` if the task, the tenant, the root or any listed link is revoked. Revoking a link revokes every chain that contains it and no chain that stops before it.
- Raises `RevocationSourceUnreachable` when status cannot be determined; `verify_chain` then returns `valid=False`. Returning `False` on uncertainty is a checker bug.
- The root is not checked separately by a `RevocationChecker`; the chain checker decides on `context.task_root`.

## Scope matching (`scope.py`)

Rules are in the TaskRoot "Scope" section. In a chain, a prefix pattern ends at a separator (`.` `:` `/` `_` `-`) before `*`, so `deploy.*` never covers `deployx`. `covers` is the enforcement matcher and `scope_narrows` is the delegation check; both use the same entry rules. Principal prefixes in the trust policy use their own stricter delimiter set (`:` `/` `.`).
