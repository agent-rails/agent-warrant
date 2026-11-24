# Grant chain, part 1: task root and issuer trust policy

Facts about `agent_warrant.task_root` and `agent_warrant.trust`. Byte profile: `canonical.md`. Vectors: `tests/vectors/task_root.json`, checked by `tests/test_task_root_vectors.py`. Later parts (delegation links, ledger) are not specified here.

## TaskRoot

Record type `task-root`, version 2 for a permissions scope and 1 for a v1 scope (see Scope). Fields, all required, none optional:

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
| `scope` | object | `{"permissions": [...]}` (v2) or, read only, `{"tools": [...], "resources": [...], "max_cost_per_call": int}` (v1); see Scope below; bounds every delegated link |
| `subject` | string | first delegate's Ed25519 public key; must satisfy Public keys below |
| `issuer` | id | resolved to a key by the `IssuerResolver`; see Ids below |

`proof` is the issuer's Ed25519 signature and is not part of the body.

`issue_task_root` signs v2 only: a v1 scope raises `ValueError` (`scope: a v1 scope cannot be issued, use permissions`). A decoded or constructed root carries `scope_version` (1 or 2) and `permissions`, the validated view of its scope (see Scope); neither is part of the body.

## Ids

`task_id`, `tenant_id`, `principal`, `purpose` and `issuer` are 1 to 256 characters, each in ASCII 0x21 to 0x7E. Space, control characters (including NUL and DEL) and all non-ASCII characters are refused, so bidi overrides, zero-width characters and look-alike letters cannot appear. Ids are compared byte for byte; callers map names into this alphabet before they enter a record.

## Public keys

`identity.is_valid_public_key` accepts a key only if it is the unique unpadded base64url form of 32 bytes, y is below 2**255-19, the point is on the curve, x = 0 does not carry a sign bit, and the point is not one of the 8 small-order points (a signature by or for those can be forged without a private key). Keys that carry a torsion component on top of a large-order part are not detected. The same check applies to `subject`.

## Wire form and signed bytes

- Body: `canonicalize` of the eleven fields above.
- Signed bytes: `signing_input("task-root", version, body)`, which is `b"agent-warrant/task-root/v<version>" + b"\x00" + canonical body`. `version` is the scope version: 2 for a permissions scope, 1 for a v1 scope. It is taken from the body, never chosen separately, so a v2 body signed under the v1 tag, or a v1 body under the v2 tag, does not verify. v1 roots keep their signed bytes and binding byte for byte.
- Transport: `base64url(canonical body) + "." + base64url(signature)`, unpadded. Padding, whitespace or any other non-canonical base64url is refused. Encoded length is at most 16384 characters.
- The received body must equal `canonicalize` of the decoded fields byte for byte (sorted keys, no whitespace, no escapes where a raw character is canonical); anything else is refused even with a valid signature, so each root has exactly one encoding.
- Decoding uses `strict_decode` only: duplicate keys, unknown keys, missing keys, floats, non-integer timestamps, lone surrogates and integers outside +/-(2**53-1) are refused.
- The signature covers the re-canonicalized body, never the received bytes.
- A signature made over the untagged body, over another record type's tag, or over another version's tag does not verify. A v1 `Grant` encoding is refused at decode (unknown and missing keys).
- Binding: `base64url(sha256(signed bytes))`. This is the identifier passed to the `RevocationChecker`, together with the root's issuer.

## verify_root

`verify_root(encoded, resolver, trust_policy, revocation_checker, now, *, scope_v1_cutoff) -> TaskRootResult(valid, reason, root, checked_at)`. `check_root(encoded, resolver, trust_policy, now, *, scope_v1_cutoff)` runs the same checks without the revocation lookup.

- `now` is an integer number of seconds. A non-integer `now` yields an invalid result.
- `scope_v1_cutoff` is required, keyword-only and has no default: Unix seconds, an integer >= 0. A `bool` or non-integer raises `TypeError` and a negative value raises `ValueError` (caller bug). 0 refuses every v1 root.
- Never raises on attacker-controlled `encoded`; every failure is `valid=False` with a reason. `trust_policy` that is not an `IssuerTrustPolicy` raises `TypeError` (caller bug).
- Order of checks, stopping at the first failure:
  1. decode and field validation
  2. issuer is listed in the trust policy (before any key lookup)
  3. issuer key resolves
  4. issuer signature over the signed bytes
  5. `issued_at <= now + 5` (clock skew, seconds)
  6. `now < expires_at`
  7. claims within the issuer's allowance
  8. a v1 scope is accepted only if `issued_at < scope_v1_cutoff`; otherwise reason `scope_v1_expired`
  9. revocation: `is_revoked(root.issuer, root.binding())`; `RevocationSourceUnreachable` fails closed
- The cutoff compares the issuer-signed `issued_at`, which the issuer can backdate; root lifetime is at most 86400 s, so no v1 root accepted under a cutoff is valid after cutoff + 86400. v1 is read only and is removed in a later minor release.
- No possession proof is checked. `valid=True` means the issuer signed these claims, the issuer may assert them, and the root is in its validity window and not revoked. It does not show that any presenter holds `subject`'s key.

## Scope

v2 shape is exactly `{"permissions": [{"tools": [...], "resources": [...], "max_cost_per_call": int}, ...]}` (`validate_scope`).

- 1 to 16 permissions; at most 64 tool and resource entries in total across them. Counts are checked before any entry is validated, and a `Permission` refuses more than 64 entries in a list.
- Each permission allows every listed tool on every listed resource, at most `max_cost_per_call` (integer 0 to 2**53-1) per call. Pairing is per permission: a tool from one permission is never allowed on a resource from another.
- `tools` and `resources` are non-empty. An entry may not appear twice in one list (exact string equality); the same entry may appear in different permissions. Two equal permissions are refused.
- Order is not semantic but is signed: reordering permissions or entries yields a valid record with a different binding, which needs its own revocation.
- A scope with both key sets, or any other keys, is refused.

v1 shape is exactly `{"tools": [...], "resources": [...], "max_cost_per_call": int}` (at most 64 entries per list, lists may be empty; `validate_scope_v1`). It is read only: it is normalized to exactly one permission with the same semantics, and new roots and links cannot carry it.

`scope_version(scope)` returns 2 or 1 from the keys alone and raises `ValueError` for any other shape. `permissions_of(scope)` validates and returns an immutable tuple of `Permission(tools, resources, max_cost_per_call)`; an invalid scope raises `ValueError`. Records expose this view as `.permissions`, built once at construction or decode; signed bytes, binding and encoding always use the received body, never the view. A record holds `scope` as canonical bytes and every read of `.scope` returns a fresh copy, so mutating that copy, or the dict passed to `issue_task_root`, `delegate` or the constructor, changes neither the signed bytes, the binding nor the view.

- Entry: an exact id, or a prefix pattern. Ids are ASCII printable (0x21 to 0x7E, no whitespace), at most 128 characters; callers normalise before.
- A prefix pattern is a non-empty prefix whose last character is one of `.` `:` `/` `_` `-`, followed by a single final `*`. `deploy.*` is valid and covers `deploy.prod` but not `deployx`. `deploy*`, bare `*`, `a*b` and `**` are refused.
- Ids are opaque strings, never path-resolved or percent-decoded. `/` delimits segments; a segment may not be empty, `.` or `..` (a prefix stem may end in `/`). `env/prod/../secret`, `env//prod`, `/env` and `env/prod/` are refused as entries and never covered as queries; `env/%2e%2e/x` is an ordinary id.
- `check_call(permissions, tool, resource, cost) -> CallRefusal | None` decides one call against a `.permissions` view. `None` (allowed) only if one permission covers both `tool` and `resource` and `cost` is at most that permission's cap. `OUT_OF_SCOPE` (`out_of_scope`): no permission covers the pair, or either id is not concrete (an invalid id, or one containing `*`). `COST_OVER_CALL_CAP` (`cost_over_call_cap`): some permission covers the pair but none allows `cost`. `permissions` that is not a tuple of `Permission` or a `bool` or non-integer `cost` raises `TypeError`; a cost outside 0 to 2**53-1 raises `ValueError`. Ids must be exactly `str`, `cost` exactly `int` and `permissions` exactly a `tuple` of `Permission`: a subclass could override the comparisons matching relies on, so a subclassed id is `OUT_OF_SCOPE` and a subclassed cost or permission raises `TypeError`. Entries and caps in a scope or `Permission` follow the same rule. This is the single call matcher; it is not `fnmatch`. `covers` is removed.
- `Permission.covers(tool, resource)` is the same pair check for one permission, without cost.
- `entry_covers(pattern, value)`: one entry against one value (prefix pattern by stem, exact id by equality). Pattern matching only: it validates neither argument, so a caller must refuse invalid or non-concrete values first.
- `scope_narrows(parent, child)`: every child permission is contained by one parent permission (`Permission.contains`): each child tool and resource lies inside one of that parent permission's entries (exact by equal id or covering prefix; prefix pattern only by a prefix pattern whose prefix it extends) and the child cap is not above that parent permission's cap. Tools and resources from different parent permissions never combine, so `{read} x {todo, payroll}` under parents `{read} x {todo}` and `{read} x {payroll}` does not narrow; the issuer splits it. A v1 child under a v2 parent, or an invalid scope on either side, does not narrow. A v1 parent is one permission.
- The issuer trust policy does not bound `scope`; the root scope is whatever the listed issuer signed.

Mapping to RFC 9396 (OAuth 2.0 Rich Authorization Requests): `permissions` corresponds to `authorization_details`, an array of objects each pairing `actions` with `locations`. `tools` maps to `actions`, `resources` to `locations`. There is no `type` field; `max_cost_per_call` has no RAR counterpart. RFC 9396 leaves comparing two authorization details to each type; the containment rule above is this library's.

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

Record type `chain-link`, version 2 for a permissions scope and 1 for a v1 scope. Fields, all required, none optional:

| Field | Type | Rule |
| --- | --- | --- |
| `task_id` | id | equals the root's |
| `tenant_id` | id | equals the root's |
| `task_root` | digest | binding of the TaskRoot |
| `parent_hash` | digest | binding of the previous record: the TaskRoot for the first link, otherwise the previous link |
| `issuer` | public key | the previous holder; signs the link; must equal the previous record's `subject` |
| `subject` | public key | the next holder |
| `scope` | object | v2 or (read only) v1, as in the TaskRoot; narrows the previous record's scope |
| `budget` | integer | at most the previous record's budget |
| `depth` | integer | 1 to 16; previous depth + 1 (the TaskRoot is depth 0) |
| `issued_at` | integer | seconds; at least the previous `issued_at`; at most `now + 5` |
| `expires_at` | integer | seconds; greater than `issued_at`; at most the previous `expires_at`; at most 86400 s after `issued_at`; greater than `now` |

- Digests are canonical unpadded base64url of 32 bytes. Public keys follow the TaskRoot "Public keys" rule. Ids follow the TaskRoot "Ids" rule.
- A link's binding is `base64url(sha256(signed bytes))`. Signed bytes are `signing_input("chain-link", version, body)`, with `version` the scope version as for the TaskRoot; a body under the other version's tag does not verify. Transport and canonical-body rules are the TaskRoot's; encoded length is at most 16384 characters.
- The root's `max_depth` bounds the number of links. `max_depth` 0 allows no links.
- A v1 link under a v1 record and a v2 link under a v1 record are accepted; a v1 link under a v2 record is refused (`v1 scope under a v2 scope`).

## delegate

`delegate(root, parent, parent_holder_key, *, child_subject, scope, budget, ttl, now) -> ChainLink`, where `parent` is the TaskRoot or the previous link. It raises `TypeError` if `root` is not a TaskRoot, and `ValueError` for anything verification would refuse: a TaskRoot `parent` that is not `root`, a key that is not `parent.subject`, a parent from another root, depth over `root.max_depth`, a v1 `scope` (`scope: a v1 scope cannot be delegated, use permissions`), a scope that does not narrow, budget above the parent's or not an integer, a parent not valid at `now`, an invalid `child_subject`, a non-positive `ttl`. `expires_at` is `min(now + ttl, parent.expires_at)`. Links are signed as version 2.

## Possession proof

`LeafProof` is `{audience, binding, iat, request_digest}` plus a signature, transported like a link. The signed bytes are `signing_input("possession", 1, {"audience": ..., "binding": ..., "iat": ..., "request_digest": ...})` under the leaf subject's key (the TaskRoot's subject when there are no links).

- `binding` is the leaf record's binding, so a proof for one record does not satisfy another.
- `audience` is the id of the verifier the proof is addressed to (same alphabet and length as other ids). A proof presented to a different verifier is refused.
- `request_digest` is the canonical base64url sha256 digest of the one request the proof authorizes (the executor uses the Operation digest). A proof presented with a different request is refused.
- The `possession` tag keeps a proof from verifying as a link or a root and the reverse.
- A proof is not single-use: the same chain and proof replayed to the same verifier for the same request within the age window is accepted. Making that effect happen once is the ledger's idempotency key, not this check.

## verify_chain

`verify_chain(root_encoded, links_encoded, leaf_proof, resolver, trust_policy, revocation_checker, now, *, expected_audience, expected_request_digest, scope_v1_cutoff, max_proof_age_seconds=60) -> ChainVerifyResult(valid, reason, root, links, checked_at)`. `scope_v1_cutoff` is required and keyword-only, with the `verify_root` rules.

- Never raises on attacker-controlled input; every failure is `valid=False` with a reason. `expected_audience` must be an id, `expected_request_digest` a canonical digest and `max_proof_age_seconds` an integer >= 0, else the result is `valid=False`. `revocation_checker` that is `None` or lacks `is_revoked` raises `TypeError` (caller bug). `now` is an integer.
- Total encoded size (root plus links) is at most 262144 characters.
- Order of checks, stopping at the first failure:
  1. the root, as `check_root` (decode, policy lists issuer, issuer signature, validity window, issuer allowance, v1 cutoff)
  2. number of links at most `root.max_depth`
  3. per link, in order: decode; same `task_id` and `tenant_id` as the root; `task_root` equals the root binding; `issuer` equals the previous subject; `parent_hash` equals the previous binding; `depth` is previous + 1; signature by `issuer`; not a v1 scope under a v2 record; scope narrows; budget not above previous; `expires_at` not after previous; `now < expires_at`; `issued_at` not before previous; `issued_at <= now + 5`
  4. leaf proof: decodes; bound to the leaf binding; signature by the leaf subject; `audience` equals `expected_audience`; `request_digest` equals `expected_request_digest`; `iat <= now + 5`; `now - iat <= max_proof_age_seconds`
  5. revocation, once, with a `ChainContext`
- Reordered, duplicated or skipped links fail the `parent_hash`/`issuer`/`depth` checks. A link from another task or tenant fails the `task_id`/`tenant_id` check; a link under a different root with the same task and tenant fails the `task_root` check.
- A TaskRoot alone never yields a valid chain: the proof must be signed by the leaf subject's key, and links must be signed by the previous subject's key. A captured chain and proof is useless to another verifier or for another request.
- `valid=True` means the chain is authentic and narrowing, inside its validity window, not revoked, and the presenter holds the leaf key now. `leaf_scope`, `leaf_permissions` and `leaf_subject` expose the leaf's authority; applying it (`check_call(result.leaf_permissions, tool, resource, cost)`) and charging budget are the caller's job. All three are `None` on an invalid result.
- Only the root is subject to the v1 cutoff. A v1 link can only sit under a v1 root, so it ends with that root.

## Chain revocation

`ChainRevocationChecker.is_revoked(context) -> bool`, with `ChainContext(task_id, tenant_id, root_issuer, task_root, link_bindings)`.

- Mandatory. Called last and once, so an invalid chain never triggers a lookup.
- Returns `True` if the task, the tenant, the root or any listed link is revoked. Revoking a link revokes every chain that contains it and no chain that stops before it.
- Only an explicit `False` means not revoked. Any other return value (`None`, `0`, `""`, ...) is treated as revoked, and any exception other than `RevocationSourceUnreachable` yields `valid=False` with reason `revocation check failed`. The same rule applies to `verify_root` and `verify`.
- Raises `RevocationSourceUnreachable` when status cannot be determined; `verify_chain` then returns `valid=False`. Returning `False` on uncertainty is a checker bug.
- The root is not checked separately by a `RevocationChecker`; the chain checker decides on `context.task_root`.

## Scope matching (`scope.py`)

Rules are in the TaskRoot "Scope" section. In a chain, a prefix pattern ends at a separator (`.` `:` `/` `_` `-`) before `*`, so `deploy.*` never covers `deployx`. `check_call` is the enforcement matcher and `scope_narrows` is the delegation check; both use the same entry rules (`entry_covers`). Principal prefixes in the trust policy use their own stricter delimiter set (`:` `/` `.`).
