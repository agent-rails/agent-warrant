# Grant chain, part 1: task root and issuer trust policy

Facts about `agent_warrant.task_root` and `agent_warrant.trust`. Byte profile: `canonical.md`. Vectors: `tests/vectors/task_root.json`, checked by `tests/test_task_root_vectors.py`. Later parts (delegation links, ledger) are not specified here.

## TaskRoot

Record type `task-root`, version 1. Fields, all required, none optional:

| Field | Type | Rule |
| --- | --- | --- |
| `task_id` | string | non-empty, at most 256 characters |
| `tenant_id` | string | non-empty, at most 256 characters |
| `principal` | string | non-empty, at most 256 characters |
| `purpose` | string | non-empty, at most 256 characters; persona label |
| `budget` | integer | 0 to 2**53-1 |
| `max_depth` | integer | 0 to 16 (`MAX_CHAIN_DEPTH`) |
| `issued_at` | integer | seconds, 0 to 2**53-1 |
| `expires_at` | integer | seconds; greater than `issued_at`; at most 86400 s after it (same cap as `Issuer.MAX_TTL_SECONDS`) |
| `subject` | string | first delegate's Ed25519 public key, canonical unpadded base64url of 32 bytes |
| `issuer` | string | non-empty, at most 256 characters; resolved to a key by the `IssuerResolver` |

`proof` is the issuer's Ed25519 signature and is not part of the body.

Strings are compared byte for byte. No Unicode normalisation is applied; callers must normalise ids before they enter a record.

## Wire form and signed bytes

- Body: `canonicalize` of the ten fields above.
- Signed bytes: `signing_input("task-root", 1, body)`, which is `b"agent-warrant/task-root/v1" + b"\x00" + canonical body`.
- Transport: `base64url(canonical body) + "." + base64url(signature)`, unpadded. Padding, whitespace or any other non-canonical base64url is refused. Encoded length is at most 16384 characters.
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

## Issuer trust policy

A resolver maps an issuer to a key only, so a valid signature alone does not authorise a tenant, principal or budget. `IssuerTrustPolicy` maps issuer id to an `IssuerAllowance`:

- `tenants`: exact tenant ids.
- `principals`: exact principals.
- `principal_prefixes`: a principal also matches if it starts with a listed prefix. Prefixes must be non-empty; there are no wildcards.
- `max_budget`, `max_depth`: inclusive upper bounds, integers 0 to 2**53-1.
- An empty set allows nothing. An issuer absent from the policy is refused.
- Collections passed as a bare `str` raise `TypeError`; empty entries raise `ValueError`.

The policy is copied at construction.
