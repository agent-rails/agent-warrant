# Task ledger

Facts about `agent_warrant.ledger`. Chain and revocation context rules: `grant-chain.md`. Race tests: `tests/test_ledger_race.py`.

## Scope and limits

- Single host, single SQLite file (stdlib `sqlite3`). Several processes on the same host may share the file; hosts may not. A multi-host deployment needs a networked database behind the same interface.
- One connection per call, WAL journal, `synchronous = FULL`, `foreign_keys = ON`, busy timeout 30 s, parameterized statements only. Every mutating call is one `BEGIN IMMEDIATE` transaction.
- The file is created with mode 0600. Schema version is `PRAGMA user_version = 1`; any other non-zero version is refused.
- The ledger does not verify signatures. It trusts its caller to pass only a valid `verify_root` result to `open_task` and only the links of a chain that `verify_chain` accepted to `reserve`. Code running as the same OS user can edit the file; protecting it needs a separate user (enforced mode) and is not provided here.
- Time is the integer `now` the caller passes; the ledger never reads a clock.

## Errors

- `Refused`: a policy refusal. Nothing was changed.
- `LedgerUnavailable`: the database could not be read or written (including a corrupt file or unsupported schema). Callers fail closed.
- `ValueError`: a malformed argument such as a non-integer `now` or a malformed id or binding.

## Tasks

`open_task(result, now)` takes a valid `TaskRootResult` from `verify_root` and stores `(tenant_id, task_id) -> root binding, budget, spent = 0`. Opening the same root again is a no-op. A different root for an existing `(tenant_id, task_id)`, or a root whose binding, task or tenant is revoked, is refused. `task_id` is unique only within a tenant.

## Revocation

- `revoke(binding, now)`, `revoke_task(tenant_id, task_id, now)`, `revoke_tenant(tenant_id, now)`. Task revocation is keyed by tenant and task, because task ids are unique only per tenant.
- Insert-only: repeats are no-ops, there is no un-revoke API, and triggers abort any `UPDATE` or `DELETE` on the three revocation tables.
- `is_revoked(context)` implements `ChainRevocationChecker`: true if the root binding, any link binding, the task or the tenant is revoked. A database error raises `RevocationSourceUnreachable`.

## Operation

Built by the trusted executor only. Fields: `op_id`, `tenant_id`, `task_id`, `leaf_binding`, `tool`, `resource`, `args_digest`, `cost`, `verdict_allowed`, `expires_at`.

- `op_id`, `tenant_id`, `task_id`: ASCII printable ids without whitespace. `tool`, `resource`: concrete scope ids (valid entries with no `*`). `leaf_binding`, `args_digest`: canonical base64url sha256 digests. `cost`: integer 0 to 2**53-1. `verdict_allowed`: bool. `expires_at`: non-negative integer seconds.
- `digest()` is `base64url(sha256(signing_input("operation", 1, fields)))` over all ten fields, so a change to any field changes the digest.
- `op_id` is unique per `(tenant_id, task_id)`.

## reserve

`reserve(operation, links, now) -> Reservation`, where `links` are the verified chain's `ChainLink` records in order (empty when the TaskRoot subject acts directly). In one transaction, in order:

1. Expired `reserved` reservations of this task are released (below).
2. If `(tenant_id, task_id, op_id)` already exists: the same digest returns the stored reservation in its current state (including `released`); a different digest is refused. No other check runs.
3. Refused: verdict not allow; `now >= expires_at`; unknown task; links of another tenant or task; links that do not chain from the task's root binding by `parent_hash` and `task_root`; `leaf_binding` not equal to the last link's binding (the root binding with no links); the root, any link, the task or the tenant revoked.
4. Refused if `spent + cost > budget` for the task pool, or `spent + cost > cap` for any link. A link registers on first reserve with its `budget` as its cap; the same binding with different terms is refused.
5. The cost is added to the pool and to every link in the chain, and the reservation is stored as `reserved` with the operation's `expires_at`.

A malformed operation (including a negative, non-integer or boolean cost) is refused before any database access.

## State machine

```
reserved --mark_issued--> issued --mark_done--------------> done
   |                         \--mark_outcome_unknown-----> outcome_unknown
   \--(expires_at reached, not issued)--> released
```

- `reserved`, `issued`, `done` and `outcome_unknown` hold their cost against the pool and every link cap.
- `released` returns the cost to the pool and the links. It happens only to a `reserved` reservation whose `expires_at <= now`, on the next ledger access for that task (`reserve`, `mark_*`, `reservation`, `task_budget`, `link_budget`). A released reservation is never issued, and its `op_id` stays used.
- `mark_issued` is recorded before a credential is minted. It is refused if the reservation was released, was already issued, or the root, a link, the task or the tenant is now revoked (the cost stays held).
- `mark_done` and `mark_outcome_unknown` are accepted only from `issued`. Any other transition is refused.
- `issued` reservations are not released by expiry. `outcome_unknown` is never credited back automatically; reconciling it is an operator action outside this API.

## Read helpers

`reservation(tenant_id, task_id, op_id, now)`, `task_budget(tenant_id, task_id, now) -> BudgetStatus(budget, spent)`, `link_budget(link, now)`; all release expired reservations first.

## Concurrency

Transactions take the write lock up front, so concurrent `reserve` calls from separate processes serialize. Tests start real subprocesses on one database file: two racers for the last unit yield exactly one winner; eight racers for three units yield exactly three; four racers using the same `op_id` charge once.
