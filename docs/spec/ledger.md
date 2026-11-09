# Task ledger

Facts about `agent_warrant.ledger`. Chain and revocation context rules: `grant-chain.md`. Race tests: `tests/test_ledger_race.py`.

## Scope and limits

- Single host, single SQLite file (stdlib `sqlite3`). Several processes on the same host may share the file; hosts may not. A multi-host deployment needs a networked database behind the same interface.
- One SQLite connection per `TaskLedger`, opened after the file checks and reused until `close()` (also a context manager). WAL journal, `synchronous = FULL`, `foreign_keys = ON`, busy timeout 30 s, parameterized statements only. Every mutating call is one `BEGIN IMMEDIATE` transaction.
- Interrupts: if a signal or other `BaseException` hits between `BEGIN IMMEDIATE` and the end of `COMMIT`, the transaction is rolled back; if the rollback itself fails, the connection is closed and dropped, and the next call reconnects through the full file checks. A connection is therefore never left holding the write lock.
- Threads: the connection is opened with `check_same_thread=False` and each call holds one lock, so a ledger may be shared between threads; calls serialize. A ledger is bound to the process that opened it: a call from a forked child raises `LedgerUnavailable`; open a new `TaskLedger` after `fork()`. Several processes may use the same file.
- `TaskLedger.create(path)` creates a new ledger: `O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600, schema written. It refuses an existing path. `TaskLedger.create(path, shared_group=gid)` creates the file 0600, sets its group to `gid` and only then widens it to 0640; if the group cannot be set (the effective user is not in it) the new file is removed and `LedgerUnavailable` is raised. `TaskLedger.open(path)` (and `TaskLedger(path)`, both also taking `shared_group`) attach to an existing ledger and never create a file; a missing file, an empty file or a database without the schema raises `LedgerUnavailable`, and `is_revoked` on a deleted database raises `RevocationSourceUnreachable` and does not recreate it. SQLite is opened with URI `mode=rw`. Schema version is `PRAGMA user_version = 1`; any other value is refused.
- Before every call the path is re-opened with `O_NOFOLLOW` and inspected with `fstat`: it must be a regular file, owned by the effective user, with mode exactly 0600, or exactly 0640 and group `shared_group` when that is set (an existing file with any other mode or group is refused, never chmod-ed), with a single hard link (`st_nlink == 1`), starting with the SQLite header, and it must be the same file (device and inode) the connection was opened on. The device and inode are read before the connection is opened and again after it, and must match; a deleted, replaced, loosened, hard-linked or header-overwritten file raises `LedgerUnavailable` (`RevocationSourceUnreachable` from `is_revoked`). The parent directory must exist and must not be group or other writable (so a sticky `/tmp` is refused). What this does not stop: the checks and each SQLite statement are separate steps, so a process running as the same user can modify the file's contents between them, or swap the file between a check and the next statement (detected only on the next call). The `-wal` and `-shm` sidecar files are created by SQLite with the database's mode but are not individually inspected. Protecting against a same-user attacker needs a separate OS user and is not provided here.
- The ledger does not verify signatures. It trusts its caller to pass only a valid `verify_root` result to `open_task` and only the links of a chain that `verify_chain` accepted to `reserve`. Code running as the same OS user can edit the file; protecting it needs a separate user (enforced mode) and is not provided here.
- Time is the integer `now` the caller passes, 0 to 2**53-1; the ledger never reads a clock.

## Read-only open

`TaskLedger.open_read_only(path, writer_uid, group) -> ReadOnlyLedger` is for a process running as another user that must check revocations and reservations but never change them.

- The file is opened `O_RDONLY | O_NOFOLLOW` and checked with `fstat` before every call: a regular file owned by `writer_uid`, mode exactly 0640, `st_gid == group`, one hard link, the SQLite header, and the same device and inode the connection was opened on (read before and after connecting, as for the writer). The parent directory rule is the writer's. A failed check raises `LedgerUnavailable` (`RevocationSourceUnreachable` from `is_revoked`). The schema version is read with `PRAGMA user_version` and must be 1.
- SQLite is opened with URI `mode=ro`. No PRAGMA is set, no transaction is begun and expired reservations are not released. Each read is one `SELECT`.
- `is_revoked(context)`: the writer's check, read-only.
- `reservation_readonly(tenant_id, task_id, op_id) -> Reservation | None`: the stored row as it is. A `reserved` row whose `expires_at` has passed is returned unchanged; the caller must compare `expires_at` with its own clock and treat it as unusable.
- Every mutating method of `TaskLedger` (`open_task`, `revoke*`, `reserve`, `mark_*`) and the read helpers that release expired reservations (`reservation`, `task_budget`, `link_budget`) raise `LedgerUnavailable`.
- Dependency on the writer: the database is in WAL mode. SQLite (3.22.0 and later) reads a WAL database without write access only if the `-wal` and `-shm` files already exist and are readable, or the directory is writable (sqlite.org/wal.html, section 5). The reader cannot write the directory, and the last connection to close deletes both files, so a reader works only while the writer holds the database open. Otherwise every call raises `LedgerUnavailable`; callers fail closed.
- Sidecar files: SQLite creates `-wal` and `-shm` with the database's mode (0640 in shared-group mode). Their group is set by the operating system when they are created, not by this library, and they are not inspected. Run the writer with the shared group as its effective group so that the reader can open them. Linux CI tests this with a second OS user: the writer runs under `sg` with the shared group, the database and both sidecars are 0640 in that group, the reader sees the writer's commits, cannot open the file for writing, and fails with `LedgerUnavailable` after the writer closes.
- Not protected: the writer (or any process running as the writer's user) can still change any row the reader sees. The reader only guarantees that it does not write and that the file it reads has the expected owner, mode and group.

## Errors

- `Refused`: a policy refusal, including a database constraint violation. Nothing was changed.
- `LedgerUnavailable`: the database could not be read or written (a missing, replaced, corrupt or unsafe file, an unsupported schema, or any unexpected error inside a transaction). Callers fail closed.
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
3. Refused: verdict not allow; `now >= expires_at`; unknown task; `now >= min(root.expires_at, every link.expires_at)` (`chain has expired`); links that do not chain from the task's root binding by `parent_hash` and `task_root`; `leaf_binding` not equal to the last link's binding (the root binding with no links); the root, any link, the task or the tenant revoked.
4. Refused if a link's `budget` or `expires_at` is not an integer in 0 to 2**53-1, if a link's `budget` exceeds its parent's (the root's budget for the first link), if `spent + cost > budget` for the task pool, or if `spent + cost > cap` for any link. A link registers on first reserve with its `budget` as its cap; the same binding with different terms is refused. The budget check is defense in depth: the documented trust boundary is unchanged and a forged link is still the caller's problem.
5. The cost is added to the pool and to every link in the chain, and the reservation is stored as `reserved` with `expires_at = min(operation.expires_at, root.expires_at, every link.expires_at)`.

A malformed operation (including a negative, non-integer or boolean cost) and links of another tenant or task are refused before any database access.

## State machine

```
reserved --mark_issued--> issued --mark_done--------------> done
   |                         \--mark_outcome_unknown-----> outcome_unknown
   \--(expires_at reached, not issued)--> released
```

- `reserved`, `issued`, `done` and `outcome_unknown` hold their cost against the pool and every link cap.
- `released` returns the cost to the pool and the links. It happens only to a `reserved` reservation whose `expires_at <= now`, on the next ledger access for that task (`reserve`, `mark_*`, `reservation`, `task_budget`, `link_budget`). A released reservation is never issued, and its `op_id` stays used.
- `mark_issued` is recorded before a credential is minted. Because the reservation expires with the chain, it is refused at or after the chain's earliest expiry (the reservation has been released), and also if the reservation was released, was already issued, or the root, a link, the task or the tenant is now revoked (the cost stays held).
- `mark_done` and `mark_outcome_unknown` are accepted only from `issued`. Any other transition is refused.
- `issued` reservations are not released by expiry. `outcome_unknown` is never credited back automatically; reconciling it is an operator action outside this API.

## Read helpers

`reservation(tenant_id, task_id, op_id, now)`, `task_budget(tenant_id, task_id, now) -> BudgetStatus(budget, spent)`, `link_budget(link, now)`; all release expired reservations first.

## Concurrency

Transactions take the write lock up front, so concurrent `reserve` calls from separate processes serialize. Tests start real subprocesses on one database file: two racers for the last unit yield exactly one winner; eight racers for three units yield exactly three; four racers using the same `op_id` charge once.
