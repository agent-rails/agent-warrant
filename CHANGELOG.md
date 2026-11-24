# Changelog

Notable changes. This project follows [Semantic Versioning](https://semver.org). While on `0.x`, minor versions may include breaking changes.

## [Unreleased]

## [0.4.0] - 2026-11-24

### Scopes, task roots and chains

- Breaking: scopes are lists of permissions, `{"permissions": [{"tools": [...], "resources": [...], "max_cost_per_call": int}, ...]}`. A call is allowed only if one permission covers both its tool and its resource and its cost is within that permission's cap, so tools and resources from different permissions no longer pair. Bounds: 1 to 16 permissions, at most 64 entries in total, non-empty lists, no entry twice in one list, no permission twice. See `docs/spec/grant-chain.md`, Scope.
- Breaking: `covers` is removed. Use `check_call(permissions, tool, resource, cost)`, which returns `None` or `CallRefusal.OUT_OF_SCOPE` / `CallRefusal.COST_OVER_CALL_CAP` and checks cost. Ids, entries, costs and caps must be exactly `str` and `int`; subclasses are refused. New: `validate_scope_v1`, `scope_version`, `Permission`, `permissions_of`, `CallRefusal`, `entry_covers`. `validate_scope` checks the permissions shape.
- Breaking: `scope_narrows` requires each child permission to fit inside one parent permission, with a cap not above that permission's cap. A v1 child under a v2 parent does not narrow.
- Breaking: `issue_task_root` and `delegate` refuse a v1 scope and sign version 2 records. The record version is taken from the scope shape, so a body under the other version's tag does not verify. v1 roots and links keep their signed bytes and bindings.
- Breaking: `verify_root`, `check_root` and `verify_chain` take a required keyword-only `scope_v1_cutoff` (Unix seconds, no default). A v1 root issued at or after it is refused with `scope_v1_expired`; 0 refuses every v1 root. v1 scopes are read only and will be removed in a later minor release.
- `verify_chain` refuses a v1 link under a v2 record (`v1 scope under a v2 scope`). `TaskRoot` and `ChainLink` expose `scope_version` and `permissions`; `ChainVerifyResult.leaf_permissions` is the leaf's view, ready for `check_call`.
- 0.3.0 and earlier refuse v2 records. Upgrade every verifier, with the same `scope_v1_cutoff`, before issuing v2 roots.
- Opt-in benchmarks: `pytest -m bench` (`tests/test_scope_bench.py`).

## [0.3.0] - 2026-11-20

### Ledger

- Breaking: the parent directory of a ledger must now be owned by root or the ledger's owner (the effective user for the writer, `writer_uid` for `open_read_only`). Another user owning it could rename the ledger even when the directory is not group or other writable. A root writer in a directory owned by another user is now refused; move the ledger into a directory owned by the writer, or by root for a root writer.
- Fix: the file checks no longer open the database. Closing that descriptor released every POSIX lock SQLite held on the file in the process, so another process closing its connection (for example a second `TaskLedger.open(...).close()`) checkpointed and deleted `-wal` and `-shm` while this process kept writing to the deleted files: its writes were invisible to other connections and lost when it closed. Reproduced on Linux (SQLite 3.46.1); not reproduced on macOS. The file is now inspected with `lstat` only, SQLite checks the header when connecting, and a `-wal` or `-shm` file that is removed or replaced while connected closes the connection and fails the call; the next call reconnects.
- Changed: a database header overwritten in place after the connection is open is no longer detected on the next call. This is the same-user modification the spec already excludes. Messages for a missing or symlinked path are now `cannot inspect ledger file` and `ledger path is not a regular file`.

## [0.2.0] - 2026-11-15

### Ledger

- `TaskLedger.create(path, shared_group=gid)` and `TaskLedger.open(path, shared_group=gid)`: the file is mode 0640 in group `gid` instead of 0600. The writer must run with `gid` as its effective group (for example systemd `Group=`) and the parent directory must be in group `gid`; otherwise it is refused before touching the file. The default is unchanged.
- The writer now also checks the `-wal` and `-shm` files when present: regular file (not a symlink), owner, the database's mode and group, one link.
- `TaskLedger.open_read_only(path, writer_uid, group)` returns a `ReadOnlyLedger`: `O_RDONLY` file checks (owner `writer_uid`, mode 0640, group `group`, one link, SQLite header, same device and inode, and the same checks on `-wal` and `-shm`, which must exist), SQLite `mode=ro` with no attached databases and an authorizer allowing only reads, `is_revoked` and `reservation_readonly`; no PRAGMA writes, no transactions, no release of expired reservations; mutating methods raise `LedgerUnavailable`. It opens only while the writer holds the WAL database open. See `docs/spec/ledger.md`.
- `TaskLedger.issued_expired(now)`: `issued` reservations whose expiry has passed, for restart recovery. Read-only.
- File-check errors no longer include the file's path.

## [0.1.0] - 2026-11-09

First release. Specs: `docs/spec/`. Design history: `docs/DESIGN.md`. Limits: `docs/THREAT_MODEL.md`.

### Grants (top-level `agent_warrant`)

- `Grant`, `PossessionProof`, `sign()`, `prove()`, `verify()`; `Issuer`, `Verifier`, `HolderKeypair`. Ed25519, issuer-signed, scoped, expiring; a fresh possession proof binds the grant to its holder.
- `IssuerResolver`, `PinnedResolver` (out-of-band key pinning) and `DidWebResolver` (did:web over HTTPS; Multikey, `JsonWebKey2020` and `publicKeyBase58` Ed25519 keys). Fails closed. HTTPS fetches refuse non-global addresses and dial the screened IP.
- Opt-in revocation: `RevocationChecker`, `RevocationList` (issuer-signed, with `sequence` and expiry), `StaticRevocationChecker` (checks the list's signature, issuer and expiry once, when constructed; `is_revoked()` keeps using that list, so the caller replaces the checker before the list expires), `HttpRevocationChecker` (fetches and checks the list on every call). A list that cannot be fetched or fails a check fails closed.

### Task roots and delegation chains

- `agent_warrant.canonical`: canonical byte profile, `strict_decode` (duplicate keys, depth, size and integer range refused) and domain-separated `signing_input`.
- `agent_warrant.task_root`: `TaskRoot`, `issue_task_root`, `verify_root`. One signed root per task carries tenant, principal, purpose, budget, maximum chain depth and scope.
- `agent_warrant.trust`: `IssuerTrustPolicy`, `IssuerAllowance`, `TenantAllowance`. A valid signature alone does not authorise a tenant, principal or budget.
- `agent_warrant.scope`: scope validation, `covers`, `scope_narrows`.
- `agent_warrant.chain`: `ChainLink`, `delegate`, `LeafProof`, `prove_leaf`, `verify_chain`. Each link narrows scope, budget and expiry; the leaf proof is bound to an audience and a request digest. `verify_chain` returns `valid=False` with a reason instead of raising on untrusted input.

### Ledger

- `agent_warrant.ledger.TaskLedger`: single-host SQLite ledger. Insert-only revocation of a binding, task or tenant (`is_revoked` implements the chain revocation check); `reserve` enforces the task budget and every link cap and refuses a replayed `op_id` with different contents; reservations move `reserved`, `issued`, `done` or `outcome_unknown`, and expired unissued reservations are released.
- The file must be a regular, 0600, single-link file owned by the effective user in a directory that is not group or other writable. A process running as the same OS user can still change it; see `docs/spec/ledger.md`.

## Stability

- Public API is everything exported from `agent_warrant`'s top-level `__all__`, plus the names without a leading underscore in `agent_warrant.canonical`, `agent_warrant.task_root`, `agent_warrant.trust`, `agent_warrant.scope`, `agent_warrant.chain` and `agent_warrant.ledger`.
- On `0.x`: breaking changes may land in minor releases. Pin to `~=0.1.0` if you need stability.
- Ships PEP 561 type information (`py.typed`).
