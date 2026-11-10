# Changelog

Notable changes. This project follows [Semantic Versioning](https://semver.org). While on `0.x`, minor versions may include breaking changes.

## [Unreleased]

### Ledger

- `TaskLedger.create(path, shared_group=gid)` and `TaskLedger.open(path, shared_group=gid)`: the file is mode 0640 in group `gid` instead of 0600. The writer must run with `gid` as its effective group (for example systemd `Group=`); otherwise it is refused before touching the file. The default is unchanged.
- The writer now also checks the `-wal` and `-shm` files when present: regular file (not a symlink), owner, the database's mode and group, one link.
- `TaskLedger.open_read_only(path, writer_uid, group)` returns a `ReadOnlyLedger`: `O_RDONLY` file checks (owner `writer_uid`, mode 0640, group `group`, one link, SQLite header, same device and inode, and the same checks on `-wal` and `-shm`, which must exist), SQLite `mode=ro` with no attached databases and an authorizer allowing only reads, `is_revoked` and `reservation_readonly`; no PRAGMA writes, no transactions, no release of expired reservations; mutating methods raise `LedgerUnavailable`. It opens only while the writer holds the WAL database open. See `docs/spec/ledger.md`.

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
