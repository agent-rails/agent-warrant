from __future__ import annotations

import os
import sqlite3
import stat
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn
from urllib.parse import quote

from .canonical import MAX_SAFE_INTEGER, signing_input
from .chain import ChainContext, ChainLink
from .encoding import b64u_decode, sha256_b64u
from .exceptions import RevocationSourceUnreachable
from .scope import validate_entry
from .task_root import TaskRootResult

SCHEMA_VERSION = 1
SQLITE_MAGIC = b"SQLite format 3\x00"
OPERATION_TYPE = "operation"
OPERATION_VERSION = 1
STATES = ("reserved", "issued", "done", "outcome_unknown", "released")
BUSY_TIMEOUT_SECONDS = 30
SIDECAR_SUFFIXES = ("-wal", "-shm")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    root_binding TEXT NOT NULL,
    budget INTEGER NOT NULL CHECK (budget >= 0),
    spent INTEGER NOT NULL DEFAULT 0 CHECK (spent >= 0 AND spent <= budget),
    root_expires_at INTEGER NOT NULL,
    opened_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, task_id)
);
CREATE TABLE IF NOT EXISTS revoked_bindings (
    binding TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS revoked_tasks (
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    revoked_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, task_id)
);
CREATE TABLE IF NOT EXISTS revoked_tenants (
    tenant_id TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);
"""

_RESERVATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS links (
    binding TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    cap INTEGER NOT NULL CHECK (cap >= 0),
    spent INTEGER NOT NULL DEFAULT 0 CHECK (spent >= 0 AND spent <= cap),
    FOREIGN KEY (tenant_id, task_id) REFERENCES tasks (tenant_id, task_id)
);
CREATE TABLE IF NOT EXISTS reservations (
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    op_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    leaf_binding TEXT NOT NULL,
    cost INTEGER NOT NULL CHECK (cost >= 0),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'issued', 'done', 'outcome_unknown', 'released')),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, task_id, op_id),
    FOREIGN KEY (tenant_id, task_id) REFERENCES tasks (tenant_id, task_id)
);
CREATE TABLE IF NOT EXISTS reservation_links (
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    op_id TEXT NOT NULL,
    binding TEXT NOT NULL REFERENCES links (binding),
    PRIMARY KEY (tenant_id, task_id, op_id, binding),
    FOREIGN KEY (tenant_id, task_id, op_id) REFERENCES reservations (tenant_id, task_id, op_id)
);
"""

_INSERT_ONLY_TABLES = ("revoked_bindings", "revoked_tasks", "revoked_tenants")


class LedgerError(Exception):
    """Base class for ledger failures."""


class Refused(LedgerError):
    """The ledger refused a request on policy grounds (unknown or revoked task, budget
    exhausted, reused op_id, bad state transition). Nothing was changed."""


class LedgerUnavailable(LedgerError):
    """The database could not be read or written. Callers must fail closed."""


def _check_parent(path: Path) -> None:
    try:
        parent_mode = os.stat(path.parent).st_mode
    except OSError as err:
        raise LedgerUnavailable(f"cannot inspect parent directory: {err.strerror}") from err
    if not stat.S_ISDIR(parent_mode) or parent_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise LedgerUnavailable("parent directory must exist and not be group or other writable")


@dataclass(frozen=True)
class _FilePolicy:
    flags: int
    owner: int
    mode: int
    group: int | None
    require_sidecars: bool = False


def _check_sidecars(path: Path, policy: _FilePolicy) -> None:
    """Refuse `-wal` and `-shm` files that do not match `policy`: inspected with lstat
    (a symlink is refused, not followed), each must be a regular file owned by
    `policy.owner`, with mode exactly `policy.mode`, in group `policy.group` when set,
    with a single hard link. A missing file is accepted unless `policy.require_sidecars`."""
    for suffix in SIDECAR_SUFFIXES:
        try:
            info = os.lstat(path.with_name(path.name + suffix))
        except FileNotFoundError:
            if policy.require_sidecars:
                raise LedgerUnavailable(
                    f"ledger {suffix} file is missing: the writer is not holding the database open"
                ) from None
            continue
        except OSError as err:
            raise LedgerUnavailable(f"cannot inspect ledger {suffix} file: {err.strerror}") from err
        if not stat.S_ISREG(info.st_mode):
            raise LedgerUnavailable(f"ledger {suffix} file is not a regular file")
        if info.st_uid != policy.owner:
            raise LedgerUnavailable(f"ledger {suffix} file owner is not the expected user")
        if stat.S_IMODE(info.st_mode) != policy.mode:
            raise LedgerUnavailable(
                f"ledger {suffix} file mode must be {oct(policy.mode)}, found {oct(stat.S_IMODE(info.st_mode))}"
            )
        if policy.group is not None and info.st_gid != policy.group:
            raise LedgerUnavailable(f"ledger {suffix} file group must be {policy.group}, found {info.st_gid}")
        if info.st_nlink != 1:
            raise LedgerUnavailable(f"ledger {suffix} file has multiple hard links")


def _check_file(path: Path, policy: _FilePolicy, allow_empty: bool = False) -> os.stat_result:
    """Refuse a database path that does not match `policy`. The file is opened with
    O_NOFOLLOW (no symlink is followed) and never created, and inspected with fstat: it
    must be a regular file, owned by `policy.owner`, with mode exactly `policy.mode`, in
    group `policy.group` when set, with a single hard link, starting with the SQLite
    header (an empty file only when `allow_empty`, while creating); its parent directory
    must not be group or other writable; the `-wal` and `-shm` files must pass
    `_check_sidecars`. A file is never chmod-ed here, only refused."""
    _check_parent(path)
    try:
        descriptor = os.open(path, policy.flags | os.O_NOFOLLOW)
    except OSError as err:
        raise LedgerUnavailable(f"cannot open ledger file: {err.strerror}") from err
    try:
        info = os.fstat(descriptor)
        header = os.pread(descriptor, len(SQLITE_MAGIC), 0)
    except OSError as err:
        raise LedgerUnavailable(f"cannot inspect ledger file: {err.strerror}") from err
    finally:
        os.close(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise LedgerUnavailable("ledger path is not a regular file")
    if info.st_uid != policy.owner:
        raise LedgerUnavailable("ledger file owner is not the expected user")
    if stat.S_IMODE(info.st_mode) != policy.mode:
        raise LedgerUnavailable(f"ledger file mode must be {oct(policy.mode)}, found {oct(stat.S_IMODE(info.st_mode))}")
    if policy.group is not None and info.st_gid != policy.group:
        raise LedgerUnavailable(f"ledger file group must be {policy.group}, found {info.st_gid}")
    if info.st_nlink != 1:
        raise LedgerUnavailable("ledger file has multiple hard links")
    if header != SQLITE_MAGIC and not (allow_empty and info.st_size == 0):
        raise LedgerUnavailable("ledger file is not a SQLite database")
    _check_sidecars(path, policy)
    return info


def _check_os_id(label: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _writer_policy(shared_group: int | None) -> _FilePolicy:
    """The writer's file policy. With `shared_group` the writer must run with that group
    as its effective group, because SQLite creates `-wal` and `-shm` in the creating
    process's group, not the database's."""
    if shared_group is None:
        return _FilePolicy(flags=os.O_RDWR, owner=os.geteuid(), mode=0o600, group=None)
    group = _check_os_id("shared_group", shared_group)
    if os.getegid() != group:
        raise LedgerUnavailable(
            f"shared_group {group} must be the writer's effective group, found {os.getegid()}; "
            "run the writer with the shared group as its primary group"
        )
    return _FilePolicy(flags=os.O_RDWR, owner=os.geteuid(), mode=0o640, group=group)


def _create_file(path: Path, policy: _FilePolicy) -> None:
    """Create a new empty ledger file with O_EXCL and mode 0600; never replaces a file
    and never creates through a symlink. With a shared group the file is moved to that
    group first and only then widened to 0640; if the group cannot be set the new file
    is removed."""
    _check_parent(path)
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError as err:
        raise LedgerUnavailable(f"cannot create ledger file: {err.strerror}") from err
    try:
        os.fchmod(descriptor, 0o600)
        if policy.group is not None:
            os.fchown(descriptor, -1, policy.group)
            os.fchmod(descriptor, policy.mode)
    except OSError as err:
        os.unlink(path)
        raise LedgerUnavailable(f"cannot set the ledger file group: {err.strerror}") from err
    finally:
        os.close(descriptor)


def _check_id(label: str, value: object) -> str:
    if not isinstance(value, str) or not value or not all("!" <= character <= "~" for character in value):
        raise ValueError(f"{label} must be a non-empty ASCII printable string without whitespace")
    return value


def _check_binding(value: object) -> str:
    try:
        if isinstance(value, str) and len(b64u_decode(value)) == 32:
            return value
    except ValueError:
        pass
    raise ValueError("binding must be a canonical base64url sha256 digest")


def _is_ledger_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_SAFE_INTEGER


def _check_now(now: object) -> int:
    if isinstance(now, bool) or not isinstance(now, int) or not 0 <= now <= MAX_SAFE_INTEGER:
        raise ValueError(f"now must be an integer between 0 and {MAX_SAFE_INTEGER}")
    return now


@dataclass(frozen=True)
class Operation:
    """One effect the trusted executor wants to perform, built by the executor only.
    `op_id` is the idempotency key, unique per (tenant_id, task_id). `leaf_binding`
    is the binding of the chain's last record (the TaskRoot when there are no links).
    `cost` comes from a policy-owned cost schedule. `digest()` covers every field, so
    a replayed op_id is recognised only when the whole operation is identical."""

    op_id: str
    tenant_id: str
    task_id: str
    leaf_binding: str
    tool: str
    resource: str
    args_digest: str
    cost: int
    verdict_allowed: bool
    expires_at: int

    def signable_fields(self) -> dict[str, object]:
        return {
            "op_id": self.op_id,
            "tenant_id": self.tenant_id,
            "task_id": self.task_id,
            "leaf_binding": self.leaf_binding,
            "tool": self.tool,
            "resource": self.resource,
            "args_digest": self.args_digest,
            "cost": self.cost,
            "verdict_allowed": self.verdict_allowed,
            "expires_at": self.expires_at,
        }

    def digest(self) -> str:
        return sha256_b64u(signing_input(OPERATION_TYPE, OPERATION_VERSION, self.signable_fields()))

    def refusal(self) -> str | None:
        for name in ("op_id", "tenant_id", "task_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or not all("!" <= character <= "~" for character in value):
                return f"{name} must be a non-empty ASCII printable string without whitespace"
        for name in ("tool", "resource"):
            value = getattr(self, name)
            if not isinstance(value, str) or validate_entry(value) or "*" in value:
                return f"{name} must be a concrete id"
        for name in ("leaf_binding", "args_digest"):
            try:
                _check_binding(getattr(self, name))
            except ValueError:
                return f"{name} must be a canonical base64url sha256 digest"
        if isinstance(self.cost, bool) or not isinstance(self.cost, int) or not 0 <= self.cost <= MAX_SAFE_INTEGER:
            return f"cost must be an integer between 0 and {MAX_SAFE_INTEGER}"
        if not isinstance(self.verdict_allowed, bool):
            return "verdict_allowed must be a bool"
        if (
            isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, int)
            or not 0 <= self.expires_at <= MAX_SAFE_INTEGER
        ):
            return "expires_at must be a non-negative integer"
        return None


@dataclass(frozen=True)
class Reservation:
    tenant_id: str
    task_id: str
    op_id: str
    digest: str
    cost: int
    state: str
    expires_at: int


@dataclass(frozen=True)
class BudgetStatus:
    budget: int
    spent: int

    @property
    def remaining(self) -> int:
        return self.budget - self.spent


class _LedgerFile:
    """Connection lifecycle shared by the writer and the reader: the file checks, the
    (device, inode) identity re-check on every call, the fork guard and close()."""

    _URI_MODE = "rw"
    _CONNECT_PRAGMAS: tuple[str, ...] = ()

    def _attach(self, path: Path, policy: _FilePolicy) -> None:
        self._path = path
        self._policy = policy
        self._allow_empty = getattr(self, "_allow_empty", False)
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._closed = False
        self._identity: tuple[int, int] | None = None
        self._pid = os.getpid()
        self._reconnect()

    def _reconnect(self) -> None:
        """Open the SQLite connection through the full file checks. The file's
        (device, inode) is read before connecting, must match the identity this
        ledger was first opened on, and must be unchanged after connecting."""
        before = _check_file(self._path, self._policy, self._allow_empty)
        identity = (before.st_dev, before.st_ino)
        if self._identity is not None and identity != self._identity:
            raise LedgerUnavailable("ledger file was replaced")
        uri = f"file:{quote(str(self._path), safe='/')}?mode={self._URI_MODE}"
        connection = None
        try:
            connection = sqlite3.connect(
                uri, uri=True, timeout=BUSY_TIMEOUT_SECONDS, isolation_level=None, check_same_thread=False
            )
            self._configure(connection)
            after = _check_file(self._path, self._policy, self._allow_empty)
            if (after.st_dev, after.st_ino) != identity:
                raise LedgerUnavailable("ledger file was replaced while connecting")
        except sqlite3.Error as err:
            if connection is not None:
                connection.close()
            raise LedgerUnavailable(f"ledger database error: {err}") from err
        except BaseException:
            if connection is not None:
                connection.close()
            raise
        self._identity = identity
        self._connection = connection
        self._pid = os.getpid()

    def _configure(self, connection: sqlite3.Connection) -> None:
        for pragma in self._CONNECT_PRAGMAS:
            connection.execute(pragma)

    def close(self) -> None:
        """Release the SQLite connection for good. Idempotent; later calls raise
        LedgerUnavailable."""
        with self._lock:
            self._closed = True
            connection, self._connection = self._connection, None
        if connection is not None:
            connection.close()

    def _drop(self, connection: sqlite3.Connection) -> None:
        """Discard a connection that may be mid-transaction or otherwise unusable. The
        next call reconnects through the full file checks."""
        self._connection = None
        try:
            connection.close()
        except Exception:
            pass

    def _live_connection(self) -> sqlite3.Connection:
        if self._closed:
            raise LedgerUnavailable("ledger is closed")
        if os.getpid() != self._pid:
            raise LedgerUnavailable("ledger connection belongs to another process; open a new ledger after fork")
        if self._connection is None:
            self._reconnect()
        info = _check_file(self._path, self._policy, self._allow_empty)
        if (info.st_dev, info.st_ino) != self._identity:
            raise LedgerUnavailable("ledger file was replaced")
        return self._connection


class TaskLedger(_LedgerFile):
    """Single-host SQLite ledger of task budgets and revocations. One SQLite connection
    is opened after the file checks and reused for the ledger's lifetime (WAL journal,
    full synchronous commits, parameterized statements only). Every call still
    re-inspects the file by path with fstat (regular file, owner, mode 0600, private
    parent, and the `-wal` and `-shm` files) and refuses if the path now points at a
    different file than the one opened, so a deleted, replaced or loosened database
    fails closed.

    Thread safety: the connection is opened with check_same_thread=False and every
    call holds one lock, so a ledger may be shared between threads; calls serialize.
    Do not share a ledger across fork(); open one per process. Several processes may
    use the same file: writes are `BEGIN IMMEDIATE` transactions with a busy timeout.
    Call close() (or use `with`) to release the connection.

    Revocations are insert-only: there is no un-revoke, and triggers abort any
    UPDATE or DELETE on the revocation tables. The ledger trusts its caller to pass
    only results of verify_root and chains from verify_chain; it does not re-verify
    signatures."""

    _CONNECT_PRAGMAS = ("PRAGMA journal_mode = WAL", "PRAGMA synchronous = FULL", "PRAGMA foreign_keys = ON")

    def __init__(self, path: str | os.PathLike[str], shared_group: int | None = None) -> None:
        """Attach to an existing ledger. Never creates a file: a missing, replaced or
        schema-less database raises LedgerUnavailable. Use `create` for a new ledger.
        With `shared_group` (a gid) the file must have mode 0640 and that group instead
        of mode 0600, and the writer must run with that group as its effective group."""
        self._attach(Path(os.path.abspath(path)), _writer_policy(shared_group))
        with self._transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            self.close()
            raise LedgerUnavailable("ledger database has no schema")
        if version != SCHEMA_VERSION:
            self.close()
            raise LedgerUnavailable(f"unsupported ledger schema version {version}")

    @classmethod
    def open(cls, path: str | os.PathLike[str], shared_group: int | None = None) -> TaskLedger:
        return cls(path, shared_group)

    @classmethod
    def open_read_only(cls, path: str | os.PathLike[str], writer_uid: int, group: int) -> ReadOnlyLedger:
        return ReadOnlyLedger(path, writer_uid, group)

    @classmethod
    def create(cls, path: str | os.PathLike[str], shared_group: int | None = None) -> TaskLedger:
        """Create a new ledger file with the schema. Refuses an existing path. The file
        is 0600, or 0640 in group `shared_group` (which must be the effective group) so
        that a reader in that group can use `open_read_only`."""
        target = Path(os.path.abspath(path))
        policy = _writer_policy(shared_group)
        _create_file(target, policy)
        ledger = cls.__new__(cls)
        ledger._allow_empty = True
        ledger._attach(target, policy)
        with ledger._transaction() as connection:
            for statement in (_SCHEMA + _RESERVATION_SCHEMA).split(";"):
                if statement.strip():
                    connection.execute(statement)
            for table in _INSERT_ONLY_TABLES:
                for action in ("UPDATE", "DELETE"):
                    connection.execute(
                        f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} BEFORE {action} ON {table} "
                        "BEGIN SELECT RAISE(ABORT, 'revocations are insert-only'); END"
                    )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        ledger._allow_empty = False
        return ledger

    def __enter__(self) -> TaskLedger:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _rollback_or_drop(self, connection: sqlite3.Connection) -> None:
        try:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            healthy = not connection.in_transaction
        except Exception:
            healthy = False
        except BaseException:
            self._drop(connection)
            raise
        if not healthy:
            self._drop(connection)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                connection = self._live_connection()
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    yield connection
                    connection.execute("COMMIT")
                except BaseException:
                    self._rollback_or_drop(connection)
                    raise
            except (Refused, LedgerUnavailable):
                raise
            except sqlite3.IntegrityError as err:
                raise Refused(f"ledger constraint violated: {err}") from err
            except Exception as err:
                raise LedgerUnavailable(f"ledger error: {err}") from err

    def open_task(self, result: TaskRootResult, now: int) -> None:
        """Register a task from a valid verify_root result. Idempotent for the same
        root; a different root for the same (tenant, task) is refused, as is a root
        whose binding, task or tenant is already revoked."""
        if not isinstance(result, TaskRootResult) or not result.valid or result.root is None:
            raise ValueError("open_task requires a valid verify_root result")
        _check_now(now)
        root = result.root
        binding = root.binding()
        with self._transaction() as connection:
            if self._revoked(connection, root.tenant_id, root.task_id, (binding,)):
                raise Refused("task root, task or tenant is revoked")
            row = connection.execute(
                "SELECT root_binding FROM tasks WHERE tenant_id = ? AND task_id = ?", (root.tenant_id, root.task_id)
            ).fetchone()
            if row is not None:
                if row[0] != binding:
                    raise Refused("a different task root is already open for this tenant and task")
                return
            connection.execute(
                "INSERT INTO tasks (tenant_id, task_id, root_binding, budget, root_expires_at, opened_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (root.tenant_id, root.task_id, binding, root.budget, root.expires_at, now),
            )

    def revoke(self, binding: str, now: int) -> None:
        _check_binding(binding)
        _check_now(now)
        with self._transaction() as connection:
            connection.execute("INSERT OR IGNORE INTO revoked_bindings VALUES (?, ?)", (binding, now))

    def revoke_task(self, tenant_id: str, task_id: str, now: int) -> None:
        _check_id("tenant_id", tenant_id)
        _check_id("task_id", task_id)
        _check_now(now)
        with self._transaction() as connection:
            connection.execute("INSERT OR IGNORE INTO revoked_tasks VALUES (?, ?, ?)", (tenant_id, task_id, now))

    def revoke_tenant(self, tenant_id: str, now: int) -> None:
        _check_id("tenant_id", tenant_id)
        _check_now(now)
        with self._transaction() as connection:
            connection.execute("INSERT OR IGNORE INTO revoked_tenants VALUES (?, ?)", (tenant_id, now))

    @staticmethod
    def _revoked(connection: sqlite3.Connection, tenant_id: str, task_id: str, bindings: tuple[str, ...]) -> bool:
        placeholders = ", ".join("?" for _ in bindings)
        row = connection.execute(
            f"SELECT 1 FROM revoked_bindings WHERE binding IN ({placeholders}) "
            "UNION ALL SELECT 1 FROM revoked_tasks WHERE tenant_id = ? AND task_id = ? "
            "UNION ALL SELECT 1 FROM revoked_tenants WHERE tenant_id = ? LIMIT 1",
            (*bindings, tenant_id, task_id, tenant_id),
        ).fetchone()
        return row is not None

    def is_revoked(self, context: ChainContext) -> bool:
        """ChainRevocationChecker: True if the root, any link, the task or the tenant
        is revoked. A database failure raises RevocationSourceUnreachable."""
        bindings = (context.task_root, *context.link_bindings)
        try:
            with self._lock:
                connection = self._live_connection()
                return self._revoked(connection, context.tenant_id, context.task_id, bindings)
        except Exception as err:
            raise RevocationSourceUnreachable(f"ledger database error: {err}") from err

    @staticmethod
    def _release_expired(connection: sqlite3.Connection, tenant_id: str, task_id: str, now: int) -> None:
        expired = connection.execute(
            "SELECT op_id, cost FROM reservations "
            "WHERE tenant_id = ? AND task_id = ? AND state = 'reserved' AND expires_at <= ?",
            (tenant_id, task_id, now),
        ).fetchall()
        for op_id, cost in expired:
            connection.execute(
                "UPDATE tasks SET spent = spent - ? WHERE tenant_id = ? AND task_id = ?", (cost, tenant_id, task_id)
            )
            connection.execute(
                "UPDATE links SET spent = spent - ? WHERE binding IN "
                "(SELECT binding FROM reservation_links WHERE tenant_id = ? AND task_id = ? AND op_id = ?)",
                (cost, tenant_id, task_id, op_id),
            )
            connection.execute(
                "UPDATE reservations SET state = 'released', updated_at = ? "
                "WHERE tenant_id = ? AND task_id = ? AND op_id = ?",
                (now, tenant_id, task_id, op_id),
            )

    @staticmethod
    def _read_reservation(
        connection: sqlite3.Connection, tenant_id: str, task_id: str, op_id: str
    ) -> Reservation | None:
        row = connection.execute(
            "SELECT digest, cost, state, expires_at FROM reservations "
            "WHERE tenant_id = ? AND task_id = ? AND op_id = ?",
            (tenant_id, task_id, op_id),
        ).fetchone()
        if row is None:
            return None
        return Reservation(tenant_id, task_id, op_id, row[0], row[1], row[2], row[3])

    def reserve(self, operation: Operation, links: Sequence[ChainLink], now: int) -> Reservation:
        """Atomically reserve `operation.cost` against the task pool and every link's
        cap, in one BEGIN IMMEDIATE transaction. `links` is the verified chain's links
        in order (empty when the TaskRoot subject acts directly); each registers with
        its budget as its cap on first use. Raises Refused, changing nothing, for: a
        malformed operation, a non-allow verdict, an expired operation, an unknown or
        revoked task, tenant, root or link, a chain that does not end at
        `operation.leaf_binding`, a reused op_id with a different operation, or any
        pool or cap that cannot cover the cost. The same (tenant, task, op_id) with an
        identical operation returns the stored reservation in whatever state it is in."""
        _check_now(now)
        if not isinstance(operation, Operation):
            raise Refused("malformed operation: not an Operation")
        problem = operation.refusal()
        if problem:
            raise Refused(f"malformed operation: {problem}")
        links = tuple(links)
        for link in links:
            if not isinstance(link, ChainLink):
                raise Refused("links must be ChainLink records")
            if (link.tenant_id, link.task_id) != (operation.tenant_id, operation.task_id):
                raise Refused("a link belongs to a different tenant or task")
            if not _is_ledger_integer(link.budget):
                raise Refused(f"link budget must be an integer between 0 and {MAX_SAFE_INTEGER}")
            if not _is_ledger_integer(link.expires_at):
                raise Refused(f"link expires_at must be an integer between 0 and {MAX_SAFE_INTEGER}")
        digest = operation.digest()
        try:
            bindings = tuple(link.binding() for link in links)
        except (ValueError, TypeError) as err:
            raise Refused(f"malformed link: {err}") from None
        with self._transaction() as connection:
            self._release_expired(connection, operation.tenant_id, operation.task_id, now)
            stored = self._read_reservation(connection, operation.tenant_id, operation.task_id, operation.op_id)
            if stored is not None:
                if stored.digest != digest:
                    raise Refused("op_id was already used for a different operation")
                return stored
            if not operation.verdict_allowed:
                raise Refused("operation verdict is not allow")
            if now >= operation.expires_at:
                raise Refused("operation has expired")
            task = connection.execute(
                "SELECT root_binding, budget, spent, root_expires_at FROM tasks WHERE tenant_id = ? AND task_id = ?",
                (operation.tenant_id, operation.task_id),
            ).fetchone()
            if task is None:
                raise Refused("unknown task")
            root_binding, budget, spent, root_expires_at = task
            chain_expires_at = min((root_expires_at, *(link.expires_at for link in links)))
            if now >= chain_expires_at:
                raise Refused("chain has expired")
            reservation_expires_at = min(operation.expires_at, chain_expires_at)
            expected_parent = root_binding
            parent_budget = budget
            for link in links:
                if link.parent_hash != expected_parent or link.task_root != root_binding:
                    raise Refused("links do not form a chain from this task's root")
                if link.budget > parent_budget:
                    raise Refused("link budget exceeds its parent's budget")
                expected_parent = link.binding()
                parent_budget = link.budget
            if expected_parent != operation.leaf_binding:
                raise Refused("operation leaf_binding is not the end of the chain")
            if self._revoked(connection, operation.tenant_id, operation.task_id, (root_binding, *bindings)):
                raise Refused("task root, task, tenant or a link is revoked")
            if spent + operation.cost > budget:
                raise Refused(f"task budget exhausted: {budget - spent} remaining, cost {operation.cost}")
            for link, binding in zip(links, bindings, strict=True):
                registered = connection.execute(
                    "SELECT cap, spent, tenant_id, task_id FROM links WHERE binding = ?", (binding,)
                ).fetchone()
                if registered is None:
                    connection.execute(
                        "INSERT INTO links (binding, tenant_id, task_id, cap) VALUES (?, ?, ?, ?)",
                        (binding, link.tenant_id, link.task_id, link.budget),
                    )
                    registered = (link.budget, 0, link.tenant_id, link.task_id)
                cap, link_spent, link_tenant, link_task = registered
                if (link_tenant, link_task, cap) != (link.tenant_id, link.task_id, link.budget):
                    raise Refused("link is registered with different terms")
                if link_spent + operation.cost > cap:
                    raise Refused(f"link budget exhausted: {cap - link_spent} remaining, cost {operation.cost}")
            connection.execute(
                "UPDATE tasks SET spent = spent + ? WHERE tenant_id = ? AND task_id = ?",
                (operation.cost, operation.tenant_id, operation.task_id),
            )
            connection.execute(
                "INSERT INTO reservations (tenant_id, task_id, op_id, digest, leaf_binding, cost, state, expires_at, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?, ?, ?)",
                (
                    operation.tenant_id,
                    operation.task_id,
                    operation.op_id,
                    digest,
                    operation.leaf_binding,
                    operation.cost,
                    reservation_expires_at,
                    now,
                    now,
                ),
            )
            for binding in bindings:
                connection.execute("UPDATE links SET spent = spent + ? WHERE binding = ?", (operation.cost, binding))
                connection.execute(
                    "INSERT INTO reservation_links (tenant_id, task_id, op_id, binding) VALUES (?, ?, ?, ?)",
                    (operation.tenant_id, operation.task_id, operation.op_id, binding),
                )
            return Reservation(
                operation.tenant_id,
                operation.task_id,
                operation.op_id,
                digest,
                operation.cost,
                "reserved",
                reservation_expires_at,
            )

    def _transition(
        self, tenant_id: str, task_id: str, op_id: str, now: int, allowed_from: tuple[str, ...], target: str
    ) -> Reservation:
        _check_id("tenant_id", tenant_id)
        _check_id("task_id", task_id)
        _check_id("op_id", op_id)
        _check_now(now)
        with self._transaction() as connection:
            self._release_expired(connection, tenant_id, task_id, now)
            stored = self._read_reservation(connection, tenant_id, task_id, op_id)
            if stored is None:
                raise Refused("unknown reservation")
            if stored.state not in allowed_from:
                raise Refused(f"cannot move a {stored.state} reservation to {target}")
            if target == "issued":
                root_binding = connection.execute(
                    "SELECT root_binding FROM tasks WHERE tenant_id = ? AND task_id = ?", (tenant_id, task_id)
                ).fetchone()[0]
                link_bindings = tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT binding FROM reservation_links WHERE tenant_id = ? AND task_id = ? AND op_id = ?",
                        (tenant_id, task_id, op_id),
                    )
                )
                if self._revoked(connection, tenant_id, task_id, (root_binding, *link_bindings)):
                    raise Refused("task root, task, tenant or a link is revoked")
            connection.execute(
                "UPDATE reservations SET state = ?, updated_at = ? WHERE tenant_id = ? AND task_id = ? AND op_id = ?",
                (target, now, tenant_id, task_id, op_id),
            )
            return Reservation(tenant_id, task_id, op_id, stored.digest, stored.cost, target, stored.expires_at)

    def mark_issued(self, tenant_id: str, task_id: str, op_id: str, now: int) -> Reservation:
        """reserved -> issued, recorded before a credential is minted. Refused if the
        reservation expired and was released, was already issued, or is now revoked."""
        return self._transition(tenant_id, task_id, op_id, now, ("reserved",), "issued")

    def mark_done(self, tenant_id: str, task_id: str, op_id: str, now: int) -> Reservation:
        return self._transition(tenant_id, task_id, op_id, now, ("issued",), "done")

    def mark_outcome_unknown(self, tenant_id: str, task_id: str, op_id: str, now: int) -> Reservation:
        """issued -> outcome_unknown. The budget stays spent; it is never credited
        back automatically, only an operator reconciles it."""
        return self._transition(tenant_id, task_id, op_id, now, ("issued",), "outcome_unknown")

    def reservation(self, tenant_id: str, task_id: str, op_id: str, now: int) -> Reservation | None:
        _check_now(now)
        with self._transaction() as connection:
            self._release_expired(connection, tenant_id, task_id, now)
            return self._read_reservation(connection, tenant_id, task_id, op_id)

    def task_budget(self, tenant_id: str, task_id: str, now: int) -> BudgetStatus:
        _check_now(now)
        with self._transaction() as connection:
            self._release_expired(connection, tenant_id, task_id, now)
            row = connection.execute(
                "SELECT budget, spent FROM tasks WHERE tenant_id = ? AND task_id = ?", (tenant_id, task_id)
            ).fetchone()
            if row is None:
                raise Refused("unknown task")
            return BudgetStatus(budget=row[0], spent=row[1])

    def link_budget(self, link: ChainLink, now: int) -> BudgetStatus | None:
        """Spend against `link`'s cap, or None if the link has not been used yet."""
        _check_now(now)
        with self._transaction() as connection:
            self._release_expired(connection, link.tenant_id, link.task_id, now)
            row = connection.execute("SELECT cap, spent FROM links WHERE binding = ?", (link.binding(),)).fetchone()
            return None if row is None else BudgetStatus(budget=row[0], spent=row[1])


def _authorize_read(
    action: int, first: str | None, second: str | None, database: str | None, source: str | None
) -> int:
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and first == "user_version" and second is None:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _read_only(name: str) -> Callable[..., NoReturn]:
    def refuse(self: ReadOnlyLedger, *args: object, **kwargs: object) -> NoReturn:
        raise LedgerUnavailable(f"ledger is open read-only: {name} is not allowed")

    refuse.__name__ = name
    return refuse


class ReadOnlyLedger(_LedgerFile):
    """Read-only view of a ledger owned by another user, for a process that must check
    revocation and reservations but never change them. The file is opened O_RDONLY and
    SQLite with `mode=ro`; no PRAGMA is set, no transaction is begun and expired
    reservations are not released. The connection allows no attached database and its
    authorizer permits only SELECT, table reads, functions and reading
    `PRAGMA user_version`. Before every call the file must be a regular file owned by
    `writer_uid`, mode exactly 0640, in group `group`, with one hard link and the
    SQLite header, and the same (device, inode) the connection was opened on; `-wal` and
    `-shm` must exist and match the same owner, mode, group and link count.

    The database is in WAL mode, so a reader that cannot write the directory needs the
    `-wal` and `-shm` files to exist and be readable: the writer must hold the database
    open. Otherwise every call raises LedgerUnavailable. Mutating methods raise
    LedgerUnavailable."""

    _URI_MODE = "ro"

    def __init__(self, path: str | os.PathLike[str], writer_uid: int, group: int) -> None:
        policy = _FilePolicy(
            flags=os.O_RDONLY,
            owner=_check_os_id("writer_uid", writer_uid),
            mode=0o640,
            group=_check_os_id("group", group),
            require_sidecars=True,
        )
        self._attach(Path(os.path.abspath(path)), policy)
        try:
            with self._read() as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
        except BaseException:
            self.close()
            raise
        if version == 0:
            self.close()
            raise LedgerUnavailable("ledger database has no schema")
        if version != SCHEMA_VERSION:
            self.close()
            raise LedgerUnavailable(f"unsupported ledger schema version {version}")

    def __enter__(self) -> ReadOnlyLedger:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _configure(self, connection: sqlite3.Connection) -> None:
        if sys.version_info >= (3, 11):
            connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        connection.set_authorizer(_authorize_read)

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._live_connection()
            except LedgerUnavailable:
                raise
            except Exception as err:
                raise LedgerUnavailable(f"ledger error: {err}") from err

    def is_revoked(self, context: ChainContext) -> bool:
        """ChainRevocationChecker: True if the root, any link, the task or the tenant
        is revoked. A database failure raises RevocationSourceUnreachable."""
        bindings = (context.task_root, *context.link_bindings)
        try:
            with self._read() as connection:
                return TaskLedger._revoked(connection, context.tenant_id, context.task_id, bindings)
        except Exception as err:
            raise RevocationSourceUnreachable(f"ledger database error: {err}") from err

    def reservation_readonly(self, tenant_id: str, task_id: str, op_id: str) -> Reservation | None:
        """The stored reservation as it is in the file, or None. Expired `reserved`
        rows are returned unchanged with their `expires_at`; the caller checks expiry."""
        _check_id("tenant_id", tenant_id)
        _check_id("task_id", task_id)
        _check_id("op_id", op_id)
        with self._read() as connection:
            return TaskLedger._read_reservation(connection, tenant_id, task_id, op_id)

    open_task = _read_only("open_task")
    revoke = _read_only("revoke")
    revoke_task = _read_only("revoke_task")
    revoke_tenant = _read_only("revoke_tenant")
    reserve = _read_only("reserve")
    mark_issued = _read_only("mark_issued")
    mark_done = _read_only("mark_done")
    mark_outcome_unknown = _read_only("mark_outcome_unknown")
    reservation = _read_only("reservation")
    task_budget = _read_only("task_budget")
    link_budget = _read_only("link_budget")
