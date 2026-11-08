from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from .chain import ChainContext
from .encoding import b64u_decode
from .exceptions import RevocationSourceUnreachable
from .task_root import TaskRootResult

SCHEMA_VERSION = 1
BUSY_TIMEOUT_SECONDS = 30

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    root_binding TEXT NOT NULL,
    budget INTEGER NOT NULL CHECK (budget >= 0),
    spent INTEGER NOT NULL DEFAULT 0 CHECK (spent >= 0 AND spent <= budget),
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

_INSERT_ONLY_TABLES = ("revoked_bindings", "revoked_tasks", "revoked_tenants")


class LedgerError(Exception):
    """Base class for ledger failures."""


class Refused(LedgerError):
    """The ledger refused a request on policy grounds (unknown or revoked task, budget
    exhausted, reused op_id, bad state transition). Nothing was changed."""


class LedgerUnavailable(LedgerError):
    """The database could not be read or written. Callers must fail closed."""


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


def _check_now(now: object) -> int:
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise ValueError("now must be a non-negative integer")
    return now


class TaskLedger:
    """Single-host SQLite ledger of task budgets and revocations. One connection per
    call, WAL journal, full synchronous commits, parameterized statements only.
    Revocations are insert-only: there is no un-revoke, and triggers abort any
    UPDATE or DELETE on the revocation tables. The ledger trusts its caller to pass
    only results of verify_root and chains from verify_chain; it does not re-verify
    signatures."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        try:
            os.close(os.open(self._path, os.O_CREAT | os.O_RDWR, 0o600))
            with self._transaction() as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, SCHEMA_VERSION):
                    raise LedgerUnavailable(f"unsupported ledger schema version {version}")
                for statement in _SCHEMA.split(";"):
                    if statement.strip():
                        connection.execute(statement)
                for table in _INSERT_ONLY_TABLES:
                    for action in ("UPDATE", "DELETE"):
                        connection.execute(
                            f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} BEFORE {action} ON {table} "
                            "BEGIN SELECT RAISE(ABORT, 'revocations are insert-only'); END"
                        )
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except OSError as err:
            raise LedgerUnavailable(f"cannot open ledger: {err}") from err

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=BUSY_TIMEOUT_SECONDS, isolation_level=None)
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    yield connection
                except BaseException:
                    connection.execute("ROLLBACK")
                    raise
                connection.execute("COMMIT")
        except sqlite3.Error as err:
            raise LedgerUnavailable(f"ledger database error: {err}") from err

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
                "INSERT INTO tasks (tenant_id, task_id, root_binding, budget, opened_at) VALUES (?, ?, ?, ?, ?)",
                (root.tenant_id, root.task_id, binding, root.budget, now),
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
            with closing(self._connect()) as connection:
                return self._revoked(connection, context.tenant_id, context.task_id, bindings)
        except sqlite3.Error as err:
            raise RevocationSourceUnreachable(f"ledger database error: {err}") from err
