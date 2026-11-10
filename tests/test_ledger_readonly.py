from __future__ import annotations

import hashlib
import inspect
import os
import shutil
import sqlite3
import stat

import pytest
from test_ledger import NOW, World

from agent_warrant.encoding import sha256_b64u
from agent_warrant.exceptions import RevocationSourceUnreachable
from agent_warrant.ledger import LedgerUnavailable, Operation, ReadOnlyLedger, TaskLedger

UID = os.geteuid()
GID = os.getegid()


def shared_dir(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o750)
    os.chmod(directory, 0o750)
    return directory


def operation(world, **overrides):
    fields = {
        "op_id": "op-1",
        "tenant_id": world.root.tenant_id,
        "task_id": world.root.task_id,
        "leaf_binding": world.root.binding(),
        "tool": "deploy.prod",
        "resource": "env/prod",
        "args_digest": sha256_b64u(b"args"),
        "cost": 10,
        "verdict_allowed": True,
        "expires_at": NOW + 60,
    }
    fields.update(overrides)
    return Operation(**fields)


@pytest.fixture
def world():
    return World(budget=100)


@pytest.fixture
def path(tmp_path):
    return shared_dir(tmp_path) / "ledger.db"


@pytest.fixture
def writer(path, world):
    ledger = TaskLedger.create(path, shared_group=GID)
    ledger.open_task(world.verified(), NOW)
    yield ledger
    ledger.close()


@pytest.fixture
def reader(writer, path):
    ledger = TaskLedger.open_read_only(path, UID, GID)
    yield ledger
    ledger.close()


def stored_state(path, op_id):
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return connection.execute("SELECT state FROM reservations WHERE op_id = ?", (op_id,)).fetchone()[0]
    finally:
        connection.close()


def test_open_read_only_returns_a_read_only_ledger(reader):
    assert isinstance(reader, ReadOnlyLedger)


def test_reads_see_the_writers_commits(writer, reader, world):
    assert reader.is_revoked(world.context()) is False
    assert reader.reservation_readonly("t1", "task-1", "op-1") is None
    reserved = writer.reserve(operation(world), [], NOW)
    assert reader.reservation_readonly("t1", "task-1", "op-1") == reserved
    writer.mark_issued("t1", "task-1", "op-1", NOW)
    assert reader.reservation_readonly("t1", "task-1", "op-1").state == "issued"
    writer.revoke_tenant("t1", NOW)
    assert reader.is_revoked(world.context()) is True


@pytest.mark.parametrize("level", ["binding", "link", "task", "tenant"])
def test_is_revoked_works_read_only_at_every_level(writer, reader, world, level):
    links = world.chain(1)
    context = world.context(links)
    assert reader.is_revoked(context) is False
    if level == "binding":
        writer.revoke(world.root.binding(), NOW)
    elif level == "link":
        writer.revoke(links[0].binding(), NOW)
    elif level == "task":
        writer.revoke_task("t1", "task-1", NOW)
    else:
        writer.revoke_tenant("t1", NOW)
    assert reader.is_revoked(context) is True


def test_reservation_readonly_does_not_release_an_expired_reservation(writer, reader, world, path):
    writer.reserve(operation(world, expires_at=NOW + 5), [], NOW)
    stored = reader.reservation_readonly("t1", "task-1", "op-1")
    assert (stored.state, stored.expires_at) == ("reserved", NOW + 5)
    assert stored_state(path, "op-1") == "reserved"
    assert writer.task_budget("t1", "task-1", NOW).spent == 10
    assert writer.reservation("t1", "task-1", "op-1", NOW + 5).state == "released"
    assert reader.reservation_readonly("t1", "task-1", "op-1").state == "released"


def test_reservation_readonly_takes_no_clock():
    assert list(inspect.signature(ReadOnlyLedger.reservation_readonly).parameters) == [
        "self",
        "tenant_id",
        "task_id",
        "op_id",
    ]


@pytest.mark.parametrize("value", ["", "has space", None, 1])
def test_reservation_readonly_validates_ids(reader, value):
    with pytest.raises(ValueError):
        reader.reservation_readonly("t1", "task-1", value)


MUTATING = {
    "open_task": lambda world: (world.verified(), NOW),
    "revoke": lambda world: (world.root.binding(), NOW),
    "revoke_task": lambda world: ("t1", "task-1", NOW),
    "revoke_tenant": lambda world: ("t1", NOW),
    "reserve": lambda world: (operation(world), [], NOW),
    "mark_issued": lambda world: ("t1", "task-1", "op-1", NOW),
    "mark_done": lambda world: ("t1", "task-1", "op-1", NOW),
    "mark_outcome_unknown": lambda world: ("t1", "task-1", "op-1", NOW),
    "reservation": lambda world: ("t1", "task-1", "op-1", NOW + 100),
    "task_budget": lambda world: ("t1", "task-1", NOW + 100),
    "link_budget": lambda world: (world.chain(1)[0], NOW + 100),
}


@pytest.mark.parametrize("name", sorted(MUTATING))
def test_mutating_methods_raise_and_change_nothing(writer, reader, world, path, name):
    writer.reserve(operation(world, expires_at=NOW + 5), [], NOW)
    with pytest.raises(LedgerUnavailable, match="read-only"):
        getattr(reader, name)(*MUTATING[name](world))
    assert stored_state(path, "op-1") == "reserved"
    assert reader.is_revoked(world.context()) is False


def test_every_public_writer_method_is_covered_by_the_reader():
    writer_methods = {
        name for name, member in vars(TaskLedger).items() if callable(member) and not name.startswith("_")
    }
    assert writer_methods - {"open", "create", "open_read_only", "is_revoked", "close"} == set(MUTATING)


REFUSED_STATEMENTS = [
    "ATTACH '{out}/attached.db' AS other",
    "ATTACH 'file:{out}/attached-uri.db?mode=rwc' AS other",
    "VACUUM INTO '{out}/copy.db'",
    "VACUUM",
    "CREATE TABLE other (x)",
    "CREATE TEMP TABLE other (x)",
    "INSERT INTO revoked_tenants VALUES ('t1', 1)",
    "UPDATE reservations SET state = 'done'",
    "DELETE FROM reservations",
    "PRAGMA user_version = 2",
    "PRAGMA journal_mode = DELETE",
    "BEGIN IMMEDIATE",
]


@pytest.mark.parametrize("statement", REFUSED_STATEMENTS)
def test_the_reader_connection_refuses_statements_and_creates_no_file(writer, reader, world, path, tmp_path, statement):
    writer.reserve(operation(world), [], NOW)
    out = tmp_path / "out"
    out.mkdir()
    before = sorted(os.listdir(path.parent))
    with pytest.raises(sqlite3.DatabaseError):
        reader._connection.execute(statement.format(out=out)).fetchall()
    assert os.listdir(out) == []
    assert sorted(os.listdir(path.parent)) == before
    assert stored_state(path, "op-1") == "reserved"
    assert reader.reservation_readonly("t1", "task-1", "op-1").state == "reserved"


@pytest.mark.skipif(not hasattr(sqlite3.Connection, "setlimit"), reason="Connection.setlimit needs Python 3.11")
def test_the_reader_connection_allows_no_attached_database(reader):
    assert reader._connection.getlimit(sqlite3.SQLITE_LIMIT_ATTACHED) == 0


def test_open_after_the_writer_closed_names_the_missing_wal(writer, path):
    writer.close()
    with pytest.raises(LedgerUnavailable, match="writer is not holding the database open"):
        TaskLedger.open_read_only(path, UID, GID)
    assert not (path.parent / (path.name + "-wal")).exists()


def other_member_group():
    groups = [gid for gid in os.getgroups() if gid != GID]
    if not groups:
        pytest.skip("needs the current user to belong to a second group")
    return groups[0]


def sidecar(path, suffix):
    return path.with_name(path.name + suffix)


def loosen_mode(path, suffix):
    os.chmod(sidecar(path, suffix), 0o644)


def move_to_another_group(path, suffix):
    os.chown(sidecar(path, suffix), -1, other_member_group())


def hard_link(path, suffix):
    os.link(sidecar(path, suffix), path.with_name("extra" + suffix))


def replace_with_symlink(path, suffix):
    target = path.with_name("moved" + suffix)
    os.rename(sidecar(path, suffix), target)
    sidecar(path, suffix).symlink_to(target)


SIDECAR_TAMPERING = {
    "mode": (loosen_mode, "mode must be 0o640"),
    "group": (move_to_another_group, "group must be"),
    "hard link": (hard_link, "has multiple hard links"),
    "symlink": (replace_with_symlink, "is not a regular file"),
}


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
@pytest.mark.parametrize("tampering", sorted(SIDECAR_TAMPERING))
def test_reader_refuses_a_tampered_sidecar(writer, reader, path, world, suffix, tampering):
    change, message = SIDECAR_TAMPERING[tampering]
    change(path, suffix)
    with pytest.raises(LedgerUnavailable, match=f"ledger {suffix} file {message}"):
        reader.reservation_readonly("t1", "task-1", "op-1")
    with pytest.raises(RevocationSourceUnreachable):
        reader.is_revoked(world.context())
    with pytest.raises(LedgerUnavailable, match=f"ledger {suffix} file {message}"):
        TaskLedger.open_read_only(path, UID, GID)


def test_reading_does_not_change_the_database_or_its_wal(writer, reader, world, path):
    writer.reserve(operation(world, expires_at=NOW + 5), [], NOW)
    wal = path.parent / (path.name + "-wal")

    def digest():
        return hashlib.sha256(path.read_bytes()).hexdigest(), hashlib.sha256(wal.read_bytes()).hexdigest()

    before = digest()
    reader.is_revoked(world.context(world.chain(1)))
    reader.reservation_readonly("t1", "task-1", "op-1")
    assert digest() == before


def test_wrong_owner_is_refused(writer, path):
    with pytest.raises(LedgerUnavailable, match="owner"):
        TaskLedger.open_read_only(path, UID + 1, GID)


def test_wrong_group_is_refused(writer, path):
    with pytest.raises(LedgerUnavailable, match="group"):
        TaskLedger.open_read_only(path, UID, GID + 1)


def test_private_writer_ledger_is_refused(tmp_path):
    path = shared_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path).close()
    with pytest.raises(LedgerUnavailable, match="mode"):
        TaskLedger.open_read_only(path, UID, GID)


@pytest.mark.parametrize("mode", [0o600, 0o644, 0o660, 0o604, 0o440, 0o740, 0o650, 0o666])
def test_any_mode_other_than_0640_is_refused_and_not_modified(writer, path, mode):
    os.chmod(path, mode)
    try:
        with pytest.raises(LedgerUnavailable, match="mode|cannot open ledger file"):
            TaskLedger.open_read_only(path, UID, GID)
        assert stat.S_IMODE(os.stat(path).st_mode) == mode
    finally:
        os.chmod(path, 0o640)


def test_hard_linked_file_is_refused(writer, path):
    os.link(path, path.parent / "other-name.db")
    with pytest.raises(LedgerUnavailable, match="hard links"):
        TaskLedger.open_read_only(path, UID, GID)


def test_file_without_the_sqlite_header_is_refused(path):
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"not a database at all, just bytes")
    os.chmod(path, 0o640)
    with pytest.raises(LedgerUnavailable, match="not a SQLite database"):
        TaskLedger.open_read_only(path, UID, GID)


def test_empty_file_is_refused(path):
    path.touch()
    os.chmod(path, 0o640)
    with pytest.raises(LedgerUnavailable, match="not a SQLite database"):
        TaskLedger.open_read_only(path, UID, GID)


def test_database_without_the_schema_is_refused(path):
    sqlite3.connect(path).execute("CREATE TABLE other (x)").connection.close()
    os.chmod(path, 0o640)
    holder = sqlite3.connect(path)
    try:
        holder.execute("PRAGMA journal_mode = WAL")
        holder.execute("SELECT * FROM other").fetchall()
        with pytest.raises(LedgerUnavailable, match="no schema"):
            TaskLedger.open_read_only(path, UID, GID)
    finally:
        holder.close()


def test_missing_file_is_refused_and_not_created(path):
    with pytest.raises(LedgerUnavailable, match="cannot open"):
        TaskLedger.open_read_only(path, UID, GID)
    assert not path.exists()


def test_symlink_is_not_followed(writer, path):
    link = path.parent / "link.db"
    link.symlink_to(path)
    with pytest.raises(LedgerUnavailable, match="cannot open"):
        TaskLedger.open_read_only(link, UID, GID)


def test_group_or_other_writable_parent_is_refused(writer, path):
    os.chmod(path.parent, 0o770)
    try:
        with pytest.raises(LedgerUnavailable, match="parent directory"):
            TaskLedger.open_read_only(path, UID, GID)
    finally:
        os.chmod(path.parent, 0o750)


def test_every_read_rechecks_the_file(reader, path, world):
    os.chmod(path, 0o644)
    with pytest.raises(LedgerUnavailable, match="mode"):
        reader.reservation_readonly("t1", "task-1", "op-1")
    with pytest.raises(RevocationSourceUnreachable):
        reader.is_revoked(world.context())


def test_replaced_file_is_refused(reader, writer, path, world):
    copy = path.parent / "copy.db"
    shutil.copy(path, copy)
    os.chmod(copy, 0o640)
    os.replace(copy, path)
    with pytest.raises(LedgerUnavailable, match="replaced"):
        reader.reservation_readonly("t1", "task-1", "op-1")
    with pytest.raises(RevocationSourceUnreachable):
        reader.is_revoked(world.context())


def test_deleted_file_is_refused(reader, path, world):
    os.unlink(path)
    with pytest.raises(RevocationSourceUnreachable):
        reader.is_revoked(world.context())
    assert not path.exists()


def test_closed_reader_is_refused(reader, world):
    reader.close()
    with pytest.raises(LedgerUnavailable, match="closed"):
        reader.reservation_readonly("t1", "task-1", "op-1")
    with pytest.raises(RevocationSourceUnreachable):
        reader.is_revoked(world.context())


def test_reader_used_from_a_forked_process_is_refused(reader, monkeypatch):
    real_pid = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: real_pid + 1)
    with pytest.raises(LedgerUnavailable, match="another process"):
        reader.reservation_readonly("t1", "task-1", "op-1")


def test_reader_works_as_a_context_manager(writer, path, world):
    with TaskLedger.open_read_only(path, UID, GID) as reader:
        assert reader.is_revoked(world.context()) is False
    with pytest.raises(LedgerUnavailable, match="closed"):
        reader.reservation_readonly("t1", "task-1", "op-1")


@pytest.mark.parametrize(("writer_uid", "group"), [(True, GID), (-1, GID), (UID, None), (UID, "0"), (UID, -2)])
def test_malformed_ids_are_value_errors(writer, path, writer_uid, group):
    with pytest.raises(ValueError):
        TaskLedger.open_read_only(path, writer_uid, group)
