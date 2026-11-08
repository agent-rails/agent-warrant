from __future__ import annotations

import os
import sqlite3
import stat
import subprocess
import sys

import pytest
from test_ledger import NOW, World

from agent_warrant.encoding import sha256_b64u
from agent_warrant.exceptions import RevocationSourceUnreachable
from agent_warrant.ledger import LedgerUnavailable, Operation, TaskLedger


def private_dir(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_new_database_is_private(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path)
    assert mode_of(path) == 0o600


def test_wal_and_shm_files_are_private(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    ledger.open_task(World().verified(), NOW)
    for suffix in ("-wal", "-shm"):
        sidecar = path.parent / (path.name + suffix)
        if sidecar.exists():
            assert mode_of(sidecar) == 0o600


@pytest.mark.parametrize("mode", [0o666, 0o644, 0o640, 0o604, 0o400, 0o700, 0o000])
def test_existing_database_with_any_other_mode_is_refused_and_not_modified(tmp_path, mode):
    path = private_dir(tmp_path) / "ledger.db"
    path.touch()
    os.chmod(path, mode)
    with pytest.raises(LedgerUnavailable, match="mode|cannot open ledger file"):
        TaskLedger(path)
    assert mode_of(path) == mode
    assert path.stat().st_size == 0


def test_symlink_is_not_followed(tmp_path):
    directory = private_dir(tmp_path)
    victim = directory / "victim.db"
    victim.touch()
    os.chmod(victim, 0o600)
    link = directory / "link.db"
    link.symlink_to(victim)
    with pytest.raises(LedgerUnavailable):
        TaskLedger(link)
    assert victim.stat().st_size == 0


def test_dangling_symlink_is_not_followed_or_created_through(tmp_path):
    directory = private_dir(tmp_path)
    link = directory / "link.db"
    link.symlink_to(directory / "missing.db")
    with pytest.raises(LedgerUnavailable):
        TaskLedger(link)
    assert not (directory / "missing.db").exists()


def test_directory_is_refused(tmp_path):
    directory = private_dir(tmp_path)
    (directory / "ledger.db").mkdir()
    with pytest.raises(LedgerUnavailable):
        TaskLedger(directory / "ledger.db")


def test_file_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path)
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(LedgerUnavailable, match="owner"):
        TaskLedger(path)


@pytest.mark.parametrize("mode", [0o770, 0o707, 0o777, 0o722, 0o702])
def test_group_or_other_writable_parent_is_refused(tmp_path, mode):
    directory = private_dir(tmp_path)
    os.chmod(directory, mode)
    try:
        with pytest.raises(LedgerUnavailable, match="parent directory"):
            TaskLedger.create(directory / "ledger.db")
        assert not (directory / "ledger.db").exists()
    finally:
        os.chmod(directory, 0o700)


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o700])
def test_parent_that_is_not_group_or_other_writable_is_accepted(tmp_path, mode):
    directory = private_dir(tmp_path)
    os.chmod(directory, mode)
    try:
        TaskLedger.create(directory / "ledger.db")
    finally:
        os.chmod(directory, 0o700)


def test_existing_private_database_reopens(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path).revoke_tenant("t1", NOW)
    assert TaskLedger.open(path).is_revoked(World().context()) is True


def test_every_operation_rechecks_the_file(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    os.chmod(path, 0o666)
    with pytest.raises(LedgerUnavailable, match="mode"):
        ledger.revoke_tenant("t1", NOW)


def test_create_makes_a_private_database_with_the_schema(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    assert mode_of(path) == 0o600
    assert ledger.is_revoked(World().context()) is False


def test_create_refuses_to_replace_an_existing_file(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path).revoke_tenant("t1", NOW)
    with pytest.raises(LedgerUnavailable, match="cannot create"):
        TaskLedger.create(path)
    assert TaskLedger.open(path).is_revoked(World().context()) is True


def test_create_refuses_a_dangling_symlink(tmp_path):
    directory = private_dir(tmp_path)
    (directory / "link.db").symlink_to(directory / "missing.db")
    with pytest.raises(LedgerUnavailable):
        TaskLedger.create(directory / "link.db")
    assert not (directory / "missing.db").exists()


def test_open_never_creates_a_missing_database(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    with pytest.raises(LedgerUnavailable):
        TaskLedger.open(path)
    assert not path.exists()


def test_constructor_never_creates_a_missing_database(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    with pytest.raises(LedgerUnavailable):
        TaskLedger(path)
    assert not path.exists()


def delete_database(path):
    for suffix in ("", "-wal", "-shm"):
        sidecar = path.parent / (path.name + suffix)
        if sidecar.exists():
            sidecar.unlink()


def test_deleted_database_is_unreachable_not_not_revoked_and_is_not_recreated(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    ledger.revoke_tenant("t1", NOW)
    delete_database(path)
    with pytest.raises(RevocationSourceUnreachable):
        ledger.is_revoked(World().context())
    assert not path.exists()


def test_new_instance_on_a_deleted_database_fails(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path).revoke_tenant("t1", NOW)
    delete_database(path)
    with pytest.raises(LedgerUnavailable):
        TaskLedger.open(path)
    assert not path.exists()


def test_writes_to_a_deleted_database_fail_and_do_not_recreate_it(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    delete_database(path)
    with pytest.raises(LedgerUnavailable):
        ledger.revoke_tenant("t1", NOW)
    with pytest.raises(LedgerUnavailable):
        ledger.open_task(World().verified(), NOW)
    assert not path.exists()


def test_an_empty_replacement_file_never_answers_not_revoked(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    ledger.revoke_tenant("t1", NOW)
    delete_database(path)
    path.touch()
    os.chmod(path, 0o600)
    with pytest.raises(RevocationSourceUnreachable):
        ledger.is_revoked(World().context())
    with pytest.raises(LedgerUnavailable, match="schema|SQLite"):
        TaskLedger.open(path)


def test_open_refuses_a_database_with_an_unsupported_schema_version(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 99")
    connection.close()
    with pytest.raises(LedgerUnavailable, match="schema version 99"):
        TaskLedger.open(path)


def count_connections(monkeypatch):
    import agent_warrant.ledger as ledger_module

    calls = []
    real = sqlite3.connect

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(ledger_module.sqlite3, "connect", counting)
    return calls


def test_one_sqlite_connection_serves_every_call(tmp_path, monkeypatch):
    calls = count_connections(monkeypatch)
    world = World()
    ledger = TaskLedger.create(private_dir(tmp_path) / "ledger.db")
    ledger.open_task(world.verified(), NOW)
    for index in range(5):
        ledger.revoke_tenant(f"tenant-{index}", NOW)
        ledger.is_revoked(world.context())
        ledger.task_budget("t1", "task-1", NOW)
    assert len(calls) == 1


def test_open_uses_one_connection_too(tmp_path, monkeypatch):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path)
    calls = count_connections(monkeypatch)
    ledger = TaskLedger.open(path)
    for _ in range(3):
        ledger.is_revoked(World().context())
    assert len(calls) == 1


def test_close_makes_further_use_fail_closed(tmp_path):
    ledger = TaskLedger.create(private_dir(tmp_path) / "ledger.db")
    ledger.close()
    with pytest.raises(LedgerUnavailable, match="closed"):
        ledger.revoke_tenant("t1", NOW)
    with pytest.raises(RevocationSourceUnreachable):
        ledger.is_revoked(World().context())


def test_close_is_idempotent(tmp_path):
    ledger = TaskLedger.create(private_dir(tmp_path) / "ledger.db")
    ledger.close()
    ledger.close()


def test_context_manager_closes_the_ledger(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    with TaskLedger.create(path) as ledger:
        ledger.revoke_tenant("t1", NOW)
    with pytest.raises(LedgerUnavailable, match="closed"):
        ledger.revoke_tenant("t2", NOW)
    with TaskLedger.open(path) as reopened:
        assert reopened.is_revoked(World().context()) is True


def test_a_file_swapped_in_at_the_same_path_is_refused(tmp_path):
    import shutil

    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    ledger.revoke_tenant("t1", NOW)
    copy = path.parent / "copy.db"
    shutil.copy(path, copy)
    os.chmod(copy, 0o600)
    os.replace(copy, path)
    with pytest.raises(LedgerUnavailable, match="replaced"):
        ledger.revoke_tenant("t2", NOW)
    with pytest.raises(RevocationSourceUnreachable):
        ledger.is_revoked(World().context())


def test_a_ledger_is_safe_to_share_between_threads(tmp_path):
    import threading

    world = World(budget=1000)
    ledger = TaskLedger.create(private_dir(tmp_path) / "ledger.db")
    ledger.open_task(world.verified(), NOW)
    errors = []

    def work(thread_number):
        try:
            for index in range(10):
                ledger.is_revoked(world.context())
                ledger.reserve(
                    Operation(
                        f"op-{thread_number}-{index}",
                        "t1",
                        "task-1",
                        world.root.binding(),
                        "deploy.prod",
                        "env/prod",
                        sha256_b64u(b"a"),
                        1,
                        True,
                        NOW + 100,
                    ),
                    [],
                    NOW,
                )
        except Exception as err:
            errors.append(err)

    threads = [threading.Thread(target=work, args=(number,)) for number in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert errors == []
    assert ledger.task_budget("t1", "task-1", NOW).spent == 80


def test_overwriting_the_header_in_place_fails_closed(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    ledger.revoke_tenant("t1", NOW)
    with open(path, "r+b") as handle:
        handle.write(b"garbage-garbage-")
    with pytest.raises(RevocationSourceUnreachable):
        ledger.is_revoked(World().context())
    with pytest.raises(LedgerUnavailable, match="not a SQLite database"):
        ledger.revoke_tenant("t2", NOW)


class FlakyConnection:
    """Delegates to a real sqlite3 connection but raises on chosen statements."""

    def __init__(self, real, fail_on):
        self._real = real
        self.fail_on = dict(fail_on)

    def execute(self, sql, *args):
        error = self.fail_on.pop(sql, None)
        if error is not None:
            raise error
        return self._real.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._real, name)


OTHER_PROCESS_WRITER = """
import sys
import agent_warrant.ledger as ledger_module
ledger_module.BUSY_TIMEOUT_SECONDS = 3
ledger = ledger_module.TaskLedger.open(sys.argv[1])
ledger.revoke_tenant("other-process", 1_000_000)
print("WROTE")
"""


def other_process_can_write(path):
    result = subprocess.run(
        [sys.executable, "-c", OTHER_PROCESS_WRITER, str(path)], capture_output=True, text=True, timeout=60
    )
    return result.returncode == 0 and result.stdout.strip() == "WROTE", result.stderr


def test_interrupt_at_commit_does_not_leave_a_transaction_open(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    real = ledger._connection
    ledger._connection = FlakyConnection(real, {"COMMIT": KeyboardInterrupt("signal at COMMIT")})
    with pytest.raises(KeyboardInterrupt):
        ledger.revoke_tenant("t1", NOW)
    assert real.in_transaction is False
    wrote, stderr = other_process_can_write(path)
    assert wrote, stderr
    ledger.revoke_tenant("t2", NOW)
    assert ledger.is_revoked(World().context()) is False
    assert ledger.is_revoked(World(tenant="t2").context()) is True


def test_interrupted_commit_is_rolled_back_not_half_applied(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    ledger._connection = FlakyConnection(ledger._connection, {"COMMIT": KeyboardInterrupt()})
    with pytest.raises(KeyboardInterrupt):
        ledger.revoke_tenant("t1", NOW)
    assert ledger.is_revoked(World().context()) is False
    reader = sqlite3.connect(path)
    assert reader.execute("SELECT COUNT(*) FROM revoked_tenants").fetchone()[0] == 0
    reader.close()


def test_failed_rollback_closes_and_drops_the_connection_and_the_next_call_reconnects(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    real = ledger._connection

    class RollbackFails(FlakyConnection):
        def rollback(self):
            raise OSError("rollback failed")

    ledger._connection = RollbackFails(real, {"COMMIT": KeyboardInterrupt(), "ROLLBACK": OSError("no rollback")})
    with pytest.raises(KeyboardInterrupt):
        ledger.revoke_tenant("t1", NOW)
    assert ledger._connection is None
    wrote, stderr = other_process_can_write(path)
    assert wrote, stderr
    ledger.revoke_tenant("t2", NOW)
    assert ledger._connection is not None
    assert ledger.is_revoked(World(tenant="t2").context()) is True


def test_an_interrupt_during_a_refusal_rollback_still_releases_the_lock(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    ledger._connection = FlakyConnection(ledger._connection, {"ROLLBACK": KeyboardInterrupt()})
    with pytest.raises(KeyboardInterrupt):
        ledger.task_budget("t1", "no-such-task", NOW)
    assert ledger._connection is None
    wrote, stderr = other_process_can_write(path)
    assert wrote, stderr
    ledger.revoke_tenant("t3", NOW)


def test_a_dropped_connection_reconnects_only_through_the_file_checks(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    ledger._connection.close()
    ledger._connection = None
    os.chmod(path, 0o666)
    with pytest.raises(LedgerUnavailable, match="mode"):
        ledger.revoke_tenant("t1", NOW)
    os.chmod(path, 0o600)
    ledger.revoke_tenant("t1", NOW)


def test_close_is_final_and_a_dropped_connection_is_not(tmp_path):
    ledger = TaskLedger.create(private_dir(tmp_path) / "ledger.db")
    ledger.close()
    with pytest.raises(LedgerUnavailable, match="closed"):
        ledger.revoke_tenant("t1", NOW)


def test_file_swapped_between_the_check_and_the_connect_is_refused(tmp_path, monkeypatch):
    import shutil

    import agent_warrant.ledger as ledger_module

    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path).close()
    real_connect = sqlite3.connect

    def swapping_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        copy = path.parent / "swap.db"
        shutil.copy(path, copy)
        os.chmod(copy, 0o600)
        os.replace(copy, path)
        return connection

    monkeypatch.setattr(ledger_module.sqlite3, "connect", swapping_connect)
    with pytest.raises(LedgerUnavailable, match="replaced"):
        TaskLedger.open(path)


def test_ledger_used_from_a_forked_process_is_refused(tmp_path, monkeypatch):
    ledger = TaskLedger.create(private_dir(tmp_path) / "ledger.db")
    real_pid = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: real_pid + 1)
    with pytest.raises(LedgerUnavailable, match="another process"):
        ledger.revoke_tenant("t1", NOW)
    with pytest.raises(RevocationSourceUnreachable):
        ledger.is_revoked(World().context())


def test_a_hard_linked_database_is_refused(tmp_path):
    directory = private_dir(tmp_path)
    path = directory / "ledger.db"
    TaskLedger.create(path).close()
    os.link(path, directory / "other-name.db")
    with pytest.raises(LedgerUnavailable, match="hard links"):
        TaskLedger.open(path)
