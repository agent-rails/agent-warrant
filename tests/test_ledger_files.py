from __future__ import annotations

import os
import sqlite3
import stat

import pytest
from test_ledger import NOW, World

from agent_warrant.exceptions import RevocationSourceUnreachable
from agent_warrant.ledger import LedgerUnavailable, TaskLedger


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
    with pytest.raises(LedgerUnavailable, match="schema"):
        TaskLedger.open(path)


def test_open_refuses_a_database_with_an_unsupported_schema_version(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 99")
    connection.close()
    with pytest.raises(LedgerUnavailable, match="schema version 99"):
        TaskLedger.open(path)
