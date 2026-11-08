from __future__ import annotations

import os
import stat

import pytest
from test_ledger import NOW, World

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
    TaskLedger(path)
    assert mode_of(path) == 0o600


def test_wal_and_shm_files_are_private(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger(path)
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
    TaskLedger(path)
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
            TaskLedger(directory / "ledger.db")
        assert not (directory / "ledger.db").exists()
    finally:
        os.chmod(directory, 0o700)


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o700])
def test_parent_that_is_not_group_or_other_writable_is_accepted(tmp_path, mode):
    directory = private_dir(tmp_path)
    os.chmod(directory, mode)
    try:
        TaskLedger(directory / "ledger.db")
    finally:
        os.chmod(directory, 0o700)


def test_existing_private_database_reopens(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger(path).revoke_tenant("t1", NOW)
    assert TaskLedger(path).is_revoked(World().context()) is True


def test_every_operation_rechecks_the_file(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger(path)
    os.chmod(path, 0o666)
    with pytest.raises(LedgerUnavailable, match="mode"):
        ledger.revoke_tenant("t1", NOW)
