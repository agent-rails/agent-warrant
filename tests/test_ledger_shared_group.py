from __future__ import annotations

import grp
import os
import stat

import pytest
from test_ledger import NOW, World

from agent_warrant.ledger import LedgerUnavailable, TaskLedger


def private_dir(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o750)
    os.chmod(directory, 0o750)
    return directory


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def other_member_group():
    groups = [gid for gid in os.getgroups() if gid != os.getegid()]
    if not groups:
        pytest.skip("needs the current user to belong to a second group")
    return groups[0]


def non_member_group():
    if os.geteuid() == 0:
        pytest.skip("root may set any group")
    member = set(os.getgroups()) | {os.getegid()}
    for entry in grp.getgrall():
        if entry.gr_gid not in member:
            return entry.gr_gid
    pytest.skip("no group outside the current user's groups")


def test_default_create_is_still_0600(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path)
    assert mode_of(path) == 0o600


def test_shared_group_create_is_0640_in_that_group(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    group = os.getegid()
    TaskLedger.create(path, shared_group=group)
    assert mode_of(path) == 0o640
    assert os.stat(path).st_gid == group


def test_create_with_a_member_group_other_than_the_effective_group_is_refused(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    with pytest.raises(LedgerUnavailable, match="effective group"):
        TaskLedger.create(path, shared_group=other_member_group())
    assert not path.exists()


def test_open_with_a_member_group_other_than_the_effective_group_is_refused(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    group = other_member_group()
    TaskLedger.create(path, shared_group=os.getegid()).close()
    os.chown(path, -1, group)
    with pytest.raises(LedgerUnavailable, match="effective group"):
        TaskLedger.open(path, shared_group=group)


def test_shared_group_ledger_reopens_and_works(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    group = os.getegid()
    TaskLedger.create(path, shared_group=group).revoke_tenant("t1", NOW)
    assert TaskLedger.open(path, shared_group=group).is_revoked(World().context()) is True
    assert TaskLedger(path, group).is_revoked(World().context()) is True


def test_shared_group_sidecars_take_the_database_mode(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path, shared_group=os.getegid())
    ledger.open_task(World().verified(), NOW)
    for suffix in ("-wal", "-shm"):
        sidecar = path.parent / (path.name + suffix)
        assert sidecar.exists()
        assert mode_of(sidecar) == 0o640


def test_shared_ledger_opened_without_the_group_is_refused(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path, shared_group=os.getegid()).close()
    with pytest.raises(LedgerUnavailable, match="mode"):
        TaskLedger.open(path)
    assert mode_of(path) == 0o640


def test_private_ledger_opened_with_a_group_is_refused(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path).close()
    with pytest.raises(LedgerUnavailable, match="mode"):
        TaskLedger.open(path, shared_group=os.getegid())
    assert mode_of(path) == 0o600


@pytest.mark.parametrize("mode", [0o600, 0o644, 0o660, 0o604, 0o440, 0o740, 0o650])
def test_shared_ledger_with_any_other_mode_is_refused_and_not_modified(tmp_path, mode):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path, shared_group=os.getegid()).close()
    os.chmod(path, mode)
    with pytest.raises(LedgerUnavailable, match="mode|cannot open ledger file"):
        TaskLedger.open(path, shared_group=os.getegid())
    assert mode_of(path) == mode


def test_shared_ledger_in_another_group_is_refused(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    group = other_member_group()
    TaskLedger.create(path, shared_group=os.getegid()).close()
    os.chown(path, -1, group)
    with pytest.raises(LedgerUnavailable, match="group"):
        TaskLedger.open(path, shared_group=os.getegid())


def test_every_operation_rechecks_the_group(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    group = other_member_group()
    ledger = TaskLedger.create(path, shared_group=os.getegid())
    os.chown(path, -1, group)
    with pytest.raises(LedgerUnavailable, match="group"):
        ledger.revoke_tenant("t1", NOW)


def test_create_in_a_group_the_user_is_not_in_is_refused_and_leaves_no_file(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    with pytest.raises(LedgerUnavailable, match="group"):
        TaskLedger.create(path, shared_group=non_member_group())
    assert not path.exists()


@pytest.mark.parametrize("value", [True, -1, "0", 1.0])
def test_malformed_shared_group_is_a_value_error(tmp_path, value):
    path = private_dir(tmp_path) / "ledger.db"
    with pytest.raises(ValueError, match="shared_group"):
        TaskLedger.create(path, shared_group=value)
    assert not path.exists()


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


def shared_writer(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path, shared_group=os.getegid())
    ledger.open_task(World().verified(), NOW)
    return path, ledger


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
@pytest.mark.parametrize("tampering", sorted(SIDECAR_TAMPERING))
def test_writer_refuses_a_tampered_sidecar_on_the_next_call(tmp_path, suffix, tampering):
    path, ledger = shared_writer(tmp_path)
    change, message = SIDECAR_TAMPERING[tampering]
    change(path, suffix)
    with pytest.raises(LedgerUnavailable, match=f"ledger {suffix} file {message}"):
        ledger.revoke_tenant("t1", NOW)


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_writer_refuses_to_open_beside_a_tampered_sidecar(tmp_path, suffix):
    path, ledger = shared_writer(tmp_path)
    loosen_mode(path, suffix)
    with pytest.raises(LedgerUnavailable, match=f"ledger {suffix} file mode"):
        TaskLedger.open(path, shared_group=os.getegid())


def test_private_writer_refuses_a_loosened_sidecar(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    ledger = TaskLedger.create(path)
    ledger.open_task(World().verified(), NOW)
    assert mode_of(sidecar(path, "-wal")) == 0o600
    loosen_mode(path, "-wal")
    with pytest.raises(LedgerUnavailable, match="ledger -wal file mode must be 0o600"):
        ledger.revoke_tenant("t1", NOW)


def test_writer_opens_when_no_sidecar_exists(tmp_path):
    path = private_dir(tmp_path) / "ledger.db"
    TaskLedger.create(path, shared_group=os.getegid()).close()
    assert not sidecar(path, "-wal").exists()
    assert TaskLedger.open(path, shared_group=os.getegid()).is_revoked(World().context()) is False
