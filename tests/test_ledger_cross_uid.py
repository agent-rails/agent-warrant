from __future__ import annotations

import dataclasses
import grp
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from test_ledger import NOW, World

import agent_warrant
from agent_warrant.encoding import sha256_b64u
from agent_warrant.ledger import Operation, TaskLedger

READER_USER = os.environ.get("AGENT_WARRANT_READER_USER")
SHARED_GROUP = os.environ.get("AGENT_WARRANT_SHARED_GROUP")

pytestmark = pytest.mark.skipif(
    not (READER_USER and SHARED_GROUP),
    reason="needs AGENT_WARRANT_READER_USER, a second OS user reachable by sudo -n, and "
    "AGENT_WARRANT_SHARED_GROUP, a group both users are in and the writer's primary group",
)

READER_CODE = """
import json, sys
sys.path.insert(0, sys.argv[1])
from agent_warrant.chain import ChainContext
from agent_warrant.ledger import LedgerUnavailable, TaskLedger
path, writer_uid, group = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
context = json.loads(sys.argv[5])
context["link_bindings"] = tuple(context["link_bindings"])
report = {}
try:
    open(path, "r+b").close()
    report["file_writable"] = True
except PermissionError:
    report["file_writable"] = False
try:
    TaskLedger.open(path).close()
    report["writer_open"] = "opened"
except LedgerUnavailable as err:
    report["writer_open"] = str(err)
try:
    with TaskLedger.open_read_only(path, writer_uid, group) as ledger:
        report["revoked"] = ledger.is_revoked(ChainContext(**context))
        stored = ledger.reservation_readonly("t1", "task-1", "op-1")
        report["reservation"] = None if stored is None else [stored.state, stored.expires_at]
        try:
            ledger.revoke_tenant("t1", 1)
            report["revoke"] = "revoked"
        except LedgerUnavailable as err:
            report["revoke"] = str(err)
except LedgerUnavailable as err:
    report["error"] = str(err)
print(json.dumps(report))
"""

OTHER_PRIMARY_GROUP_WRITER_CODE = """
import json, os, sys
sys.path.insert(0, sys.argv[1])
from agent_warrant.ledger import LedgerUnavailable, TaskLedger
path, group = sys.argv[2], int(sys.argv[3])
report = {"egid": os.getegid(), "groups": os.getgroups()}
try:
    TaskLedger.create(path, shared_group=group).close()
    report["create"] = "created"
except LedgerUnavailable as err:
    report["create"] = str(err)
print(json.dumps(report))
"""


def make_readable_tree(root):
    for directory, _, files in os.walk(root):
        os.chmod(directory, 0o755)
        for name in files:
            os.chmod(os.path.join(directory, name), 0o644)


@pytest.fixture
def shared_world():
    gid = grp.getgrnam(SHARED_GROUP).gr_gid
    assert (os.getgid(), os.getegid()) == (gid, gid), "run the writer with the shared group as its primary group"
    code_root = Path(tempfile.mkdtemp(prefix="agent-warrant-code-"))
    state = Path(tempfile.mkdtemp(prefix="agent-warrant-state-"))
    try:
        shutil.copytree(
            Path(agent_warrant.__file__).parent,
            code_root / "agent_warrant",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        make_readable_tree(code_root)
        os.chown(state, -1, gid)
        os.chmod(state, 0o750)
        yield code_root, state / "ledger.db", gid
    finally:
        shutil.rmtree(code_root, ignore_errors=True)
        shutil.rmtree(state, ignore_errors=True)


def read_as_other_user(code_root, path, gid, context):
    result = subprocess.run(
        [
            "sudo",
            "-n",
            "-u",
            READER_USER,
            sys.executable,
            "-I",
            "-B",
            "-c",
            READER_CODE,
            str(code_root),
            str(path),
            str(os.geteuid()),
            str(gid),
            json.dumps(dataclasses.asdict(context)),
        ],
        capture_output=True,
        cwd="/",
        timeout=60,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_another_user_reads_while_the_writer_holds_the_database_open(shared_world):
    code_root, path, gid = shared_world
    assert pwd.getpwnam(READER_USER).pw_uid != os.geteuid()
    world = World(budget=100)
    context = world.context()
    writer = TaskLedger.create(path, shared_group=gid)
    writer.open_task(world.verified(), NOW)
    writer.reserve(
        Operation(
            op_id="op-1",
            tenant_id="t1",
            task_id="task-1",
            leaf_binding=world.root.binding(),
            tool="deploy.prod",
            resource="env/prod",
            args_digest=sha256_b64u(b"args"),
            cost=10,
            verdict_allowed=True,
            expires_at=NOW + 5,
        ),
        [],
        NOW,
    )
    for suffix in ("", "-wal", "-shm"):
        info = os.stat(f"{path}{suffix}")
        assert (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (0o640, os.geteuid(), gid), suffix

    first = read_as_other_user(code_root, path, gid, context)
    assert first["file_writable"] is False
    assert first["writer_open"] != "opened"
    assert "error" not in first, first
    assert first["revoked"] is False
    assert first["reservation"] == ["reserved", NOW + 5]
    assert "read-only" in first["revoke"]

    writer.revoke_tenant("t1", NOW)
    second = read_as_other_user(code_root, path, gid, context)
    assert "error" not in second, second
    assert second["revoked"] is True

    writer.close()
    assert not os.path.exists(f"{path}-wal")
    assert not os.path.exists(f"{path}-shm")
    after_close = read_as_other_user(code_root, path, gid, context)
    assert "writer is not holding the database open" in after_close.get("error", ""), after_close
    assert "revoked" not in after_close


def test_a_writer_whose_primary_group_is_not_the_shared_group_is_refused(shared_world):
    code_root, path, gid = shared_world
    result = subprocess.run(
        [
            "sudo",
            "-n",
            "-u",
            pwd.getpwuid(os.geteuid()).pw_name,
            sys.executable,
            "-I",
            "-B",
            "-c",
            OTHER_PRIMARY_GROUP_WRITER_CODE,
            str(code_root),
            str(path),
            str(gid),
        ],
        capture_output=True,
        cwd="/",
        timeout=60,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["egid"] != gid, report
    assert gid in report["groups"], report
    assert "must be the writer's effective group" in report["create"], report
    assert not path.exists()
