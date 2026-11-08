from __future__ import annotations

import subprocess
import sys
import time

import pytest
from test_ledger import NOW, World

from agent_warrant.encoding import sha256_b64u
from agent_warrant.ledger import TaskLedger

TIMEOUT_SECONDS = 90

RACER = """
import sys, time
from agent_warrant.ledger import Operation, Refused, TaskLedger

path, tenant, task, root_binding, op_id, args_digest, start_at = sys.argv[1:8]
operation = Operation(
    op_id=op_id,
    tenant_id=tenant,
    task_id=task,
    leaf_binding=root_binding,
    tool="deploy.prod",
    resource="env/prod",
    args_digest=args_digest,
    cost=1,
    verdict_allowed=True,
    expires_at=2_000_000,
)
ledger = TaskLedger(path)
while time.time() < float(start_at):
    pass
try:
    ledger.reserve(operation, [], 1_000_000)
    print("WON")
except Refused as err:
    print("REFUSED " + str(err))
"""


def race(path, world, racers):
    start_at = time.time() + 4
    args_digest = sha256_b64u(b"args")
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                RACER,
                str(path),
                world.root.tenant_id,
                world.root.task_id,
                world.root.binding(),
                f"op-{index}",
                args_digest,
                str(start_at),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(racers)
    ]
    results = []
    for process in processes:
        try:
            out, err = process.communicate(timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            for other in processes:
                other.kill()
            raise
        assert process.returncode == 0, err
        results.append(out.strip())
    return results


@pytest.mark.parametrize("round_number", range(3))
def test_two_processes_race_for_the_last_budget_unit(tmp_path, round_number):
    world = World(budget=1)
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    ledger.open_task(world.verified(), NOW)
    results = race(path, world, 2)
    assert sorted(result.split()[0] for result in results) == ["REFUSED", "WON"]
    assert any("task budget exhausted" in result for result in results if result.startswith("REFUSED"))
    status = ledger.task_budget(world.root.tenant_id, world.root.task_id, NOW)
    assert (status.budget, status.spent) == (1, 1)


def test_many_processes_never_overspend_the_pool(tmp_path):
    world = World(budget=3)
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    ledger.open_task(world.verified(), NOW)
    results = race(path, world, 8)
    assert sum(result == "WON" for result in results) == 3
    assert sum(result.startswith("REFUSED") for result in results) == 5
    assert ledger.task_budget(world.root.tenant_id, world.root.task_id, NOW).spent == 3


def test_racers_with_the_same_op_id_charge_once(tmp_path):
    world = World(budget=5)
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    ledger.open_task(world.verified(), NOW)
    start_at = time.time() + 4
    digest = sha256_b64u(b"args")
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                RACER,
                str(path),
                world.root.tenant_id,
                world.root.task_id,
                world.root.binding(),
                "op-same",
                digest,
                str(start_at),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    outputs = [process.communicate(timeout=TIMEOUT_SECONDS)[0].strip() for process in processes]
    assert outputs == ["WON"] * 4
    assert ledger.task_budget(world.root.tenant_id, world.root.task_id, NOW).spent == 1
