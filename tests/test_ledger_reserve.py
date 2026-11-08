from __future__ import annotations

import dataclasses

import pytest
from test_ledger import NOW, World

from agent_warrant.encoding import sha256_b64u
from agent_warrant.ledger import Operation, Refused, TaskLedger

ARGS = sha256_b64u(b"args")


@pytest.fixture
def world():
    return World(budget=100)


@pytest.fixture
def ledger(tmp_path, world):
    opened = TaskLedger.create(tmp_path / "ledger.db")
    opened.open_task(world.verified(), NOW)
    return opened


def operation(world, links=(), **overrides):
    leaf = links[-1].binding() if links else world.root.binding()
    fields = {
        "op_id": "op-1",
        "tenant_id": world.root.tenant_id,
        "task_id": world.root.task_id,
        "leaf_binding": leaf,
        "tool": "deploy.prod",
        "resource": "env/prod",
        "args_digest": ARGS,
        "cost": 10,
        "verdict_allowed": True,
        "expires_at": NOW + 60,
    }
    fields.update(overrides)
    return Operation(**fields)


def test_reserve_returns_a_reserved_reservation(ledger, world):
    op = operation(world)
    reservation = ledger.reserve(op, [], NOW)
    assert reservation.state == "reserved"
    assert reservation.cost == 10
    assert reservation.digest == op.digest()
    assert reservation.expires_at == NOW + 60


def test_reserve_charges_the_task_pool(ledger, world):
    ledger.reserve(operation(world), [], NOW)
    status = ledger.task_budget("t1", "task-1", NOW)
    assert (status.budget, status.spent, status.remaining) == (100, 10, 90)


def test_pool_is_enforced_exactly(ledger, world):
    for index in range(10):
        ledger.reserve(operation(world, op_id=f"op-{index}"), [], NOW)
    assert ledger.task_budget("t1", "task-1", NOW).remaining == 0
    with pytest.raises(Refused, match="task budget exhausted: 0 remaining"):
        ledger.reserve(operation(world, op_id="op-x", cost=1), [], NOW)


def test_one_unit_over_the_pool_is_refused_and_changes_nothing(ledger, world):
    ledger.reserve(operation(world, cost=95), [], NOW)
    with pytest.raises(Refused, match="budget exhausted"):
        ledger.reserve(operation(world, op_id="op-2", cost=6), [], NOW)
    assert ledger.task_budget("t1", "task-1", NOW).spent == 95
    assert ledger.reservation("t1", "task-1", "op-2", NOW) is None


def test_zero_cost_operation_is_allowed(ledger, world):
    assert ledger.reserve(operation(world, cost=0), [], NOW).state == "reserved"


@pytest.mark.parametrize("cost", [-1, 1.5, "10", None, True, 2**53])
def test_malformed_cost_is_refused(ledger, world, cost):
    with pytest.raises(Refused, match="cost must be an integer"):
        ledger.reserve(operation(world, cost=cost), [], NOW)
    assert ledger.task_budget("t1", "task-1", NOW).spent == 0


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("op_id", "", "op_id"),
        ("op_id", "a b", "op_id"),
        ("tool", "deploy.*", "tool must be a concrete id"),
        ("resource", "*", "resource must be a concrete id"),
        ("tool", "", "tool must be a concrete id"),
        ("args_digest", "short", "args_digest"),
        ("leaf_binding", "short", "leaf_binding"),
        ("verdict_allowed", "yes", "verdict_allowed"),
        ("expires_at", 1.5, "expires_at"),
        ("expires_at", -1, "expires_at"),
    ],
)
def test_malformed_operation_fields_are_refused(ledger, world, field, value, message):
    with pytest.raises(Refused, match=message):
        ledger.reserve(operation(world, **{field: value}), [], NOW)


def test_non_operation_is_refused(ledger):
    with pytest.raises(Refused, match="not an Operation"):
        ledger.reserve({"op_id": "x"}, [], NOW)


def test_non_allow_verdict_is_refused(ledger, world):
    with pytest.raises(Refused, match="verdict is not allow"):
        ledger.reserve(operation(world, verdict_allowed=False), [], NOW)


def test_expired_operation_is_refused(ledger, world):
    with pytest.raises(Refused, match="operation has expired"):
        ledger.reserve(operation(world, expires_at=NOW), [], NOW)


def test_unknown_task_is_refused(ledger, world):
    with pytest.raises(Refused, match="unknown task"):
        ledger.reserve(operation(world, task_id="nope"), [], NOW)


def test_unknown_tenant_is_refused(ledger, world):
    with pytest.raises(Refused, match="unknown task"):
        ledger.reserve(operation(world, tenant_id="t9"), [], NOW)


def test_revoked_task_is_refused(ledger, world):
    ledger.revoke_task("t1", "task-1", NOW)
    with pytest.raises(Refused, match="revoked"):
        ledger.reserve(operation(world), [], NOW)


def test_revoked_tenant_is_refused(ledger, world):
    ledger.revoke_tenant("t1", NOW)
    with pytest.raises(Refused, match="revoked"):
        ledger.reserve(operation(world), [], NOW)


def test_revoked_root_is_refused(ledger, world):
    ledger.revoke(world.root.binding(), NOW)
    with pytest.raises(Refused, match="revoked"):
        ledger.reserve(operation(world), [], NOW)


def test_revoked_link_is_refused_but_its_parent_still_works(ledger, world):
    links = world.chain(2)
    ledger.revoke(links[1].binding(), NOW)
    with pytest.raises(Refused, match="revoked"):
        ledger.reserve(operation(world, links), links, NOW)
    assert ledger.reserve(operation(world, links[:1], op_id="op-2"), links[:1], NOW).state == "reserved"


def test_other_tenants_revocation_does_not_apply(ledger, world):
    ledger.revoke_tenant("t2", NOW)
    ledger.revoke_task("t2", "task-1", NOW)
    assert ledger.reserve(operation(world), [], NOW).state == "reserved"


def test_link_cap_is_enforced(ledger, world):
    links = world.chain(1, budget=25)
    ledger.reserve(operation(world, links, op_id="a", cost=20), links, NOW)
    with pytest.raises(Refused, match="link budget exhausted: 5 remaining"):
        ledger.reserve(operation(world, links, op_id="b", cost=6), links, NOW)
    assert ledger.task_budget("t1", "task-1", NOW).spent == 20
    assert ledger.link_budget(links[0], NOW).spent == 20


def test_every_link_cap_in_the_chain_is_enforced(ledger, world):
    first = world.chain(1, budget=50)[0]
    from agent_warrant.chain import delegate
    from agent_warrant.identity import encode_public_key

    second = delegate(
        world.root,
        first,
        world.keys[1],
        child_subject=encode_public_key(world.keys[2].public_key()),
        scope=first.scope,
        budget=15,
        ttl=60,
        now=NOW,
    )
    links = [first, second]
    ledger.reserve(operation(world, links, op_id="a", cost=15), links, NOW)
    with pytest.raises(Refused, match="link budget exhausted: 0 remaining"):
        ledger.reserve(operation(world, links, op_id="b", cost=1), links, NOW)
    assert ledger.link_budget(first, NOW).spent == 15
    assert ledger.reserve(operation(world, [first], op_id="c", cost=35), [first], NOW).state == "reserved"
    with pytest.raises(Refused, match="link budget exhausted"):
        ledger.reserve(operation(world, [first], op_id="d", cost=1), [first], NOW)


def test_spend_through_a_subtree_counts_against_the_shared_parent_link(ledger, world):
    first = world.chain(1, budget=30)[0]
    ledger.reserve(operation(world, [first], op_id="a", cost=30), [first], NOW)
    with pytest.raises(Refused, match="link budget exhausted"):
        ledger.reserve(operation(world, [first], op_id="b", cost=1), [first], NOW)


def test_links_register_on_first_reserve_only(ledger, world):
    links = world.chain(2)
    assert ledger.link_budget(links[0], NOW) is None
    ledger.reserve(operation(world, links), links, NOW)
    assert ledger.link_budget(links[0], NOW).budget == links[0].budget
    assert ledger.link_budget(links[1], NOW).spent == 10


def test_pool_and_link_check_is_atomic(ledger, world):
    links = world.chain(1, budget=5)
    with pytest.raises(Refused, match="link budget exhausted"):
        ledger.reserve(operation(world, links, cost=6), links, NOW)
    assert ledger.task_budget("t1", "task-1", NOW).spent == 0
    assert ledger.link_budget(links[0], NOW) is None or ledger.link_budget(links[0], NOW).spent == 0


def test_links_from_another_task_are_refused(ledger, world):
    other = World(task="task-2")
    foreign = other.chain(1)
    with pytest.raises(Refused, match="different tenant or task"):
        ledger.reserve(operation(world, foreign), foreign, NOW)


def test_links_from_another_root_with_same_task_are_refused(ledger, world):
    other = World()
    foreign = other.chain(1)
    with pytest.raises(Refused, match="do not form a chain from this task's root"):
        ledger.reserve(operation(world, foreign), foreign, NOW)


def test_leaf_binding_must_be_the_end_of_the_chain(ledger, world):
    links = world.chain(2)
    with pytest.raises(Refused, match="leaf_binding is not the end of the chain"):
        ledger.reserve(operation(world, links[:1]), links, NOW)
    with pytest.raises(Refused, match="leaf_binding is not the end of the chain"):
        ledger.reserve(operation(world, links), [], NOW)


def test_reordered_links_are_refused(ledger, world):
    links = world.chain(2)
    with pytest.raises(Refused, match="do not form a chain"):
        ledger.reserve(operation(world, links), [links[1], links[0]], NOW)


def test_non_link_values_are_refused(ledger, world):
    with pytest.raises(Refused, match="ChainLink"):
        ledger.reserve(operation(world), ["link"], NOW)


def test_same_op_id_and_same_operation_returns_the_stored_reservation(ledger, world):
    op = operation(world)
    first = ledger.reserve(op, [], NOW)
    second = ledger.reserve(op, [], NOW + 1)
    assert second == first
    assert ledger.task_budget("t1", "task-1", NOW).spent == 10


def test_replay_returns_the_current_state_not_reserved(ledger, world):
    op = operation(world)
    ledger.reserve(op, [], NOW)
    ledger.mark_issued("t1", "task-1", "op-1", NOW)
    assert ledger.reserve(op, [], NOW).state == "issued"
    ledger.mark_done("t1", "task-1", "op-1", NOW)
    assert ledger.reserve(op, [], NOW).state == "done"
    assert ledger.task_budget("t1", "task-1", NOW).spent == 10


@pytest.mark.parametrize(
    "change",
    [
        {"cost": 11},
        {"tool": "deploy.staging"},
        {"resource": "env/staging"},
        {"args_digest": sha256_b64u(b"other")},
        {"expires_at": NOW + 61},
        {"verdict_allowed": False},
    ],
)
def test_same_op_id_with_a_different_operation_is_refused(ledger, world, change):
    ledger.reserve(operation(world), [], NOW)
    with pytest.raises(Refused, match="op_id was already used for a different operation"):
        ledger.reserve(operation(world, **change), [], NOW)
    assert ledger.task_budget("t1", "task-1", NOW).spent == 10


def test_every_operation_field_changes_the_digest(world):
    base = operation(world)
    changes = {
        "op_id": "op-2",
        "tenant_id": "t2",
        "task_id": "task-2",
        "leaf_binding": sha256_b64u(b"x"),
        "tool": "deploy.x",
        "resource": "env/x",
        "args_digest": sha256_b64u(b"y"),
        "cost": 11,
        "verdict_allowed": False,
        "expires_at": NOW + 61,
    }
    assert set(changes) == {field.name for field in dataclasses.fields(Operation)}
    digests = {base.digest()} | {dataclasses.replace(base, **{k: v}).digest() for k, v in changes.items()}
    assert len(digests) == len(changes) + 1


def test_op_id_is_scoped_per_tenant_and_task(tmp_path):
    ledger = TaskLedger.create(tmp_path / "ledger.db")
    worlds = [World(tenant="t1", task="task-1"), World(tenant="t1", task="task-2"), World(tenant="t2", task="task-1")]
    for world in worlds:
        ledger.open_task(world.verified(), NOW)
        assert ledger.reserve(operation(world), [], NOW).state == "reserved"
    for world in worlds:
        assert ledger.task_budget(world.root.tenant_id, world.root.task_id, NOW).spent == 10


def test_same_op_id_in_another_task_with_different_operation_is_independent(tmp_path):
    ledger = TaskLedger.create(tmp_path / "ledger.db")
    one, two = World(task="task-1"), World(task="task-2")
    ledger.open_task(one.verified(), NOW)
    ledger.open_task(two.verified(), NOW)
    ledger.reserve(operation(one, cost=10), [], NOW)
    assert ledger.reserve(operation(two, cost=20), [], NOW).cost == 20


def test_state_machine_happy_path(ledger, world):
    ledger.reserve(operation(world), [], NOW)
    assert ledger.mark_issued("t1", "task-1", "op-1", NOW).state == "issued"
    assert ledger.mark_done("t1", "task-1", "op-1", NOW).state == "done"
    assert ledger.reservation("t1", "task-1", "op-1", NOW).state == "done"


def test_outcome_unknown_keeps_budget_spent(ledger, world):
    ledger.reserve(operation(world), [], NOW)
    ledger.mark_issued("t1", "task-1", "op-1", NOW)
    assert ledger.mark_outcome_unknown("t1", "task-1", "op-1", NOW).state == "outcome_unknown"
    assert ledger.task_budget("t1", "task-1", NOW + 10**6).spent == 10


@pytest.mark.parametrize(
    ("setup", "action"),
    [
        ((), "mark_done"),
        ((), "mark_outcome_unknown"),
        (("mark_issued",), "mark_issued"),
        (("mark_issued", "mark_done"), "mark_issued"),
        (("mark_issued", "mark_done"), "mark_done"),
        (("mark_issued", "mark_done"), "mark_outcome_unknown"),
        (("mark_issued", "mark_outcome_unknown"), "mark_done"),
        (("mark_issued", "mark_outcome_unknown"), "mark_issued"),
    ],
)
def test_invalid_transitions_are_refused(ledger, world, setup, action):
    ledger.reserve(operation(world), [], NOW)
    for step in setup:
        getattr(ledger, step)("t1", "task-1", "op-1", NOW)
    with pytest.raises(Refused, match="cannot move"):
        getattr(ledger, action)("t1", "task-1", "op-1", NOW)


def test_transition_of_unknown_reservation_is_refused(ledger):
    with pytest.raises(Refused, match="unknown reservation"):
        ledger.mark_issued("t1", "task-1", "nope", NOW)


def test_mark_issued_is_refused_after_revocation_and_budget_stays_held(ledger, world):
    ledger.reserve(operation(world), [], NOW)
    ledger.revoke_task("t1", "task-1", NOW)
    with pytest.raises(Refused, match="revoked"):
        ledger.mark_issued("t1", "task-1", "op-1", NOW)
    assert ledger.reservation("t1", "task-1", "op-1", NOW).state == "reserved"


def test_mark_issued_is_refused_after_a_link_is_revoked(ledger, world):
    links = world.chain(2)
    ledger.reserve(operation(world, links), links, NOW)
    ledger.revoke(links[0].binding(), NOW)
    with pytest.raises(Refused, match="revoked"):
        ledger.mark_issued("t1", "task-1", "op-1", NOW)


def test_expired_reserved_reservation_is_released_on_next_access(ledger, world):
    links = world.chain(1)
    ledger.reserve(operation(world, links, cost=40), links, NOW)
    assert ledger.task_budget("t1", "task-1", NOW + 59).spent == 40
    assert ledger.task_budget("t1", "task-1", NOW + 60).spent == 0
    assert ledger.link_budget(links[0], NOW + 60).spent == 0
    assert ledger.reservation("t1", "task-1", "op-1", NOW + 60).state == "released"


def test_released_budget_can_be_reserved_again(ledger, world):
    ledger.reserve(operation(world, cost=100), [], NOW)
    with pytest.raises(Refused, match="budget exhausted"):
        ledger.reserve(operation(world, op_id="op-2", cost=1), [], NOW + 59)
    assert (
        ledger.reserve(operation(world, op_id="op-3", cost=100, expires_at=NOW + 200), [], NOW + 60).state == "reserved"
    )


def test_expired_reservation_is_never_issued(ledger, world):
    ledger.reserve(operation(world), [], NOW)
    with pytest.raises(Refused, match="cannot move a released reservation to issued"):
        ledger.mark_issued("t1", "task-1", "op-1", NOW + 60)


def test_issued_reservation_is_not_released_by_expiry(ledger, world):
    ledger.reserve(operation(world), [], NOW)
    ledger.mark_issued("t1", "task-1", "op-1", NOW + 30)
    assert ledger.task_budget("t1", "task-1", NOW + 10**6).spent == 10
    assert ledger.reservation("t1", "task-1", "op-1", NOW + 10**6).state == "issued"


def test_replay_of_a_released_op_id_does_not_reserve_again(ledger, world):
    op = operation(world)
    ledger.reserve(op, [], NOW)
    replay = ledger.reserve(op, [], NOW + 60)
    assert replay.state == "released"
    assert ledger.task_budget("t1", "task-1", NOW + 60).spent == 0


def test_reservations_and_spend_persist_across_restart(tmp_path, world):
    path = tmp_path / "ledger.db"
    first = TaskLedger.create(path)
    first.open_task(world.verified(), NOW)
    links = world.chain(1)
    first.reserve(operation(world, links, cost=30), links, NOW)
    first.mark_issued("t1", "task-1", "op-1", NOW)
    del first
    second = TaskLedger.open(path)
    assert second.task_budget("t1", "task-1", NOW).spent == 30
    assert second.link_budget(links[0], NOW).spent == 30
    assert second.reservation("t1", "task-1", "op-1", NOW).state == "issued"
    with pytest.raises(Refused, match="budget exhausted"):
        second.reserve(operation(world, op_id="op-2", cost=71), [], NOW)
    assert second.reserve(operation(world, links, cost=30), links, NOW).state == "issued"


def test_crash_between_reserve_and_issue_does_not_double_charge(tmp_path, world):
    path = tmp_path / "ledger.db"
    first = TaskLedger.create(path)
    first.open_task(world.verified(), NOW)
    op = operation(world)
    first.reserve(op, [], NOW)
    del first
    second = TaskLedger.open(path)
    again = second.reserve(op, [], NOW + 1)
    assert again.state == "reserved"
    assert second.task_budget("t1", "task-1", NOW + 1).spent == 10


def test_reserve_is_refused_once_the_chain_has_expired_even_if_the_operation_has_not(ledger, world):
    links = world.chain(1)
    assert links[0].expires_at == NOW + 600
    with pytest.raises(Refused, match="chain has expired"):
        ledger.reserve(operation(world, links, expires_at=NOW + 10**6), links, NOW + 600)
    assert ledger.task_budget("t1", "task-1", NOW + 600).spent == 0


def test_reserve_is_refused_once_the_root_has_expired(tmp_path):
    world = World(ttl=100)
    ledger = TaskLedger.create(tmp_path / "ledger.db")
    ledger.open_task(world.verified(), NOW)
    assert ledger.reserve(operation(world, expires_at=NOW + 10**6), [], NOW + 99).state == "reserved"
    with pytest.raises(Refused, match="chain has expired"):
        ledger.reserve(operation(world, op_id="op-2", expires_at=NOW + 10**6), [], NOW + 100)


def test_any_expired_link_in_the_chain_refuses_the_reservation(ledger, world):
    links = world.chain(2)
    short = dataclasses.replace(links[1], expires_at=NOW + 50)
    with pytest.raises(Refused, match="chain has expired"):
        ledger.reserve(operation(world, [links[0], short], expires_at=NOW + 10**6), [links[0], short], NOW + 50)


def test_reservation_expiry_is_the_earliest_of_operation_and_chain(ledger, world):
    links = world.chain(1)
    reservation = ledger.reserve(operation(world, links, expires_at=NOW + 10**6), links, NOW)
    assert reservation.expires_at == links[0].expires_at
    sooner = ledger.reserve(operation(world, links, op_id="op-2", expires_at=NOW + 30), links, NOW)
    assert sooner.expires_at == NOW + 30
    root_only = ledger.reserve(operation(world, op_id="op-3", expires_at=NOW + 10**6), [], NOW)
    assert root_only.expires_at == world.root.expires_at


def test_mark_issued_succeeds_just_before_chain_expiry(ledger, world):
    links = world.chain(1)
    ledger.reserve(operation(world, links, expires_at=NOW + 10**6), links, NOW)
    assert ledger.mark_issued("t1", "task-1", "op-1", NOW + 599).state == "issued"


def test_mark_issued_is_refused_at_chain_expiry_even_if_the_operation_outlives_it(ledger, world):
    links = world.chain(1)
    ledger.reserve(operation(world, links, expires_at=NOW + 10**6), links, NOW)
    with pytest.raises(Refused, match="cannot move a released reservation to issued"):
        ledger.mark_issued("t1", "task-1", "op-1", NOW + 600)
    assert ledger.task_budget("t1", "task-1", NOW + 600).spent == 0


def test_replay_after_chain_expiry_returns_the_stored_reservation(ledger, world):
    links = world.chain(1)
    op = operation(world, links, expires_at=NOW + 10**6)
    ledger.reserve(op, links, NOW)
    assert ledger.reserve(op, links, NOW + 600).state == "released"


def test_forged_first_link_with_a_cap_above_the_root_budget_is_refused(ledger, world):
    link = dataclasses.replace(world.chain(1, budget=10)[0], budget=10**6, proof="AAAA")
    with pytest.raises(Refused, match="link budget exceeds its parent's budget"):
        ledger.reserve(operation(world, [link], cost=50), [link], NOW)
    assert ledger.link_budget(link, NOW) is None
    assert ledger.task_budget("t1", "task-1", NOW).spent == 0


def test_forged_second_link_with_a_cap_above_its_parent_is_refused(ledger, world):
    first, second = world.chain(2, budget=20)
    forged = dataclasses.replace(second, budget=21)
    with pytest.raises(Refused, match="link budget exceeds its parent's budget"):
        ledger.reserve(operation(world, [first, forged]), [first, forged], NOW)
    assert ledger.link_budget(first, NOW) is None


def test_links_whose_caps_equal_or_narrow_their_parents_are_accepted(ledger, world):
    first = world.chain(1, budget=100)[0]
    assert first.budget == world.root.budget
    assert ledger.reserve(operation(world, [first]), [first], NOW).state == "reserved"
    narrower = world.chain(2, budget=40)
    assert ledger.reserve(operation(world, narrower, op_id="op-2"), narrower, NOW).state == "reserved"
