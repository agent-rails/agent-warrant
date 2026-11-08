from __future__ import annotations

import sqlite3

import pytest

from agent_warrant.chain import ChainContext, delegate, prove_leaf, verify_chain
from agent_warrant.encoding import sha256_b64u
from agent_warrant.exceptions import RevocationSourceUnreachable
from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.ledger import LedgerUnavailable, Refused, TaskLedger
from agent_warrant.resolver import PinnedResolver
from agent_warrant.task_root import TaskRootResult, issue_task_root, verify_root
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance

NOW = 1_000_000
AUDIENCE = "executor-1"
REQUEST = sha256_b64u(b"request-1")
SCOPE = {"tools": ["deploy.*"], "resources": ["env/*"], "max_cost_per_call": 5}
POLICY = IssuerTrustPolicy(
    {
        "issuer-a": IssuerAllowance(
            tenants={"t1": TenantAllowance(principals={"alice"}), "t2": TenantAllowance(principals={"alice"})},
            max_budget=1000,
            max_depth=16,
        )
    }
)


class NeverRevoked:
    def is_revoked(self, issuer, binding):
        return False


class World:
    def __init__(self, tenant="t1", task="task-1", budget=100, max_depth=3, ttl=3600):
        self.issuer_key = generate_keypair()
        self.resolver = PinnedResolver({"issuer-a": self.issuer_key.public_key()})
        self.keys = [generate_keypair() for _ in range(5)]
        self.root = issue_task_root(
            self.issuer_key,
            issuer="issuer-a",
            task_id=task,
            tenant_id=tenant,
            principal="alice",
            purpose="deploy",
            budget=budget,
            max_depth=max_depth,
            issued_at=NOW,
            expires_at=NOW + ttl,
            scope=SCOPE,
            subject=encode_public_key(self.keys[0].public_key()),
        )

    def verified(self):
        return verify_root(self.root.encode(), self.resolver, POLICY, NeverRevoked(), NOW)

    def chain(self, length, budget=None):
        links, parent = [], self.root
        for index in range(length):
            parent = delegate(
                self.root,
                parent,
                self.keys[index],
                child_subject=encode_public_key(self.keys[index + 1].public_key()),
                scope=SCOPE,
                budget=parent.budget if budget is None else budget,
                ttl=600,
                now=NOW,
            )
            links.append(parent)
        return links

    def context(self, links=()):
        return ChainContext(
            task_id=self.root.task_id,
            tenant_id=self.root.tenant_id,
            root_issuer="issuer-a",
            task_root=self.root.binding(),
            link_bindings=tuple(link.binding() for link in links),
        )


@pytest.fixture
def ledger(tmp_path):
    return TaskLedger.create(tmp_path / "ledger.db")


@pytest.fixture
def world():
    return World()


def test_open_task_accepts_a_verified_root(ledger, world):
    ledger.open_task(world.verified(), NOW)


def test_open_task_is_idempotent_for_the_same_root(ledger, world):
    ledger.open_task(world.verified(), NOW)
    ledger.open_task(world.verified(), NOW + 1)


@pytest.mark.parametrize("bad", [None, "root", object()])
def test_open_task_rejects_non_results(ledger, bad):
    with pytest.raises(ValueError, match="valid verify_root result"):
        ledger.open_task(bad, NOW)


def test_open_task_rejects_invalid_results(ledger, world):
    invalid = TaskRootResult(valid=False, reason="expired", root=world.root, checked_at=NOW)
    with pytest.raises(ValueError, match="valid verify_root result"):
        ledger.open_task(invalid, NOW)
    with pytest.raises(ValueError, match="valid verify_root result"):
        ledger.open_task(TaskRootResult(valid=True, reason="ok", root=None, checked_at=NOW), NOW)


def test_different_root_for_the_same_tenant_and_task_is_refused(ledger, world):
    ledger.open_task(world.verified(), NOW)
    other = World()
    with pytest.raises(Refused, match="different task root"):
        ledger.open_task(other.verified(), NOW)


def test_same_task_id_under_another_tenant_is_independent(ledger):
    ledger.open_task(World(tenant="t1").verified(), NOW)
    ledger.open_task(World(tenant="t2").verified(), NOW)


def test_nothing_is_revoked_by_default(ledger, world):
    assert ledger.is_revoked(world.context(world.chain(2))) is False


def test_revoke_binding_revokes_root_chain(ledger, world):
    ledger.revoke(world.root.binding(), NOW)
    assert ledger.is_revoked(world.context()) is True
    assert ledger.is_revoked(world.context(world.chain(2))) is True


def test_revoke_mid_chain_link_revokes_chains_through_it_only(ledger, world):
    links = world.chain(3)
    ledger.revoke(links[1].binding(), NOW)
    assert ledger.is_revoked(world.context(links)) is True
    assert ledger.is_revoked(world.context(links[:2])) is True
    assert ledger.is_revoked(world.context(links[:1])) is False
    assert ledger.is_revoked(world.context()) is False


def test_revoke_task_applies_to_that_tenant_task_only(ledger, world):
    ledger.revoke_task("t1", "task-1", NOW)
    assert ledger.is_revoked(world.context()) is True
    other_task = World(task="task-2")
    other_tenant = World(tenant="t2", task="task-1")
    assert ledger.is_revoked(other_task.context()) is False
    assert ledger.is_revoked(other_tenant.context()) is False


def test_revoke_tenant_applies_to_every_task_of_the_tenant(ledger, world):
    ledger.revoke_tenant("t1", NOW)
    assert ledger.is_revoked(world.context()) is True
    assert ledger.is_revoked(World(task="task-9").context()) is True
    assert ledger.is_revoked(World(tenant="t2").context()) is False


def test_revoking_twice_is_a_no_op(ledger, world):
    ledger.revoke(world.root.binding(), NOW)
    ledger.revoke(world.root.binding(), NOW + 5)
    ledger.revoke_task("t1", "task-1", NOW)
    ledger.revoke_task("t1", "task-1", NOW + 5)
    ledger.revoke_tenant("t1", NOW)
    ledger.revoke_tenant("t1", NOW + 5)


def test_open_task_refuses_revoked_task(ledger):
    ledger.revoke_task("t1", "task-1", NOW)
    with pytest.raises(Refused, match="revoked"):
        ledger.open_task(World().verified(), NOW)


def test_open_task_refuses_revoked_tenant(ledger):
    ledger.revoke_tenant("t1", NOW)
    with pytest.raises(Refused, match="revoked"):
        ledger.open_task(World().verified(), NOW)


def test_open_task_refuses_revoked_binding(ledger, world):
    ledger.revoke(world.root.binding(), NOW)
    with pytest.raises(Refused, match="revoked"):
        ledger.open_task(world.verified(), NOW)


@pytest.mark.parametrize("binding", ["", "short", "B" * 43, None, 5, "a" * 44])
def test_revoke_rejects_malformed_binding(ledger, binding):
    with pytest.raises(ValueError, match="binding"):
        ledger.revoke(binding, NOW)


@pytest.mark.parametrize("value", ["", "a b", "a\x00b", None, "café"])
def test_revoke_task_and_tenant_reject_malformed_ids(ledger, value):
    with pytest.raises(ValueError):
        ledger.revoke_tenant(value, NOW)
    with pytest.raises(ValueError):
        ledger.revoke_task(value, "task-1", NOW)
    with pytest.raises(ValueError):
        ledger.revoke_task("t1", value, NOW)


@pytest.mark.parametrize("now", [-1, 1.5, True, None])
def test_revoke_rejects_malformed_time(ledger, world, now):
    with pytest.raises(ValueError, match="now"):
        ledger.revoke_tenant("t1", now)


def test_there_is_no_unrevoke_api():
    public = {name for name in dir(TaskLedger) if not name.startswith("_")}
    assert not {name for name in public if "unrevoke" in name or "restore" in name or "clear" in name}


def test_revocation_rows_cannot_be_updated_or_deleted(ledger, world, tmp_path):
    ledger.revoke(world.root.binding(), NOW)
    ledger.revoke_task("t1", "task-1", NOW)
    ledger.revoke_tenant("t1", NOW)
    connection = sqlite3.connect(tmp_path / "ledger.db")
    for table in ("revoked_bindings", "revoked_tasks", "revoked_tenants"):
        with pytest.raises(sqlite3.IntegrityError, match="insert-only"):
            connection.execute(f"DELETE FROM {table}")
        with pytest.raises(sqlite3.IntegrityError, match="insert-only"):
            connection.execute(f"UPDATE {table} SET revoked_at = 0")
    connection.close()
    assert ledger.is_revoked(world.context()) is True


def test_revocations_persist_across_restart(tmp_path, world):
    path = tmp_path / "ledger.db"
    first = TaskLedger.create(path)
    first.open_task(world.verified(), NOW)
    links = world.chain(2)
    first.revoke(links[1].binding(), NOW)
    first.revoke_tenant("t9", NOW)
    del first
    second = TaskLedger.open(path)
    assert second.is_revoked(world.context(links)) is True
    assert second.is_revoked(world.context(links[:1])) is False
    assert second.is_revoked(World(tenant="t9").context()) is True
    with pytest.raises(Refused, match="different task root"):
        second.open_task(World().verified(), NOW)


def test_database_failure_is_unreachable_not_not_revoked(tmp_path, world):
    path = tmp_path / "ledger.db"
    ledger = TaskLedger.create(path)
    path.unlink()
    path.mkdir()
    with pytest.raises(RevocationSourceUnreachable):
        ledger.is_revoked(world.context())


def test_corrupt_database_is_unreachable(tmp_path, world):
    path = tmp_path / "ledger.db"
    ledger = TaskLedger.create(path)
    path.write_bytes(b"this is not a sqlite database" * 100)
    for suffix in ("-wal", "-shm"):
        (tmp_path / f"ledger.db{suffix}").unlink(missing_ok=True)
    with pytest.raises(RevocationSourceUnreachable):
        ledger.is_revoked(world.context())


def test_writes_fail_closed_on_database_failure(tmp_path, world):
    path = tmp_path / "ledger.db"
    ledger = TaskLedger.create(path)
    path.unlink()
    path.mkdir()
    with pytest.raises(LedgerUnavailable):
        ledger.revoke_tenant("t1", NOW)
    with pytest.raises(LedgerUnavailable):
        ledger.open_task(world.verified(), NOW)


def test_unsupported_schema_version_is_refused(tmp_path):
    path = tmp_path / "ledger.db"
    TaskLedger.create(path)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 99")
    connection.close()
    with pytest.raises(LedgerUnavailable, match="schema version 99"):
        TaskLedger.open(path)


def test_ledger_file_is_private(tmp_path):
    TaskLedger.create(tmp_path / "ledger.db")
    assert (tmp_path / "ledger.db").stat().st_mode & 0o077 == 0


def test_ledger_is_a_chain_revocation_checker_for_verify_chain(ledger, world):
    links = world.chain(2)
    proof = prove_leaf(links[-1], world.keys[2], NOW, audience=AUDIENCE, request_digest=REQUEST).encode()
    encoded = [link.encode() for link in links]
    args = (world.root.encode(), encoded, proof, world.resolver, POLICY, ledger, NOW)
    expected = {"expected_audience": AUDIENCE, "expected_request_digest": REQUEST}
    assert verify_chain(*args, **expected).valid is True
    ledger.revoke(links[0].binding(), NOW)
    result = verify_chain(*args, **expected)
    assert (result.valid, result.reason) == (False, "chain has been revoked")


def test_verify_chain_fails_closed_when_ledger_is_unreachable(tmp_path, world):
    path = tmp_path / "ledger.db"
    ledger = TaskLedger.create(path)
    links = world.chain(1)
    proof = prove_leaf(links[-1], world.keys[1], NOW, audience=AUDIENCE, request_digest=REQUEST).encode()
    path.unlink()
    path.mkdir()
    result = verify_chain(
        world.root.encode(),
        [links[0].encode()],
        proof,
        world.resolver,
        POLICY,
        ledger,
        NOW,
        expected_audience=AUDIENCE,
        expected_request_digest=REQUEST,
    )
    assert result.valid is False
    assert result.reason.startswith("revocation status unavailable")
