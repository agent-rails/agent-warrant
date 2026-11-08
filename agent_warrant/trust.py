from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from .canonical import MAX_SAFE_INTEGER

if TYPE_CHECKING:
    from .task_root import TaskRoot


def _names(label: str, values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, str):
        raise TypeError(f"{label} must be a collection of strings, not a str")
    result = frozenset(values)
    for value in result:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} entries must be non-empty strings")
    return result


PREFIX_DELIMITERS = ":/."


def _prefixes(values: Iterable[str]) -> frozenset[str]:
    result = _names("principal_prefixes", values)
    for prefix in result:
        if len(prefix) < 2 or prefix[-1] not in PREFIX_DELIMITERS:
            raise ValueError(
                f"principal_prefixes entry {prefix!r} must be a non-empty stem ending in one of {PREFIX_DELIMITERS}"
            )
    return result


def _limit(label: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ValueError(f"{label} must be an integer between 0 and {MAX_SAFE_INTEGER}")
    return value


@dataclass(frozen=True, kw_only=True)
class TenantAllowance:
    """Which principals an issuer may assert for one tenant. Principals match
    exactly; a prefix applies only when listed in `principal_prefixes`, must end in
    one of : / . after a non-empty stem (no wildcards), so `svc:team-a:` matches
    `svc:team-a:x` but never `svc:team-admin`. An empty set allows nothing."""

    principals: Iterable[str] = field(default_factory=frozenset)
    principal_prefixes: Iterable[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "principals", _names("principals", self.principals))
        object.__setattr__(self, "principal_prefixes", _prefixes(self.principal_prefixes))

    def permits(self, principal: str) -> bool:
        return principal in self.principals or any(principal.startswith(prefix) for prefix in self.principal_prefixes)


@dataclass(frozen=True, kw_only=True)
class IssuerAllowance:
    """What one issuer may assert in a TaskRoot: a mapping tenant -> TenantAllowance
    (principals are bound to their tenant, never pooled across tenants), plus
    inclusive caps on budget and delegation depth."""

    tenants: Mapping[str, TenantAllowance]
    max_budget: int
    max_depth: int

    def __post_init__(self) -> None:
        if not isinstance(self.tenants, Mapping):
            raise TypeError("tenants must be a mapping of tenant id to TenantAllowance")
        for tenant, tenant_allowance in self.tenants.items():
            if not isinstance(tenant, str) or not tenant:
                raise ValueError("tenant ids must be non-empty strings")
            if not isinstance(tenant_allowance, TenantAllowance):
                raise TypeError(f"allowance for tenant {tenant!r} must be a TenantAllowance")
        object.__setattr__(self, "tenants", MappingProxyType(dict(self.tenants)))
        _limit("max_budget", self.max_budget)
        _limit("max_depth", self.max_depth)

    def refusal(self, root: TaskRoot) -> str | None:
        tenant_allowance = self.tenants.get(root.tenant_id)
        if tenant_allowance is None:
            return f"issuer may not assert tenant {root.tenant_id!r}"
        if not tenant_allowance.permits(root.principal):
            return f"issuer may not assert principal {root.principal!r} for tenant {root.tenant_id!r}"
        if root.budget > self.max_budget:
            return f"budget {root.budget} exceeds issuer allowance {self.max_budget}"
        if root.max_depth > self.max_depth:
            return f"max_depth {root.max_depth} exceeds issuer allowance {self.max_depth}"
        return None


class IssuerTrustPolicy:
    """Maps issuer -> IssuerAllowance. A resolver maps an issuer to a key only, so
    a valid signature alone never grants authority to assert a tenant, principal
    or budget; this policy does. An issuer not listed here is refused."""

    def __init__(self, allowances: Mapping[str, IssuerAllowance]) -> None:
        for issuer, allowance in allowances.items():
            if not isinstance(issuer, str) or not issuer:
                raise ValueError("issuer ids must be non-empty strings")
            if not isinstance(allowance, IssuerAllowance):
                raise TypeError(f"allowance for {issuer!r} must be an IssuerAllowance")
        self._allowances = dict(allowances)

    def check_issuer(self, issuer: str) -> str | None:
        if issuer not in self._allowances:
            return f"issuer {issuer!r} is not in the trust policy"
        return None

    def check_claims(self, root: TaskRoot) -> str | None:
        allowance = self._allowances.get(root.issuer)
        if allowance is None:
            return f"issuer {root.issuer!r} is not in the trust policy"
        return allowance.refusal(root)
