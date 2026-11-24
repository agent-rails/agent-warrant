from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .canonical import MAX_SAFE_INTEGER

SEPARATORS = ".:/_-"
MAX_ID_CHARACTERS = 128
MAX_ENTRIES = 64
MAX_PERMISSIONS = 16
MAX_TOTAL_ENTRIES = 64
_SCOPE_KEYS = frozenset({"tools", "resources", "max_cost_per_call"})
_SCOPE_V2_KEYS = frozenset({"permissions"})


def validate_entry(entry: Any) -> str | None:
    """Return why `entry` is not a valid scope entry, or None if it is.

    An entry is an exact id or a prefix pattern. Ids are ASCII printable without
    whitespace (callers normalise before), and exactly `str`: a subclass could override
    the comparisons matching relies on. A prefix pattern is a non-empty prefix
    ending at a separator (. : / _ -) followed by a single trailing `*`: `deploy.*`
    is valid, `deploy*`, `*` and `a*b` are not. Ids are opaque strings, never resolved
    as paths or decoded: `/` only delimits segments, and a segment may not be empty,
    `.` or `..` (a pattern stem may end in `/`), so `env/prod/../secret` is refused.
    """
    if type(entry) is not str or not entry:
        return "entry must be a non-empty string"
    if len(entry) > MAX_ID_CHARACTERS:
        return f"entry is longer than {MAX_ID_CHARACTERS} characters"
    if not all("!" <= character <= "~" for character in entry):
        return "entry must be ASCII printable without whitespace"
    body = entry[:-1] if entry.endswith("*") else entry
    if "*" in body:
        return "`*` is allowed only as the final character of a prefix pattern"
    is_pattern = body is not entry
    if is_pattern and (not body or body[-1] not in SEPARATORS):
        return f"prefix pattern must end at a separator ({SEPARATORS}) before `*`"
    segments = body.split("/")
    for position, segment in enumerate(segments):
        if segment in (".", ".."):
            return "`.` and `..` path segments are not allowed"
        trailing_pattern_slash = is_pattern and position == len(segments) - 1 and len(segments) > 1
        if not segment and not trailing_pattern_slash:
            return "empty path segments are not allowed"
    return None


def validate_scope_v1(scope: Any) -> str | None:
    """Return why `scope` is not a valid v1 scope, or None if it is. The shape is exactly
    {"tools": [...], "resources": [...], "max_cost_per_call": int}. v1 is read only: new
    records carry v2 scopes (see validate_scope)."""
    if not isinstance(scope, dict):
        return "scope must be an object"
    if set(scope) != _SCOPE_KEYS:
        return f"scope keys must be exactly {sorted(_SCOPE_KEYS)}"
    for name in ("tools", "resources"):
        entries = scope[name]
        if not isinstance(entries, list):
            return f"{name} must be a list"
        if len(entries) > MAX_ENTRIES:
            return f"{name} has more than {MAX_ENTRIES} entries"
        for entry in entries:
            reason = validate_entry(entry)
            if reason:
                return f"{name}: {reason}"
    return _cost_refusal(scope["max_cost_per_call"])


def _cost_refusal(cost: Any) -> str | None:
    if type(cost) is not int or not 0 <= cost <= MAX_SAFE_INTEGER:
        return f"max_cost_per_call must be an integer between 0 and {MAX_SAFE_INTEGER}"
    return None


def _permission_refusal(item: Any) -> str | None:
    if not isinstance(item, dict):
        return "permission must be an object"
    if set(item) != _SCOPE_KEYS:
        return f"permission keys must be exactly {sorted(_SCOPE_KEYS)}"
    for name in ("tools", "resources"):
        entries = item[name]
        if not isinstance(entries, list):
            return f"{name} must be a list"
        if not entries:
            return f"{name} must not be empty"
        for entry in entries:
            reason = validate_entry(entry)
            if reason:
                return f"{name}: {reason}"
        if len(set(entries)) != len(entries):
            return f"{name} has duplicate entries"
    return _cost_refusal(item["max_cost_per_call"])


def validate_scope(scope: Any) -> str | None:
    """Return why `scope` is not a valid v2 scope, or None if it is. The shape is exactly
    {"permissions": [{"tools": [...], "resources": [...], "max_cost_per_call": int}, ...]}:
    1 to 16 permissions, each with non-empty lists of valid entries and no entry twice in
    one list, at most 64 tool and resource entries in total, and no permission twice."""
    if not isinstance(scope, dict):
        return "scope must be an object"
    if set(scope) != _SCOPE_V2_KEYS:
        return f"scope keys must be exactly {sorted(_SCOPE_V2_KEYS)}"
    items = scope["permissions"]
    if not isinstance(items, list):
        return "permissions must be a list"
    if not items:
        return "permissions must not be empty"
    if len(items) > MAX_PERMISSIONS:
        return f"permissions has more than {MAX_PERMISSIONS} entries"
    total = 0
    for position, item in enumerate(items):
        reason = _permission_refusal(item)
        if reason:
            return f"permissions[{position}]: {reason}"
        if item in items[:position]:
            return f"permissions[{position}]: duplicate permission"
        total += len(item["tools"]) + len(item["resources"])
        if total > MAX_TOTAL_ENTRIES:
            return f"permissions have more than {MAX_TOTAL_ENTRIES} tool and resource entries in total"
    return None


def scope_version(scope: Any) -> int:
    """Return 2 for a {"permissions": [...]} scope and 1 for a v1 scope, judged by its
    keys only. Any other shape raises ValueError. Does not validate the contents."""
    if _is_v1(scope):
        return 1
    if isinstance(scope, dict) and set(scope) == _SCOPE_V2_KEYS:
        return 2
    raise ValueError("scope is neither a v1 nor a v2 scope")


def _is_v1(scope: Any) -> bool:
    return isinstance(scope, dict) and set(scope) == _SCOPE_KEYS


@dataclass(frozen=True)
class Permission:
    """One permission: every listed tool on every listed resource, at most
    `max_cost_per_call` per call. Built from a validated scope by permissions_of; the
    fields are tuples, so the view cannot change after it is built. A permission from a
    v1 scope may have empty lists or more than 64 entries."""

    tools: tuple[str, ...]
    resources: tuple[str, ...]
    max_cost_per_call: int

    def __post_init__(self) -> None:
        for name in ("tools", "resources"):
            entries = getattr(self, name)
            if isinstance(entries, str):
                raise TypeError(f"{name} must be a sequence of entries, not a string")
            entries = tuple(entries)
            for entry in entries:
                reason = validate_entry(entry)
                if reason:
                    raise ValueError(f"{name}: {reason}")
            object.__setattr__(self, name, entries)
        reason = _cost_refusal(self.max_cost_per_call)
        if reason:
            raise ValueError(reason)

    def covers(self, tool: str, resource: str) -> bool:
        """True if this permission allows `tool` on `resource`. Both must be concrete
        ids (valid entries without `*`); anything else is not covered. Cost is not
        checked here: check_call checks it against this permission's cap."""
        return _is_concrete(tool) and _is_concrete(resource) and self._matches(tool, resource)

    def _matches(self, tool: str, resource: str) -> bool:
        return _covered_by_any(self.tools, tool) and _covered_by_any(self.resources, resource)

    def contains(self, child: Permission) -> bool:
        """True if `child` allows nothing this permission does not: every child tool and
        resource lies inside one of this permission's tools or resources (an exact id by
        the same id or a covering prefix, a prefix pattern only by a prefix pattern whose
        prefix it extends) and the child cap is not above this cap."""
        if child.max_cost_per_call > self.max_cost_per_call:
            return False
        return all(any(_entry_narrows(own, entry) for own in self.tools) for entry in child.tools) and all(
            any(_entry_narrows(own, entry) for own in self.resources) for entry in child.resources
        )


def permissions_of(scope: Any) -> tuple[Permission, ...]:
    """The validated, immutable view of a v1 or v2 scope: one Permission per v2 item, or
    exactly one for a v1 scope. An invalid scope raises ValueError; a scope with neither
    key set is judged as v2."""
    is_v1 = _is_v1(scope)
    reason = validate_scope_v1(scope) if is_v1 else validate_scope(scope)
    if reason:
        raise ValueError(reason)
    items = [scope] if is_v1 else scope["permissions"]
    return tuple(Permission(item["tools"], item["resources"], item["max_cost_per_call"]) for item in items)


class CallRefusal(Enum):
    OUT_OF_SCOPE = "out_of_scope"
    COST_OVER_CALL_CAP = "cost_over_call_cap"


def entry_covers(pattern: str, value: str) -> bool:
    """True if the entry `pattern` covers `value`: a prefix pattern covers every value
    starting with its stem, an exact id only itself. Pattern matching only: neither
    argument is validated, so callers must refuse invalid or non-concrete values first
    (check_call and Permission.covers do)."""
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def _entry_narrows(parent: str, child: str) -> bool:
    if parent.endswith("*"):
        return child.startswith(parent[:-1])
    return parent == child


def _covered_by_any(entries: tuple[str, ...], value: str) -> bool:
    return any(entry_covers(pattern, value) for pattern in entries)


def _is_concrete(value: Any) -> bool:
    return type(value) is str and validate_entry(value) is None and "*" not in value


def check_call(permissions: tuple[Permission, ...], tool: str, resource: str, cost: int) -> CallRefusal | None:
    """Decide one call against a decoded scope view (permissions_of, or a record's
    `.permissions`). The call is allowed (None) only if one permission covers both
    `tool` and `resource` and `cost` is within that permission's cap. OUT_OF_SCOPE: no
    permission covers the pair, or either id is not concrete. COST_OVER_CALL_CAP: some
    permission covers the pair but none allows `cost`. Ids, cost and permissions must be
    exactly str, int and Permission, never subclasses. A cost that is not an integer from
    0 to MAX_SAFE_INTEGER raises."""
    if type(permissions) is not tuple or not all(type(item) is Permission for item in permissions):
        raise TypeError("permissions must be a tuple of Permission")
    if type(cost) is not int:
        raise TypeError("cost must be an integer")
    if not 0 <= cost <= MAX_SAFE_INTEGER:
        raise ValueError(f"cost must be between 0 and {MAX_SAFE_INTEGER}")
    if not (_is_concrete(tool) and _is_concrete(resource)):
        return CallRefusal.OUT_OF_SCOPE
    covered = False
    for item in permissions:
        if item._matches(tool, resource):
            if cost <= item.max_cost_per_call:
                return None
            covered = True
    return CallRefusal.COST_OVER_CALL_CAP if covered else CallRefusal.OUT_OF_SCOPE


def _narrows(parent: tuple[Permission, ...], child: tuple[Permission, ...]) -> bool:
    return all(any(own.contains(item) for own in parent) for item in child)


def scope_narrows(parent: Any, child: Any) -> bool:
    """True if `child` allows nothing that `parent` does not: every child permission is
    contained by one parent permission (Permission.contains), so tools and resources from
    different parent permissions never combine and each child cap fits the parent
    permission that contains it. A v1 scope is one permission. A v1 child under a v2
    parent, or an invalid scope on either side, is not narrowing."""
    try:
        parent_permissions = permissions_of(parent)
        child_permissions = permissions_of(child)
    except ValueError:
        return False
    if scope_version(parent) == 2 and scope_version(child) == 1:
        return False
    return _narrows(parent_permissions, child_permissions)
