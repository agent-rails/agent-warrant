from __future__ import annotations

from typing import Any

from .canonical import MAX_SAFE_INTEGER

SEPARATORS = ".:/_-"
MAX_ID_CHARACTERS = 128
MAX_ENTRIES = 64
_SCOPE_KEYS = frozenset({"tools", "resources", "max_cost_per_call"})


def validate_entry(entry: Any) -> str | None:
    """Return why `entry` is not a valid scope entry, or None if it is.

    An entry is an exact id or a prefix pattern. Ids are ASCII printable without
    whitespace (callers normalise before). A prefix pattern is a non-empty prefix
    ending at a separator (. : / _ -) followed by a single trailing `*`: `deploy.*`
    is valid, `deploy*`, `*` and `a*b` are not.
    """
    if not isinstance(entry, str) or not entry:
        return "entry must be a non-empty string"
    if len(entry) > MAX_ID_CHARACTERS:
        return f"entry is longer than {MAX_ID_CHARACTERS} characters"
    if not all("!" <= character <= "~" for character in entry):
        return "entry must be ASCII printable without whitespace"
    body = entry[:-1] if entry.endswith("*") else entry
    if "*" in body:
        return "`*` is allowed only as the final character of a prefix pattern"
    if body is not entry and (not body or body[-1] not in SEPARATORS):
        return f"prefix pattern must end at a separator ({SEPARATORS}) before `*`"
    return None


def validate_scope(scope: Any) -> str | None:
    """Return why `scope` is not a valid scope, or None if it is. The shape is exactly
    {"tools": [...], "resources": [...], "max_cost_per_call": int}."""
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
    cost = scope["max_cost_per_call"]
    if isinstance(cost, bool) or not isinstance(cost, int) or not 0 <= cost <= MAX_SAFE_INTEGER:
        return f"max_cost_per_call must be an integer between 0 and {MAX_SAFE_INTEGER}"
    return None


def _entry_covers(pattern: str, value: str) -> bool:
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def _entry_narrows(parent: str, child: str) -> bool:
    if parent.endswith("*"):
        return child.startswith(parent[:-1])
    return parent == child


def _covered_by_any(entries: list[str], value: str) -> bool:
    return any(_entry_covers(pattern, value) for pattern in entries)


def covers(scope: dict[str, Any], tool: str, resource: str) -> bool:
    """True if `scope` allows `tool` on `resource`. Both must be concrete ids (no `*`);
    anything else, or an invalid scope, is not covered. Cost is checked separately
    against `max_cost_per_call`. This is the only matcher: enforcement and narrowing
    both reduce to it."""
    if validate_scope(scope):
        return False
    for value in (tool, resource):
        if validate_entry(value) or "*" in value:
            return False
    return _covered_by_any(scope["tools"], tool) and _covered_by_any(scope["resources"], resource)


def scope_narrows(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    """True if `child` allows nothing that `parent` does not. Every child entry must be
    inside some parent entry: an exact id by the same id or a covering prefix, a prefix
    pattern only by a prefix pattern whose prefix it extends. Cost may not rise. An
    invalid scope on either side is not narrowing."""
    if validate_scope(parent) or validate_scope(child):
        return False
    if child["max_cost_per_call"] > parent["max_cost_per_call"]:
        return False
    for name in ("tools", "resources"):
        for entry in child[name]:
            if not any(_entry_narrows(candidate, entry) for candidate in parent[name]):
                return False
    return True
