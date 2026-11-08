from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from typing import Any

# A compact authority claim's scope structure never legitimately needs deep nesting.
# Bounding it here, at the source, protects every caller of canonicalize() uniformly --
# found live: canonicalize()'s own pure-Python recursive walk (not json.loads, which
# decode()'s size cap and RecursionError catch already guard) trips Python's interpreter
# recursion limit at roughly 2-3KB of nested input, well UNDER the encoded-grant size cap
# (MAX_ENCODED_GRANT_BYTES=16KB) that was assumed to prevent this class of gap. Patching
# each of canonicalize()'s call sites individually with a RecursionError catch was
# considered and rejected: it's exactly the kind of fragile, easy-to-miss-a-spot fix that
# already missed this same call before (three separate never-raises violations were found
# in three separate adversarial review passes on this codebase, each via a different
# unguarded field). Depth-limiting the shared primitive fixes it for every caller at once,
# present and future.
MAX_CANONICALIZE_DEPTH = 32


def canonicalize(fields: dict[str, Any]) -> bytes:
    """RFC 8785 (JCS)-style deterministic serialization: sorted keys, compact
    separators, UTF-8 bytes. Signing and verification both route through this
    single implementation -- never re-derived inline (see DESIGN.md's note on
    the two-drifting-implementations anti-pattern this guards against).

    Only the JCS number-formatting cases this project's own data model can
    ever produce are handled: no floats appear in a Grant/PossessionProof
    (timestamps are floats -- see the explicit rejection below). Deliberately
    narrower than full JCS, not full RFC 8785 conformance.

    Depth-bounded (see MAX_CANONICALIZE_DEPTH): raises ValueError, not
    RecursionError, on anything nested past a small ceiling. Every caller in
    this project treats ValueError as an expected, caught failure mode --
    RecursionError was not, and every value passed here can be
    attacker-controlled.
    """
    _validate(fields, depth=0)
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _validate(value: Any, depth: int) -> None:
    if depth > MAX_CANONICALIZE_DEPTH:
        raise ValueError(f"value nested deeper than {MAX_CANONICALIZE_DEPTH} levels; refusing to canonicalize")
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite float {value!r} cannot be canonicalized (JCS has no NaN/Infinity)")
        return
    if isinstance(value, dict):
        for inner in value.values():
            _validate(inner, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for inner in value:
            _validate(inner, depth + 1)
        return
    if isinstance(value, (str, int)) or value is None:
        return
    raise ValueError(f"{type(value).__name__} cannot be canonicalized: not a JSON-representable type")


MAX_STRICT_DECODE_BYTES = 65536
MAX_STRICT_DECODE_DEPTH = 8
DOMAIN_SEPARATOR = b"\x00"
_RECORD_TYPE = re.compile(r"[a-z][a-z0-9-]*")


def strict_decode(
    data: bytes | str,
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    integer_fields: Iterable[str] = (),
    max_bytes: int = MAX_STRICT_DECODE_BYTES,
    max_depth: int = MAX_STRICT_DECODE_DEPTH,
) -> dict[str, Any]:
    """Decode a JSON object for a new record type, refusing anything ambiguous.

    Raises ValueError, with a specific message, on: input over max_bytes, invalid
    JSON, a non-object top level, duplicate keys at any depth, floats anywhere
    (including 1.0 and 1e3), NaN/Infinity, nesting past max_depth, keys outside
    required + optional, missing required keys, and any integer_fields value that
    is not an int (bool is refused).

    Applies no Unicode normalisation: strings decode byte-for-byte as sent.
    """
    required_set = frozenset(required)
    allowed = required_set | frozenset(optional)
    integers = frozenset(integer_fields)
    if len(data) > max_bytes:
        raise ValueError(f"input is {len(data)} bytes, over the {max_bytes} byte limit")
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except RecursionError:
        raise ValueError("input nested too deeply to decode") from None
    except UnicodeDecodeError as exc:
        raise ValueError(f"input is not valid UTF-8: {exc.reason}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"input is not valid JSON: {exc.msg}") from None
    if not isinstance(value, dict):
        raise ValueError(f"top level must be a JSON object, got {type(value).__name__}")
    _check_depth(value, 1, max_depth)
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown keys: {', '.join(unknown)}")
    missing = sorted(required_set - set(value))
    if missing:
        raise ValueError(f"missing required keys: {', '.join(missing)}")
    for name in sorted(integers & set(value)):
        field = value[name]
        if isinstance(field, bool) or not isinstance(field, int):
            raise ValueError(f"{name} must be an integer, got {type(field).__name__}")
    return value


def signing_input(record_type: str, version: int, body: dict[str, Any]) -> bytes:
    """Bytes to sign or verify for a new record type: the domain tag
    agent-warrant/<record_type>/v<version>, a NUL separator, then the canonical
    body. The tag is part of the signed bytes, so a signature over one record
    type never verifies as another type or version.
    """
    if not _RECORD_TYPE.fullmatch(record_type):
        raise ValueError(f"record type {record_type!r} must match {_RECORD_TYPE.pattern}")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError(f"version must be a positive integer, got {version!r}")
    _reject_floats(body)
    tag = f"agent-warrant/{record_type}/v{version}".encode()
    return tag + DOMAIN_SEPARATOR + canonicalize(body)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_float(literal: str) -> float:
    raise ValueError(f"floats are not allowed: {literal}")


def _reject_constant(literal: str) -> float:
    raise ValueError(f"{literal} is not allowed")


def _check_depth(value: Any, depth: int, limit: int) -> None:
    if isinstance(value, dict):
        children: Iterable[Any] = value.values()
    elif isinstance(value, list):
        children = value
    else:
        return
    if depth > limit:
        raise ValueError(f"nesting deeper than {limit} levels")
    for child in children:
        _check_depth(child, depth + 1, limit)


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError(f"floats are not allowed in signed records: {value!r}")
    if isinstance(value, dict):
        for inner in value.values():
            _reject_floats(inner)
    elif isinstance(value, (list, tuple)):
        for inner in value:
            _reject_floats(inner)
