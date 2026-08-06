from __future__ import annotations

import json
import math
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
