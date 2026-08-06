from __future__ import annotations

import json
import math
from typing import Any


def canonicalize(fields: dict[str, Any]) -> bytes:
    """RFC 8785 (JCS)-style deterministic serialization: sorted keys, compact
    separators, UTF-8 bytes. Signing and verification both route through this
    single implementation -- never re-derived inline (see DESIGN.md's note on
    the two-drifting-implementations anti-pattern this guards against).

    Only the JCS number-formatting cases this project's own data model can
    ever produce are handled: no floats appear in a Grant/PossessionProof
    (timestamps are floats -- see the explicit rejection below). Deliberately
    narrower than full JCS, not full RFC 8785 conformance.
    """
    _reject_non_finite(fields)
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _reject_non_finite(value: Any) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite float {value!r} cannot be canonicalized (JCS has no NaN/Infinity)")
        return
    if isinstance(value, dict):
        for inner in value.values():
            _reject_non_finite(inner)
        return
    if isinstance(value, (list, tuple)):
        for inner in value:
            _reject_non_finite(inner)
        return
