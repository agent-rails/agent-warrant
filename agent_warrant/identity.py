from __future__ import annotations

import base64
import binascii
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair() -> Ed25519PrivateKey:
    """One place this project generates keys, so a future change (e.g. a
    hardware-backed key source) has a single call site to change."""
    return Ed25519PrivateKey.generate()


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    return base64.urlsafe_b64encode(public_key.public_bytes_raw()).rstrip(b"=").decode()


def decode_public_key(encoded: str) -> Ed25519PublicKey:
    padded = encoded + "=" * (-len(encoded) % 4)
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(padded))


_FIELD_PRIME = 2**255 - 19
_CURVE_D = -121665 * pow(121666, -1, _FIELD_PRIME) % _FIELD_PRIME
_SQRT_MINUS_ONE = pow(2, (_FIELD_PRIME - 1) // 4, _FIELD_PRIME)


def _decompress(raw: bytes) -> tuple[int, int] | None:
    value = int.from_bytes(raw, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _FIELD_PRIME:
        return None
    x_squared = (y * y - 1) * pow(_CURVE_D * y * y + 1, -1, _FIELD_PRIME) % _FIELD_PRIME
    x = pow(x_squared, (_FIELD_PRIME + 3) // 8, _FIELD_PRIME)
    if (x * x - x_squared) % _FIELD_PRIME:
        x = x * _SQRT_MINUS_ONE % _FIELD_PRIME
    if (x * x - x_squared) % _FIELD_PRIME:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _FIELD_PRIME - x
    return x, y


def _double(point: tuple[int, int]) -> tuple[int, int]:
    x, y = point
    cross = _CURVE_D * x * x % _FIELD_PRIME * y % _FIELD_PRIME * y % _FIELD_PRIME
    new_x = 2 * x * y * pow(1 + cross, -1, _FIELD_PRIME) % _FIELD_PRIME
    new_y = (y * y + x * x) * pow(1 - cross, -1, _FIELD_PRIME) % _FIELD_PRIME
    return new_x, new_y


MAX_ENCODED_KEY_CHARACTERS = 64
KEY_CACHE_SIZE = 4096


def is_valid_public_key(encoded: object) -> bool:
    """True only for the unique unpadded base64url form of a 32-byte Ed25519 public
    key that is safe to bind a holder to: y below the field prime, a point on the
    curve, no sign bit on x = 0, and not one of the 8 small-order points (for which
    a signature can be forged without the private key). Keys with a torsion
    component but a large-order part are not detected. The result is a pure function
    of the string and is memoized (bounded); inputs longer than a valid key are
    refused before they reach the cache."""
    if not isinstance(encoded, str) or len(encoded) > MAX_ENCODED_KEY_CHARACTERS:
        return False
    return _validate_encoded_key(encoded)


@lru_cache(maxsize=KEY_CACHE_SIZE)
def _validate_encoded_key(encoded: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, binascii.Error):
        return False
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != encoded:
        return False
    point = _decompress(raw)
    if point is None:
        return False
    for _ in range(3):
        point = _double(point)
    return point != (0, 1)
