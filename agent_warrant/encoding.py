from __future__ import annotations

import base64
import binascii
import hashlib


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(data: str) -> bytes:
    """Decode unpadded base64url, refusing padding, whitespace, foreign characters and
    non-zero trailing bits: exactly one string decodes to any given bytes."""
    try:
        decoded = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (ValueError, binascii.Error):
        raise ValueError("not canonical unpadded base64url") from None
    if b64u(decoded) != data:
        raise ValueError("not canonical unpadded base64url")
    return decoded


def sha256_b64u(data: bytes) -> str:
    return b64u(hashlib.sha256(data).digest())


def pack(body: bytes, signature: bytes) -> str:
    return f"{b64u(body)}.{b64u(signature)}"


def unpack(encoded: str, max_characters: int) -> tuple[bytes, str]:
    """Split `base64url(body).base64url(signature)` into (body bytes, signature string).
    Raises ValueError on a non-str, oversized, mis-separated or non-canonical input."""
    if not isinstance(encoded, str):
        raise ValueError(f"expected str, got {type(encoded).__name__}")
    if len(encoded) > max_characters:
        raise ValueError(f"encoded length exceeds {max_characters}")
    body_b64, separator, proof = encoded.partition(".")
    if not separator or not proof or "." in proof:
        raise ValueError("expected exactly one '.' separator")
    body = b64u_decode(body_b64)
    b64u_decode(proof)
    return body, proof
