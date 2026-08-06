from __future__ import annotations

import base64

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
