from __future__ import annotations

import base64

import pytest

from agent_warrant.identity import encode_public_key, generate_keypair, is_valid_public_key

P = 2**255 - 19


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def le(value: int, sign: int = 0) -> bytes:
    return (value | (sign << 255)).to_bytes(32, "little")


SMALL_ORDER = {
    "identity": le(1),
    "order-2": le(P - 1),
    "order-4-sign-0": le(0),
    "order-4-sign-1": le(0, 1),
    "order-8-a": bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    "order-8-a-sign-flipped": bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    "order-8-b": bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    "order-8-b-sign-flipped": bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
}


def test_generated_keys_are_valid():
    for _ in range(20):
        assert is_valid_public_key(encode_public_key(generate_keypair().public_key())) is True


@pytest.mark.parametrize("name", sorted(SMALL_ORDER))
def test_small_order_points_are_refused(name):
    assert is_valid_public_key(b64u(SMALL_ORDER[name])) is False


@pytest.mark.parametrize("offset", [0, 1, 2, 18])
def test_y_at_or_above_field_prime_is_refused(offset):
    assert is_valid_public_key(b64u(le(P + offset))) is False


def test_non_canonical_alias_of_identity_is_refused():
    assert is_valid_public_key(b64u(le(P + 1))) is False


def test_x_zero_with_sign_bit_is_refused():
    assert is_valid_public_key(b64u(le(1, 1))) is False


def test_point_not_on_curve_is_refused():
    off_curve = next(le(y) for y in range(2, 200) if not is_valid_public_key(b64u(le(y))))
    assert is_valid_public_key(b64u(off_curve)) is False


@pytest.mark.parametrize("encoded", ["", "AA", "not base64!", None, 5, b"x", "A" * 44])
def test_malformed_encodings_are_refused(encoded):
    assert is_valid_public_key(encoded) is False


def test_padding_and_whitespace_variants_are_refused():
    valid = encode_public_key(generate_keypair().public_key())
    assert is_valid_public_key(valid) is True
    assert is_valid_public_key(valid + "=") is False
    assert is_valid_public_key(valid + "\n") is False
    assert is_valid_public_key(" " + valid) is False


def test_wrong_length_is_refused():
    assert is_valid_public_key(b64u(bytes(31))) is False
    assert is_valid_public_key(b64u(bytes(33))) is False


def test_non_zero_trailing_bits_are_refused():
    valid = encode_public_key(generate_keypair().public_key())
    last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".index(valid[-1])
    alias = valid[:-1] + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last ^ 1]
    assert is_valid_public_key(alias) is False


def test_validation_is_cached_per_encoded_key():
    from agent_warrant import identity

    identity._validate_encoded_key.cache_clear()
    key = encode_public_key(generate_keypair().public_key())
    assert is_valid_public_key(key) is True
    after_first = identity._validate_encoded_key.cache_info()
    assert (after_first.hits, after_first.misses) == (0, 1)
    assert is_valid_public_key(key) is True
    assert is_valid_public_key(key) is True
    after_repeat = identity._validate_encoded_key.cache_info()
    assert (after_repeat.hits, after_repeat.misses) == (2, 1)


def test_cached_results_do_not_leak_between_keys():
    from agent_warrant import identity

    identity._validate_encoded_key.cache_clear()
    good = encode_public_key(generate_keypair().public_key())
    weak = b64u(SMALL_ORDER["identity"])
    for _ in range(3):
        assert is_valid_public_key(good) is True
        assert is_valid_public_key(weak) is False


def test_cache_is_bounded():
    from agent_warrant import identity

    assert identity._validate_encoded_key.cache_info().maxsize == 4096


def test_oversized_input_is_refused_without_being_cached():
    from agent_warrant import identity

    identity._validate_encoded_key.cache_clear()
    assert is_valid_public_key("A" * 10_000_000) is False
    assert identity._validate_encoded_key.cache_info().currsize == 0


def test_non_string_input_is_not_cached():
    from agent_warrant import identity

    identity._validate_encoded_key.cache_clear()
    assert is_valid_public_key(None) is False
    assert is_valid_public_key(b"x") is False
    assert identity._validate_encoded_key.cache_info().currsize == 0


def test_a_str_subclass_is_not_accepted_as_a_key():
    class Sneaky(str):
        pass

    key = encode_public_key(generate_keypair().public_key())
    assert is_valid_public_key(key) is True
    assert is_valid_public_key(Sneaky(key)) is False
