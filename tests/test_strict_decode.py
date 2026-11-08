from __future__ import annotations

import json

import pytest

from agent_warrant.canonical import MAX_STRICT_DECODE_BYTES, canonicalize, signing_input, strict_decode

FIELDS = {"required": {"id", "issued_at"}, "optional": {"note"}, "integer_fields": {"issued_at"}}


def decode(data):
    return strict_decode(data, **FIELDS)


def test_accepts_well_formed_record():
    assert decode('{"id":"a","issued_at":10,"note":"x"}') == {"id": "a", "issued_at": 10, "note": "x"}


def test_accepts_bytes_and_omitted_optional():
    assert decode(b'{"id":"a","issued_at":10}') == {"id": "a", "issued_at": 10}


def test_rejects_duplicate_key():
    with pytest.raises(ValueError, match="duplicate key 'id'"):
        decode('{"id":"a","id":"b","issued_at":1}')


def test_rejects_nested_duplicate_key():
    with pytest.raises(ValueError, match="duplicate key 'k'"):
        decode('{"id":"a","issued_at":1,"note":{"k":1,"k":2}}')


def test_rejects_unknown_key():
    with pytest.raises(ValueError, match="unknown keys: extra"):
        decode('{"id":"a","issued_at":1,"extra":1}')


def test_rejects_missing_required_key():
    with pytest.raises(ValueError, match="missing required keys: issued_at"):
        decode('{"id":"a"}')


@pytest.mark.parametrize("literal", ["1.0", "1e3", "0.5", "-0.0"])
def test_rejects_float_in_integer_field(literal):
    with pytest.raises(ValueError, match="floats are not allowed"):
        decode('{"id":"a","issued_at":' + literal + "}")


def test_rejects_float_in_any_field():
    with pytest.raises(ValueError, match="floats are not allowed"):
        decode('{"id":"a","issued_at":1,"note":[1.5]}')


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_rejects_non_finite_constants(literal):
    with pytest.raises(ValueError, match="not allowed"):
        decode('{"id":"a","issued_at":1,"note":' + literal + "}")


def test_rejects_bool_where_int_expected():
    with pytest.raises(ValueError, match="issued_at must be an integer, got bool"):
        decode('{"id":"a","issued_at":true}')


def test_rejects_string_timestamp():
    with pytest.raises(ValueError, match="issued_at must be an integer, got str"):
        decode('{"id":"a","issued_at":"10"}')


def test_rejects_null_timestamp():
    with pytest.raises(ValueError, match="issued_at must be an integer, got NoneType"):
        decode('{"id":"a","issued_at":null}')


def test_rejects_deep_nesting():
    nested = '{"id":"a","issued_at":1,"note":' + "[" * 20 + "]" * 20 + "}"
    with pytest.raises(ValueError, match="nesting deeper than 8"):
        decode(nested)


def test_rejects_nesting_that_overflows_the_parser():
    nested = '{"note":' + "[" * 50000 + "]" * 50000 + "}"
    with pytest.raises(ValueError):
        strict_decode(nested, required=(), optional={"note"}, max_bytes=10**6)


def test_rejects_oversized_input():
    padding = "a" * MAX_STRICT_DECODE_BYTES
    with pytest.raises(ValueError, match="byte limit"):
        decode('{"id":"' + padding + '","issued_at":1}')


def test_rejects_non_object_top_level():
    with pytest.raises(ValueError, match="top level must be a JSON object, got list"):
        decode("[1]")


def test_rejects_invalid_json():
    with pytest.raises(ValueError, match="not valid JSON"):
        decode("{")


def test_rejects_invalid_utf8():
    with pytest.raises(ValueError, match="not valid UTF-8"):
        decode(b'{"id":"\xff","issued_at":1}')


def test_domain_tagged_bytes_differ_across_types_for_same_body():
    body = {"id": "a", "issued_at": 1}
    assert signing_input("task-root", 1, body) != signing_input("chain-link", 1, body)


def test_domain_tagged_bytes_differ_across_versions():
    body = {"id": "a"}
    assert signing_input("task-root", 1, body) != signing_input("task-root", 2, body)


def test_signing_input_layout():
    body = {"b": 1, "a": 2}
    assert signing_input("task-root", 1, body) == b"agent-warrant/task-root/v1\x00" + canonicalize(body)


def test_signing_input_never_equals_untagged_canonical_body():
    body = {"a": 1}
    assert signing_input("task-root", 1, body) != canonicalize(body)


def test_signing_input_refuses_float():
    with pytest.raises(ValueError, match="floats are not allowed"):
        signing_input("task-root", 1, {"a": [1.0]})


@pytest.mark.parametrize("record_type", ["", "Task", "task/root", "task\x00root", "1task"])
def test_signing_input_refuses_malformed_record_type(record_type):
    with pytest.raises(ValueError, match="record type"):
        signing_input(record_type, 1, {})


@pytest.mark.parametrize("version", [0, -1, True, 1.0, "1"])
def test_signing_input_refuses_malformed_version(version):
    with pytest.raises(ValueError, match="version"):
        signing_input("task-root", version, {})


def test_decode_then_signing_input_roundtrip_is_stable():
    raw = json.dumps({"issued_at": 5, "id": "a"})
    assert signing_input("task-root", 1, decode(raw)) == signing_input("task-root", 1, {"id": "a", "issued_at": 5})
