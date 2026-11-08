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


MAX_SAFE = 2**53 - 1


@pytest.mark.parametrize("escape", ["\\ud800", "\\udfff", "\\udc00", "\\ud83dx"])
def test_rejects_lone_surrogate_in_value(escape):
    with pytest.raises(ValueError, match="surrogate"):
        decode('{"id":"' + escape + '","issued_at":1}')


def test_rejects_lone_surrogate_in_key():
    with pytest.raises(ValueError, match="surrogate"):
        strict_decode('{"\\ud800":1}', required=(), optional={"\ud800"})


def test_rejects_lone_surrogate_in_nested_value():
    with pytest.raises(ValueError, match="surrogate"):
        decode('{"id":"a","issued_at":1,"note":[{"k":"\\ud83d"}]}')


def test_accepts_valid_surrogate_pair_escape():
    assert decode('{"id":"\\ud83d\\ude00","issued_at":1}')["id"] == "\U0001f600"


def test_rejects_lone_surrogate_in_str_input():
    with pytest.raises(ValueError, match="surrogate"):
        decode('{"id":"\ud800","issued_at":1}')


def test_byte_cap_counts_utf8_bytes_for_str():
    text = '{"id":"' + "中" * 30000 + '","issued_at":1}'
    assert len(text) < MAX_STRICT_DECODE_BYTES
    with pytest.raises(ValueError, match="byte limit"):
        decode(text)


def test_byte_cap_counts_utf8_bytes_for_bytes():
    raw = ('{"id":"' + "中" * 30000 + '","issued_at":1}').encode()
    with pytest.raises(ValueError, match="byte limit"):
        decode(raw)


@pytest.mark.parametrize("value", [MAX_SAFE, -MAX_SAFE, 0])
def test_accepts_integers_in_interoperable_range(value):
    assert decode('{"id":"a","issued_at":' + str(value) + "}")["issued_at"] == value


@pytest.mark.parametrize("value", [MAX_SAFE + 1, -MAX_SAFE - 1, 10**30])
def test_rejects_integer_outside_interoperable_range(value):
    with pytest.raises(ValueError, match="outside"):
        decode('{"id":"a","issued_at":' + str(value) + "}")


def test_rejects_out_of_range_integer_in_non_integer_field():
    with pytest.raises(ValueError, match="outside"):
        decode('{"id":"a","issued_at":1,"note":[9007199254740992]}')


def test_rejects_negative_zero():
    with pytest.raises(ValueError, match="-0"):
        decode('{"id":"a","issued_at":-0}')


@pytest.mark.parametrize(
    "raw", [' {"id":"a","issued_at":1}', '{"id":"a","issued_at":1}\n', '{"id":"a","issued_at":1} ']
)
def test_rejects_surrounding_whitespace(raw):
    with pytest.raises(ValueError, match="whitespace"):
        decode(raw)


def test_rejects_trailing_data():
    with pytest.raises(ValueError, match="not valid JSON"):
        decode('{"id":"a","issued_at":1}x')


def test_rejects_bom():
    with pytest.raises(ValueError, match="not valid JSON"):
        decode(b'\xef\xbb\xbf{"id":"a","issued_at":1}')


def test_rejects_escaped_duplicate_key():
    with pytest.raises(ValueError, match="duplicate key 'id'"):
        decode('{"id":"a","\\u0069d":"b","issued_at":1}')


@pytest.mark.parametrize("name", ["required", "optional", "integer_fields"])
def test_rejects_str_for_field_set(name):
    kwargs = {"required": (), "optional": (), "integer_fields": ()}
    kwargs[name] = "id"
    with pytest.raises(TypeError, match=name):
        strict_decode("{}", **kwargs)


def test_signing_input_refuses_lone_surrogate_value():
    with pytest.raises(ValueError, match="surrogate"):
        signing_input("task-root", 1, {"a": "\ud800"})


def test_signing_input_refuses_lone_surrogate_key():
    with pytest.raises(ValueError, match="surrogate"):
        signing_input("task-root", 1, {"\ud800": "a"})


def test_signing_input_refuses_non_str_key():
    with pytest.raises(ValueError, match="keys must be str, got int"):
        signing_input("task-root", 1, {1: "x"})


def test_signing_input_refuses_tuple_value():
    with pytest.raises(ValueError, match="tuple is not an allowed value type"):
        signing_input("task-root", 1, {"a": (1, 2)})


@pytest.mark.parametrize("body", [[], [("a", 1)], "text", None, 5])
def test_signing_input_refuses_non_dict_body(body):
    with pytest.raises(ValueError, match="body must be a dict"):
        signing_input("task-root", 1, body)


def test_signing_input_refuses_non_json_value():
    with pytest.raises(ValueError, match="bytes is not an allowed value type"):
        signing_input("task-root", 1, {"a": b"x"})


def nested(levels):
    body = {}
    cursor = body
    for _ in range(levels - 1):
        cursor["k"] = {}
        cursor = cursor["k"]
    return body


def test_signing_input_accepts_depth_at_limit():
    signing_input("task-root", 1, nested(8))


def test_signing_input_refuses_depth_over_limit():
    with pytest.raises(ValueError, match="nesting deeper than 8"):
        signing_input("task-root", 1, nested(9))


@pytest.mark.parametrize("value", [MAX_SAFE + 1, -MAX_SAFE - 1])
def test_signing_input_refuses_out_of_range_integer(value):
    with pytest.raises(ValueError, match="outside"):
        signing_input("task-root", 1, {"a": [value]})


@pytest.mark.parametrize("value", [MAX_SAFE, -MAX_SAFE])
def test_signing_input_accepts_boundary_integers(value):
    signing_input("task-root", 1, {"a": value})


def test_signing_input_accepts_bool_none_list_dict_values():
    signing_input("task-root", 1, {"a": True, "b": None, "c": [1, "x", {"d": False}]})
