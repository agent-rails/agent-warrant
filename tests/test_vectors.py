from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agent_warrant.canonical import canonicalize, signing_input, strict_decode

VECTORS = json.loads((Path(__file__).parent / "vectors" / "canonical.json").read_text(encoding="utf-8"))


def by_name(entries, name):
    return next(entry for entry in entries if entry["name"] == name)


@pytest.mark.parametrize("vector", VECTORS["canonical"], ids=lambda v: v["name"])
def test_canonical_bytes_match_vector(vector):
    produced = canonicalize(vector["input"])
    assert produced.hex() == vector["canonical_hex"]
    assert hashlib.sha256(produced).hexdigest() == vector["sha256"]


@pytest.mark.parametrize("vector", VECTORS["signing_input"], ids=lambda v: v["name"])
def test_signing_input_matches_vector(vector):
    produced = signing_input(vector["record_type"], vector["version"], vector["body"])
    assert produced.hex() == vector["signing_input_hex"]
    assert hashlib.sha256(produced).hexdigest() == vector["sha256"]


def test_signing_input_vectors_differ_across_type_and_version():
    hexes = {vector["signing_input_hex"] for vector in VECTORS["signing_input"]}
    assert len(hexes) == len(VECTORS["signing_input"])


@pytest.mark.parametrize("vector", VECTORS["strict_rejections"], ids=lambda v: v["name"])
def test_strict_decoder_refuses_vector(vector):
    with pytest.raises(ValueError, match=vector["error"]):
        strict_decode(vector["raw"], required={"id", "issued_at"}, integer_fields={"issued_at"})


def test_nfc_and_nfd_strings_produce_different_bytes():
    nfc = by_name(VECTORS["canonical"], "nfc-composed")
    nfd = by_name(VECTORS["canonical"], "nfd-decomposed")
    assert nfc["input"]["id"] != nfd["input"]["id"]
    assert canonicalize(nfc["input"]) != canonicalize(nfd["input"])
    assert nfc["sha256"] != nfd["sha256"]


def test_float_one_is_refused_where_integer_one_is_accepted():
    accepted = strict_decode('{"id":"a","issued_at":1}', required={"id", "issued_at"}, integer_fields={"issued_at"})
    assert accepted["issued_at"] == 1
    with pytest.raises(ValueError, match="floats are not allowed"):
        strict_decode('{"id":"a","issued_at":1.0}', required={"id", "issued_at"}, integer_fields={"issued_at"})


def test_duplicate_keys_are_refused():
    with pytest.raises(ValueError, match="duplicate key"):
        strict_decode('{"id":"a","id":"a","issued_at":1}', required={"id", "issued_at"})
