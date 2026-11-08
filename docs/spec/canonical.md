# Canonical byte profile

Facts about the bytes `agent_warrant.canonical` produces. Vectors: `tests/vectors/canonical.json`, checked by `tests/test_vectors.py`.

## canonicalize

- Input: a JSON-representable `dict`.
- Output: `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded as UTF-8.
- Keys are sorted by Python string order (Unicode code point), at every depth.
- No whitespace between tokens.
- Non-ASCII characters are emitted as raw UTF-8, not `\uXXXX` escapes.
- Integers are emitted in decimal with no leading zeros or plus sign.
- No Unicode normalisation is applied. `"café"` (NFC) and `"café"` (NFD) produce different bytes. Callers MUST normalise identifiers before they enter a record.
- Refused with `ValueError`: NaN, Infinity, non-JSON types, nesting deeper than `MAX_CANONICALIZE_DEPTH` (32).
- This is not full RFC 8785: finite floats are still serialised by Python, so records of new types must not contain them (see strict_decode).

## strict_decode

For new record types. v1 `Grant.decode` is unchanged.

- Refused with `ValueError`: input over 65536 bytes, invalid UTF-8 or JSON, non-object top level, duplicate keys at any depth, any float (`1.0`, `1e3`), NaN/Infinity, nesting deeper than 8, keys outside `required + optional`, missing required keys, `integer_fields` values that are not `int` (`bool` is refused).

## signing_input

`signing_input(record_type, version, body)` returns:

```
b"agent-warrant/<record_type>/v<version>" + b"\x00" + canonicalize(body)
```

- `record_type` matches `[a-z][a-z0-9-]*`; `version` is a positive `int`.
- The tag is inside the signed bytes, so a signature over one record type or version does not verify as another.
- `body` containing a float is refused.
