# Canonical byte profile

Facts about the bytes `agent_warrant.canonical` produces. Vectors: `tests/vectors/canonical.json`, checked by `tests/test_vectors.py`.

## canonicalize

- Input: a JSON-representable `dict`.
- Output: `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded as UTF-8.
- Keys are sorted by Python string order (Unicode code point), at every depth.
- No whitespace between tokens.
- Non-ASCII characters are emitted as raw UTF-8, not `\uXXXX` escapes.
- Integers are emitted in decimal with no leading zeros or plus sign. `canonicalize` does not range-check them; `strict_decode` and `signing_input` do (below).
- No Unicode normalisation is applied. `"café"` (NFC) and `"café"` (NFD) produce different bytes. Callers MUST normalise identifiers before they enter a record.
- Refused with `ValueError`: NaN, Infinity, non-JSON types, nesting deeper than `MAX_CANONICALIZE_DEPTH` (32).
- This is not full RFC 8785: finite floats are still serialised by Python, so records of new types must not contain them (see strict_decode).

## strict_decode

For new record types. v1 `Grant.decode` is unchanged.

- Size is counted in UTF-8 bytes, also for `str` input; the cap is 65536.
- Refused with `ValueError`: invalid UTF-8 or JSON, a BOM, leading or trailing whitespace, trailing data, non-object top level, duplicate keys at any depth (after unescaping, so `"\u0069d"` duplicates `"id"`), any float (`1.0`, `1e3`), NaN/Infinity, `-0`, integers outside the interoperable range, lone surrogates (U+D800 to U+DFFF) in keys or strings, nesting deeper than 8, keys outside `required + optional`, missing required keys, `integer_fields` values that are not `int` (`bool` is refused).
- Integer range: `-(2**53-1)` to `2**53-1` inclusive, for every integer in the record, so values round-trip through IEEE 754 doubles in other languages.
- `required`, `optional` and `integer_fields` must be collections of names; a `str` raises `TypeError`.
- Signatures cover only the re-canonicalized form (`signing_input`). Raw input bytes are never hashed, so any two inputs that decode to the same value share one signature.

## signing_input

`signing_input(record_type, version, body)` returns:

```
b"agent-warrant/<record_type>/v<version>" + b"\x00" + canonicalize(body)
```

- `record_type` matches `[a-z][a-z0-9-]*`; `version` is a positive `int`.
- The tag is inside the signed bytes, so a signature over one record type or version does not verify as another.
- `body` must be a `dict` with `str` keys. Values are `str`, `int`, `bool`, `None`, `list` or `dict`, recursively. Tuples, floats, bytes and non-`str` keys are refused.
- Same limits as `strict_decode`: nesting at most 8 levels, no lone surrogates, integers within `-(2**53-1)` to `2**53-1`.
