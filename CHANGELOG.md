# Changelog

Notable changes. This project follows [Semantic Versioning](https://semver.org). While on `0.x`, minor versions may include breaking changes.

## [Unreleased]

Initial implementation: `Grant`, `PossessionProof`, `sign()`/`prove()`/`verify()`, `Issuer`/`Verifier`/`HolderKeypair`, `IssuerResolver`/`PinnedResolver`, JCS-style canonicalization. Went through two pre-code adversarial review cycles before any code was written -- see docs/DESIGN.md for the design history, including two real corrections (holder-binding was initially a no-op, and a canonicalization-drift bug was reintroduced inside the fix for that gap and caught in the second pass).

## Stability

- Public API is everything exported from `agent_warrant`'s top-level `__all__`.
- On `0.x`: breaking changes may land in minor releases. Pin to `~=0.1.0` if you need stability.
- Ships PEP 561 type information (`py.typed`).
