# Changelog

Notable changes. This project follows [Semantic Versioning](https://semver.org). While on `0.x`, minor versions may include breaking changes.

## [Unreleased]

Initial implementation: `Grant`, `PossessionProof`, `sign()`/`prove()`/`verify()`, `Issuer`/`Verifier`/`HolderKeypair`, `IssuerResolver`/`PinnedResolver`, JCS-style canonicalization. Went through two pre-code adversarial review cycles before any code was written -- see docs/DESIGN.md for the design history, including two real corrections (holder-binding was initially a no-op, and a canonicalization-drift bug was reintroduced inside the fix for that gap and caught in the second pass).

Added `DidWebResolver`: real trust bootstrap via HTTPS + domain ownership, implementing the did:web method spec directly (Multikey/`publicKeyMultibase`, `JsonWebKey2020`/`publicKeyJwk`, and legacy `publicKeyBase58` Ed25519 key extraction). Fails closed on every malformed-input/network/document class of failure. Shares a new `https_fetch.py` module with the revocation checker below, which rejects resolution to private/loopback/link-local/reserved/multicast addresses before connecting (SSRF hardening for a pre-authentication network surface -- see docs/THREAT_MODEL.md).

Added opt-in revocation checking: `RevocationChecker` protocol, `RevocationList` (issuer-signed set of revoked `grant_binding` values -- reuses the existing Ed25519 trust chain, no new keys or shared secrets), `StaticRevocationChecker` and `HttpRevocationChecker`/`HttpRevocationListFetcher`. Wired into `verify()`/`Verifier.check()` as a new optional `revocation_checker` parameter, checked last, fail-closed on an unreachable/unverifiable revocation source. Default behavior (no `revocation_checker` supplied) is unchanged from before this existed. Deliberately not StatusList2021-shaped -- see docs/DESIGN.md for why that spec's public-anonymous-scale bitstring design doesn't fit this project's known, bounded cross-org verifier population.

## Stability

- Public API is everything exported from `agent_warrant`'s top-level `__all__`.
- On `0.x`: breaking changes may land in minor releases. Pin to `~=0.1.0` if you need stability.
- Ships PEP 561 type information (`py.typed`).
