from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl

DEFAULT_HTTPS_TIMEOUT_SECONDS = 5.0

_BLOCKED_ADDRESS_PREDICATES = (
    "is_private",
    "is_loopback",
    "is_link_local",
    "is_reserved",
    "is_multicast",
    "is_unspecified",
)


def https_get(
    host: str,
    path: str,
    *,
    port: int | None = None,
    timeout_seconds: float = DEFAULT_HTTPS_TIMEOUT_SECONDS,
    max_bytes: int,
) -> bytes:
    """Raw HTTPS GET, shared by every resolver/checker in this package that
    fetches attacker-influenced, pre-authentication content (DidWebResolver,
    HttpRevocationListFetcher). Hardcodes the scheme to HTTPS -- no caller
    can make this speak plaintext HTTP. Never follows redirects (http.client
    doesn't -- a 3xx response is surfaced as a failure, not silently
    followed, so a compromised or misconfigured host can't downgrade a
    fetch to plaintext via a Location header). Verifies TLS certificates
    with the platform default trust store and hostname checking on
    (ssl.create_default_context() -- both are already the http.client
    default, set explicitly here so a future refactor can't accidentally
    disable them). Caps response size so a malicious/misbehaving host can't
    exhaust memory by streaming without bound. Resolves the target and
    rejects private/loopback/link-local/reserved/multicast/unspecified
    addresses before connecting -- `grant.issuer` reaches resolver.resolve()
    before any signature check, so a crafted issuer string could otherwise
    make the verifying process itself probe internal network addresses
    (SSRF) using nothing but an unsigned, unauthenticated grant. Residual,
    disclosed in docs/THREAT_MODEL.md: this check-then-connect has a DNS
    rebinding TOCTOU gap -- a name that resolves to a public address at
    check time and a private one at connect time would slip through.
    Raises OSError or http.client.HTTPException on any failure; callers
    translate that into their own fail-closed exception type."""
    target_port = port if port is not None else 443
    _reject_private_targets(host, target_port)
    connection = http.client.HTTPSConnection(
        host, target_port, timeout=timeout_seconds, context=ssl.create_default_context()
    )
    try:
        connection.request("GET", path, headers={"Accept": "application/json", "Host": host})
        response = connection.getresponse()
        if response.status != 200:
            raise OSError(f"HTTPS GET https://{host}{path} returned status {response.status}")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise OSError(f"HTTPS GET https://{host}{path} exceeded {max_bytes} byte limit")
        return body
    finally:
        connection.close()


def _reject_private_targets(host: str, port: int) -> None:
    try:
        addr_info = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as err:
        raise OSError(f"DNS resolution failed for {host!r}: {err}") from err
    if not addr_info:
        raise OSError(f"DNS resolution for {host!r} returned no addresses")
    for _family, _type, _proto, _canonname, sockaddr in addr_info:
        ip = ipaddress.ip_address(sockaddr[0])
        if any(getattr(ip, predicate) for predicate in _BLOCKED_ADDRESS_PREDICATES):
            raise OSError(f"refusing to fetch {host!r}: resolves to a private/reserved address {ip}")
