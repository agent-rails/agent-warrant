from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading

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
    doesn't -- a non-200 response, 3xx included, is surfaced as a failure, not
    silently followed, so a compromised or misconfigured host can't downgrade
    a fetch to plaintext via a Location header). Verifies TLS certificates
    with the platform default trust store and hostname checking on
    (ssl.create_default_context()).

    SSRF hardening, closed (not merely disclosed): `grant.issuer` reaches
    resolver.resolve() before any signature check, so a crafted issuer string
    could otherwise make the verifying process itself probe internal network
    addresses. This resolves the host exactly once, rejects the fetch if ANY
    resolved address is non-global (private/loopback/link-local/reserved/
    multicast/unspecified), pins the screened IP, and connects to that pinned
    IP directly -- the hostname is still used for TLS SNI and certificate
    verification and for the Host header, but is never re-resolved at connect
    time. This removes the DNS-rebinding TOCTOU that a check-then-connect
    pattern has (where a name resolves to a public address at check time and a
    private one at connect time).

    Total-time bound: a wall-clock watchdog closes the connection once
    `timeout_seconds` elapses, so a slow-drip host (one byte per just-under-
    the-per-socket-timeout interval) cannot hold the fetch open indefinitely.
    Residual, disclosed in docs/THREAT_MODEL.md: the initial name resolution
    uses the OS resolver's own timeout, not this wall-clock budget.

    Caps response size so a malicious/misbehaving host can't exhaust memory by
    streaming without bound. Raises OSError or http.client.HTTPException on any
    failure; callers translate that into their own fail-closed exception type.
    Failure messages are deliberately generic (no host/port/path or remote
    response text) so nothing attacker-controlled leaks into a caller-visible
    reason string."""
    target_port = port if port is not None else 443
    pinned_ip = _resolve_and_pin_target(host, target_port)
    context = ssl.create_default_context()
    connection = _build_pinned_connection(host, pinned_ip, target_port, timeout_seconds, context)
    watchdog = threading.Timer(timeout_seconds, _force_close, args=(connection,))
    watchdog.daemon = True
    watchdog.start()
    try:
        connection.request("GET", path, headers={"Accept": "application/json", "Host": host})
        response = connection.getresponse()
        if response.status != 200:
            raise OSError("issuer endpoint returned a non-success HTTP status")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise OSError("issuer endpoint response exceeded the size limit")
        return body
    finally:
        watchdog.cancel()
        connection.close()


def _resolve_and_pin_target(host: str, port: int) -> str:
    """Resolve the host once, reject if any resolved address is non-global,
    and return the single screened IP to connect to. Connecting to this
    returned literal (rather than the hostname) is what closes the DNS
    rebinding TOCTOU -- there is no second resolution."""
    try:
        addr_info = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as err:
        raise OSError("issuer host could not be resolved") from err
    if not addr_info:
        raise OSError("issuer host resolved to no addresses")
    pinned_ip: str | None = None
    for _family, _type, _proto, _canonname, sockaddr in addr_info:
        candidate = sockaddr[0]
        ip = ipaddress.ip_address(candidate)
        if any(getattr(ip, predicate) for predicate in _BLOCKED_ADDRESS_PREDICATES):
            raise OSError("issuer host resolves to a non-global address")
        if pinned_ip is None:
            pinned_ip = candidate
    assert pinned_ip is not None
    return pinned_ip


def _build_pinned_connection(
    host: str,
    connect_ip: str,
    port: int,
    timeout_seconds: float,
    context: ssl.SSLContext,
) -> http.client.HTTPSConnection:
    """Build an HTTPSConnection that connects to `connect_ip` directly while
    still presenting `host` for TLS SNI/certificate verification and the Host
    header. The connect override does no DNS resolution of its own."""
    connection = http.client.HTTPSConnection(host, port, timeout=timeout_seconds, context=context)

    def connect() -> None:
        raw_sock = socket.create_connection((connect_ip, port), timeout=timeout_seconds)
        connection.sock = context.wrap_socket(raw_sock, server_hostname=host)

    connection.connect = connect  # type: ignore[method-assign]
    return connection


def _force_close(connection: http.client.HTTPSConnection) -> None:
    """Watchdog callback: close the connection when the wall-clock budget is
    exhausted, unblocking any in-progress recv."""
    try:
        connection.close()
    except OSError:
        pass
