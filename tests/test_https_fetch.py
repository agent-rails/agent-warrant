from __future__ import annotations

import http.client
import socket
import time

import pytest

from agent_warrant.https_fetch import (
    _build_pinned_connection,
    _resolve_and_pin_target,
    https_get,
)


class _FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, _n: int) -> bytes:
        return self._body


class _FakeConnection:
    last_instance: _FakeConnection | None = None

    def __init__(self, host, port=None, timeout=None, context=None) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.requested_path = None
        self.closed = False
        type(self).last_instance = self

    def request(self, method, path, headers=None) -> None:
        self.requested_path = path
        self.method = method
        self.headers = headers

    def getresponse(self) -> _FakeResponse:
        raise NotImplementedError

    def close(self) -> None:
        self.closed = True


def _patch_connection(monkeypatch, response: _FakeResponse | Exception):
    class _Connection(_FakeConnection):
        def getresponse(self):
            if isinstance(response, Exception):
                raise response
            return response

    monkeypatch.setattr(http.client, "HTTPSConnection", _Connection)
    return _Connection


def _patch_resolve_public(monkeypatch):
    import socket

    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, None, None, "", ("93.184.216.34", 443))]
    )


def test_https_get_happy_path(monkeypatch):
    _patch_resolve_public(monkeypatch)
    connection_cls = _patch_connection(monkeypatch, _FakeResponse(200, b'{"ok": true}'))
    body = https_get("example.com", "/thing.json", max_bytes=1024)
    assert body == b'{"ok": true}'
    assert connection_cls.last_instance.closed is True
    assert connection_cls.last_instance.requested_path == "/thing.json"


@pytest.mark.parametrize("status", [201, 204, 301, 302, 307, 308, 400, 404, 500])
def test_https_get_rejects_any_non_200_status(monkeypatch, status):
    # Only 200 is accepted; every other status (including 2xx and every
    # redirect) is a fail-closed error. http.client never auto-follows a 3xx,
    # so a Location header cannot redirect the fetch or downgrade it.
    _patch_resolve_public(monkeypatch)
    _patch_connection(monkeypatch, _FakeResponse(status, b""))
    with pytest.raises(OSError, match="non-success"):
        https_get("example.com", "/thing.json", max_bytes=1024)


def test_https_get_rejects_oversized_response(monkeypatch):
    _patch_resolve_public(monkeypatch)
    _patch_connection(monkeypatch, _FakeResponse(200, b"x" * 100))
    with pytest.raises(OSError, match="exceeded"):
        https_get("example.com", "/thing.json", max_bytes=10)


def test_https_get_translates_connection_failure(monkeypatch):
    _patch_resolve_public(monkeypatch)

    class _Connection(_FakeConnection):
        def request(self, method, path, headers=None) -> None:
            raise OSError("connection refused")

    monkeypatch.setattr(http.client, "HTTPSConnection", _Connection)
    with pytest.raises(OSError, match="connection refused"):
        https_get("example.com", "/thing.json", max_bytes=1024)


def test_https_get_translates_http_exception(monkeypatch):
    _patch_resolve_public(monkeypatch)

    class _Connection(_FakeConnection):
        def request(self, method, path, headers=None) -> None:
            raise http.client.HTTPException("bad chunked encoding")

    monkeypatch.setattr(http.client, "HTTPSConnection", _Connection)
    with pytest.raises(http.client.HTTPException):
        https_get("example.com", "/thing.json", max_bytes=1024)


@pytest.mark.parametrize(
    "resolved_ip",
    ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "192.168.1.1"],
)
def test_https_get_refuses_private_or_reserved_targets(monkeypatch, resolved_ip):
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, None, None, "", (resolved_ip, 443))])
    connection_created = False

    class _Connection(_FakeConnection):
        def __init__(self, *a, **k):
            nonlocal connection_created
            connection_created = True
            super().__init__(*a, **k)

    monkeypatch.setattr(http.client, "HTTPSConnection", _Connection)
    with pytest.raises(OSError, match="non-global"):
        https_get("internal.example", "/thing.json", max_bytes=1024)
    assert connection_created is False


def test_https_get_translates_dns_failure(monkeypatch):
    import socket

    def _boom(*a, **k):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    with pytest.raises(OSError, match="could not be resolved"):
        https_get("does-not-exist.invalid", "/thing.json", max_bytes=1024)


# --- SSRF: pin the screened IP, connect to it directly (no re-resolution) ---


def test_resolve_and_pin_returns_first_screened_global_ip(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, None, None, "", ("93.184.216.34", 443))]
    )
    assert _resolve_and_pin_target("example.com", 443) == "93.184.216.34"


def test_resolve_and_pin_rejects_when_any_resolved_address_is_private(monkeypatch):
    # A rebinding-style host that resolves to one public and one private
    # address must be rejected outright -- not partially accepted.
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, None, None, "", ("93.184.216.34", 443)),
            (socket.AF_INET, None, None, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(OSError, match="non-global"):
        _resolve_and_pin_target("rebind.example", 443)


def test_pinned_connection_dials_screened_ip_with_hostname_sni(monkeypatch):
    # The TOCTOU fix: the connection dials the SCREENED IP literal, never
    # re-resolving the hostname, while still presenting the hostname for TLS
    # SNI / certificate verification.
    captured = {}

    class _FakeContext:
        def wrap_socket(self, sock, server_hostname=None):
            captured["server_hostname"] = server_hostname
            captured["wrapped"] = sock
            return sock

    def _fake_create_connection(address, timeout=None):
        captured["dialed"] = address
        return "raw-socket"

    monkeypatch.setattr(socket, "create_connection", _fake_create_connection)
    connection = _build_pinned_connection("example.com", "93.184.216.34", 443, 5.0, _FakeContext())
    connection.connect()

    assert captured["dialed"] == ("93.184.216.34", 443)
    assert captured["server_hostname"] == "example.com"
    assert connection.sock == "raw-socket"


# --- total wall-clock deadline (slow-drip cannot hold the fetch open) ---


def test_https_get_enforces_total_deadline_via_watchdog(monkeypatch):
    _patch_resolve_public(monkeypatch)

    class _SlowConnection(_FakeConnection):
        def getresponse(self):
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if self.closed:
                    raise OSError("connection closed by deadline watchdog")
                time.sleep(0.005)
            raise AssertionError("watchdog never fired to bound the total request time")

    monkeypatch.setattr(http.client, "HTTPSConnection", _SlowConnection)
    started = time.monotonic()
    with pytest.raises(OSError, match="watchdog"):
        https_get("example.com", "/thing.json", timeout_seconds=0.1, max_bytes=1024)
    assert time.monotonic() - started < 2.0


# --- generic failure messages (no host/path/status/remote text leak) ---


def test_https_get_failure_messages_do_not_leak_target(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, None, None, "", ("10.0.0.5", 443))])
    with pytest.raises(OSError) as exc_info:
        https_get("secret-internal-host.corp", "/admin/secret", max_bytes=1024)
    message = str(exc_info.value)
    assert "secret-internal-host" not in message
    assert "/admin/secret" not in message
    assert "10.0.0.5" not in message
