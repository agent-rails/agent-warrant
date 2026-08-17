from __future__ import annotations

import http.client

import pytest

from agent_warrant.https_fetch import https_get


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


def test_https_get_rejects_non_200_status(monkeypatch):
    _patch_resolve_public(monkeypatch)
    _patch_connection(monkeypatch, _FakeResponse(302, b""))
    with pytest.raises(OSError, match="status 302"):
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
    with pytest.raises(OSError, match="private/reserved"):
        https_get("internal.example", "/thing.json", max_bytes=1024)
    assert connection_created is False


def test_https_get_translates_dns_failure(monkeypatch):
    import socket

    def _boom(*a, **k):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    with pytest.raises(OSError, match="DNS resolution failed"):
        https_get("does-not-exist.invalid", "/thing.json", max_bytes=1024)
