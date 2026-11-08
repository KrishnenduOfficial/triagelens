"""Verify the pytest guard rejects real transports while allowing test doubles."""

import asyncio
import socket

import httpx
import pytest


def test_real_http_transport_blocked_before_dns(monkeypatch):
    def unexpected_dns(*args, **kwargs):
        pytest.fail("Real transport reached DNS")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_dns)
    with httpx.Client(trust_env=False) as client:
        with pytest.raises(AssertionError, match="External network disabled"):
            client.get("https://example.invalid")


def test_real_async_http_transport_blocked_before_dns(monkeypatch):
    def unexpected_dns(*args, **kwargs):
        pytest.fail("Real async transport reached DNS")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_dns)

    async def request():
        async with httpx.AsyncClient(trust_env=False) as client:
            with pytest.raises(AssertionError, match="External network disabled"):
                await client.get("https://example.invalid")

    asyncio.run(request())


@pytest.mark.parametrize("operation", ["create_connection", "connect", "connect_ex"])
def test_direct_tcp_connections_are_blocked(operation):
    with pytest.raises(AssertionError, match="External network disabled"):
        if operation == "create_connection":
            socket.create_connection(("example.invalid", 443))
        else:
            with socket.socket() as sock:
                getattr(sock, operation)(("127.0.0.1", 443))


def test_mock_transport_remains_usable():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"offline": True}))
    with httpx.Client(transport=transport) as client:
        assert client.get("https://example.invalid").json() == {"offline": True}
