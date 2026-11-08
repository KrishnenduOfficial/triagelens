"""Keep ordinary pytest runs offline, even when local API keys are configured."""

import socket
import sys

import httpx
import pytest


@pytest.fixture(autouse=True)
def block_external_network(monkeypatch):
    """Reject real HTTP transports and TCP connections before contacting services.

    ASGI/MockTransport and injected senders remain usable. Windows asyncio uses
    socketpair's internal loopback connection to wake its event loop; preserve that
    specific standard-library operation, rather than allowing general localhost I/O.
    """
    original_connect = socket.socket.connect
    fallback_socketpair = getattr(socket, "_fallback_socketpair", None)

    def deny(*args, **kwargs):
        raise AssertionError("External network disabled during pytest; inject a test sender or provider.")

    async def deny_async(*args, **kwargs):
        deny()

    def connect(sock, address):
        if fallback_socketpair is not None and sys._getframe(1).f_code is fallback_socketpair.__code__:
            return original_connect(sock, address)
        deny()

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", deny)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", deny_async)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
