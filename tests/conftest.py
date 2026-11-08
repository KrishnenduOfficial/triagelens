"""Keep ordinary pytest runs offline, even when local API keys are configured."""

import socket
import sys

import httpx
import pytest

from src.engine import llm


class PipelineTestEngine(llm.TriageEngineBase):
    """Test-only neutral transport for shared pipeline invariants.

    This deliberately synthetic envelope tests the base independently of any API.
    Groq's actual wire format and strict parsing are covered in test_groq.py.
    It never supplies a default sender; all callers inject or patch HTTPX offline.
    """

    DEFAULT_MODEL = "test-primary"
    DEFAULT_FALLBACK_MODELS = ["test-fallback-a", "test-fallback-b"]
    ENV_KEY = "TEST_LLM_API_KEY"
    ENV_MODEL = "TEST_LLM_MODEL"
    ENV_FALLBACKS = "TEST_LLM_FALLBACK_MODELS"
    PROVIDER_ID = "offline-test-transport"
    PROVIDER_LABEL = "Test LLM"

    def _generation_settings(self, candidate):
        return {"temperature": 0.1}

    def _prepare_request(self, candidate, user_prompt, generation):
        return (f"https://offline.invalid/{candidate}:triage",
                {"Authorization": f"Bearer {self.api_key}"},
                {"inputs": [{"role": "user", "segments": [{"text": user_prompt}]}],
                 "system": {"segments": [{"text": llm.DFIR_SYSTEM_PROMPT}]},
                 "generation": generation})

    def _response_text(self, response, candidate):
        if isinstance(response, str):
            return response
        outputs = response.get("outputs", [])
        if outputs:
            segments = outputs[0].get("message", {}).get("segments", [])
            if segments and segments[0].get("text"):
                return segments[0]["text"]
        return response.get("text", "")


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
