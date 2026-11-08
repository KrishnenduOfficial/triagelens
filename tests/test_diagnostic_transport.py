"""Provider-neutral trace protections exercised through the real Groq diagnostic."""
import json
import logging
import httpx
import pytest
from scripts.diagnose_groq import diagnose_groq
from scripts.diagnose_groq import main
from test_groq import completion

MODEL = 'openai/gpt-oss-120b'
SECRET = 'canary-private-key'

def response():
    return httpx.Response(200, json=completion())


@pytest.mark.parametrize("timeout", ["0", "-1", "nan", "inf"])
def test_invalid_timeout_rejected_before_network(timeout):
    with pytest.raises(SystemExit) as failure:
        main(["--timeout", timeout])
    assert failure.value.code == 2

@pytest.mark.parametrize('phase,event', [
    ('connect', 'connection.connect_tcp'), ('tls', 'connection.start_tls'),
    ('tls', 'proxy.start_tls'),
    ('response_headers', 'http11.receive_response_headers'), ('response_body', 'http11.receive_response_body'),
])
def test_trace_distinguishes_timeout_phase_without_reflecting_info(phase, event, caplog):
    ticks = iter([10, 10.1, 10.4, 10.5])
    def send(url, **kwargs):
        callback = kwargs['extensions']['trace']
        callback(event + '.started', {'request': SECRET, 'host': SECRET})
        callback(event + '.failed', {'exception': httpx.ReadTimeout(SECRET)})
        raise httpx.ReadTimeout(SECRET)
    result = diagnose_groq(SECRET, MODEL, 30, trace=True, request_sender=send, clock=lambda: next(ticks))
    assert result['failure_category'] == 'read_timeout'
    assert result['transport_trace']['failure_phase'] == phase
    assert result['transport_trace']['events'][-1] == {'phase': phase, 'state': 'failed', 'elapsed_ms': 400.0, 'duration_ms': 300.0}
    assert result['elapsed_ms'] == 500.0
    assert result['request_count'] == 1
    assert SECRET not in json.dumps(result) + caplog.text


def test_trace_unknown_events_are_dropped_and_event_list_is_bounded():
    def send(url, **kwargs):
        callback = kwargs['extensions']['trace']
        callback(SECRET + '.complete', {'private': SECRET})
        for _ in range(100):
            callback('http11.send_request_body.started', {'private': SECRET})
            callback('http11.send_request_body.complete', {'private': SECRET})
        return response()
    result = diagnose_groq(SECRET, MODEL, 30, trace=True, request_sender=send)
    assert result['success']
    assert len(result['transport_trace']['events']) <= 64
    assert result['transport_trace']['truncated'] is True
    assert SECRET not in json.dumps(result)


def test_trace_absence_does_not_invent_response_phase():
    def send(url, **kwargs):
        raise httpx.ReadTimeout('withheld')
    result = diagnose_groq(SECRET, MODEL, 30, trace=True, request_sender=send)
    assert result['transport_trace']['failure_phase'] is None
    assert result['transport_trace']['events'] == []


@pytest.mark.parametrize('body_timeout', [False, True])
def test_trace_client_observes_headers_before_body_and_closes(monkeypatch, body_timeout):
    real_client = httpx.Client
    clients, seen, closed = [], [], []
    class Stream(httpx.SyncByteStream):
        def __init__(self, request):
            self.request = request
        def __iter__(self):
            callback = self.request.extensions['trace']
            callback('http11.receive_response_body.started', {})
            if body_timeout:
                callback('http11.receive_response_body.failed', {'exception': SECRET})
                raise httpx.ReadTimeout(SECRET)
            yield response().content
            callback('http11.receive_response_body.complete', {})
        def close(self):
            closed.append(True)
    def handler(request):
        seen.append(request)
        callback = request.extensions['trace']
        callback('http11.receive_response_headers.started', {})
        callback('http11.receive_response_headers.complete', {'return_value': (b'HTTP/1.1', 200, b'OK', [(b'private', SECRET.encode())])})
        return httpx.Response(200, stream=Stream(request))
    def factory(**kwargs):
        # Keep real HTTPX lifecycle/hooks; replace only its network boundary.
        assert set(kwargs) == {'event_hooks', 'http1', 'http2', 'follow_redirects'}
        client = real_client(transport=httpx.MockTransport(handler), **kwargs)
        clients.append(client)
        return client
    monkeypatch.setattr(httpx, 'Client', factory)
    result = diagnose_groq(SECRET, MODEL, 60, trace=True)
    assert result['http_status'] == 200
    assert result['transport_trace']['response_headers_received'] is True
    assert result['success'] is not body_timeout
    assert result['transport_trace']['failure_phase'] == ('response_body' if body_timeout else None)
    assert result['request_count'] == len(seen) == 1
    assert clients[0].is_closed and closed
    assert seen[0].extensions['timeout']['read'] == 60
    assert SECRET not in json.dumps(result)


def test_default_path_never_constructs_trace_client(monkeypatch):
    monkeypatch.setattr(httpx, 'Client', lambda **kwargs: pytest.fail('Default path changed transport'))
    result = diagnose_groq(SECRET, MODEL, 30, request_sender=lambda *a, **k: response())
    assert result['success']


def test_actual_httpcore_phases_and_verbose_library_logs_are_safe(monkeypatch, caplog):
    import httpcore
    from httpx._transports.default import map_httpcore_exceptions

    caplog.set_level(logging.DEBUG)
    core_streams = []
    class NetworkStream(httpcore.NetworkStream):
        def __init__(self):
            self.reads = 0
        def read(self, max_bytes, timeout=None):
            self.reads += 1
            if self.reads == 1:
                return b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nX-Private: ' + SECRET.encode() + b'\r\n\r\n'
            raise httpcore.ReadTimeout(SECRET)
        def write(self, buffer, timeout=None):
            pass
        def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            import ssl
            assert ssl_context.verify_mode == ssl.CERT_REQUIRED
            return self
        def get_extra_info(self, info):
            return None
        def close(self):
            pass
    class Backend(httpcore.NetworkBackend):
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            stream = NetworkStream()
            core_streams.append(stream)
            return stream
    class Body(httpx.SyncByteStream):
        def __init__(self, stream):
            self.stream = stream
        def __iter__(self):
            with map_httpcore_exceptions():
                yield from self.stream
        def close(self):
            self.stream.close()
    class Transport(httpx.BaseTransport):
        def __init__(self):
            self.pool = httpcore.ConnectionPool(network_backend=Backend())
        def handle_request(self, request):
            with map_httpcore_exceptions():
                result = self.pool.handle_request(httpcore.Request(method=request.method,
                    url=str(request.url), headers=request.headers.raw,
                    content=request.stream, extensions=request.extensions))
                return httpx.Response(result.status, headers=result.headers,
                                      stream=Body(result.stream), extensions=result.extensions)
        def close(self):
            self.pool.close()
    real_client = httpx.Client
    monkeypatch.setattr(httpx, 'Client', lambda **kwargs: real_client(transport=Transport(), **kwargs))
    result = diagnose_groq(SECRET, MODEL, 60, trace=True)
    assert result['failure_category'] == 'read_timeout'
    assert result['http_status'] == 200 and len(core_streams) == 1
    assert result['transport_trace']['failure_phase'] == 'response_body'
    assert {'connect', 'tls', 'request_headers', 'request_body', 'response_headers', 'response_body'} <= {
        event['phase'] for event in result['transport_trace']['events']}
    assert SECRET not in json.dumps(result) + caplog.text


def test_transport_log_filters_are_restored_after_failure(caplog):
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger('httpcore.http11')
    before = list(logger.filters)
    root_before = {handler: list(handler.filters) for handler in logging.getLogger().handlers}
    def send(url, **kwargs):
        logger.debug('hidden diagnostic details: %s', SECRET)
        raise httpx.ReadTimeout(SECRET)
    result = diagnose_groq(SECRET, MODEL, 30, trace=True, request_sender=send)
    logger.debug('outside-diagnostic-logging-restored')
    assert result['failure_category'] == 'read_timeout'
    assert logger.filters == before
    assert all(handler.filters == filters for handler, filters in root_before.items())
    assert 'outside-diagnostic-logging-restored' in caplog.text
    assert SECRET not in caplog.text


def test_transport_log_filter_does_not_suppress_other_threads(caplog):
    from concurrent.futures import ThreadPoolExecutor
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger('httpcore.http11')
    def send(url, **kwargs):
        logger.info('hidden diagnostic details: %s', SECRET)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(logger.info, 'unrelated-request-logging-preserved').result()
        return response()
    assert diagnose_groq(SECRET, MODEL, 30, trace=True, request_sender=send)['success']
    assert 'unrelated-request-logging-preserved' in caplog.text
    assert SECRET not in caplog.text


def test_nonfinite_trace_tick_does_not_break_http_or_emit_nan():
    ticks = iter([10, float('nan'), 10.2, 10.3])
    def send(url, **kwargs):
        callback = kwargs['extensions']['trace']
        callback('connection.connect_tcp.started', {})
        callback('connection.connect_tcp.complete', {})
        return response()
    result = diagnose_groq(SECRET, MODEL, 30, trace=True, request_sender=send, clock=lambda: next(ticks))
    assert result['success']
    assert result['transport_trace']['events'] == [{'phase': 'connect', 'state': 'complete', 'elapsed_ms': 200.0}]
    json.dumps(result, allow_nan=False)


def test_raw_trace_info_cannot_fabricate_target_status_or_reflect_objects():
    class Poison:
        def __repr__(self):
            raise AssertionError('Trace info must not be inspected')
    def send(url, **kwargs):
        callback = kwargs['extensions']['trace']
        callback('http11.receive_response_headers.complete', {'return_value': (b'HTTP/1.1', 200, b'OK', Poison())})
        callback('http11.receive_response_headers.started', Poison())
        raise httpx.ReadTimeout(SECRET)
    result = diagnose_groq(SECRET, MODEL, 30, trace=True, request_sender=send)
    assert result['failure_category'] == 'read_timeout'
    assert result['http_status'] is None
    assert result['transport_trace']['response_headers_received'] is False
    assert result['transport_trace']['failure_phase'] == 'response_headers'
