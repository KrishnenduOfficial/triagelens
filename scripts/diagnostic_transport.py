"""Shared metadata-only transport tracing for operator diagnostics."""

import argparse
from contextlib import contextmanager
from contextvars import ContextVar
import logging
import math


_DIAGNOSTIC_TRANSPORT_LOGS = ContextVar('diagnostic_transport_logs', default=False)


class _WithholdTransportLogs(logging.Filter):
    def filter(self, record):
        transport = record.name == 'httpx' or record.name.startswith(('httpx.', 'httpcore.')) or record.name == 'httpcore'
        return not (transport and _DIAGNOSTIC_TRANSPORT_LOGS.get())


@contextmanager
def _withhold_transport_logs():
    """Block raw library logs only in this diagnostic context; keep log levels.

    HTTPcore DEBUG logs otherwise echo response headers and exception text even
    when the trace callback itself discards them. A context-local filter leaves
    unrelated threads/requests alone and is removed on every exit path.
    """
    targets = set(logging.getLogger().handlers)
    for logger in list(logging.Logger.manager.loggerDict.values()):
        if isinstance(logger, logging.Logger):
            targets.update(logger.handlers)
            if logger.name.startswith(('httpx', 'httpcore')):
                targets.add(logger)
    if logging.lastResort is not None:
        targets.add(logging.lastResort)
    guard = _WithholdTransportLogs()
    for target in targets:
        target.addFilter(guard)
    token = _DIAGNOSTIC_TRANSPORT_LOGS.set(True)
    try:
        yield
    finally:
        _DIAGNOSTIC_TRANSPORT_LOGS.reset(token)
        for target in targets:
            target.removeFilter(guard)


class TransportTrace:
    """Record only allow-listed phase names and injected-clock timings.

    HTTPcore info can contain headers, requests, sockets, and exception messages.
    Never inspect, stringify, or store that info. No verbose library logging is
    enabled by this observer. These phases may include a configured proxy.
    """

    PHASES = {
        'connection.connect_tcp': 'connect',
        'connection.start_tls': 'tls',
        'proxy.start_tls': 'tls',
        'http11.send_request_headers': 'request_headers',
        'http11.send_request_body': 'request_body',
        'http11.receive_response_headers': 'response_headers',
        'http11.receive_response_body': 'response_body',
    }
    MAX_EVENTS = 64

    def __init__(self, output, clock, start):
        self.output = output
        self.clock = clock
        self.start = start
        self.pending = {}
        self.failed_phase = None

    def __call__(self, event, info):
        if not isinstance(event, str):
            return
        name, _, state = event.rpartition('.')
        phase = self.PHASES.get(name)
        if phase is None or state not in ('started', 'complete', 'failed'):
            return
        # Clock failures must not turn a successful HTTP operation into failure.
        try:
            now = self.clock()
            if not math.isfinite(now):
                return
            elapsed = round(max(0.0, now - self.start) * 1000, 1)
        except Exception:
            return
        record = {'phase': phase, 'state': state, 'elapsed_ms': elapsed}
        if state == 'started':
            self.pending[phase] = now
        else:
            began = self.pending.pop(phase, None)
            if began is not None:
                record['duration_ms'] = round(max(0.0, now - began) * 1000, 1)
            if state == 'failed':
                self.failed_phase = phase
        self.output['status'] = 'recorded'
        if len(self.output['events']) < self.MAX_EVENTS:
            self.output['events'].append(record)
        else:
            self.output['truncated'] = True

    def note_failure(self):
        self.output['failure_phase'] = self.failed_phase or next(reversed(self.pending), None)


def positive_timeout(value: str) -> float:
    """Reject invalid budgets without echoing potentially sensitive input."""
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Timeout must be a positive finite number.") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("Timeout must be a positive finite number.")
    return timeout
