"""Harmless native containment probes; no external hosts or sample execution."""

import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import socket
import select
import subprocess
import sys
import time

import pytest

from src.engine import yara, yara_windows as win
from test_yara import PACK, SOURCE


@pytest.fixture(scope='module')
def runtime(tmp_path_factory):
    if sys.platform != 'win32' or yara._engine_version() is None:
        return None
    path = tmp_path_factory.mktemp('yara_runtime')
    win._stage_runtime(path)
    return path


def _ready(runtime):
    if runtime is None:
        assert yara.scan_snapshot(b'plain', PACK).status in ('missing_engine', 'unavailable')
        return False
    return True


def _code(body):
    return 'import json\nprint(json.dumps({"phase":"compiled"}), flush=True)\n' + body


def _probe(runtime, body, limits=None, **options):
    with win._Sandbox(runtime, limits or yara.Limits()) as sandbox:
        sandbox.start(['-c', _code(body)])
        raw = sandbox.communicate(b'', response_bytes=262144, seconds=5,
                                  compile_seconds=5, **options)
        return json.loads(raw)


def test_native_appcontainer_denies_loopback_tcp_udp(runtime):
    if not _ready(runtime):
        return
    with socket.socket() as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_server:
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        udp_server.bind(('127.0.0.1', 0))
        port = server.getsockname()[1]
        udp_port = udp_server.getsockname()[1]
        # Positive control: these exact receivers accept a trusted local client
        # outside AppContainer. The worker probe below must reach neither one.
        control = f'''import socket
with socket.socket() as tcp:
    tcp.connect(('127.0.0.1', {port}))
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    udp.sendto(b'harmless-control', ('127.0.0.1', {udp_port}))
'''
        subprocess.run([sys.executable, '-I', '-c', control], check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       creationflags=0x08000000)
        assert select.select([server, udp_server], [], [], 1)[0] == [server, udp_server]
        connection, _ = server.accept()
        connection.close()
        assert udp_server.recvfrom(100)[0] == b'harmless-control'
        body = f'''
import socket
tcp = socket.socket()
tcp.settimeout(1)
tcp_error = tcp.connect_ex(('127.0.0.1', {port}))
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    udp.sendto(b'harmless', ('127.0.0.1', {udp_port}))
    udp_error = 0
except OSError as error:
    udp_error = error.winerror
print(json.dumps({{'result': {{'tcp': tcp_error, 'udp': udp_error}}}}), flush=True)
'''
        result = _probe(runtime, body)
        # Windows filtering can silently drop UDP or leave TCP pending instead
        # of returning WSAEACCES. Verify delivery at actual local receivers too.
        assert result['tcp'] != 0
        assert result['udp'] in (0, 10013)
        assert select.select([server, udp_server], [], [], 0.2)[0] == []


def test_native_filesystem_and_environment_isolation(runtime, tmp_path, monkeypatch):
    if not _ready(runtime):
        return
    canary = tmp_path / 'private-canary.txt'
    canary.write_text('harmless private marker')
    monkeypatch.setenv('TRIAGELENS_TEST_SECRET', 'fake-secret-only')
    body = f'''
import os
try:
    open({str(canary)!r}, 'rb').read()
    denied = False
except PermissionError:
    denied = True
try:
    open('worker.py', 'ab').write(b'harmless')
    readonly = False
except PermissionError:
    readonly = True
print(json.dumps({{'result': {{'denied': denied, 'readonly': readonly,
    'secret_absent': 'TRIAGELENS_TEST_SECRET' not in os.environ}}}}), flush=True)
'''
    assert _probe(runtime, body) == {'denied': True, 'readonly': True, 'secret_absent': True}


def test_native_job_limits_and_handle_cleanup(runtime):
    if not _ready(runtime):
        return
    with win._Sandbox(runtime, yara.Limits()) as sandbox:
        sandbox.start(['-c', _code('print(json.dumps({"result": {"ok": True}}), flush=True)')])
        query = sandbox.api.k.QueryInformationJobObject
        query.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p]
        query.restype = W.BOOL
        info = win._ExtendedLimits()
        assert query(sandbox.job, 9, C.byref(info), C.sizeof(info), None)
        assert info.basic.active == 1
        assert info.basic.process_time == 100_000_000
        assert info.process_memory == info.job_memory == 512 * 1024 * 1024
        assert info.basic.flags & 0x2000  # kill on last job handle close
        assert json.loads(sandbox.communicate(b'', response_bytes=4096, seconds=5, compile_seconds=5)) == {'ok': True}
    assert sandbox.handles == []


def test_native_memory_limit(runtime):
    if not _ready(runtime):
        return
    body = '''
try:
    value = bytearray(600 * 1024 * 1024)
    bounded = False
except MemoryError:
    bounded = True
print(json.dumps({'result': {'bounded': bounded}}), flush=True)
'''
    assert _probe(runtime, body) == {'bounded': True}


def test_native_process_count_limit(runtime):
    if not _ready(runtime):
        return
    body = '''
import subprocess, sys
try:
    child = subprocess.Popen([sys.executable, '-c', 'pass'])
    child.wait(timeout=1)
    denied = False
except OSError:
    denied = True
print(json.dumps({'result': {'denied': denied}}), flush=True)
'''
    assert _probe(runtime, body) == {'denied': True}


def test_native_cpu_limit(runtime):
    if not _ready(runtime):
        return
    # Keep the CPU allowance at one second. Windows checks user-time limits
    # periodically; use the production wall deadline to observe its exit status,
    # independently of the much shorter wall-deadline probes below.
    with pytest.raises(win.WorkerStopped) as error, win._Sandbox(runtime, yara.Limits(cpu_seconds=1)) as sandbox:
        sandbox.start(['-c', _code('while True: pass')])
        sandbox.communicate(b'', response_bytes=4096, seconds=20, compile_seconds=10)
    assert error.value.status == 'resource_exhausted'


@pytest.mark.parametrize('compiled,category', [(False, 'compile_deadline'), (True, 'worker_deadline')])
def test_native_deadlines_reap_worker(runtime, compiled, category):
    if not _ready(runtime):
        return
    sandbox = win._Sandbox(runtime, yara.Limits())
    with pytest.raises(win.WorkerStopped) as error, sandbox:
        code = 'import time; time.sleep(3)'
        sandbox.start(['-c', _code(code) if compiled else code])
        if compiled:
            ready_by = time.monotonic() + 2
            available = W.DWORD()
            while not available.value and time.monotonic() < ready_by:
                assert sandbox.api.k.PeekNamedPipe(sandbox.output, None, 0, None, C.byref(available), None)
                time.sleep(0.01)
            assert available.value  # Handshake is queued before the 0.2 s timer.
        sandbox.communicate(b'', response_bytes=4096, seconds=0.2 if compiled else 3,
                            compile_seconds=3 if compiled else 0.2)
    assert error.value.category == category
    assert sandbox.handles == []
    assert sandbox.writer is None or not sandbox.writer.is_alive()


def test_native_slow_rule_engine_timeout_and_cleanup(runtime, monkeypatch):
    if not _ready(runtime):
        return
    # Dynamic byte reads keep this bounded test from being constant-folded.
    # No matching byte exists; the engine must interrupt the long loop.
    source = SOURCE[:SOURCE.index('strings:')] + '''condition:
        for any i in (1..1000000000) : (uint8(i % filesize) == 255)
    }'''
    sandboxes = []
    original = win._Sandbox

    def observe(*args, **kwargs):
        sandbox = original(*args, **kwargs)
        sandboxes.append(sandbox)
        return sandbox

    monkeypatch.setattr(win, '_Sandbox', observe)
    result = yara.scan_snapshot(b'\x00' * 65536, (yara.RuleSource('slow_test_only', source),),
                                limits=yara.Limits(scan_seconds=1))
    assert result.status == 'timeout', result
    assert [d.category for d in result.diagnostics] == ['scan_timeout']
    assert not result.matches
    assert len(sandboxes) == 1
    assert sandboxes[0].handles == []
    assert sandboxes[0].writer is None or not sandboxes[0].writer.is_alive()
    # A fresh native worker remains usable after the timed-out scan.
    assert yara.scan_snapshot(b'plain', PACK).status == 'no_match'


@pytest.mark.parametrize('body,category', [
    ('print("x" * 10000, flush=True)', 'oversized_response'),
    ('print("invalid", flush=True)', 'malformed_response'),
    ('print(json.dumps({"result": {}, "extra": 1}), flush=True)', 'invalid_protocol'),
    ('print(json.dumps({"result": {}}), flush=True)\nprint(json.dumps({"result": {}}), flush=True)', 'invalid_protocol'),
])
def test_native_invalid_ipc_cleanup(runtime, body, category):
    if not _ready(runtime):
        return
    sandbox = win._Sandbox(runtime, yara.Limits())
    with pytest.raises(win.WorkerStopped) as error, sandbox:
        sandbox.start(['-c', _code(body)])
        sandbox.communicate(b'', response_bytes=4096, seconds=3, compile_seconds=3)
    assert error.value.category == category
    assert sandbox.handles == []


def test_native_setup_failure_never_releases_child(runtime, monkeypatch):
    if not _ready(runtime):
        return
    api = win._API()
    calls = []

    def fail(*_):
        calls.append('limit_setup')
        return False

    monkeypatch.setattr(api.k, 'SetInformationJobObject', fail)
    monkeypatch.setattr(win, '_API', lambda: api)
    sandbox = win._Sandbox(runtime, yara.Limits())
    with pytest.raises(win.IsolationUnavailable), sandbox:
        sandbox.start(['-c', 'raise SystemExit(99)'])
    assert calls == ['limit_setup']
    assert not sandbox.process.process and sandbox.handles == []


def test_native_identity_failure_kills_suspended_child(runtime, monkeypatch):
    if not _ready(runtime):
        return
    api, released = win._API(), []
    monkeypatch.setattr(api.a, 'EqualSid', lambda *_: False)
    monkeypatch.setattr(api.k, 'ResumeThread', lambda *_: released.append(True))
    monkeypatch.setattr(win, '_API', lambda: api)
    sandbox = win._Sandbox(runtime, yara.Limits())
    with pytest.raises(win.IsolationUnavailable), sandbox:
        sandbox.start(['-c', 'raise SystemExit(99)'])
    assert sandbox.process.pid and not released
    assert sandbox.handles == []


def test_native_parent_exit_kills_worker(runtime):
    if not _ready(runtime):
        return
    # This helper deliberately exits without context cleanup. The OS must close
    # its sole job handle and kill the still-running worker. It prints identifiers
    # only; a fresh profile is deleted by this test after observing termination.
    helper = f'''
import os, sys, json
from pathlib import Path
sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})
from src.engine.yara import Limits
from src.engine.yara_windows import _Sandbox
sandbox = _Sandbox(Path({str(runtime)!r}), Limits())
sandbox.start(['-c', 'import time; time.sleep(30)'])
print(json.dumps({{'pid': sandbox.process.pid, 'profile': sandbox.profile}}), flush=True)
sys.stdin.readline()
os._exit(0)
'''
    parent = subprocess.Popen([sys.executable, '-I', '-c', helper], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                              creationflags=0x08000000)
    api, handle, info = win._API(), None, None
    try:
        # Helper startup is bounded by a supervising timer; readline cannot hang
        # the suite if native setup fails before printing its handshake.
        import threading
        timer = threading.Timer(10, parent.kill)
        timer.start()
        try:
            info = json.loads(parent.stdout.readline())
        finally:
            timer.cancel()
        open_process = api.k.OpenProcess
        open_process.argtypes, open_process.restype = [W.DWORD, W.BOOL, W.DWORD], W.HANDLE
        handle = open_process(0x100000, False, info['pid'])
        assert handle
        parent.communicate('\n', timeout=5)
        assert parent.returncode == 0
        assert api.k.WaitForSingleObject(handle, 5000) == 0
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if handle:
            api.k.CloseHandle(handle)
        if info:
            assert api.u.DeleteAppContainerProfile(info['profile']) == 0


@pytest.mark.parametrize('text,expected', [
    (SOURCE.replace('$marker\n}', 'unknown_identifier\n}'), 'compile_error'),
    (SOURCE.replace('author = "TriageLens tests"', ''), 'compile_error'),
    (SOURCE.replace('license = "MIT"', 'license = 42'), 'compile_error'),
    (SOURCE.replace('license = "MIT"', 'license = "MIT" extra = "private"'), 'compile_error'),
    (SOURCE.replace('license = "MIT"', 'license = "MIT" license = "MIT"'), 'compile_error'),
    (SOURCE, 'no_match'),
])
def test_native_compilation_and_no_match(runtime, text, expected):
    if not _ready(runtime):
        return
    result = yara.scan_snapshot(b'plain harmless data', (yara.RuleSource('harmless', text),))
    assert result.status == expected, result
    assert not result.matches
    assert 'unknown_identifier' not in str(result.diagnostics)
    assert 'private' not in str(result.diagnostics)
    if expected == 'compile_error':
        assert result.diagnostics


def test_native_occurrences_truncated(runtime):
    if not _ready(runtime):
        return
    source = SOURCE.replace('"harmless marker"', '"a"')
    result = yara.scan_snapshot(b'a' * 1000, (yara.RuleSource('harmless', source),),
                                limits=yara.Limits(occurrences_per_pattern=2))
    assert result.status == 'truncated', result
    assert len(result.matches[0].occurrences) == 2
