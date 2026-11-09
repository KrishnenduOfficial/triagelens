"""Offline scanner checks; all sample bytes are harmless and never executed."""

import hashlib
import json
import sys

import pytest

from src.engine import yara


SOURCE = '''rule harmless_marker {
meta:
    id = "test.marker"
    author = "TriageLens tests"
    source = "https://example.invalid/rules"
    revision = "test-v1"
    license = "MIT"
    mitre_attack = "T1059.001,T9999"
strings:
    $marker = "harmless marker"
condition:
    $marker
}'''
PACK = (yara.RuleSource('harmless', SOURCE),)


def test_standard_eicar_snapshot_and_benign_control():
    # The standard 68-byte antivirus test string is data only, never executed
    # or written as a sample file. A test-only hex rule avoids source escaping.
    data = (b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' +
            b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
    assert len(data) == 68
    assert hashlib.sha256(data).hexdigest() == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    source = SOURCE.replace('"harmless marker"', '{ ' + data.hex(' ') + ' }')
    pack = (yara.RuleSource('eicar_test_only', source),)
    result = yara.scan_snapshot(data, pack)
    if yara._engine_version() is None or sys.platform != 'win32':
        assert result.status in ('missing_engine', 'unavailable')
        return
    assert result.status == 'match', result
    assert result.matches[0].occurrences[0].offset == 0
    assert result.matches[0].occurrences[0].length == len(data)
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert yara.scan_snapshot(b'ordinary benign text', pack).status == 'no_match'


def test_real_isolated_harmless_scan():
    """With the optional wheel, actually compile/scan inside Windows isolation."""
    result = yara.scan_snapshot(b'prefix harmless marker suffix', PACK)
    if yara._engine_version() is None:
        assert result.status == 'missing_engine'
    elif sys.platform != 'win32':
        assert result.status == 'unavailable'
    else:
        assert result.status == 'match', result
        assert result.matches[0].occurrences[0].offset == 7
        assert result.matches[0].occurrences[0].length == 15
        assert result.matches[0].technique_ids == ['T1059.001']
        assert result.matches[0].invalid_technique_ids == ['T9999']
        assert result.sha256 == hashlib.sha256(b'prefix harmless marker suffix').hexdigest()
        assert result.size == 29
        assert result.version == '1.22.1'
        assert result.pack_digest and result.started_at <= result.ended_at


def test_base_install_missing_engine(monkeypatch):
    monkeypatch.setattr(yara.importlib.util, 'find_spec', lambda _: None)
    result = yara.scan_snapshot(b'plain', PACK)
    assert result.status == 'missing_engine'
    assert not result.matches
    assert 'yara_x' not in sys.modules  # Parent never imports native scanner.


@pytest.mark.parametrize('data', [bytearray(b'a'), 'text', b'x' * (yara.MAX_FILE_BYTES + 1)])
def test_invalid_or_oversized_snapshot(data):
    result = yara.scan_snapshot(data, PACK)
    assert result.status == 'rejected'
    assert result.sha256 is None and result.size is None


@pytest.mark.parametrize('data', [b'PK\x03\x04harmless', b'\x1f\x8bplain', b'7z\xbc\xaf\x27\x1c', b'Rar!', b'BZh', b'\xfd7zXZ\x00', b'0' * 257 + b'ustar'])
def test_archives_rejected_without_decoding(data):
    assert yara.scan_snapshot(data, PACK).diagnostics[0].category == 'archive'


@pytest.mark.parametrize('sources', [(), list(PACK), PACK * 31,
    (yara.RuleSource('../private', SOURCE),), PACK + PACK,
    (yara.RuleSource('x', 'import "pe" ' + SOURCE),),
    (yara.RuleSource('x', 'include "private.yar" ' + SOURCE),),
    (yara.RuleSource('x', SOURCE * 2),),
    (yara.RuleSource('x', 'x' * (yara.MAX_SOURCE_BYTES + 1)),),
    (yara.RuleSource('x', SOURCE + '\n' + '$a = "x"\n' * 10001),)])
def test_rule_admission_limits(sources):
    result = yara.scan_snapshot(b'plain', sources)
    assert result.status == 'rejected'
    assert result.diagnostics[0].category == 'invalid_rule_pack'


def test_busy_and_release(monkeypatch):
    yara._ADMISSION.acquire()
    try:
        assert yara.scan_snapshot(b'plain', PACK).status == 'busy'
    finally:
        yara._ADMISSION.release()
    monkeypatch.setattr(yara, '_engine_version', lambda: None)
    assert yara.scan_snapshot(b'plain', PACK).status == 'missing_engine'
    assert yara.scan_snapshot(b'plain', PACK).status == 'missing_engine'


@pytest.mark.parametrize('value', [0, -1, True, 1.5, 21])
def test_limits_cannot_be_disabled_or_raised(value):
    with pytest.raises(ValueError):
        yara.Limits(worker_seconds=value)


def test_engine_version_mismatch_no_fallback(monkeypatch):
    monkeypatch.setattr(yara, '_engine_version', lambda: 'other')
    assert yara.scan_snapshot(b'plain', PACK).diagnostics[0].category == 'unsupported_engine_version'


def test_unsupported_platform_fails_closed(monkeypatch):
    from src.engine import yara_windows
    monkeypatch.setattr(yara, '_engine_version', lambda: '1.22.1')
    monkeypatch.setattr(yara_windows.sys, 'platform', 'unsupported')
    assert yara.scan_snapshot(b'plain', PACK).diagnostics[0].category == 'isolation_unavailable'


def _response(**changes):
    value = {'status': 'no_match'}
    value.update(changes)
    return json.dumps(value).encode()


def _transport(monkeypatch, raw):
    from src.engine import yara_windows
    monkeypatch.setattr(yara, '_engine_version', lambda: '1.22.1')
    monkeypatch.setattr(yara_windows, 'run_worker', lambda *_: raw)


@pytest.mark.parametrize('raw', [b'not json', b'[]', b'{}', b'{"status":"benign"}',
    b'{"status":"no_match","extra":"private"}',
    b'x' * (yara.MAX_RESPONSE_BYTES + 1), _response(status='match')])
def test_malformed_responses_never_become_clean(monkeypatch, raw):
    _transport(monkeypatch, raw)
    result = yara.scan_snapshot(b'plain', PACK)
    assert result.status == 'worker_failure' and not result.matches


def _match(**changes):
    value = {'namespace': 'harmless', 'rule': 'harmless_marker',
             'source_digest': hashlib.sha256(SOURCE.encode()).hexdigest(),
             'metadata': {'id': 'test.marker', 'author': 'TriageLens tests',
                          'source': 'https://example.invalid/rules', 'revision': 'v1', 'license': 'MIT'},
             'occurrences': [{'pattern': '$marker', 'offset': 0, 'length': 1}]}
    value.update(changes)
    return value


@pytest.mark.parametrize('match', [_match(namespace='unknown'), _match(source_digest='0' * 64),
    _match(metadata={}), _match(occurrences=[{'pattern': '$a', 'offset': 5, 'length': 1}]),
    _match(occurrences=[{'pattern': '$a', 'offset': 0, 'length': 1}] * 101),
    _match(metadata={'private': 'value'}), _match(unexpected='bytes')])
def test_untrusted_result_validation(monkeypatch, match):
    _transport(monkeypatch, _response(status='match', matches=[match]))
    assert yara.scan_snapshot(b'plain', PACK).status == 'worker_failure'


def test_failure_cleanup_and_no_fallback(monkeypatch):
    from src.engine import yara_windows
    monkeypatch.setattr(yara, '_engine_version', lambda: '1.22.1')
    calls = []

    def fail(*_):
        calls.append(True)
        raise yara_windows.IsolationUnavailable()

    monkeypatch.setattr(yara_windows, 'run_worker', fail)
    result = yara.scan_snapshot(b'plain', PACK)
    assert result.status == 'unavailable' and not result.matches
    assert len(calls) == 1
    assert yara.scan_snapshot(b'plain', PACK).status == 'unavailable'


@pytest.mark.parametrize('status', ['timeout', 'resource_exhausted', 'worker_failure'])
def test_worker_stop_statuses(monkeypatch, status):
    from src.engine import yara_windows
    monkeypatch.setattr(yara, '_engine_version', lambda: '1.22.1')

    def fail(*_):
        raise yara_windows.WorkerStopped(status, 'bounded_failure')

    monkeypatch.setattr(yara_windows, 'run_worker', fail)
    result = yara.scan_snapshot(b'plain', PACK)
    assert result.status == status and not result.matches


def test_truncation_never_clean(monkeypatch):
    _transport(monkeypatch, _response(status='truncated', matches=[_match()]))
    assert yara.scan_snapshot(b'plain', PACK).status == 'truncated'


def test_unmapped_hit_retained_with_explicit_diagnostic(monkeypatch):
    _transport(monkeypatch, _response(status='match', matches=[_match()]))
    result = yara.scan_snapshot(b'plain', PACK)
    assert result.status == 'match' and result.matches
    assert result.matches[0].technique_ids == []
    assert result.diagnostics[0].category == 'missing_attack_metadata'
