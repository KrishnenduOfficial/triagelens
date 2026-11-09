"""Offline checks for the original YARA pack; inputs are harmless text."""

from pathlib import Path
import sys

import pytest

from src.engine.yara import RuleSource, scan_snapshot, _engine_version


ROOT = Path(__file__).resolve().parents[1] / 'rules' / 'yara'
CASES = [
    ('powershell_encoded_command', b'powershell -encodedcommand example',
     {'T1059.001', 'T1027'}),
    ('windows_script_host', b'wscript.exe example.vbs', {'T1059.005'}),
]

CURATED = [
    ('bat_chunked_setenv', b'@echo off' + b'\r\nset "abcdefghij=xy"' * 11),
    ('bat_substring_env', b'@echo off\r\n:~1,2%'),
]


@pytest.mark.parametrize('name,positive,techniques', CASES)
def test_original_rule_scans_and_metadata(name, positive, techniques):
    source = RuleSource(name, (ROOT / f'{name}.yar').read_text(encoding='utf-8'))
    result = scan_snapshot(positive, (source,))
    if _engine_version() is None or sys.platform != 'win32':
        assert result.status in {'missing_engine', 'unavailable'}
        return
    assert result.status == 'match', result
    match = result.matches[0]
    assert match.metadata['author'] == 'TriageLens Contributors'
    assert match.metadata['license'] == 'MIT'
    assert match.metadata['source'].startswith('https://')
    assert match.metadata['revision'] == '1'
    assert set(match.technique_ids) == techniques
    assert not match.invalid_technique_ids
    assert scan_snapshot(b'ordinary unrelated text', (source,)).status == 'no_match'


@pytest.mark.parametrize('name,positive', CURATED)
def test_curated_rule_scans_and_metadata(name, positive):
    source = RuleSource(name, (ROOT / f'{name}.yar').read_text(encoding='utf-8'))
    result = scan_snapshot(positive, (source,))
    if _engine_version() is None or sys.platform != 'win32':
        assert result.status in {'missing_engine', 'unavailable'}
        return
    assert result.status == 'match', result
    match = result.matches[0]
    assert match.metadata['author'] == 'Marcin Ulikowski'
    assert match.metadata['license'] == 'MIT'
    assert 'elceef/yara-rulz' in match.metadata['source']
    assert set(match.technique_ids) == {'T1027', 'T1059.003'}
    assert not match.invalid_technique_ids
    assert scan_snapshot(b'ordinary unrelated text', (source,)).status == 'no_match'


def test_pack_compiles_together():
    sources = tuple(RuleSource(path.stem, path.read_text(encoding='utf-8'))
                    for path in sorted(ROOT.glob('*.yar')))
    assert len(sources) == 4
    result = scan_snapshot(b'ordinary unrelated text', sources)
    if _engine_version() is None or sys.platform != 'win32':
        assert result.status in {'missing_engine', 'unavailable'}
    else:
        assert result.status == 'no_match', result
