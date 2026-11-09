"""Harmless registered-root boundary probes; no samples are executed or unpacked."""
from dataclasses import replace
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4
import zipfile

import pytest
from fastapi.testclient import TestClient

from src.api.main import create_app
from src.engine import yara, yara_files, yara_service
from src.engine.database import DatabaseManager
from test_yara_integration import sample_result, alert


pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Windows file admission')
REAL_SCAN = yara.scan_snapshot


@pytest.fixture
def scan_env(tmp_path, monkeypatch):
    root = tmp_path / 'samples'
    root.mkdir()
    db = DatabaseManager(str(tmp_path / 'boundary.sqlite'))
    db.init_db()
    scanned = []

    def scan(data, sources, **kwargs):
        scanned.append(data)
        return replace(sample_result(data), status='no_match', matches=())

    monkeypatch.setattr('src.config.get_yara_scan_roots', lambda: {'safe': str(root)})
    monkeypatch.setattr(yara, 'scan_snapshot', scan)
    with TestClient(create_app(db)) as client:
        yield root, db, client, scanned
    db.close()


def submit(env, relative_path=''):
    _, db, client, _ = env
    job_id = str(uuid4())
    response = client.post('/api/yara/scans', json={
        'job_id': job_id, 'root_id': 'safe', 'relative_path': relative_path})
    if response.status_code == 200:
        assert client.get('/api/yara/jobs/' + job_id).json() == response.json()
    else:
        assert db.get_yara_job(job_id) is None
    return response


@pytest.mark.parametrize('path', [
    '..', '../outside', 'nested/../../outside', r'nested\..\outside',
    r'C:\outside', 'C:outside', r'\outside', r'\\server\share',
    r'\\?\C:\outside', r'\\.\NUL', 'safe.txt:stream', 'NUL.txt',
    'CON', 'COM1.txt', 'nested//file', 'nested/./file', 'file.', 'file ',
    'nested/../file', 'bad\x00name',
])
def test_api_rejects_unsafe_relative_paths_without_scanning(scan_env, path):
    response = submit(scan_env, path)
    assert response.status_code == 400
    assert response.json()['detail'] == 'invalid_path'
    assert scan_env[3] == []
    assert str(scan_env[0]) not in response.text


@pytest.mark.parametrize('root', [
    '.', 'C:relative', 'C:\\', r'\\server\share\samples', r'\\?\C:\samples',
])
def test_unsafe_registered_roots_are_rejected(root):
    with pytest.raises(yara_files.FileRejected, match='invalid_root'):
        yara_files.validate_root(root)


def test_protected_and_broad_ancestor_roots_are_rejected():
    from src.config import PROJECT_ROOT
    for path in (PROJECT_ROOT, PROJECT_ROOT.parent, Path.home() / '.ssh'):
        with pytest.raises(yara_files.FileRejected, match='protected_root'):
            yara_files.validate_root(str(path))


def test_native_snapshot_denies_replacement_and_writes(scan_env):
    root = scan_env[0]
    target, replacement = root / 'safe.txt', root / 'replacement.txt'
    target.write_bytes(b'original harmless bytes')
    replacement.write_bytes(b'other harmless bytes')
    with yara_files.pinned_path(str(root), ('safe.txt',), file=True):
        with pytest.raises(PermissionError):
            target.write_bytes(b'changed')
        with pytest.raises(PermissionError):
            os.replace(replacement, target)
        with pytest.raises(PermissionError):
            root.rename(root.with_name('renamed'))
    assert yara_files.read_snapshot(str(root), ('safe.txt',), 100) == b'original harmless bytes'


def test_registered_root_replacement_is_incomplete(scan_env):
    root, _, _, scanned = scan_env
    root.rename(root.with_name('original'))
    root.mkdir()
    (root / 'safe.txt').write_bytes(b'harmless replacement')
    response = submit(scan_env)
    assert response.status_code == 200
    assert response.json()['status'] == 'incomplete'
    assert response.json()['errors'] == ['root_changed']
    assert response.json()['scan_ids'] == scanned == []


def test_junction_cannot_escape_registered_root(scan_env):
    root, _, _, scanned = scan_env
    outside = root.parent / 'outside'
    outside.mkdir()
    canary = outside / 'canary.txt'
    canary.write_bytes(b'harmless outside canary')
    junction = root / 'junction'
    created = subprocess.run(['cmd', '/d', '/c', 'mklink', '/J', str(junction), str(outside)],
                             capture_output=True, timeout=5, creationflags=0x08000000)
    assert created.returncode == 0
    try:
        with pytest.raises(yara_files.FileRejected, match='reparse_or_type'):
            yara_files.read_snapshot(str(root), ('junction', 'canary.txt'), 100)
        response = submit(scan_env)
        assert response.json()['status'] == 'incomplete'
        assert response.json()['scan_ids'] == scanned == []
        assert canary.read_bytes() == b'harmless outside canary'
    finally:
        junction.rmdir()  # Remove only the junction, never its target tree.


def test_oversized_file_never_reaches_scanner(scan_env):
    root = scan_env[0]
    with (root / 'too-large.txt').open('wb') as stream:
        stream.truncate(yara_files.MAX_FILE + 1)
    response = submit(scan_env)
    assert response.json()['status'] == 'incomplete'
    assert response.json()['errors'] == ['size_limit']
    assert response.json()['scan_ids'] == scan_env[3] == []
    assert response.json()['bytes'] == 0


def test_snapshot_read_enforces_cap_when_metadata_understates_size(scan_env, monkeypatch):
    root = scan_env[0]
    (root / 'safe.txt').write_bytes(b'harmless larger bytes')
    original = yara_files._info

    def understated(k, handle):
        info = original(k, handle)
        if not info.attributes & 0x10:
            info.size_low = 1
        return info

    monkeypatch.setattr(yara_files, '_info', understated)
    with pytest.raises(yara_files.FileRejected, match='size_limit'):
        yara_files.read_snapshot(str(root), ('safe.txt',), 5)


@pytest.mark.parametrize('extension', sorted(yara_files.ARCHIVES))
def test_archive_extensions_rejected_before_scan(scan_env, extension):
    (scan_env[0] / ('opaque' + extension.upper())).write_bytes(b'harmless ordinary text')
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete'
    assert job['errors'] == ['archive_or_invalid_file']
    assert job['scan_ids'] == scan_env[3] == []


@pytest.mark.parametrize('header', [
    b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08', b'\x1f\x8b',
    b'7z\xbc\xaf\x27\x1c', b'Rar!', b'BZh', b'\xfd7zXZ\x00', b'0' * 257 + b'ustar',
])
def test_disguised_archive_is_persisted_as_rejected(scan_env, monkeypatch, header):
    root, db, client, scanned = scan_env
    # Restore the actual admission path: signatures must reject before a worker.
    monkeypatch.setattr(yara, 'scan_snapshot', REAL_SCAN)
    monkeypatch.setattr(yara, '_engine_version', lambda: pytest.fail('archive reached engine admission'))
    data = header + b'harmless opaque payload'
    (root / 'looks-benign.txt').write_bytes(data)
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete'
    assert job['errors'] == ['scan_rejected']
    assert scanned == []
    assert len(job['scan_ids']) == 1
    result = client.get('/api/yara/scans/' + job['scan_ids'][0]).json()
    assert result['status'] == 'rejected'
    assert result['diagnostics'] == [{'category': 'archive', 'source': None, 'line': None}]
    assert result['sha256'] is None and result['detection_ids'] == []
    assert str(root) not in str(job) + str(result)
    assert db.connection.execute('SELECT count(*) FROM detections').fetchone()[0] == 0


def test_real_zip_with_traversal_member_is_never_extracted(scan_env, monkeypatch):
    root = scan_env[0]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('../escape.txt', b'harmless marker' * 10000)
    monkeypatch.setattr(yara, 'scan_snapshot', REAL_SCAN)
    (root / 'renamed.txt').write_bytes(buffer.getvalue())
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete' and job['errors'] == ['scan_rejected']
    assert not (root.parent / 'escape.txt').exists()
    assert not (root / 'escape.txt').exists()


def test_hardlink_rejection_is_persisted_without_scanning(scan_env):
    root = scan_env[0]
    (root / 'safe.txt').write_bytes(b'harmless linked bytes')
    os.link(root / 'safe.txt', root.parent / 'second-link.txt')
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete' and job['errors'] == ['hardlink']
    assert job['scan_ids'] == scan_env[3] == []


def test_nested_enumeration_never_exceeds_global_entry_limit(scan_env):
    root = scan_env[0]
    first = root / 'a'
    first.mkdir()
    # Directory-only fixtures reach the entry bound without the 100-file bound.
    for index in range(999):
        (first / f'd{index:04}').mkdir()
    (root / 'z.txt').write_bytes(b'must remain unvisited')
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete' and job['truncated']
    assert 'entry_limit' in job['errors']
    assert job['entries'] == 1000
    assert job['files'] == 0 and scan_env[3] == []


def test_exact_entry_budget_completes_without_false_truncation(scan_env):
    root = scan_env[0]
    first = root / 'a'
    first.mkdir()
    for index in range(999):
        (first / f'd{index:04}').mkdir()
    job = submit(scan_env).json()
    assert job['status'] == 'completed' and not job['truncated']
    assert job['entries'] == 1000 and job['errors'] == []


def test_unknown_root_and_excessive_request_depth_never_scan(scan_env):
    _, db, client, scanned = scan_env
    job_id = str(uuid4())
    response = client.post('/api/yara/scans', json={'job_id': job_id, 'root_id': 'unknown'})
    assert response.status_code == 400 and response.json()['detail'] == 'unknown_root'
    assert db.get_yara_job(job_id) is None
    response = submit(scan_env, 'a/b/c/d/e')
    assert response.status_code == 400 and response.json()['detail'] == 'depth_limit'
    assert scanned == []


def test_file_limit_reports_unvisited_scope(scan_env):
    root = scan_env[0]
    for index in range(101):
        (root / f'f{index:03}.txt').write_bytes(b'harmless')
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete' and job['truncated']
    assert job['errors'] == ['file_limit'] and job['files'] == 100
    assert len(job['scan_ids']) == len(scan_env[3]) == 100


def test_depth_limit_reports_incomplete_scope(scan_env):
    root = scan_env[0]
    deep = root.joinpath(*['nested'] * 5)
    deep.mkdir(parents=True)
    (deep / 'safe.txt').write_bytes(b'unvisited harmless bytes')
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete' and job['truncated']
    assert job['errors'] == ['depth_limit'] and job['scan_ids'] == []
    assert scan_env[3] == []


def test_total_snapshot_budget_stops_before_scanner(scan_env, monkeypatch):
    root = scan_env[0]
    for index in range(9):
        (root / f'f{index}.txt').write_bytes(b'harmless placeholder')
    acquired = []
    block = b'\x00' * yara_files.MAX_FILE

    def read(root, parts, remaining):
        acquired.append(remaining)
        if remaining < len(block):
            raise yara_files.FileRejected('size_limit')
        return block

    monkeypatch.setattr(yara_files, 'read_snapshot', read)
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete' and job['errors'] == ['size_limit']
    assert job['bytes'] == 128 * 1024 * 1024
    assert acquired == list(range(128 * 1024 * 1024, -1, -len(block)))
    assert len(scan_env[3]) == 8


def test_job_deadline_never_becomes_completed(scan_env, monkeypatch):
    (scan_env[0] / 'safe.txt').write_bytes(b'harmless')
    ticks = iter([0, 61])
    monkeypatch.setattr(yara_service, 'time', SimpleNamespace(monotonic=lambda: next(ticks)))
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete' and job['truncated']
    assert job['errors'] == ['job_deadline']
    assert job['scan_ids'] == scan_env[3] == []


def test_timeout_persists_without_detections_or_label_changes(scan_env, monkeypatch):
    root, db, client, _ = scan_env
    data = b'harmless time-limited sample'
    (root / 'safe.txt').write_bytes(data)
    item = alert(hashlib.sha256(data).hexdigest())
    db.insert_alert(item)
    result = replace(sample_result(data), status='timeout', matches=(),
                     diagnostics=(yara.Diagnostic(category='scan_timeout'),))
    monkeypatch.setattr(yara, 'scan_snapshot', lambda *args, **kwargs: result)
    job = submit(scan_env).json()
    assert job['status'] == 'incomplete' and job['errors'] == ['scan_timeout']
    saved = client.get('/api/yara/scans/' + result.scan_id).json()
    assert saved['status'] == 'timeout' and saved['detection_ids'] == []
    assert saved['sha256'] == hashlib.sha256(data).hexdigest()
    assert db.get_alert(item.internal_id)['ground_truth_label'] == 'benign'
    assert db.connection.execute('SELECT count(*) FROM detections').fetchone()[0] == 0
