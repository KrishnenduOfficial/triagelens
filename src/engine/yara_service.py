"""Offline registered-directory orchestration for bounded YARA scans."""
import hashlib
import json
import os
import ctypes
from ctypes import wintypes
from pathlib import Path
import threading
import time

from src.engine import yara, yara_files

_JOB_LOCK = threading.Lock()
_RULES = Path(__file__).resolve().parents[2] / 'rules' / 'yara'


def _root_identity(info):
    return info.volume, info.index_high, info.index_low


class YaraService:
    def __init__(self, db, roots):
        self.db = db
        self.roots = {}
        for name, path in roots.items():
            clean = yara_files.validate_root(path)
            with yara_files.pinned_path(clean, ()) as (_, (_, _, info)):
                self.roots[name] = (clean, _root_identity(info))

    def scan(self, job_id, root_id, relative_path):
        parts = yara_files.relative_parts(relative_path)
        if len(parts) > 4:
            raise yara_files.FileRejected('depth_limit')
        if root_id not in self.roots:
            raise yara_files.FileRejected('unknown_root')
        if not _JOB_LOCK.acquire(blocking=False):
            raise RuntimeError('busy')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.CreateMutexW.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        mutex = kernel.CreateMutexW(None, False, 'Local\\TriageLensYaraScan')
        if not mutex:
            _JOB_LOCK.release()
            raise RuntimeError('admission_unavailable')
        wait = kernel.WaitForSingleObject(mutex, 0)
        if wait not in (0, 0x80):  # Signalled or abandoned by an exited process.
            kernel.CloseHandle(mutex)
            _JOB_LOCK.release()
            raise RuntimeError('busy')
        try:
            request_hash = hashlib.sha256(json.dumps([root_id, parts], separators=(',', ':')).encode()).hexdigest()
            job = {'job_id': job_id, 'status': 'running', 'scan_ids': [], 'errors': [],
                   'entries': 0, 'files': 0, 'bytes': 0, 'truncated': False}
            if not self.db.create_yara_job(job_id, request_hash, job):
                return self.db.get_yara_job(job_id)
            deadline = time.monotonic() + 60
            root, expected = self.roots[root_id]
            try:
                sources = tuple(yara.RuleSource(p.stem, p.read_text(encoding='utf-8'))
                                for p in sorted(_RULES.glob('*.yar')))
                if not sources:
                    raise ValueError('empty rule pack')
            except (OSError, UnicodeError, ValueError):
                job['status'] = 'incomplete'
                job['errors'].append('rule_pack_unavailable')
                self.db.update_yara_job(job_id, job)
                return job

            def stop(reason):
                job['truncated'] = True
                if reason not in job['errors']:
                    job['errors'].append(reason)

            def visit(current, depth):
                if job['truncated']:
                    return
                if time.monotonic() >= deadline:
                    stop('job_deadline')
                    return
                try:
                    with yara_files.pinned_path(root, current) as (path, _):
                        # Consume at most the remaining allowance plus one before sorting.
                        with os.scandir(path) as entries:
                            names = []
                            for entry in entries:
                                if time.monotonic() >= deadline:
                                    stop('job_deadline')
                                    break
                                if job['entries'] >= 1000:
                                    stop('entry_limit')
                                    break
                                job['entries'] += 1
                                names.append((entry.name, entry.is_dir(follow_symlinks=False)))
                        for name, directory in sorted(names, key=lambda item: item[0].casefold()):
                            if job['truncated']:
                                break
                            if time.monotonic() >= deadline:
                                stop('job_deadline')
                                break
                            try:
                                single = yara_files.relative_parts(name)
                                if len(single) != 1:
                                    raise yara_files.FileRejected('invalid_path')
                                child = current + single
                                if directory:
                                    if depth >= 4:
                                        stop('depth_limit')
                                    else:
                                        visit(child, depth + 1)
                                    continue
                                if job['files'] >= 100:
                                    stop('file_limit')
                                    break
                                job['files'] += 1
                                data = yara_files.read_snapshot(root, child, 128 * 1024 * 1024 - job['bytes'])
                                job['bytes'] += len(data)
                                remaining = int(deadline - time.monotonic())
                                if remaining < 1:
                                    stop('job_deadline')
                                    break
                                result = yara.scan_snapshot(data, sources, limits=yara.Limits(worker_seconds=min(20, remaining)))
                                self.db.save_yara_scan(result)
                                job['scan_ids'].append(result.scan_id)
                                if result.status not in ('match', 'no_match'):
                                    job['errors'].append('scan_' + result.status)
                                self.db.update_yara_job(job_id, job)
                            except yara_files.FileRejected as exc:
                                job['errors'].append(str(exc))
                except (OSError, yara_files.FileRejected):
                    job['errors'].append('directory_unavailable')

            try:
                with yara_files.pinned_path(root, ()) as (_, (_, _, info)):
                    if _root_identity(info) != expected:
                        raise yara_files.FileRejected('root_changed')
                    visit(parts, len(parts))
                job['status'] = 'incomplete' if job['truncated'] or job['errors'] else 'completed'
            except yara_files.FileRejected as exc:
                job['errors'].append(str(exc))
                job['status'] = 'incomplete'
            except Exception:
                job['errors'].append('internal_failure')
                job['status'] = 'incomplete'
            self.db.update_yara_job(job_id, job)
            return job
        finally:
            kernel.ReleaseMutex(mutex)
            kernel.CloseHandle(mutex)
            _JOB_LOCK.release()
