"""Bounded Windows file snapshots for explicitly registered YARA roots.

Directory handles pin every traversed component against rename and reject
reparse points. File bytes are read only from the validated, pinned handle.
"""
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
import ntpath
import os
from pathlib import Path
import re
import sys

from src.config import PROJECT_ROOT

ARCHIVES = {'.zip', '.rar', '.7z', '.gz', '.bz2', '.xz', '.tar', '.tgz', '.cab', '.iso'}
MAX_FILE = 16 * 1024 * 1024


class FileRejected(Exception):
    """A path or snapshot did not meet the admission contract."""


def relative_parts(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or len(value) > 1024 or '\x00' in value:
        raise FileRejected('invalid_path')
    if value in ('', '.'):
        return ()
    drive, _ = ntpath.splitdrive(value)
    parts = re.split(r'[/\\]', value)
    if drive or ntpath.isabs(value) or any(not p or p in ('.', '..') or ':' in p or p[-1] in '. ' for p in parts):
        raise FileRejected('invalid_path')
    if any(re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', p) for p in parts):
        raise FileRejected('invalid_path')
    return tuple(parts)


def validate_root(value: str) -> str:
    if sys.platform != 'win32':
        raise FileRejected('windows_only')
    if not isinstance(value, str) or not ntpath.isabs(value) or value.startswith(('\\\\', '//')):
        raise FileRejected('invalid_root')
    drive, tail = ntpath.splitdrive(value)
    if not re.fullmatch(r'[A-Za-z]:', drive) or not tail.strip('\\/'):
        raise FileRejected('invalid_root')
    relative_parts(tail.lstrip('\\/'))
    root = ntpath.normcase(ntpath.normpath(value))
    protected = [str(PROJECT_ROOT), os.environ.get('WINDIR', ''), os.environ.get('ProgramData', ''),
                 os.environ.get('ProgramFiles', ''), os.environ.get('ProgramFiles(x86)', ''),
                 *[str(Path.home() / name) for name in ('.ssh', '.aws', '.azure', '.gnupg', '.codex', '.agents')],
                 *[str(Path(base) / 'Microsoft' / name)
                   for base in (os.environ.get('APPDATA', ''), os.environ.get('LOCALAPPDATA', ''))
                   if base for name in ('Credentials', 'Protect')]]
    for item in filter(None, protected):
        item = ntpath.normcase(ntpath.normpath(item))
        try:
            common = ntpath.commonpath([root, item])
        except ValueError:
            continue
        if common in (root, item):
            raise FileRejected('protected_root')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel.GetDriveTypeW.restype = wintypes.UINT
    if kernel.GetDriveTypeW(drive + '\\') != 3:
        raise FileRejected('nonlocal_root')
    return root


class _Info(ctypes.Structure):
    _fields_ = [('attributes', wintypes.DWORD), ('created', wintypes.FILETIME),
                ('accessed', wintypes.FILETIME), ('written', wintypes.FILETIME),
                ('volume', wintypes.DWORD), ('size_high', wintypes.DWORD),
                ('size_low', wintypes.DWORD), ('links', wintypes.DWORD),
                ('index_high', wintypes.DWORD), ('index_low', wintypes.DWORD)]


def _api():
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                               wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Info)]
    k.GetFileInformationByHandle.restype = wintypes.BOOL
    k.GetFileType.argtypes = [wintypes.HANDLE]
    k.GetFileType.restype = wintypes.DWORD
    k.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    k.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k


def _info(k, handle):
    value = _Info()
    if not k.GetFileInformationByHandle(handle, ctypes.byref(value)):
        raise FileRejected('handle_info')
    return value


def _identity(info):
    return (info.volume, info.index_high, info.index_low, info.size_high, info.size_low,
            info.written.dwHighDateTime, info.written.dwLowDateTime, info.links, info.attributes)


@contextmanager
def open_checked(path: str, directory: bool):
    k = _api()
    # Allow writes to directories, never replacement; files deny write and delete.
    handle = k.CreateFileW(path, 0x80 if directory else 0x80000000, 3 if directory else 1,
                           None, 3, 0x00200000 | (0x02000000 if directory else 0), None)
    if handle == wintypes.HANDLE(-1).value:
        raise FileRejected('open_failed')
    try:
        info = _info(k, handle)
        if (k.GetFileType(handle) != 1 or info.attributes & (0x400 | 0x40)
                or bool(info.attributes & 0x10) != directory):
            raise FileRejected('reparse_or_type')
        if not directory and info.links != 1:
            raise FileRejected('hardlink')
        buffer = ctypes.create_unicode_buffer(32768)
        n = k.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        final = buffer.value
        if not n or n >= len(buffer) or not final.startswith('\\\\?\\'):
            raise FileRejected('final_path')
        if ntpath.normcase(ntpath.normpath(final[4:])) != ntpath.normcase(ntpath.normpath(path)):
            raise FileRejected('final_path')
        yield k, handle, info
    finally:
        k.CloseHandle(handle)


@contextmanager
def pinned_path(root: str, parts: tuple[str, ...], *, file: bool = False):
    """Pin all ancestors, checking each component and its final handle path."""
    root = validate_root(root)
    drive, tail = ntpath.splitdrive(root)
    components = tuple(p for p in tail.split('\\') if p) + parts
    current = drive + '\\'
    with ExitStack() as stack:
        opened = None
        for index, part in enumerate(components):
            current = ntpath.join(current, part)
            opened = stack.enter_context(open_checked(current, not (file and index == len(components)-1)))
        if opened is None:
            raise FileRejected('invalid_root')
        yield current, opened


def read_snapshot(root: str, parts: tuple[str, ...], remaining: int) -> bytes:
    if not parts or ntpath.splitext(parts[-1])[1].lower() in ARCHIVES:
        raise FileRejected('archive_or_invalid_file')
    with pinned_path(root, parts, file=True) as (_, (k, handle, before)):
        size = (before.size_high << 32) | before.size_low
        cap = min(MAX_FILE, remaining)
        if size > cap:
            raise FileRejected('size_limit')
        k.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        k.ReadFile.restype = wintypes.BOOL
        chunks, total = [], 0
        while True:
            buf = ctypes.create_string_buffer(min(65536, cap - total + 1))
            count = wintypes.DWORD()
            if not k.ReadFile(handle, buf, len(buf), ctypes.byref(count), None):
                raise FileRejected('read_failed')
            if not count.value:
                break
            total += count.value
            if total > cap:
                raise FileRejected('size_limit')
            chunks.append(buf.raw[:count.value])
        if total != size or _identity(before) != _identity(_info(k, handle)):
            raise FileRejected('file_changed')
        return b''.join(chunks)
