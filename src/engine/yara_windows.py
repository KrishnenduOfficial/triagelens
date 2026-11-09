"""Windows AppContainer + Job Object launcher for the optional YARA worker.

OS API contracts: Microsoft UpdateProcThreadAttribute, SECURITY_CAPABILITIES,
JOBOBJECT_EXTENDED_LIMIT_INFORMATION. No network capabilities or loopback
exemptions are granted. Only a private runtime copy receives read/execute ACLs;
the input root, repository, database and environment are never granted to it.
Unsupported platforms or setup failures fail closed. No unrestricted fallback.
"""

from dataclasses import asdict
import base64
import ctypes as C
from ctypes import wintypes as W
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4
import zipfile


class IsolationUnavailable(Exception):
    pass


class WorkerStopped(Exception):
    def __init__(self, status, category):
        self.status, self.category = status, category


class _SecurityCapabilities(C.Structure):
    _fields_ = [('sid', C.c_void_p), ('capabilities', C.c_void_p),
                ('count', W.DWORD), ('reserved', W.DWORD)]


class _Startup(C.Structure):
    _fields_ = [('cb', W.DWORD), ('reserved', W.LPWSTR), ('desktop', W.LPWSTR),
                ('title', W.LPWSTR), ('x', W.DWORD), ('y', W.DWORD),
                ('width', W.DWORD), ('height', W.DWORD), ('xchars', W.DWORD),
                ('ychars', W.DWORD), ('fill', W.DWORD), ('flags', W.DWORD),
                ('show', W.WORD), ('reserved2_size', W.WORD),
                ('reserved2', C.c_void_p), ('stdin', W.HANDLE),
                ('stdout', W.HANDLE), ('stderr', W.HANDLE)]


class _StartupEx(C.Structure):
    _fields_ = [('startup', _Startup), ('attributes', C.c_void_p)]


class _Process(C.Structure):
    _fields_ = [('process', W.HANDLE), ('thread', W.HANDLE),
                ('pid', W.DWORD), ('tid', W.DWORD)]


class _Security(C.Structure):
    _fields_ = [('length', W.DWORD), ('descriptor', C.c_void_p), ('inherit', W.BOOL)]


class _BasicLimits(C.Structure):
    _fields_ = [('process_time', C.c_longlong), ('job_time', C.c_longlong),
                ('flags', W.DWORD), ('min_ws', C.c_size_t), ('max_ws', C.c_size_t),
                ('active', W.DWORD), ('affinity', C.c_size_t),
                ('priority', W.DWORD), ('scheduling', W.DWORD)]


class _ExtendedLimits(C.Structure):
    _fields_ = [('basic', _BasicLimits), ('io', C.c_ulonglong * 6),
                ('process_memory', C.c_size_t), ('job_memory', C.c_size_t),
                ('peak_process', C.c_size_t), ('peak_job', C.c_size_t)]


class _API:
    def __init__(self):
        if sys.platform != 'win32':
            raise IsolationUnavailable()
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.u = C.WinDLL('userenv', use_last_error=True)
        self.a = C.WinDLL('advapi32', use_last_error=True)
        P, D, H, S = C.c_void_p, W.DWORD, W.HANDLE, C.c_size_t
        signatures = {
            'CreateJobObjectW': ([P, W.LPCWSTR], H),
            'SetInformationJobObject': ([H, C.c_int, P, D], W.BOOL),
            'CreatePipe': ([C.POINTER(H), C.POINTER(H), P, D], W.BOOL),
            'SetHandleInformation': ([H, D, D], W.BOOL),
            'InitializeProcThreadAttributeList': ([P, D, D, C.POINTER(S)], W.BOOL),
            'UpdateProcThreadAttribute': ([P, D, S, P, S, P, P], W.BOOL),
            'DeleteProcThreadAttributeList': ([P], None),
            'CreateProcessW': ([W.LPCWSTR, W.LPWSTR, P, P, W.BOOL, D, P, W.LPCWSTR, P, P], W.BOOL),
            'ResumeThread': ([H], D), 'CloseHandle': ([H], W.BOOL),
            'TerminateJobObject': ([H, W.UINT], W.BOOL),
            'WaitForSingleObject': ([H, D], D),
            'GetExitCodeProcess': ([H, C.POINTER(D)], W.BOOL),
            'PeekNamedPipe': ([H, P, D, P, C.POINTER(D), P], W.BOOL),
            'ReadFile': ([H, P, D, C.POINTER(D), P], W.BOOL),
            'WriteFile': ([H, P, D, C.POINTER(D), P], W.BOOL),
            'LocalFree': ([P], P),
            'IsProcessInJob': ([H, H, C.POINTER(W.BOOL)], W.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.k, name)
            function.argtypes, function.restype = args, result
        self.u.CreateAppContainerProfile.argtypes = [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, P, D, C.POINTER(P)]
        self.u.CreateAppContainerProfile.restype = C.c_long
        self.u.DeleteAppContainerProfile.argtypes = [W.LPCWSTR]
        self.u.DeleteAppContainerProfile.restype = C.c_long
        self.a.FreeSid.argtypes, self.a.FreeSid.restype = [P], P
        self.a.ConvertSidToStringSidW.argtypes = [P, C.POINTER(W.LPWSTR)]
        self.a.ConvertSidToStringSidW.restype = W.BOOL
        self.a.OpenProcessToken.argtypes = [H, D, C.POINTER(H)]
        self.a.OpenProcessToken.restype = W.BOOL
        self.a.GetTokenInformation.argtypes = [H, C.c_int, P, D, C.POINTER(D)]
        self.a.GetTokenInformation.restype = W.BOOL
        self.a.EqualSid.argtypes, self.a.EqualSid.restype = [P, P], W.BOOL

    @staticmethod
    def check(value):
        if not value:
            raise IsolationUnavailable()
        return value


def _stage_runtime(root: Path):
    """Copy trusted interpreter/stdlib and pinned extension, never project data.

    The temporary tree is disposable; no ACL on the installed runtime changes.
    An isolated ._pth file excludes site initialization and all external imports.
    """
    base = Path(sys.base_prefix)
    for name in ('python.exe', 'python3.dll', f'python{sys.version_info.major}{sys.version_info.minor}.dll'):
        shutil.copyfile(base / name, root / name)
    for path in base.glob('vcruntime*.dll'):
        shutil.copyfile(path, root / path.name)
    dlls = root / 'DLLs'
    dlls.mkdir()
    for path in (base / 'DLLs').iterdir():
        if path.suffix.lower() in ('.pyd', '.dll') and path.is_file():
            shutil.copyfile(path, dlls / path.name)
    excluded = {'site-packages', 'test', 'tests', 'idlelib', 'tkinter', 'turtledemo', 'ensurepip', '__pycache__'}
    with zipfile.ZipFile(root / 'stdlib.zip', 'w', compression=zipfile.ZIP_STORED) as archive:
        count = total = 0
        for folder, directories, files in os.walk(base / 'Lib', followlinks=False):
            directories[:] = [d for d in directories if d not in excluded and not (Path(folder) / d).is_symlink()]
            for name in files:
                path = Path(folder) / name
                if path.suffix != '.py' or path.is_symlink():
                    continue
                count += 1
                total += path.stat().st_size
                if count > 3000 or total > 64 * 1024 * 1024:
                    raise IsolationUnavailable()
                archive.write(path, str(path.relative_to(base / 'Lib')))
    (root / 'python._pth').write_text('stdlib.zip\nDLLs\n.\n', encoding='ascii')
    spec = importlib.util.find_spec('yara_x')
    if spec is None or not spec.origin:
        raise IsolationUnavailable()
    package = Path(spec.origin).parent
    (root / 'yara_x').mkdir()
    for name in ('__init__.py', 'yara_x.pyd'):
        shutil.copyfile(package / name, root / 'yara_x' / name)
    shutil.copyfile(Path(__file__).with_name('yara_worker.py'), root / 'worker.py')


class _Sandbox:
    """Private OS launcher; caller supplies only trusted worker entrypoints."""

    def __init__(self, runtime: Path, limits):
        self.api, self.runtime, self.limits = _API(), runtime, limits
        self.handles, self.sid, self.attributes = [], C.c_void_p(), None
        self.process, self.job, self.writer = _Process(), None, None
        self.profile = None

    def _own(self, handle):
        self.api.check(handle)
        self.handles.append(handle)
        return handle

    def _close(self, handle):
        if handle in self.handles:
            self.api.k.CloseHandle(handle)
            self.handles.remove(handle)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        k = self.api.k
        if self.job:
            k.TerminateJobObject(self.job, 1)
        if self.process.process:
            k.WaitForSingleObject(self.process.process, 5000)
        if self.writer:
            self.writer.join(timeout=5)
        for handle in self.handles[:]:
            self._close(handle)
        if self.attributes:
            k.DeleteProcThreadAttributeList(self.attributes)
        if self.sid:
            self.api.a.FreeSid(self.sid)
        if self.profile:
            self.api.u.DeleteAppContainerProfile(self.profile)

    def start(self, arguments):
        api, k = self.api, self.api.k
        # Fresh identity: never adopt an existing profile or loopback exemption.
        # Only a profile created successfully here is owned and removed here.
        profile = 'TriageLens.' + uuid4().hex
        if api.u.CreateAppContainerProfile(profile, profile, 'Disposable YARA worker', None, 0, C.byref(self.sid)) != 0:
            raise IsolationUnavailable()
        self.profile = profile
        sid_text = W.LPWSTR()
        api.check(api.a.ConvertSidToStringSidW(self.sid, C.byref(sid_text)))
        try:
            result = subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32' / 'icacls.exe'),
                                     str(self.runtime), '/grant', '*' + sid_text.value + ':(OI)(CI)(RX)', '/Q'],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=10, creationflags=0x08000000)
            if result.returncode:
                raise IsolationUnavailable()
        finally:
            k.LocalFree(C.cast(sid_text, C.c_void_p))
        self.job = self._own(k.CreateJobObjectW(None, None))
        info = _ExtendedLimits()
        # KILL_ON_JOB_CLOSE | ACTIVE_PROCESS | PROCESS_TIME | PROCESS_MEMORY | JOB_MEMORY.
        info.basic.flags = 0x2000 | 0x8 | 0x2 | 0x100 | 0x200
        info.basic.active, info.basic.process_time = 1, self.limits.cpu_seconds * 10_000_000
        info.process_memory = info.job_memory = self.limits.memory_bytes
        api.check(k.SetInformationJobObject(self.job, 9, C.byref(info), C.sizeof(info)))
        security = _Security(C.sizeof(_Security), None, True)
        child_in, parent_in, parent_out, child_out = (W.HANDLE() for _ in range(4))
        api.check(k.CreatePipe(C.byref(child_in), C.byref(parent_in), C.byref(security), 0))
        self._own(child_in.value)
        self.input = self._own(parent_in.value)
        api.check(k.CreatePipe(C.byref(parent_out), C.byref(child_out), C.byref(security), 0))
        self.output = self._own(parent_out.value)
        self._own(child_out.value)
        api.check(k.SetHandleInformation(self.input, 1, 0))
        api.check(k.SetHandleInformation(self.output, 1, 0))
        length = C.c_size_t()
        k.InitializeProcThreadAttributeList(None, 3, 0, C.byref(length))
        self.attribute_buffer = C.create_string_buffer(length.value)
        self.attributes = C.cast(self.attribute_buffer, C.c_void_p)
        api.check(k.InitializeProcThreadAttributeList(self.attributes, 3, 0, C.byref(length)))
        capabilities = _SecurityCapabilities(self.sid, None, 0, 0)
        handles = (W.HANDLE * 2)(child_in.value, child_out.value)
        jobs = (W.HANDLE * 1)(self.job)
        for attribute, value in ((0x20009, capabilities), (0x20002, handles), (0x2000D, jobs)):
            api.check(k.UpdateProcThreadAttribute(self.attributes, 0, attribute, C.byref(value), C.sizeof(value), None, None))
        startup = _StartupEx()
        startup.startup.cb = C.sizeof(startup)
        startup.startup.flags = 0x100  # STARTF_USESTDHANDLES
        startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = child_in.value, child_out.value, child_out.value
        startup.attributes = self.attributes
        executable = str(self.runtime / 'python.exe')
        command = C.create_unicode_buffer(subprocess.list2cmdline([executable, '-I', '-S', '-B', '-X', 'utf8', *arguments]))
        # Secrets, PATH, PYTHONPATH, proxy variables and credentials are excluded.
        # LOCALAPPDATA is needed by Windows to resolve the new profile; Windows
        # redirects it to that profile for the child. It grants no filesystem ACL.
        environment = C.create_unicode_buffer('LOCALAPPDATA=' + os.environ['LOCALAPPDATA']
                                              + '\0SystemRoot=' + os.environ['SystemRoot'] + '\0\0')
        flags = 0x00080000 | 0x00000400 | 0x00000004 | 0x08000000
        api.check(k.CreateProcessW(executable, command, None, None, True, flags,
                                  environment, str(self.runtime), C.byref(startup), C.byref(self.process)))
        self._own(self.process.process)
        self._own(self.process.thread)
        self._close(child_in.value)
        self._close(child_out.value)
        token = W.HANDLE()
        api.check(api.a.OpenProcessToken(self.process.process, 0x8, C.byref(token)))
        self._own(token.value)
        returned, is_container = W.DWORD(), W.DWORD()
        api.check(api.a.GetTokenInformation(token, 29, C.byref(is_container), C.sizeof(is_container), C.byref(returned)))
        package_info = C.create_string_buffer(256)
        api.check(api.a.GetTokenInformation(token, 31, package_info, len(package_info), C.byref(returned)))
        package_sid = C.cast(package_info, C.POINTER(C.c_void_p))[0]
        in_job = W.BOOL()
        api.check(k.IsProcessInJob(self.process.process, self.job, C.byref(in_job)))
        if not is_container.value or not in_job.value or not api.a.EqualSid(package_sid, self.sid):
            raise IsolationUnavailable()
        self._close(token.value)
        # Job-list assignment is atomic with creation: no orphan window exists
        # between process creation and resource containment, even on parent exit.
        if k.ResumeThread(self.process.thread) == 0xffffffff:
            raise IsolationUnavailable()

    def communicate(self, payload: bytes, *, response_bytes: int, seconds: float, compile_seconds: float):
        k, started = self.api.k, time.monotonic()
        errors = []

        def write():
            try:
                for offset in range(0, len(payload), 65536):
                    block = payload[offset:offset + 65536]
                    written = W.DWORD()
                    if not k.WriteFile(self.input, block, len(block), C.byref(written), None) or written.value != len(block):
                        errors.append(True)
                        break
            finally:
                self._close(self.input)

        self.writer = threading.Thread(target=write, daemon=True)
        self.writer.start()
        buffer, compiled, final = bytearray(), False, None
        while True:
            elapsed = time.monotonic() - started
            if elapsed >= seconds or (not compiled and elapsed >= compile_seconds):
                raise WorkerStopped('timeout', 'worker_deadline' if elapsed >= seconds else 'compile_deadline')
            available = W.DWORD()
            ok = k.PeekNamedPipe(self.output, None, 0, None, C.byref(available), None)
            if ok and available.value:
                block = C.create_string_buffer(min(available.value, 65536))
                read = W.DWORD()
                if not k.ReadFile(self.output, block, len(block), C.byref(read), None):
                    raise WorkerStopped('worker_failure', 'ipc_read')
                buffer.extend(block.raw[:read.value])
                if len(buffer) > response_bytes + 64:
                    raise WorkerStopped('worker_failure', 'oversized_response')
                while b'\n' in buffer:
                    line, _, remaining = buffer.partition(b'\n')
                    buffer = bytearray(remaining)
                    try:
                        frame = json.loads(line)
                    except (ValueError, UnicodeError):
                        raise WorkerStopped('worker_failure', 'malformed_response') from None
                    if frame == {'phase': 'compiled'} and not compiled and final is None:
                        compiled = True
                    elif isinstance(frame, dict) and set(frame) == {'result'} and final is None:
                        if (isinstance(frame['result'], dict)
                                and frame['result'].get('status') in ('match', 'no_match', 'truncated') and not compiled):
                            raise WorkerStopped('worker_failure', 'invalid_protocol')
                        final = json.dumps(frame['result'], separators=(',', ':'), ensure_ascii=True).encode()
                    else:
                        raise WorkerStopped('worker_failure', 'invalid_protocol')
            if k.WaitForSingleObject(self.process.process, 0) == 0:
                # Drain the pipe before accepting exit; stale bytes cannot pass.
                if ok and available.value:
                    continue
                code = W.DWORD()
                self.api.check(k.GetExitCodeProcess(self.process.process, C.byref(code)))
                if code.value in (0xc0000044, 0xc0000017, 0xc000012d):
                    raise WorkerStopped('resource_exhausted', 'os_resource_limit')
                if code.value or final is None or buffer or errors:
                    raise WorkerStopped('worker_failure', 'worker_exit')
                return final
            time.sleep(0.01)


def run_worker(data: bytes, sources: list[dict], limits) -> bytes:
    if sys.platform != 'win32':
        raise IsolationUnavailable()
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='triagelens-yara-') as directory:
            runtime = Path(directory).resolve()
            if runtime.parent != Path(tempfile.gettempdir()).resolve():
                raise IsolationUnavailable()
            _stage_runtime(runtime)
            payload = json.dumps({'data': base64.b64encode(data).decode('ascii'),
                                  'sources': sources, 'limits': asdict(limits)},
                                 ensure_ascii=True, separators=(',', ':')).encode()
            if len(payload) > 24 * 1024 * 1024:
                raise WorkerStopped('worker_failure', 'oversized_request')
            with _Sandbox(runtime, limits) as sandbox:
                sandbox.start(['worker.py'])
                remaining = min(limits.worker_seconds, 60 - (time.monotonic() - started))
                if remaining <= 0:
                    raise WorkerStopped('timeout', 'job_deadline')
                return sandbox.communicate(payload, response_bytes=limits.response_bytes,
                                           seconds=remaining, compile_seconds=limits.compile_seconds)
    except (OSError, AttributeError, subprocess.SubprocessError):
        raise IsolationUnavailable() from None
