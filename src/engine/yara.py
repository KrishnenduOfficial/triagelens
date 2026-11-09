"""Optional, offline YARA-X snapshot scanner (T3.2, ADR-065).

``scan_snapshot(b'harmless bytes', (RuleSource('example', source_text),))``
compiles and scans in a fresh Windows AppContainer/Job Object. Only immutable
bytes and reviewed text rules are accepted. This module never opens sample paths,
executes samples, extracts archives, persists detections or contacts providers.
Root registration, safe file acquisition and hash linking belong to T3.4.
No-match applies only to this snapshot and pack; it is not a benign verdict.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
import json
import re
import threading
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from typing import Literal

from src.engine.attack import rule_techniques


ENGINE_VERSION = '1.22.1'
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
_ADMISSION = threading.Lock()
_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,127}$')


@dataclass(frozen=True)
class Limits:
    file_bytes: int = MAX_FILE_BYTES
    compile_seconds: int = 10
    scan_seconds: int = 5
    worker_seconds: int = 20
    memory_bytes: int = 512 * 1024 * 1024
    cpu_seconds: int = 10
    occurrences_per_pattern: int = 100
    occurrences_per_file: int = 1000
    response_bytes: int = MAX_RESPONSE_BYTES

    def __post_init__(self):
        # Callers may tighten bounds, never silently disable them.
        for name, value in asdict(self).items():
            ceiling = self.__dataclass_fields__[name].default
            if type(value) is not int or not 0 < value <= ceiling:
                raise ValueError('Limits must be positive integers within ADR-065 defaults')


@dataclass(frozen=True)
class RuleSource:
    namespace: str
    text: str


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Diagnostic(_Strict):
    category: str = Field(pattern=r'^[A-Za-z0-9_]{1,64}$')
    source: int | None = Field(default=None, ge=0, lt=30)
    line: int | None = Field(default=None, ge=1, le=MAX_SOURCE_BYTES + 1)


class Occurrence(_Strict):
    pattern: str = Field(pattern=r'^\$[A-Za-z0-9_]{0,128}$')
    offset: int = Field(ge=0, le=MAX_FILE_BYTES)
    length: int = Field(ge=0, le=MAX_FILE_BYTES)


class Match(_Strict):
    namespace: str = Field(pattern=r'^[A-Za-z_][A-Za-z0-9_]{0,127}$')
    rule: str = Field(pattern=r'^[A-Za-z_][A-Za-z0-9_]{0,127}$')
    source_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    metadata: dict[str, str]
    occurrences: list[Occurrence] = Field(max_length=1000)
    technique_ids: list[str] = Field(default_factory=list, max_length=100)
    invalid_technique_ids: list[str] = Field(default_factory=list, max_length=100)


class WorkerResult(_Strict):
    status: Literal['match', 'no_match', 'compile_error', 'timeout',
                    'resource_exhausted', 'worker_failure', 'truncated']
    diagnostics: list[Diagnostic] = Field(default_factory=list, max_length=30)
    matches: list[Match] = Field(default_factory=list, max_length=30)


@dataclass(frozen=True)
class ScanResult:
    scan_id: str
    status: str
    sha256: str | None
    size: int | None
    started_at: str
    ended_at: str
    engine: str
    version: str | None
    pack_digest: str | None
    limits: Limits
    diagnostics: tuple[Diagnostic, ...]
    matches: tuple[Match, ...]


def _pack(sources: tuple[RuleSource, ...]) -> list[dict]:
    if not isinstance(sources, tuple) or not 1 <= len(sources) <= 30:
        raise ValueError('Expected 1..30 reviewed rule sources')
    total, patterns, seen, output = 0, 0, set(), []
    for item in sources:
        if (not isinstance(item, RuleSource) or not isinstance(item.namespace, str)
                or not _IDENTIFIER.fullmatch(item.namespace) or item.namespace in seen
                or not isinstance(item.text, str)):
            raise ValueError('Invalid or duplicate rule namespace')
        raw = item.text.encode('utf-8')
        total += len(raw)
        if total > MAX_SOURCE_BYTES:
            raise ValueError('Rule source limit exceeded')
        # Intentionally conservative admission: keywords even in comments/strings
        # are rejected. Native compilation remains inside the restricted worker.
        if re.search(r'\b(?:include|import)\b', item.text):
            raise ValueError('Includes and module imports are disabled')
        if len(re.findall(r'\brule\b', item.text)) != 1:
            raise ValueError('Exactly one rule per namespace is required')
        patterns += len(re.findall(r'\$[A-Za-z0-9_]*\s*=', item.text))
        if patterns > 10_000:
            raise ValueError('Pattern limit exceeded')
        seen.add(item.namespace)
        output.append({'namespace': item.namespace, 'text': item.text,
                       'digest': hashlib.sha256(raw).hexdigest()})
    return output


def _engine_version() -> str | None:
    try:
        if importlib.util.find_spec('yara_x') is None:
            return None
        return importlib.metadata.version('yara-x')
    except (ImportError, ValueError, importlib.metadata.PackageNotFoundError):
        return None


def _validate_response(raw: bytes, pack: list[dict], size: int, limits: Limits) -> WorkerResult:
    if len(raw) > limits.response_bytes:
        raise ValueError('Oversized worker result')
    result = WorkerResult.model_validate_json(raw)
    if ((result.status == 'match' and not result.matches)
            or (result.status not in ('match', 'truncated') and result.matches)):
        raise ValueError('Inconsistent worker status')
    entries, seen, count = {p['namespace']: p for p in pack}, set(), 0
    matches, diagnostics = [], list(result.diagnostics)
    for match in result.matches:
        item = entries.get(match.namespace)
        if item is None or match.source_digest != item['digest'] or match.namespace in seen:
            raise ValueError('Unexpected rule provenance')
        seen.add(match.namespace)
        meta = match.metadata
        required = {'id', 'author', 'source', 'revision', 'license'}
        if (not required.issubset(meta) or set(meta) - required - {'mitre_attack'}
                or any(not v.strip() or len(v) > 256 or any(ord(c) < 32 for c in v)
                       for v in meta.values())):
            raise ValueError('Invalid rule metadata')
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', meta['id']):
            raise ValueError('Invalid rule identity')
        if not re.fullmatch(r'https://[^\s]{1,240}', meta['source']):
            raise ValueError('Invalid source reference')
        per_pattern = {}
        for occurrence in match.occurrences:
            if occurrence.offset + occurrence.length > size:
                raise ValueError('Occurrence outside snapshot')
            per_pattern[occurrence.pattern] = per_pattern.get(occurrence.pattern, 0) + 1
            if per_pattern[occurrence.pattern] > limits.occurrences_per_pattern:
                raise ValueError('Too many pattern occurrences')
            count += 1
        ids = meta.get('mitre_attack')
        valid, invalid = rule_techniques('yara', ids.split(',') if ids else [])
        if not ids or invalid:
            diagnostics.append(Diagnostic(category='missing_attack_metadata' if not ids else 'invalid_attack_metadata',
                                          source=pack.index(item)))
        matches.append(match.model_copy(update={'technique_ids': valid,
                                                'invalid_technique_ids': invalid}))
    if count > limits.occurrences_per_file:
        raise ValueError('Too many occurrences')
    return result.model_copy(update={'matches': matches, 'diagnostics': diagnostics})


def scan_snapshot(data: bytes, sources: tuple[RuleSource, ...], *, limits: Limits | None = None) -> ScanResult:
    """Scan one immutable file snapshot, without granting the worker file access.

    Busy admission is per process. No public runner injection or unrestricted
    execution mode exists. Missing engine/isolation returns unavailable states.
    """
    limits = limits or Limits()
    started = datetime.now(timezone.utc).isoformat()
    scan_id, digest, size, pack_digest, version = str(uuid4()), None, None, None, None

    def finish(status, category=None, result=None):
        return ScanResult(scan_id, status, digest, size, started,
                          datetime.now(timezone.utc).isoformat(), 'yara-x', version,
                          pack_digest, limits,
                          tuple(result.diagnostics) if result else ((Diagnostic(category=category),) if category else ()),
                          tuple(result.matches) if result else ())

    if not _ADMISSION.acquire(blocking=False):
        return finish('busy', 'busy')
    try:
        if type(data) is not bytes or len(data) > limits.file_bytes:
            return finish('rejected', 'invalid_snapshot')
        # Common archive signatures are rejected; no decoding/extraction occurs.
        if data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08', b'\x1f\x8b', b'7z\xbc\xaf\x27\x1c', b'Rar!', b'BZh', b'\xfd7zXZ\x00')) or data[257:262] == b'ustar':
            return finish('rejected', 'archive')
        digest, size = hashlib.sha256(data).hexdigest(), len(data)
        try:
            pack = _pack(sources)
        except (ValueError, UnicodeError):
            return finish('rejected', 'invalid_rule_pack')
        pack_digest = hashlib.sha256(json.dumps(pack, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        version = _engine_version()
        if version is None:
            return finish('missing_engine', 'missing_engine')
        if version != ENGINE_VERSION:
            return finish('unavailable', 'unsupported_engine_version')
        from src.engine.yara_windows import run_worker, IsolationUnavailable, WorkerStopped
        try:
            raw = run_worker(data, pack, limits)
            result = _validate_response(raw, pack, size, limits)
        except IsolationUnavailable:
            return finish('unavailable', 'isolation_unavailable')
        except WorkerStopped as exc:
            return finish(exc.status, exc.category)
        except (ValueError, ValidationError, TypeError, KeyError):
            return finish('worker_failure', 'invalid_response')
        return finish(result.status, result=result)
    finally:
        _ADMISSION.release()
