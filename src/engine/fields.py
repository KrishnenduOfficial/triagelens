"""Small OCSF-inspired telemetry view; this is not an OCSF implementation.

Paths are tuples of literal keys: a dotted EVTX Details key is one segment.
Only declared paths are read. No labels, provenance, XML or rule results are
searched, and neither source records nor inference inputs are modified.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Mapping


Path = tuple[str, ...]


@dataclass(frozen=True)
class FieldMapping:
    kind: Literal["text", "code", "pid", "port"]
    paths: tuple[Path, ...]
    event_paths: tuple[tuple[str, tuple[Path, ...]], ...] = ()


def _event_data(*names: str) -> tuple[Path, ...]:
    """Ordered aliases across flat JSON, adapter Details and exported objects."""
    return tuple(path for name in names for path in (
        (name,), ("Details", f"EventData.{name}"), ("EventData", name),
        ("Event", "EventData", name),
    ))


def _system(name: str) -> tuple[Path, ...]:
    return (("System", name), ("Event", "System", name))


# Primary user follows the existing correlation/EVTX selection order; it does
# not assert that the selected account is the actor. Explicit roles stay apart.
FIELD_MAPPINGS: Mapping[str, FieldMapping] = MappingProxyType({
    "metadata.event_code": FieldMapping("code", (
        ("EventID",), ("EventId",), ("EventCode",), *_system("EventID"),
    )),
    "metadata.log_name": FieldMapping("text", (("Channel",), *_system("Channel"))),
    "device.hostname": FieldMapping("text", (
        *((name,) for name in ("host", "hostname", "computer_name", "computername",
                              "computer", "workstation", "device_name")),
        *_system("Computer"),
    )),
    "user.name": FieldMapping("text", (
        *((name,) for name in ("user", "username", "target_user_name", "subject_user_name",
                              "targetusername", "subjectusername", "account_name")),
        *_event_data("User", "TargetUserName", "SubjectUserName"),
    )),
    "actor.user.name": FieldMapping("text", _event_data("SubjectUserName")),
    "target.user.name": FieldMapping("text", _event_data("TargetUserName")),
    "process.file.path": FieldMapping("text", _event_data("Image", "NewProcessName"),
                                      (("4688", _event_data("NewProcessName")),)),
    "process.cmd_line": FieldMapping("text", _event_data("CommandLine")),
    "process.pid": FieldMapping("pid", _event_data("NewProcessId", "ProcessId"),
                                (("4688", _event_data("NewProcessId")),)),
    "process.parent_process.file.path": FieldMapping("text", _event_data("ParentImage", "ParentProcessName")),
    "process.parent_process.pid": FieldMapping("pid", _event_data("ParentProcessId", "CreatorProcessId"),
                                               (("4688", _event_data("ProcessId")),)),
    "src_endpoint.ip": FieldMapping("text", _event_data("SourceIp", "IpAddress")),
    "src_endpoint.port": FieldMapping("port", _event_data("SourcePort", "IpPort")),
    "dst_endpoint.ip": FieldMapping("text", _event_data("DestinationIp")),
    "dst_endpoint.port": FieldMapping("port", _event_data("DestinationPort")),
})


def _lookup(record: Mapping[str, Any], path: Path) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, Mapping):
            return None
        if key in current:
            current = current[key]
        else:
            matches = [value for name, value in current.items()
                       if isinstance(name, str) and name.casefold() == key.casefold()]
            # Do not choose an arbitrary value from case-colliding keys.
            if len(matches) != 1:
                return None
            current = matches[0]
    return current


def _typed(value: Any, kind: str) -> str | int | None:
    if kind == "text":
        return value if isinstance(value, str) and value.strip() else None
    if kind == "code":
        if isinstance(value, str) and value.strip():
            return value.strip()
        return str(value) if type(value) is int and 0 <= value < 2**63 else None
    if isinstance(value, str):
        text = value.strip()
        if kind == "pid" and text[:2].lower() == "0x":
            digits, base = text[2:], 16
            allowed = "0123456789abcdefABCDEF"
        else:
            digits, base, allowed = text, 10, "0123456789"
        # Bound conversion work, and reject signs, floats, booleans and junk.
        if not digits or len(digits) > 19 or any(char not in allowed for char in digits):
            return None
        value = int(digits, base)
    upper = 65535 if kind == "port" else 2**63 - 1
    return value if type(value) is int and 0 <= value <= upper else None


def resolve_field(record: Mapping[str, Any], name: str) -> str | int | None:
    """First valid declared alias wins; unknown/missing fields return None.

    Canonical names are case insensitive. Explicit canonical nested/literal
    input precedes source aliases. Keys prefer exact matches, then a unique
    case-insensitive match. Container values are never stringified or traversed
    beyond a declared path. Text is preserved; PID/port conversion is explicit.
    """
    name = name.lower()
    mapping = FIELD_MAPPINGS.get(name)
    if mapping is None:
        return None
    paths = mapping.paths
    if mapping.event_paths:
        code = resolve_field(record, "metadata.event_code")
        paths = next((paths for event, paths in mapping.event_paths if event == code), paths)
    for path in (tuple(name.split(".")), (name,), *paths):
        value = _typed(_lookup(record, path), mapping.kind)
        if value is not None:
            return value
    return None


def canonical_fields(record: Mapping[str, Any]) -> dict[str, str | int]:
    """Return a fresh flat projection for local consumers, including future Sigma."""
    return {name: value for name in FIELD_MAPPINGS
            if (value := resolve_field(record, name)) is not None}
