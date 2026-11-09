"""Bounded Windows EVTX intake; source paths remain local provenance.

The native parser buffers one EVTX chunk, and this adapter retains one alert
batch. Parser errors count failed parser operations (possibly whole chunks),
not an inferred number of lost records. No dataset labels are inferred here.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Protocol
import xml.etree.ElementTree as ET

from src.models.alert import NormalizedAlert

logger = logging.getLogger(__name__)


class RecordParser(Protocol):
    def records(self) -> Iterator[dict]: ...


@dataclass
class EvtxIntakeStats:
    """Cumulative counters for one adapter; no paths or record values."""

    files_seen: int = 0
    files_failed: int = 0
    records_seen: int = 0
    alerts_emitted: int = 0
    parser_errors: int = 0
    normalization_errors: int = 0
    missing_timestamps: int = 0
    invalid_timestamps: int = 0


def _native_parser(stream: BinaryIO) -> RecordParser:
    from evtx import PyEvtxParser

    return PyEvtxParser(
        stream, number_of_threads=1, skip_errors=False,
        recover_records=False, validate_checksums=True,
    )


def _name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _child(element: ET.Element, name: str) -> ET.Element | None:
    return next((child for child in element if _name(child) == name), None)


def _text(element: ET.Element | None) -> str | None:
    return element.text.strip() if element is not None and element.text else None


def _flatten(element: ET.Element) -> dict[str, str | None]:
    """Flatten named Data and UserData leaves without overwriting duplicates.

    Escape path delimiters in source names so a dotted name and a nested path
    remain distinct. Repeated siblings receive zero-based bracket indices.
    """
    result: dict[str, str | None] = {}

    def visit(node: ET.Element, path: str, depth: int) -> None:
        if depth > 32:
            raise ValueError("EVTX event data exceeds depth limit")
        children = list(node)
        if not children:
            result[path] = node.text
            return
        names = [child.get("Name") or _name(child) for child in children]
        totals: dict[str, int] = {}
        for name in names:
            totals[name] = totals.get(name, 0) + 1
        positions: dict[str, int] = {}
        for child, name in zip(children, names):
            segment = (name.replace("\\", "\\\\").replace(".", "\\.")
                       .replace("[", "\\[").replace("]", "\\]"))
            index = positions.get(name, 0)
            positions[name] = index + 1
            if totals[name] > 1:
                segment += f"[{index}]"
            visit(child, f"{path}.{segment}" if path else segment, depth + 1)

    visit(element, "", 0)
    return result


class EvtxIntakeEngine:
    """Stream normalized alerts with explicit, metadata-only error accounting."""

    MAX_RECORD_CHARACTERS = 1_048_576
    MAX_CONSECUTIVE_PARSER_ERRORS = 100

    def __init__(self, parser_factory: Callable[[BinaryIO], RecordParser] = _native_parser):
        self.stats = EvtxIntakeStats()
        self._parser_factory = parser_factory

    def _normalize(self, record: dict, path: Path) -> NormalizedAlert:
        xml = record["data"]
        if not isinstance(xml, str) or len(xml) > self.MAX_RECORD_CHARACTERS:
            raise ValueError("Invalid or oversized EVTX record")
        event = ET.fromstring(xml)
        system = _child(event, "System")
        if _name(event) != "Event" or system is None:
            raise ValueError("EVTX record has no Event/System")
        event_id = _text(_child(system, "EventID"))
        if not event_id or not event_id.isascii() or not event_id.isdecimal():
            raise ValueError("EVTX record has no valid EventID")

        time_created = _child(system, "TimeCreated")
        raw_time = time_created.get("SystemTime") if time_created is not None else None
        timestamp = None
        if raw_time:
            try:
                timestamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                else:
                    timestamp = timestamp.astimezone(timezone.utc)
            except (ValueError, OverflowError):
                timestamp = None
                self.stats.invalid_timestamps += 1
        else:
            self.stats.missing_timestamps += 1

        details: dict[str, str | None] = {}
        for name in ("EventData", "UserData"):
            data = _child(event, name)
            if data is not None and len(data):
                # Separate containers prevent EventData/UserData name collisions.
                details.update({f"{name}.{key}": value for key, value in _flatten(data).items()})
        security = _child(system, "Security")
        user = next((details[key] for key in (
            "EventData.User", "EventData.TargetUserName", "EventData.SubjectUserName"
        ) if details.get(key)), None)
        if not user and security is not None:
            user = security.get("UserID")
        return NormalizedAlert(
            timestamp=timestamp, source_dataset="Windows EVTX", source_file=str(path),
            event_type=event_id, ground_truth_label=None,
            original_record={
                "EventID": int(event_id), "Channel": _text(_child(system, "Channel")),
                "ComputerName": _text(_child(system, "Computer")), "User": user,
                "Details": details, "raw_xml": xml,
            },
        )

    def ingest_evtx(self, file_path: str | Path, batch_size: int = 100) -> Iterator[list[NormalizedAlert]]:
        """Yield batches and continue after recoverable parser/record errors.

        Missing/unreadable/corrupt files are counted as failed files and yield no
        further records. Dependency/configuration errors propagate. Closing the
        generator also closes its file. Only a fixed warning is logged: exception
        strings can contain source paths and untrusted event contents.
        """
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        path = Path(file_path)
        self.stats.files_seen += 1
        batch: list[NormalizedAlert] = []
        try:
            with path.open("rb") as stream:
                parser = self._parser_factory(stream)
                records = iter(parser.records())
                consecutive_errors = 0
                while True:
                    try:
                        record = next(records)
                    except StopIteration:
                        break
                    except RuntimeError:
                        self.stats.parser_errors += 1
                        consecutive_errors += 1
                        logger.warning("EVTX parser operation failed; see intake counters")
                        if consecutive_errors >= self.MAX_CONSECUTIVE_PARSER_ERRORS:
                            self.stats.files_failed += 1
                            break
                        continue
                    consecutive_errors = 0
                    self.stats.records_seen += 1
                    try:
                        alert = self._normalize(record, path)
                    except (ET.ParseError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
                        self.stats.normalization_errors += 1
                        logger.warning("EVTX record normalization failed; see intake counters")
                        continue
                    batch.append(alert)
                    self.stats.alerts_emitted += 1
                    if len(batch) == batch_size:
                        yield batch
                        batch = []
        except (OSError, RuntimeError):
            self.stats.files_failed += 1
            logger.warning("EVTX file could not be read; see intake counters")
        if batch:
            yield batch
