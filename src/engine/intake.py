"""Alert intake engine for ingesting and validating security alerts."""

import csv
from datetime import datetime, timezone
import io
import json
import logging
import math
from pathlib import Path
import re
from typing import Any, Dict, Generator, List, Optional, Union

from src.models.alert import NormalizedAlert
from src.engine.evtx import EvtxIntakeEngine

logger = logging.getLogger(__name__)


class AlertIntakeEngine:
    """Engine responsible for ingesting, validating, and normalizing alerts."""

    def __init__(self) -> None:
        self.evtx = EvtxIntakeEngine()

    @staticmethod
    def _read_file_text(file_path: Path) -> str:
        """Reads a text file handling UTF-8, UTF-8 with BOM, UTF-16, and fallback encodings."""
        raw_bytes = file_path.read_bytes()
        if not raw_bytes:
            return ""

        # Check BOMs
        if raw_bytes.startswith(b"\xef\xbb\xbf"):
            return raw_bytes.decode("utf-8-sig", errors="replace")
        if raw_bytes.startswith(b"\xff\xfe") or raw_bytes.startswith(b"\xfe\xff"):
            return raw_bytes.decode("utf-16", errors="replace")

        # Try UTF-8
        try:
            return raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            pass

        # Try UTF-16
        try:
            return raw_bytes.decode("utf-16")
        except (UnicodeDecodeError, UnicodeError):
            pass

        # Fallback with replacement
        return raw_bytes.decode("utf-8", errors="replace")

    def _normalize_timestamp(self, ts_value: Any) -> Optional[datetime]:
        """Normalizes various timestamp representations into a standard datetime object.

        Handles ISO 8601 strings, UNIX epoch integers/floats (seconds or milliseconds),
        numeric strings, far-future dates, negative epochs, and floating-point epochs
        with excessive precision. Returns None gracefully for completely corrupted
        timestamps without throwing unhandled exceptions.

        Args:
            ts_value: Raw timestamp representation.

        Returns:
            A timezone-aware or naive datetime object, or None if conversion fails.
        """
        if ts_value is None or isinstance(ts_value, bool):
            return None

        if isinstance(ts_value, datetime):
            return ts_value

        # Numeric UNIX epoch (seconds or milliseconds)
        if isinstance(ts_value, (int, float)):
            if math.isnan(ts_value) or math.isinf(ts_value):
                return None
            try:
                val = float(ts_value)
                if abs(val) > 1e11:
                    val = val / 1000.0
                dt = datetime.fromtimestamp(val, tz=timezone.utc)
                if 1 <= dt.year <= 9999:
                    return dt
                return None
            except (ValueError, OSError, OverflowError):
                return None

        # String representations
        if isinstance(ts_value, str):
            clean_ts = ts_value.strip()
            if not clean_ts:
                return None

            # Attempt numeric epoch in string form
            try:
                val = float(clean_ts)
                if not math.isnan(val) and not math.isinf(val):
                    if abs(val) > 1e11:
                        val = val / 1000.0
                    dt = datetime.fromtimestamp(val, tz=timezone.utc)
                    if 1 <= dt.year <= 9999:
                        return dt
            except (ValueError, OSError, OverflowError):
                pass

            # Attempt ISO 8601 parsing
            try:
                iso_formatted = clean_ts.replace("Z", "+00:00")
                dt = datetime.fromisoformat(iso_formatted)
                if 1 <= dt.year <= 9999:
                    return dt
                return None
            except (ValueError, TypeError):
                pass

            return None

        return None

    def _normalize_fields(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes common field variations into standard canonical keys.

        Args:
            raw_record: Raw dictionary of alert attributes.

        Returns:
            Dictionary containing normalized canonical keys:
            'event_type', 'source_dataset', 'timestamp', 'indicators', 'ground_truth_label'.
        """
        normalized: Dict[str, Any] = {}

        # Build clean key-lookup dictionary (stripping null bytes and whitespace)
        clean_lookup: Dict[str, Any] = {}
        for k, v in raw_record.items():
            clean_k = str(k).strip().replace("\x00", "")
            clean_lookup[clean_k] = v
            lower_k = clean_k.lower()
            if lower_k not in clean_lookup:
                clean_lookup[lower_k] = v
            alpha_k = re.sub(r"[^a-zA-Z0-9]", "", clean_k).lower()
            if alpha_k not in clean_lookup:
                clean_lookup[alpha_k] = v

        def get_val(cand_key: str) -> Any:
            if cand_key in clean_lookup:
                return clean_lookup[cand_key]
            lower = cand_key.lower()
            if lower in clean_lookup:
                return clean_lookup[lower]
            alpha = re.sub(r"[^a-zA-Z0-9]", "", cand_key).lower()
            if alpha in clean_lookup:
                return clean_lookup[alpha]
            return None

        # 1. Event Type mapping (including Task, task, EventID, event_id, id)
        event_type_candidates = [
            "event_type",
            "EventName",
            "event_name",
            "EventID",
            "event_id",
            "id",
            "Task",
            "task",
            "activity",
            "action",
        ]
        for key in event_type_candidates:
            matched_val = get_val(key)
            if matched_val is not None:
                val = str(matched_val).strip()
                if val:
                    normalized["event_type"] = val
                    break
        if "event_type" not in normalized:
            normalized["event_type"] = "Unknown"

        # 2. Source Dataset mapping
        dataset_candidates = [
            "source_dataset",
            "dataset_source",
            "dataset",
            "source",
        ]
        for key in dataset_candidates:
            matched_val = get_val(key)
            if matched_val is not None:
                val = str(matched_val).strip()
                if val:
                    normalized["source_dataset"] = val
                    break
        if "source_dataset" not in normalized:
            normalized["source_dataset"] = "Unknown"

        # 3. Timestamp mapping
        timestamp_candidates = [
            "timestamp",
            "TimeCreated",
            "time_created",
            "event_time",
            "datetime",
            "date_time",
            "@timestamp",
            "ts",
        ]
        raw_ts = None
        for key in timestamp_candidates:
            matched_val = get_val(key)
            if matched_val is not None:
                raw_ts = matched_val
                break
        normalized["timestamp"] = self._normalize_timestamp(raw_ts)

        # 4. Indicators mapping
        indicator_candidates = [
            "indicators",
            "extracted_indicators",
            "iocs",
            "ioc",
            "ips",
            "hashes",
            "ip_addresses",
            "domains",
        ]
        indicators: List[str] = []
        for key in indicator_candidates:
            matched_val = get_val(key)
            if matched_val is not None:
                if isinstance(matched_val, list):
                    for item in matched_val:
                        if item is not None and not isinstance(item, (dict, list, bool)):
                            s = str(item).strip()
                            if s and s.lower() not in ("none", "null"):
                                indicators.append(s)
                elif isinstance(matched_val, (str, int, float)) and not isinstance(matched_val, bool):
                    if isinstance(matched_val, str):
                        delimiters = [",", ";", "|", "\n"]
                        current_parts = [matched_val]
                        for delim in delimiters:
                            new_parts = []
                            for p in current_parts:
                                new_parts.extend(p.split(delim))
                            current_parts = new_parts
                        for item in current_parts:
                            s = item.strip()
                            if s:
                                indicators.append(s)
                    else:
                        indicators.append(str(matched_val))
                break
        normalized["indicators"] = indicators

        # 5. Ground truth label mapping
        label_candidates = [
            "ground_truth_label",
            "ground_truth",
            "label",
            "classification",
            "verdict",
        ]
        for key in label_candidates:
            matched_val = get_val(key)
            if matched_val is not None:
                val = str(matched_val).strip()
                if val:
                    normalized["ground_truth_label"] = val
                    break
        if "ground_truth_label" not in normalized:
            normalized["ground_truth_label"] = None

        return normalized

    def ingest_json(self, file_path: Union[str, Path]) -> List[NormalizedAlert]:
        """Ingests security alerts from a JSON file and normalizes them.

        Args:
            file_path: Path to the JSON file to ingest.

        Returns:
            A list of validated NormalizedAlert instances.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file content is empty, not valid JSON, or not dict/list.
        """
        path = Path(file_path)
        if not path.is_file():
            logger.error("Alert file not found: %s", file_path)
            raise FileNotFoundError(f"Alert file not found: {file_path}")

        logger.info("Ingesting alerts from JSON file: %s", file_path)
        text = self._read_file_text(path)
        if not text.strip():
            logger.error("Empty JSON file: %s", file_path)
            raise ValueError(f"Empty JSON file: {file_path}")

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            logger.error("Malformed JSON in file %s: %s", file_path, exc)
            raise ValueError(f"Malformed JSON in file {file_path}: {exc}") from exc

        if isinstance(data, dict):
            records = [data]
        elif isinstance(data, list):
            records = data
        else:
            logger.error(
                "Invalid JSON content in %s: expected dict or list, got %s",
                file_path,
                type(data).__name__,
            )
            raise ValueError(
                f"Invalid JSON content in {file_path}: expected dict or list, got {type(data).__name__}"
            )

        normalized_alerts: List[NormalizedAlert] = []
        for index, raw_record in enumerate(records):
            if not isinstance(raw_record, dict):
                logger.error(
                    "Record at index %d in %s is not a JSON object: %s",
                    index,
                    file_path,
                    type(raw_record).__name__,
                )
                raise ValueError(
                    f"Record at index {index} is not a JSON object: {type(raw_record).__name__}"
                )

            norm_fields = self._normalize_fields(raw_record)

            alert = NormalizedAlert(
                timestamp=norm_fields["timestamp"],
                source_dataset=norm_fields["source_dataset"],
                source_file=str(file_path),
                event_type=norm_fields["event_type"],
                original_record=raw_record,
                extracted_indicators=norm_fields["indicators"],
                ground_truth_label=norm_fields["ground_truth_label"],
            )
            normalized_alerts.append(alert)

        logger.info(
            "Successfully ingested %d records from %s",
            len(normalized_alerts),
            file_path,
        )
        return normalized_alerts

    def ingest_csv(self, file_path: Union[str, Path]) -> List[NormalizedAlert]:
        """Ingests security alerts from a CSV file and normalizes them.

        Args:
            file_path: Path to the CSV file to ingest.

        Returns:
            A list of validated NormalizedAlert instances.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the CSV file is empty, headerless, or unparseable.
        """
        path = Path(file_path)
        if not path.is_file():
            logger.error("Alert file not found: %s", file_path)
            raise FileNotFoundError(f"Alert file not found: {file_path}")

        logger.info("Ingesting alerts from CSV file: %s", file_path)
        text = self._read_file_text(path)
        if not text.strip():
            logger.error("Empty CSV file: %s", file_path)
            raise ValueError(f"Empty or headerless CSV file: {file_path}")

        rows: List[Dict[str, Any]] = []
        try:
            reader = csv.DictReader(io.StringIO(text))
            if reader.fieldnames is None:
                raise ValueError(f"Empty or headerless CSV file: {file_path}")
            rows = list(reader)
        except (csv.Error, ValueError):
            try:
                reader = csv.DictReader(
                    io.StringIO(text), quoting=csv.QUOTE_NONE, escapechar="\\"
                )
                if reader.fieldnames is None:
                    raise ValueError(f"Empty or headerless CSV file: {file_path}")
                rows = list(reader)
            except Exception as exc:
                logger.error("Malformed CSV in file %s: %s", file_path, exc)
                raise ValueError(f"Malformed CSV in file {file_path}: {exc}") from exc

        normalized_alerts: List[NormalizedAlert] = []
        for row in rows:
            row_dict = dict(row)
            norm_fields = self._normalize_fields(row_dict)

            alert = NormalizedAlert(
                timestamp=norm_fields["timestamp"],
                source_dataset=norm_fields["source_dataset"],
                source_file=str(file_path),
                event_type=norm_fields["event_type"],
                original_record=row_dict,
                extracted_indicators=norm_fields["indicators"],
                ground_truth_label=norm_fields["ground_truth_label"],
            )
            normalized_alerts.append(alert)

        logger.info(
            "Successfully ingested %d records from %s",
            len(normalized_alerts),
            file_path,
        )
        return normalized_alerts

    def ingest_directory(
        self, dir_path: Union[str, Path], batch_size: int = 100
    ) -> Generator[List[NormalizedAlert], None, None]:
        """Process JSON/CSV/EVTX files and yield batches of NormalizedAlerts.

        EVTX streams through a single-chunk native parser. Its cumulative error
        counters are available as ``engine.evtx.stats``. JSON/CSV retain their
        existing whole-file loading behavior.

        Adversarially resilient: skips empty, unreadable, corrupt, or unsupported files
        without halting batch iteration or throwing unhandled exceptions.

        Args:
            dir_path: Directory path containing alert files.
            batch_size: Maximum number of alerts per yielded batch.

        Yields:
            Batches of NormalizedAlert instances (each batch up to batch_size).

        Raises:
            FileNotFoundError: If the directory does not exist.
            NotADirectoryError: If dir_path is not a directory.
            ValueError: If batch_size <= 0.
        """
        path = Path(dir_path)
        if not path.exists():
            logger.error("Directory not found: %s", dir_path)
            raise FileNotFoundError(f"Directory not found: {dir_path}")
        if not path.is_dir():
            logger.error("Path is not a directory: %s", dir_path)
            raise NotADirectoryError(f"Path is not a directory: {dir_path}")
        if batch_size <= 0:
            raise ValueError(f"batch_size must be a positive integer, got {batch_size}")

        logger.info(
            "Scanning directory for alert files: %s (batch_size=%d)", dir_path, batch_size
        )
        current_batch: List[NormalizedAlert] = []

        try:
            entries = sorted(path.iterdir())
        except (PermissionError, OSError) as exc:
            logger.error("Cannot access directory %s: %s", dir_path, exc)
            return

        for file_path in entries:
            if not file_path.is_file():
                continue
            suffix = file_path.suffix.lower()
            if suffix not in (".json", ".csv", ".evtx"):
                continue

            try:
                if suffix == ".evtx":
                    for batch in self.evtx.ingest_evtx(file_path, batch_size):
                        for alert in batch:
                            current_batch.append(alert)
                            if len(current_batch) >= batch_size:
                                yield current_batch
                                current_batch = []
                    continue
                elif suffix == ".json":
                    alerts = self.ingest_json(file_path)
                elif suffix == ".csv":
                    alerts = self.ingest_csv(file_path)
                else:
                    continue

                for alert in alerts:
                    current_batch.append(alert)
                    if len(current_batch) >= batch_size:
                        yield current_batch
                        current_batch = []

            except (PermissionError, OSError, ValueError) as exc:
                logger.warning(
                    "Skipping unreadable, empty, or corrupt file in batching %s: %s",
                    file_path.name,
                    exc,
                )
                continue

        if current_batch:
            yield current_batch
