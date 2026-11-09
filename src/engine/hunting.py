"""Threat hunting filter engine for TriageLens.

Translates the limited KQL-style hunting filter syntax into secure,
parameterized SQLite queries targeting relational columns and deep JSON telemetry.
"""

from datetime import datetime
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from src.engine.database import DatabaseManager
from src.models.alert import NormalizedAlert

logger = logging.getLogger(__name__)


class KQLParseError(ValueError):
    """Raised when a KQL-style hunting filter has invalid or unsafe syntax."""

    pass


class ThreatHuntingEngine:
    """Orchestrates security telemetry hunting using a KQL-style filter.

    Translates expressions like:
        event_type == "Process Creation" AND CommandLine contains "powershell"
    into parameterized SQLite statements utilizing json_extract.
    """

    DIRECT_COLUMNS: Dict[str, str] = {
        "id": "id",
        "internal_id": "id",
        "event_type": "event_type",
        "source_dataset": "source_dataset",
        "source_file": "source_file",
        "ground_truth_label": "ground_truth_label",
        "timestamp": "timestamp",
        "timeline_id": "timeline_id",
    }

    # Strict token specifications for the KQL-style filter syntax
    TOKEN_SPEC = [
        ("STRING", r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\''),
        ("OPERATOR", r"==|!=|>=|<=|!contains|\bcontains\b|>|<"),
        ("CONJUNCTION", r"\b(?:AND|OR)\b"),
        ("IDENTIFIER", r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*"),
        ("MISC", r"[^\s]+"),
    ]

    TOKEN_REGEX = re.compile(
        "|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_SPEC),
        re.IGNORECASE,
    )

    FIELD_NAME_REGEX = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$")

    DEFAULT_LIMIT = 500
    MAX_LIMIT = 1000

    def __init__(self, db: DatabaseManager) -> None:
        """Initializes ThreatHuntingEngine with a DatabaseManager instance."""
        self.db = db

    def _check_balanced_quotes(self, text: str) -> None:
        """Ensures all string quotes in the query are properly closed."""
        in_quote = None
        escaped = False
        for char in text:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char in ('"', "'"):
                if in_quote is None:
                    in_quote = char
                elif in_quote == char:
                    in_quote = None
        if in_quote is not None:
            raise KQLParseError(f"Unterminated {in_quote} quote literal in hunting filter.")

    def translate_kql_to_sql(
        self, kql_query: str, limit: Optional[int] = None
    ) -> Tuple[str, List[Any]]:
        """Parses a KQL-style hunting filter into a parameterized SQLite query.

        Args:
            kql_query: KQL-style hunting filter expression.

        Returns:
            Tuple of (SQL query string with '?' placeholders, list of parameter values).

        Raises:
            KQLParseError: If syntax is invalid, unsupported, or contains injection attempts.
        """
        if not kql_query or not kql_query.strip():
            raise KQLParseError("KQL-style hunting filter cannot be empty.")

        query = kql_query.strip()
        self._check_balanced_quotes(query)

        tokens: List[Tuple[str, str]] = []
        for match in self.TOKEN_REGEX.finditer(query):
            kind = match.lastgroup
            val = match.group()
            if kind == "MISC":
                raise KQLParseError(f"Unexpected token in query: '{val}'")
            tokens.append((kind, val))

        if not tokens:
            raise KQLParseError("No valid tokens found in query.")

        i = 0
        n = len(tokens)
        clauses: List[str] = []
        params: List[Any] = []

        while i < n:
            # 1. Expect field identifier
            if i >= n or tokens[i][0] != "IDENTIFIER":
                found = tokens[i][1] if i < n else "end of query"
                raise KQLParseError(f"Expected field identifier, got '{found}'")
            field = tokens[i][1]
            if not self.FIELD_NAME_REGEX.match(field):
                raise KQLParseError(f"Invalid field identifier: '{field}'")
            i += 1

            # 2. Expect operator
            if i >= n or tokens[i][0] != "OPERATOR":
                found = tokens[i][1] if i < n else "end of query"
                raise KQLParseError(f"Expected comparison operator after '{field}', got '{found}'")
            op = tokens[i][1].lower()
            i += 1

            # 3. Expect value (STRING or numeric/boolean IDENTIFIER)
            if i >= n or tokens[i][0] not in ("STRING", "IDENTIFIER"):
                found = tokens[i][1] if i < n else "end of query"
                raise KQLParseError(f"Expected value after '{field} {op}', got '{found}'")
            raw_val = tokens[i][1]
            val_kind = tokens[i][0]
            i += 1

            # Unquote and unescape string values
            if val_kind == "STRING":
                val: Any = raw_val[1:-1].replace(r'\"', '"').replace(r"\'", "'")
            else:
                if raw_val.lower() == "true":
                    val = True
                elif raw_val.lower() == "false":
                    val = False
                else:
                    try:
                        val = float(raw_val) if "." in raw_val else int(raw_val)
                    except ValueError:
                        val = raw_val

            # Map field to direct column or json_extract
            field_lower = field.lower()
            if field_lower in self.DIRECT_COLUMNS:
                sql_col = self.DIRECT_COLUMNS[field_lower]
            else:
                # Deep JSON extraction from original_record
                sql_col = f"json_extract(original_record, '$.{field}')"

            # Map operator
            if op == "==":
                clause_str = f"{sql_col} = ?"
                params.append(val)
            elif op == "!=":
                clause_str = f"{sql_col} != ?"
                params.append(val)
            elif op == "contains":
                clause_str = f"{sql_col} LIKE ?"
                params.append(f"%{val}%")
            elif op == "!contains":
                clause_str = f"{sql_col} NOT LIKE ?"
                params.append(f"%{val}%")
            elif op == ">=":
                clause_str = f"{sql_col} >= ?"
                params.append(val)
            elif op == "<=":
                clause_str = f"{sql_col} <= ?"
                params.append(val)
            elif op == ">":
                clause_str = f"{sql_col} > ?"
                params.append(val)
            elif op == "<":
                clause_str = f"{sql_col} < ?"
                params.append(val)
            else:
                raise KQLParseError(f"Unsupported operator: '{op}'")

            clauses.append(clause_str)

            # Check if there is a trailing condition separated by AND/OR
            if i < n:
                if tokens[i][0] != "CONJUNCTION":
                    raise KQLParseError(
                        f"Expected logical operator (AND/OR) between conditions, got '{tokens[i][1]}'"
                    )
                conj = tokens[i][1].upper()
                clauses.append(conj)
                i += 1
                if i >= n:
                    raise KQLParseError(f"Trailing conjunction '{conj}' at end of query.")

        where_clause = " ".join(clauses)
        effective_limit = min(
            limit if limit is not None and limit > 0 else self.DEFAULT_LIMIT,
            self.MAX_LIMIT,
        )
        sql = f"SELECT * FROM alerts WHERE {where_clause} ORDER BY timestamp ASC LIMIT ?;"
        params.append(effective_limit)
        return sql, params

    def execute_hunt(
        self, kql_query: str, limit: Optional[int] = None
    ) -> List[NormalizedAlert]:
        """Executes a KQL-style hunting filter against the alerts table.

        Args:
            kql_query: KQL-style hunting filter expression.
            limit: Optional maximum number of matching alerts to return (default 500, max 1000).

        Returns:
            List of matching NormalizedAlert instances.
        """
        sql, params = self.translate_kql_to_sql(kql_query, limit=limit)

        with self.db._lock:
            conn = self.db.connect()
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()

        matched_alerts: List[NormalizedAlert] = []
        for row in rows:
            data = dict(row)
            orig_rec = (
                json.loads(data["original_record"])
                if isinstance(data["original_record"], str)
                else data["original_record"]
            )
            indicators = (
                json.loads(data["extracted_indicators"])
                if isinstance(data["extracted_indicators"], str)
                else data["extracted_indicators"]
            )

            ts: Optional[datetime] = None
            if data.get("timestamp"):
                try:
                    ts = datetime.fromisoformat(data["timestamp"])
                except Exception:
                    ts = None

            alert = NormalizedAlert(
                internal_id=UUID(data["id"]) if isinstance(data["id"], str) else data["id"],
                timestamp=ts,
                source_dataset=data["source_dataset"],
                source_file=data["source_file"],
                event_type=data["event_type"],
                original_record=orig_rec,
                extracted_indicators=indicators,
                ground_truth_label=data.get("ground_truth_label"),
            )
            matched_alerts.append(alert)

        logger.info(
            "Threat hunt executed: '%s' matched %d alerts.",
            kql_query,
            len(matched_alerts),
        )
        return matched_alerts

