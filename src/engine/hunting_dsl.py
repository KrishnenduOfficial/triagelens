"""Bounded hunting grammar, immutable syntax tree and SQL dialect contract."""

from dataclasses import dataclass
import math
import re
from typing import Any, Protocol

from src.engine.fields import FIELD_MAPPINGS


class KQLParseError(ValueError):
    """Invalid or unsupported hunting filter syntax."""


DIRECT_COLUMNS = {
    "id": "id", "internal_id": "id", "event_type": "event_type",
    "source_dataset": "source_dataset", "source_file": "source_file",
    "ground_truth_label": "ground_truth_label", "timestamp": "timestamp",
    "timeline_id": "timeline_id",
}
MAX_QUERY_LENGTH = 2000
MAX_TOKENS = 512
MAX_DEPTH = 32
MAX_COMPARISONS = 128
FIELD_PATTERN = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*\Z")
TOKEN_PATTERN = re.compile(
    r'''(?P<STRING>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')'''
    r"|(?P<OP>!contains\b|==|!=|>=|<=|>|<)"
    r"|(?P<LPAREN>\()|(?P<RPAREN>\))"
    r"|(?P<NUMBER>-?\d+(?:\.\d+)?)(?![A-Za-z0-9_.])"
    r"|(?P<WORD>[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Comparison:
    field: str
    operator: str
    value: str | int | float | bool


@dataclass(frozen=True)
class Logical:
    operator: str
    children: tuple["Expression", ...]


Expression = Comparison | Logical


class Parser:
    """Recursive descent over a fully consumed, size-bounded token stream."""

    def __init__(self, query: str):
        if not isinstance(query, str) or not query.strip():
            raise KQLParseError("KQL-style hunting filter cannot be empty.")
        if len(query) > MAX_QUERY_LENGTH:
            raise KQLParseError("Hunting filter exceeds 2000 characters.")
        self.tokens: list[tuple[str, str]] = []
        position = 0
        while position < len(query):
            if query[position].isspace():
                position += 1
                continue
            match = TOKEN_PATTERN.match(query, position)
            if match is None:
                if query[position] in "\"'":
                    raise KQLParseError("Unterminated quote literal in hunting filter.")
                raise KQLParseError(f"Unexpected token at character {position + 1}.")
            self.tokens.append((match.lastgroup, match.group()))
            if len(self.tokens) > MAX_TOKENS:
                raise KQLParseError("Hunting filter exceeds token limit.")
            position = match.end()
        self.position = 0
        self.comparisons = 0

    def _peek(self, value: str) -> bool:
        return (self.position < len(self.tokens)
                and self.tokens[self.position][0] != "STRING"
                and self.tokens[self.position][1].upper() == value)

    def parse(self) -> Expression:
        result = self._or(0)
        if self.position != len(self.tokens):
            raise KQLParseError("Expected logical operator (AND/OR) or end of query.")
        return result

    def _or(self, depth: int) -> Expression:
        children = [self._and(depth)]
        while self._peek("OR"):
            self.position += 1
            self._check_trailing()
            children.append(self._and(depth))
        return children[0] if len(children) == 1 else Logical("OR", tuple(children))

    def _and(self, depth: int) -> Expression:
        children = [self._unary(depth)]
        while self._peek("AND"):
            self.position += 1
            self._check_trailing()
            children.append(self._unary(depth))
        return children[0] if len(children) == 1 else Logical("AND", tuple(children))

    def _check_trailing(self) -> None:
        if self.position == len(self.tokens):
            raise KQLParseError("Trailing conjunction at end of query.")

    def _unary(self, depth: int) -> Expression:
        if depth > MAX_DEPTH:
            raise KQLParseError("Hunting filter exceeds nesting limit.")
        if self._peek("NOT"):
            self.position += 1
            return Logical("NOT", (self._unary(depth + 1),))
        if self._peek("("):
            self.position += 1
            result = self._or(depth + 1)
            if not self._peek(")"):
                raise KQLParseError("Expected closing parenthesis.")
            self.position += 1
            return result
        return self._comparison()

    def _comparison(self) -> Comparison:
        if (self.position >= len(self.tokens)
                or self.tokens[self.position][0] not in {"WORD", "NUMBER"}
                or not FIELD_PATTERN.fullmatch(self.tokens[self.position][1])
                or self.tokens[self.position][1].upper() in {"AND", "OR", "NOT", "CONTAINS"}):
            raise KQLParseError("Expected field identifier.")
        field = self.tokens[self.position][1]
        self.position += 1
        if self.position >= len(self.tokens):
            raise KQLParseError("Expected comparison operator.")
        kind, operator = self.tokens[self.position]
        if kind != "OP" and not self._peek("CONTAINS"):
            raise KQLParseError("Expected comparison operator.")
        self.position += 1
        if self.position >= len(self.tokens):
            raise KQLParseError("Expected comparison value.")
        kind, raw = self.tokens[self.position]
        if kind not in {"STRING", "NUMBER", "WORD"} or (
            kind == "WORD" and raw.upper() in {"AND", "OR", "NOT", "CONTAINS", "NULL"}
        ):
            raise KQLParseError("Expected comparison value (null is unsupported).")
        self.position += 1
        value: Any = raw
        if kind == "STRING":
            # Unknown escapes stay literal, allowing Windows paths.
            value = re.sub(r"\\([\\\"'])", lambda m: m[1], raw[1:-1])
        elif kind == "NUMBER":
            value = float(raw) if "." in raw else int(raw)
            if (isinstance(value, int) and not -(2**63) <= value < 2**63
                    or isinstance(value, float) and not math.isfinite(value)):
                raise KQLParseError("Numeric literal out of range.")
        elif raw.lower() in {"true", "false"}:
            value = raw.lower() == "true"
        operator = operator.lower()
        if operator in {"contains", "!contains"} and not isinstance(value, str):
            raise KQLParseError("Substring operators require a string value.")
        self.comparisons += 1
        if self.comparisons > MAX_COMPARISONS:
            raise KQLParseError("Hunting filter exceeds comparison limit.")
        return Comparison(field, operator, value)


def parse_query(query: str) -> Expression:
    return Parser(query).parse()


class SQLDialect(Protocol):
    """A backend supplies field/type expressions, comparisons and SELECT syntax."""

    def comparison(self, node: Comparison, params: list[Any]) -> str: ...

    def select(self, predicate: str) -> str: ...


class SQLiteDialect:
    """SQLite JSON scalar matching with explicit types and literal substring search."""

    def comparison(self, node: Comparison, params: list[Any]) -> str:
        # Validate even externally constructed ASTs; SQL structure is never user SQL.
        if not FIELD_PATTERN.fullmatch(node.field):
            raise KQLParseError("Invalid field identifier.")
        direct = DIRECT_COLUMNS.get(node.field.lower())
        if direct:
            column = direct
            type_expr = f"typeof({column})"
            allowed_types = "('text')" if isinstance(node.value, str) else "('integer','real')"
        elif node.field.lower() in FIELD_MAPPINGS:
            # The field name comes from the fixed mapping, never arbitrary SQL.
            column = f"triagelens_field(original_record, '{node.field.lower()}')"
            type_expr = f"typeof({column})"
            allowed_types = "('text')" if isinstance(node.value, str) else "('integer','real')"
        else:
            column = f"json_extract(original_record, '$.{node.field}')"
            type_expr = f"json_type(original_record, '$.{node.field}')"
            allowed_types = "('text')" if isinstance(node.value, str) else "('integer','real','true','false')"
        # Mismatched types and missing/null/container values are UNKNOWN, including !=.
        guard = f"{type_expr} IN {allowed_types}"
        if node.operator in {"contains", "!contains"}:
            if not isinstance(node.value, str):
                raise KQLParseError("Substring operators require a string value.")
            escaped = node.value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")
            op = "LIKE" if node.operator == "contains" else "NOT LIKE"
            predicate = f"{column} {op} ? ESCAPE '\\'"
        else:
            operators = {"==": "=", "!=": "!=", ">": ">", "<": "<", ">=": ">=", "<=": "<="}
            if node.operator not in operators:
                raise KQLParseError("Unsupported comparison operator.")
            params.append(node.value)
            predicate = f"{column} {operators[node.operator]} ?"
        return f"(CASE WHEN {guard} THEN {predicate} ELSE NULL END)"

    def select(self, predicate: str) -> str:
        return f"SELECT * FROM alerts WHERE {predicate} ORDER BY timestamp ASC, id ASC LIMIT ?;"


def compile_query(tree: Expression, dialect: SQLDialect, limit: int) -> tuple[str, list[Any]]:
    params: list[Any] = []

    def visit(node: Expression, depth: int = 0) -> str:
        if depth > 2 * MAX_DEPTH + 2:
            raise KQLParseError("Hunting filter exceeds nesting limit.")
        if isinstance(node, Comparison):
            return dialect.comparison(node, params)
        if node.operator == "NOT" and len(node.children) == 1:
            return f"(NOT {visit(node.children[0], depth + 1)})"
        if node.operator not in {"AND", "OR"} or len(node.children) < 2:
            raise KQLParseError("Invalid logical expression.")
        return "(" + f" {node.operator} ".join(visit(child, depth + 1) for child in node.children) + ")"

    predicate = visit(tree)
    params.append(limit)
    return dialect.select(predicate), params
