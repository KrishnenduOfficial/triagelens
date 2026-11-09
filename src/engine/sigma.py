"""Local, single-event Sigma subset (T2.3); no persistence or inference integration.

Usage::

    pack = load_curated_rules()
    for issue in pack.issues:  # unsupported/invalid rules are never silently dropped
        print(issue.source, issue.status, issue.reason)
    matches = pack.evaluate(alert)  # NormalizedAlert -> attributed rule results

``load_rules([Path(...)])`` loads local UTF-8 files, one rule per file. Rules need
title, UUID id and author. pySigma parses selections and conditions; this module
compiles its AST into an immutable local evaluator using the shared field layer.
No pySigma pipelines, downloads, templates, jq expressions or plugins execute.

Subset: mapping selections (AND fields), lists of mappings (OR), scalar/list
values (OR, or AND with |all); contains, startswith, endswith, re, all. Conditions
support parentheses, not > and > or, 1 of / all of identifier* or them. Normal
strings match case-insensitively with Sigma * / ? wildcards and backslash escapes;
regex uses case-sensitive RE2 search (inline flags allowed). Unsupported RE2
constructs, including backreferences/lookaround, are reported, never approximated.
Missing/invalid canonical fields do not match, except null (missing or null).
NOT negates that Boolean result. No truncation, container stringification, or
general numeric coercion: nonnegative integer rules below 2**53 match PID/port
integers; EventID integers
match the canonical text code. Text fields require string rules.

Logsources: product windows is required. process_creation maps to Sysmon channel
Microsoft-Windows-Sysmon/Operational + EventID 1, or Security + 4688;
network_connection maps to Sysmon + 3. service sysmon/security restricts those
alternatives; without category it selects that exact channel, any event code.
Other products/categories/services are unsupported. Channel comparison ignores
case; absent channel/code never satisfies a category. Logsource definition is an
informational prerequisite only, not an automatically verified logging setting.

Fields: canonical names in FIELD_MAPPINGS, plus EventID -> metadata.event_code,
Channel -> metadata.log_name, Computer -> device.hostname, User -> user.name,
Image -> process.file.path, CommandLine -> process.cmd_line,
ParentImage -> process.parent_process.file.path, SourceIp/SourcePort ->
src_endpoint.ip/port, DestinationIp/DestinationPort -> dst_endpoint.ip/port,
SubjectUserName -> actor.user.name, TargetUserName -> target.user.name.
Aliases are exact Sigma field names. No raw-record search or label/provenance
fields. Security 4688 uses the shared child/creator and account-role mappings.

Explicitly unsupported: other modifiers/fields/logsources, keyword selections,
condition lists, any/n-of selectors, timeframe/aggregation/correlation, collection
actions/filters, alternate taxonomies, YAML anchors/aliases, and float/bool values.
Limits: 30 files per load, 64 KiB/file, 4,096 YAML tokens, 2,048 structure/AST
nodes, 24 structure/AST levels, 128 condition tokens, 12 condition parentheses,
2,048 chars/value/regex and 32,768 chars/referenced event text. RE2 uses a 1 MiB
compile budget. Limits reject rules or raise SigmaEvaluationError for oversized
events; partial matches are withheld. Work is bounded, not a hard-time guarantee.
The bundled three-rule pack has two supported rules and one explicitly unsupported
field diagnostic; synthetic fixtures establish behavior, not real-data accuracy.
"""

from dataclasses import dataclass, field, replace
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Literal, Mapping
from uuid import UUID

import re2
import yaml
from sigma.conditions import (ConditionAND, ConditionOR, ConditionNOT,
                              ConditionFieldEqualsValueExpression)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import SigmaString, SigmaNumber, SigmaNull, SigmaRegularExpression, SpecialChars

from src.engine.fields import FIELD_MAPPINGS, resolve_field
from src.models.alert import NormalizedAlert


MAX_RULES = 30
MAX_RULE_BYTES = 65536
MAX_NODES = 2048
MAX_DEPTH = 24
MAX_VALUE = 2048
MAX_EVENT_TEXT = 32768
SYSMON = "microsoft-windows-sysmon/operational"
ALIASES = {
    "EventID": "metadata.event_code", "Channel": "metadata.log_name",
    "Computer": "device.hostname", "User": "user.name", "Image": "process.file.path",
    "CommandLine": "process.cmd_line", "ParentImage": "process.parent_process.file.path",
    "SourceIp": "src_endpoint.ip", "SourcePort": "src_endpoint.port",
    "DestinationIp": "dst_endpoint.ip", "DestinationPort": "dst_endpoint.port",
    "SubjectUserName": "actor.user.name", "TargetUserName": "target.user.name",
}


class SigmaEvaluationError(ValueError):
    """Evaluation unavailable; caller must not treat this as a no-match."""


class _Rejected(ValueError):
    def __init__(self, status: Literal["invalid", "unsupported"], reason: str):
        self.status, self.reason = status, reason


def _reject(reason: str, status: Literal["invalid", "unsupported"] = "unsupported") -> None:
    raise _Rejected(status, reason)


@dataclass(frozen=True)
class RuleIssue:
    source: str
    status: Literal["invalid", "unsupported"]
    reason: str  # stable diagnostic; never raw parser exceptions or event values


@dataclass(frozen=True)
class SigmaMatch:
    event_id: str
    rule_id: str
    title: str
    author: str
    license: str
    source: str
    tags: tuple[str, ...]
    level: str | None


@dataclass(frozen=True)
class _Predicate:
    name: str
    value: int | str | None = None
    regex: Any = field(default=None, repr=False, compare=False)
    search: bool = False

    def matches(self, values: Mapping[str, Any]) -> bool:
        actual = values[self.name]
        if self.regex is not None:
            if not isinstance(actual, str):
                return False
            return bool(self.regex.search(actual) if self.search else self.regex.fullmatch(actual))
        return type(actual) is type(self.value) and actual == self.value


@dataclass(frozen=True)
class _Boolean:
    op: Literal["and", "or", "not"]
    children: tuple["_Boolean | _Predicate", ...]

    def matches(self, values: Mapping[str, Any]) -> bool:
        if self.op == "not":
            return not self.children[0].matches(values)
        results = (child.matches(values) for child in self.children)
        return all(results) if self.op == "and" else any(results)


@dataclass(frozen=True)
class CompiledRule:
    id: str
    title: str
    author: str
    license: str
    source: str
    tags: tuple[str, ...]
    level: str | None
    _logsources: tuple[tuple[str, str | None], ...] = field(repr=False)
    _fields: frozenset[str] = field(repr=False)
    _condition: _Boolean | _Predicate = field(repr=False)

    def matches(self, record: Mapping[str, Any]) -> bool:
        channel = resolve_field(record, "metadata.log_name")
        code = resolve_field(record, "metadata.event_code")
        if not isinstance(channel, str) or len(channel) > MAX_EVENT_TEXT:
            if isinstance(channel, str):
                raise SigmaEvaluationError("event_text_limit")
            return False
        if not any(channel.casefold() == name and (event is None or code == event)
                   for name, event in self._logsources):
            return False
        values = {name: resolve_field(record, name) for name in self._fields}
        if any(isinstance(value, str) and len(value) > MAX_EVENT_TEXT for value in values.values()):
            raise SigmaEvaluationError("event_text_limit")
        return self._condition.matches(values)


@dataclass(frozen=True)
class RuleLoadResult:
    rules: tuple[CompiledRule, ...]
    issues: tuple[RuleIssue, ...]

    def evaluate(self, alert: NormalizedAlert) -> tuple[SigmaMatch, ...]:
        """Return attributed results separately; never mutate the alert or labels."""
        return tuple(SigmaMatch(str(alert.internal_id), rule.id, rule.title, rule.author,
                                rule.license, rule.source, rule.tags, rule.level)
                     for rule in self.rules if rule.matches(alert.original_record))


class _StrictLoader(yaml.CSafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys):
            _reject("duplicate_or_nontext_yaml_key", "invalid")
        return super().construct_mapping(node, deep=deep)


def _document(text: str) -> dict:
    if len(text.encode("utf-8")) > MAX_RULE_BYTES:
        _reject("rule_byte_limit", "invalid")
    depth = 0
    for count, token in enumerate(yaml.scan(text), 1):
        if count > 4096:
            _reject("yaml_token_limit", "invalid")
        if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)):
            _reject("yaml_anchors_or_aliases")
        if isinstance(token, (yaml.tokens.BlockMappingStartToken, yaml.tokens.BlockSequenceStartToken,
                              yaml.tokens.FlowMappingStartToken, yaml.tokens.FlowSequenceStartToken)):
            depth += 1
        elif isinstance(token, (yaml.tokens.BlockEndToken, yaml.tokens.FlowMappingEndToken,
                                yaml.tokens.FlowSequenceEndToken)):
            depth -= 1
        if depth > MAX_DEPTH:
            _reject("yaml_depth_limit", "invalid")
    document = yaml.load(text, Loader=_StrictLoader)
    pending = [(document, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            _reject("rule_structure_limit", "invalid")
        if isinstance(node, dict):
            pending.extend((value, depth + 1) for value in node.values())
        elif isinstance(node, list):
            pending.extend((value, depth + 1) for value in node)
    if not isinstance(document, dict):
        _reject("rule_must_be_mapping", "invalid")
    return document


def _regex(pattern: str, *, case_sensitive: bool = True, dot_nl: bool = False) -> Any:
    if len(pattern) > MAX_VALUE * 4:
        _reject("compiled_pattern_limit")
    options = re2.Options()
    options.log_errors = False
    options.max_mem = 1024 * 1024
    options.case_sensitive, options.dot_nl = case_sensitive, dot_nl
    try:
        return re2.compile(pattern, options=options)
    except re2.error:
        _reject("unsupported_or_invalid_re2")


def _logsource(document: dict) -> tuple[tuple[str, str | None], ...]:
    source = document.get("logsource")
    if not isinstance(source, dict):
        _reject("invalid_logsource", "invalid")
    if set(source) - {"product", "category", "service", "definition"}:
        _reject("logsource_attribute")
    if source.get("product") != "windows":
        _reject("logsource_product")
    service, category = source.get("service"), source.get("category")
    if service not in (None, "sysmon", "security"):
        _reject("logsource_service")
    if category == "process_creation":
        alternatives = ((SYSMON, "1"), ("security", "4688"))
    elif category == "network_connection":
        alternatives = ((SYSMON, "3"),)
    elif category is None and service is not None:
        alternatives = ((SYSMON if service == "sysmon" else "security", None),)
    else:
        _reject("logsource_category")
    alternatives = tuple((channel, code) for channel, code in alternatives
                         if service is None or channel == (SYSMON if service == "sysmon" else "security"))
    if not alternatives:
        _reject("incompatible_logsource")
    return alternatives


def _selection(selection: Any) -> None:
    if isinstance(selection, list) and selection and all(isinstance(item, dict) for item in selection):
        for item in selection:
            _selection(item)
        return
    if not isinstance(selection, dict) or not selection:
        _reject("keyword_or_empty_selection")
    for key, value in selection.items():
        name, *modifiers = key.split("|")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", name):
            _reject("unmapped_field")
        if name not in ALIASES and name not in FIELD_MAPPINGS:
            _reject("unmapped_field:" + name)
        if (set(modifiers) - {"contains", "startswith", "endswith", "re", "all"}
                or len(set(modifiers)) != len(modifiers)
                or len(set(modifiers) - {"all"}) > 1):
            _reject("modifier_or_combination")
        values = value if isinstance(value, list) else [value]
        if not values or ("all" in modifiers and len(values) < 2):
            _reject("empty_or_singleton_all", "invalid")
        for item in values:
            if not (item is None or type(item) in (str, int)):
                _reject("value_type")
            if isinstance(item, str) and len(item) > MAX_VALUE:
                _reject("value_length_limit")
            if type(item) is int and not 0 <= item < 2**53:
                _reject("integer_range")
            kind = FIELD_MAPPINGS[ALIASES.get(name, name)].kind
            if type(item) is int and kind == "text":
                _reject("numeric_rule_for_text_field")
            if isinstance(item, str) and kind in ("pid", "port"):
                _reject("text_rule_for_numeric_field")
            if set(modifiers) - {"all"} and not isinstance(item, str):
                _reject("modifier_value_type")
            if "re" in modifiers:
                _regex(item)  # reject safely before pySigma can print parser details


def _condition_subset(condition: Any) -> None:
    if not isinstance(condition, str):
        _reject("condition_list_or_type")
    tokens = re.findall(r"[A-Za-z0-9_*-]+|[()]|\S", condition)
    if len(tokens) > 128:
        _reject("condition_token_limit")
    depth = unary = 0
    for token in tokens:
        if not re.fullmatch(r"[A-Za-z0-9_*-]+|[()]", token):
            _reject("condition_operator")
        if token == "any" or (token.isdigit() and token != "1"):
            _reject("condition_quantifier")
        depth += (token == "(") - (token == ")")
        unary = unary + 1 if token == "not" else 0
        if depth > 12 or unary > 12:
            _reject("condition_depth_limit")


def _compile(node: Any, fields: set[str], budget: list[int], depth: int = 0) -> _Boolean | _Predicate:
    budget[0] += 1
    if budget[0] > MAX_NODES or depth > MAX_DEPTH:
        _reject("expanded_condition_limit")
    operators = {ConditionAND: "and", ConditionOR: "or", ConditionNOT: "not"}
    if type(node) in operators:
        return _Boolean(operators[type(node)], tuple(_compile(child, fields, budget, depth + 1)
                                                    for child in node.args))
    if not isinstance(node, ConditionFieldEqualsValueExpression):
        _reject("condition_node")
    name = ALIASES.get(node.field, node.field)
    fields.add(name)
    value, kind = node.value, FIELD_MAPPINGS[name].kind
    if isinstance(value, SigmaNull):
        return _Predicate(name)
    if isinstance(value, SigmaNumber):
        if kind == "code":
            return _Predicate(name, str(value.number))
        if kind not in ("pid", "port"):
            _reject("numeric_rule_for_text_field")
        return _Predicate(name, value.number)
    if kind in ("pid", "port"):
        _reject("text_rule_for_numeric_field")
    if isinstance(value, SigmaRegularExpression):
        return _Predicate(name, regex=_regex(value.to_plain()), search=True)
    if isinstance(value, SigmaString):
        parts = []
        for part in value:
            if isinstance(part, str):
                parts.append(re.escape(part))
            elif part == SpecialChars.WILDCARD_MULTI:
                parts.append(".*")
            elif part == SpecialChars.WILDCARD_SINGLE:
                parts.append(".")
            else:
                _reject("string_placeholder")
        return _Predicate(name, regex=_regex("".join(parts), case_sensitive=False, dot_nl=True))
    _reject("sigma_value_type")


def load_rule(text: str, *, source: str = "<memory>") -> RuleLoadResult:
    """Validate one rule, returning either a compiled rule or a visible issue."""
    try:
        document = _document(text)
        if any(key in document for key in ("action", "correlation", "filter")):
            _reject("collection_or_correlation")
        if document.get("taxonomy", "sigma") != "sigma":
            _reject("taxonomy")
        if any(not isinstance(document.get(key), str) or not document[key].strip()
               for key in ("title", "id", "author")):
            _reject("required_title_id_author", "invalid")
        UUID(document["id"])
        logsources = _logsource(document)
        detection = document.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            _reject("invalid_detection", "invalid")
        if "timeframe" in detection:
            _reject("timeframe")
        _condition_subset(detection["condition"])
        for name, selection in detection.items():
            if name != "condition":
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", name):
                    _reject("selection_name")
                _selection(selection)
        rule = SigmaRule.from_dict(document)
        fields: set[str] = set()
        condition = _compile(rule.detection.parsed_condition[0].parsed, fields, [0])
        compiled = CompiledRule(str(rule.id), rule.title, rule.author, rule.license or "unspecified",
                                source, tuple(str(tag) for tag in rule.tags),
                                rule.level.name.lower() if rule.level else None,
                                logsources, frozenset(fields), condition)
        return RuleLoadResult((compiled,), ())
    except _Rejected as error:
        issue = RuleIssue(source, error.status, error.reason)
    except (SigmaError, yaml.YAMLError, ValueError, TypeError, AttributeError,
            KeyError, IndexError, RecursionError):
        issue = RuleIssue(source, "invalid", "invalid_sigma_rule")
    return RuleLoadResult((), (issue,))


def load_rules(paths: Iterable[str | Path]) -> RuleLoadResult:
    """Read at most 30 local files; invalid/unsupported/duplicate rules are listed."""
    rules, issues, seen = [], [], set()
    for index, path in enumerate(paths):
        if index >= MAX_RULES:
            issues.append(RuleIssue("<pack>", "invalid", "rule_count_limit"))
            break
        path = Path(path)
        try:
            with path.open("rb") as stream:
                data = stream.read(MAX_RULE_BYTES + 1)
            result = load_rule(data.decode("utf-8"), source=path.name)
        except (OSError, UnicodeError):
            result = RuleLoadResult((), (RuleIssue(path.name, "invalid", "unreadable_rule"),))
        issues.extend(result.issues)
        for rule in result.rules:
            if rule.id in seen:
                issues.append(RuleIssue(path.name, "invalid", "duplicate_rule_id"))
            else:
                rules.append(rule)
                seen.add(rule.id)
    return RuleLoadResult(tuple(rules), tuple(issues))


def load_curated_rules() -> RuleLoadResult:
    """Load the pinned pack with hash checks, source links and DRL attribution."""
    folder = Path(__file__).resolve().parents[2] / "rules" / "sigma"
    try:
        with (folder / "manifest.json").open("rb") as stream:
            manifest = json.loads(stream.read(MAX_RULE_BYTES + 1))
    except (OSError, ValueError, UnicodeError):
        raise SigmaEvaluationError("curated_manifest_unavailable") from None
    if (not isinstance(manifest, dict) or not isinstance(manifest.get("rules"), list)
            or manifest.get("license") != "DRL-1.1"):
        raise SigmaEvaluationError("invalid_curated_manifest")
    entries = manifest["rules"]
    if len(entries) > MAX_RULES:
        raise SigmaEvaluationError("curated_rule_count_limit")
    rules, issues, seen = [], [], set()
    for entry in entries:
        if not isinstance(entry, dict) or any(not isinstance(entry.get(key), str)
                                              for key in ("file", "sha256", "source", "author")):
            raise SigmaEvaluationError("invalid_curated_manifest")
        path = folder / entry["file"]
        if path.parent != folder or path.suffix != ".yml":
            raise SigmaEvaluationError("invalid_curated_path")
        try:
            with path.open("rb") as stream:
                data = stream.read(MAX_RULE_BYTES + 1)
        except OSError:
            issues.append(RuleIssue(path.name, "invalid", "unreadable_rule"))
            continue
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            issues.append(RuleIssue(path.name, "invalid", "curated_hash_mismatch"))
            continue
        try:
            result = load_rule(data.decode("utf-8"), source=entry["source"])
        except UnicodeError:
            issues.append(RuleIssue(path.name, "invalid", "unreadable_rule"))
            continue
        issues.extend(result.issues)
        for rule in result.rules:
            if rule.author != entry["author"]:
                raise SigmaEvaluationError("curated_attribution_mismatch")
            if rule.id in seen:
                issues.append(RuleIssue(path.name, "invalid", "duplicate_rule_id"))
            else:
                rules.append(replace(rule, license=manifest["license"]))
                seen.add(rule.id)
    return RuleLoadResult(tuple(rules), tuple(issues))
