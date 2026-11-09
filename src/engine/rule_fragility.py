"""Offline fragility measurements on caller-supplied synthetic flat events.

Each case names one rule and the fields to mutate. Variants change one field at
a time: an unrecognized field name, a UTF-8 base64 representation, or swapped
letter case. These are input perturbations, not claims of equivalent Windows
telemetry. Only changed variants of baseline-matching cases are scored.
"""

import base64
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from src.engine.sigma import RuleLoadResult, SigmaEvaluationError


@dataclass(frozen=True)
class SyntheticCase:
    rule_id: str
    record: dict[str, Any]
    fields: tuple[str, ...]


def _variants(case: SyntheticCase):
    for key in case.fields:
        value = case.record[key]
        renamed = f"mutated_{key}"
        if renamed not in case.record:
            record = deepcopy(case.record)
            record[renamed] = record.pop(key)
            yield "field_rename", record
        encoded = "base64:" + base64.b64encode(value.encode("utf-8")).decode("ascii")
        for family, changed in (("encoding", encoded), ("case", value.swapcase())):
            if changed != value:
                record = deepcopy(case.record)
                record[key] = changed
                yield family, record


def evaluate_fragility(pack: RuleLoadResult, cases: list[SyntheticCase]) -> dict[str, Any]:
    """Return per-rule losses / successfully evaluated variants, or null.

    Inputs must be synthetic; only explicitly selected, flat string fields are
    changed. Baseline misses and evaluation errors never count as rule breaks.
    Reports contain counts and rule attribution, not event contents.
    """
    if len(cases) > 100:
        raise ValueError("synthetic_case_limit")
    known = {rule.id for rule in pack.rules}
    for case in cases:
        if case.rule_id not in known:
            raise ValueError("unknown_rule_id")
        if (not case.fields or len(case.fields) > 16 or len(set(case.fields)) != len(case.fields)
                or any(not isinstance(key, str) or key not in case.record
                       or not isinstance(case.record[key], str)
                       or len(case.record[key]) > 2048 for key in case.fields)):
            raise ValueError("invalid_mutation_fields")

    reports = []
    for rule in pack.rules:
        families = {name: {"evaluated": 0, "lost": 0, "errors": 0}
                    for name in ("field_rename", "encoding", "case")}
        baseline_matches = baseline_misses = baseline_errors = 0
        for case in (case for case in cases if case.rule_id == rule.id):
            try:
                matched = rule.matches(case.record)
            except SigmaEvaluationError:
                baseline_errors += 1
                continue
            if not matched:
                baseline_misses += 1
                continue
            baseline_matches += 1
            for family, record in _variants(case):
                try:
                    matched = rule.matches(record)
                except SigmaEvaluationError:
                    families[family]["errors"] += 1
                    continue
                families[family]["evaluated"] += 1
                families[family]["lost"] += int(not matched)
        evaluated = sum(item["evaluated"] for item in families.values())
        lost = sum(item["lost"] for item in families.values())
        reports.append({"rule_id": rule.id, "title": rule.title, "author": rule.author,
                        "source": rule.source, "baseline_matches": baseline_matches,
                        "baseline_misses": baseline_misses, "baseline_errors": baseline_errors,
                        "evaluated": evaluated, "lost": lost,
                        "fragility_score": lost / evaluated if evaluated else None,
                        "families": families})
    return {"rules": reports, "issues": [{"source": issue.source, "status": issue.status,
                                          "reason": issue.reason} for issue in pack.issues]}
