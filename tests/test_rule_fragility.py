"""Offline behavior of the synthetic Sigma fragility measurement."""

from copy import deepcopy

import pytest

from src.engine.rule_fragility import SyntheticCase, evaluate_fragility
from src.engine.sigma import (CompiledRule, MAX_EVENT_TEXT, SigmaEvaluationError,
                              load_curated_rules)


RULE = "7be5fb68-f9ef-476d-8b51-0256ebece19e"


@pytest.fixture
def case():
    return SyntheticCase(RULE, {"Channel": "Microsoft-Windows-Sysmon/Operational",
                                "EventID": 1, "Image": r"C:\Windows\hostname.exe"},
                         ("Image",))


def test_scores_changed_variants_with_attribution_and_no_input_mutation(case):
    original = deepcopy(case.record)
    pack = load_curated_rules()
    result = evaluate_fragility(pack, [case])
    rule = next(item for item in result["rules"] if item["rule_id"] == RULE)
    assert (rule["baseline_matches"], rule["lost"], rule["evaluated"]) == (1, 2, 3)
    assert rule["fragility_score"] == pytest.approx(2 / 3)
    assert [(rule["families"][name]["lost"], rule["families"][name]["evaluated"])
            for name in ("field_rename", "encoding", "case")] == [(1, 1), (1, 1), (0, 1)]
    assert rule["author"] and rule["source"]
    assert any(issue["status"] == "unsupported" for issue in result["issues"])
    assert case.record == original
    assert result == evaluate_fragility(pack, [case])
    assert next(item for item in result["rules"] if item["rule_id"] != RULE)["fragility_score"] is None


def test_baseline_miss_and_error_are_not_losses(case):
    miss = SyntheticCase(RULE, {**case.record, "Image": "other.exe"}, case.fields)
    error = SyntheticCase(RULE, {**case.record, "Channel": "x" * (MAX_EVENT_TEXT + 1)}, case.fields)
    result = evaluate_fragility(load_curated_rules(), [miss, error])
    rule = next(item for item in result["rules"] if item["rule_id"] == RULE)
    assert (rule["baseline_misses"], rule["baseline_errors"], rule["evaluated"]) == (1, 1, 0)
    assert rule["fragility_score"] is None


def test_variant_errors_excluded_from_denominator(case, monkeypatch):
    original = CompiledRule.matches

    def matches(rule, record):
        if "mutated_Image" in record:
            raise SigmaEvaluationError("synthetic_error")
        return original(rule, record)

    monkeypatch.setattr(CompiledRule, "matches", matches)
    result = evaluate_fragility(load_curated_rules(), [case])
    rule = next(item for item in result["rules"] if item["rule_id"] == RULE)
    assert rule["families"]["field_rename"]["errors"] == 1
    assert (rule["lost"], rule["evaluated"], rule["fragility_score"]) == (1, 2, 0.5)


def test_no_op_mutations_are_not_scored(case):
    # A collision prevents a destructive rename; numeric text has no case variant.
    rule = load_curated_rules()
    synthetic = SyntheticCase(RULE, {**case.record, "Extra": "123", "mutated_Extra": "x"}, ("Extra",))
    report = next(x for x in evaluate_fragility(rule, [synthetic])["rules"] if x["rule_id"] == RULE)
    assert report["baseline_matches"] == 1 and report["evaluated"] == 1
    assert report["families"]["case"]["evaluated"] == 0
    assert report["families"]["field_rename"]["evaluated"] == 0


@pytest.mark.parametrize("fields", [("Missing",), ("EventID",), ("Image", "Image"), ()])
def test_invalid_mutation_fields_rejected(case, fields):
    with pytest.raises(ValueError, match="invalid_mutation_fields"):
        evaluate_fragility(load_curated_rules(), [SyntheticCase(RULE, case.record, fields)])


def test_unknown_rule_and_case_limit_rejected(case):
    pack = load_curated_rules()
    with pytest.raises(ValueError, match="unknown_rule_id"):
        evaluate_fragility(pack, [SyntheticCase("unknown", case.record, case.fields)])
    with pytest.raises(ValueError, match="synthetic_case_limit"):
        evaluate_fragility(pack, [case] * 101)
