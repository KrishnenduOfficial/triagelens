"""Offline contracts for the documented local Sigma subset and attributed pack."""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil

import pytest
import yaml

from conftest import PipelineTestEngine
from src.engine.evtx import EvtxIntakeEngine
from src.engine import sigma
from src.engine.sigma import (MAX_EVENT_TEXT, MAX_RULE_BYTES, SigmaEvaluationError,
                              load_rule, load_rules, load_curated_rules)
from src.engine.timeline import TimelineBuilder
from src.models.alert import GroundTruthMetadata, NormalizedAlert


def document(detection=None, logsource=None, **metadata):
    return {
        "title": "Synthetic rule", "id": "01234567-89ab-4cde-8fab-0123456789ab",
        "author": "Synthetic fixture author", "license": "MIT",
        "logsource": logsource or {"product": "windows", "category": "process_creation"},
        "detection": detection or {"selection": {"Image|endswith": r"\hostname.exe"},
                                    "condition": "selection"}, **metadata,
    }


def compiled(detection=None, logsource=None):
    result = load_rule(yaml.safe_dump(document(detection, logsource)))
    assert result.issues == ()
    assert len(result.rules) == 1
    return result.rules[0]


def event_record(**fields):
    return {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, **fields}


def alert(record, **metadata):
    return NormalizedAlert(source_dataset="fixture", source_file="fixture.evtx",
                           event_type="fixture", original_record=record, **metadata)


@pytest.mark.parametrize("key,value,actual,expected", [
    ("Image", "AbC", "abc", True),
    ("Image", "AbC", "prefixabc", False),
    ("Image", "a?c*", "ABCxyz", True),
    ("Image", r"a\*c", "a*c", True),
    ("Image", r"a\*c", "abc", False),
    ("Image", "[ab]", "a", False),
    ("Image|contains", "needle", "prefixNEEDLEsuffix", True),
    ("Image|contains", "a.b", "xaXby", False),
    ("Image|contains", "a?b", "xa\nby", True),
    ("Image|startswith", "start", "STARTsuffix", True),
    ("Image|startswith", "start", "prefixstart", False),
    ("Image|endswith", "end", "prefixEND", True),
    ("Image|endswith", "end", "endprefix", False),
    ("Image", ["first", "second"], "SECOND", True),
    ("Image|contains|all", ["one", "two"], "TWO and ONE", True),
    ("Image|contains|all", ["one", "two"], "ONE", False),
    ("Image|startswith|all", ["a", "ab"], "ABC", True),
    ("Image|endswith|all", ["c", "bc"], "ABC", True),
    ("Image|all", ["same", "SAME"], "same", True),
    ("Image|re", r"abc[0-9]+", "prefixabc42suffix", True),
    ("Image|re", r"^abc$", "prefixabc", False),
    ("Image|re", r"abc", "ABC", False),
    ("Image|re", r"(?i)abc", "ABC", True),
    ("Image|re", r"(?s)a.b", "a\nb", True),
    ("Image|re|all", [r"^a", r"c$"], "abc", True),
    ("Image|re", [r"^a", r"^b"], "bee", True),
])
def test_modifiers_wildcards_escaping_and_case(key, value, actual, expected):
    rule = compiled({"selection": {key: value}, "condition": "selection"})
    assert rule.matches(event_record(Image=actual)) is expected


@pytest.mark.parametrize("condition,a,b,c,expected", [
    ("a or b and c", True, False, False, True),
    ("(a or b) and c", True, False, False, False),
    ("a and not b", True, False, False, True),
    ("not (a or b)", False, False, True, True),
    ("1 of selection_*", False, True, False, True),
    ("all of selection_*", True, True, True, True),
    ("all of selection_*", True, False, True, False),
    ("1 of them", False, False, True, True),
    ("all of them", True, True, False, False),
    ("a and not 1 of selection_*", True, False, False, False),
    ("not not a", True, False, False, True),
])
def test_conditions_and_selection_expansion(condition, a, b, c, expected):
    detection = {"a": {"Image": "yes"}, "b": {"CommandLine": "yes"},
                 "c": {"ParentImage": "yes"}}
    if "selection_" in condition:
        detection.update({"selection_a": deepcopy(detection["a"]),
                          "selection_b": deepcopy(detection["b"]),
                          "selection_c": deepcopy(detection["c"])})
    rule = compiled({**detection, "condition": condition})
    record = event_record(Image="yes" if a else "no", CommandLine="yes" if b else "no",
                          ParentImage="yes" if c else "no")
    assert rule.matches(record) is expected


def test_mapping_fields_are_and_list_of_mappings_are_or():
    rule = compiled({"selection": [{"Image": "a", "CommandLine": "b"}, {"Image": "c"}],
                     "condition": "selection"})
    assert rule.matches(event_record(Image="a", CommandLine="b"))
    assert not rule.matches(event_record(Image="a", CommandLine="wrong"))
    assert rule.matches(event_record(Image="c"))


@pytest.mark.parametrize("actual", [None, [], {"nested": "hostname.exe"}, "", False, 3])
def test_missing_and_incompatible_values_are_not_stringified(actual):
    rule = compiled()
    assert not rule.matches(event_record(Image=actual))
    assert not rule.matches(event_record())


def test_null_and_missing_under_not_have_explicit_boolean_semantics():
    null = compiled({"selection": {"Image": None}, "condition": "selection"})
    assert null.matches(event_record()) and null.matches(event_record(Image=None))
    assert not null.matches(event_record(Image="some.exe"))
    negative = compiled({"selection": {"Image": "blocked.exe"}, "condition": "not selection"})
    assert negative.matches(event_record())
    assert not negative.matches(event_record(Image="blocked.exe"))


@pytest.mark.parametrize("logsource,record,expected", [
    ({"category": "process_creation"}, event_record(Image=r"C:\hostname.exe"), True),
    ({"category": "process_creation"}, {"Channel": "SECURITY", "EventID": 4688,
                                         "NewProcessName": r"C:\hostname.exe"}, True),
    ({"category": "process_creation"}, event_record(EventID=3, Image=r"C:\hostname.exe"), False),
    ({"category": "process_creation"}, {"EventID": 1, "Image": r"C:\hostname.exe"}, False),
    ({"category": "process_creation"}, {"Channel": "Security", "EventID": 1,
                                         "Image": r"C:\hostname.exe"}, False),
    ({"category": "process_creation", "service": "sysmon"},
     {"Channel": "Security", "EventID": 4688, "NewProcessName": r"C:\hostname.exe"}, False),
    ({"service": "security"}, {"Channel": "Security", "EventID": 1102,
                               "Image": r"C:\hostname.exe"}, True),
    ({"service": "security"}, event_record(Image=r"C:\hostname.exe"), False),
    ({"category": "network_connection"}, event_record(EventID=3, Image=r"C:\hostname.exe"), True),
    ({"category": "network_connection"}, event_record(Image=r"C:\hostname.exe"), False),
])
def test_logsource_requires_observed_channel_and_category_event(logsource, record, expected):
    assert compiled(logsource={"product": "windows", **logsource}).matches(record) is expected


@pytest.mark.parametrize("shape", ["flat", "adapter", "export", "canonical"])
def test_equivalent_record_shapes_reuse_canonical_resolver(shape):
    if shape == "flat":
        record = event_record(Image=r"C:\hostname.exe")
    elif shape == "adapter":
        record = event_record(Details={"EventData.Image": r"C:\hostname.exe"})
    elif shape == "export":
        record = {"Event": {"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1},
                            "EventData": {"Image": r"C:\hostname.exe"}}}
    else:
        record = {"metadata": {"event_code": "1", "log_name": "Microsoft-Windows-Sysmon/Operational"},
                  "process.file.path": r"C:\hostname.exe"}
    assert compiled().matches(record)


def test_canonical_types_alias_precedence_and_independent_account_roles():
    rule = compiled({"s": {"EventID": 4688, "process.pid": 42,
                            "process.parent_process.pid": 7,
                            "SubjectUserName": "creator", "TargetUserName": "target"},
                     "condition": "s"})
    record = {"Channel": "Security", "EventID": "4688", "NewProcessId": "0x2a", "ProcessId": "0x7",
              "SubjectUserName": "creator", "TargetUserName": "target"}
    assert rule.matches(record)
    assert not rule.matches({**record, "NewProcessId": None})
    assert not rule.matches({**record, "process.pid": 43})
    code_text = compiled({"s": {"EventID": "1"}, "condition": "s"})
    assert code_text.matches(event_record())


def test_network_logsource_maps_endpoint_fields_and_typed_ports():
    rule = compiled({"s": {"SourceIp": "192.0.2.1", "DestinationIp": "198.51.100.2",
                            "SourcePort": 12345, "DestinationPort": 443}, "condition": "s"},
                    {"product": "windows", "category": "network_connection"})
    record = event_record(EventID=3, Details={"EventData.SourceIp": "192.0.2.1",
                                             "EventData.DestinationIp": "198.51.100.2",
                                             "EventData.SourcePort": "12345",
                                             "EventData.DestinationPort": "443"})
    assert rule.matches(record)
    record["Details"]["EventData.DestinationPort"] = "65536"
    assert not rule.matches(record)


@pytest.mark.parametrize("key,value,reason", [
    ("Image|base64", "abc", "modifier_or_combination"),
    ("Image|cidr", "192.0.2.0/24", "modifier_or_combination"),
    ("Image|contains|startswith", "abc", "modifier_or_combination"),
    ("Image|contains|contains", "abc", "modifier_or_combination"),
    ("Image|re", r"(a)\1", "unsupported_or_invalid_re2"),
    ("Image|re", r"(?=a)", "unsupported_or_invalid_re2"),
    ("Image|re", "[", "unsupported_or_invalid_re2"),
    ("OriginalFileName", "fixture.exe", "unmapped_field:OriginalFileName"),
    ("ground_truth_label", "malicious", "unmapped_field:ground_truth_label"),
    ("source_file", "filename", "unmapped_field:source_file"),
    ("Image", True, "value_type"),
    ("Image", 1.5, "value_type"),
    ("Image", 42, "numeric_rule_for_text_field"),
    ("process.pid", "42", "text_rule_for_numeric_field"),
    ("process.pid", 2**53, "integer_range"),
    ("Image|contains", 42, "numeric_rule_for_text_field"),
    ("Image|re", None, "modifier_value_type"),
    ("Image", "x" * 2049, "value_length_limit"),
])
def test_unsupported_field_modifier_and_value_diagnostics(key, value, reason, capsys):
    result = load_rule(yaml.safe_dump(document({"s": {key: value}, "condition": "s"})))
    assert result.rules == ()
    assert [(issue.status, issue.reason) for issue in result.issues] == [("unsupported", reason)]
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("patch,reason", [
    ({"logsource": {"product": "linux", "category": "process_creation"}}, "logsource_product"),
    ({"logsource": {"product": "windows", "category": "registry_event"}}, "logsource_category"),
    ({"logsource": {"product": "windows", "service": "powershell"}}, "logsource_service"),
    ({"logsource": {"product": "windows", "category": "network_connection", "service": "security"}},
     "incompatible_logsource"),
    ({"logsource": {"product": "windows", "service": "security", "other": "value"}}, "logsource_attribute"),
    ({"detection": {"s": ["keyword"], "condition": "s"}}, "keyword_or_empty_selection"),
    ({"detection": {"s": {"Image": "x"}, "condition": ["s"]}}, "condition_list_or_type"),
    ({"detection": {"s": {"Image": "x"}, "timeframe": "5m", "condition": "s"}}, "timeframe"),
    ({"detection": {"s": {"Image": "x"}, "condition": "2 of them"}}, "condition_quantifier"),
    ({"detection": {"s": {"Image": "x"}, "condition": "any of them"}}, "condition_quantifier"),
    ({"detection": {"s": {"Image": "x"}, "condition": "s | count() > 2"}}, "condition_operator"),
    ({"correlation": {"type": "event_count"}}, "collection_or_correlation"),
    ({"action": "global"}, "collection_or_correlation"),
    ({"filter": {}}, "collection_or_correlation"),
    ({"taxonomy": "custom"}, "taxonomy"),
])
def test_unsupported_rule_features_are_visible(patch, reason):
    result = load_rule(yaml.safe_dump(document(**patch)))
    assert result.rules == () and result.issues[0].reason == reason
    assert result.issues[0].status == "unsupported"


@pytest.mark.parametrize("detection", [
    {"s": {"Image": "x"}, "condition": "missing"},
    {"s": {"Image": "x"}, "condition": "1 of absent_*"},
    {"s": {"Image": "x"}, "condition": "s and"},
    {"s": {"Image": "x"}, "condition": "(s"},
    {"s": {"Image|all": ["one"]}, "condition": "s"},
    {"s": {"Image": []}, "condition": "s"},
])
def test_invalid_conditions_or_empty_values_withhold_whole_rule(detection):
    result = load_rule(yaml.safe_dump(document(detection)))
    assert result.rules == () and result.issues[0].status == "invalid"


@pytest.mark.parametrize("text", [
    "[]", "[invalid", "title: one\ntitle: two", "1: value", "? [one, two]\n: value",
    "title: !!python/object/apply:os.system [echo forbidden]", "---\n{}\n---\n{}",
    "title: &a fixture\nauthor: *a", "a: &a [*a]",
    "x" * (MAX_RULE_BYTES + 1),
])
def test_malformed_unsafe_or_oversized_yaml_rejected(text):
    result = load_rule(text)
    assert not result.rules and result.issues


@pytest.mark.parametrize("field,value", [("title", None), ("id", "bad-uuid"),
                                          ("author", ""), ("logsource", None), ("tags", 42)])
def test_required_and_invalid_metadata(field, value):
    rule = document()
    rule[field] = value
    result = load_rule(yaml.safe_dump(rule))
    assert result.rules == () and result.issues[0].status == "invalid"


def test_unreferenced_unsupported_selection_still_rejects_rule():
    result = load_rule(yaml.safe_dump(document({"s": {"Image": "x"},
                                               "unused": {"OriginalFileName": "x"}, "condition": "s"})))
    assert not result.rules and result.issues[0].reason == "unmapped_field:OriginalFileName"


def test_bounds_on_condition_yaml_and_expanded_ast():
    for condition in ("not " * 13 + "s", "(" * 13 + "s" + ")" * 13,
                      " or ".join(["s"] * 66)):
        result = load_rule(yaml.safe_dump(document({"s": {"Image": "x"}, "condition": condition})))
        assert not result.rules and "limit" in result.issues[0].reason
    text = "nested: " + "[" * 26 + "x" + "]" * 26
    assert load_rule(text).issues[0].reason == "yaml_depth_limit"
    detection = {f"s{i}": {"Image": [str(j) for j in range(40)]} for i in range(12)}
    detection["condition"] = " and ".join(["1 of them"] * 8)
    result = load_rule(yaml.safe_dump(document(detection)))
    assert not result.rules and result.issues[0].reason == "expanded_condition_limit"


def test_event_limit_withholds_partial_matches_and_never_truncates():
    pack = load_curated_rules()
    record = event_record(Image=r"C:\hostname.exe", CommandLine="x" * (MAX_EVENT_TEXT + 1))
    with pytest.raises(SigmaEvaluationError, match="^event_text_limit$"):
        pack.evaluate(alert(record))
    assert pack.evaluate(alert(event_record(Image=r"C:\hostname.exe")))


def test_local_loader_file_errors_duplicates_and_count_limit(tmp_path):
    valid = tmp_path / "valid.yml"
    valid.write_text(yaml.safe_dump(document()), encoding="utf-8")
    broken = tmp_path / "broken.yml"
    broken.write_bytes(b"\xff")
    too_big = tmp_path / "large.yml"
    too_big.write_bytes(b"x" * (MAX_RULE_BYTES + 1))
    result = load_rules([valid, valid, broken, too_big, tmp_path / "missing.yml"])
    assert len(result.rules) == 1
    assert [issue.reason for issue in result.issues] == ["duplicate_rule_id", "unreadable_rule",
                                                       "rule_byte_limit", "unreadable_rule"]
    consumed = []
    def paths():
        for i in range(100):
            consumed.append(i)
            yield valid
    result = load_rules(paths())
    assert consumed == list(range(31))
    assert result.issues[-1].reason == "rule_count_limit"


def test_curated_pack_hashes_attribution_fixtures_and_unsupported_inventory():
    folder = Path(__file__).resolve().parents[1] / "rules" / "sigma"
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["rules"]) == 3 <= 30
    for entry in manifest["rules"]:
        assert hashlib.sha256((folder / entry["file"]).read_bytes()).hexdigest() == entry["sha256"]
        assert manifest["revision"] in entry["source"]
    pack = load_curated_rules()
    assert len(pack.rules) == 2
    assert [(issue.status, issue.reason) for issue in pack.issues] == [
        ("unsupported", "unmapped_field:OriginalFileName")]
    cases = [
        (event_record(Image=r"C:\Windows\System32\HOSTNAME.EXE"), "frack113"),
        (event_record(CommandLine="auditpol fixture /logon:none"),
         "Nasreddine Bencherchali (Nextron Systems)"),
    ]
    for record, author in cases:
        event = alert(record)
        matches = pack.evaluate(event)
        assert len(matches) == 1
        match = matches[0]
        assert match.author == author and match.license == "DRL-1.1"
        assert match.event_id == str(event.internal_id)
        assert match.source.startswith(manifest["repository"] + "/blob/" + manifest["revision"])
        assert match.tags and match.level in ("low", "high")
    assert pack.evaluate(alert(event_record(Image=r"C:\Windows\notepad.exe", CommandLine="fixture"))) == ()


@pytest.mark.parametrize("failure", ["hash", "missing_rule", "author", "duplicate", "manifest", "schema"])
def test_curated_pack_integrity_failures_are_explicit(tmp_path, monkeypatch, failure):
    real_folder = Path(sigma.__file__).resolve().parents[2] / "rules" / "sigma"
    folder = tmp_path / "rules" / "sigma"
    shutil.copytree(real_folder, folder)
    monkeypatch.setattr(sigma, "__file__", str(tmp_path / "src" / "engine" / "sigma.py"))
    manifest_path = folder / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rule_path = folder / manifest["rules"][0]["file"]
    if failure == "hash":
        rule_path.write_bytes(rule_path.read_bytes() + b"\n# changed\n")
        result = load_curated_rules()
        assert result.issues[0].reason == "curated_hash_mismatch"
        assert result.evaluate(alert(event_record(Image=r"C:\hostname.exe"))) == ()
    elif failure == "missing_rule":
        rule_path.unlink()
        result = load_curated_rules()
        assert result.issues[0].reason == "unreadable_rule"
    elif failure == "manifest":
        manifest_path.write_text("broken-json", encoding="utf-8")
        with pytest.raises(SigmaEvaluationError, match="^curated_manifest_unavailable$"):
            load_curated_rules()
    elif failure == "schema":
        manifest_path.write_text('{"rules": 42}', encoding="utf-8")
        with pytest.raises(SigmaEvaluationError, match="^invalid_curated_manifest$"):
            load_curated_rules()
    else:
        if failure == "author":
            manifest["rules"][0]["author"] = "wrong fixture author"
        else:
            manifest["rules"].append(deepcopy(manifest["rules"][0]))
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        if failure == "author":
            with pytest.raises(SigmaEvaluationError, match="^curated_attribution_mismatch$"):
                load_curated_rules()
        else:
            assert load_curated_rules().issues[-1].reason == "duplicate_rule_id"


def test_evtx_normalized_security_event_evaluates_without_reingestion():
    xml = ('<Event><System><EventID>4688</EventID><Channel>Security</Channel></System>'
           '<EventData><Data Name="NewProcessName">C:\\Windows\\HOSTNAME.EXE</Data>'
           '<Data Name="NewProcessId">0x2a</Data><Data Name="ProcessId">0x7</Data>'
           '</EventData></Event>')
    event = EvtxIntakeEngine()._normalize({"data": xml}, Path("synthetic.evtx"))
    assert len(load_curated_rules().evaluate(event)) == 1


def test_rule_results_are_separate_from_labels_predictions_and_prompts(capsys):
    event = alert(event_record(Image=r"C:\hostname.exe"), ground_truth_label="benign",
                  ground_truth_metadata=GroundTruthMetadata(relative_path="T1003-label-canary.evtx",
                                                            status="mapped", technique_ids=["T1003"]))
    before = deepcopy(event.model_dump())
    engine = PipelineTestEngine(api_key="offline-placeholder", fallback_models=[], enable_cache=False)
    timeline = TimelineBuilder().build_timelines([event])[0]
    payload_before = engine._build_sanitized_triage_payload(timeline)
    hits = load_curated_rules().evaluate(event)
    assert event.model_dump() == before
    assert engine._build_sanitized_triage_payload(timeline) == payload_before
    prompt = json.dumps(payload_before)
    assert all(word not in prompt for word in (hits[0].rule_id, "frack113", "label-canary", "attack.t1082"))
    assert "ground_truth" not in asdict(hits[0])
    assert capsys.readouterr() == ("", "")


def test_labels_and_provenance_cannot_supply_missing_detection_fields():
    record = event_record(ground_truth_label="malicious", detections={"Image": r"C:\hostname.exe"},
                          source_file=r"C:\hostname.exe", metadata={"Image": r"C:\hostname.exe"})
    assert load_curated_rules().evaluate(alert(record)) == ()


def test_regex_pathological_backtracking_pattern_finishes_with_re2():
    rule = compiled({"s": {"CommandLine|re": "(a+)+$"}, "condition": "s"})
    assert not rule.matches(event_record(CommandLine="a" * 32000 + "!"))
