"""Offline-first evaluation cohort partitioning and per-run summaries.

The manifest and reports are local evaluation artifacts, not inference input.
Their hashes are integrity checks, not protection against guessing source names.
"""

from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

from src.engine.evaluation import AccuracyTracker, wilson_score_interval
from src.engine.attack import summarize_comparisons, rule_techniques, validate_techniques
from src.engine.sigma import SigmaEvaluationError
from src.engine.evtx import EvtxIntakeEngine
from src.models.alert import GroundTruthMetadata, NormalizedAlert
from src.models.timeline import ThreatTimeline


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _event(alert, *, truth: bool) -> dict:
    data = alert.model_dump(mode="json", exclude={"internal_id"})
    if not truth:
        for key in ("source_file", "source_dataset", "ground_truth_label", "ground_truth_metadata"):
            data.pop(key, None)
    return data


REVIEW_COLUMNS = ("sample_id", "source_file", "timestamp", "event_type", "event_data",
                  "decision", "reason", "reviewer")


def review_sample_id(alert: NormalizedAlert) -> str:
    return digest(_event(alert, truth=True))


def collect_review_samples(paths, per_file=2):
    """Read a bounded prefix of each file; no labels are inferred from source."""
    if not paths or isinstance(per_file, bool) or not isinstance(per_file, int) or per_file < 1:
        raise ValueError("Review sources and a positive per-file limit are required")
    alerts, seen, stats = [], set(), []
    for path in paths:
        path = Path(path).resolve()
        if path.suffix.lower() != ".evtx":
            raise ValueError("Review sources must be EVTX files")
        engine = EvtxIntakeEngine()
        batches = engine.ingest_evtx(path, batch_size=1)
        try:
            for batch in batches:
                alert = batch[0]
                key = review_sample_id(alert)
                if key not in seen:
                    seen.add(key)
                    alerts.append(alert)
                if engine.stats.alerts_emitted >= per_file:
                    break
        finally:
            batches.close()
        current = engine.stats
        if current.files_failed or current.parser_errors or current.normalization_errors:
            raise ValueError("Review source has intake errors; no review set was written")
        stats.append({"events": current.alerts_emitted, "missing_timestamps": current.missing_timestamps,
                      "invalid_timestamps": current.invalid_timestamps})
    if not alerts:
        raise ValueError("Review sources contained no events")
    return alerts, stats


def review_row(alert: NormalizedAlert) -> dict:
    """Only editable columns are decision, reason and reviewer."""
    telemetry = dict(alert.original_record)
    telemetry.pop("raw_xml", None)
    return {"sample_id": review_sample_id(alert), "source_file": alert.source_file,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else "",
            "event_type": alert.event_type,
            "event_data": json.dumps(telemetry, sort_keys=True, ensure_ascii=True),
            "decision": "unreviewed", "reason": "", "reviewer": ""}


def write_review_csv(stream, alerts):
    writer = csv.DictWriter(stream, fieldnames=REVIEW_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(review_row(alert) for alert in alerts)


def import_review(alerts, stream):
    """Bind independently reviewed decisions to exact saved events; exclude uncertainty."""
    by_id = {review_sample_id(alert): alert for alert in alerts}
    if len(by_id) != len(alerts) or any(a.ground_truth_label is not None or
                                        a.ground_truth_metadata is not None for a in alerts):
        raise ValueError("Candidate events must be unique and unlabeled")
    reader = csv.DictReader(stream)
    if tuple(reader.fieldnames or ()) != REVIEW_COLUMNS:
        raise ValueError("Review columns are missing or changed")
    rows = list(reader)
    if len(rows) != len(alerts) or {row["sample_id"] for row in rows} != set(by_id):
        raise ValueError("Review must contain exactly one row per candidate")
    if len({row["sample_id"] for row in rows}) != len(rows):
        raise ValueError("Duplicate review sample")
    timelines, uncertain = [], 0
    for row in rows:
        alert = by_id[row["sample_id"]]
        expected = review_row(alert)
        if any(row[key] != expected[key] for key in REVIEW_COLUMNS[:5]) or None in row:
            raise ValueError("Review evidence or row structure was changed")
        decision = row["decision"].strip().lower()
        if decision not in ("malicious", "benign", "uncertain"):
            raise ValueError("Every candidate needs a malicious, benign or uncertain decision")
        if not row["reviewer"].strip() or not row["reason"].strip():
            raise ValueError("Every decision requires a reviewer and independent evidence/reason")
        if decision == "uncertain":
            uncertain += 1
            continue
        truth = GroundTruthMetadata(relative_path=alert.source_file, status="mapped",
                                    label_sources={"independent_review": decision})
        reviewed = alert.model_copy(update={"ground_truth_label": decision,
                                            "ground_truth_metadata": truth}, deep=True)
        timelines.append(ThreatTimeline(grouping_key="reviewed-event", alerts=[reviewed], total_events=1,
                                        correlation_type="potential", correlation_reason="single_reviewed_event"))
    return timelines, uncertain


def timeline_identity(timeline: ThreatTimeline) -> str:
    """Stable across parser-generated UUIDs; detects telemetry and label changes."""
    return digest({"events": [_event(a, truth=True) for a in timeline.alerts],
                   "grouping_key": timeline.grouping_key,
                   "correlation_type": timeline.correlation_type,
                   "correlation_reason": timeline.correlation_reason,
                   "start_time": timeline.start_time.isoformat() if timeline.start_time else None,
                   "end_time": timeline.end_time.isoformat() if timeline.end_time else None,
                   "total_events": timeline.total_events,
                   "enrichment": [e.model_dump(mode="json") for e in timeline.enrichment_data]})


def make_manifest(timelines: list[ThreatTimeline], seed: str, test_percent: int = 20) -> dict:
    """Hash-assign connected source/duplicate-event groups without using labels."""
    if not seed or not 1 <= test_percent <= 99 or not timelines:
        raise ValueError("A nonempty cohort, seed, and test percentage 1-99 are required")
    ids = [timeline_identity(t) for t in timelines]
    if len(set(ids)) != len(ids) or any(not t.alerts for t in timelines):
        raise ValueError("Timelines must be nonempty and unique")
    parent = list(range(len(timelines)))

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen = {}
    for index, timeline in enumerate(timelines):
        for alert in timeline.alerts:
            if not alert.source_file or not alert.source_dataset:
                raise ValueError("Each alert needs source provenance for grouping")
            keys = (("source", digest(alert.source_file)),
                    ("event", digest(_event(alert, truth=False))))
            for key in keys:
                if key in seen:
                    parent[root(index)] = root(seen[key])
                else:
                    seen[key] = index
    groups = defaultdict(list)
    for i, identity in enumerate(ids):
        groups[root(i)].append(identity)
    assignments = {}
    for members in groups.values():
        # Group key depends on provenance/telemetry, not truth or the order supplied.
        indices = [ids.index(member) for member in members]
        sources = sorted({digest(a.source_file)
                          for i in indices for a in timelines[i].alerts})
        group_hash = digest([seed, sources])
        split = "test" if int(group_hash, 16) % 100 < test_percent else "development"
        assignments.update({member: split for member in members})
    if set(assignments.values()) != {"development", "test"}:
        raise ValueError("Both splits must contain at least one independent group")
    return {"version": 1, "seed": seed, "test_percent": test_percent,
            "assignments": dict(sorted(assignments.items()))}


def select_split(timelines: list[ThreatTimeline], manifest: dict, split: str) -> list[ThreatTimeline]:
    if split not in ("development", "test"):
        raise ValueError("Invalid split")
    expected = make_manifest(timelines, manifest["seed"], manifest["test_percent"])
    if manifest != expected:
        raise ValueError("Cohort or split manifest changed")
    return [t for t in timelines if manifest["assignments"][timeline_identity(t)] == split]


def frozen_configuration(manifest: dict, settings: dict) -> dict:
    """Capture the selected settings before test use; store locally, immutably by convention."""
    return {"version": 1, "manifest_hash": digest(manifest), "settings": settings,
            "settings_hash": digest(settings)}


def verify_freeze(manifest: dict, settings: dict, frozen: dict) -> None:
    if frozen != frozen_configuration(manifest, settings):
        raise ValueError("Test configuration or split does not match the frozen configuration")


def _metrics(results) -> dict:
    raw = AccuracyTracker.from_evaluations(results).get_metrics()
    keys = ("total", "tp", "tn", "fp", "fn", "positive_samples", "negative_samples",
            "accuracy", "accuracy_ci95", "precision", "precision_ci95", "recall", "recall_ci95",
            "specificity", "specificity_ci95", "f1_score", "false_positive_rate", "false_negative_rate",
            "unavailable", "unknown", "unknown_ground_truth", "abstained", "labelled_binary_coverage",
            "availability_rate")
    metrics = {key: raw[key] for key in keys}
    for key, denominator in (("accuracy", raw["total"]),
                             ("precision", raw["tp"] + raw["fp"]),
                             ("recall", raw["tp"] + raw["fn"])):
        if not denominator:
            metrics[key] = metrics[key + "_ci95"] = None
    if not raw["positive_samples"]:
        metrics["false_negative_rate"] = None
    if not raw["negative_samples"]:
        metrics["false_positive_rate"] = None
    if not (2 * raw["tp"] + raw["fp"] + raw["fn"]):
        metrics["f1_score"] = None
    if not results:
        metrics["availability_rate"] = None
    return metrics


def evaluate_rules(timeline, rules):
    """Evaluate each supported rule independently; errors are unavailable, not misses."""
    outcomes = {}
    for rule in rules:
        try:
            # Evaluate all events even after a match so errors cannot be hidden.
            matches = [rule.matches(alert.original_record) for alert in timeline.alerts]
            outcomes[rule.id] = any(matches) if matches else None
        except SigmaEvaluationError:
            outcomes[rule.id] = None
    return outcomes


def _rate(successes, total):
    return {"count": successes, "total": total,
            "rate": successes / total if total else None,
            "ci95": wilson_score_interval(successes, total) if total else None}


def summarize_rule_comparison(records, pack):
    """Compare on paired labelled timelines; technique positives require annotations.

    A technique detection is any hit by a rule tagged with that exact technique;
    AI detection is its binary malicious disposition, not a technique prediction.
    Benign false positives are measured across all paired benign timelines.
    """
    mappings = {}
    invalid = {}
    for rule in pack.rules:
        ids, bad = rule_techniques("sigma", rule.tags)
        mappings[rule.id] = ids
        if bad:
            invalid[rule.id] = bad
    techniques = sorted({t for ids in mappings.values() for t in ids} |
                        {t for r in records for t in r["techniques"]})
    rows = {}
    for technique in techniques:
        rule_ids = [key for key, ids in mappings.items() if technique in ids and key not in invalid]
        pairs = []
        for record in records:
            result = record["result"]
            truth = result.ground_truth
            ids, bad = validate_techniques(record["techniques"])
            eligible = truth is False or (truth is True and record["technique_truth_complete"]
                                           and not bad and technique in ids)
            outcomes = record["rule_outcomes"]
            if (eligible and result.llm_prediction is not None and rule_ids and
                    all(outcomes.get(key) is not None for key in rule_ids)):
                pairs.append((truth, any(outcomes[key] for key in rule_ids), result.llm_prediction))
        positive = [(sigma, ai) for truth, sigma, ai in pairs if truth is True]
        negative = [(sigma, ai) for truth, sigma, ai in pairs if truth is False]
        rows[technique] = {"rule_ids": rule_ids, "paired_timelines": len(pairs),
            "not_paired_timelines": len(records) - len(pairs),
            "detection": {"sigma": _rate(sum(s for s, _ in positive), len(positive)),
                          "ai": _rate(sum(a for _, a in positive), len(positive)),
                          "sigma_only": sum(s and not a for s, a in positive),
                          "ai_only": sum(a and not s for s, a in positive)},
            "benign_false_positives": {"sigma": _rate(sum(s for s, _ in negative), len(negative)),
                                       "ai": _rate(sum(a for _, a in negative), len(negative))}}
    per_rule = {}
    for rule in pack.rules:
        benign = [r for r in records if r['result'].ground_truth is False and
                  r['rule_outcomes'].get(rule.id) is not None]
        per_rule[rule.id] = {"title": rule.title, "techniques": mappings[rule.id],
                             "benign_false_positives": _rate(
                                 sum(r['rule_outcomes'][rule.id] for r in benign), len(benign)),
                             "unavailable": sum(r['rule_outcomes'].get(rule.id) is None for r in records)}
    return {"input_timelines": len(records), "techniques": rows, "rules": per_rule,
            "rule_issues": [{"source": issue.source, "status": issue.status, "reason": issue.reason}
                            for issue in pack.issues], "invalid_rule_techniques": invalid,
            "limits": ["Paired timelines only; AI uses the recorded binary prediction basis, Sigma uses exact rule tags.",
                       "Benign false positives are not technique-specific ground truth; annotations may be incomplete.",
                       "Intervals assume independent timelines; small or related samples limit interpretation.",
                       "Unsupported rules are excluded; counts describe this pack and cohort, not general performance."]}


def summarize(records: list[dict]) -> dict:
    """Summarize one repetition; each record carries a locally evaluated result."""
    metrics = _metrics([r["result"] for r in records])
    counts = Counter("unknown" if r["result"].ground_truth is None else
                     "malicious" if r["result"].ground_truth else "benign" for r in records)
    techniques = defaultdict(list)
    for record in records:
        for technique in record["techniques"]:
            techniques[technique].append(record["result"])
    breakdown = {key: _metrics(values) for key, values in sorted(techniques.items())}
    errors = [{"timeline_id": str(r["result"].timeline_id),
               "verdict_id": str(r["result"].verdict_id), "category": r["result"].category,
               "techniques": r["techniques"], "review_status": "pending analyst review"}
              for r in records if r["result"].category in ("False Positive", "False Negative")]
    latency = [r["elapsed_seconds"] for r in records]
    return {"metrics": metrics, "input_class_balance": dict(counts),
            "techniques": breakdown, "technique_prediction": summarize_comparisons(
                [r.get('technique_comparison', {'status': 'unavailable'}) for r in records]), "errors": errors,
            "acquisition_origins": dict(Counter(r["origin"] for r in records)),
            "latency_seconds": {"count": len(latency), "mean": sum(latency) / len(latency) if latency else None,
                                "max": max(latency) if latency else None},
            "limits": ["Wilson intervals assume independent observations; related events can violate this assumption.",
                       "Per-technique results use independent dataset annotations and may overlap.",
                       "Technique comparison is annotation-based; shared tactics do not establish correct techniques.",
                       "Latency measures acquisition including pacing, not complete pipeline latency.",
                       "False positives and negatives require human review."]}
