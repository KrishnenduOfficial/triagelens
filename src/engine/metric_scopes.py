"""Explicit metric counting units and immutable, evaluation-only cohort declarations.

No current labels, prompt construction, or cache-expiry checks belong in selection.
All rows used for a response are copied from one SQLite read snapshot.
"""

import hashlib
import json
import re
from uuid import UUID

from src.engine.evaluation import AccuracyTracker
from src.models.evaluation import EvaluationResult


class MetricSelectionError(ValueError):
    def __init__(self, message, status_code=409):
        super().__init__(message)
        self.status_code = status_code


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def normalize_manifest(manifest):
    """Reject ambiguous case/context assignments before hashing a declaration."""
    fields = {"version", "kind", "revision", "evaluator_version", "label_policy_version",
              "inference_policy_hash", "members"}
    if not isinstance(manifest, dict):
        raise MetricSelectionError("Invalid cohort manifest", 422)
    expected = fields | ({"source_run_id"} if manifest.get("kind") == "ad_hoc" else set())
    if set(manifest) != expected or type(manifest.get("version")) is not int or manifest["version"] != 1:
        raise MetricSelectionError("Unsupported cohort manifest", 422)
    if manifest["kind"] not in ("ad_hoc", "declared"):
        raise MetricSelectionError("Unsupported cohort kind", 422)
    if (manifest["evaluator_version"] not in ("AccuracyTracker-v1", "AccuracyTracker-disposition-v1") or
            manifest["label_policy_version"] != "evaluation-context-v1"):
        raise MetricSelectionError("Unsupported evaluator or label-policy version", 422)
    if not isinstance(manifest["revision"], str) or not manifest["revision"].strip():
        raise MetricSelectionError("Cohort revision is required", 422)
    if not _hash(manifest["inference_policy_hash"]):
        raise MetricSelectionError("Invalid cohort inference policy", 422)
    if not isinstance(manifest["members"], list) or not manifest["members"]:
        raise MetricSelectionError("Cohort must declare case/context members", 422)
    members = {}
    for member in manifest["members"]:
        if not isinstance(member, dict) or set(member) != {"case_id", "evidence_hash", "evaluation_context_hash"}:
            raise MetricSelectionError("Invalid cohort member", 422)
        try:
            case_id = str(UUID(member["case_id"]))
        except (ValueError, TypeError, AttributeError):
            raise MetricSelectionError("Invalid cohort case identity", 422) from None
        if not _hash(member["evidence_hash"]) or not _hash(member["evaluation_context_hash"]):
            raise MetricSelectionError("Invalid cohort member fingerprints", 422)
        if case_id in members:
            raise MetricSelectionError("Conflicting case assignments in cohort")
        members[case_id] = {**member, "case_id": case_id}
    normalized = {**manifest, "members": [members[key] for key in sorted(members)]}
    if manifest["kind"] == "ad_hoc":
        try:
            normalized["source_run_id"] = str(UUID(manifest["source_run_id"]))
        except (ValueError, TypeError, AttributeError):
            raise MetricSelectionError("Invalid ad hoc source run", 422) from None
    return normalized


def validate_selectors(scope, run_id=None, cohort_id=None):
    if scope not in ("history", "run", "quality", "attempts"):
        raise MetricSelectionError("Unknown metric scope", 422)
    valid = ((scope == "history" and run_id is None and cohort_id is None) or
             (scope == "run" and run_id is not None and cohort_id is None) or
             (scope == "quality" and run_id is None and cohort_id is not None) or
             (scope == "attempts" and ((run_id is None) != (cohort_id is None))))
    if not valid:
        raise MetricSelectionError("Invalid metric scope/selector combination", 422)
    if run_id is not None:
        try:
            run_id = str(UUID(str(run_id)))
        except (ValueError, TypeError, AttributeError):
            raise MetricSelectionError("Invalid run identifier", 422) from None
    if cohort_id is not None and not _hash(cohort_id):
        raise MetricSelectionError("Invalid cohort identifier", 422)
    return run_id


def _manifest(snapshot, cohort_id):
    record = snapshot["cohorts"].get(cohort_id)
    if record is None:
        raise MetricSelectionError("Unknown or undeclared quality cohort", 404)
    manifest = normalize_manifest(json.loads(record))
    if fingerprint(manifest) != cohort_id:
        raise MetricSelectionError("Cohort manifest integrity failure")
    return manifest


def _verified_member(row, observation, run, manifest, members):
    """Verify historical acquisition metadata, never today's cache TTL or labels."""
    if (row["provenance_version"] != 1 or not observation or
            observation["origin"] not in ("fresh", "cache") or
            not _hash(observation["evidence_hash"]) or
            not _hash(observation["inference_policy_hash"]) or
            not _hash(row["evaluation_context_hash"]) or
            (observation["origin"] == "fresh" and observation["attempt_id"] is None) or
            (observation["origin"] == "cache" and observation["cache_validation"] != "verified")):
        return False
    if (observation["status"] != "completed" or observation["timeline_id"] != row["timeline_id"] or
            observation["verdict_id"] != row["verdict_id"] or
            row["quality_cohort_hash"] != run["quality_cohort_hash"]):
        raise MetricSelectionError("Evaluation provenance integrity failure")
    member = members.get(row["timeline_id"])
    evaluator = ("AccuracyTracker-disposition-v1" if row["prediction_basis"] == "explicit_disposition_v1"
                 else "AccuracyTracker-v1")
    if row["verdict_id"] is not None and manifest["evaluator_version"] != evaluator:
        raise MetricSelectionError("Outcome prediction basis does not match cohort evaluator")
    if (member is None or member["evidence_hash"] != observation["evidence_hash"] or
            member["evaluation_context_hash"] != row["evaluation_context_hash"] or
            manifest["inference_policy_hash"] != observation["inference_policy_hash"]):
        raise MetricSelectionError("Observation does not match declared cohort membership")
    return True


def run_manifest(snapshot, run_id):
    """Freeze a terminal run as a run-local cohort; never infer missing provenance."""
    run = snapshot["runs"].get(run_id)
    if run is None:
        raise MetricSelectionError("Unknown run", 404)
    if run["status"] not in ("completed", "failed"):
        raise MetricSelectionError("Cohort declaration requires a terminal run")
    members, policies, evaluators = {}, set(), set()
    for row in snapshot["rows"]:
        ob = snapshot["observations"].get(row["observation_id"])
        if not ob or ob["run_id"] != run_id:
            continue
        if (row["provenance_version"] != 1 or ob["status"] != "completed" or
                ob["origin"] not in ("fresh", "cache") or
                (ob["origin"] == "cache" and ob["cache_validation"] != "verified") or
                not all(_hash(v) for v in (ob["evidence_hash"], ob["inference_policy_hash"], row["evaluation_context_hash"]))):
            raise MetricSelectionError("Run contains unverifiable cohort outcomes")
        member = {"case_id": row["timeline_id"], "evidence_hash": ob["evidence_hash"],
                  "evaluation_context_hash": row["evaluation_context_hash"]}
        if member["case_id"] in members and members[member["case_id"]] != member:
            raise MetricSelectionError("Conflicting case assignments in cohort")
        members[member["case_id"]] = member
        policies.add(ob["inference_policy_hash"])
        if row["verdict_id"] is not None:
            evaluators.add("AccuracyTracker-disposition-v1" if row["prediction_basis"] == "explicit_disposition_v1"
                           else "AccuracyTracker-v1")
    if not members or len(policies) != 1:
        raise MetricSelectionError("Run requires nonempty membership and one inference policy")
    if len(evaluators) > 1:
        raise MetricSelectionError("Cohort requires one prediction basis")
    return normalize_manifest({"version": 1, "kind": "ad_hoc", "revision": "1", "source_run_id": run_id,
        "evaluator_version": next(iter(evaluators), "AccuracyTracker-v1"), "label_policy_version": "evaluation-context-v1",
        "inference_policy_hash": next(iter(policies)), "members": list(members.values())})


def scoped_metrics(db, scope="history", run_id=None, cohort_id=None, fallback_tracker=None):
    run_id = validate_selectors(scope, run_id, cohort_id)
    snapshot = db.metric_snapshot()
    runs, observations = snapshot["runs"], snapshot["observations"]
    manifest = _manifest(snapshot, cohort_id) if cohort_id else None
    members = {m["case_id"]: m for m in manifest["members"]} if manifest else {}
    if run_id is not None and run_id not in runs:
        raise MetricSelectionError("Unknown run", 404)
    if run_id is not None:
        selected_runs = {run_id}
    elif cohort_id:
        selected_runs = {r for r, c in snapshot["bindings"].items() if c == cohort_id}
    else:
        selected_runs = set(runs)
    obs = {key: value for key, value in observations.items() if value["run_id"] in selected_runs}
    rows = [row for row in snapshot["rows"] if scope == "history" or row["observation_id"] in obs]
    outcome_observations = {r["observation_id"] for r in rows}
    missing_outcomes = sum(o["status"] == "completed" and key not in outcome_observations for key, o in obs.items())
    if scope in ("quality", "attempts") and missing_outcomes:
        raise MetricSelectionError("Completed observations are missing evaluation outcomes")
    legacy = sum(row["observation_id"] is None or row["provenance_version"] is None for row in snapshot["rows"])
    coverage = {"evaluation_rows": len(rows), "legacy_unknown": legacy,
        "excluded_legacy_unknown": legacy if scope != "history" else 0,
        "outside_selection": len(snapshot["rows"]) - len(rows),
        "observations": len(obs), "missing_outcomes": missing_outcomes,
        "fresh": sum(o["origin"] == "fresh" for o in obs.values()),
        "cache": sum(o["origin"] == "cache" for o in obs.values()),
        "unknown_origin": sum(o["origin"] in (None, "unknown") for o in obs.values()),
        "completed_fresh": sum(o["origin"] == "fresh" and o["status"] == "completed" and o["attempt_id"] is not None for o in obs.values()),
        "deduplicated": 0, "excluded_unverifiable": 0, "excluded_no_verdict": 0}
    for state in ("skipped", "pending", "interrupted"):
        coverage[state] = sum(o["status"] == state for o in obs.values())
    coverage["run_status_counts"] = {state: sum(runs[r]["status"] == state for r in selected_runs)
                                     for state in ("running", "completed", "failed")}
    selected, selected_evidence = [], []
    seen = {}
    for row in rows:
        ob = observations.get(row["observation_id"])
        if manifest and not _verified_member(row, ob, runs[ob["run_id"]], manifest, members):
            coverage["excluded_unverifiable"] += 1
            continue
        if scope == "attempts" and (row["provenance_version"] != 1 or not ob or
                ob["status"] != "completed" or ob["origin"] != "fresh" or not ob["attempt_id"]):
            continue
        if scope == "quality":
            if row["verdict_id"] is None:
                coverage["excluded_no_verdict"] += 1
                continue
            key = (row["verdict_id"], row["evaluation_context_hash"])
            outcome = {k: row[k] for k in EvaluationResult.model_fields
                       if k not in ("observation_id", "quality_cohort_hash", "provenance_version")}
            if key in seen:
                if seen[key] != outcome:
                    raise MetricSelectionError("Conflicting canonical quality snapshots")
                coverage["deduplicated"] += 1
                continue
            seen[key] = outcome
        selected.append(row)
        selected_evidence.append(ob["evidence_hash"] if ob else None)
    # History deliberately retains legacy verdict-column fallback behavior.
    source = "database"
    if scope == "history":
        tracker = AccuracyTracker.from_evaluations(snapshot["history"])
        if not tracker.history and fallback_tracker is not None:
            tracker, source = fallback_tracker, "memory"
    else:
        tracker = AccuracyTracker.from_evaluations([EvaluationResult(**row) for row in selected])
    result = tracker.get_metrics()
    evidence = [value for value in selected_evidence if value is not None]
    coverage.update(selected_units=len(tracker.history), unique_evidence=len(set(evidence)),
                    repeated_evidence=len(evidence) - len(set(evidence)), evidence_unknown=len(selected_evidence) - len(evidence))
    if source == "memory":
        coverage["evidence_unknown"] = len(tracker.history)
    if manifest:
        included_cases = {r["timeline_id"] for r in selected}
        coverage.update(manifest_cases=len(manifest["members"]), included_cases=len(included_cases),
                        missing_cases=len(manifest["members"]) - len(included_cases))
    denominator = len(tracker.history)
    availability_status = "result_availability"
    if scope == "quality":
        result["availability_rate"], denominator = None, None
        availability_status = "not_applicable_to_quality"
    elif scope == "attempts":
        result["availability_rate"] = sum(r["verdict_id"] is not None for r in selected) / denominator if denominator else None
        availability_status = "fresh_result_availability" if denominator else "no_completed_fresh_attempts"
    result["selection"] = {"scope": scope, "source": source,
        "unit": {"history": "evaluation_row", "run": "run_evaluation_row", "quality": "verdict_context", "attempts": "completed_fresh_attempt"}[scope],
        "run_id": run_id, "run_status": runs[run_id]["status"] if run_id else None,
        "cohort_id": cohort_id, "cohort_kind": manifest["kind"] if manifest else None,
        "inference_policy_hash": manifest["inference_policy_hash"] if manifest else None,
        "observed_inference_policies": sorted({o["inference_policy_hash"] for o in obs.values()
                                                if _hash(o["inference_policy_hash"])}),
        "context_selection": "immutable_manifest_members" if manifest else "persisted_outcomes",
        "context_count": len({r["evaluation_context_hash"] for r in selected if r["evaluation_context_hash"]}),
        "availability_status": availability_status, "coverage": coverage,
        "denominators": {"binary": tracker.total_evaluated, "severity": tracker.severity_evaluated,
                         "calibration": len(tracker.confidence_pairs), "availability": denominator},
        "sampling_note": "Deduplication does not establish independent evidence or provider uptime."}
    return result
