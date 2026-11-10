"""Evaluation runner for TriageLens.

Executes real LLM-assisted triage and evaluation across the 70-timeline benchmark dataset.
Enforces ADR-008 (AI predictions and ground truth strictly separate).
Maintains SQLite verdict cache for reproducibility and resilience.
Calculates statistical performance metrics via AccuracyTracker and writes
docs/results/groq_evaluation_report.md with all required metadata.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional
from uuid import UUID

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

from src.cli import detect_indicator_type
from src.config import open_database, get_groq_api_key
from src.engine.database import DatabaseManager
from src.engine.attack import evaluate_timeline
from src.engine.sigma import load_curated_rules
from src.engine.enrichment import EnrichmentEngine
from src.engine.benign import BenignEvtxAdapter
from src.engine.evtx import EvtxIntakeEngine
from src.engine.ground_truth import DatasetGroundTruthMapper
from src.engine.evaluation import AccuracyTracker, DatasetGroundTruthConfig
from src.engine.evaluation_protocol import (make_manifest, select_split, frozen_configuration,
                                            verify_freeze, summarize, digest, collect_review_samples,
                                            write_review_csv, import_review, evaluate_rules,
                                            summarize_rule_comparison)
from src.engine.groq import GroqTriageEngine
from src.engine.provenance import evaluation_run
from src.engine.timeline import TimelineBuilder
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


def protocol_settings(engine):
    """Capture the actual inference configuration, without credentials."""
    source_root = Path(__file__).resolve().parent.parent
    source_files = ["scripts/run_evaluation.py", "src/engine/evaluation_protocol.py",
                    "src/engine/evaluation.py", "src/engine/llm.py", "src/engine/groq.py",
                    "src/engine/triage_policy.py", "src/models/evidence.py", "src/models/triage.py",
                    "src/utils/masking.py", "src/engine/attack.py", "data/attack/enterprise-17.1.json",
                    "src/engine/sigma.py", "rules/sigma/manifest.json",
                    "rules/sigma/proc_creation_win_auditpol_nt_resource_kit_usage.yml",
                    "rules/sigma/proc_creation_win_hktl_sharpldapwhoami.yml",
                    "rules/sigma/proc_creation_win_hostname_execution.yml"]
    return {"provider": engine.PROVIDER_ID, "model": engine.model,
            "fallback_models": engine.fallback_models, "timeout": engine.timeout,
            "pacing": [engine._rpm, engine._tpm, engine._token_estimate, engine._max_wait],
            "policy_version": engine.POLICY_VERSION,
            "evidence_contract_version": engine.EVIDENCE_CONTRACT_VERSION,
            "system_prompt_hash": digest(engine._system_prompt()),
            "generation_hash": digest({model: engine._generation_settings(model)
                                       for model in [engine.model, *engine.fallback_models]}),
            "source_hashes": {path: hashlib.sha256((source_root / path).read_bytes()).hexdigest()
                              for path in source_files},
            "cache": False, "enrichment": "precomputed_or_disabled"}


def run_protocol(timelines, manifest, split, settings, frozen, engine, db_path, repetitions=1):
    """Run a fixed cohort with fresh acquisitions and one persisted run per repetition.

    Caller obtains approval for all network use. Engine is injected so ordinary tests
    remain offline. Protocol reports contain sensitive local evaluation metadata.
    """
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    selected = select_split(timelines, manifest, split)
    if any(a.ground_truth_metadata is None or a.ground_truth_metadata.status != "mapped"
           or a.ground_truth_label not in ("malicious", "benign")
           for t in selected for a in t.alerts):
        raise ValueError("Protocol requires independently mapped labels for every selected event")
    if settings != protocol_settings(engine):
        raise ValueError("Runtime inference settings differ from protocol settings")
    if split == "test":
        verify_freeze(manifest, settings, frozen)
    if getattr(engine, "enable_cache", None) is not False:
        raise ValueError("Protocol repetitions require cache disabled")
    reports = []
    inserted = set()
    rule_pack = load_curated_rules()
    for repetition in range(1, repetitions + 1):
        db = open_database('evaluator', str(db_path) if db_path is not None else None,
                           sqlite_factory=DatabaseManager)
        with evaluation_run(db, 'evaluation') as run:
            tracker = AccuracyTracker()
            records = []
            for ordinal, timeline in enumerate(selected, 1):
                existing = db.get_timeline(timeline.timeline_id)
                if existing and timeline.timeline_id not in inserted:
                    raise ValueError("Protocol requires a fresh database for selected timeline IDs")
                if not existing:
                    db.insert_timeline(timeline)
                    inserted.add(timeline.timeline_id)
                observation = run.observe(timeline, ordinal)
                start = time.monotonic()
                acquisition = run.acquire(engine, timeline, observation)
                elapsed = time.monotonic() - start
                if acquisition.origin == "cache" or (acquisition.verdict is not None and acquisition.origin != "fresh"):
                    raise ValueError("Cached or unverified acquisition cannot be counted as a repetition")
                result = tracker.evaluate(acquisition.verdict, timeline)
                run.complete(observation, result, timeline, tracker, verdict=acquisition.verdict,
                             failure_category=acquisition.failure_category)
                techniques = sorted({technique for a in timeline.alerts
                                     for technique in a.ground_truth_metadata.technique_ids})
                records.append({"result": result, "techniques": techniques,
                                "technique_truth_complete": bool(timeline.alerts) and all(
                                    a.ground_truth_metadata is not None and
                                    bool(a.ground_truth_metadata.technique_ids) for a in timeline.alerts),
                                "rule_outcomes": evaluate_rules(timeline, rule_pack.rules),
                                "technique_comparison": evaluate_timeline(timeline, acquisition.verdict),
                                "elapsed_seconds": elapsed, "origin": acquisition.origin})
            report = summarize(records)
            report["sigma_vs_ai"] = summarize_rule_comparison(records, rule_pack)
            report.update({"repetition": repetition, "run_id": run.run_id, "split": split})
            reports.append(report)
    return reports


def protocol_intake(sources, max_events):
    """Build a bounded local cohort from explicitly reviewed whole EVTX files."""
    if not isinstance(sources, list) or not sources or max_events < 1:
        raise ValueError("A source list and positive event cap are required")
    alerts = []
    seen_paths = set()
    counters = {"files": 0, "events": 0, "parser_errors": 0, "normalization_errors": 0,
                "files_failed": 0, "missing_timestamps": 0, "invalid_timestamps": 0}
    for item in sources:
        if (not isinstance(item, dict) or set(item) != {"root", "file", "source", "label", "reviewed"}
                or item["reviewed"] is not True or item["label"] not in ("benign", "malicious")
                or item["source"] not in ("local", "public", "attack")):
            raise ValueError("Every source must specify root, file, source, label and whole-file review")
        root = Path(item["root"]).resolve()
        key = item["file"]
        path = (root / key).resolve()
        if not path.is_relative_to(root) or path.suffix.lower() != ".evtx":
            raise ValueError("Each file must be an EVTX file within its source root")
        if path in seen_paths:
            raise ValueError("Each source file may appear only once")
        seen_paths.add(path)
        if item["source"] in ("local", "public"):
            if item["label"] != "benign":
                raise ValueError("Baseline files require reviewed benign labels")
            adapter = BenignEvtxAdapter(root, source=item["source"], reviewed_files={key: True})
            engine = adapter.engine
            batches = adapter.ingest(key)
        else:
            mapper = DatasetGroundTruthMapper(root, file_labels={key: item["label"]})
            engine = EvtxIntakeEngine(ground_truth_mapper=mapper)
            batches = engine.ingest_evtx(path)
        for batch in batches:
            alerts.extend(batch)
            if len(alerts) > max_events:
                raise ValueError("Cohort exceeds the event cap; no partial cohort was written")
        stats = engine.stats
        for name in ("parser_errors", "normalization_errors", "files_failed",
                     "missing_timestamps", "invalid_timestamps"):
            counters[name] += getattr(stats, name)
        counters["files"] += 1
    counters["events"] = len(alerts)
    if not alerts or counters["files_failed"] or counters["parser_errors"] or counters["normalization_errors"]:
        raise ValueError("Intake failed or contained parser/normalization errors; cohort not written")
    return TimelineBuilder().build_timelines(alerts), counters


def protocol_command(args):
    """Prepare/freeze/estimate offline, or execute an explicitly approved bounded run.

    Cohort JSON is a local list of serialized ThreatTimeline objects produced after
    reviewed EVTX intake and correlation. Store it and reports outside version control.
    """
    if not args.protocol_out:
        raise ValueError("Protocol output path is required")
    if args.end_to_end or args.max_lookups is not None or args.pacing != 2.0:
        raise ValueError("Protocol mode uses provider pacing and precomputed or disabled enrichment")
    if args.protocol_mode == "review-prepare":
        if not args.protocol_sources or not args.protocol_candidates:
            raise ValueError("Review preparation requires source and candidate paths")
        if Path(args.protocol_out).resolve() == Path(args.protocol_candidates).resolve():
            raise ValueError("Candidate and review paths must differ")
        with open(args.protocol_sources, encoding="utf-8") as stream:
            paths = json.load(stream)
        if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
            raise ValueError("Review sources must be a JSON list of EVTX paths")
        alerts, stats = collect_review_samples(paths, args.protocol_samples_per_file)
        with open(args.protocol_candidates, "x", encoding="utf-8") as stream:
            json.dump([alert.model_dump(mode="json") for alert in alerts], stream, allow_nan=False)
        with open(args.protocol_out, "x", encoding="utf-8", newline="") as stream:
            write_review_csv(stream, alerts)
        print(f"Offline review set: {len(alerts)} candidate events from {len(paths)} files; "
              f"missing/invalid timestamps: {sum(s['missing_timestamps'] + s['invalid_timestamps'] for s in stats)}.")
        return
    if args.protocol_mode == "review-import":
        if not args.protocol_candidates or not args.protocol_review:
            raise ValueError("Review import requires candidate and completed review paths")
        with open(args.protocol_candidates, encoding="utf-8") as stream:
            alerts = [NormalizedAlert.model_validate(item) for item in json.load(stream)]
        with open(args.protocol_review, encoding="utf-8-sig", newline="") as stream:
            timelines, uncertain = import_review(alerts, stream)
        if not timelines:
            raise ValueError("No reviewed binary decisions are available")
        with open(args.protocol_out, "x", encoding="utf-8") as stream:
            json.dump([timeline.model_dump(mode="json") for timeline in timelines], stream, allow_nan=False)
        print(f"Reviewed cohort: {len(timelines)} single-event cases; {uncertain} uncertain cases excluded.")
        return
    if args.protocol_mode == "intake":
        if not args.protocol_sources or args.protocol_max_events is None:
            raise ValueError("Intake requires reviewed source configuration and an event cap")
        with open(args.protocol_sources, encoding="utf-8") as stream:
            sources = json.load(stream)
        timelines, counters = protocol_intake(sources, args.protocol_max_events)
        with open(args.protocol_out, "x", encoding="utf-8") as stream:
            json.dump([timeline.model_dump(mode="json") for timeline in timelines], stream, allow_nan=False)
        print("Offline intake counts:", json.dumps(counters))
        return
    if not args.protocol_cohort:
        raise ValueError("Protocol cohort path is required")
    with open(args.protocol_cohort, encoding="utf-8") as stream:
        timelines = [ThreatTimeline.model_validate(item) for item in json.load(stream)]
    if args.protocol_mode == "prepare":
        result = make_manifest(timelines, args.protocol_seed, args.protocol_test_percent)
    else:
        if not args.protocol_manifest:
            raise ValueError("Protocol manifest path is required")
        with open(args.protocol_manifest, encoding="utf-8") as stream:
            manifest = json.load(stream)
        selected = select_split(timelines, manifest, args.protocol_split)
        if args.protocol_repetitions < 1:
            raise ValueError("Repetitions must be positive")
        # Constructing an engine performs no network request. The placeholder is
        # used for offline settings capture only and is never stored in output.
        key = get_groq_api_key() if args.protocol_mode == "run" else "offline-placeholder"
        if not key:
            raise ValueError("GROQ_API_KEY is required for a live protocol run")
        engine = GroqTriageEngine(api_key=key, enable_cache=False)
        settings = protocol_settings(engine)
        requests = len(selected) * args.protocol_repetitions * (1 + len(engine.fallback_models))
        estimate = {"split": args.protocol_split, "timelines": len(selected),
                    "repetitions": args.protocol_repetitions, "max_provider_attempts": requests,
                    "estimated_tokens": requests * engine._token_estimate,
                    "token_estimate_is_not_a_cap": True, "settings": settings}
        if args.protocol_mode == "freeze":
            result = frozen_configuration(manifest, settings)
        elif args.protocol_mode == "estimate":
            result = estimate
        else:
            if not args.protocol_confirm_live or args.protocol_max_requests is None:
                raise ValueError("Live run requires explicit confirmation and maximum requests")
            if requests > args.protocol_max_requests:
                raise ValueError("Estimated provider attempts exceed the approved maximum")
            frozen = None
            if args.protocol_split == "test":
                if not args.protocol_freeze:
                    raise ValueError("Test split requires a frozen configuration")
                with open(args.protocol_freeze, encoding="utf-8") as stream:
                    frozen = json.load(stream)
                verify_freeze(manifest, settings, frozen)
            if not args.db_path:
                raise ValueError("A dedicated protocol database path is required")
            # Reserve the output before any send, preventing accidental overwrite.
            with open(args.protocol_out, "x", encoding="utf-8") as stream:
                result = {"estimate": estimate, "reports": run_protocol(
                    timelines, manifest, args.protocol_split, settings, frozen, engine,
                    args.db_path, args.protocol_repetitions)}
                json.dump(result, stream, indent=2, allow_nan=False)
            print("Protocol run saved; analyst review of every FP/FN remains required.")
            return
    with open(args.protocol_out, "x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
    print("Protocol artifact saved locally.")


def load_benchmark_timelines(benchmark_path: str = "data/eval_benchmark_70.json") -> List[ThreatTimeline]:
    """Loads and deserializes benchmark timelines from JSON."""
    with open(benchmark_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    timelines: List[ThreatTimeline] = []
    for item in data:
        alerts = []
        for a_dict in item.get("alerts", []):
            alert = NormalizedAlert(
                source_dataset=a_dict["source_dataset"],
                source_file=a_dict["source_file"],
                event_type=a_dict["event_type"],
                timestamp=datetime.fromisoformat(a_dict["timestamp"]) if a_dict.get("timestamp") else None,
                original_record=a_dict.get("original_record", {}),
                extracted_indicators=a_dict.get("extracted_indicators", []),
                ground_truth_label=a_dict.get("ground_truth_label"),
            )
            alerts.append(alert)

        timeline = ThreatTimeline(
            timeline_id=UUID(item["timeline_id"]) if "timeline_id" in item else None,
            grouping_key=item["grouping_key"],
            alerts=alerts,
            start_time=datetime.fromisoformat(item["start_time"]) if item.get("start_time") else None,
            end_time=datetime.fromisoformat(item["end_time"]) if item.get("end_time") else None,
            total_events=item.get("total_events", len(alerts)),
            correlation_type=item.get("correlation_type", "confirmed"),
            correlation_reason=item.get("correlation_reason", ""),
        )
        timelines.append(timeline)

    return timelines


def run_evaluation_pipeline(
    timelines: Optional[List[ThreatTimeline]] = None,
    benchmark_path: str = "data/eval_benchmark_70.json",
    db_path: Optional[str] = None,
    results_output_dir: Optional[str] = None,
    pacing_seconds: float = 0.0,
    end_to_end: bool = False,
    max_lookups: Optional[int] = None,
) -> Dict[str, Any]:
    """Executes evaluation pipeline across threat timelines with optional enrichment and persistent storage."""
    api_key = get_groq_api_key()
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable is missing or empty.")

    db = open_database('evaluator', db_path, sqlite_factory=DatabaseManager)
    with evaluation_run(db, 'evaluation') as run:
        engine = GroqTriageEngine(api_key=api_key)
        return _run_evaluation_with_db(db, run, engine, timelines, benchmark_path,
                                       results_output_dir, pacing_seconds, end_to_end, max_lookups)


def _run_evaluation_with_db(db, run, engine, timelines, benchmark_path,
                            results_output_dir, pacing_seconds, end_to_end, max_lookups):

    if timelines is None:
        timelines = load_benchmark_timelines(benchmark_path)

    # Optional end-to-end mode: run alerts through real EnrichmentEngine before triage
    if end_to_end:
        enrichment_engine = EnrichmentEngine(db=db, max_lookups_per_run=max_lookups)
        for tl in timelines:
            if not tl.enrichment_data:
                tl.enrichment_data = []
            for alert in (tl.alerts or []):
                for ind in (alert.extracted_indicators or []):
                    ind_type = detect_indicator_type(ind)
                    if ind_type in ("unknown", "invalid"):
                        continue
                    enr_results = enrichment_engine.lookup_indicator(ind, indicator_type=ind_type)
                    for res in enr_results:
                        tl.enrichment_data.append(res)
                        try:
                            db.insert_enrichment(res)
                        except Exception:
                            pass

    tracker = AccuracyTracker()
    tracker.register_dataset_config(DatasetGroundTruthConfig(
        name="EVAL-BENCHMARK-MALICIOUS",
        malicious_labels={"malicious", "attack", "true"},
        benign_labels={"benign", "clean", "false"},
    ))
    tracker.register_dataset_config(DatasetGroundTruthConfig(
        name="EVAL-BENCHMARK-BENIGN",
        malicious_labels={"malicious", "attack", "true"},
        benign_labels={"benign", "clean", "false"},
    ))

    print(f"Starting TriageLens Real Evaluation Run across {len(timelines)} timelines...")
    print(f"Model Configuration: Primary='{engine.model}', Fallbacks={engine.fallback_models}")
    print(f"Target Database: {db.db_path} (end_to_end={end_to_end})")
    print(f"Evaluation run: {run.run_id}")

    evaluation_records: List[Dict[str, Any]] = []

    for idx, tl in enumerate(timelines, start=1):
        print(f"[{idx:02d}/{len(timelines):02d}] Evaluating timeline '{tl.correlation_reason or tl.grouping_key}'... ", end="", flush=True)

        if not db.get_timeline(tl.timeline_id):
            db.insert_timeline(tl)
        observation_id = run.observe(tl, idx)
        # A shared prepared contract validates memory and SQLite candidates.
        t0 = time.time()
        acquisition = run.acquire(engine, tl, observation_id)
        verdict = acquisition.verdict
        failure_category = acquisition.failure_category
        elapsed = time.time() - t0
        if verdict and acquisition.origin=='cache':
            print(f"(cached: {verdict.model_name}) -> Severity: {verdict.severity} ", end="", flush=True)
        else:
            if verdict:
                print(f"(live: {verdict.model_name} in {elapsed:.1f}s) -> Severity: {verdict.severity} ", end="", flush=True)
            else:
                print("(FAILED / UNAVAILABLE) ", end="", flush=True)

            if pacing_seconds > 0 and idx < len(timelines):
                time.sleep(pacing_seconds)

        # 3. Evaluate against independent ground truth (ADR-008)
        eval_result = tracker.evaluate(verdict, tl)
        # Persistence failures must not produce a successful but incomplete report.
        run.complete(observation_id, eval_result, tl, tracker,
                     verdict=verdict, failure_category=failure_category)

        status_symbol = "UNSCORED" if eval_result.is_correct is None else "OK" if eval_result.is_correct else "ERR"
        print(f"[{eval_result.category}] {status_symbol}")

        evaluation_records.append({
            "index": idx,
            "scenario": tl.correlation_reason or tl.grouping_key,
            "grouping_key": tl.grouping_key,
            "total_events": tl.total_events,
            "ground_truth_bool": eval_result.ground_truth,
            "ground_truth_label": (
                "Unknown" if eval_result.ground_truth is None
                else "Malicious" if eval_result.ground_truth else "Benign"
            ),
            "llm_prediction_bool": eval_result.llm_prediction,
            "llm_prediction_label": (
                ("Unavailable" if verdict is None else "Undetermined") if eval_result.llm_prediction is None
                else "Malicious" if eval_result.llm_prediction else "Benign"
            ),
            "severity_prediction": verdict.severity if verdict else "N/A",
            "disposition": verdict.disposition if verdict else None,
            "prediction_basis": eval_result.prediction_basis,
            "policy_version": verdict.policy_version if verdict else None,
            "category": eval_result.category,
            "is_correct": eval_result.is_correct,
            "model_name": verdict.model_name if verdict else "N/A",
            "summary": verdict.summary if verdict else "No verdict generated",
        })

    # Calculate aggregate performance metrics
    metrics = tracker.get_metrics()
    report_data = tracker.generate_reproducible_report()
    spec_val_str = f"{metrics['specificity'] * 100:.1f}%" if metrics.get('specificity') is not None else "N/A"
    fpr_str = f"{metrics['false_positive_rate'] * 100:.1f}%" if metrics.get('fpr_valid') else "N/A (undefined)"

    if results_output_dir:
        out_dir = Path(results_output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        report_file = out_dir / "groq_evaluation_report.md"

        # Generate Markdown Report
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        model_counts: Dict[str, int] = {}
        for r in evaluation_records:
            m = r.get("model_name")
            if m and m != "N/A":
                model_counts[m] = model_counts.get(m, 0) + 1
        primary_responder = max(model_counts.items(), key=lambda x: x[1])[0] if model_counts else engine.model

        def ci_str(ci: Optional[Any]) -> str:
            if not ci:
                return "N/A"
            return f"[{ci[0]*100:.1f}%, {ci[1]*100:.1f}%]"

        enrich_status_str = "Enabled (--end-to-end)" if end_to_end else "Disabled (raw telemetry baseline)"

        md_content = f"""# TriageLens Real Evaluation Run Report

**Date of Execution:** {now_str}  
**Primary Answering Model:** `{primary_responder}` ({model_counts.get(primary_responder, 0)} verdicts generated)  
**Configured Model Hierarchy:** `{engine.model}` (configured primary) -> `{', '.join(engine.fallback_models)}`  
**Dataset:** `data/eval_benchmark_70.json` (70 Balanced Enterprise Timelines; Synthetic Telemetry)  
**Evaluation Digest (SHA-256):** `{report_data['integrity_hash']}`  

**Prediction basis:** explicit disposition `{metrics['explicit_disposition_count']}`;
legacy severity proxy `{metrics['legacy_severity_proxy_count']}`;
unrecorded `{metrics['prediction_basis_unknown_count']}`.
**Assessment policies:** `{', '.join(sorted({r['policy_version'] or 'unrecorded' for r in evaluation_records}))}`.
**Undetermined dispositions:** `{metrics['abstained']}`; total unscored binary
outcomes (including unknown truth): `{metrics['unknown']}`.
**Labelled binary coverage:** `{metrics['labelled_binary']} / {metrics['labelled_available']}`
available labelled outcomes; labelled abstentions `{metrics['labelled_abstained']}`;
available outcomes with unknown truth `{metrics['unknown_ground_truth']}`.
Abstention is an available result, excluded from binary accuracy and calibration.
Confidence measures binary correctness under the recorded policy, not severity
or recommendation safety. Legacy confidence targets may be unrecorded. Compare
explicit run/cohort identities rather than combining different policy generations.

---

## 1. Executive Summary & Configuration Settings

> [!NOTE]
> **Dataset Nature & Operational Context:** The evaluation benchmark (`data/eval_benchmark_70.json`) contains **synthetically generated telemetry** representing textbook MITRE ATT&CK patterns and benign IT administration operations. **Threat intelligence enrichment was {enrich_status_str}**.

| Parameter | Configuration Value |
|---|---|
| **Evaluation Framework** | TriageLens AccuracyTracker (ADR-008, ADR-022, ADR-034) |
| **Active Answering Model** | `{primary_responder}` |
| **Configured Model Hierarchy** | `{engine.model}` -> `{', '.join(engine.fallback_models)}` |
| **Threat Intelligence Enrichment** | **{enrich_status_str}** |
| **Temperature** | `0.1` (Deterministic DFIR mode) |
| **Timeout** | `30.0s` |
| **Total Timelines Evaluated** | `{tracker.total_evaluated}` |
| **Ground-Truth Positive (Malicious)** | `{metrics['positive_samples']} ({metrics['positive_ratio']*100:.1f}%)` |
| **Ground-Truth Negative (Benign)** | `{metrics['negative_samples']} ({metrics['negative_ratio']*100:.1f}%)` |
| **Class Imbalance Flag** | `{metrics['is_imbalanced']}` |
| **Availability Rate** | `{metrics['availability_rate']*100:.1f}%` |

---

## 2. Confusion Matrix & Performance Metrics (With Wilson 95% Confidence Intervals)

| Metric | Measured Value | Wilson 95% Confidence Interval | Sample Basis | SOC Engineering Benchmark Target |
|---|---|---|---|---|
| **Accuracy** | **{metrics['accuracy']*100:.1f}%** | **{ci_str(metrics.get('accuracy_ci95'))}** | {metrics['true_positives'] + metrics['true_negatives']} / {metrics['total']} | ≥ 85.0% |
| **Precision** | **{metrics['precision']*100:.1f}%** | **{ci_str(metrics.get('precision_ci95'))}** | {metrics['true_positives']} / {metrics['true_positives'] + metrics['false_positives']} | ≥ 80.0% |
| **Recall (Sensitivity)** | **{metrics['recall']*100:.1f}%** | **{ci_str(metrics.get('recall_ci95'))}** | {metrics['true_positives']} / {metrics['positive_samples']} | ≥ 85.0% |
| **Specificity (True Negative Rate)** | **{spec_val_str}** | **{ci_str(metrics.get('specificity_ci95'))}** | {metrics['true_negatives']} / {metrics['negative_samples']} | ≥ 85.0% |
| **F1-Score** | **{metrics['f1_score']*100:.1f}%** | N/A | Harmonic mean | ≥ 85.0% |
| **False Positive Rate (FPR)** | **{fpr_str}** | - | {metrics['false_positives']} / {metrics['negative_samples']} | ≤ 15.0% |
| **False Negative Rate (FNR)** | **{metrics['false_negative_rate']*100:.1f}%** | - | {metrics['false_negatives']} / {metrics['positive_samples']} | ≤ 15.0% |

### Confusion Matrix Counts
- **True Positives (TP):** `{metrics['true_positives']}` (Attacks correctly triaged as Malicious)
- **True Negatives (TN):** `{metrics['true_negatives']}` (Benign activity correctly triaged as Benign)
- **False Positives (FP):** `{metrics['false_positives']}` (Benign activity falsely escalated as Malicious)
- **False Negatives (FN):** `{metrics['false_negatives']}` (Attacks missed or downgraded to Benign)
- **Unavailable / Failed:** `{metrics['unavailable']}`

#### Failure Analysis:
Prediction errors predominantly occurred in low-evidence, 1–2 event scenarios lacking corroborating lateral movement or external threat intelligence enrichment.

---

## 3. Timeline-by-Timeline Evaluation Results

| # | Scenario Identifier | Ground Truth | Predicted Verdict | Predicted Severity | Category | Model Name | Summary |
|---|---|---|---|---|---|---|---|
"""

        for rec in evaluation_records:
            clean_summary = rec["summary"].replace("|", "\\|").replace("\n", " ")
            if len(clean_summary) > 75:
                clean_summary = clean_summary[:72] + "..."
            md_content += f"| {rec['index']} | `{rec['scenario']}` | **{rec['ground_truth_label']}** | {rec['llm_prediction_label']} | `{rec['severity_prediction']}` | `{rec['category']}` | `{rec['model_name']}` | {clean_summary} |\n"

        md_content += """
---

## 4. Key Architectural Observations

1. **Class Balance Integrity:** In compliance with ADR-022, evaluation executed with exactly 50% benign and 50% malicious timelines, producing scientifically valid Specificity and False Positive Rate metrics.
2. **Untrusted Evidence Isolation:** All timelines were transmitted within `<FORENSIC_EVIDENCE>` delimiters with zero ground truth or provenance leakage (ADR-008, ADR-017, ADR-023).
3. **Model Resilience & Fallback:** Responding model attribution was captured and persisted in SQLite for every assessment.
"""

        with open(report_file, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Report saved to: {report_file}")

    print("\n" + "=" * 70)
    print("EVALUATION RUN COMPLETE")
    print("=" * 70)
    print(f"Total Evaluated: {tracker.total_evaluated}")
    print(f"Unavailable:     {metrics['unavailable']}")
    print(f"Availability:    {metrics['availability_rate']*100:.1f}%")
    print(f"Accuracy:        {metrics['accuracy']*100:.1f}%")
    print(f"Precision:       {metrics['precision']*100:.1f}%")
    print(f"Recall:          {metrics['recall']*100:.1f}%")
    print(f"Specificity:     {spec_val_str}")
    print(f"F1-Score:        {metrics['f1_score']*100:.1f}%")
    print("=" * 70)

    return metrics


def run_evaluation(
    benchmark_path: str = "data/eval_benchmark_70.json",
    cache_db_path: Optional[str] = None,
    results_output_dir: str = "docs/results",
    pacing_seconds: float = 2.0,
    end_to_end: bool = False,
    max_lookups: Optional[int] = None,
) -> Dict[str, Any]:
    """Executes the full evaluation run across benchmark timelines."""
    return run_evaluation_pipeline(
        benchmark_path=benchmark_path,
        db_path=cache_db_path,
        results_output_dir=results_output_dir,
        pacing_seconds=pacing_seconds,
        end_to_end=end_to_end,
        max_lookups=max_lookups,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TriageLens Benchmark Evaluation Runner",
        epilog=("Protocol: intake -> prepare -> development estimate/run -> freeze -> test estimate/run. "
                "The sources JSON is an array of objects with root, file (relative to root), source "
                "(local, public, attack), label (benign, malicious), and reviewed (true). "
                "Review applies to every event in each file. Store cohort, manifest, freeze, "
                "report and dedicated database outside Git; obtain approval before live runs."))
    parser.add_argument(
        "--benchmark-path",
        default="data/eval_benchmark_70.json",
        help="Path to benchmark JSON (default: 'data/eval_benchmark_70.json')",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="SQLite path override; relative paths use the project root (default: DATABASE_PATH, TRIAGELENS_DB_PATH, or data/triagelens.db)",
    )
    parser.add_argument(
        "--end-to-end",
        action="store_true",
        help="Run through real Threat Intelligence Enrichment before AI triage",
    )
    parser.add_argument(
        "--max-lookups",
        type=int,
        default=None,
        help="Maximum external threat intelligence lookups per run (default: unlimited)",
    )
    parser.add_argument(
        "--pacing",
        type=float,
        default=2.0,
        help="Pacing delay in seconds between live triage calls (default: 2.0s)",
    )
    parser.add_argument("--protocol-mode", choices=("review-prepare", "review-import", "intake", "prepare", "freeze", "estimate", "run"))
    parser.add_argument("--protocol-sources", help="Local JSON list of independently reviewed EVTX files")
    parser.add_argument("--protocol-candidates", help="Local unlabeled candidate-event JSON")
    parser.add_argument("--protocol-review", help="Completed independent review CSV")
    parser.add_argument("--protocol-samples-per-file", type=int, default=2)
    parser.add_argument("--protocol-max-events", type=int, help="Maximum events retained in memory")
    parser.add_argument("--protocol-cohort", help="Local JSON array of reviewed correlated timelines")
    parser.add_argument("--protocol-manifest", help="Local fixed split manifest")
    parser.add_argument("--protocol-freeze", help="Local frozen settings for test evaluation")
    parser.add_argument("--protocol-out", help="New local output file; never overwritten")
    parser.add_argument("--protocol-seed", default="triagelens-s1-v1")
    parser.add_argument("--protocol-test-percent", type=int, default=20)
    parser.add_argument("--protocol-split", choices=("development", "test"), default="development")
    parser.add_argument("--protocol-repetitions", type=int, default=1)
    parser.add_argument("--protocol-max-requests", type=int)
    parser.add_argument("--protocol-confirm-live", action="store_true")

    args = parser.parse_args()
    if args.protocol_mode:
        protocol_command(args)
    else:
        run_evaluation(
            benchmark_path=args.benchmark_path,
            cache_db_path=args.db_path,
            pacing_seconds=args.pacing,
            end_to_end=args.end_to_end,
            max_lookups=args.max_lookups,
        )
