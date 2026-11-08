"""2-Model Evaluation Comparison Script for TriageLens.

Compares two Groq-hosted models on a representative 20-timeline split
(10 Malicious, 10 Benign) from data/eval_benchmark_70.json.

Evaluates:
- Classification performance: Accuracy, Precision, Recall, Specificity, F1, FPR, FNR
- Confidence calibration: Brier score, Expected Calibration Error (ECE), calibration bins
- Latency and availability
- Uncertainty and missing information telemetry

Outputs report to docs/results/groq_model_comparison_report.md.
"""

from datetime import datetime, timezone
from contextlib import closing
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

from src.config import get_groq_api_key
from src.engine.database import DatabaseManager
from src.engine.evaluation import AccuracyTracker, DatasetGroundTruthConfig
from src.engine.groq import GroqTriageEngine
from src.engine.provenance import acquire_triage
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


def load_balanced_subset(
    benchmark_path: str = "data/eval_benchmark_70.json",
    num_malicious: int = 10,
    num_benign: int = 10,
) -> List[ThreatTimeline]:
    """Loads a balanced subset of timelines from the benchmark dataset."""
    with open(benchmark_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    malicious_items = []
    benign_items = []

    for item in data:
        is_mal = any(a.get("ground_truth_label") == "malicious" for a in item.get("alerts", []))
        if is_mal and len(malicious_items) < num_malicious:
            malicious_items.append(item)
        elif not is_mal and len(benign_items) < num_benign:
            benign_items.append(item)

        if len(malicious_items) >= num_malicious and len(benign_items) >= num_benign:
            break

    selected_items = malicious_items + benign_items
    timelines: List[ThreatTimeline] = []

    for item in selected_items:
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


def evaluate_model(
    model_name: str,
    timelines: List[ThreatTimeline],
    api_key: str,
    cache_db_path: str = "data/eval_compare_cache.db",
    pacing_seconds: float = 1.5,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], float]:
    """Runs evaluation for a specific model against the provided timelines."""
    print(f"\n========================================================")
    print(f"Evaluating Model: {model_name} on {len(timelines)} timelines")
    print(f"========================================================")

    engine = GroqTriageEngine(api_key=api_key, model=model_name, fallback_models=[])
    db = DatabaseManager(db_path=cache_db_path)
    with closing(db):
        db.init_db()
        return _evaluate_model_with_db(model_name,timelines,pacing_seconds,engine,db)


def _evaluate_model_with_db(model_name,timelines,pacing_seconds,engine,db):

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

    records: List[Dict[str, Any]] = []
    latencies: List[float] = []

    for idx, tl in enumerate(timelines, start=1):
        print(f"[{idx:02d}/{len(timelines):02d}] {(tl.correlation_reason or '')[:45]:<45} ... ", end="", flush=True)

        if not db.get_timeline(tl.timeline_id):
            db.insert_timeline(tl)
        t0 = time.time()
        acquisition = acquire_triage(engine,tl,lambda origin:None,persistent_cache=db)
        acquisition_elapsed = time.time()-t0
        verdict = acquisition.verdict
        elapsed = 0.0
        if verdict:
            db.persist_cached_verdict(verdict,acquisition.cache_provenance)
        if verdict and acquisition.origin=='cache':
            print(f"(cached) -> {verdict.severity} ", end="", flush=True)
        else:
            elapsed = acquisition_elapsed
            latencies.append(elapsed)

            if verdict:
                print(f"({elapsed:.1f}s) -> {verdict.severity} ", end="", flush=True)
            else:
                print("(FAILED) ", end="", flush=True)

            if pacing_seconds > 0 and idx < len(timelines):
                time.sleep(pacing_seconds)

        eval_result = tracker.evaluate(verdict, tl)
        status_tag = "PASS" if eval_result.is_correct else "FAIL"
        print(f"[{eval_result.category}] {status_tag}")

        records.append({
            "index": idx,
            "scenario": tl.correlation_reason or tl.grouping_key,
            "ground_truth": "Malicious" if eval_result.ground_truth else "Benign",
            "prediction": "Malicious" if eval_result.llm_prediction else "Benign",
            "severity": verdict.severity if verdict else "N/A",
            "confidence": verdict.confidence_score if verdict else 0.0,
            "uncertainty": verdict.uncertainty_level if verdict else "N/A",
            "is_correct": eval_result.is_correct,
            "category": eval_result.category,
        })

    metrics = tracker.get_metrics()
    avg_latency = (sum(latencies) / len(latencies)) if latencies else None
    return metrics, records, avg_latency


def generate_comparison_report(
    model_a_name: str,
    metrics_a: Dict[str, Any],
    records_a: List[Dict[str, Any]],
    latency_a: Optional[float],
    model_b_name: str,
    metrics_b: Dict[str, Any],
    records_b: List[Dict[str, Any]],
    latency_b: Optional[float],
    output_path: str = "docs/results/groq_model_comparison_report.md",
) -> None:
    """Generates the Markdown comparison report."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Format helpers
    def pct(val: Optional[float]) -> str:
        return f"{val * 100:.1f}%" if val is not None else "N/A"

    def ci_str(ci: Optional[Tuple[float, float]]) -> str:
        if not ci:
            return "N/A"
        return f"[{ci[0]*100:.1f}%, {ci[1]*100:.1f}%]"

    def flt(val: Optional[float]) -> str:
        return f"{val:.4f}" if val is not None else "N/A"

    latency_a_str = f"{latency_a:.2f}s" if latency_a is not None else "N/A (cached)"
    latency_b_str = f"{latency_b:.2f}s" if latency_b is not None else "N/A (cached)"
    latency_delta_str = (
        f"{(latency_a - latency_b):+.2f}s"
        if latency_a is not None and latency_b is not None
        else "-"
    )

    # Calibration table rows
    bins_a = metrics_a.get("calibration_bins", [])
    bins_b = metrics_b.get("calibration_bins", [])

    cal_rows = []
    for i in range(max(len(bins_a), len(bins_b))):
        ba = bins_a[i] if i < len(bins_a) else {}
        bb = bins_b[i] if i < len(bins_b) else {}
        bin_label = ba.get("bin", bb.get("bin", f"Bin {i+1}"))
        cal_rows.append(
            f"| `{bin_label}` | {ba.get('count', 0)} | {pct(ba.get('mean_confidence'))} | {pct(ba.get('accuracy'))} | {bb.get('count', 0)} | {pct(bb.get('mean_confidence'))} | {pct(bb.get('accuracy'))} |"
        )
    cal_table_md = "\n".join(cal_rows)

    # Disagreement table
    disagreements = []
    for ra, rb in zip(records_a, records_b):
        if ra["prediction"] != rb["prediction"] or ra["is_correct"] != rb["is_correct"]:
            disagreements.append(
                f"| {ra['index']} | {ra['scenario'][:35]} | {ra['ground_truth']} | {ra['prediction']} ({ra['severity']}) | {rb['prediction']} ({rb['severity']}) | {'Match' if ra['prediction'] == rb['prediction'] else '**Differ**'} |"
            )
    disagreement_md = "\n".join(disagreements) if disagreements else "| - | No prediction disagreements observed | - | - | - | - |"

    md = f"""# TriageLens 2-Model Evaluation & Calibration Comparison Report

**Date of Execution:** {now_str}  
**Dataset:** `data/eval_benchmark_70.json` (Balanced Representative Split: 10 Malicious, 10 Benign; Synthetic Telemetry)  
**Evaluated Architectures:**  
- **Model A:** `{model_a_name}` (Fast / High-throughput tier)
- **Model B:** `{model_b_name}` (Ultra-efficient lite tier)

> [!WARNING]
> **Small-Sample Caveat ($n=20$):** This comparison uses a small sample size of 20 timelines evaluated on textbook synthetic scenarios with threat intelligence enrichment disabled. On $n=20$, a 100% accuracy score corresponds to a wide Wilson 95% confidence interval of [83.9%, 100.0%], and calibration metrics (Brier score, ECE) are sensitive to individual predictions and should be interpreted as qualitative noise rather than statistically conclusive evidence.

---

## 1. Executive Performance Comparison

| Metric | Model A: `{model_a_name}` | Model B: `{model_b_name}` | Delta (A - B) | Wilson 95% CI (A) | Wilson 95% CI (B) | Target |
|---|---|---|---|---|---|---|
| **Accuracy** | **{pct(metrics_a.get('accuracy'))}** | **{pct(metrics_b.get('accuracy'))}** | {((metrics_a.get('accuracy',0) - metrics_b.get('accuracy',0))*100):+.1f}% | {ci_str(metrics_a.get('accuracy_ci95'))} | {ci_str(metrics_b.get('accuracy_ci95'))} | ≥ 85.0% |
| **Precision** | **{pct(metrics_a.get('precision'))}** | **{pct(metrics_b.get('precision'))}** | {((metrics_a.get('precision',0) - metrics_b.get('precision',0))*100):+.1f}% | {ci_str(metrics_a.get('precision_ci95'))} | {ci_str(metrics_b.get('precision_ci95'))} | ≥ 80.0% |
| **Recall (Sensitivity)** | **{pct(metrics_a.get('recall'))}** | **{pct(metrics_b.get('recall'))}** | {((metrics_a.get('recall',0) - metrics_b.get('recall',0))*100):+.1f}% | {ci_str(metrics_a.get('recall_ci95'))} | {ci_str(metrics_b.get('recall_ci95'))} | ≥ 85.0% |
| **Specificity (TNR)** | **{pct(metrics_a.get('specificity'))}** | **{pct(metrics_b.get('specificity'))}** | {((metrics_a.get('specificity',0) - metrics_b.get('specificity',0))*100):+.1f}% | {ci_str(metrics_a.get('specificity_ci95'))} | {ci_str(metrics_b.get('specificity_ci95'))} | ≥ 85.0% |
| **F1-Score** | **{pct(metrics_a.get('f1_score'))}** | **{pct(metrics_b.get('f1_score'))}** | {((metrics_a.get('f1_score',0) - metrics_b.get('f1_score',0))*100):+.1f}% | N/A | N/A | ≥ 85.0% |
| **False Positive Rate (FPR)** | **{pct(metrics_a.get('false_positive_rate'))}** | **{pct(metrics_b.get('false_positive_rate'))}** | {((metrics_a.get('false_positive_rate',0) - metrics_b.get('false_positive_rate',0))*100):+.1f}% | - | - | ≤ 15.0% |
| **False Negative Rate (FNR)** | **{pct(metrics_a.get('false_negative_rate'))}** | **{pct(metrics_b.get('false_negative_rate'))}** | {((metrics_a.get('false_negative_rate',0) - metrics_b.get('false_negative_rate',0))*100):+.1f}% | - | - | ≤ 15.0% |
| **Average Latency / Timeline** | `{latency_a_str}` | `{latency_b_str}` | `{latency_delta_str}` | - | - | < 5.0s |
| **Availability Rate** | `{pct(metrics_a.get('availability_rate'))}` | `{pct(metrics_b.get('availability_rate'))}` | - | - | - | 100% |

### Confusion Matrix Counts

| Count | `{model_a_name}` | `{model_b_name}` | Description |
|---|---|---|---|
| **True Positives (TP)** | `{metrics_a.get('true_positives', 0)}` | `{metrics_b.get('true_positives', 0)}` | Attacks correctly triaged as Malicious |
| **True Negatives (TN)** | `{metrics_a.get('true_negatives', 0)}` | `{metrics_b.get('true_negatives', 0)}` | Benign events correctly triaged as Benign |
| **False Positives (FP)** | `{metrics_a.get('false_positives', 0)}` | `{metrics_b.get('false_positives', 0)}` | Benign noise escalated as Malicious |
| **False Negatives (FN)** | `{metrics_a.get('false_negatives', 0)}` | `{metrics_b.get('false_negatives', 0)}` | Real attacks missed or downgraded |

---

## 2. Confidence Calibration & Error Analysis

A reliable SOC triage AI must not only predict the correct verdict, but its reported confidence score must reflect actual empirical probability.

| Calibration Metric | Model A: `{model_a_name}` | Model B: `{model_b_name}` | Interpretation |
|---|---|---|---|
| **Brier Score** | **{flt(metrics_a.get('brier_score'))}** | **{flt(metrics_b.get('brier_score'))}** | Lower is better (0.0 = perfect probabilistic accuracy) |
| **Expected Calibration Error (ECE)** | **{flt(metrics_a.get('expected_calibration_error'))}** | **{flt(metrics_b.get('expected_calibration_error'))}** | Lower is better (weighted gap between confidence & accuracy) |

### Reliability Bins Comparison (5-Bin Calibration Curve)

| Bin Range | Samples (A) | Conf (A) | Acc (A) | Samples (B) | Conf (B) | Acc (B) |
|---|---|---|---|---|---|---|
{cal_table_md}

---

## 3. Disagreement & Edge Case Analysis

| Index | Scenario | Ground Truth | `{model_a_name}` | `{model_b_name}` | Verdict Status |
|---|---|---|---|---|---|
{disagreement_md}

---

## 4. Key Takeaways & Deployment Recommendations

1. **Analytical Accuracy vs Efficiency:** Assess measured results alongside availability, sample size, and latency; model quality is not assumed.
2. **Confidence Calibration:** Brier score and ECE describe this sample's calibration. Human analysts retain response authority.
3. **Availability:** Each model is evaluated without fallback. Free-tier limits can interrupt either model; continuity is not guaranteed.
"""

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(md, encoding="utf-8")
    print(f"\nReport successfully generated at: {output_path}")


def main() -> None:
    api_key = get_groq_api_key()
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable is missing or empty.")

    timelines = load_balanced_subset("data/eval_benchmark_70.json", num_malicious=10, num_benign=10)
    print(f"Loaded {len(timelines)} balanced test timelines (10 Malicious, 10 Benign).")

    model_a = "openai/gpt-oss-120b"
    model_b = "openai/gpt-oss-20b"

    metrics_a, records_a, latency_a = evaluate_model(
        model_name=model_a,
        timelines=timelines,
        api_key=api_key,
        cache_db_path="data/eval_cache.db",  # Can reuse existing cached verdicts
        pacing_seconds=1.5,
    )

    metrics_b, records_b, latency_b = evaluate_model(
        model_name=model_b,
        timelines=timelines,
        api_key=api_key,
        cache_db_path="data/eval_compare_cache.db",
        pacing_seconds=1.5,
    )

    generate_comparison_report(
        model_a_name=model_a,
        metrics_a=metrics_a,
        records_a=records_a,
        latency_a=latency_a,
        model_b_name=model_b,
        metrics_b=metrics_b,
        records_b=records_b,
        latency_b=latency_b,
        output_path="docs/results/groq_model_comparison_report.md",
    )


if __name__ == "__main__":
    main()
