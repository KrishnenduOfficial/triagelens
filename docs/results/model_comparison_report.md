# TriageLens 2-Model Evaluation & Calibration Comparison Report

**Date of Execution:** 2026-11-06 01:03:04 UTC  
**Dataset:** `data/eval_benchmark_70.json` (Balanced Representative Split: 10 Malicious, 10 Benign)  
**Evaluated Architectures:**  
- **Model A:** `gemini-3.5-flash-lite` (Fast / High-throughput tier)
- **Model B:** `gemini-3.1-flash-lite` (Ultra-efficient lite tier)

---

## 1. Executive Performance Comparison

| Metric | Model A: `gemini-3.5-flash-lite` | Model B: `gemini-3.1-flash-lite` | Delta (A - B) | SOC Engineering Target |
|---|---|---|---|---|
| **Accuracy** | **95.0%** | **100.0%** | -5.0% | ≥ 85.0% |
| **Precision** | **90.9%** | **100.0%** | -9.1% | ≥ 80.0% |
| **Recall (Sensitivity)** | **100.0%** | **100.0%** | +0.0% | ≥ 85.0% |
| **Specificity (TNR)** | **90.0%** | **100.0%** | -10.0% | ≥ 85.0% |
| **F1-Score** | **95.2%** | **100.0%** | -4.8% | ≥ 85.0% |
| **False Positive Rate (FPR)** | **10.0%** | **0.0%** | +10.0% | ≤ 15.0% |
| **False Negative Rate (FNR)** | **0.0%** | **0.0%** | +0.0% | ≤ 15.0% |
| **Average Latency / Timeline** | `0.00s` | `0.00s` | `+0.00s` | < 5.0s |
| **Availability Rate** | `100.0%` | `100.0%` | - | 100% |

### Confusion Matrix Counts

| Count | `gemini-3.5-flash-lite` | `gemini-3.1-flash-lite` | Description |
|---|---|---|---|
| **True Positives (TP)** | `10` | `10` | Attacks correctly triaged as Malicious |
| **True Negatives (TN)** | `9` | `10` | Benign events correctly triaged as Benign |
| **False Positives (FP)** | `1` | `0` | Benign noise escalated as Malicious |
| **False Negatives (FN)** | `0` | `0` | Real attacks missed or downgraded |

---

## 2. Confidence Calibration & Error Analysis

A reliable SOC triage AI must not only predict the correct verdict, but its reported confidence score must reflect actual empirical probability.

| Calibration Metric | Model A: `gemini-3.5-flash-lite` | Model B: `gemini-3.1-flash-lite` | Interpretation |
|---|---|---|---|
| **Brier Score** | **0.0390** | **0.0071** | Lower is better (0.0 = perfect probabilistic accuracy) |
| **Expected Calibration Error (ECE)** | **0.0020** | **0.0585** | Lower is better (weighted gap between confidence & accuracy) |

### Reliability Bins Comparison (5-Bin Calibration Curve)

| Bin Range | Samples (A) | Conf (A) | Acc (A) | Samples (B) | Conf (B) | Acc (B) |
|---|---|---|---|---|---|---|
| `0.0 - 0.2` | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.0% |
| `0.2 - 0.4` | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.0% |
| `0.4 - 0.6` | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.0% |
| `0.6 - 0.8` | 0 | 0.0% | 0.0% | 1 | 75.0% | 100.0% |
| `0.8 - 1.0` | 20 | 95.2% | 95.0% | 19 | 95.2% | 100.0% |

---

## 3. Disagreement & Edge Case Analysis

| Index | Scenario | Ground Truth | `gemini-3.5-flash-lite` | `gemini-3.1-flash-lite` | Verdict Status |
|---|---|---|---|---|---|
| 20 | benign_scenario_B10-ITAdmin-DomainJ | Benign | Malicious (MEDIUM) | Benign (LOW) | **Differ** |

---

## 4. Key Takeaways & Deployment Recommendations

1. **Analytical Accuracy vs Efficiency:** Both models demonstrate strong classification performance across the balanced dataset.
2. **Confidence Calibration:** Comparing Brier score and ECE reveals how well calibrated the models are. Well-calibrated confidence scores allow SOC orchestrators to route high-confidence predictions to automated containment and low-confidence predictions to human Tier-2 analysts.
3. **Architectural Redundancy:** TriageLens's fallback engine guarantees uninterrupted SOC operations even under provider throttling or temporary quota exhaustion.
