# TriageLens 2-Model Evaluation & Calibration Comparison Report

**Date of Execution:** 2026-11-06 01:03:04 UTC  
**Dataset:** `data/eval_benchmark_70.json` (Balanced Representative Split: 10 Malicious, 10 Benign; Synthetic Telemetry)  
**Evaluated Architectures:**  
- **Model A:** `gemini-3.5-flash-lite` (Fast / High-throughput tier)
- **Model B:** `gemini-3.1-flash-lite` (Ultra-efficient lite tier)

> [!WARNING]
> **Sample Size & Statistical Noise Limitation ($n=20$):** This comparison uses a small sample size of 20 timelines evaluated on textbook synthetic scenarios with threat intelligence enrichment disabled. On $n=20$, a 100% accuracy score corresponds to a wide Wilson 95% confidence interval of **[83.9%, 100.0%]**, and calibration metrics (Brier score, ECE) are sensitive to individual predictions and should be interpreted as qualitative noise rather than statistically conclusive evidence.

---

## 1. Executive Performance Comparison

| Metric | Model A: `gemini-3.5-flash-lite` | Model B: `gemini-3.1-flash-lite` | Delta (A - B) | Wilson 95% CI (A) | Wilson 95% CI (B) | Target |
|---|---|---|---|---|---|---|
| **Accuracy** | **95.0%** (19/20) | **100.0%** (20/20) | -5.0% | [76.4%, 99.1%] | [83.9%, 100.0%] | ≥ 85.0% |
| **Precision** | **90.9%** (10/11) | **100.0%** (10/10) | -9.1% | [62.3%, 98.4%] | [72.2%, 100.0%] | ≥ 80.0% |
| **Recall (Sensitivity)** | **100.0%** (10/10) | **100.0%** (10/10) | +0.0% | [72.2%, 100.0%] | [72.2%, 100.0%] | ≥ 85.0% |
| **Specificity (TNR)** | **90.0%** (9/10) | **100.0%** (10/10) | -10.0% | [59.6%, 98.2%] | [72.2%, 100.0%] | ≥ 85.0% |
| **F1-Score** | **95.2%** | **100.0%** | -4.8% | N/A | N/A | ≥ 85.0% |
| **False Positive Rate (FPR)** | **10.0%** (1/10) | **0.0%** (0/10) | +10.0% | [1.8%, 40.4%] | [0.0%, 27.8%] | ≤ 15.0% |
| **False Negative Rate (FNR)** | **0.0%** (0/10) | **0.0%** (0/10) | +0.0% | [0.0%, 27.8%] | [0.0%, 27.8%] | ≤ 15.0% |
| **Average Latency / Timeline** | `N/A (cached)` | `N/A (cached)` | - | Unmeasured | Unmeasured | < 5.0s |
| **Availability Rate** | `100.0%` | `100.0%` | - | - | - | 100% |

*(Note: Latency was not captured during this cached evaluation run; `0.00s` entries in earlier logs reflected cache replay rather than live model inference time).*

### Confusion Matrix Counts

| Count | `gemini-3.5-flash-lite` | `gemini-3.1-flash-lite` | Description |
|---|---|---|---|
| **True Positives (TP)** | `10` | `10` | Attacks correctly triaged as Malicious |
| **True Negatives (TN)** | `9` | `10` | Benign events correctly triaged as Benign |
| **False Positives (FP)** | `1` | `0` | Benign noise escalated as Malicious |
| **False Negatives (FN)** | `0` | `0` | Real attacks missed or downgraded |

---

## 2. Confidence Calibration & Error Analysis

A reliable SOC triage AI must not only predict the correct verdict, but its reported confidence score must reflect actual empirical probability. On small subsets ($n=20$), calibration scores should be viewed as preliminary indicators.

| Calibration Metric | Model A: `gemini-3.5-flash-lite` | Model B: `gemini-3.1-flash-lite` | Statistical Note ($n=20$) |
|---|---|---|---|
| **Brier Score** | **0.0390** | **0.0071** | Subject to high small-sample variance |
| **Expected Calibration Error (ECE)** | **0.0020** | **0.0585** | 19 of 20 samples fall in single highest bin (`0.8 - 1.0`) |

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
| 20 | `benign_scenario_B10-ITAdmin-DomainJoinVerify` | Benign | Malicious (MEDIUM) | Benign (LOW) | **Differ** |

*Edge Case Finding:* `gemini-3.5-flash-lite` flagged the single-command administrative query `nltest.exe` as potential domain reconnaissance, while `gemini-3.1-flash-lite` classified it as benign administrative activity. In both cases, the absence of threat intelligence enrichment left the model to judge single-command intent without external context.

---

## 4. Key Takeaways & Deployment Recommendations

1. **Synthetic Telemetry Scope:** Both models were evaluated on textbook synthetic telemetry. Performance on ambiguous real-world enterprise noise with live threat intelligence enrichment will diverge from synthetic benchmarks.
2. **Small-Sample Limitations ($n=20$):** High accuracy rates (95% - 100%) on $n=20$ have wide confidence intervals ([76% - 99%] and [84% - 100%]). Larger evaluation runs across diverse datasets are required before drawing firm production conclusions.
3. **Architectural Redundancy:** TriageLens's fallback engine guarantees uninterrupted SOC operations even under provider throttling or temporary quota exhaustion.
