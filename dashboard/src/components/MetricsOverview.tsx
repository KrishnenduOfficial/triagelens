import React, { useEffect, useState } from "react";
import { fetchMetrics, type Metrics } from "../api/apiService";

export const MetricsOverview: React.FC = () => {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchMetrics();
      setMetrics(data);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect to accuracy evaluation backend."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const formatPercent = (val: number | undefined | null): string => {
    if (val === undefined || val === null || isNaN(val)) return "0.0%";
    return `${(val * 100).toFixed(1)}%`;
  };

  return (
    <section className="dashboard-card metrics-section" aria-label="AI Performance Metrics">
      <div className="card-header">
        <div>
          <div className="badge-row">
            <span className="badge badge-accent">Ground-Truth Engine</span>
            <span className="badge badge-neutral">Stage 5 Validation</span>
          </div>
          <h2 className="card-title">AI Triage Reliability & Ground Truth</h2>
          <p className="card-subtitle">
            Measuring how often LLM triage decisions agree with deterministic ground truth labels.
          </p>
        </div>
        <button
          className="btn btn-secondary"
          onClick={loadData}
          disabled={loading}
          aria-label="Refresh accuracy metrics"
        >
          {loading ? "Evaluating..." : "Refresh Metrics"}
        </button>
      </div>

      {loading && !metrics && (
        <div className="state-container loading-state">
          <div className="spinner" />
          <p>Evaluating AI verdicts against ground truth reference labels...</p>
        </div>
      )}

      {error && (
        <div className="state-container error-state">
          <div className="error-icon">⚠️</div>
          <div>
            <h4>Unable to Load Metrics</h4>
            <p className="error-text">{error}</p>
            <button className="btn btn-primary" onClick={loadData}>
              Retry Connection
            </button>
          </div>
        </div>
      )}

      {metrics && (
        <div className="metrics-content">
          {/* Top Level Statistical Rates */}
          <div className="rates-grid">
            <div className="stat-box">
              <span className="stat-label">Model Accuracy</span>
              <span className="stat-value text-accent">
                {formatPercent(metrics.accuracy)}
              </span>
              <span className="stat-hint">
                {metrics.tp + metrics.tn} / {metrics.total || 0} Correct
              </span>
            </div>

            <div className="stat-box">
              <span className="stat-label">Precision</span>
              <span className="stat-value text-success">
                {formatPercent(metrics.precision)}
              </span>
              <span className="stat-hint">
                TP / (TP + FP)
              </span>
            </div>

            <div className="stat-box">
              <span className="stat-label">Recall (Sensitivity)</span>
              <span className="stat-value text-warning">
                {formatPercent(metrics.recall)}
              </span>
              <span className="stat-hint">
                TP / (TP + FN)
              </span>
            </div>

            <div className="stat-box">
              <span className="stat-label">F1-Score</span>
              <span className="stat-value text-info">
                {formatPercent(metrics.f1_score)}
              </span>
              <span className="stat-hint">
                Harmonic Mean
              </span>
            </div>
          </div>

          {/* Confusion Matrix & Error Rates */}
          <div className="matrix-and-rates-row">
            <div className="matrix-card">
              <h3 className="section-label">Confusion Matrix</h3>
              <div className="matrix-grid">
                <div className="matrix-cell cell-tp">
                  <span className="cell-title">True Positive (TP)</span>
                  <span className="cell-count">{metrics.tp ?? metrics.true_positives ?? 0}</span>
                  <span className="cell-desc">Malicious confirmed</span>
                </div>
                <div className="matrix-cell cell-fp">
                  <span className="cell-title">False Positive (FP)</span>
                  <span className="cell-count">{metrics.fp ?? metrics.false_positives ?? 0}</span>
                  <span className="cell-desc">False alarm on benign</span>
                </div>
                <div className="matrix-cell cell-fn">
                  <span className="cell-title">False Negative (FN)</span>
                  <span className="cell-count">{metrics.fn ?? metrics.false_negatives ?? 0}</span>
                  <span className="cell-desc">Threat missed by AI</span>
                </div>
                <div className="matrix-cell cell-tn">
                  <span className="cell-title">True Negative (TN)</span>
                  <span className="cell-count">{metrics.tn ?? metrics.true_negatives ?? 0}</span>
                  <span className="cell-desc">Benign dismissed</span>
                </div>
              </div>
            </div>

            <div className="rates-card">
              <h3 className="section-label">Error & Coverage Breakdown</h3>
              <div className="rate-item">
                <div className="rate-info">
                  <span>False Positive Rate (FPR)</span>
                  <span className="mono">{formatPercent(metrics.false_positive_rate)}</span>
                </div>
                <div className="progress-bar-bg">
                  <div
                    className="progress-bar-fill fill-warning"
                    style={{ width: `${Math.min(100, (metrics.false_positive_rate || 0) * 100)}%` }}
                  />
                </div>
              </div>

              <div className="rate-item">
                <div className="rate-info">
                  <span>False Negative Rate (FNR)</span>
                  <span className="mono">{formatPercent(metrics.false_negative_rate)}</span>
                </div>
                <div className="progress-bar-bg">
                  <div
                    className="progress-bar-fill fill-danger"
                    style={{ width: `${Math.min(100, (metrics.false_negative_rate || 0) * 100)}%` }}
                  />
                </div>
              </div>

              <div className="rate-summary-counts">
                <div className="summary-pill">
                  <span>Total Evaluated:</span>
                  <strong className="mono">{metrics.total ?? 0}</strong>
                </div>
                <div className="summary-pill">
                  <span>Unlabeled / Skipped:</span>
                  <strong className="mono">{metrics.unknown ?? 0}</strong>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

