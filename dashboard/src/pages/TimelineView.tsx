import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { VerdictQualifications } from "../components/VerdictQualifications";
import {
  fetchTimelineDetail,
  saveAnalystReview,
  type AnalystReview,
  type SeverityLevel,
  type TimelineDetail,
} from "../api/apiService";

export const AnalystReviewSummary: React.FC<{ review: AnalystReview }> = ({ review }) => (
  <div>
    <p>Decision: {review.decision}</p>
    {review.override_disposition && <p>Analyst disposition: {review.override_disposition}</p>}
    <p>Rationale: {review.rationale || 'None provided'}</p>
    <p>Recorded: {review.created_at}</p>
  </div>
);

export const HumanReviewNotice: React.FC = () => (
  <div className="analyst-advisory-banner" role="note">
    <span className="advisory-icon">🛡️</span>
    <div className="advisory-text"><strong>AI output needs human review.</strong> AI-generated assessments are advisory. The AI is never the final authority on incident maliciousness.</div>
  </div>
);

export const TimelineView: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [timeline, setTimeline] = useState<TimelineDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedAlerts, setExpandedAlerts] = useState<Record<string, boolean>>({});
  const [decision, setDecision] = useState<'confirm' | 'override'>('confirm');
  const [override, setOverride] = useState<NonNullable<AnalystReview['override_disposition']>>('MALICIOUS');
  const [rationale, setRationale] = useState('');
  const [reviewError, setReviewError] = useState('');
  const [saving, setSaving] = useState(false);

  const submitReview = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!id || !timeline?.verdict) return;
    setSaving(true);
    setReviewError('');
    try {
      const review = await saveAnalystReview(id, { verdict_id: timeline.verdict.id, decision,
        override_disposition: decision === 'override' ? override : null, rationale: rationale.trim() });
      setTimeline({ ...timeline, analyst_review: review });
    } catch (err) {
      setReviewError(err instanceof Error ? err.message : 'Review could not be saved.');
    } finally {
      setSaving(false);
    }
  };

  useEffect(() => {
    if (!id) return;
    let active = true;
    const loadDetail = async () => {
      setLoading(true);
      setError(null);
      setTimeline(null);
      try {
        const data = await fetchTimelineDetail(id);
        if (active) setTimeline(data);
      } catch (err) {
        if (active) setError(
          err instanceof Error
            ? err.message
            : `Failed to load details for timeline ID ${id}.`
        );
      } finally {
        if (active) setLoading(false);
      }
    };

    loadDetail();
    return () => { active = false; };
  }, [id]);

  const toggleAlertExpand = (alertId: string) => {
    setExpandedAlerts((prev) => ({
      ...prev,
      [alertId]: !prev[alertId],
    }));
  };

  const formatDate = (isoString: string | null | undefined): string => {
    if (!isoString) return "N/A";
    try {
      const d = new Date(isoString);
      return isNaN(d.getTime()) ? isoString : d.toLocaleString();
    } catch {
      return isoString;
    }
  };

  const getSeverityBadgeClass = (severity: SeverityLevel | string | undefined): string => {
    const sev = (severity || "").toUpperCase();
    switch (sev) {
      case "CRITICAL":
        return "badge-severity-critical";
      case "HIGH":
        return "badge-severity-high";
      case "MEDIUM":
        return "badge-severity-medium";
      case "LOW":
        return "badge-severity-low";
      case "INFORMATIONAL":
        return "badge-severity-info";
      default:
        return "badge-neutral";
    }
  };

  return (
    <div className="timeline-view-container">
      {/* Top Navigation Bar */}
      <div className="timeline-nav-header">
        <Link to="/" className="btn btn-secondary btn-sm" aria-label="Back to dashboard">
          ← Back to Console
        </Link>
        <span className="mono text-muted text-sm">
          Timeline UUID: {id || "Unknown"}
        </span>
      </div>

      {loading && (
        <div className="dashboard-card state-container loading-state">
          <div className="spinner" />
          <p>Retrieving timeline telemetry, security alerts, and AI triage verdict...</p>
        </div>
      )}

      {error && (
        <div className="dashboard-card state-container error-state">
          <div className="error-icon">⚠️</div>
          <div>
            <h3>Timeline Lookup Failed</h3>
            <p className="error-text">{error}</p>
            <Link to="/" className="btn btn-primary btn-sm">
              Return to Console
            </Link>
          </div>
        </div>
      )}

      {!loading && !error && timeline && timeline.id === id && (
        <div className="timeline-detail-content">
          {/* Header Card: Grouping Key & Time Bounds */}
          <div className="dashboard-card timeline-summary-card">
            <div className="summary-top-row">
              <div>
                <span className="badge badge-accent">Correlated Incident</span>
                <h1 className="timeline-title mono">{timeline.grouping_key}</h1>
              </div>
              <div className="event-count-box">
                <span className="stat-label">Correlated Events</span>
                <span className="event-number mono">
                  {timeline.total_events ?? (timeline.alerts ? timeline.alerts.length : 0)}
                </span>
              </div>
            </div>

            <div className="time-bounds-grid">
              <div className="bound-item">
                <span className="bound-label">First Event Detected:</span>
                <span className="bound-value mono">{formatDate(timeline.start_time)}</span>
              </div>
              <div className="bound-item">
                <span className="bound-label">Latest Event Detected:</span>
                <span className="bound-value mono">{formatDate(timeline.end_time)}</span>
              </div>
              <div className="bound-item">
                <span className="bound-label">Ingestion Timestamp:</span>
                <span className="bound-value mono">{formatDate(timeline.created_at)}</span>
              </div>
            </div>
          </div>

          {/* AI Triage Verdict Card */}
          <div className="dashboard-card verdict-card">
            <div className="card-header">
              <div>
                <span className="badge badge-ai">Stage 4 LLM Triage</span>
                <h2 className="card-title">AI Incident Assessment</h2>
              </div>
              {timeline.verdict && (
                <div className="verdict-badges">
                  <span
                    className={`badge badge-severity ${getSeverityBadgeClass(
                      timeline.verdict.severity
                    )}`}
                  >
                    {timeline.verdict.severity}
                  </span>
                  <span className="badge badge-confidence mono">
                    {timeline.verdict.disposition === "UNDETERMINED" ? "Abstention confidence" : timeline.verdict.policy_version ? "Disposition confidence" : "Legacy confidence (target unrecorded)"}: {(timeline.verdict.confidence_score * 100).toFixed(1)}%
                  </span>
                  <span className="badge mono">
                    Disposition: {timeline.verdict.disposition ?? "Not recorded (legacy)"}
                  </span>
                  <span className="badge mono">Policy: {timeline.verdict.policy_version ?? "Not recorded"}</span>
                </div>
              )}
            </div>

            {/* Analyst Review Advisory */}
            <HumanReviewNotice />

            {timeline.verdict ? (
              <div className="verdict-body">
                <VerdictQualifications verdict={timeline.verdict} />
                <div className="verdict-block">
                  <h4 className="block-title">Executive Threat Summary</h4>
                  <p className="verdict-summary-text">{timeline.verdict.summary}</p>
                </div>

                {Array.isArray(timeline.verdict.reasoning) &&
                  timeline.verdict.reasoning.length > 0 && (
                    <div className="verdict-block">
                      <h4 className="block-title">Analytical Reasoning & Supporting Evidence</h4>
                      <ul className="styled-list">
                        {timeline.verdict.reasoning.map((item, idx) => (
                          <li key={idx} className="reasoning-item">
                            <span className="bullet-point">▸</span> {item}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                {Array.isArray(timeline.verdict.recommended_actions) &&
                  timeline.verdict.recommended_actions.length > 0 && (
                    <div className="verdict-block">
                      <h4 className="block-title">Recommended DFIR Investigation Actions</h4>
                      <p className="stat-hint" role="note">Unreviewed AI suggestions. Authorized analyst approval is required. Preserve evidence before destructive cleanup; justified emergency containment may precede full collection. Confidence does not certify recommendation safety.</p>
                      <div className="actions-list">
                        {timeline.verdict.recommended_actions.map((act, idx) => (
                          <div key={idx} className="action-pill">
                            <span className="action-index mono">{idx + 1}</span>
                            <span className="action-text">{act}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
              </div>
            ) : (
              <div className="state-container empty-state">
                <p className="text-muted">No AI triage verdict has been generated for this timeline yet.</p>
              </div>
            )}
          </div>

          {/* Constituent Alert Events List */}
          {timeline.verdict && <section className="dashboard-card">
            <h2>Analyst review</h2>
            {timeline.analyst_review ? <AnalystReviewSummary review={timeline.analyst_review} /> : <form onSubmit={submitReview}>
              <p>Reviews are final for this verdict.</p>
              <label>Decision <select value={decision} onChange={e => setDecision(e.target.value as 'confirm' | 'override')}>
                <option value="confirm">Confirm assessment</option><option value="override">Override disposition</option>
              </select></label>
              {decision === 'override' && <label>Analyst disposition <select value={override} onChange={e => setOverride(e.target.value as typeof override)}>
                <option>MALICIOUS</option><option>BENIGN</option><option>UNDETERMINED</option>
              </select></label>}
              <label>Rationale {decision === 'override' ? '(required)' : '(optional)'} <textarea maxLength={2000} required={decision === 'override'} value={rationale} onChange={e => setRationale(e.target.value)} /></label>
              {reviewError && <p role="alert">{reviewError}</p>}
              <button className="btn btn-primary" disabled={saving || (decision === 'override' && !rationale.trim())}>Save review</button>
            </form>}
          </section>}
          <div className="dashboard-card alerts-feed-card">
            <div className="card-header">
              <div>
                <h3 className="card-title">Constituent Alert Sequence</h3>
                <p className="card-subtitle">
                  Raw telemetry and normalized security alerts ordered chronologically.
                </p>
              </div>
              <span className="badge badge-neutral mono">
                {timeline.alerts ? timeline.alerts.length : 0} Events
              </span>
            </div>

            {(!timeline.alerts || timeline.alerts.length === 0) ? (
              <div className="state-container empty-state">
                <p className="text-muted">No alerts attached to this timeline.</p>
              </div>
            ) : (
              <div className="alerts-sequence-list">
                {timeline.alerts.map((alert, index) => {
                  const isExpanded = !!expandedAlerts[alert.id];
                  return (
                    <div key={alert.id || index} className="alert-event-item">
                      <div className="alert-item-header">
                        <div className="alert-header-left">
                          <span className="step-counter mono">#{index + 1}</span>
                          <span className="event-type-badge mono">{alert.event_type}</span>
                          <span className="mono text-muted text-sm">
                            {formatDate(alert.timestamp)}
                          </span>
                        </div>
                        <div className="alert-header-right">
                          {alert.ground_truth_label && (
                            <span
                              className={`badge ${
                                alert.ground_truth_label.toLowerCase() === "benign"
                                  ? "badge-success"
                                  : "badge-danger"
                              }`}
                            >
                              GT: {alert.ground_truth_label}
                            </span>
                          )}
                          <button
                            className="btn btn-secondary btn-xs"
                            onClick={() => toggleAlertExpand(alert.id)}
                            aria-expanded={isExpanded}
                          >
                            {isExpanded ? "Hide JSON" : "Inspect Raw"}
                          </button>
                        </div>
                      </div>

                      <div className="alert-metadata-row">
                        <span className="meta-tag">
                          Source Dataset: <strong>{alert.source_dataset}</strong>
                        </span>
                        <span className="meta-tag">
                          Source File: <strong className="mono">{alert.source_file}</strong>
                        </span>
                        {Array.isArray(alert.extracted_indicators) &&
                          alert.extracted_indicators.length > 0 && (
                            <div className="indicators-group">
                              <span className="meta-tag-label">IOCs:</span>
                              {alert.extracted_indicators.map((ioc, iocIdx) => (
                                <span key={iocIdx} className="ioc-pill mono">
                                  {ioc}
                                </span>
                              ))}
                            </div>
                          )}
                      </div>

                      {isExpanded && (
                        <div className="raw-record-viewer">
                          <div className="raw-record-header">
                            <span className="mono text-xs">original_record (JSON)</span>
                          </div>
                          <pre className="raw-json-block mono">
                            {JSON.stringify(alert.original_record, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

