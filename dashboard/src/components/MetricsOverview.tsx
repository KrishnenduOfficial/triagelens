import React, { useEffect, useState, type FormEvent } from "react";
import type { MetricCoverageKey, MetricQuery, MetricScope, Metrics } from "../api/apiService";
import { buildMetricQuery, formatInterval, formatPercent, queryDescription, scopeNames, unitNames } from "../metrics/presentation";
import { createMetricsLoader, type MetricRequestState } from "../metrics/request";

const historyQuery: MetricQuery = { scope: "history" };
const countText = (value: number | undefined | null) => value === undefined || value === null ? "N/A" : value;
const scalar = (value: number | undefined | null) => typeof value === "number" && Number.isFinite(value) ? value.toFixed(4) : "N/A";
const coverageLabels: [MetricCoverageKey, string][] = [
  ["selected_units", "Selected units"], ["evaluation_rows", "Stored result rows"],
  ["observations", "Input observations"], ["fresh", "Fresh acquisitions"],
  ["completed_fresh", "Completed fresh attempts"], ["cache", "Cache replay observations"],
  ["unknown_origin", "Unknown acquisition origin"], ["skipped", "Skipped"],
  ["pending", "Pending"], ["interrupted", "Interrupted"],
  ["legacy_unknown", "Legacy rows in database"], ["excluded_legacy_unknown", "Legacy rows excluded"],
  ["outside_selection", "Rows outside selection"], ["excluded_unverifiable", "Unverifiable rows excluded"],
  ["excluded_no_verdict", "No-verdict rows excluded"], ["deduplicated", "Duplicate quality rows removed"],
  ["missing_outcomes", "Completed observations missing outcomes"],
  ["manifest_cases", "Manifest cases"], ["included_cases", "Cases contributing selected units"],
  ["missing_cases", "Manifest cases without selected units"],
  ["unique_evidence", "Unique evidence hashes"], ["repeated_evidence", "Repeated evidence units"],
  ["evidence_unknown", "Units without evidence hashes"],
];

function RateCard({ label, value, hint, interval }: {
  label: string; value: string; hint: React.ReactNode; interval?: string;
}) {
  return <div className="stat-box">
    <span className="stat-label">{label}</span>
    <span className="stat-value text-accent">{value}</span>
    <span className="stat-hint">{hint}</span>
    {interval && <span className="stat-hint">{interval}</span>}
  </div>;
}

/** This view consumes the server's selected results; it never deduplicates locally. */
export const MetricResults: React.FC<{ metrics: Metrics }> = ({ metrics }) => {
  const selection = metrics.selection;
  const scope = selection?.scope ?? "history";
  const coverage = selection?.coverage;
  const availabilityDenominator = selection?.denominators.availability ??
    (scope !== "quality" && metrics.unavailable !== undefined ? metrics.total + metrics.unknown + metrics.unavailable : null);
  const severityDenominator = selection?.denominators.severity ?? metrics.severity_evaluated;
  const calibrationDenominator = selection?.denominators.calibration;
  const noFresh = scope === "attempts" && availabilityDenominator === 0;
  const validFpr = metrics.fpr_valid !== false && metrics.tn + metrics.fp > 0;
  const validFnr = metrics.fnr_valid !== false && metrics.tp + metrics.fn > 0;
  const available = availabilityDenominator !== null && availabilityDenominator > 0;

  return <div className="metrics-content">
    <div className="metric-selection" aria-label="Displayed metric selection">
      <h3>{scopeNames[scope]}</h3>
      <p>{selection?.source === "memory" ? "In-memory evaluation rows; stored history is empty." : selection ? unitNames[selection.unit] : "History evaluation rows; replay weighting and source cannot be verified without scope metadata."}</p>
      {selection ? <>
        <p>Source: {selection.source === "database" ? "Database" : "In-memory tracker"}.
          {selection.source === "memory" && " Stored history is empty; these results come from the API's in-memory tracker."}
          {selection.run_status && ` Run status: ${selection.run_status}.`}</p>
        {selection.run_id && <p>Run: <code>{selection.run_id}</code></p>}
        {selection.cohort_id && <p>Cohort: <code>{selection.cohort_id}</code> ({selection.cohort_kind === "ad_hoc" ? "ad hoc: known completed cases" : "declared manifest"})</p>}
      </> : <p role="note">Scope metadata unavailable. History compatibility view; acquisition provenance and extra coverage are unknown.</p>}
    </div>

    <div className="rates-grid">
      <RateCard label="Model accuracy" value={formatPercent(metrics.total > 0 ? metrics.accuracy : null)}
        hint={<>{metrics.tp + metrics.tn} / {metrics.total} binary-labeled results correct</>}
        interval={formatInterval(metrics.accuracy_ci95, metrics.total > 0)} />
      <RateCard label="Precision" value={formatPercent(metrics.tp + metrics.fp > 0 ? metrics.precision : null)}
        hint={<>{metrics.tp} / {metrics.tp + metrics.fp} predicted-positive results</>}
        interval={formatInterval(metrics.precision_ci95, metrics.tp + metrics.fp > 0)} />
      <RateCard label="Recall (sensitivity)" value={formatPercent(validFnr ? metrics.recall : null)}
        hint={<>{metrics.tp} / {metrics.tp + metrics.fn} ground-truth positive results</>}
        interval={formatInterval(metrics.recall_ci95, validFnr)} />
      <RateCard label="F1 score" value={formatPercent(2 * metrics.tp + metrics.fp + metrics.fn > 0 ? metrics.f1_score : null)}
        hint="Harmonic mean of precision and recall" />
    </div>

    <div className="matrix-and-rates-row">
      <div className="matrix-card">
        <h3 className="section-label">Confusion matrix</h3>
        <div className="matrix-grid">
          {([
            ["tp", "True positive", "Malicious confirmed"], ["fp", "False positive", "False alarm on benign"],
            ["fn", "False negative", "Threat missed"], ["tn", "True negative", "Benign correctly classified"],
          ] as const).map(([key, title, description]) => <div className={`matrix-cell cell-${key}`} key={key}>
            <span className="cell-title">{title}</span><span className="cell-count">{metrics[key]}</span>
            <span className="cell-desc">{description}</span>
          </div>)}
        </div>
      </div>
      <div className="rates-card">
        <h3 className="section-label">Errors and result coverage</h3>
        <dl className="metric-facts">
          <div><dt>False positive rate</dt><dd>{formatPercent(validFpr ? metrics.false_positive_rate : null)}</dd></div>
          <div><dt>False negative rate</dt><dd>{formatPercent(validFnr ? metrics.false_negative_rate : null)}</dd></div>
          <div><dt>Binary-labeled results</dt><dd>{metrics.total}</dd></div>
          <div><dt>Unscored binary outcomes (unknown or abstained)</dt><dd>{metrics.unknown}</dd></div>
          <div><dt>Undetermined dispositions</dt><dd>{countText(metrics.abstained)}</dd></div>
          <div><dt>Explicit disposition outcomes</dt><dd>{countText(metrics.explicit_disposition_count)}</dd></div>
          <div><dt>Legacy severity-proxy outcomes</dt><dd>{countText(metrics.legacy_severity_proxy_count)}</dd></div>
          <div><dt>Prediction basis unrecorded</dt><dd>{countText(metrics.prediction_basis_unknown_count)}</dd></div>
          <div><dt>Unavailable outcomes</dt><dd>{countText(metrics.unavailable)}</dd></div>
        </dl>
        {!validFpr && <p className="stat-hint">FPR is undefined without negative samples.</p>}
        {!validFnr && <p className="stat-hint">FNR and recall are undefined without positive samples.</p>}
        <p className="stat-hint">Unknown truth and undetermined disposition do not enter binary accuracy or calibration. Abstention is an available response. Calibration measures confidence in binary correctness, not severity or recommendation safety. Historical results may use a different prediction basis; use explicit cohorts for policy comparisons.</p>
      </div>
    </div>

    <div className="rates-grid">
      <RateCard label={scope === "quality" ? "Availability" : scope === "attempts" ? "Fresh result availability" : "Result availability"}
        value={scope === "quality" ? "Not applicable" : formatPercent(available ? metrics.availability_rate : null)}
        hint={scope === "quality" ? "Quality excludes no-verdict outcomes; no service availability percentage." : noFresh ?
          "No completed fresh attempts. Cache replays do not demonstrate live service success." :
          `${countText(availabilityDenominator)} completed ${scope === "attempts" ? "fresh logical attempts" : "results"}${availabilityDenominator === 0 ? "; no availability evidence" : ""}.`} />
      <RateCard label="Severity accuracy" value={formatPercent(severityDenominator !== undefined && severityDenominator > 0 ? metrics.severity_accuracy : null)}
        hint={`${countText(metrics.severity_matches)} matches / ${countText(severityDenominator)} severity evaluations`} />
      <RateCard label="Brier score" value={scalar(calibrationDenominator === 0 ? null : metrics.brier_score)}
        hint={`${countText(calibrationDenominator)} calibration samples; lower is better`} />
      <RateCard label="Calibration error (ECE)" value={formatPercent(calibrationDenominator === 0 ? null : metrics.expected_calibration_error)}
        hint={`${countText(calibrationDenominator)} calibration samples`} />
    </div>

    {coverage && <details className="metric-coverage" open>
      <summary>Selection and acquisition coverage</summary>
      <dl className="metric-facts coverage-facts">
        {coverageLabels.filter(([key]) => coverage[key] !== undefined).map(([key, label]) =>
          <div key={key}><dt>{label}</dt><dd>{coverage[key]}</dd></div>)}
        {coverage.run_status_counts && Object.entries(coverage.run_status_counts).map(([status, value]) =>
          <div key={status}><dt>{status} runs</dt><dd>{value}</dd></div>)}
      </dl>
      {selection?.context_selection && <p>Context selection: {selection.context_selection === "immutable_manifest_members" ? "immutable case/context manifest" : "persisted evaluation outcomes"}.</p>}
      {selection?.inference_policy_hash && <p>Inference policy: <code>{selection.inference_policy_hash}</code></p>}
    </details>}
    <p className="metric-caveat" role="note">Cache deduplication does not establish independent evidence. Wilson intervals depend on sampling assumptions; repeated evidence may be correlated. Result availability does not prove provider uptime or primary-model availability.</p>
  </div>;
};

export const MetricRequestView: React.FC<{ state: MetricRequestState; onRetry: () => void }> = ({ state, onRetry }) => <>
  <p className="metric-applied" aria-live="polite">Applied selection: {queryDescription(state.query)}</p>
  {state.status === "loading" && <p role="status">Loading metrics for this selection…</p>}
  {state.status === "error" && <div className="state-container error-state" role="alert">
    <div><h3>Unable to load selected metrics</h3><p className="error-text">{state.error}</p>
      <p>No previous or fallback results are displayed for this selection.</p>
      <button className="btn btn-primary" onClick={onRetry}>Retry selection</button></div>
  </div>}
  {state.status === "ready" && state.metrics && <MetricResults metrics={state.metrics} />}
</>;

export const MetricsOverview: React.FC = () => {
  const [scope, setScope] = useState<MetricScope>("history");
  const [selector, setSelector] = useState("run");
  const [identifier, setIdentifier] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [applied, setApplied] = useState<MetricQuery>(historyQuery);
  const [loader] = useState(() => createMetricsLoader());
  const [result, setResult] = useState<MetricRequestState>({ query: historyQuery, status: "loading", metrics: null, error: null });

  useEffect(() => loader.load(applied, setResult), [applied, loader]);

  const displayed: MetricRequestState = result.query === applied ? result : { query: applied, status: "loading", metrics: null, error: null };
  const identifierKind = scope === "quality" ? "cohort" : scope === "run" ? "run" : selector;
  const apply = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const query = buildMetricQuery(scope, identifierKind, identifier);
      setFormError(null);
      setApplied(query);
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Invalid metric selection.");
    }
  };
  const reload = () => {
    // A new identity hides the previous result even before effect cleanup runs.
    setApplied(query => ({ ...query }));
  };

  return <section className="dashboard-card metrics-section" aria-label="AI performance metrics">
    <div className="card-header">
      <div>
        <div className="badge-row"><span className="badge badge-accent">Ground-truth evaluation</span></div>
        <h2 className="card-title">AI triage reliability and ground truth</h2>
        <p className="card-subtitle">Compare stored predictions with independent reference labels. History is the default.</p>
      </div>
      <button className="btn btn-secondary" onClick={reload} disabled={displayed.status === "loading"}>Refresh metrics</button>
    </div>
    <form className="metric-controls" onSubmit={apply} aria-label="Metric scope selection">
      <label>Scope<select value={scope} onChange={event => { setScope(event.target.value as MetricScope); setIdentifier(""); setFormError(null); }}>
        {Object.entries(scopeNames).map(([value, label]) => <option value={value} key={value}>{label}</option>)}
      </select></label>
      {scope === "attempts" && <label>Select attempts by<select value={selector} onChange={event => { setSelector(event.target.value); setIdentifier(""); }}>
        <option value="run">Run</option><option value="cohort">Registered cohort</option>
      </select></label>}
      {scope !== "history" && <label className="metric-identifier">{identifierKind === "run" ? "Run UUID" : "Registered cohort ID"}
        <input value={identifier} onChange={event => setIdentifier(event.target.value)} required spellCheck={false} autoComplete="off"
          maxLength={identifierKind === "run" ? 36 : 64} aria-describedby="metric-selector-help" />
      </label>}
      <button className="btn btn-primary" type="submit">Apply selection</button>
      <p id="metric-selector-help" className="stat-hint">Selections apply when submitted. Use an explicit run ID or registered cohort ID; no latest run is chosen automatically.</p>
      {formError && <p role="alert" className="error-text">Selection not applied: {formError} Displayed results still belong to the applied selection below.</p>}
    </form>
    <MetricRequestView state={displayed} onRetry={reload} />
  </section>;
};
