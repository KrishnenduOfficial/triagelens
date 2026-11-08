import type { MetricQuery, MetricScope, Metrics } from "../api/apiService";

export const scopeNames: Record<MetricScope, string> = {
  history: "History", run: "Run", quality: "Quality", attempts: "Fresh attempts",
};
export const unitNames = {
  evaluation_row: "Persisted evaluation rows; cache replays count again.",
  run_evaluation_row: "Evaluation rows in one run; repeated occurrences count again.",
  verdict_context: "Unique verdict/context pairs in the selected immutable cohort.",
  completed_fresh_attempt: "Completed fresh logical attempts; HTTP retries are not separate attempts.",
};
const units = { history: "evaluation_row", run: "run_evaluation_row", quality: "verdict_context", attempts: "completed_fresh_attempt" };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digest = /^[0-9a-f]{64}$/;

export function buildMetricQuery(scope: string, selector: string, identifier: string): MetricQuery {
  const value = identifier.trim().toLowerCase();
  if (scope === "history") return { scope: "history" };
  if (scope === "run" || (scope === "attempts" && selector === "run")) {
    if (!uuid.test(value)) throw new Error("Enter a complete run UUID.");
    return { scope, run_id: value };
  }
  if (scope === "quality" || (scope === "attempts" && selector === "cohort")) {
    if (!digest.test(value)) throw new Error("Enter the registered cohort ID (64 hexadecimal characters).");
    return { scope, cohort_id: value };
  }
  throw new Error("Choose a valid metric scope and selector.");
}

export function validateMetricQuery(query: MetricQuery): void {
  if (!query || typeof query !== "object") throw new Error("Invalid metric selection.");
  const keys = Object.keys(query);
  if (keys.some(key => !["scope", "run_id", "cohort_id"].includes(key))) throw new Error("Unknown metric selector.");
  const hasRun = query.run_id !== undefined;
  const hasCohort = query.cohort_id !== undefined;
  if ((query.scope === "history" && (hasRun || hasCohort)) ||
      (query.scope === "run" && (!hasRun || hasCohort)) ||
      (query.scope === "quality" && (!hasCohort || hasRun)) ||
      (query.scope === "attempts" && hasRun === hasCohort) ||
      !Object.hasOwn(scopeNames, query.scope) ||
      (hasRun && !uuid.test(query.run_id!)) || (hasCohort && !digest.test(query.cohort_id!))) {
    throw new Error("Invalid metric scope/selector combination.");
  }
}

const count = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value) && value >= 0;
const rate = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);

/** Validate the counting contract before displaying an explicit scope as successful. */
export function validateMetricResponse(value: unknown, query: MetricQuery): asserts value is Metrics {
  if (!object(value) || !["tp", "tn", "fp", "fn", "total", "unknown"].every(key => count(value[key])) ||
      !["accuracy", "precision", "recall", "f1_score", "false_positive_rate", "false_negative_rate"].every(key => rate(value[key]))) {
    throw new Error("Invalid metric response; numeric results are missing or malformed.");
  }
  for (const key of ["unavailable", "severity_evaluated", "severity_matches"]) {
    if (value[key] !== undefined && !count(value[key])) throw new Error("Invalid metric count.");
  }
  for (const key of ["availability_rate", "severity_accuracy", "brier_score", "expected_calibration_error"]) {
    if (value[key] !== undefined && value[key] !== null && !rate(value[key])) throw new Error("Invalid metric rate.");
  }
  const selection = value.selection;
  if (selection === undefined && query.scope === "history") return; // Older API: no invented provenance.
  if (!object(selection) || selection.scope !== query.scope || selection.unit !== units[query.scope] ||
      !["database", "memory"].includes(String(selection.source)) ||
      (query.scope !== "history" && selection.source !== "database") ||
      (selection.run_id ?? undefined) !== query.run_id || (selection.cohort_id ?? undefined) !== query.cohort_id ||
      !object(selection.coverage) || !object(selection.denominators)) {
    throw new Error("Metric scope/selection metadata does not match the requested results.");
  }
  if (![null, "running", "completed", "failed"].includes(selection.run_status as string | null) ||
      (query.run_id !== undefined && selection.run_status === null) ||
      (query.cohort_id !== undefined && !["ad_hoc", "declared"].includes(String(selection.cohort_kind))) ||
      !["result_availability", "not_applicable_to_quality", "fresh_result_availability", "no_completed_fresh_attempts"].includes(String(selection.availability_status))) {
    throw new Error("Invalid metric selection status.");
  }
  const denominators = selection.denominators;
  if (!["binary", "severity", "calibration"].every(key => count(denominators[key])) ||
      denominators.binary !== value.total ||
      (query.scope === "quality" ? denominators.availability !== null || value.availability_rate !== null : !count(denominators.availability))) {
    throw new Error("Invalid metric selection denominators.");
  }
  if (query.scope === "attempts" && (denominators.availability === 0 ?
      value.availability_rate !== null || selection.availability_status !== "no_completed_fresh_attempts" :
      !rate(value.availability_rate) || selection.availability_status !== "fresh_result_availability")) {
    throw new Error("Invalid fresh-attempt availability contract.");
  }
  for (const [key, item] of Object.entries(selection.coverage)) {
    if (key === "run_status_counts") {
      if (!object(item) || !Object.values(item).every(count)) throw new Error("Invalid run coverage.");
    } else if (!count(item)) throw new Error("Invalid metric coverage.");
  }
}

export function formatPercent(value: number | null | undefined): string {
  return typeof value === "number" && Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : "N/A";
}

export function formatInterval(value: [number, number] | undefined, valid: boolean): string {
  if (!valid || !Array.isArray(value) || value.length !== 2 || !value.every(rate) || value[0] > value[1]) return "95% interval: N/A";
  return `95% Wilson interval: ${formatPercent(value[0])} to ${formatPercent(value[1])}`;
}

export function queryDescription(query: MetricQuery): string {
  return `${scopeNames[query.scope]}${query.run_id ? ` · Run ${query.run_id}` : query.cohort_id ? ` · Cohort ${query.cohort_id}` : " · All stored history"}`;
}
