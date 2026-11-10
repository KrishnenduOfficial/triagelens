/**
 * TriageLens Dashboard API Client Service
 *
 * Provides typed HTTP communication with the FastAPI backend,
 * response validation, and resilient error normalization.
 */

import axios, { type AxiosError, type AxiosInstance } from "axios";
import { validateMetricQuery, validateMetricResponse } from "../metrics/presentation";

// Environment-configurable API URL with local fallback
const API_BASE_URL =
  import.meta.env?.VITE_API_BASE_URL || "http://localhost:8000";

export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
});

// =====================================================================
// Type Definitions Matching FastAPI Models
// =====================================================================

export type SeverityLevel =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFORMATIONAL";

export interface Metrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  false_negative_rate: number;
  true_positives: number;
  true_negatives: number;
  false_positives: number;
  false_negatives: number;
  tp: number;
  tn: number;
  fp: number;
  fn: number;
  total: number;
  unknown: number;
  abstained?: number;
  labelled_available?: number;
  labelled_binary?: number;
  labelled_abstained?: number;
  labelled_binary_coverage?: number | null;
  unknown_ground_truth?: number;
  explicit_disposition_count?: number;
  legacy_severity_proxy_count?: number;
  prediction_basis_unknown_count?: number;
  accuracy_pct?: number;
  unavailable?: number;
  availability_rate?: number | null;
  fpr_valid?: boolean;
  fnr_valid?: boolean;
  accuracy_ci95?: [number, number];
  precision_ci95?: [number, number];
  recall_ci95?: [number, number];
  severity_accuracy?: number;
  severity_evaluated?: number;
  severity_matches?: number;
  brier_score?: number | null;
  expected_calibration_error?: number | null;
  selection?: MetricSelection;
}

export type MetricScope = "history" | "run" | "quality" | "attempts";
export type MetricQuery =
  | { scope: "history"; run_id?: never; cohort_id?: never }
  | { scope: "run"; run_id: string; cohort_id?: never }
  | { scope: "quality"; cohort_id: string; run_id?: never }
  | ({ scope: "attempts" } & (
    | { run_id: string; cohort_id?: never }
    | { cohort_id: string; run_id?: never }
  ));

export interface MetricSelection {
  scope: MetricScope;
  source: "database" | "memory";
  unit: "evaluation_row" | "run_evaluation_row" | "verdict_context" | "completed_fresh_attempt";
  run_id: string | null;
  run_status: "running" | "completed" | "failed" | null;
  cohort_id: string | null;
  cohort_kind: "ad_hoc" | "declared" | null;
  inference_policy_hash?: string | null;
  context_selection?: string;
  context_count?: number;
  observed_inference_policies?: string[];
  availability_status: "result_availability" | "not_applicable_to_quality" |
    "fresh_result_availability" | "no_completed_fresh_attempts";
  coverage: Partial<Record<MetricCoverageKey, number>> & {
    run_status_counts?: Partial<Record<"running" | "completed" | "failed", number>>;
  };
  denominators: { binary: number; severity: number; calibration: number; availability: number | null };
}

export type MetricCoverageKey = "evaluation_rows" | "selected_units" | "observations" |
  "fresh" | "completed_fresh" | "cache" | "unknown_origin" | "skipped" | "pending" |
  "interrupted" | "legacy_unknown" | "excluded_legacy_unknown" | "outside_selection" |
  "excluded_unverifiable" | "excluded_no_verdict" | "deduplicated" | "missing_outcomes" |
  "unique_evidence" | "repeated_evidence" | "evidence_unknown" | "manifest_cases" |
  "included_cases" | "missing_cases";

export interface TimelineSummary {
  id: string;
  grouping_key: string;
  start_time: string | null;
  end_time: string | null;
  total_events: number;
  created_at: string;
  alert_ids?: string[];
}

export interface EvidenceReference {
  evidence_id: string;
  field_path: string[];
}

export interface EvidenceStatement {
  statement: string;
  refs: EvidenceReference[];
}

export interface EvidenceGap {
  category: "authorization" | "execution_outcome" | "protocol" | "threat_intelligence" |
    "scope_impact" | "process_context" | "other";
  description: string;
  required_evidence: string;
  blocks_disposition: boolean;
}

export interface EvidenceBasis {
  kind: "malicious_support" | "benign_support" | "insufficient_evidence";
  decision_refs: EvidenceReference[];
  observations: EvidenceStatement[];
  hypotheses: EvidenceStatement[];
  gaps: EvidenceGap[];
}

export interface TriageVerdict {
  id: string;
  timeline_id: string;
  severity: SeverityLevel;
  confidence_score: number;
  disposition?: "MALICIOUS" | "BENIGN" | "UNDETERMINED" | null;
  policy_version?: string | null;
  model_name?: string | null;
  uncertainty_level?: "LOW" | "MEDIUM" | "HIGH" | null;
  missing_information?: string[] | null;
  missing_information_recorded?: boolean;
  evidence_basis?: EvidenceBasis | null;
  evidence_context?: Record<string, Record<string, unknown>> | null;
  evidence_contract_version?: string | null;
  summary: string;
  reasoning: string[];
  recommended_actions: string[];
  raw_llm_response?: string;
  created_at?: string;
}

export interface NormalizedAlert {
  id: string;
  timeline_id?: string | null;
  timestamp?: string | null;
  source_dataset: string;
  source_file: string;
  event_type: string;
  original_record: Record<string, unknown>;
  extracted_indicators: string[];
  ground_truth_label?: string | null;
  created_at?: string;
}

export interface AlertQuery {
  skip: number; limit: number; sort: string; direction: string;
  dataset?: string; event_type?: string; host?: string; user?: string;
  search?: string; start?: string; end?: string;
}
export interface AlertPage { items: NormalizedAlert[]; total: number; skip: number; limit: number }

export interface IntelligenceLookup {
  id: number; provider: string; status: 'ok' | 'not_found' | 'rate_limited' | 'unavailable';
  recorded_status: string; lookup_timestamp: string | null; summary: Record<string, unknown>;
}

export async function fetchThreatIntelligence(indicator: string): Promise<IntelligenceLookup[]> {
  try {
    return (await apiClient.get<IntelligenceLookup[]>('/api/threat-intelligence', { params: { indicator } })).data;
  } catch (error) {
    throw normalizeError(error, 'Failed to retrieve recorded threat intelligence.');
  }
}

export async function fetchAlerts(query: AlertQuery): Promise<AlertPage> {
  try {
    return (await apiClient.get<AlertPage>('/api/alerts', { params: query })).data;
  } catch (error) {
    throw normalizeError(error, 'Failed to retrieve alerts.');
  }
}

export interface TimelineDetail extends TimelineSummary {
  alerts: NormalizedAlert[];
  verdict: TriageVerdict | null;
  timeline?: TimelineSummary;
}

export interface ApiErrorDetails {
  message: string;
  statusCode?: number;
  detail?: unknown;
}

// =====================================================================
// Error Normalization Helper
// =====================================================================

export function normalizeError(
  error: unknown,
  fallbackMessage: string
): Error {
  if (axios.isAxiosError(error)) {
    const axiosErr = error as AxiosError<{ detail?: string }>;
    if (axiosErr.response) {
      const status = axiosErr.response.status;
      const detail = axiosErr.response.data?.detail || axiosErr.message;
      return new Error(`[API ${status}] ${detail}`);
    } else if (axiosErr.request) {
      return new Error(
        "[Network Error] Unable to connect to TriageLens backend. Ensure FastAPI server is running on " +
          API_BASE_URL
      );
    }
    return new Error(`[Client Error] ${axiosErr.message}`);
  }
  if (error instanceof Error) {
    return error;
  }
  return new Error(fallbackMessage);
}

// =====================================================================
// API Service Methods
// =====================================================================

/**
 * Fetches real-time accuracy and performance evaluation metrics.
 */
export async function fetchMetrics(
  query: MetricQuery = { scope: "history" }, signal?: AbortSignal,
): Promise<Metrics> {
  validateMetricQuery(query);
  try {
    const response = await apiClient.get<Metrics>("/api/metrics", {
      params: query.scope === "history" ? undefined : query,
      signal,
    });
    validateMetricResponse(response.data, query);
    return response.data;
  } catch (error) {
    throw normalizeError(error, "Failed to retrieve accuracy metrics.");
  }
}

/**
 * Fetches paginated list of threat timelines.
 *
 * @param skip Offset records to skip (default 0)
 * @param limit Maximum records to return (1-1000, default 50)
 */
export async function fetchTimelines(
  skip: number = 0,
  limit: number = 50
): Promise<TimelineSummary[]> {
  try {
    const response = await apiClient.get<TimelineSummary[]>("/api/timelines", {
      params: { skip, limit },
    });
    return response.data;
  } catch (error) {
    throw normalizeError(error, "Failed to retrieve threat timelines.");
  }
}

/**
 * Fetches detailed threat timeline including correlated alerts and LLM triage verdict.
 *
 * @param timelineId Unique UUID of the timeline
 */
export async function fetchTimelineDetail(
  timelineId: string
): Promise<TimelineDetail> {
  try {
    const response = await apiClient.get<TimelineDetail>(
      `/api/timelines/${encodeURIComponent(timelineId)}`
    );
    return response.data;
  } catch (error) {
    throw normalizeError(
      error,
      `Failed to retrieve details for timeline '${timelineId}'.`
    );
  }
}

/**
 * Executes a KQL-style hunting filter against the alerts telemetry database.
 *
 * @param query KQL-style hunting filter (e.g., 'CommandLine contains "powershell"')
 * @returns Array of matching NormalizedAlert objects
 */
export const huntAlerts = async (query: string): Promise<NormalizedAlert[]> => {
  try {
    const response = await apiClient.post<NormalizedAlert[]>("/api/hunt", {
      query,
    });
    return response.data;
  } catch (error) {
    throw normalizeError(error, "Failed to execute threat hunt query.");
  }
};
