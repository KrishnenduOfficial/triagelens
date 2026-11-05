/**
 * TriageLens Dashboard API Client Service
 *
 * Provides typed HTTP communication with the FastAPI backend,
 * response validation, and resilient error normalization.
 */

import axios, { type AxiosError, type AxiosInstance } from "axios";

// Environment-configurable API URL with local fallback
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

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
  accuracy_pct?: number;
}

export interface TimelineSummary {
  id: string;
  grouping_key: string;
  start_time: string | null;
  end_time: string | null;
  total_events: number;
  created_at: string;
  alert_ids?: string[];
}

export interface TriageVerdict {
  id: string;
  timeline_id: string;
  severity: SeverityLevel;
  confidence_score: number;
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
export async function fetchMetrics(): Promise<Metrics> {
  try {
    const response = await apiClient.get<Metrics>("/api/metrics");
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
